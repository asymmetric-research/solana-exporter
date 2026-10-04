package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/asymmetric-research/solana-exporter/pkg/rpc"
	"github.com/asymmetric-research/solana-exporter/pkg/slog"
	"github.com/asymmetric-research/solana-exporter/pkg/voteinclusion"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

const (
	ReasonLabel = "reason"

	StatusIncluded = "included"
	StatusMissed   = "missed"

	// leaderScheduleRetryInterval rate-limits retries of leader schedules that could not be fetched.
	leaderScheduleRetryInterval = 30 * time.Second
)

// VoteInclusionWatcher tracks, for each configured votekey, in how many Alpenglow reward certificates the validator
// was included. See package voteinclusion for how this is derived from vote credits.
type VoteInclusionWatcher struct {
	client *rpc.Client
	logger *zap.SugaredLogger

	config *ExporterConfig

	tracker  *voteinclusion.Tracker
	schedule *rpc.EpochSchedule
	// referencesEpoch is the epoch the reference accounts were last picked for.
	referencesEpoch int64
	// nodekeys maps each tracked votekey to its node identity, for leader schedules.
	nodekeys              map[string]string
	nextLeaderScheduleTry time.Time

	// prometheus:
	RewardSlotsMetric         *prometheus.CounterVec
	UnattributedSlotsMetric   *prometheus.CounterVec
	LastIncludedSlotMetric    *prometheus.GaugeVec
	CreditsPerRewardSlot      *prometheus.GaugeVec
	ObservedSlotMetric        prometheus.Gauge
	ReferenceValidatorsMetric prometheus.Gauge
	PendingGapsMetric         prometheus.Gauge
}

func NewVoteInclusionWatcher(client *rpc.Client, config *ExporterConfig) *VoteInclusionWatcher {
	logger := slog.Get()
	watcher := VoteInclusionWatcher{
		client:          client,
		logger:          logger,
		config:          config,
		referencesEpoch: -1,
		nodekeys:        make(map[string]string),
		RewardSlotsMetric: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "solana_validator_alpenglow_reward_slots_total",
				Help: fmt.Sprintf(
					"Number of Alpenglow reward slots, grouped by %s, and %s ('%s' in the reward certificate or '%s')",
					VotekeyLabel, SkipStatusLabel, StatusIncluded, StatusMissed,
				),
			},
			[]string{VotekeyLabel, SkipStatusLabel},
		),
		UnattributedSlotsMetric: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "solana_validator_alpenglow_unattributed_slots_total",
				Help: fmt.Sprintf(
					"Number of slots that could not be counted towards reward-certificate inclusion, "+
						"grouped by %s and %s",
					VotekeyLabel, ReasonLabel,
				),
			},
			[]string{VotekeyLabel, ReasonLabel},
		),
		LastIncludedSlotMetric: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "solana_validator_alpenglow_last_included_slot",
				Help: fmt.Sprintf(
					"Upper bound of the latest slot range in which the validator (represented by %s) was in a reward "+
						"certificate",
					VotekeyLabel,
				),
			},
			[]string{VotekeyLabel},
		),
		CreditsPerRewardSlot: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "solana_validator_alpenglow_credits_per_reward_slot",
				Help: fmt.Sprintf(
					"Vote credits earned per included reward slot in the current epoch, grouped by %s (0 until learnt)",
					VotekeyLabel,
				),
			},
			[]string{VotekeyLabel},
		),
		ObservedSlotMetric: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "solana_alpenglow_observed_slot",
			Help: "Finalized slot of the latest vote-credit observation",
		}),
		ReferenceValidatorsMetric: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "solana_alpenglow_reference_validators",
			Help: "Number of reference validators used to estimate how many reward slots had a reward certificate",
		}),
		PendingGapsMetric: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "solana_alpenglow_pending_gaps",
			Help: "Number of observation gaps waiting for per-slot rewards to be learnt",
		}),
	}
	logger.Info("Registering vote-inclusion watcher metrics:")
	for _, collector := range []prometheus.Collector{
		watcher.RewardSlotsMetric,
		watcher.UnattributedSlotsMetric,
		watcher.LastIncludedSlotMetric,
		watcher.CreditsPerRewardSlot,
		watcher.ObservedSlotMetric,
		watcher.ReferenceValidatorsMetric,
		watcher.PendingGapsMetric,
	} {
		if err := prometheus.Register(collector); err != nil {
			var alreadyRegisteredErr prometheus.AlreadyRegisteredError
			if errors.As(err, &alreadyRegisteredErr) {
				continue
			}
			logger.Fatal(fmt.Errorf("failed to register collector: %w", err))
		}
	}
	// emit zeros up front, so that rate() works before the first inclusion or miss:
	for _, votekey := range config.Votekeys {
		watcher.RewardSlotsMetric.WithLabelValues(votekey, StatusIncluded).Add(0)
		watcher.RewardSlotsMetric.WithLabelValues(votekey, StatusMissed).Add(0)
	}
	return &watcher
}

func (c *VoteInclusionWatcher) WatchVoteInclusion(ctx context.Context) {
	ticker := time.NewTicker(c.config.SlotPace)
	defer ticker.Stop()

	c.logger.Infof("Starting vote-inclusion watcher, running every %vs", c.config.SlotPace.Seconds())
	for {
		if err := c.observe(ctx); err != nil {
			c.logger.Errorf("Failed to observe vote inclusion: %v", err)
		}
		select {
		case <-ctx.Done():
			c.logger.Info("Stopping vote-inclusion watcher")
			return
		case <-ticker.C:
		}
	}
}

// observe reads the vote credits of all tracked accounts and feeds them to the tracker.
func (c *VoteInclusionWatcher) observe(ctx context.Context) error {
	if c.tracker == nil {
		schedule, err := c.client.GetEpochSchedule(ctx)
		if err != nil {
			return fmt.Errorf("failed to get epoch schedule: %w", err)
		}
		c.schedule = schedule
		c.tracker = voteinclusion.NewTracker(voteinclusion.Config{Schedule: schedule})
		c.tracker.SetAccounts(c.config.Votekeys, nil)
	}

	votekeys := c.tracker.Accounts()
	slot, accounts, err := rpc.GetMultipleAccounts[rpc.VoteAccountData](
		ctx, c.client, rpc.CommitmentFinalized, votekeys,
	)
	if err != nil {
		return fmt.Errorf("failed to get vote accounts: %w", err)
	}
	credits := make(map[string]uint64)
	for i, account := range accounts {
		if account == nil || account.Data.Parsed.Type != "vote" {
			c.logger.Warnf("%v is not a vote account, skipping", votekeys[i])
			continue
		}
		info := account.Data.Parsed.Info
		accountCredits, err := info.TotalCredits()
		if err != nil {
			c.logger.Errorf("Failed to read credits of %v: %v", votekeys[i], err)
			continue
		}
		credits[votekeys[i]] = accountCredits
		c.nodekeys[votekeys[i]] = info.NodePubkey
	}

	epoch := c.schedule.GetEpoch(slot)
	if c.referencesEpoch < 0 {
		c.logger.Infof("First vote-inclusion observation at slot %v (epoch %v)", slot, epoch)
	}
	if epoch != c.referencesEpoch {
		c.pickReferences(ctx, epoch)
	}
	c.fetchLeaderSchedules(ctx, epoch)

	for _, result := range c.tracker.Observe(voteinclusion.Observation{Slot: slot, Credits: credits}) {
		c.emit(result)
	}
	c.ObservedSlotMetric.Set(float64(slot))
	c.PendingGapsMetric.Set(float64(c.tracker.Pending()))
	for _, votekey := range c.config.Votekeys {
		c.CreditsPerRewardSlot.WithLabelValues(votekey).Set(float64(c.tracker.PerSlotReward(votekey, epoch)))
	}
	return nil
}

// pickReferences re-picks the top-staked current validators as references, once per epoch.
func (c *VoteInclusionWatcher) pickReferences(ctx context.Context, epoch int64) {
	voteAccounts, err := c.client.GetVoteAccounts(ctx, rpc.CommitmentFinalized)
	if err != nil {
		c.logger.Errorf("Failed to get vote accounts for picking references, retrying next run: %v", err)
		return
	}
	current := slices.Clone(voteAccounts.Current)
	slices.SortFunc(current, func(a, b rpc.VoteAccount) int { return cmp.Compare(b.ActivatedStake, a.ActivatedStake) })

	var references []string
	for _, account := range current {
		if len(references) == c.config.AlpenglowReferenceCount {
			break
		}
		if !slices.Contains(c.config.Votekeys, account.VotePubkey) {
			references = append(references, account.VotePubkey)
		}
	}
	c.tracker.SetAccounts(c.config.Votekeys, references)
	c.referencesEpoch = epoch
	c.ReferenceValidatorsMetric.Set(float64(len(references)))
	c.logger.Infof("Epoch %v: tracking vote inclusion against %v reference validators", epoch, len(references))
}

// fetchLeaderSchedules loads the leader slots of every tracked account for the epoch. Gaps without a schedule are
// reported as unattributed, so missing schedules are retried, at most every leaderScheduleRetryInterval.
func (c *VoteInclusionWatcher) fetchLeaderSchedules(ctx context.Context, epoch int64) {
	var missing []string
	for _, votekey := range c.tracker.Accounts() {
		if c.nodekeys[votekey] != "" && !c.tracker.HasLeaderSchedule(votekey, epoch) {
			missing = append(missing, votekey)
		}
	}
	if len(missing) == 0 || time.Now().Before(c.nextLeaderScheduleTry) {
		return
	}

	firstSlot := c.schedule.GetFirstSlotInEpoch(epoch)
	leaderSchedule, err := c.client.GetLeaderSchedule(ctx, rpc.CommitmentConfirmed, firstSlot)
	if err == nil && len(leaderSchedule) == 0 {
		// null result: the node doesn't have the schedule for this epoch (yet).
		err = errors.New("empty leader schedule")
	}
	if err != nil {
		c.logger.Errorf("Failed to get leader schedule for epoch %v: %v", epoch, err)
		c.nextLeaderScheduleTry = time.Now().Add(leaderScheduleRetryInterval)
		return
	}
	for _, votekey := range missing {
		// leader schedules hold slot indexes; a node absent from it has no leader slots this epoch:
		var slots []int64
		for _, slotIndex := range leaderSchedule[c.nodekeys[votekey]] {
			slots = append(slots, firstSlot+slotIndex)
		}
		c.tracker.SetLeaderSlots(votekey, epoch, slots)
	}
}

func (c *VoteInclusionWatcher) emit(result voteinclusion.Result) {
	if result.Reason != "" {
		c.UnattributedSlotsMetric.WithLabelValues(result.Votekey, result.Reason).Add(float64(result.To - result.From))
		return
	}
	c.RewardSlotsMetric.WithLabelValues(result.Votekey, StatusIncluded).Add(float64(result.Included))
	if result.Included > 0 {
		c.LastIncludedSlotMetric.WithLabelValues(result.Votekey).Set(float64(result.To))
	}
	// Expected is the maximum count across all accounts in the gap, including this one, so it is >= Included:
	if result.Expected > result.Included {
		missed := result.Expected - result.Included
		c.RewardSlotsMetric.WithLabelValues(result.Votekey, StatusMissed).Add(float64(missed))
		c.logger.Infof(
			"%v missed %v of %v reward slots in (%v, %v]",
			result.Votekey, missed, result.Expected, result.From, result.To,
		)
	}
}
