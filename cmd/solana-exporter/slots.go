package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/asymmetric-research/solana-exporter/pkg/slog"
	"go.uber.org/zap"

	"github.com/asymmetric-research/solana-exporter/pkg/rpc"
	"github.com/prometheus/client_golang/prometheus"
)

type SlotWatcher struct {
	client *rpc.Client
	logger *zap.SugaredLogger

	config *ExporterConfig

	// currentEpoch is the current epoch we are watching
	currentEpoch int64
	// firstSlot is the first slot [inclusive] of the current epoch which we are watching
	firstSlot int64
	// lastSlot is the last slot [inclusive] of the current epoch which we are watching
	lastSlot int64
	// slotWatermark is the last (most recent) slot we have tracked
	slotWatermark int64

	leaderSchedule map[string][]int64

	// for tracking which metrics we have and deleting them accordingly:
	nodekeyTracker *EpochTrackedValidators

	// prometheus:
	TotalTransactionsMetric   prometheus.Gauge
	SlotHeightMetric          prometheus.Gauge
	EpochNumberMetric         prometheus.Gauge
	EpochFirstSlotMetric      prometheus.Gauge
	EpochLastSlotMetric       prometheus.Gauge
	LeaderSlotsMetric         *prometheus.CounterVec
	LeaderSlotsByEpochMetric  *prometheus.CounterVec
	ClusterSlotsByEpochMetric *prometheus.CounterVec
	InflationRewardsMetric    *prometheus.CounterVec
	FeeRewardsMetric          *prometheus.CounterVec
	BlockSizeMetric           *prometheus.GaugeVec
	BlockHeightMetric         prometheus.Gauge
}

func NewSlotWatcher(client *rpc.Client, config *ExporterConfig) *SlotWatcher {
	logger := slog.Get()
	watcher := SlotWatcher{
		client:         client,
		logger:         logger,
		config:         config,
		nodekeyTracker: NewEpochTrackedValidators(),
		// metrics:
		TotalTransactionsMetric: prometheus.NewGauge(prometheus.GaugeOpts{
			// even though this isn't a counter, it is supposed to act as one,
			// and so we name it with the _total suffix
			Name: "solana_node_transactions_total",
			Help: "Total number of transactions processed without error since genesis.",
		}),
		SlotHeightMetric: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "solana_node_slot_height",
			Help: "The current slot number",
		}),
		EpochNumberMetric: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "solana_node_epoch_number",
			Help: "The current epoch number.",
		}),
		EpochFirstSlotMetric: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "solana_node_epoch_first_slot",
			Help: "Current epoch's first slot [inclusive].",
		}),
		EpochLastSlotMetric: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "solana_node_epoch_last_slot",
			Help: "Current epoch's last slot [inclusive].",
		}),
		LeaderSlotsMetric: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "solana_validator_leader_slots_total",
				Help: fmt.Sprintf(
					"Number of slots processed, grouped by %s, and %s ('%s' or '%s')",
					NodekeyLabel, SkipStatusLabel, StatusValid, StatusSkipped,
				),
			},
			[]string{NodekeyLabel, SkipStatusLabel},
		),
		LeaderSlotsByEpochMetric: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "solana_validator_leader_slots_by_epoch_total",
				Help: fmt.Sprintf(
					"Number of slots processed, grouped by %s, %s ('%s' or '%s'), and %s",
					NodekeyLabel, SkipStatusLabel, StatusValid, StatusSkipped, EpochLabel,
				),
			},
			[]string{NodekeyLabel, EpochLabel, SkipStatusLabel},
		),
		ClusterSlotsByEpochMetric: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "solana_cluster_slots_by_epoch_total",
				Help: fmt.Sprintf(
					"Number of slots processed by the cluster, grouped by %s ('%s' or '%s'), and %s",
					SkipStatusLabel, StatusValid, StatusSkipped, EpochLabel,
				),
			},
			[]string{EpochLabel, SkipStatusLabel},
		),
		InflationRewardsMetric: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "solana_validator_inflation_rewards_total",
				Help: fmt.Sprintf("Inflation reward earned, grouped by %s and %s", VotekeyLabel, EpochLabel),
			},
			[]string{VotekeyLabel, EpochLabel},
		),
		FeeRewardsMetric: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "solana_validator_fee_rewards_total",
				Help: fmt.Sprintf("Transaction fee rewards earned, grouped by %s and %s", NodekeyLabel, EpochLabel),
			},
			[]string{NodekeyLabel, EpochLabel},
		),
		BlockSizeMetric: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "solana_validator_block_size",
				Help: fmt.Sprintf("Number of transactions per block, grouped by %s", NodekeyLabel),
			},
			[]string{NodekeyLabel, TransactionTypeLabel},
		),
		BlockHeightMetric: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "solana_node_block_height",
			Help: "The current block height of the node",
		}),
	}
	// register
	logger.Info("Registering slot watcher metrics:")
	for _, collector := range []prometheus.Collector{
		watcher.TotalTransactionsMetric,
		watcher.SlotHeightMetric,
		watcher.EpochNumberMetric,
		watcher.EpochFirstSlotMetric,
		watcher.EpochLastSlotMetric,
		watcher.LeaderSlotsMetric,
		watcher.LeaderSlotsByEpochMetric,
		watcher.ClusterSlotsByEpochMetric,
		watcher.InflationRewardsMetric,
		watcher.FeeRewardsMetric,
		watcher.BlockSizeMetric,
		watcher.BlockHeightMetric,
	} {
		if err := prometheus.Register(collector); err != nil {
			var (
				alreadyRegisteredErr *prometheus.AlreadyRegisteredError
				duplicateErr         = strings.Contains(err.Error(), "duplicate metrics collector registration attempted")
			)
			if errors.As(err, &alreadyRegisteredErr) || duplicateErr {
				continue
			} else {
				logger.Fatal(fmt.Errorf("failed to register collector: %w", err))
			}
		}
	}
	return &watcher
}

func (c *SlotWatcher) WatchSlots(ctx context.Context) {
	ticker := time.NewTicker(c.config.SlotPace)
	defer ticker.Stop()

	c.logger.Infof("Starting slot watcher, running every %vs", c.config.SlotPace.Seconds())

	for {
		select {
		case <-ctx.Done():
			c.logger.Infof("Stopping WatchSlots() at slot %v", c.slotWatermark)
			return
		default:
			<-ticker.C
			// TODO: separate fee-rewards watching from general slot watching, such that general slot watching commitment level can be dropped to confirmed
			commitment := rpc.CommitmentFinalized
			epochInfo, err := c.client.GetEpochInfo(ctx, commitment)
			if err != nil {
				c.logger.Errorf("Failed to get epoch info, bailing out: %v", err)
				continue
			}

			// if we are running for the first time, then we need to set our tracking numbers:
			if c.currentEpoch == 0 {
				c.trackEpoch(ctx, epochInfo)
			}

			c.logger.Infof("Current slot: %v", epochInfo.AbsoluteSlot)
			c.TotalTransactionsMetric.Set(float64(epochInfo.TransactionCount))
			c.SlotHeightMetric.Set(float64(epochInfo.AbsoluteSlot))
			c.BlockHeightMetric.Set(float64(epochInfo.BlockHeight))

			// if we get here, then the tracking numbers are set, so this is a "normal" run.
			// start by checking if we have progressed since last run:
			if epochInfo.AbsoluteSlot <= c.slotWatermark {
				c.logger.Infof("%v slot number has not advanced from %v, skipping", commitment, c.slotWatermark)
				continue
			}

			if epochInfo.Epoch > c.currentEpoch {
				c.closeCurrentEpoch(ctx, epochInfo)
			}

			// update block production metrics up until the current slot:
			c.moveSlotWatermark(ctx, epochInfo.AbsoluteSlot)
		}
	}
}

// trackEpoch takes in a new rpc.EpochInfo and sets the SlotWatcher tracking metrics accordingly,
// and updates the prometheus gauges associated with those metrics.
func (c *SlotWatcher) trackEpoch(ctx context.Context, epoch *rpc.EpochInfo) {
	c.logger.Infof("Tracking epoch %v (from %v)", epoch.Epoch, c.currentEpoch)
	firstSlot, lastSlot := GetEpochBounds(epoch)
	// if we haven't yet set c.currentEpoch, that (hopefully) means this is the initial setup,
	// and so we can simply store the tracking numbers
	if c.currentEpoch == 0 {
		c.currentEpoch = epoch.Epoch
		c.firstSlot = firstSlot
		c.lastSlot = lastSlot
		// we don't backfill on startup. we set the watermark to current slot minus 1,
		//such that the current slot is the first slot tracked
		c.slotWatermark = epoch.AbsoluteSlot - 1
	} else {
		// if c.currentEpoch is already set, then, just in case, run some checks
		// to make sure that we make sure that we are tracking consistently
		assertf(epoch.Epoch == c.currentEpoch+1, "epoch jumped from %v to %v", c.currentEpoch, epoch.Epoch)
		assertf(
			firstSlot == c.lastSlot+1,
			"first slot %v does not follow from current last slot %v",
			firstSlot,
			c.lastSlot,
		)

		// and also, make sure that we have completed the last epoch:
		assertf(
			c.slotWatermark == c.lastSlot,
			"can't update epoch when watermark %v hasn't reached current last-slot %v",
			c.slotWatermark,
			c.lastSlot,
		)

		// the epoch number is progressing correctly, so we can update our tracking numbers:
		c.currentEpoch = epoch.Epoch
		c.firstSlot = firstSlot
		c.lastSlot = lastSlot
	}

	// emit epoch bounds:
	c.logger.Infof("Emitting epoch bounds: %v (slots %v -> %v)", c.currentEpoch, c.firstSlot, c.lastSlot)
	c.EpochNumberMetric.Set(float64(c.currentEpoch))
	c.EpochFirstSlotMetric.Set(float64(c.firstSlot))
	c.EpochLastSlotMetric.Set(float64(c.lastSlot))

	// update leader schedule:
	if !c.config.LightMode {
		c.logger.Infof("Updating leader schedule for epoch %v ...", c.currentEpoch)
		leaderSchedule, err := GetTrimmedLeaderSchedule(ctx, c.client, c.config.Nodekeys, epoch.AbsoluteSlot, c.firstSlot)
		if err != nil {
			c.logger.Errorf("Failed to get trimmed leader schedule, bailing out: %v", err)
		}
		c.leaderSchedule = leaderSchedule
	} else {
		c.logger.Debug("Skipping leader schedule update in light mode")
	}
}

// cleanEpoch deletes old epoch-labelled metrics which are no longer being updated due to an epoch change.
func (c *SlotWatcher) cleanEpoch(ctx context.Context, epoch int64) {
	c.logger.Infof(
		"Waiting %vs before cleaning epoch %d...",
		c.config.EpochCleanupTime.Seconds(), epoch,
	)
	select {
	case <-ctx.Done():
		return
	case <-time.After(c.config.EpochCleanupTime):
	}

	c.logger.Infof("Cleaning epoch %d", epoch)
	epochStr := toString(epoch)
	// rewards:
	for i, nodekey := range c.config.Nodekeys {
		c.deleteMetricLabelValues(c.FeeRewardsMetric, "fee-rewards", nodekey, epochStr)
		c.deleteMetricLabelValues(c.InflationRewardsMetric, "inflation-rewards", c.config.Votekeys[i], epochStr)
	}
	// slots:
	var trackedNodekeys []string
	trackedNodekeys, err := c.nodekeyTracker.GetTrackedValidators(epoch)
	if err != nil {
		c.logger.Errorf("Failed to get tracked validators, bailing out: %v", err)
	}
	for _, status := range []string{StatusValid, StatusSkipped} {
		c.deleteMetricLabelValues(c.ClusterSlotsByEpochMetric, "cluster-slots-by-epoch", epochStr, status)
		for _, nodekey := range trackedNodekeys {
			c.deleteMetricLabelValues(c.LeaderSlotsByEpochMetric, "leader-slots-by-epoch", nodekey, epochStr, status)
		}
	}
	c.logger.Infof("Finished cleaning epoch %d", epoch)
}

// closeCurrentEpoch is called when an epoch change-over happens, and we need to make sure we track the last
// remaining slots in the "current" epoch before we start tracking the new one.
func (c *SlotWatcher) closeCurrentEpoch(ctx context.Context, newEpoch *rpc.EpochInfo) {
	c.logger.Infof("Closing current epoch %v, moving into epoch %v", c.currentEpoch, newEpoch.Epoch)
	if c.config.LightMode {
		// In light mode, we only need to update epoch tracking numbers
		c.trackEpoch(ctx, newEpoch)
		return
	}

	// fetch inflation rewards for epoch we about to close:
	if len(c.config.Votekeys) > 0 {
		if err := c.fetchAndEmitInflationRewards(ctx, c.currentEpoch); err != nil {
			c.logger.Errorf("Failed to emit inflation rewards, bailing out: %v", err)
		}
	}

	c.moveSlotWatermark(ctx, c.lastSlot)
	go c.cleanEpoch(ctx, c.currentEpoch)
	c.trackEpoch(ctx, newEpoch)
}

// checkValidSlotRange makes sure that the slot range we are going to query is within the current epoch we are tracking.
func (c *SlotWatcher) checkValidSlotRange(from, to int64) error {
	if from < c.firstSlot || to > c.lastSlot {
		return fmt.Errorf(
			"start-end slots (%v -> %v) is not contained within current epoch %v range (%v -> %v)",
			from,
			to,
			c.currentEpoch,
			c.firstSlot,
			c.lastSlot,
		)
	}
	return nil
}

// moveSlotWatermark performs all the slot-watching tasks required to move the slotWatermark to the provided 'to' slot.
func (c *SlotWatcher) moveSlotWatermark(ctx context.Context, to int64) {
	if c.config.LightMode {
		c.logger.Debugf("Skipping slot watermark movement in light mode (would move %v -> %v)", c.slotWatermark, to)
		c.slotWatermark = to
		return
	}
	c.logger.Infof("Moving watermark %v -> %v", c.slotWatermark, to)
	startSlot := c.slotWatermark + 1
	c.fetchAndEmitBlockProduction(ctx, startSlot, to)
	c.fetchAndEmitBlockInfos(ctx, startSlot, to)
	c.slotWatermark = to
}

// fetchAndEmitBlockProduction fetches block production from startSlot up to the provided endSlot [inclusive],
// and emits the prometheus metrics,
func (c *SlotWatcher) fetchAndEmitBlockProduction(ctx context.Context, startSlot, endSlot int64) {
	if c.config.LightMode {
		c.logger.Debug("Skipping block-production fetching in light mode.")
		return
	}
	c.logger.Debugf("Fetching block production in [%v -> %v]", startSlot, endSlot)

	// make sure the bounds are contained within the epoch we are currently watching:
	if err := c.checkValidSlotRange(startSlot, endSlot); err != nil {
		c.logger.Fatalf("invalid slot range: %v", err)
	}

	// fetch block production:
	blockProduction, err := c.client.GetBlockProduction(ctx, rpc.CommitmentFinalized, startSlot, endSlot)
	if err != nil {
		c.logger.Errorf("Failed to get block production, bailing out: %v", err)
		return
	}

	// emit the metrics:
	var (
		epochStr = toString(c.currentEpoch)
		nodekeys []string
	)
	for address, production := range blockProduction.ByIdentity {
		valid := float64(production.BlocksProduced)
		skipped := float64(production.LeaderSlots - production.BlocksProduced)

		c.LeaderSlotsMetric.WithLabelValues(address, StatusValid).Add(valid)
		c.LeaderSlotsMetric.WithLabelValues(address, StatusSkipped).Add(skipped)

		if slices.Contains(c.config.Nodekeys, address) || c.config.ComprehensiveSlotTracking {
			c.LeaderSlotsByEpochMetric.WithLabelValues(address, epochStr, StatusValid).Add(valid)
			c.LeaderSlotsByEpochMetric.WithLabelValues(address, epochStr, StatusSkipped).Add(skipped)
			nodekeys = append(nodekeys, address)
		}

		// additionally, track block production for the whole cluster:
		c.ClusterSlotsByEpochMetric.WithLabelValues(epochStr, StatusValid).Add(valid)
		c.ClusterSlotsByEpochMetric.WithLabelValues(epochStr, StatusSkipped).Add(skipped)
	}

	// update tracked nodekeys:
	c.nodekeyTracker.AddTrackedNodekeys(c.currentEpoch, nodekeys)

	c.logger.Debugf("Fetched block production in [%v -> %v]", startSlot, endSlot)
}

// fetchAndEmitBlockInfos fetches and emits all the fee rewards (+ block sizes) for the tracked addresses between the
// startSlot and endSlot [inclusive]
func (c *SlotWatcher) fetchAndEmitBlockInfos(ctx context.Context, startSlot, endSlot int64) {
	if c.config.LightMode {
		c.logger.Debug("Skipping block-infos fetching in light mode.")
		return
	}
	c.logger.Debugf("Fetching fee rewards in [%v -> %v]", startSlot, endSlot)

	if err := c.checkValidSlotRange(startSlot, endSlot); err != nil {
		c.logger.Fatalf("invalid slot range: %v", err)
	}
	scheduleToFetch := SelectFromSchedule(c.leaderSchedule, startSlot, endSlot)
	for nodekey, leaderSlots := range scheduleToFetch {
		if len(leaderSlots) == 0 {
			continue
		}

		c.logger.Infof("Fetching fee rewards for %v in [%v -> %v]: %v ...", nodekey, startSlot, endSlot, leaderSlots)
		for _, slot := range leaderSlots {
			err := c.fetchAndEmitSingleBlockInfo(ctx, nodekey, c.currentEpoch, slot)
			if err != nil {
				c.logger.Errorf("Failed to fetch fee rewards for %v at %v: %v", nodekey, slot, err)
			}
		}
	}

	c.logger.Debugf("Fetched fee rewards in [%v -> %v]", startSlot, endSlot)
}

// fetchAndEmitSingleBlockInfo fetches and emits the fee reward + block size for a single block.
func (c *SlotWatcher) fetchAndEmitSingleBlockInfo(
	ctx context.Context, nodekey string, epoch int64, slot int64,
) error {
	transactionDetails := "none"
	if c.config.MonitorBlockSizes {
		transactionDetails = "full"
	}
	block, err := c.client.GetBlock(ctx, rpc.CommitmentConfirmed, slot, transactionDetails)
	if err != nil {
		var rpcError *rpc.Error
		if errors.As(err, &rpcError) {
			// this is the error code for slot was skipped:
			if rpcError.Code == rpc.SlotSkippedCode && strings.Contains(rpcError.Message, "skipped") {
				c.logger.Infof("slot %v was skipped, no fee rewards.", slot)
				return nil
			}
		}
		return err
	}

	foundFeeReward := false
	for _, reward := range block.Rewards {
		if strings.ToLower(reward.RewardType) == "fee" {
			// make sure we haven't made a logic issue or something:
			assertf(
				reward.Pubkey == nodekey,
				"fetching fee reward for %v but got fee reward for %v",
				nodekey,
				reward.Pubkey,
			)
			amount := float64(reward.Lamports) / rpc.LamportsInSol
			c.FeeRewardsMetric.WithLabelValues(nodekey, toString(epoch)).Add(amount)
			foundFeeReward = true
		}
	}

	if !foundFeeReward {
		c.logger.Errorf("No fee reward for slot %d", slot)
	}

	// track block size:
	if c.config.MonitorBlockSizes {
		// now count and emit votes:
		voteCount, err := CountVoteTransactions(block)
		if err != nil {
			return err
		}
		c.BlockSizeMetric.WithLabelValues(nodekey, TransactionTypeVote).Set(float64(voteCount))
		nonVoteCount := len(block.Transactions) - voteCount
		c.BlockSizeMetric.WithLabelValues(nodekey, TransactionTypeNonVote).Set(float64(nonVoteCount))
	}
	return nil
}

// fetchAndEmitInflationRewards fetches and emits the inflation rewards for the configured inflationRewardAddresses
// at the provided epoch
func (c *SlotWatcher) fetchAndEmitInflationRewards(ctx context.Context, epoch int64) error {
	if c.config.LightMode {
		c.logger.Debug("Skipping inflation-rewards fetching in light mode.")
		return nil
	}
	c.logger.Infof("Fetching inflation reward for epoch %v ...", toString(epoch))
	rewardInfos, err := c.client.GetInflationReward(ctx, rpc.CommitmentConfirmed, c.config.Votekeys, epoch)
	if err != nil {
		return fmt.Errorf("error fetching inflation rewards: %w", err)
	}

	for i, rewardInfo := range rewardInfos {
		address := c.config.Votekeys[i]
		reward := float64(rewardInfo.Amount) / rpc.LamportsInSol
		c.InflationRewardsMetric.WithLabelValues(address, toString(epoch)).Add(reward)
	}
	c.logger.Infof("Fetched inflation reward for epoch %v.", epoch)
	return nil
}

func (c *SlotWatcher) deleteMetricLabelValues(metric *prometheus.CounterVec, name string, lvs ...string) {
	c.logger.Debugf("deleting %v with lv %v", name, lvs)
	if ok := metric.DeleteLabelValues(lvs...); !ok {
		c.logger.Errorf("Failed to delete %s with label values %v", name, lvs)
	}
}
