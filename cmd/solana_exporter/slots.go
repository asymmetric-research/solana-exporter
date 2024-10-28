package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/asymmetric-research/solana_exporter/pkg/slog"
	"go.uber.org/zap"
	"slices"
	"strings"
	"time"

	"github.com/asymmetric-research/solana_exporter/pkg/rpc"
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

	// prometheus:
	TotalTransactionsMetric  prometheus.Gauge
	SlotHeightMetric         prometheus.Gauge
	EpochNumberMetric        prometheus.Gauge
	EpochFirstSlotMetric     prometheus.Gauge
	EpochLastSlotMetric      prometheus.Gauge
	LeaderSlotsMetric        *prometheus.CounterVec
	LeaderSlotsByEpochMetric *prometheus.CounterVec
	InflationRewardsMetric   *prometheus.GaugeVec
	FeeRewardsMetric         *prometheus.CounterVec
	BlockSizeMetric          *prometheus.GaugeVec
	BlockHeightMetric        prometheus.Gauge
}

func NewSlotWatcher(client *rpc.Client, config *ExporterConfig) *SlotWatcher {
	logger := slog.Get()
	watcher := SlotWatcher{
		client: client,
		logger: logger,
		config: config,
		// metrics:
		TotalTransactionsMetric: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "solana_total_transactions",
			Help: "Total number of transactions processed without error since genesis.",
		}),
		SlotHeightMetric: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "solana_slot_height",
			Help: "The current slot number",
		}),
		EpochNumberMetric: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "solana_epoch_number",
			Help: "The current epoch number.",
		}),
		EpochFirstSlotMetric: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "solana_epoch_first_slot",
			Help: "Current epoch's first slot [inclusive].",
		}),
		EpochLastSlotMetric: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "solana_epoch_last_slot",
			Help: "Current epoch's last slot [inclusive].",
		}),
		LeaderSlotsMetric: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "solana_leader_slots",
				Help: fmt.Sprintf(
					"Number of slots processed, grouped by %s, and %s ('%s' or '%s')",
					NodekeyLabel, SkipStatusLabel, StatusValid, StatusSkipped,
				),
			},
			[]string{NodekeyLabel, SkipStatusLabel},
		),
		LeaderSlotsByEpochMetric: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "solana_leader_slots_by_epoch",
				Help: fmt.Sprintf(
					"Number of slots processed, grouped by %s, %s ('%s' or '%s'), and %s",
					NodekeyLabel, SkipStatusLabel, StatusValid, StatusSkipped, EpochLabel,
				),
			},
			[]string{NodekeyLabel, EpochLabel, SkipStatusLabel},
		),
		InflationRewardsMetric: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "solana_inflation_rewards",
				Help: fmt.Sprintf("Inflation reward earned, grouped by %s and %s", VotekeyLabel, EpochLabel),
			},
			[]string{VotekeyLabel, EpochLabel},
		),
		FeeRewardsMetric: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "solana_fee_rewards",
				Help: fmt.Sprintf("Transaction fee rewards earned, grouped by %s and %s", NodekeyLabel, EpochLabel),
			},
			[]string{NodekeyLabel, EpochLabel},
		),
		BlockSizeMetric: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "solana_block_size",
				Help: fmt.Sprintf("Number of transactions per block, grouped by %s", NodekeyLabel),
			},
			[]string{NodekeyLabel, TransactionTypeLabel},
		),
		BlockHeightMetric: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "solana_block_height",
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
				// fetch inflation rewards for vote accounts:
				if len(c.config.VoteKeys) > 0 {
					err = c.fetchAndEmitInflationRewards(ctx, c.currentEpoch)
					if err != nil {
						c.logger.Errorf("Failed to emit inflation rewards, bailing out: %v", err)
					}
				}
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
	c.logger.Infof("Updating leader schedule for epoch %v ...", c.currentEpoch)
	leaderSchedule, err := GetTrimmedLeaderSchedule(ctx, c.client, c.config.NodeKeys, epoch.AbsoluteSlot, c.firstSlot)
	if err != nil {
		c.logger.Errorf("Failed to get trimmed leader schedule, bailing out: %v", err)
	}
	c.leaderSchedule = leaderSchedule
}

// closeCurrentEpoch is called when an epoch change-over happens, and we need to make sure we track the last
// remaining slots in the "current" epoch before we start tracking the new one.
func (c *SlotWatcher) closeCurrentEpoch(ctx context.Context, newEpoch *rpc.EpochInfo) {
	c.logger.Infof("Closing current epoch %v, moving into epoch %v", c.currentEpoch, newEpoch.Epoch)
	c.moveSlotWatermark(ctx, c.lastSlot)
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
	c.fetchAndEmitBlockProduction(ctx, to)
	c.fetchAndEmitBlockInfos(ctx, to)
	c.slotWatermark = to
}

// fetchAndEmitBlockProduction fetches block production up to the provided endSlot, emits the prometheus metrics,
// and updates the SlotWatcher.slotWatermark accordingly
func (c *SlotWatcher) fetchAndEmitBlockProduction(ctx context.Context, endSlot int64) {
	if c.config.LightMode {
		c.logger.Debug("Skipping block-production fetching in light mode.")
		return
	}
	// add 1 because GetBlockProduction's range is inclusive, and the watermark is already tracked
	startSlot := c.slotWatermark + 1
	c.logger.Infof("Fetching block production in [%v -> %v]", startSlot, endSlot)

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
	for address, production := range blockProduction.ByIdentity {
		valid := float64(production.BlocksProduced)
		skipped := float64(production.LeaderSlots - production.BlocksProduced)

		c.LeaderSlotsMetric.WithLabelValues(address, StatusValid).Add(valid)
		c.LeaderSlotsMetric.WithLabelValues(address, StatusSkipped).Add(skipped)

		if slices.Contains(c.config.NodeKeys, address) || c.config.ComprehensiveSlotTracking {
			epochStr := toString(c.currentEpoch)
			c.LeaderSlotsByEpochMetric.WithLabelValues(address, epochStr, StatusValid).Add(valid)
			c.LeaderSlotsByEpochMetric.WithLabelValues(address, epochStr, StatusSkipped).Add(skipped)
		}
	}

	c.logger.Infof("Fetched block production in [%v -> %v]", startSlot, endSlot)
}

// fetchAndEmitBlockInfos fetches and emits all the fee rewards (+ block sizes) for the tracked addresses between the
// slotWatermark and endSlot
func (c *SlotWatcher) fetchAndEmitBlockInfos(ctx context.Context, endSlot int64) {
	if c.config.LightMode {
		c.logger.Debug("Skipping block-infos fetching in light mode.")
		return
	}
	startSlot := c.slotWatermark + 1
	c.logger.Infof("Fetching fee rewards in [%v -> %v]", startSlot, endSlot)

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

	c.logger.Infof("Fetched fee rewards in [%v -> %v]", startSlot, endSlot)
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
		var rpcError *rpc.RPCError
		if errors.As(err, &rpcError) {
			// this is the error code for slot was skipped:
			if rpcError.Code == rpc.SlotSkippedCode && strings.Contains(rpcError.Message, "skipped") {
				c.logger.Infof("slot %v was skipped, no fee rewards.", slot)
				return nil
			}
		}
		return err
	}

	for _, reward := range block.Rewards {
		if reward.RewardType == "fee" {
			// make sure we haven't made a logic issue or something:
			assertf(
				reward.Pubkey == nodekey,
				"fetching fee reward for %v but got fee reward for %v",
				nodekey,
				reward.Pubkey,
			)
			amount := float64(reward.Lamports) / float64(rpc.LamportsInSol)
			c.FeeRewardsMetric.WithLabelValues(nodekey, toString(epoch)).Add(amount)
		}
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
	rewardInfos, err := c.client.GetInflationReward(ctx, rpc.CommitmentConfirmed, c.config.VoteKeys, epoch)
	if err != nil {
		return fmt.Errorf("error fetching inflation rewards: %w", err)
	}

	for i, rewardInfo := range rewardInfos {
		address := c.config.VoteKeys[i]
		reward := float64(rewardInfo.Amount) / float64(rpc.LamportsInSol)
		c.InflationRewardsMetric.WithLabelValues(address, toString(epoch)).Set(reward)
	}
	c.logger.Infof("Fetched inflation reward for epoch %v.", epoch)
	return nil
}
