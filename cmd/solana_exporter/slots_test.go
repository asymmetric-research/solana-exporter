package main

import (
	"context"
	"fmt"
	"github.com/asymmetric-research/solana_exporter/pkg/rpc"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"regexp"
	"testing"
	"time"
)

type slotMetricValues struct {
	SlotHeight        float64
	TotalTransactions float64
	EpochNumber       float64
	EpochFirstSlot    float64
	EpochLastSlot     float64
	BlockHeight       float64
}

// extractName takes a Prometheus descriptor and returns its name
func extractName(desc *prometheus.Desc) string {
	// Get the string representation of the descriptor
	descString := desc.String()
	// Use regex to extract the metric name and help message from the descriptor string
	reName := regexp.MustCompile(`fqName: "([^"]+)"`)
	nameMatch := reName.FindStringSubmatch(descString)

	var name string
	if len(nameMatch) > 1 {
		name = nameMatch[1]
	}

	return name
}

func getSlotMetricValues(watcher *SlotWatcher) slotMetricValues {
	return slotMetricValues{
		SlotHeight:        testutil.ToFloat64(watcher.SlotHeightMetric),
		TotalTransactions: testutil.ToFloat64(watcher.TotalTransactionsMetric),
		EpochNumber:       testutil.ToFloat64(watcher.EpochNumberMetric),
		EpochFirstSlot:    testutil.ToFloat64(watcher.EpochFirstSlotMetric),
		EpochLastSlot:     testutil.ToFloat64(watcher.EpochLastSlotMetric),
		BlockHeight:       testutil.ToFloat64(watcher.BlockHeightMetric),
	}
}

func assertSlotMetricsChangeCorrectly(t *testing.T, initial slotMetricValues, final slotMetricValues) {
	// make sure that things have increased
	assert.Greaterf(t,
		final.SlotHeight,
		initial.SlotHeight,
		"Slot has not increased! (%v -> %v)",
		initial.SlotHeight, final.SlotHeight,
	)
	assert.Greaterf(t,
		final.TotalTransactions,
		initial.TotalTransactions,
		"Total transactions have not increased! (%v -> %v)",
		initial.TotalTransactions, final.TotalTransactions,
	)
	assert.GreaterOrEqualf(t,
		final.EpochNumber,
		initial.EpochNumber,
		"Epoch number has decreased! (%v -> %v)",
		initial.EpochNumber, final.EpochNumber,
	)
	assert.GreaterOrEqualf(t,
		final.EpochFirstSlot,
		initial.EpochFirstSlot,
		"Epoch first slot has decreased! (%v -> %v)",
		initial.EpochFirstSlot, final.EpochFirstSlot,
	)
	assert.GreaterOrEqualf(t,
		final.EpochLastSlot,
		initial.EpochLastSlot,
		"Epoch last slot has decreased! (%v -> %v)",
		initial.EpochLastSlot, final.EpochLastSlot,
	)
	assert.Greaterf(t,
		final.BlockHeight,
		initial.BlockHeight,
		"Block height has decreased! (%v -> %v)",
		initial.BlockHeight, final.BlockHeight,
	)
}

func TestSlotWatcher_WatchSlots_Static(t *testing.T) {
	// TODO: is this test necessary? If not - remove, else, could definitely do with a clean.

	ctx := context.Background()

	simulator, client := NewSimulator(t, 35)
	watcher := NewSlotWatcher(client, newTestConfig(simulator, true))
	// reset metrics before running tests:
	watcher.LeaderSlotsMetric.Reset()
	watcher.LeaderSlotsByEpochMetric.Reset()

	go watcher.WatchSlots(ctx)

	// make sure inflation rewards are collected:
	epochInfo, err := client.GetEpochInfo(ctx, rpc.CommitmentFinalized)
	assert.NoError(t, err)
	err = watcher.fetchAndEmitInflationRewards(ctx, epochInfo.Epoch)
	assert.NoError(t, err)
	time.Sleep(1 * time.Second)

	type testCase struct {
		expectedValue float64
		metric        prometheus.Gauge
	}

	// epoch info tests:
	firstSlot, lastSlot := GetEpochBounds(epochInfo)
	tests := []testCase{
		{expectedValue: float64(epochInfo.AbsoluteSlot), metric: watcher.SlotHeightMetric},
		{expectedValue: float64(epochInfo.TransactionCount), metric: watcher.TotalTransactionsMetric},
		{expectedValue: float64(epochInfo.Epoch), metric: watcher.EpochNumberMetric},
		{expectedValue: float64(firstSlot), metric: watcher.EpochFirstSlotMetric},
		{expectedValue: float64(lastSlot), metric: watcher.EpochLastSlotMetric},
	}

	// add inflation reward tests:
	inflationRewards, err := client.GetInflationReward(ctx, rpc.CommitmentFinalized, simulator.Votekeys, 2)
	assert.NoError(t, err)
	for i, rewardInfo := range inflationRewards {
		epoch := fmt.Sprintf("%v", epochInfo.Epoch)
		tests = append(
			tests,
			testCase{
				expectedValue: float64(rewardInfo.Amount) / float64(rpc.LamportsInSol),
				metric:        watcher.InflationRewardsMetric.WithLabelValues(simulator.Votekeys[i], epoch),
			},
		)
	}

	for _, testCase := range tests {
		name := extractName(testCase.metric.Desc())
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, testCase.expectedValue, testutil.ToFloat64(testCase.metric))
		})
	}
}

func TestSlotWatcher_WatchSlots_Dynamic(t *testing.T) {
	// TODO: figure out how to get rid of the error logs that happen when this test closes.
	//  This is presumably due to the context cancelling mid-execution of a WatchSlots() iteration

	// create clients:
	simulator, client := NewSimulator(t, 23)
	watcher := NewSlotWatcher(client, newTestConfig(simulator, true))
	// reset metrics before running tests:
	watcher.LeaderSlotsMetric.Reset()
	watcher.LeaderSlotsByEpochMetric.Reset()

	// start client/collector and wait a bit:
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watcher.WatchSlots(ctx)
	time.Sleep(time.Second)

	go simulator.Run(ctx)
	time.Sleep(time.Second)

	initial := getSlotMetricValues(watcher)

	// wait a bit:
	var epochChanged bool
	for i := 0; i < 5; i++ {
		// wait a bit then get new metrics
		time.Sleep(time.Second)
		final := getSlotMetricValues(watcher)

		// make sure things are changing correctly:
		assertSlotMetricsChangeCorrectly(t, initial, final)

		// sense check to make sure the exporter is not "ahead" of the client (due to double counting or whatever)
		assert.LessOrEqualf(t,
			int(final.SlotHeight),
			simulator.Slot,
			"Exporter slot (%v) ahead of simulator slot (%v)!",
			int(final.SlotHeight), simulator.Slot,
		)
		assert.LessOrEqualf(t,
			int(final.TotalTransactions),
			simulator.TransactionCount,
			"Exporter transaction count (%v) ahead of simulator transaction count (%v)!",
			int(final.TotalTransactions), simulator.TransactionCount,
		)
		assert.LessOrEqualf(t,
			int(final.EpochNumber),
			simulator.Epoch,
			"Exporter epoch (%v) ahead of simulator epoch (%v)!",
			int(final.EpochNumber), simulator.Epoch,
		)

		// check block sizes (should always be the same due to simulator design:
		for _, nodekey := range simulator.Nodekeys {
			assert.Equalf(t,
				float64(2),
				testutil.ToFloat64(watcher.BlockSizeMetric.WithLabelValues(nodekey, TransactionTypeNonVote)),
				"Incorrect %s block size for %s",
				TransactionTypeNonVote, nodekey,
			)
			assert.Equalf(t,
				float64(3),
				testutil.ToFloat64(watcher.BlockSizeMetric.WithLabelValues(nodekey, TransactionTypeVote)),
				"Incorrect %s block size for %s",
				TransactionTypeVote, nodekey,
			)
		}

		// check if epoch changed
		if final.EpochNumber > initial.EpochNumber {
			epochChanged = true

			// run some tests for the previous epoch:
			leaderSlotsPerEpoch := simulator.EpochSize / len(simulator.Nodekeys)
			for i, nodekey := range simulator.Nodekeys {
				// leader slots per epoch:
				assert.Equalf(t,
					float64(leaderSlotsPerEpoch*3/4),
					testutil.ToFloat64(
						watcher.LeaderSlotsByEpochMetric.WithLabelValues(nodekey, toString(initial.EpochNumber), StatusValid),
					),
					"Incorrect %s leader slots for %s at epoch %v",
					StatusValid, nodekey, initial.EpochNumber,
				)
				assert.Equalf(t,
					float64(leaderSlotsPerEpoch*1/4),
					testutil.ToFloat64(
						watcher.LeaderSlotsByEpochMetric.WithLabelValues(nodekey, toString(initial.EpochNumber), StatusSkipped),
					),
					"Incorrect %s leader slots for %s at epoch %v",
					StatusSkipped, nodekey, initial.EpochNumber,
				)

				// inflation rewards:
				votekey := simulator.Votekeys[i]
				assert.Equalf(t,
					float64(InflationRewardLamports)/rpc.LamportsInSol,
					testutil.ToFloat64(
						watcher.InflationRewardsMetric.WithLabelValues(votekey, toString(initial.EpochNumber)),
					),
					"Incorrect inflation reward for %s at epoch %v",
					votekey, initial.EpochNumber,
				)

				// fee rewards:
				assert.Equalf(t,
					float64(FeeRewardLamports*leaderSlotsPerEpoch*3/4)/rpc.LamportsInSol,
					testutil.ToFloat64(
						watcher.FeeRewardsMetric.WithLabelValues(nodekey, toString(initial.EpochNumber)),
					),
					"Incorrect fee reward for %s at epoch %v",
					nodekey, initial.EpochNumber,
				)
			}
		}

		// make current final the new initial (for next iteration)
		initial = final
	}

	// epoch should have changed somewhere
	assert.Truef(t, epochChanged, "Epoch has not changed!")
}
