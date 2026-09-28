package main

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"math/rand"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/asymmetric-research/solana-exporter/pkg/rpc"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type (
	Simulator struct {
		Server *rpc.MockServer

		Slot             int
		BlockHeight      int
		Epoch            int
		TransactionCount int

		// constants for the simulator
		SlotTime                time.Duration
		EpochSize               int
		LeaderSchedule          map[string][]int
		Nodekeys                []string
		Votekeys                []string
		FeeRewardLamports       int
		InflationRewardLamports int
		LastVoteDistances       map[string]int
		RootSlotDistances       map[string]int
	}
)

func NewSimulator(t *testing.T, slot int) (*Simulator, *rpc.Client) {
	nodekeys := []string{"aaa", "bbb", "ccc"}
	votekeys := []string{"AAA", "BBB", "CCC"}
	// "ccc" deliberately has no BLS pubkey set:
	blsPubkeys := []string{"blsAAA", "blsBBB", ""}
	feeRewardLamports, inflationRewardLamports := 10, 10

	validatorInfos := make(map[string]rpc.MockValidatorInfo)
	for i, nodekey := range nodekeys {
		validatorInfos[nodekey] = rpc.MockValidatorInfo{
			Votekey:    votekeys[i],
			Stake:      1_000_000,
			Delinquent: false,
			Commission: 11,
			BlsPubkey:  blsPubkeys[i],
		}
	}
	leaderSchedule := map[string][]int{
		"aaa": {0, 1, 2, 3, 12, 13, 14, 15},
		"bbb": {4, 5, 6, 7, 16, 17, 18, 19},
		"ccc": {8, 9, 10, 11, 20, 21, 22, 23},
	}
	mockServer, client := rpc.NewMockClient(t, rpc.MockConfig{
		EasyResults: map[string]any{
			"getVersion":        map[string]string{"solana-core": "v1.0.0"},
			"getIdentity":       map[string]string{"identity": "testIdentity"},
			"getLeaderSchedule": leaderSchedule,
			"getHealth":         "ok",
		},
		Balances: map[string]int{
			"aaa": 1 * rpc.LamportsInSol,
			"bbb": 2 * rpc.LamportsInSol,
			"ccc": 3 * rpc.LamportsInSol,
			"AAA": 4 * rpc.LamportsInSol,
			"BBB": 5 * rpc.LamportsInSol,
			"CCC": 6 * rpc.LamportsInSol,
		},
		InflationRewards: map[string]int{
			"AAA": inflationRewardLamports,
			"BBB": inflationRewardLamports,
			"CCC": inflationRewardLamports,
		},
		ValidatorInfos: validatorInfos,
	})
	simulator := Simulator{
		Slot:                    0,
		Server:                  mockServer,
		EpochSize:               24,
		SlotTime:                100 * time.Millisecond,
		LeaderSchedule:          leaderSchedule,
		Nodekeys:                nodekeys,
		Votekeys:                votekeys,
		InflationRewardLamports: inflationRewardLamports,
		FeeRewardLamports:       feeRewardLamports,
		LastVoteDistances:       map[string]int{"aaa": 1, "bbb": 2, "ccc": 3},
		RootSlotDistances:       map[string]int{"aaa": 4, "bbb": 5, "ccc": 6},
	}
	simulator.PopulateSlot(0)
	if slot > 0 {
		for {
			simulator.Slot++
			simulator.PopulateSlot(simulator.Slot)
			if simulator.Slot == slot {
				break
			}
		}
	}

	return &simulator, client
}

func (c *Simulator) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return

		default:
			c.Slot++
			c.PopulateSlot(c.Slot)
			// add 5% noise to the slot time:
			noiseRange := float64(c.SlotTime) * 0.05
			noise := (rand.Float64()*2 - 1) * noiseRange
			time.Sleep(c.SlotTime + time.Duration(noise))
		}
	}
}

func (c *Simulator) getLeader() string {
	index := c.Slot % c.EpochSize
	for leader, slots := range c.LeaderSchedule {
		if slices.Contains(slots, index) {
			return leader
		}
	}
	panic(fmt.Sprintf("leader not found at slot %d", c.Slot))
}

func (c *Simulator) PopulateSlot(slot int) {
	leader := c.getLeader()

	var block *rpc.MockBlockInfo
	// every 4th slot is skipped
	if slot%4 != 3 {
		c.BlockHeight++
		// only add some transactions if a block was produced
		transactions := [][]string{
			{"aaa", "bbb", "ccc"},
			{"xxx", "yyy", "zzz"},
		}
		// assume all validators voted
		for _, nodekey := range c.Nodekeys {
			transactions = append(transactions, []string{nodekey, strings.ToUpper(nodekey), VoteProgram})
			info := c.Server.GetValidatorInfo(nodekey)
			info.LastVote = max(0, slot-c.LastVoteDistances[nodekey])
			info.RootSlot = max(0, slot-c.RootSlotDistances[nodekey])
			c.Server.SetOpt(rpc.ValidatorInfoOpt, nodekey, info)
		}

		c.TransactionCount += len(transactions)
		block = &rpc.MockBlockInfo{Fee: c.FeeRewardLamports, Transactions: transactions}
	}
	// add slot info:
	c.Server.SetOpt(rpc.SlotInfosOpt, slot, rpc.MockSlotInfo{Leader: leader, Block: block})

	// now update the server:
	c.Epoch = int(math.Floor(float64(slot) / float64(c.EpochSize)))
	c.Server.SetOpt(
		rpc.EasyResultsOpt,
		"getSlot",
		slot,
	)
	c.Server.SetOpt(
		rpc.EasyResultsOpt,
		"getEpochInfo",
		map[string]int{
			"absoluteSlot":     slot,
			"blockHeight":      c.BlockHeight,
			"epoch":            c.Epoch,
			"slotIndex":        slot % c.EpochSize,
			"slotsInEpoch":     c.EpochSize,
			"transactionCount": c.TransactionCount,
		},
	)
	c.Server.SetOpt(
		rpc.EasyResultsOpt,
		"minimumLedgerSlot",
		int(math.Max(0, float64(slot-c.EpochSize))),
	)
	c.Server.SetOpt(
		rpc.EasyResultsOpt,
		"getFirstAvailableBlock",
		int(math.Max(0, float64(slot-c.EpochSize))),
	)
}

func newTestConfig(simulator *Simulator, fast bool) *ExporterConfig {
	pace := time.Duration(100) * time.Second
	if fast {
		pace = time.Duration(500) * time.Millisecond
	}
	config := ExporterConfig{
		HTTPTimeout:                      time.Second * time.Duration(1),
		RPCURL:                           simulator.Server.URL(),
		ListenAddress:                    ":8080",
		Nodekeys:                         simulator.Nodekeys,
		Votekeys:                         simulator.Votekeys,
		BalanceAddresses:                 nil,
		ComprehensiveSlotTracking:        true,
		ComprehensiveVoteAccountTracking: true,
		MonitorBlockSizes:                true,
		LightMode:                        false,
		SlotPace:                         pace,
		ActiveIdentity:                   simulator.Nodekeys[0],
		// we need to set the epoch cleanup time to long enough such that we can test that the final state for the
		// previous epoch is correct before cleaning it. Ideally I would like a better way of doing this than simply
		// "waiting long enough", but this should do for now
		EpochCleanupTime: 5 * time.Second,
	}
	return &config
}

// runCollectionTests asserts that each collectionTest's metric collects to its expected exposition text.
func runCollectionTests(t *testing.T, collector prometheus.Collector, tests []collectionTest) {
	t.Helper()
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			err := testutil.CollectAndCompare(collector, bytes.NewBufferString(test.ExpectedResponse), test.Name)
			assert.NoErrorf(t, err, "unexpected collecting result for %s: \n%s", test.Name, err)
		})
	}
}

func TestSolanaCollector(t *testing.T) {
	simulator, client := NewSimulator(t, 35)
	simulator.Server.SetOpt(rpc.EasyResultsOpt, "getGenesisHash", rpc.MainnetGenesisHash)

	collector := NewSolanaCollector(client, newTestConfig(simulator, false))
	prometheus.NewPedanticRegistry().MustRegister(collector)

	stake := float64(1_000_000) / rpc.LamportsInSol

	testCases := []collectionTest{
		collector.ValidatorActiveStake.makeCollectionTest(
			NewLV(stake, "aaa", "AAA"),
			NewLV(stake, "bbb", "BBB"),
			NewLV(stake, "ccc", "CCC"),
		),
		collector.ClusterActiveStake.makeCollectionTest(
			NewLV(3 * stake),
		),
		collector.ValidatorLastVote.makeCollectionTest(
			NewLV(33, "aaa", "AAA"),
			NewLV(32, "bbb", "BBB"),
			NewLV(31, "ccc", "CCC"),
		),
		collector.ClusterLastVote.makeCollectionTest(
			NewLV(33),
		),
		collector.ValidatorRootSlot.makeCollectionTest(
			NewLV(30, "aaa", "AAA"),
			NewLV(29, "bbb", "BBB"),
			NewLV(28, "ccc", "CCC"),
		),
		collector.ClusterRootSlot.makeCollectionTest(
			NewLV(30),
		),
		collector.ValidatorDelinquent.makeCollectionTest(
			NewLV(0, "aaa", "AAA"),
			NewLV(0, "bbb", "BBB"),
			NewLV(0, "ccc", "CCC"),
		),
		collector.ClusterValidatorCount.makeCollectionTest(
			NewLV(3, StateCurrent),
			NewLV(0, StateDelinquent),
		),
		collector.NodeVersion.makeCollectionTest(
			NewLV(1, "v1.0.0"),
		),
		collector.NodeIdentity.makeCollectionTest(
			NewLV(1, "testIdentity"),
		),
		collector.NodeIsActive.makeCollectionTest(
			NewLV(0, "testIdentity"),
		),
		collector.NodeIsHealthy.makeCollectionTest(
			NewLV(1),
		),
		collector.NodeNumSlotsBehind.makeCollectionTest(
			NewLV(0),
		),
		collector.AccountBalances.makeCollectionTest(
			NewLV(4, "AAA"),
			NewLV(5, "BBB"),
			NewLV(6, "CCC"),
			NewLV(1, "aaa"),
			NewLV(2, "bbb"),
			NewLV(3, "ccc"),
		),
		collector.NodeMinimumLedgerSlot.makeCollectionTest(
			NewLV(11),
		),
		collector.NodeFirstAvailableBlock.makeCollectionTest(
			NewLV(11),
		),
		collector.ValidatorCommission.makeCollectionTest(
			NewLV(11, "aaa", "AAA"),
			NewLV(11, "bbb", "BBB"),
			NewLV(11, "ccc", "CCC"),
		),
		collector.ValidatorBlsPubkeySet.makeCollectionTest(
			NewLV(1, "aaa", "AAA"),
			NewLV(1, "bbb", "BBB"),
			NewLV(0, "ccc", "CCC"),
		),
	}

	runCollectionTests(t, collector, testCases)
}

func TestSolanaCollector_collectHealth(t *testing.T) {
	simulator, client := NewSimulator(t, 0)

	collector := NewSolanaCollector(client, newTestConfig(simulator, false))
	prometheus.NewPedanticRegistry().MustRegister(collector)

	t.Run("healthy", func(t *testing.T) {
		runCollectionTests(t, collector, []collectionTest{
			collector.NodeIsHealthy.makeCollectionTest(NewLV(1)),
			collector.NodeNumSlotsBehind.makeCollectionTest(NewLV(0)),
		})
	})

	getHealthErr := rpc.Error{
		Code:    rpc.NodeUnhealthyCode,
		Method:  "getHealth",
		Message: "Node is unhealthy",
		Data:    map[string]any{"numSlotsBehind": 42},
	}

	// TODO: when I try test the generic case, it fails because of the error emitted to the
	//  solana_node_num_slots_behind metric
	t.Run("unhealthy", func(t *testing.T) {
		simulator.Server.SetOpt(rpc.EasyErrorsOpt, "getHealth", getHealthErr)

		runCollectionTests(t, collector, []collectionTest{
			collector.NodeIsHealthy.makeCollectionTest(NewLV(0)),
		})
	})
}

// collectToSlice runs a single collect method and returns everything it emitted to the channel.
func collectToSlice(collect func(context.Context, chan<- prometheus.Metric)) []prometheus.Metric {
	ch := make(chan prometheus.Metric, 32)
	collect(context.Background(), ch)
	close(ch)
	var metrics []prometheus.Metric
	for m := range ch {
		metrics = append(metrics, m)
	}
	return metrics
}

// TestSolanaCollector_collectErrorPaths checks that when an RPC call fails, each collector degrades gracefully by
// emitting an invalid metric (which surfaces the error on scrape) rather than panicking or reporting a bogus value.
func TestSolanaCollector_collectErrorPaths(t *testing.T) {
	tests := []struct {
		name   string
		method string
		pick   func(*SolanaCollector) func(context.Context, chan<- prometheus.Metric)
	}{
		{"version", "getVersion", func(c *SolanaCollector) func(context.Context, chan<- prometheus.Metric) { return c.collectVersion }},
		{"identity", "getIdentity", func(c *SolanaCollector) func(context.Context, chan<- prometheus.Metric) { return c.collectIdentity }},
		{"minimum ledger slot", "minimumLedgerSlot", func(c *SolanaCollector) func(context.Context, chan<- prometheus.Metric) {
			return c.collectMinimumLedgerSlot
		}},
		{"first available block", "getFirstAvailableBlock", func(c *SolanaCollector) func(context.Context, chan<- prometheus.Metric) {
			return c.collectFirstAvailableBlock
		}},
		{"vote accounts", "getVoteAccounts", func(c *SolanaCollector) func(context.Context, chan<- prometheus.Metric) { return c.collectVoteAccounts }},
		{"balances", "getBalance", func(c *SolanaCollector) func(context.Context, chan<- prometheus.Metric) { return c.collectBalances }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			simulator, client := NewSimulator(t, 0)
			simulator.Server.SetOpt(rpc.EasyErrorsOpt, tt.method, rpc.Error{
				Code:    -32000,
				Method:  tt.method,
				Message: "simulated failure",
			})
			collector := NewSolanaCollector(client, newTestConfig(simulator, false))

			metrics := collectToSlice(tt.pick(collector))
			require.NotEmpty(t, metrics, "expected at least one metric to be emitted on RPC failure")
			for _, m := range metrics {
				// prometheus.NewInvalidMetric returns its wrapped error from Write.
				assert.Error(t, m.Write(&dto.Metric{}), "expected an invalid metric on RPC error")
			}
		})
	}
}

// TestSolanaCollector_collectVoteAccounts_delinquent checks that a delinquent validator is reported as delinquent and
// counted in the delinquent cluster bucket rather than the current one.
func TestSolanaCollector_collectVoteAccounts_delinquent(t *testing.T) {
	simulator, client := NewSimulator(t, 35)
	// move validator "ccc" into the delinquent set:
	info := simulator.Server.GetValidatorInfo("ccc")
	info.Delinquent = true
	simulator.Server.SetOpt(rpc.ValidatorInfoOpt, "ccc", info)

	collector := NewSolanaCollector(client, newTestConfig(simulator, false))
	prometheus.NewPedanticRegistry().MustRegister(collector)

	runCollectionTests(t, collector, []collectionTest{
		collector.ValidatorDelinquent.makeCollectionTest(
			NewLV(0, "aaa", "AAA"),
			NewLV(0, "bbb", "BBB"),
			NewLV(1, "ccc", "CCC"),
		),
		collector.ClusterValidatorCount.makeCollectionTest(
			NewLV(2, StateCurrent),
			NewLV(1, StateDelinquent),
		),
	})
}

// TestSolanaCollector_LightMode verifies that light mode exports only node-local metrics (health, version, identity)
// and skips everything observable from any RPC node (stake, balances, ledger slots, vote accounts).
func TestSolanaCollector_LightMode(t *testing.T) {
	simulator, client := NewSimulator(t, 35)

	config := newTestConfig(simulator, false)
	config.LightMode = true
	config.ComprehensiveSlotTracking = false
	config.ComprehensiveVoteAccountTracking = false
	config.MonitorBlockSizes = false
	config.Nodekeys = nil
	config.Votekeys = nil
	config.BalanceAddresses = nil
	config.ActiveIdentity = ""

	collector := NewSolanaCollector(client, config)
	prometheus.NewPedanticRegistry().MustRegister(collector)

	t.Run("node-local metrics are exported", func(t *testing.T) {
		runCollectionTests(t, collector, []collectionTest{
			collector.NodeVersion.makeCollectionTest(NewLV(1, "v1.0.0")),
			collector.NodeIdentity.makeCollectionTest(NewLV(1, "testIdentity")),
			collector.NodeIsHealthy.makeCollectionTest(NewLV(1)),
			collector.NodeNumSlotsBehind.makeCollectionTest(NewLV(0)),
		})
	})

	t.Run("cluster-observable metrics are skipped", func(t *testing.T) {
		skipped := []*GaugeDesc{
			collector.ValidatorActiveStake,
			collector.ClusterActiveStake,
			collector.ValidatorDelinquent,
			collector.AccountBalances,
			collector.NodeMinimumLedgerSlot,
			collector.NodeFirstAvailableBlock,
		}
		for _, desc := range skipped {
			t.Run(desc.Name, func(t *testing.T) {
				// an empty expected body means the metric must produce no samples at all
				err := testutil.CollectAndCompare(collector, bytes.NewBufferString(""), desc.Name)
				assert.NoErrorf(t, err, "expected %s to be skipped in light mode", desc.Name)
			})
		}
	})
}
