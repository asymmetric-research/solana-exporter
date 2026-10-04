package main

import (
	"context"
	"testing"
	"time"

	"github.com/asymmetric-research/solana-exporter/pkg/rpc"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// mockVoteAccounts formats a getMultipleAccounts result holding vote accounts with the given credits.
func mockVoteAccounts(slot int, nodekeys []string, credits []int) map[string]any {
	accounts := make([]any, len(nodekeys))
	for i, nodekey := range nodekeys {
		accounts[i] = map[string]any{
			"data": map[string]any{
				"parsed": map[string]any{
					"type": "vote",
					"info": map[string]any{
						"nodePubkey":   nodekey,
						"epochCredits": []map[string]any{{"epoch": 0, "credits": toString(credits[i])}},
					},
				},
				"program": "vote",
			},
		}
	}
	return map[string]any{"context": map[string]int{"slot": slot}, "value": accounts}
}

func TestVoteInclusionWatcher(t *testing.T) {
	validators := map[string]rpc.MockValidatorInfo{
		"aaa": {Votekey: "AAA", Stake: 3_000},
		"bbb": {Votekey: "BBB", Stake: 2_000},
		"ccc": {Votekey: "CCC", Stake: 1_000},
	}
	server, client := rpc.NewMockClient(t, rpc.MockConfig{
		EasyResults: map[string]any{
			"getEpochSchedule":  map[string]any{"slotsPerEpoch": 1000, "warmup": false},
			"getLeaderSchedule": map[string]any{"aaa": []int{900}, "bbb": []int{}, "ccc": []int{}},
		},
		ValidatorInfos: validators,
	})
	config := &ExporterConfig{
		Votekeys: []string{"AAA"}, SlotPace: time.Second, MonitorAlpenglowVoteInclusion: true, AlpenglowReferenceCount: 2,
	}
	watcher := NewVoteInclusionWatcher(client, config)
	ctx := context.Background()

	// per-slot rewards: AAA 30, BBB 20, CCC 10.
	observations := []struct {
		slot    int
		credits []int // AAA, BBB, CCC
	}{
		{100, []int{0}}, // first run: only the monitored account, references are picked afterwards
		{101, []int{30, 0, 0}},
		{102, []int{60, 20, 10}},     // one slot: everybody included, rates learnt
		{105, []int{90, 80, 40}},     // three slots: AAA in 1, BBB in 3
		{110, []int{90, 180, 90}},    // five slots: AAA down
		{901, []int{9999, 999, 999}}, // contains AAA's leader slot 900
	}
	for _, o := range observations {
		nodekeys := []string{"aaa", "bbb", "ccc"}[:len(o.credits)]
		server.SetOpt(rpc.EasyResultsOpt, "getMultipleAccounts", mockVoteAccounts(o.slot, nodekeys, o.credits))
		if err := watcher.observe(ctx); err != nil {
			t.Fatalf("observe() at slot %d: %v", o.slot, err)
		}
	}

	tests := []struct {
		name string
		got  float64
		want float64
	}{
		{"references", testutil.ToFloat64(watcher.ReferenceValidatorsMetric), 2},
		{"included", testutil.ToFloat64(watcher.RewardSlotsMetric.WithLabelValues("AAA", StatusIncluded)), 3},
		{"missed", testutil.ToFloat64(watcher.RewardSlotsMetric.WithLabelValues("AAA", StatusMissed)), 7},
		{"last included", testutil.ToFloat64(watcher.LastIncludedSlotMetric.WithLabelValues("AAA")), 105},
		{"credits per slot", testutil.ToFloat64(watcher.CreditsPerRewardSlot.WithLabelValues("AAA")), 30},
		{"observed slot", testutil.ToFloat64(watcher.ObservedSlotMetric), 901},
		{
			"leader gap",
			testutil.ToFloat64(watcher.UnattributedSlotsMetric.WithLabelValues("AAA", "leader")),
			901 - 110,
		},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s: got %v, want %v", tt.name, tt.got, tt.want)
		}
	}
}
