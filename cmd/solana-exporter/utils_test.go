package main

import (
	_ "embed"
	"encoding/json"
	"sort"
	"testing"

	"github.com/asymmetric-research/solana-exporter/pkg/rpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSelectFromSchedule(t *testing.T) {
	selected := SelectFromSchedule(
		map[string][]int64{
			"aaa": {0, 3, 6, 9, 12},
			"bbb": {1, 4, 7, 10, 13},
			"ccc": {2, 5, 8, 11, 14},
		},
		5,
		10,
	)
	assert.Equal(t,
		map[string][]int64{"aaa": {6, 9}, "bbb": {7, 10}, "ccc": {5, 8}},
		selected,
	)
}

func TestGetTrimmedLeaderSchedule(t *testing.T) {
	_, client := rpc.NewMockClient(t, rpc.MockConfig{
		EasyResults: map[string]any{
			"getLeaderSchedule": map[string]any{
				"aaa": []int{0, 3, 6, 9, 12},
				"bbb": []int{1, 4, 7, 10, 13},
				"ccc": []int{2, 5, 8, 11, 14},
			},
		},
	})
	ctx := t.Context()

	schedule, err := GetTrimmedLeaderSchedule(ctx, client, []string{"aaa", "bbb"}, 10, 10)
	require.NoError(t, err)
	assert.Equal(t, map[string][]int64{"aaa": {10, 13, 16, 19, 22}, "bbb": {11, 14, 17, 20, 23}}, schedule)
}

func TestCombineUnique(t *testing.T) {
	var (
		v1 = []string{"1", "2", "3"}
		v2 = []string{"2", "3", "4"}
		v3 = []string{"3", "4", "5"}
	)

	assert.Equal(t, []string{"1", "2", "3", "4", "5"}, CombineUnique(v1, v2, v3))
	assert.Equal(t, []string{"2", "3", "4", "5"}, CombineUnique(nil, v2, v3))
	assert.Equal(t, []string{"1", "2", "3", "4", "5"}, CombineUnique(v1, nil, v3))
}

func TestFetchBalances(t *testing.T) {
	simulator, client := NewSimulator(t, 0)

	ctx := t.Context()

	fetchedBalances, err := FetchBalances(ctx, client, CombineUnique(simulator.Nodekeys, simulator.Votekeys))
	require.NoError(t, err)
	assert.Equal(t,
		map[string]float64{"aaa": 1, "bbb": 2, "ccc": 3, "AAA": 4, "BBB": 5, "CCC": 6},
		fetchedBalances,
	)
}

func TestGetAssociatedValidatorAccounts(t *testing.T) {
	simulator, client := NewSimulator(t, 1)

	ctx := t.Context()

	// test finding vote accounts from identities:
	_, votekeys, err := GetAssociatedValidatorAccounts(ctx, client, rpc.CommitmentFinalized, simulator.Nodekeys, nil)
	require.NoError(t, err)
	sort.Strings(votekeys)
	assert.Equal(t, simulator.Votekeys, votekeys)

	// test finding identities from vote accounts:
	nodekeys, _, err := GetAssociatedValidatorAccounts(ctx, client, rpc.CommitmentFinalized, nil, simulator.Votekeys)
	require.NoError(t, err)
	sort.Strings(nodekeys)
	assert.Equal(t, simulator.Nodekeys, nodekeys)

	// test finding an overlapping mixture:
	nodekeys, votekeys, err = GetAssociatedValidatorAccounts(
		ctx,
		client,
		rpc.CommitmentFinalized,
		[]string{simulator.Nodekeys[0], simulator.Nodekeys[1]},
		[]string{simulator.Votekeys[1], simulator.Votekeys[2]},
	)
	require.NoError(t, err)
	sort.Strings(nodekeys)
	sort.Strings(votekeys)
	assert.Equal(t, simulator.Votekeys, votekeys)
	assert.Equal(t, simulator.Nodekeys, nodekeys)

	// test that a votekey which is not staked and does not exist (getAccountInfo returns a null value) is rejected:
	simulator.Server.SetOpt(
		rpc.EasyResultsOpt, "getAccountInfo", map[string]any{"context": map[string]int{"slot": 1}, "value": nil},
	)
	_, _, err = GetAssociatedValidatorAccounts(ctx, client, rpc.CommitmentFinalized, nil, []string{"nonexistent"})
	assert.ErrorContains(t, err, "vote account nonexistent does not exist")
}

func TestGetEpochBounds(t *testing.T) {
	epoch := rpc.EpochInfo{AbsoluteSlot: 25, SlotIndex: 5, SlotsInEpoch: 10}
	first, last := GetEpochBounds(&epoch)
	assert.Equal(t, int64(20), first)
	assert.Equal(t, int64(29), last)
}

//go:embed testdata/block-297609329.json
var blockJson []byte

func TestCountVoteTransactions(t *testing.T) {
	var block rpc.Block
	err := json.Unmarshal(blockJson, &block)
	require.NoError(t, err)

	voteCount, err := CountVoteTransactions(&block)
	require.NoError(t, err)
	// https://explorer.solana.com/block/297609329
	assert.Equal(t, 1048, voteCount)
	assert.Equal(t, 446, len(block.Transactions)-voteCount)
}

func TestEpochTrackedValidators_GetTrackedValidators(t *testing.T) {
	etv := EpochTrackedValidators{
		trackedNodekeys: map[int64]map[string]struct{}{
			1: {"a": struct{}{}, "b": struct{}{}},
			2: {"c": struct{}{}, "d": struct{}{}},
		},
	}
	t.Run(
		"simple_get",
		func(t *testing.T) {
			nodekeys, err := etv.GetTrackedValidators(1)
			require.NoError(t, err)
			sort.Strings(nodekeys)
			assert.Equal(t, []string{"a", "b"}, nodekeys)
		},
	)
	t.Run(
		"second-get",
		func(t *testing.T) {
			nodekeys, err := etv.GetTrackedValidators(2)
			require.NoError(t, err)
			sort.Strings(nodekeys)
			assert.Equal(t, []string{"c", "d"}, nodekeys)
		},
	)
	t.Run(
		"failed-get",
		func(t *testing.T) {
			_, err := etv.GetTrackedValidators(1)
			assert.Error(t, err)
		},
	)
}

func TestEpochTrackedValidators_AddTrackedValidators(t *testing.T) {
	etv := NewEpochTrackedValidators()
	etv.AddTrackedNodekeys(1, []string{"a", "b"})
	etv.AddTrackedNodekeys(2, []string{"c", "d"})
	assert.Equal(t,
		map[int64]map[string]struct{}{
			1: {"a": struct{}{}, "b": struct{}{}},
			2: {"c": struct{}{}, "d": struct{}{}},
		},
		etv.trackedNodekeys,
	)
}

func TestBoolToFloat64(t *testing.T) {
	assert.Equal(t, float64(1), BoolToFloat64(true))
	assert.Equal(t, float64(0), BoolToFloat64(false))
}

func TestExtractHealthAndNumSlotsBehind(t *testing.T) {
	t.Run("healthy-node", func(t *testing.T) {
		health, healthErr, slots, slotsErr := ExtractHealthAndNumSlotsBehind("ok", nil)
		assert.Equal(t, true, health)
		assert.NoError(t, healthErr)
		assert.Equal(t, int64(0), slots)
		assert.NoError(t, slotsErr)
	})

	t.Run("unhealthy-node", func(t *testing.T) {
		getHealthErr := rpc.Error{
			Code:    rpc.NodeUnhealthyCode,
			Method:  "getHealth",
			Message: "Node is unhealthy",
		}
		t.Run("generic", func(t *testing.T) {
			health, healthErr, slots, slotsErr := ExtractHealthAndNumSlotsBehind("", &getHealthErr)
			assert.Equal(t, false, health)
			assert.NoError(t, healthErr)
			assert.Equal(t, int64(0), slots)
			assert.Error(t, slotsErr)
		})

		getHealthErr.Data = map[string]any{"numSlotsBehind": 42}
		t.Run("specific", func(t *testing.T) {
			health, healthErr, slots, slotsErr := ExtractHealthAndNumSlotsBehind("", &getHealthErr)
			assert.Equal(t, false, health)
			assert.NoError(t, healthErr)
			assert.Equal(t, int64(42), slots)
			assert.NoError(t, slotsErr)
		})
	})
}
