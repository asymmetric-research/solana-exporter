package rpc

import (
	"context"
	"github.com/stretchr/testify/assert"
	"sort"
	"testing"
)

func TestMockServer_getBalance(t *testing.T) {
	_, client := NewMockClient(
		t, nil, nil, map[string]int{"aaa": 2 * LamportsInSol}, nil, nil, nil,
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	balance, err := client.GetBalance(ctx, CommitmentFinalized, "aaa")
	assert.NoError(t, err)
	assert.Equal(t, float64(2), balance)
}

func TestMockServer_getBlock(t *testing.T) {
	_, client := NewMockClient(t,
		nil,
		nil,
		nil,
		nil,
		map[int]MockSlotInfo{
			1: {"aaa", &MockBlockInfo{Fee: 10, Transactions: [][]string{{"bbb"}}}},
			2: {"bbb", &MockBlockInfo{Fee: 5, Transactions: [][]string{{"ccc", "ddd"}}}},
		},
		map[string]MockValidatorInfo{"aaa": {}, "bbb": {}},
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	block, err := client.GetBlock(ctx, CommitmentFinalized, 1, "full")
	assert.NoError(t, err)
	assert.Equal(t,
		Block{
			Rewards: []BlockReward{{Pubkey: "aaa", Lamports: 10, RewardType: "fee"}},
			Transactions: []map[string]any{
				{"transaction": map[string]any{"message": map[string]any{"accountKeys": []any{"bbb"}}}},
			},
		},
		*block,
	)

	block, err = client.GetBlock(ctx, CommitmentFinalized, 2, "none")
	assert.NoError(t, err)
	assert.Equal(t,
		Block{
			Rewards:      []BlockReward{{Pubkey: "bbb", Lamports: 5, RewardType: "fee"}},
			Transactions: nil,
		},
		*block,
	)
}

func TestMockServer_getBlockProduction(t *testing.T) {
	_, client := NewMockClient(
		t,
		nil,
		nil,
		nil,
		nil,
		map[int]MockSlotInfo{
			1: {"aaa", &MockBlockInfo{}},
			2: {"aaa", &MockBlockInfo{}},
			3: {"aaa", &MockBlockInfo{}},
			4: {"aaa", nil},
			5: {"bbb", &MockBlockInfo{}},
			6: {"bbb", nil},
			7: {"bbb", &MockBlockInfo{}},
			8: {"bbb", nil},
		},
		map[string]MockValidatorInfo{"aaa": {}, "bbb": {}},
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	firstSlot, lastSlot := int64(1), int64(6)
	blockProduction, err := client.GetBlockProduction(ctx, CommitmentFinalized, firstSlot, lastSlot)
	assert.NoError(t, err)
	assert.Equal(t,
		BlockProduction{
			ByIdentity: map[string]HostProduction{
				"aaa": {4, 3},
				"bbb": {2, 1},
			},
			Range: BlockProductionRange{FirstSlot: firstSlot, LastSlot: lastSlot},
		},
		*blockProduction,
	)
}

func TestMockServer_getInflationReward(t *testing.T) {
	_, client := NewMockClient(t,
		nil,
		nil,
		nil,
		map[string]int{"AAA": 2_500, "BBB": 2_501, "CCC": 2_502},
		nil,
		nil,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rewards, err := client.GetInflationReward(ctx, CommitmentFinalized, []string{"AAA", "BBB"}, 2)
	assert.NoError(t, err)
	assert.Equal(t,
		[]InflationReward{{Amount: 2_500, Epoch: 2}, {Amount: 2_501, Epoch: 2}},
		rewards,
	)
}

func TestMockServer_getVoteAccounts(t *testing.T) {
	_, client := NewMockClient(t,
		nil,
		nil,
		nil,
		nil,
		nil,
		map[string]MockValidatorInfo{
			"aaa": {"AAA", 1, 2, false, 10, 11},
			"bbb": {"BBB", 3, 4, false, 11, 12},
			"ccc": {"CCC", 5, 6, true, 12, 13},
		},
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	voteAccounts, err := client.GetVoteAccounts(ctx, CommitmentFinalized)
	assert.NoError(t, err)
	// sort the vote accounts before comparing:
	sort.Slice(voteAccounts.Current, func(i, j int) bool {
		return voteAccounts.Current[i].VotePubkey < voteAccounts.Current[j].VotePubkey
	})
	assert.Equal(t,
		VoteAccounts{
			Current: []VoteAccount{
				{1, 2, "aaa", 10, "AAA", 11},
				{3, 4, "bbb", 11, "BBB", 12},
			},
			Delinquent: []VoteAccount{
				{5, 6, "ccc", 12, "CCC", 13},
			},
		},
		*voteAccounts,
	)
}
