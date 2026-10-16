package rpc

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMockServer_getBalance(t *testing.T) {
	_, client := NewMockClient(t, MockConfig{
		Balances: map[string]int{"aaa": 2 * LamportsInSol},
	})
	ctx := t.Context()

	balance, err := client.GetBalance(ctx, CommitmentFinalized, "aaa")
	require.NoError(t, err)
	assert.Equal(t, float64(2), balance)
}

func TestMockServer_getBlock(t *testing.T) {
	_, client := NewMockClient(t, MockConfig{
		SlotInfos: map[int]MockSlotInfo{
			1: {Leader: "aaa", Block: &MockBlockInfo{Fee: 10, Transactions: [][]string{{"bbb"}}}},
			2: {Leader: "bbb", Block: &MockBlockInfo{Fee: 5, Transactions: [][]string{{"ccc", "ddd"}}}},
		},
		ValidatorInfos: map[string]MockValidatorInfo{"aaa": {}, "bbb": {}},
	})
	ctx := t.Context()

	block, err := client.GetBlock(ctx, CommitmentFinalized, 1, "full")
	require.NoError(t, err)
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
	require.NoError(t, err)
	assert.Equal(t,
		Block{
			Rewards:      []BlockReward{{Pubkey: "bbb", Lamports: 5, RewardType: "fee"}},
			Transactions: nil,
		},
		*block,
	)
}

func TestMockServer_getBlockProduction(t *testing.T) {
	_, client := NewMockClient(t, MockConfig{
		SlotInfos: map[int]MockSlotInfo{
			1: {Leader: "aaa", Block: &MockBlockInfo{}},
			2: {Leader: "aaa", Block: &MockBlockInfo{}},
			3: {Leader: "aaa", Block: &MockBlockInfo{}},
			4: {Leader: "aaa", Block: nil},
			5: {Leader: "bbb", Block: &MockBlockInfo{}},
			6: {Leader: "bbb", Block: nil},
			7: {Leader: "bbb", Block: &MockBlockInfo{}},
			8: {Leader: "bbb", Block: nil},
		},
		ValidatorInfos: map[string]MockValidatorInfo{"aaa": {}, "bbb": {}},
	})
	ctx := t.Context()

	firstSlot, lastSlot := int64(1), int64(6)
	blockProduction, err := client.GetBlockProduction(ctx, CommitmentFinalized, firstSlot, lastSlot)
	require.NoError(t, err)
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
	_, client := NewMockClient(t, MockConfig{
		InflationRewards: map[string]int{"AAA": 2_500, "BBB": 2_501, "CCC": 2_502},
	})
	ctx := t.Context()

	rewards, err := client.GetInflationReward(ctx, CommitmentFinalized, []string{"AAA", "BBB"}, 2)
	require.NoError(t, err)
	assert.Equal(t,
		[]InflationReward{{Amount: 2_500, Epoch: 2}, {Amount: 2_501, Epoch: 2}},
		rewards,
	)
}

func TestMockServer_getVoteAccounts(t *testing.T) {
	_, client := NewMockClient(t, MockConfig{
		ValidatorInfos: map[string]MockValidatorInfo{
			"aaa": {Votekey: "AAA", Stake: 1, LastVote: 2, Delinquent: false, RootSlot: 10, Commission: 11},
			"bbb": {Votekey: "BBB", Stake: 3, LastVote: 4, Delinquent: false, RootSlot: 11, Commission: 12},
			"ccc": {Votekey: "CCC", Stake: 5, LastVote: 6, Delinquent: true, RootSlot: 12, Commission: 13},
		},
	})
	ctx := t.Context()

	voteAccounts, err := client.GetVoteAccounts(ctx, CommitmentFinalized)
	require.NoError(t, err)
	// sort the vote accounts before comparing:
	sort.Slice(voteAccounts.Current, func(i, j int) bool {
		return voteAccounts.Current[i].VotePubkey < voteAccounts.Current[j].VotePubkey
	})
	assert.Equal(t,
		VoteAccounts{
			Current: []VoteAccount{
				{ActivatedStake: 1, LastVote: 2, NodePubkey: "aaa", RootSlot: 10, VotePubkey: "AAA", Commission: 11},
				{ActivatedStake: 3, LastVote: 4, NodePubkey: "bbb", RootSlot: 11, VotePubkey: "BBB", Commission: 12},
			},
			Delinquent: []VoteAccount{
				{ActivatedStake: 5, LastVote: 6, NodePubkey: "ccc", RootSlot: 12, VotePubkey: "CCC", Commission: 13},
			},
		},
		*voteAccounts,
	)
}

func TestMockServer_getMultipleAccounts(t *testing.T) {
	_, client := NewMockClient(t, MockConfig{
		ValidatorInfos: map[string]MockValidatorInfo{
			"aaa": {Votekey: "AAA", RootSlot: 10, Commission: 11, BlsPubkey: "blsAAA"},
			"bbb": {Votekey: "BBB", RootSlot: 11, Commission: 12},
		},
	})
	ctx := t.Context()

	// getMultipleAccounts returns index-aligned results, with nil for unknown accounts:
	accounts, err := GetMultipleAccounts[VoteAccountData](ctx, client, CommitmentFinalized, []string{"AAA", "XXX", "BBB"})
	require.NoError(t, err)
	require.Len(t, accounts, 3)
	require.NotNil(t, accounts[0])
	require.NotNil(t, accounts[0].Data.Parsed.Info.BlsPubkeyCompressed)
	assert.Equal(t, "blsAAA", *accounts[0].Data.Parsed.Info.BlsPubkeyCompressed)
	assert.Equal(t, "aaa", accounts[0].Data.Parsed.Info.NodePubkey)
	assert.Nil(t, accounts[1])
	require.NotNil(t, accounts[2])
	assert.Nil(t, accounts[2].Data.Parsed.Info.BlsPubkeyCompressed)
	assert.Equal(t, int64(12), accounts[2].Data.Parsed.Info.Commission)

	// getAccountInfo serves the same vote account shape:
	var voteAccountData VoteAccountData
	_, err = GetAccountInfo(ctx, client, CommitmentFinalized, "BBB", &voteAccountData)
	require.NoError(t, err)
	assert.Equal(t, "bbb", voteAccountData.NodePubkey)
	assert.Nil(t, voteAccountData.BlsPubkeyCompressed)
}
