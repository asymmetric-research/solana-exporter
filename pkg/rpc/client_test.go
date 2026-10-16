package rpc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newMethodTester(t *testing.T, method string, result any, err *Error) (*MockServer, *Client) {
	t.Helper()
	errs := make(map[string]*Error)
	if err != nil {
		errs[method] = err
	}
	return NewMockClient(t, MockConfig{
		EasyResults: map[string]any{method: result},
		EasyErrors:  errs,
	})
}

func TestClient_GetBalance(t *testing.T) {
	_, client := newMethodTester(t,
		"getBalance",
		map[string]any{"context": map[string]int{"slot": 1}, "value": 5 * LamportsInSol},
		nil,
	)
	ctx := t.Context()

	balance, err := client.GetBalance(ctx, CommitmentFinalized, "")
	require.NoError(t, err)
	assert.Equal(t, float64(5), balance)
}

func TestClient_GetBlock(t *testing.T) {
	_, client := newMethodTester(t,
		"getBlock",
		map[string]any{
			"rewards": []map[string]any{
				{"pubkey": "aaa", "lamports": 10, "rewardType": "fee"},
			},
			"transactions": []map[string]map[string]map[string][]string{
				{"transaction": {"message": {"accountKeys": {"aaa", "bbb", "ccc"}}}},
			},
		},
		nil,
	)

	ctx := t.Context()

	block, err := client.GetBlock(ctx, CommitmentFinalized, 0, "full")
	require.NoError(t, err)
	assert.Equal(t,
		&Block{
			Rewards: []BlockReward{
				{Pubkey: "aaa", Lamports: 10, RewardType: "fee"},
			},
			// note the test will fail if we don't type it exactly like this:
			Transactions: []map[string]any{
				{"transaction": map[string]any{"message": map[string]any{"accountKeys": []any{"aaa", "bbb", "ccc"}}}},
			},
		},
		block,
	)
}

func TestClient_GetBlockProduction(t *testing.T) {
	_, client := newMethodTester(t,
		"getBlockProduction",
		map[string]any{
			"context": map[string]int{
				"slot": 9887,
			},
			"value": map[string]any{
				"byIdentity": map[string][]int{
					"85iYT5RuzRTDgjyRa3cP8SYhM2j21fj7NhfJ3peu1DPr": {9888, 9886},
				},
				"range": map[string]int{
					"firstSlot": 0,
					"lastSlot":  9887,
				},
			},
		},
		nil,
	)
	ctx := t.Context()

	blockProduction, err := client.GetBlockProduction(ctx, CommitmentFinalized, 0, 0)
	require.NoError(t, err)
	assert.Equal(t,
		&BlockProduction{
			ByIdentity: map[string]HostProduction{"85iYT5RuzRTDgjyRa3cP8SYhM2j21fj7NhfJ3peu1DPr": {9888, 9886}},
			Range:      BlockProductionRange{FirstSlot: 0, LastSlot: 9887},
		},
		blockProduction,
	)
}

func TestClient_GetAccountInfo(t *testing.T) {
	_, client := newMethodTester(t,
		"getAccountInfo",
		contextualResult[AccountInfo[map[string]any]]{
			Context: resultContext{
				APIVersion: "2.2.14",
				Slot:       343274370,
			},
			Value: AccountInfo[map[string]any]{
				Data: accountInfoData[map[string]any]{
					Parsed: accountInfoParsedData[map[string]any]{
						Info: map[string]any{
							"authorizedVoters": []map[string]any{
								{
									"authorizedVoter": "Certusm1sa411sMpV9FPqU5dXAYhmmhygvxJ23S6hJ24",
									"epoch":           761,
								},
							},
							"authorizedWithdrawer": "7tP8ko6zKSXsJnUzPKsAwqukaGsgjr7cHQWzzxLQi7Gd",
							"blsPubkeyCompressed":  "2gK9aBLSpubkeyCompressedFixtureXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
							"commission":           100,
							"epochCredits": []map[string]any{
								{
									"credits":         "574047",
									"epoch":           761,
									"previousCredits": "0",
								},
							},
							"lastTimestamp": map[string]any{
								"slot":      329160377,
								"timestamp": 1742936930,
							},
							"nodePubkey":  "Certusm1sa411sMpV9FPqU5dXAYhmmhygvxJ23S6hJ24",
							"priorVoters": []string{},
							"rootSlot":    329160346,
							"votes": []map[string]any{
								{"confirmationCount": 9, "slot": 329160369},
								{"confirmationCount": 8, "slot": 329160370},
								{"confirmationCount": 7, "slot": 329160371},
								{"confirmationCount": 6, "slot": 329160372},
								{"confirmationCount": 5, "slot": 329160373},
								{"confirmationCount": 4, "slot": 329160374},
								{"confirmationCount": 3, "slot": 329160375},
								{"confirmationCount": 2, "slot": 329160376},
								{"confirmationCount": 1, "slot": 329160377},
							},
						},
						Type: "vote",
					},
					Program: "vote",
					Space:   3762,
				},
				Executable: false,
				Lamports:   27074400,
				Owner:      "Vote111111111111111111111111111111111111111",
				RentEpoch:  uint64(18446744073709551615),
				Space:      3762,
			},
		},
		nil,
	)
	ctx := t.Context()

	var voteAccountData VoteAccountData
	accountInfo, err := GetAccountInfo(
		ctx, client, CommitmentFinalized, "CertusDeBmqN8ZawdkxK5kFGMwBXdudvWHYwtNgNhvLu", &voteAccountData,
	)
	require.NoError(t, err)
	blsPubkey := "2gK9aBLSpubkeyCompressedFixtureXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	expectedData := VoteAccountData{
		AuthorizedVoters: []authorizedVoter{
			{"Certusm1sa411sMpV9FPqU5dXAYhmmhygvxJ23S6hJ24", 761},
		},
		AuthorizedWithdrawer: "7tP8ko6zKSXsJnUzPKsAwqukaGsgjr7cHQWzzxLQi7Gd",
		BlsPubkeyCompressed:  &blsPubkey,
		Commission:           100,
		EpochCredits: []epochCredit{
			{"574047", 761, "0"},
		},
		LastTimestamp: lastTimestamp{329160377, 1742936930},
		NodePubkey:    "Certusm1sa411sMpV9FPqU5dXAYhmmhygvxJ23S6hJ24",
		PriorVoters:   []string{},
		RootSlot:      329160346,
		Votes: []vote{
			{9, 329160369},
			{8, 329160370},
			{7, 329160371},
			{6, 329160372},
			{5, 329160373},
			{4, 329160374},
			{3, 329160375},
			{2, 329160376},
			{1, 329160377},
		},
	}
	assert.Equal(t,
		&AccountInfo[VoteAccountData]{
			Data: accountInfoData[VoteAccountData]{
				Parsed: accountInfoParsedData[VoteAccountData]{
					Info: expectedData,
					Type: "vote",
				},
				Program: "vote",
				Space:   3762,
			},
			Executable: false,
			Lamports:   27074400,
			Owner:      "Vote111111111111111111111111111111111111111",
			RentEpoch:  18446744073709551615,
			Space:      3762,
		},
		accountInfo,
	)
	assert.Equal(t, expectedData, voteAccountData)
}

func TestClient_GetMultipleAccounts(t *testing.T) {
	voteAccount := func(nodekey string, blsPubkey any) map[string]any {
		return map[string]any{
			"data": map[string]any{
				"parsed": map[string]any{
					"info": map[string]any{
						"authorizedVoters":     []any{},
						"authorizedWithdrawer": nodekey,
						"blsPubkeyCompressed":  blsPubkey,
						"commission":           10,
						"epochCredits": []map[string]any{
							{"credits": "1", "epoch": uint64(18446744073709551615), "previousCredits": "0"},
						},
						"lastTimestamp": map[string]int{"slot": 1, "timestamp": 2},
						"nodePubkey":    nodekey,
						"priorVoters":   []any{},
						"rootSlot":      3,
						"votes":         []any{},
					},
					"type": "vote",
				},
				"program": "vote",
				"space":   3762,
			},
			"executable": false,
			"lamports":   27074400,
			"owner":      "Vote111111111111111111111111111111111111111",
			"rentEpoch":  uint64(18446744073709551615),
			"space":      3762,
		}
	}
	_, client := newMethodTester(t,
		"getMultipleAccounts",
		map[string]any{
			"context": map[string]any{"apiVersion": "2.2.14", "slot": 343274370},
			"value":   []any{voteAccount("aaa", "blsAAA"), nil, voteAccount("ccc", nil)},
		},
		nil,
	)
	ctx := t.Context()

	accounts, err := GetMultipleAccounts[VoteAccountData](ctx, client, CommitmentFinalized, []string{"AAA", "BBB", "CCC"})
	require.NoError(t, err)
	require.Len(t, accounts, 3)

	blsPubkey := "blsAAA"
	expected := func(nodekey string, blsPubkey *string) *AccountInfo[VoteAccountData] {
		return &AccountInfo[VoteAccountData]{
			Data: accountInfoData[VoteAccountData]{
				Parsed: accountInfoParsedData[VoteAccountData]{
					Info: VoteAccountData{
						AuthorizedVoters:     []authorizedVoter{},
						AuthorizedWithdrawer: nodekey,
						BlsPubkeyCompressed:  blsPubkey,
						Commission:           10,
						EpochCredits:         []epochCredit{{"1", 18446744073709551615, "0"}},
						LastTimestamp:        lastTimestamp{1, 2},
						NodePubkey:           nodekey,
						PriorVoters:          []string{},
						RootSlot:             3,
						Votes:                []vote{},
					},
					Type: "vote",
				},
				Program: "vote",
				Space:   3762,
			},
			Executable: false,
			Lamports:   27074400,
			Owner:      "Vote111111111111111111111111111111111111111",
			RentEpoch:  uint64(18446744073709551615),
			Space:      3762,
		}
	}
	assert.Equal(t, expected("aaa", &blsPubkey), accounts[0])
	assert.Nil(t, accounts[1])
	assert.Equal(t, expected("ccc", nil), accounts[2])

	// a length mismatch between the request and the response is an error:
	_, err = GetMultipleAccounts[VoteAccountData](ctx, client, CommitmentFinalized, []string{"AAA"})
	require.Error(t, err)
}

func TestClient_GetEpochInfo(t *testing.T) {
	_, client := newMethodTester(t,
		"getEpochInfo",
		map[string]int{
			"absoluteSlot":     166_598,
			"blockHeight":      166_500,
			"epoch":            27,
			"slotIndex":        2_790,
			"slotsInEpoch":     8_192,
			"transactionCount": 22_661_093,
		},
		nil,
	)
	ctx := t.Context()

	epochInfo, err := client.GetEpochInfo(ctx, CommitmentFinalized)
	require.NoError(t, err)
	assert.Equal(t,
		EpochInfo{
			AbsoluteSlot:     166_598,
			BlockHeight:      166_500,
			Epoch:            27,
			SlotIndex:        2_790,
			SlotsInEpoch:     8_192,
			TransactionCount: 22_661_093,
		},
		*epochInfo,
	)
}

func TestClient_GetFirstAvailableBlock(t *testing.T) {
	_, client := newMethodTester(t, "getFirstAvailableBlock", 250_000, nil)
	ctx := t.Context()

	block, err := client.GetFirstAvailableBlock(ctx)
	require.NoError(t, err)
	assert.Equal(t, 250_000, int(block))
}

func TestClient_GetHealth(t *testing.T) {
	// using example responses in the docs: https://solana.com/docs/rpc/http/gethealth
	t.Run("healthy-node", func(t *testing.T) {
		_, client := newMethodTester(t, "getHealth", "ok", nil)
		ctx := t.Context()

		health, err := client.GetHealth(ctx)
		require.NoError(t, err)
		assert.Equal(t, "ok", health)
	})

	t.Run("unhealthy-node", func(t *testing.T) {
		unhealthyErr := Error{
			Code:    NodeUnhealthyCode,
			Message: "Node is unhealthy",
			Method:  "getHealth",
		}

		t.Run("generic", func(t *testing.T) {
			_, client := newMethodTester(t, "getHealth", nil, &unhealthyErr)
			ctx := t.Context()

			health, err := client.GetHealth(ctx)
			assert.Equal(t, "", health)
			assert.Equal(t, &unhealthyErr, err)
		})

		unhealthyErr.Data = map[string]any{"numSlotsBehind": float64(42)}

		t.Run("specific", func(t *testing.T) {
			_, client := newMethodTester(t, "getHealth", nil, &unhealthyErr)
			ctx := t.Context()

			health, err := client.GetHealth(ctx)
			assert.Equal(t, "", health)
			assert.Equal(t, &unhealthyErr, err)
		})
	})
}

func TestClient_GetInflationReward(t *testing.T) {
	_, client := newMethodTester(t,
		"getInflationReward",
		[]map[string]int{
			{
				"amount":        2_500,
				"effectiveSlot": 224,
				"epoch":         2,
				"postBalance":   499_999_442_500,
			},
		},
		nil,
	)
	ctx := t.Context()

	inflationReward, err := client.GetInflationReward(ctx, CommitmentFinalized, nil, 2)
	require.NoError(t, err)
	assert.Equal(t,
		[]InflationReward{{Amount: 2_500, Epoch: 2}},
		inflationReward,
	)
}

func TestClient_GetLeaderSchedule(t *testing.T) {
	expectedSchedule := map[string][]int64{
		"aaa": {0, 1, 2, 3, 4},
		"bbb": {5, 6, 7, 8, 9},
		"ccc": {10, 11, 12, 13, 14},
	}
	_, client := newMethodTester(t, "getLeaderSchedule", expectedSchedule, nil)
	ctx := t.Context()

	schedule, err := client.GetLeaderSchedule(ctx, CommitmentFinalized, 1)
	require.NoError(t, err)
	assert.Equal(t, expectedSchedule, schedule)
}

func TestClient_GetMinimumLedgerSlot(t *testing.T) {
	_, client := newMethodTester(t, "minimumLedgerSlot", 250, nil)
	ctx := t.Context()

	slot, err := client.GetMinimumLedgerSlot(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(250), slot)
}

func TestClient_GetSlot(t *testing.T) {
	_, client := newMethodTester(t, "getSlot", 1234, nil)
	ctx := t.Context()

	slot, err := client.GetSlot(ctx, CommitmentFinalized)
	require.NoError(t, err)
	assert.Equal(t, int64(1234), slot)
}

func TestClient_GetVersion(t *testing.T) {
	expectedResult := map[string]any{"feature-set": 2891131721, "solana-core": "1.16.7"}
	_, client := newMethodTester(t, "getVersion", expectedResult, nil)
	ctx := t.Context()

	version, err := client.GetVersion(ctx)
	require.NoError(t, err)
	assert.Equal(t, expectedResult["solana-core"], version)
}

func TestClient_GetVoteAccounts(t *testing.T) {
	_, client := newMethodTester(t,
		"getVoteAccounts",
		map[string]any{
			"current": []map[string]any{
				{
					"commission":       11,
					"epochVoteAccount": true,
					"epochCredits":     [][]int{{1, 64, 0}, {2, 192, 64}},
					"nodePubkey":       "B97CCUW3AEZFGy6uUg6zUdnNYvnVq5VG8PUtb2HayTDD",
					"lastVote":         147,
					"activatedStake":   42,
					"votePubkey":       "3ZT31jkAGhUaw8jsy4bTknwBMP8i4Eueh52By4zXcsVw",
				},
			},
			"delinquent": nil,
		},
		nil,
	)
	ctx := t.Context()

	voteAccounts, err := client.GetVoteAccounts(ctx, CommitmentFinalized)
	require.NoError(t, err)
	assert.Equal(t,
		&VoteAccounts{
			Current: []VoteAccount{
				{
					NodePubkey:     "B97CCUW3AEZFGy6uUg6zUdnNYvnVq5VG8PUtb2HayTDD",
					LastVote:       147,
					ActivatedStake: 42,
					VotePubkey:     "3ZT31jkAGhUaw8jsy4bTknwBMP8i4Eueh52By4zXcsVw",
					Commission:     11,
				},
			},
		},
		voteAccounts,
	)
}

func TestClient_GetIdentity(t *testing.T) {
	_, client := newMethodTester(t,
		"getIdentity", map[string]string{"identity": "random2r1F4iWqVcb8M1DbAjQuFpebkQuW2DJtestkey"},
		nil,
	)
	ctx := t.Context()

	identity, err := client.GetIdentity(ctx)
	require.NoError(t, err)
	assert.Equal(t, "random2r1F4iWqVcb8M1DbAjQuFpebkQuW2DJtestkey", identity)
}
