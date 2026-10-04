package rpc

import (
	"context"
	"math"
	"testing"
)

func TestGetMultipleAccounts(t *testing.T) {
	voteAccount := map[string]any{
		"data": map[string]any{
			"parsed": map[string]any{
				"type": "vote",
				"info": map[string]any{
					"nodePubkey": "aaa",
					"epochCredits": []map[string]any{
						{"epoch": 1048, "credits": "100", "previousCredits": "0"},
						{
							"epoch": uint64(math.MaxUint64), "credits": "18446744073709551615",
							"previousCredits": "18446744073709551615",
						},
						{"epoch": 1049, "credits": "9223372036854775900", "previousCredits": "100"},
					},
				},
			},
			"program": "vote",
		},
	}
	_, client := newMethodTester(t,
		"getMultipleAccounts",
		map[string]any{"context": map[string]int{"slot": 42}, "value": []any{voteAccount, nil}},
		nil,
	)

	slot, accounts, err := GetMultipleAccounts[VoteAccountData](
		context.Background(), client, CommitmentFinalized, []string{"AAA", "missing"},
	)
	if err != nil {
		t.Fatalf("GetMultipleAccounts() error: %v", err)
	}
	if slot != 42 || len(accounts) != 2 || accounts[1] != nil {
		t.Fatalf("GetMultipleAccounts() = %d, %+v; want slot 42 and [account, nil]", slot, accounts)
	}
	info := accounts[0].Data.Parsed.Info
	credits, err := info.TotalCredits()
	if err != nil {
		t.Fatalf("TotalCredits() error: %v", err)
	}
	// credits are u64 and may exceed int64:
	if info.NodePubkey != "aaa" || credits != 9223372036854775900 {
		t.Errorf("got nodePubkey %q, credits %d; want \"aaa\", 9223372036854775900", info.NodePubkey, credits)
	}

	if _, _, err := GetMultipleAccounts[VoteAccountData](
		context.Background(), client, CommitmentFinalized, []string{"AAA"},
	); err == nil {
		t.Errorf("GetMultipleAccounts() with a mismatched result length: want error, got nil")
	}
}

func TestClient_GetEpochSchedule(t *testing.T) {
	_, client := newMethodTester(t,
		"getEpochSchedule",
		map[string]any{
			"firstNormalEpoch": 14, "firstNormalSlot": 524256, "leaderScheduleSlotOffset": 432000,
			"slotsPerEpoch": 432000, "warmup": true,
		},
		nil,
	)
	got, err := client.GetEpochSchedule(context.Background())
	if err != nil {
		t.Fatalf("GetEpochSchedule() error: %v", err)
	}
	want := EpochSchedule{
		SlotsPerEpoch: 432000, LeaderScheduleSlotOffset: 432000, Warmup: true, FirstNormalEpoch: 14,
		FirstNormalSlot: 524256,
	}
	if *got != want {
		t.Errorf("GetEpochSchedule() = %+v, want %+v", *got, want)
	}
}

func TestVoteAccountData_TotalCredits(t *testing.T) {
	marker := epochCredit{Epoch: math.MaxUint64, Credits: "18446744073709551615", PreviousCredits: "18446744073709551615"}
	tests := []struct {
		name    string
		credits []epochCredit
		want    uint64
	}{
		{"no entries", nil, 0},
		{"tower only", []epochCredit{{Epoch: 1, Credits: "500"}}, 500},
		{"marker last, not yet credited under Alpenglow", []epochCredit{{Epoch: 1, Credits: "500"}, marker}, 500},
		{"credited after marker", []epochCredit{{Epoch: 1, Credits: "500"}, marker, {Epoch: 2, Credits: "800"}}, 800},
	}
	for _, tt := range tests {
		v := VoteAccountData{EpochCredits: tt.credits}
		got, err := v.TotalCredits()
		if err != nil || got != tt.want {
			t.Errorf("%s: TotalCredits() = %d, %v; want %d, nil", tt.name, got, err, tt.want)
		}
	}
}

// A vote account that migrated to Alpenglow carries agave's AG_MIGRATION_EPOCH_CREDIT marker, whose epoch is
// u64::MAX, in epochCredits. It must still decode.
func TestGetAccountInfo_AlpenglowMigrationMarker(t *testing.T) {
	_, client := newMethodTester(t,
		"getAccountInfo",
		map[string]any{
			"context": map[string]int{"slot": 1},
			"value": map[string]any{
				"data": map[string]any{
					"parsed": map[string]any{
						"type": "vote",
						"info": map[string]any{
							"nodePubkey": "aaa",
							"epochCredits": []map[string]any{
								{"epoch": 1048, "credits": "100", "previousCredits": "0"},
								{
									"epoch":           uint64(math.MaxUint64),
									"credits":         "18446744073709551615",
									"previousCredits": "18446744073709551615",
								},
								{"epoch": 1049, "credits": "700", "previousCredits": "100"},
							},
						},
					},
					"program": "vote",
				},
			},
		},
		nil,
	)

	var voteAccount VoteAccountData
	if _, err := GetAccountInfo(t.Context(), client, CommitmentFinalized, "AAA", &voteAccount); err != nil {
		t.Fatalf("GetAccountInfo() error: %v", err)
	}
	if got := len(voteAccount.EpochCredits); got != 3 {
		t.Fatalf("got %d epochCredits entries, want 3", got)
	}
	if got := voteAccount.EpochCredits[1].Epoch; got != math.MaxUint64 {
		t.Errorf("marker epoch = %d, want %d", got, uint64(math.MaxUint64))
	}
	if voteAccount.NodePubkey != "aaa" {
		t.Errorf("nodePubkey = %q, want %q", voteAccount.NodePubkey, "aaa")
	}
}
