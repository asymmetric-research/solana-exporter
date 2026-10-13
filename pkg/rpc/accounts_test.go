package rpc

import (
	"math"
	"testing"
)

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
