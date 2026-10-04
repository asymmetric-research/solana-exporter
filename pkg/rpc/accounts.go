// Package rpc provides a client and response types for the Solana JSON-RPC API.
package rpc

import (
	"fmt"
	"math"
	"strconv"
)

type (
	// VoteAccountData is the parsed on-chain data of a vote account.
	VoteAccountData struct {
		AuthorizedVoters     []authorizedVoter `json:"authorizedVoters"`
		AuthorizedWithdrawer string            `json:"authorizedWithdrawer"`
		Commission           int64             `json:"commission"`
		EpochCredits         []epochCredit     `json:"epochCredits"`
		LastTimestamp        lastTimestamp     `json:"lastTimestamp"`
		NodePubkey           string            `json:"nodePubkey"`
		PriorVoters          []string          `json:"priorVoters"`
		RootSlot             int64             `json:"rootSlot"`
		Votes                []vote            `json:"votes"`
	}

	authorizedVoter struct {
		AuthorizedVoter string `json:"authorizedVoter"`
		Epoch           int64  `json:"epoch"`
	}

	epochCredit struct {
		Credits string `json:"credits"`
		// Epoch is a u64: when a vote account migrates to Alpenglow, agave appends a marker entry
		// (AG_MIGRATION_EPOCH_CREDIT) whose fields are all u64::MAX.
		Epoch           uint64 `json:"epoch"`
		PreviousCredits string `json:"previousCredits"`
	}

	lastTimestamp struct {
		Slot      int64 `json:"slot"`
		Timestamp int64 `json:"timestamp"`
	}

	vote struct {
		ConfirmationCount int64 `json:"confirmationCount"`
		Slot              int64 `json:"slot"`
	}
)

// alpenglowMigrationMarkerEpoch is the epoch of the (u64::MAX, u64::MAX, u64::MAX) entry that agave pushes into
// epochCredits when a vote account migrates to Alpenglow (AG_MIGRATION_EPOCH_CREDIT).
const alpenglowMigrationMarkerEpoch = math.MaxUint64

// TotalCredits returns the vote account's cumulative credits, as held by its latest epochCredits entry. The
// Alpenglow migration marker is skipped: the first entry after it carries on from the credits before it.
func (v *VoteAccountData) TotalCredits() (uint64, error) {
	for i := len(v.EpochCredits) - 1; i >= 0; i-- {
		entry := v.EpochCredits[i]
		if entry.Epoch == alpenglowMigrationMarkerEpoch {
			continue
		}
		credits, err := strconv.ParseUint(entry.Credits, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("failed to parse epoch credits: %w", err)
		}
		return credits, nil
	}
	return 0, nil
}
