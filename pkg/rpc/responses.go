package rpc

import (
	"encoding/json"
	"fmt"
)

type (
	// Error is a JSON-RPC error returned by the node.
	Error struct {
		Message string         `json:"message"`
		Code    int64          `json:"code"`
		Data    map[string]any `json:"data"`
		// Method is not returned by the RPC, rather added by the client for visibility purposes
		Method string
	}

	// Response is the generic JSON-RPC response envelope wrapping a result of type T.
	Response[T any] struct {
		Jsonrpc string `json:"jsonrpc"`
		Result  T      `json:"result,omitempty"`
		Error   Error  `json:"error,omitempty"`
		ID      int    `json:"id"`
	}

	contextualResult[T any] struct {
		Value   T             `json:"value"`
		Context resultContext `json:"context"`
	}

	resultContext struct {
		Slot       int64  `json:"slot"`
		APIVersion string `json:"apiVersion"`
	}

	// EpochInfo describes the current epoch and slot progress.
	EpochInfo struct {
		AbsoluteSlot     int64 `json:"absoluteSlot"`
		BlockHeight      int64 `json:"blockHeight"`
		Epoch            int64 `json:"epoch"`
		SlotIndex        int64 `json:"slotIndex"`
		SlotsInEpoch     int64 `json:"slotsInEpoch"`
		TransactionCount int64 `json:"transactionCount"`
	}

	// VoteAccount holds stake and voting metadata for a single validator vote account.
	VoteAccount struct {
		ActivatedStake int64  `json:"activatedStake"`
		LastVote       int    `json:"lastVote"`
		NodePubkey     string `json:"nodePubkey"`
		RootSlot       int    `json:"rootSlot"`
		VotePubkey     string `json:"votePubkey"`
		Commission     int64  `json:"commission"`
	}

	// VoteAccounts groups current and delinquent vote accounts, as returned by getVoteAccounts.
	VoteAccounts struct {
		Current    []VoteAccount `json:"current"`
		Delinquent []VoteAccount `json:"delinquent"`
	}

	// ClusterNode is one gossip node from getClusterNodes. Only the used fields are decoded.
	ClusterNode struct {
		Pubkey string `json:"pubkey"`
		// ClientID is the client name, for example "Agave" or "Firedancer". Nil if the node does not report it.
		ClientID *string `json:"clientId"`
	}

	// HostProduction is the [leaderSlots, blocksProduced] pair reported per identity by getBlockProduction.
	HostProduction struct {
		LeaderSlots    int64
		BlocksProduced int64
	}

	// BlockProductionRange is the inclusive slot range covered by a BlockProduction result.
	BlockProductionRange struct {
		FirstSlot int64 `json:"firstSlot"`
		LastSlot  int64 `json:"lastSlot"`
	}

	// BlockProduction is the result of getBlockProduction: per-identity production over a slot range.
	BlockProduction struct {
		ByIdentity map[string]HostProduction `json:"byIdentity"`
		Range      BlockProductionRange      `json:"range"`
	}

	// InflationReward is the inflation/staking reward for an address in a given epoch.
	InflationReward struct {
		Amount int64 `json:"amount"`
		Epoch  int64 `json:"epoch"`
	}

	// Block holds the rewards and transactions of a confirmed block.
	Block struct {
		Rewards      []BlockReward    `json:"rewards"`
		Transactions []map[string]any `json:"transactions"`
	}

	// BlockReward is a single reward credited to an account within a block.
	BlockReward struct {
		Pubkey     string `json:"pubkey"`
		Lamports   int64  `json:"lamports"`
		RewardType string `json:"rewardType"`
	}

	// FullTransaction is a transaction with its message account keys, as returned with full transaction details.
	FullTransaction struct {
		Transaction struct {
			Message struct {
				AccountKeys []string `json:"accountKeys"`
			} `json:"message"`
		} `json:"transaction"`
	}

	// AccountInfo is the information associated with an account, with parsed data of type T.
	AccountInfo[T any] struct {
		Data       accountInfoData[T] `json:"data"`
		Executable bool               `json:"executable"`
		Lamports   int64              `json:"lamports"`
		Owner      string             `json:"owner"`
		RentEpoch  uint64             `json:"rentEpoch"`
		Space      int64              `json:"space"`
	}

	accountInfoData[T any] struct {
		Parsed  accountInfoParsedData[T] `json:"parsed"`
		Program string                   `json:"program"`
		Space   int64                    `json:"space"`
	}

	accountInfoParsedData[T any] struct {
		Info T      `json:"info"`
		Type string `json:"type"`
	}
)

func (e *Error) Error() string {
	return fmt.Sprintf("%s rpc error (code: %d): %s (data: %v)", e.Method, e.Code, e.Message, e.Data)
}

// UnmarshalJSON decodes the [leaderSlots, blocksProduced] array form into a HostProduction.
func (hp *HostProduction) UnmarshalJSON(data []byte) error {
	var arr []int64
	if err := json.Unmarshal(data, &arr); err != nil {
		return err
	}

	if len(arr) != 2 {
		return fmt.Errorf("expected array of 2 integers, got %d", len(arr))
	}
	hp.LeaderSlots = arr[0]
	hp.BlocksProduced = arr[1]
	return nil
}
