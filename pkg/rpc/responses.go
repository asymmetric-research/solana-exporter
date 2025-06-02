package rpc

import (
	"encoding/json"
	"fmt"
)

type (
	Error struct {
		Message string         `json:"message"`
		Code    int64          `json:"code"`
		Data    map[string]any `json:"data"`
		// Method is not returned by the RPC, rather added by the client for visibility purposes
		Method string
	}

	Response[T any] struct {
		Jsonrpc string `json:"jsonrpc"`
		Result  T      `json:"result,omitempty"`
		Error   Error  `json:"error,omitempty"`
		Id      int    `json:"id"`
	}

	contextualResult[T any] struct {
		Value   T             `json:"value"`
		Context resultContext `json:"context"`
	}

	resultContext struct {
		Slot       int64  `json:"slot"`
		ApiVersion string `json:"apiVersion"`
	}

	EpochInfo struct {
		AbsoluteSlot     int64 `json:"absoluteSlot"`
		BlockHeight      int64 `json:"blockHeight"`
		Epoch            int64 `json:"epoch"`
		SlotIndex        int64 `json:"slotIndex"`
		SlotsInEpoch     int64 `json:"slotsInEpoch"`
		TransactionCount int64 `json:"transactionCount"`
	}

	VoteAccount struct {
		ActivatedStake int64  `json:"activatedStake"`
		LastVote       int    `json:"lastVote"`
		NodePubkey     string `json:"nodePubkey"`
		RootSlot       int    `json:"rootSlot"`
		VotePubkey     string `json:"votePubkey"`
	}

	VoteAccounts struct {
		Current    []VoteAccount `json:"current"`
		Delinquent []VoteAccount `json:"delinquent"`
	}

	HostProduction struct {
		LeaderSlots    int64
		BlocksProduced int64
	}

	BlockProductionRange struct {
		FirstSlot int64 `json:"firstSlot"`
		LastSlot  int64 `json:"lastSlot"`
	}

	BlockProduction struct {
		ByIdentity map[string]HostProduction `json:"byIdentity"`
		Range      BlockProductionRange      `json:"range"`
	}

	InflationReward struct {
		Amount int64 `json:"amount"`
		Epoch  int64 `json:"epoch"`
	}

	Block struct {
		Rewards      []BlockReward    `json:"rewards"`
		Transactions []map[string]any `json:"transactions"`
	}

	BlockReward struct {
		Pubkey     string `json:"pubkey"`
		Lamports   int64  `json:"lamports"`
		RewardType string `json:"rewardType"`
	}

	FullTransaction struct {
		Transaction struct {
			Message struct {
				AccountKeys []string `json:"accountKeys"`
			} `json:"message"`
		} `json:"transaction"`
	}

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
