package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/asymmetric-research/solana-exporter/pkg/slog"
	"go.uber.org/zap"
)

type MockOpt int

const (
	BalanceOpt MockOpt = iota
	InflationRewardsOpt
	EasyResultsOpt
	SlotInfosOpt
	ValidatorInfoOpt
	EasyErrorsOpt = 5
)

type (
	// MockServer represents a mock Solana RPC server for testing
	MockServer struct {
		server   *http.Server
		listener net.Listener
		mu       sync.RWMutex
		logger   *zap.SugaredLogger

		balances         map[string]int
		inflationRewards map[string]int
		easyResults      map[string]any
		easyErrors       map[string]*Error

		SlotInfos      map[int]MockSlotInfo
		validatorInfos map[string]MockValidatorInfo
	}

	MockBlockInfo struct {
		Fee          int
		Transactions [][]string
	}

	MockSlotInfo struct {
		Leader string
		Block  *MockBlockInfo
	}

	MockValidatorInfo struct {
		Votekey    string
		Stake      int
		LastVote   int
		Delinquent bool
		RootSlot   int
		Commission int64
	}
)

// NewMockServer creates a new mock server instance
func NewMockServer(
	easyResults map[string]any,
	easyErrors map[string]*Error,
	balances map[string]int,
	inflationRewards map[string]int,
	slotInfos map[int]MockSlotInfo,
	validatorInfos map[string]MockValidatorInfo,
) (*MockServer, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %v", err)
	}

	ms := &MockServer{
		listener:         listener,
		logger:           slog.Get(),
		easyResults:      easyResults,
		easyErrors:       easyErrors,
		balances:         balances,
		inflationRewards: inflationRewards,
		SlotInfos:        slotInfos,
		validatorInfos:   validatorInfos,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", ms.handleRPCRequest)

	ms.server = &http.Server{Handler: mux}

	go func() {
		_ = ms.server.Serve(listener)
	}()

	return ms, nil
}

// URL returns the URL of the mock server
func (s *MockServer) URL() string {
	return fmt.Sprintf("http://%s", s.listener.Addr().String())
}

// Close shuts down the mock server
func (s *MockServer) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}

func (s *MockServer) MustClose() {
	if err := s.Close(); err != nil {
		panic(err)
	}
}

func (s *MockServer) SetOpt(opt MockOpt, key any, value any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch opt {
	case BalanceOpt:
		if s.balances == nil {
			s.balances = make(map[string]int)
		}
		s.balances[key.(string)] = value.(int)
	case InflationRewardsOpt:
		if s.inflationRewards == nil {
			s.inflationRewards = make(map[string]int)
		}
		s.inflationRewards[key.(string)] = value.(int)
	case EasyResultsOpt:
		if s.easyResults == nil {
			s.easyResults = make(map[string]any)
		}
		s.easyResults[key.(string)] = value
	case SlotInfosOpt:
		if s.SlotInfos == nil {
			s.SlotInfos = make(map[int]MockSlotInfo)
		}
		s.SlotInfos[key.(int)] = value.(MockSlotInfo)
	case ValidatorInfoOpt:
		if s.validatorInfos == nil {
			s.validatorInfos = make(map[string]MockValidatorInfo)
		}
		s.validatorInfos[key.(string)] = value.(MockValidatorInfo)
	case EasyErrorsOpt:
		if s.easyErrors == nil {
			s.easyErrors = make(map[string]*Error)
		}
		err := value.(Error)
		s.easyErrors[key.(string)] = &err
	}
}

func (s *MockServer) GetValidatorInfo(nodekey string) MockValidatorInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.validatorInfos[nodekey]
}

func (s *MockServer) getResult(method string, params ...any) (any, *Error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.easyErrors != nil {
		if err, ok := s.easyErrors[method]; ok && err != nil {
			return nil, err
		}
	}

	if method == "getBalance" && s.balances != nil {
		address := params[0].(string)
		result := map[string]any{
			"context": map[string]int{"slot": 1},
			"value":   s.balances[address],
		}
		return result, nil
	}

	if method == "getInflationReward" && s.inflationRewards != nil {
		addresses := params[0].([]any)
		config := params[1].(map[string]any)
		epoch := int(config["epoch"].(float64))
		rewards := make([]map[string]int, len(addresses))
		for i, item := range addresses {
			address := item.(string)
			rewards[i] = map[string]int{"amount": s.inflationRewards[address], "epoch": epoch}
		}
		return rewards, nil
	}

	if method == "getBlock" && s.SlotInfos != nil {
		// get params:
		slot := int(params[0].(float64))
		config := params[1].(map[string]any)
		transactionDetails, rewardsIncluded := config["transactionDetails"].(string), config["rewards"].(bool)

		slotInfo, ok := s.SlotInfos[slot]
		if !ok {
			s.logger.Warnf("no slot info for slot %d", slot)
			return nil, &Error{Code: BlockCleanedUpCode, Message: "Block cleaned up."}
		}
		if slotInfo.Block == nil {
			return nil, &Error{Code: SlotSkippedCode, Message: "Slot skipped."}
		}
		var (
			transactions []map[string]any
			rewards      []map[string]any
		)
		if transactionDetails == "full" {
			for _, tx := range slotInfo.Block.Transactions {
				transactions = append(
					transactions,
					map[string]any{
						"transaction": map[string]map[string][]string{"message": {"accountKeys": tx}},
					},
				)
			}
		}
		if rewardsIncluded {
			rewards = append(
				rewards,
				map[string]any{"pubkey": slotInfo.Leader, "lamports": slotInfo.Block.Fee, "rewardType": "fee"},
			)
		}
		return map[string]any{"rewards": rewards, "transactions": transactions}, nil
	}

	if method == "getBlockProduction" && s.SlotInfos != nil {
		// get params:
		config := params[0].(map[string]any)
		slotRange := config["range"].(map[string]any)
		firstSlot, lastSlot := int(slotRange["firstSlot"].(float64)), int(slotRange["lastSlot"].(float64))

		byIdentity := make(map[string][]int)
		for nodekey := range s.validatorInfos {
			byIdentity[nodekey] = []int{0, 0}
		}
		for i := firstSlot; i <= lastSlot; i++ {
			info := s.SlotInfos[i]
			production := byIdentity[info.Leader]
			production[0]++
			if info.Block != nil {
				production[1]++
			}
			byIdentity[info.Leader] = production
		}

		blockProduction := map[string]any{
			"context": map[string]int{"slot": 1},
			"value":   map[string]any{"byIdentity": byIdentity, "range": slotRange},
		}
		return blockProduction, nil
	}

	if method == "getVoteAccounts" && s.validatorInfos != nil {
		var currentVoteAccounts, delinquentVoteAccounts []map[string]any
		for nodekey, info := range s.validatorInfos {
			voteAccount := map[string]any{
				"activatedStake": int64(info.Stake),
				"lastVote":       info.LastVote,
				"nodePubkey":     nodekey,
				"rootSlot":       info.RootSlot,
				"votePubkey":     info.Votekey,
				"commission":     info.Commission,
			}
			if info.Delinquent {
				delinquentVoteAccounts = append(delinquentVoteAccounts, voteAccount)
			} else {
				currentVoteAccounts = append(currentVoteAccounts, voteAccount)
			}
		}
		voteAccounts := map[string][]map[string]any{
			"current":    currentVoteAccounts,
			"delinquent": delinquentVoteAccounts,
		}
		return voteAccounts, nil
	}

	// default is use easy results:
	result, ok := s.easyResults[method]
	if !ok {
		return nil, &Error{Code: -32601, Message: "Method not found"}
	}
	return result, nil
}

func (s *MockServer) handleRPCRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var request Request
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	response := Response[any]{Jsonrpc: "2.0", Id: request.Id}
	result, rpcErr := s.getResult(request.Method, request.Params...)
	if rpcErr != nil {
		response.Error = *rpcErr
	} else {
		response.Result = result
	}

	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// NewMockClient creates a new test client with a running mock server
func NewMockClient(
	t *testing.T,
	easyResults map[string]any,
	easyErrors map[string]*Error,
	balances map[string]int,
	inflationRewards map[string]int,
	slotInfos map[int]MockSlotInfo,
	validatorInfos map[string]MockValidatorInfo,
) (*MockServer, *Client) {
	server, err := NewMockServer(easyResults, easyErrors, balances, inflationRewards, slotInfos, validatorInfos)
	if err != nil {
		t.Fatalf("failed to create mock server: %v", err)
	}

	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("failed to close mock server: %v", err)
		}
	})

	client := NewRPCClient(server.URL(), time.Second)
	return server, client
}
