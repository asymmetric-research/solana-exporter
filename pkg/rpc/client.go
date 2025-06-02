package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/asymmetric-research/solana-exporter/pkg/slog"
	"go.uber.org/zap"
)

type (
	Client struct {
		HttpClient  http.Client
		RpcUrl      string
		HttpTimeout time.Duration
		logger      *zap.SugaredLogger
		FiredancerMetricsPort int
	}

	Request struct {
		Jsonrpc string `json:"jsonrpc"`
		Id      int    `json:"id"`
		Method  string `json:"method"`
		Params  []any  `json:"params"`
	}

	Commitment string
)

const (
	// LamportsInSol is the number of lamports in 1 SOL (a billion)
	LamportsInSol = 1_000_000_000
	// CommitmentFinalized level offers the highest level of certainty for a transaction on the Solana blockchain.
	// A transaction is considered “Finalized” when it is included in a block that has been confirmed by a
	// supermajority of the stake, and at least 31 additional confirmed blocks have been built on top of it.
	CommitmentFinalized Commitment = "finalized"
	// CommitmentConfirmed level is reached when a transaction is included in a block that has been voted on
	// by a supermajority (66%+) of the network’s stake.
	CommitmentConfirmed Commitment = "confirmed"
	// CommitmentProcessed level represents a transaction that has been received by the network and included in a block.
	CommitmentProcessed Commitment = "processed"

	DevnetGenesisHash  = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG"
	TestnetGenesisHash = "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY"
	MainnetGenesisHash = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
)

// GetClusterFromGenesisHash returns the cluster name based on the genesis hash
func GetClusterFromGenesisHash(hash string) (string, error) {
	switch hash {
	case DevnetGenesisHash:
		return "devnet", nil
	case TestnetGenesisHash:
		return "testnet", nil
	case MainnetGenesisHash:
		return "mainnet-beta", nil
	default:
		return "", fmt.Errorf("unknown genesis hash: %s", hash)
	}
}

func NewRPCClient(rpcAddr string, httpTimeout time.Duration, firedancerMetricsPort int) *Client {
	return &Client{
		HttpClient:           http.Client{},
		RpcUrl:              rpcAddr,
		HttpTimeout:         httpTimeout,
		FiredancerMetricsPort: firedancerMetricsPort,
		logger:              slog.Get(),
	}
}

func getResponse[T any](
	ctx context.Context, client *Client, method string, params []any, rpcResponse *Response[T],
) error {
	logger := slog.Get()
	// format request:
	request := &Request{Jsonrpc: "2.0", Id: 1, Method: method, Params: params}
	buffer, err := json.Marshal(request)
	if err != nil {
		logger.Fatalf("failed to marshal request: %v", err)
	}
	logger.Debugf("jsonrpc request: %s", string(buffer))

	// make request:
	ctx, cancel := context.WithTimeout(ctx, client.HttpTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", client.RpcUrl, bytes.NewBuffer(buffer))
	if err != nil {
		logger.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("content-type", "application/json")

	resp, err := client.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s rpc call failed: %w", method, err)
	}
	//goland:noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error processing %s rpc call: %w", method, err)
	}
	// debug log response:
	logger.Debugf("%s response: %v", method, string(body))

	// unmarshal the response into the predicted format
	if err = json.Unmarshal(body, rpcResponse); err != nil {
		return fmt.Errorf("failed to decode %s response body: %w", method, err)
	}

	// check for an actual rpc error
	if rpcResponse.Error.Code != 0 {
		rpcResponse.Error.Method = method
		return &rpcResponse.Error
	}
	return nil
}

// GetEpochInfo returns information about the current epoch.
// See API docs: https://solana.com/docs/rpc/http/getepochinfo
func (c *Client) GetEpochInfo(ctx context.Context, commitment Commitment) (*EpochInfo, error) {
	var resp Response[EpochInfo]
	config := map[string]string{"commitment": string(commitment)}
	if err := getResponse(ctx, c, "getEpochInfo", []any{config}, &resp); err != nil {
		return nil, err
	}
	return &resp.Result, nil
}

// GetVoteAccounts returns the account info and associated stake for all the voting accounts in the current bank.
// See API docs: https://solana.com/docs/rpc/http/getvoteaccounts
func (c *Client) GetVoteAccounts(ctx context.Context, commitment Commitment) (*VoteAccounts, error) {
	// format params:
	config := map[string]string{"commitment": string(commitment)}
	var resp Response[VoteAccounts]
	if err := getResponse(ctx, c, "getVoteAccounts", []any{config}, &resp); err != nil {
		return nil, err
	}
	return &resp.Result, nil
}

// GetVersion returns the current Solana version running on the node.
// See API docs: https://solana.com/docs/rpc/http/getversion
func (c *Client) GetVersion(ctx context.Context) (string, error) {
	var resp Response[struct {
		Version string `json:"solana-core"`
	}]
	if err := getResponse(ctx, c, "getVersion", []any{}, &resp); err != nil {
		return "", err
	}
	return resp.Result.Version, nil
}

// GetIdentity returns identity pubkey for the current node.
// See API docs: https://solana.com/docs/rpc/http/getidentity
func (c *Client) GetIdentity(ctx context.Context) (string, error) {
	var resp Response[struct {
		Identity string `json:"identity"`
	}]
	if err := getResponse(ctx, c, "getIdentity", []any{}, &resp); err != nil {
		return "", err
	}
	return resp.Result.Identity, nil
}

// GetSlot returns the slot that has reached the given or default commitment level.
// See API docs: https://solana.com/docs/rpc/http/getslot
func (c *Client) GetSlot(ctx context.Context, commitment Commitment) (int64, error) {
	config := map[string]string{"commitment": string(commitment)}
	var resp Response[int64]
	if err := getResponse(ctx, c, "getSlot", []any{config}, &resp); err != nil {
		return 0, err
	}
	return resp.Result, nil
}

// GetBlockProduction returns recent block production information from the current or previous epoch.
// See API docs: https://solana.com/docs/rpc/http/getblockproduction
func (c *Client) GetBlockProduction(
	ctx context.Context, commitment Commitment, firstSlot int64, lastSlot int64,
) (*BlockProduction, error) {
	// format params:
	config := map[string]any{
		"commitment": string(commitment),
		"range":      map[string]int64{"firstSlot": firstSlot, "lastSlot": lastSlot},
	}
	// make request:
	var resp Response[contextualResult[BlockProduction]]
	if err := getResponse(ctx, c, "getBlockProduction", []any{config}, &resp); err != nil {
		return nil, err
	}
	return &resp.Result.Value, nil
}

// GetBalance returns the lamport balance of the account of provided pubkey.
// See API docs:https://solana.com/docs/rpc/http/getbalance
func (c *Client) GetBalance(ctx context.Context, commitment Commitment, address string) (float64, error) {
	config := map[string]string{"commitment": string(commitment)}
	var resp Response[contextualResult[int64]]
	if err := getResponse(ctx, c, "getBalance", []any{address, config}, &resp); err != nil {
		return 0, err
	}
	return float64(resp.Result.Value) / float64(LamportsInSol), nil
}

// GetInflationReward returns the inflation / staking reward for a list of addresses for an epoch.
// See API docs: https://solana.com/docs/rpc/http/getinflationreward
func (c *Client) GetInflationReward(
	ctx context.Context, commitment Commitment, addresses []string, epoch int64,
) ([]InflationReward, error) {
	// format params:
	config := map[string]any{"commitment": string(commitment), "epoch": epoch}
	var resp Response[[]InflationReward]
	if err := getResponse(ctx, c, "getInflationReward", []any{addresses, config}, &resp); err != nil {
		return nil, err
	}
	return resp.Result, nil
}

// GetLeaderSchedule returns the leader schedule for an epoch.
// See API docs: https://solana.com/docs/rpc/http/getleaderschedule
func (c *Client) GetLeaderSchedule(ctx context.Context, commitment Commitment, slot int64) (map[string][]int64, error) {
	config := map[string]any{"commitment": string(commitment)}
	var resp Response[map[string][]int64]
	if err := getResponse(ctx, c, "getLeaderSchedule", []any{slot, config}, &resp); err != nil {
		return nil, err
	}
	return resp.Result, nil
}

// GetBlock returns identity and transaction information about a confirmed block in the ledger.
// See API docs: https://solana.com/docs/rpc/http/getblock
func (c *Client) GetBlock(
	ctx context.Context, commitment Commitment, slot int64, transactionDetails string,
) (*Block, error) {
	detailsOptions := []string{"full", "none"}
	if !slices.Contains(detailsOptions, transactionDetails) {
		c.logger.Fatalf(
			"%s is not a valid transaction-details option, must be one of %v", transactionDetails, detailsOptions,
		)
	}
	if commitment == CommitmentProcessed {
		// as per https://solana.com/docs/rpc/http/getblock
		c.logger.Fatalf("commitment '%v' is not supported for GetBlock", CommitmentProcessed)
	}
	config := map[string]any{
		"commitment":                     commitment,
		"encoding":                       "json", // this is default, but no harm in specifying it
		"transactionDetails":             transactionDetails,
		"rewards":                        true, // what we here for!
		"maxSupportedTransactionVersion": 0,
	}
	var resp Response[Block]
	if err := getResponse(ctx, c, "getBlock", []any{slot, config}, &resp); err != nil {
		return nil, err
	}
	return &resp.Result, nil
}

// GetHealth returns the current health of the node. A healthy node is one that is within a blockchain-configured slots
// of the latest cluster confirmed slot.
// See API docs: https://solana.com/docs/rpc/http/gethealth
func (c *Client) GetHealth(ctx context.Context) (string, error) {
	var resp Response[string]
	if err := getResponse(ctx, c, "getHealth", []any{}, &resp); err != nil {
		return "", err
	}
	return resp.Result, nil
}

// GetMinimumLedgerSlot returns the lowest slot that the node has information about in its ledger.
// See API docs: https://solana.com/docs/rpc/http/minimumledgerslot
func (c *Client) GetMinimumLedgerSlot(ctx context.Context) (int64, error) {
	var resp Response[int64]
	if err := getResponse(ctx, c, "minimumLedgerSlot", []any{}, &resp); err != nil {
		return 0, err
	}
	return resp.Result, nil
}

// GetFirstAvailableBlock returns the slot of the lowest confirmed block that has not been purged from the ledger
// See API docs: https://solana.com/docs/rpc/http/getfirstavailableblock
func (c *Client) GetFirstAvailableBlock(ctx context.Context) (int64, error) {
	var resp Response[int64]
	if err := getResponse(ctx, c, "getFirstAvailableBlock", []any{}, &resp); err != nil {
		return 0, err
	}
	return resp.Result, nil
}

// GetGenesisHash returns the hash of the genesis block
// See API docs: https://solana.com/docs/rpc/http/getgenesishash
func (c *Client) GetGenesisHash(ctx context.Context) (string, error) {
	var resp Response[string]
	if err := getResponse(ctx, c, "getGenesisHash", []any{}, &resp); err != nil {
		return "", err
	}
	return resp.Result, nil
}

// GetFiredancerMetrics checks if the node is running Firedancer by making a request to its metrics endpoint.
func (c *Client) GetFiredancerMetrics(ctx context.Context) (*http.Response, error) {
	url := fmt.Sprintf("http://127.0.0.1:%d/metrics", c.FiredancerMetricsPort)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get Firedancer metrics: %w", err)
	}

	return resp, nil
}
