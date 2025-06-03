package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/asymmetric-research/solana-exporter/pkg/rpc"
	"github.com/asymmetric-research/solana-exporter/pkg/slog"
)

type (
	arrayFlags []string

	ExporterConfig struct {
		HttpTimeout                      time.Duration
		RpcUrl                           string
		ListenAddress                    string
		Nodekeys                         []string
		Votekeys                         []string
		BalanceAddresses                 []string
		ComprehensiveSlotTracking        bool
		ComprehensiveVoteAccountTracking bool
		MonitorBlockSizes                bool
		LightMode                        bool
		SlotPace                         time.Duration
		ActiveIdentity                   string
		EpochCleanupTime                 time.Duration
	}
)

func (i *arrayFlags) String() string {
	return fmt.Sprint(*i)
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func NewExporterConfig(
	ctx context.Context,
	httpTimeout time.Duration,
	rpcUrl string,
	listenAddress string,
	nodekeys []string,
	votekeys []string,
	balanceAddresses []string,
	comprehensiveSlotTracking bool,
	comprehensiveVoteAccountTracking bool,
	monitorBlockSizes bool,
	lightMode bool,
	slotPace time.Duration,
	activeIdentity string,
	epochCleanupTime time.Duration,
) (*ExporterConfig, error) {
	logger := slog.Get()
	logger.Infow(
		"Setting up export config with ",
		"httpTimeout", httpTimeout.Seconds(),
		"rpcUrl", rpcUrl,
		"listenAddress", listenAddress,
		"nodekeys", nodekeys,
		"votekeys", votekeys,
		"balanceAddresses", balanceAddresses,
		"comprehensiveSlotTracking", comprehensiveSlotTracking,
		"comprehensiveVoteAccountTracking", comprehensiveVoteAccountTracking,
		"monitorBlockSizes", monitorBlockSizes,
		"lightMode", lightMode,
		"activeIdentity", activeIdentity,
		"slotPace", slotPace,
		"epochCleanupTime", epochCleanupTime,
	)
	if lightMode {
		if comprehensiveSlotTracking {
			return nil, fmt.Errorf("'-light-mode' is incompatible with `-comprehensive-slot-tracking`")
		}

		if comprehensiveVoteAccountTracking {
			return nil, fmt.Errorf("'-light-mode' is incompatible with '-comprehensive-vote-account-tracking'")
		}

		if monitorBlockSizes {
			return nil, fmt.Errorf("'-light-mode' is incompatible with `-monitor-block-sizes`")
		}

		if len(nodekeys) > 0 {
			return nil, fmt.Errorf("'-light-mode' is incompatible with `-nodekey`")
		}

		if len(votekeys) > 0 {
			return nil, fmt.Errorf("'-light-mode' is incompatible with `-votekey`")
		}

		if len(balanceAddresses) > 0 {
			return nil, fmt.Errorf("'-light-mode' is incompatible with `-balance-addresses`")
		}
	}

	// get votekeys from rpc:
	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()
	client := rpc.NewRPCClient(rpcUrl, httpTimeout)
	associatedNodekeys, associatedVotekeys, err := GetAssociatedValidatorAccounts(
		ctx, client, rpc.CommitmentFinalized, nodekeys, votekeys,
	)
	fmt.Println(len(associatedNodekeys), associatedNodekeys, len(associatedVotekeys), associatedVotekeys)
	if err != nil {
		return nil, fmt.Errorf("error getting associated validator accounts: %w", err)
	}

	config := ExporterConfig{
		HttpTimeout:                      httpTimeout,
		RpcUrl:                           rpcUrl,
		ListenAddress:                    listenAddress,
		Nodekeys:                         associatedNodekeys,
		Votekeys:                         associatedVotekeys,
		BalanceAddresses:                 balanceAddresses,
		ComprehensiveSlotTracking:        comprehensiveSlotTracking,
		ComprehensiveVoteAccountTracking: comprehensiveVoteAccountTracking,
		MonitorBlockSizes:                monitorBlockSizes,
		LightMode:                        lightMode,
		SlotPace:                         slotPace,
		ActiveIdentity:                   activeIdentity,
		EpochCleanupTime:                 epochCleanupTime,
	}
	return &config, nil
}

func NewExporterConfigFromCLI(ctx context.Context) (*ExporterConfig, error) {
	var (
		httpTimeout                      int
		rpcUrl                           string
		listenAddress                    string
		nodekeys                         arrayFlags
		votekeys                         arrayFlags
		balanceAddresses                 arrayFlags
		comprehensiveSlotTracking        bool
		comprehensiveVoteAccountTracking bool
		monitorBlockSizes                bool
		lightMode                        bool
		slotPace                         int
		activeIdentity                   string
		epochCleanupTime                 int
	)
	flag.IntVar(
		&httpTimeout,
		"http-timeout",
		60,
		"HTTP timeout to use, in seconds.",
	)
	flag.StringVar(
		&rpcUrl,
		"rpc-url",
		"http://localhost:8899",
		"Solana RPC URL (including protocol and path), "+
			"e.g., 'http://localhost:8899' or 'https://api.mainnet-beta.solana.com'",
	)
	flag.StringVar(
		&listenAddress,
		"listen-address",
		":8080",
		"Listen address",
	)
	flag.Var(
		&nodekeys,
		"nodekey",
		"Solana nodekey (identity account) representing validator to monitor - can set multiple times. "+
			"Can NOT be used to monitor unstaked validators.",
	)
	flag.Var(
		&votekeys,
		"votekey",
		"Solana votekey (vote account) representing validator to monitor - can set multiple times. "+
			"Can be used to monitor unstaked validators.",
	)
	flag.Var(
		&balanceAddresses,
		"balance-address",
		"Address to monitor SOL balances for, in addition to the identity and vote accounts of the "+
			"provided nodekeys - can be set multiple times.",
	)
	flag.BoolVar(
		&comprehensiveSlotTracking,
		"comprehensive-slot-tracking",
		false,
		"Set this flag to track solana_validator_leader_slots_by_epoch for all validators. "+
			"Warning: this will lead to potentially thousands of new Prometheus metrics being created every epoch.",
	)
	flag.BoolVar(
		&comprehensiveVoteAccountTracking,
		"comprehensive-vote-account-tracking",
		false,
		"Set this flag to track vote-account metrics such as solana_validator_active_stake for all validators. "+
			"Warning: this will lead to potentially thousands of Prometheus metrics.",
	)
	flag.BoolVar(
		&monitorBlockSizes,
		"monitor-block-sizes",
		false,
		"Set this flag to track block sizes (number of transactions) for the configured validators. "+
			"Warning: this might grind the RPC node.",
	)
	flag.BoolVar(
		&lightMode,
		"light-mode",
		false,
		"Set this flag to enable light-mode. In light mode, only metrics specific to the node being queried "+
			"are reported (i.e., metrics such as inflation rewards which are visible from any RPC node, "+
			"are not reported).",
	)
	flag.IntVar(
		&slotPace,
		"slot-pace",
		1,
		"This is the time (in seconds) between slot-watching metric collections, defaults to 1s.",
	)
	flag.IntVar(
		&epochCleanupTime,
		"epoch-cleanup-time",
		60,
		"The time (in seconds) to wait for end-of-epoch metrics to be scraped before cleaning, defaults to 60s",
	)
	flag.StringVar(
		&activeIdentity,
		"active-identity",
		"",
		"Validator identity public key that determines if the node is considered active in the 'solana_node_is_active' metric.",
	)
	flag.Parse()

	config, err := NewExporterConfig(
		ctx,
		time.Duration(httpTimeout)*time.Second,
		rpcUrl,
		listenAddress,
		nodekeys,
		votekeys,
		balanceAddresses,
		comprehensiveSlotTracking,
		comprehensiveVoteAccountTracking,
		monitorBlockSizes,
		lightMode,
		time.Duration(slotPace)*time.Second,
		activeIdentity,
		time.Duration(epochCleanupTime)*time.Second,
	)
	if err != nil {
		return nil, err
	}
	return config, nil
}
