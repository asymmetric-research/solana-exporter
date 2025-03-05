package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/asymmetric-research/solana-exporter/pkg/rpc"
	"github.com/asymmetric-research/solana-exporter/pkg/slog"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"slices"
)

const (
	SkipStatusLabel      = "status"
	StateLabel           = "state"
	NodekeyLabel         = "nodekey"
	VotekeyLabel         = "votekey"
	VersionLabel         = "version"
	IdentityLabel        = "identity"
	AddressLabel         = "address"
	EpochLabel           = "epoch"
	TransactionTypeLabel = "transaction_type"

	StatusSkipped = "skipped"
	StatusValid   = "valid"

	StateCurrent    = "current"
	StateDelinquent = "delinquent"

	TransactionTypeVote    = "vote"
	TransactionTypeNonVote = "non_vote"
)

type SolanaCollector struct {
	rpcClient *rpc.Client
	logger    *zap.SugaredLogger

	config *ExporterConfig

	/// descriptors:
	ValidatorActiveStake    *GaugeDesc
	ClusterActiveStake      *GaugeDesc
	ValidatorLastVote       *GaugeDesc
	ClusterLastVote         *GaugeDesc
	ValidatorRootSlot       *GaugeDesc
	ClusterRootSlot         *GaugeDesc
	ValidatorDelinquent     *GaugeDesc
	ClusterValidatorCount   *GaugeDesc
	AccountBalances         *GaugeDesc
	NodeVersion             *GaugeDesc
	NodeIsHealthy           *GaugeDesc
	NodeNumSlotsBehind      *GaugeDesc
	NodeMinimumLedgerSlot   *GaugeDesc
	NodeFirstAvailableBlock *GaugeDesc
	NodeIdentity            *GaugeDesc
	NodeIsActive            *GaugeDesc
}

func NewSolanaCollector(rpcClient *rpc.Client, config *ExporterConfig) *SolanaCollector {
	collector := &SolanaCollector{
		rpcClient: rpcClient,
		logger:    slog.Get(),
		config:    config,
		ValidatorActiveStake: NewGaugeDesc(
			"solana_validator_active_stake",
			fmt.Sprintf("Active stake (in SOL) per validator (represented by %s and %s)", VotekeyLabel, NodekeyLabel),
			VotekeyLabel, NodekeyLabel,
		),
		ClusterActiveStake: NewGaugeDesc(
			"solana_cluster_active_stake",
			"Total active stake (in SOL) of the cluster",
		),
		ValidatorLastVote: NewGaugeDesc(
			"solana_validator_last_vote",
			fmt.Sprintf("Last voted-on slot per validator (represented by %s and %s)", VotekeyLabel, NodekeyLabel),
			VotekeyLabel, NodekeyLabel,
		),
		ClusterLastVote: NewGaugeDesc(
			"solana_cluster_last_vote",
			"Most recent voted-on slot of the cluster",
		),
		ValidatorRootSlot: NewGaugeDesc(
			"solana_validator_root_slot",
			fmt.Sprintf("Root slot per validator (represented by %s and %s)", VotekeyLabel, NodekeyLabel),
			VotekeyLabel, NodekeyLabel,
		),
		ClusterRootSlot: NewGaugeDesc(
			"solana_cluster_root_slot",
			"Max root slot of the cluster",
		),
		ValidatorDelinquent: NewGaugeDesc(
			"solana_validator_delinquent",
			fmt.Sprintf("Whether a validator (represented by %s and %s) is delinquent", VotekeyLabel, NodekeyLabel),
			VotekeyLabel, NodekeyLabel,
		),
		ClusterValidatorCount: NewGaugeDesc(
			"solana_cluster_validator_count",
			fmt.Sprintf(
				"Total number of validators in the cluster, grouped by %s ('%s' or '%s')",
				StateLabel, StateCurrent, StateDelinquent,
			),
			StateLabel,
		),
		AccountBalances: NewGaugeDesc(
			"solana_account_balance",
			fmt.Sprintf("Solana account balances, grouped by %s", AddressLabel),
			AddressLabel,
		),
		NodeVersion: NewGaugeDesc(
			"solana_node_version",
			"Node version of solana",
			VersionLabel,
		),
		NodeIdentity: NewGaugeDesc(
			"solana_node_identity",
			"Node identity of solana",
			IdentityLabel,
		),
		NodeIsHealthy: NewGaugeDesc(
			"solana_node_is_healthy",
			"Whether the node is healthy",
		),
		NodeNumSlotsBehind: NewGaugeDesc(
			"solana_node_num_slots_behind",
			"The number of slots that the node is behind the latest cluster confirmed slot.",
		),
		NodeMinimumLedgerSlot: NewGaugeDesc(
			"solana_node_minimum_ledger_slot",
			"The lowest slot that the node has information about in its ledger.",
		),
		NodeFirstAvailableBlock: NewGaugeDesc(
			"solana_node_first_available_block",
			"The slot of the lowest confirmed block that has not been purged from the node's ledger.",
		),
		NodeIsActive: NewGaugeDesc(
			"solana_node_is_active",
			fmt.Sprintf("Whether the node is active and participating in consensus (using %s pubkey)", IdentityLabel),
			IdentityLabel,
		),
	}
	return collector
}

func (c *SolanaCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.NodeVersion.Desc
	ch <- c.NodeIdentity.Desc
	ch <- c.ValidatorActiveStake.Desc
	ch <- c.ClusterActiveStake.Desc
	ch <- c.ValidatorLastVote.Desc
	ch <- c.ClusterLastVote.Desc
	ch <- c.ValidatorRootSlot.Desc
	ch <- c.ClusterRootSlot.Desc
	ch <- c.ValidatorDelinquent.Desc
	ch <- c.ClusterValidatorCount.Desc
	ch <- c.AccountBalances.Desc
	ch <- c.NodeIsHealthy.Desc
	ch <- c.NodeNumSlotsBehind.Desc
	ch <- c.NodeMinimumLedgerSlot.Desc
	ch <- c.NodeFirstAvailableBlock.Desc
	ch <- c.NodeIsActive.Desc
}

func (c *SolanaCollector) collectVoteAccounts(ctx context.Context, ch chan<- prometheus.Metric) {
	if c.config.LightMode {
		c.logger.Debug("Skipping vote-accounts collection in light mode.")
		return
	}
	c.logger.Info("Collecting vote accounts...")
	voteAccounts, err := c.rpcClient.GetVoteAccounts(ctx, rpc.CommitmentConfirmed)
	if err != nil {
		c.logger.Errorf("failed to get vote accounts: %v", err)
		ch <- c.ValidatorActiveStake.NewInvalidMetric(err)
		ch <- c.ClusterActiveStake.NewInvalidMetric(err)
		ch <- c.ValidatorLastVote.NewInvalidMetric(err)
		ch <- c.ClusterLastVote.NewInvalidMetric(err)
		ch <- c.ValidatorRootSlot.NewInvalidMetric(err)
		ch <- c.ClusterRootSlot.NewInvalidMetric(err)
		ch <- c.ValidatorDelinquent.NewInvalidMetric(err)
		ch <- c.ClusterValidatorCount.NewInvalidMetric(err)
		return
	}

	var (
		totalStake  float64
		maxLastVote float64
		maxRootSlot float64
	)
	for _, account := range append(voteAccounts.Current, voteAccounts.Delinquent...) {
		accounts := []string{account.VotePubkey, account.NodePubkey}
		stake, lastVote, rootSlot :=
			float64(account.ActivatedStake)/rpc.LamportsInSol,
			float64(account.LastVote),
			float64(account.RootSlot)

		if slices.Contains(c.config.NodeKeys, account.NodePubkey) || c.config.ComprehensiveVoteAccountTracking {
			ch <- c.ValidatorActiveStake.MustNewConstMetric(stake, accounts...)
			ch <- c.ValidatorLastVote.MustNewConstMetric(lastVote, accounts...)
			ch <- c.ValidatorRootSlot.MustNewConstMetric(rootSlot, accounts...)
		}

		totalStake += stake
		maxLastVote = max(maxLastVote, lastVote)
		maxRootSlot = max(maxRootSlot, rootSlot)
	}

	{
		for _, account := range voteAccounts.Current {
			if slices.Contains(c.config.NodeKeys, account.NodePubkey) || c.config.ComprehensiveVoteAccountTracking {
				ch <- c.ValidatorDelinquent.MustNewConstMetric(0, account.VotePubkey, account.NodePubkey)
			}
		}
		for _, account := range voteAccounts.Delinquent {
			if slices.Contains(c.config.NodeKeys, account.NodePubkey) || c.config.ComprehensiveVoteAccountTracking {
				ch <- c.ValidatorDelinquent.MustNewConstMetric(1, account.VotePubkey, account.NodePubkey)
			}
		}
	}

	ch <- c.ClusterActiveStake.MustNewConstMetric(totalStake)
	ch <- c.ClusterLastVote.MustNewConstMetric(maxLastVote)
	ch <- c.ClusterRootSlot.MustNewConstMetric(maxRootSlot)
	ch <- c.ClusterValidatorCount.MustNewConstMetric(float64(len(voteAccounts.Current)), StateCurrent)
	ch <- c.ClusterValidatorCount.MustNewConstMetric(float64(len(voteAccounts.Delinquent)), StateDelinquent)

	c.logger.Info("Vote accounts collected.")
}

func (c *SolanaCollector) collectVersion(ctx context.Context, ch chan<- prometheus.Metric) {
	c.logger.Info("Collecting version...")
	version, err := c.rpcClient.GetVersion(ctx)
	if err != nil {
		c.logger.Errorf("failed to get version: %v", err)
		ch <- c.NodeVersion.NewInvalidMetric(err)
		return
	}

	ch <- c.NodeVersion.MustNewConstMetric(1, version)
	c.logger.Info("Version collected.")
}

func (c *SolanaCollector) collectIdentity(ctx context.Context, ch chan<- prometheus.Metric) {
	c.logger.Info("Collecting identity...")
	identity, err := c.rpcClient.GetIdentity(ctx)
	if err != nil {
		c.logger.Errorf("failed to get identity: %v", err)
		ch <- c.NodeIdentity.NewInvalidMetric(err)
		return
	}

	if c.config.ActiveIdentity != "" {
		isActive := 0
		if c.config.ActiveIdentity == identity {
			isActive = 1
		}
		ch <- c.NodeIsActive.MustNewConstMetric(float64(isActive), identity)
		c.logger.Info("NodeIsActive collected.")
	}

	ch <- c.NodeIdentity.MustNewConstMetric(1, identity)
	c.logger.Info("Identity collected.")
}

func (c *SolanaCollector) collectMinimumLedgerSlot(ctx context.Context, ch chan<- prometheus.Metric) {
	c.logger.Info("Collecting minimum ledger slot...")
	slot, err := c.rpcClient.GetMinimumLedgerSlot(ctx)
	if err != nil {
		c.logger.Errorf("failed to get minimum lidger slot: %v", err)
		ch <- c.NodeMinimumLedgerSlot.NewInvalidMetric(err)
		return
	}

	ch <- c.NodeMinimumLedgerSlot.MustNewConstMetric(float64(slot))
	c.logger.Info("Minimum ledger slot collected.")
}

func (c *SolanaCollector) collectFirstAvailableBlock(ctx context.Context, ch chan<- prometheus.Metric) {
	c.logger.Info("Collecting first available block...")
	block, err := c.rpcClient.GetFirstAvailableBlock(ctx)
	if err != nil {
		c.logger.Errorf("failed to get first available block: %v", err)
		ch <- c.NodeFirstAvailableBlock.NewInvalidMetric(err)
		return
	}

	ch <- c.NodeFirstAvailableBlock.MustNewConstMetric(float64(block))
	c.logger.Info("First available block collected.")
}

func (c *SolanaCollector) collectBalances(ctx context.Context, ch chan<- prometheus.Metric) {
	if c.config.LightMode {
		c.logger.Debug("Skipping balance collection in light mode.")
		return
	}
	c.logger.Info("Collecting balances...")
	balances, err := FetchBalances(
		ctx, c.rpcClient, CombineUnique(c.config.BalanceAddresses, c.config.NodeKeys, c.config.VoteKeys),
	)
	if err != nil {
		c.logger.Errorf("failed to get balances: %v", err)
		ch <- c.AccountBalances.NewInvalidMetric(err)
		return
	}

	for address, balance := range balances {
		ch <- c.AccountBalances.MustNewConstMetric(balance, address)
	}
	c.logger.Info("Balances collected.")
}

func (c *SolanaCollector) collectHealth(ctx context.Context, ch chan<- prometheus.Metric) {
	c.logger.Info("Collecting health...")
	var (
		isHealthy      = 1
		numSlotsBehind int64
	)

	_, err := c.rpcClient.GetHealth(ctx)
	if err != nil {
		var rpcError *rpc.RPCError
		if errors.As(err, &rpcError) {
			var errorData rpc.NodeUnhealthyErrorData
			if rpcError.Data == nil {
				// if there is no data, then this is some unexpected error and should just be logged
				c.logger.Errorf("failed to get health: %v", err)
				ch <- c.NodeIsHealthy.NewInvalidMetric(err)
				ch <- c.NodeNumSlotsBehind.NewInvalidMetric(err)
				return
			}
			if err = rpc.UnpackRpcErrorData(rpcError, &errorData); err != nil {
				// if we error here, it means we have the incorrect format
				c.logger.Fatalf("failed to unpack %s rpc error: %v", rpcError.Method, err.Error())
			}
			isHealthy = 0
			numSlotsBehind = errorData.NumSlotsBehind
		} else {
			// if it's not an RPC error, log it
			c.logger.Errorf("failed to get health: %v", err)
			ch <- c.NodeIsHealthy.NewInvalidMetric(err)
			ch <- c.NodeNumSlotsBehind.NewInvalidMetric(err)
			return
		}
	}

	ch <- c.NodeIsHealthy.MustNewConstMetric(float64(isHealthy))
	ch <- c.NodeNumSlotsBehind.MustNewConstMetric(float64(numSlotsBehind))
	c.logger.Info("Health collected.")
	return
}

func (c *SolanaCollector) Collect(ch chan<- prometheus.Metric) {
	c.logger.Info("========== BEGIN COLLECTION ==========")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.collectHealth(ctx, ch)
	c.collectMinimumLedgerSlot(ctx, ch)
	c.collectFirstAvailableBlock(ctx, ch)
	c.collectVoteAccounts(ctx, ch)
	c.collectVersion(ctx, ch)
	c.collectIdentity(ctx, ch)
	c.collectBalances(ctx, ch)

	c.logger.Info("=========== END COLLECTION ===========")
}
