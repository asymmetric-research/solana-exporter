package main

import (
	"context"
	"fmt"

	"slices"

	"github.com/asymmetric-research/solana-exporter/pkg/rpc"
	"github.com/asymmetric-research/solana-exporter/pkg/slog"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
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
	ValidatorActiveStake               *GaugeDesc
	ClusterActiveStake                 *GaugeDesc
	ValidatorLastVote                  *GaugeDesc
	ClusterLastVote                    *GaugeDesc
	ValidatorRootSlot                  *GaugeDesc
	ClusterRootSlot                    *GaugeDesc
	ValidatorDelinquent                *GaugeDesc
	ClusterValidatorCount              *GaugeDesc
	AccountBalances                    *GaugeDesc
	NodeVersion                        *GaugeDesc
	NodeIsHealthy                      *GaugeDesc
	NodeNumSlotsBehind                 *GaugeDesc
	NodeMinimumLedgerSlot              *GaugeDesc
	NodeFirstAvailableBlock            *GaugeDesc
	NodeIdentity                       *GaugeDesc
	NodeIsActive                       *GaugeDesc
	ValidatorCommission                *GaugeDesc
	ValidatorSkipPercentage            *GaugeDesc
	NetworkSkipPercentage              *GaugeDesc
	ValidatorSkipDelta                 *GaugeDesc
	NetworkDelinquentPercentage        *GaugeDesc
	NetworkEpochElapsedPercentage      *GaugeDesc
	ValidatorVotePerformancePercentage *GaugeDesc
	ValidatorNewerVersionsPercentage   *GaugeDesc
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
		ValidatorCommission: NewGaugeDesc(
			"solana_validator_commission",
			fmt.Sprintf("Validator commission, as a percentage (represented by %s and %s)", VotekeyLabel, NodekeyLabel),
			VotekeyLabel, NodekeyLabel,
		),
		ValidatorSkipPercentage: NewGaugeDesc(
			"solana_validator_skip_percentage",
			fmt.Sprintf("Validator skip percentage for the current epoch (represented by %s and %s)", VotekeyLabel, NodekeyLabel),
			VotekeyLabel, NodekeyLabel,
		),
		NetworkSkipPercentage: NewGaugeDesc(
			"solana_network_skip_percentage",
			"Network-wide skip percentage for the current epoch",
		),
		ValidatorSkipDelta: NewGaugeDesc(
			"solana_validator_skip_delta",
			fmt.Sprintf("How validator skip rate compares to network average, as a percentage (represented by %s and %s). Positive values indicate worse performance than network average", VotekeyLabel, NodekeyLabel),
			VotekeyLabel, NodekeyLabel,
		),
		NetworkDelinquentPercentage: NewGaugeDesc(
			"solana_network_delinquent_percentage",
			"Percentage of total stake that is delinquent",
		),
		NetworkEpochElapsedPercentage: NewGaugeDesc(
			"solana_network_epoch_elapsed_percentage",
			"How far through the current epoch (0-100%)",
		),
		ValidatorVotePerformancePercentage: NewGaugeDesc(
			"solana_validator_vote_performance_percentage",
			fmt.Sprintf("Validator voting performance percentage vs expected (represented by %s and %s)", VotekeyLabel, NodekeyLabel),
			VotekeyLabel, NodekeyLabel,
		),
		ValidatorNewerVersionsPercentage: NewGaugeDesc(
			"solana_validator_newer_versions_percentage",
			fmt.Sprintf("Percentage of stake running newer software versions than this validator (represented by %s and %s)", VotekeyLabel, NodekeyLabel),
			VotekeyLabel, NodekeyLabel,
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
	ch <- c.ValidatorCommission.Desc
	ch <- c.ValidatorSkipPercentage.Desc
	ch <- c.NetworkSkipPercentage.Desc
	ch <- c.ValidatorSkipDelta.Desc
	ch <- c.NetworkDelinquentPercentage.Desc
	ch <- c.NetworkEpochElapsedPercentage.Desc
	ch <- c.ValidatorVotePerformancePercentage.Desc
	ch <- c.ValidatorNewerVersionsPercentage.Desc
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
		ch <- c.ValidatorCommission.NewInvalidMetric(err)
		return
	}

	var (
		totalStake  float64
		maxLastVote float64
		maxRootSlot float64
	)
	for _, account := range append(voteAccounts.Current, voteAccounts.Delinquent...) {
		accounts := []string{account.VotePubkey, account.NodePubkey}
		stake, lastVote, rootSlot, commission :=
			float64(account.ActivatedStake)/rpc.LamportsInSol,
			float64(account.LastVote),
			float64(account.RootSlot),
			float64(account.Commission)

		if slices.Contains(c.config.Nodekeys, account.NodePubkey) || c.config.ComprehensiveVoteAccountTracking {
			ch <- c.ValidatorActiveStake.MustNewConstMetric(stake, accounts...)
			ch <- c.ValidatorLastVote.MustNewConstMetric(lastVote, accounts...)
			ch <- c.ValidatorRootSlot.MustNewConstMetric(rootSlot, accounts...)
			ch <- c.ValidatorCommission.MustNewConstMetric(commission, accounts...)
		}

		totalStake += stake
		maxLastVote = max(maxLastVote, lastVote)
		maxRootSlot = max(maxRootSlot, rootSlot)
	}

	{
		for _, account := range voteAccounts.Current {
			if slices.Contains(c.config.Nodekeys, account.NodePubkey) || c.config.ComprehensiveVoteAccountTracking {
				ch <- c.ValidatorDelinquent.MustNewConstMetric(0, account.VotePubkey, account.NodePubkey)
			}
		}
		for _, account := range voteAccounts.Delinquent {
			if slices.Contains(c.config.Nodekeys, account.NodePubkey) || c.config.ComprehensiveVoteAccountTracking {
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
	if c.config.LightMode {
		c.logger.Debug("Skipping minimum ledger slot collection in light mode.")
		return
	}
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
	if c.config.LightMode {
		c.logger.Debug("Skipping first available block collection in light mode.")
		return
	}
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
		ctx, c.rpcClient, CombineUnique(c.config.BalanceAddresses, c.config.Nodekeys, c.config.Votekeys),
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

	health, err := c.rpcClient.GetHealth(ctx)
	isHealthy, isHealthyErr, numSlotsBehind, numSlotsBehindErr := ExtractHealthAndNumSlotsBehind(health, err)
	if isHealthyErr != nil {
		c.logger.Errorf("failed to determine node health: %v", isHealthyErr)
		ch <- c.NodeIsHealthy.NewInvalidMetric(err)
	} else {
		ch <- c.NodeIsHealthy.MustNewConstMetric(BoolToFloat64(isHealthy))
	}

	if numSlotsBehindErr != nil {
		c.logger.Errorf("failed to determine number of slots behind: %v", numSlotsBehindErr)
		ch <- c.NodeNumSlotsBehind.NewInvalidMetric(numSlotsBehindErr)
	} else {
		ch <- c.NodeNumSlotsBehind.MustNewConstMetric(float64(numSlotsBehind))
	}

	c.logger.Info("Health collected.")
	return
}

func (c *SolanaCollector) collectValidatorSkipPercentage(ctx context.Context, ch chan<- prometheus.Metric) {
	if c.config.LightMode {
		c.logger.Debug("Skipping validator skip percentage collection in light mode.")
		return
	}
	c.logger.Debug("Collecting validator skip percentage...")

	blockProduction, err := c.getBlockProductionData(ctx)
	if err != nil {
		c.logger.Errorf("failed to get block production data: %v", err)
		ch <- c.ValidatorSkipPercentage.NewInvalidMetric(err)
		return
	}

	// If no block production data is available, skip collection
	if blockProduction == nil || len(blockProduction.ByIdentity) == 0 {
		c.logger.Debug("No block production data available, skipping skip percentage collection")
		return
	}

	// Calculate skip percentage for each configured validator
	for _, nodekey := range c.config.Nodekeys {
		production, exists := blockProduction.ByIdentity[nodekey]
		if !exists {
			c.logger.Debugf("No block production data found for validator %s", nodekey)
			continue
		}

		skipPercentage := c.calculateValidatorSkipPercentage(production)

		// Find associated votekey for this nodekey
		votekey := c.findVotekeyForNodekey(nodekey)
		if votekey != "" {
			ch <- c.ValidatorSkipPercentage.MustNewConstMetric(skipPercentage, votekey, nodekey)
		}
	}

	c.logger.Debug("Validator skip percentage collected.")
}

func (c *SolanaCollector) collectNetworkSkipPercentage(ctx context.Context, ch chan<- prometheus.Metric) {
	if c.config.LightMode {
		c.logger.Debug("Skipping network skip percentage collection in light mode.")
		return
	}
	c.logger.Debug("Collecting network skip percentage...")

	blockProduction, err := c.getBlockProductionData(ctx)
	if err != nil {
		c.logger.Errorf("failed to get block production data: %v", err)
		ch <- c.NetworkSkipPercentage.NewInvalidMetric(err)
		return
	}

	networkSkipPercentage := c.calculateNetworkSkipPercentage(blockProduction)
	if networkSkipPercentage > 0 {
		ch <- c.NetworkSkipPercentage.MustNewConstMetric(networkSkipPercentage)
	}

	c.logger.Debug("Network skip percentage collected.")
}

func (c *SolanaCollector) collectValidatorSkipDelta(ctx context.Context, ch chan<- prometheus.Metric) {
	if c.config.LightMode {
		c.logger.Debug("Skipping validator skip delta collection in light mode.")
		return
	}
	c.logger.Debug("Collecting validator skip delta...")

	blockProduction, err := c.getBlockProductionData(ctx)
	if err != nil {
		c.logger.Errorf("failed to get block production data: %v", err)
		ch <- c.ValidatorSkipDelta.NewInvalidMetric(err)
		return
	}

	// If no block production data is available, skip collection
	if blockProduction == nil || len(blockProduction.ByIdentity) == 0 {
		c.logger.Debug("No block production data available, skipping validator skip delta collection")
		return
	}

	// Calculate network skip percentage
	networkSkipPercentage := c.calculateNetworkSkipPercentage(blockProduction)

	// Calculate skip delta for each configured validator
	for _, nodekey := range c.config.Nodekeys {
		production, exists := blockProduction.ByIdentity[nodekey]
		if !exists {
			c.logger.Debugf("No block production data found for validator %s", nodekey)
			continue
		}

		// Calculate validator skip percentage
		validatorSkipPercentage := c.calculateValidatorSkipPercentage(production)

		// Calculate skip delta: 100 * (validator_skip - network_skip) / network_skip
		var skipDelta float64
		if networkSkipPercentage > 0 {
			skipDelta = 100 * (validatorSkipPercentage - networkSkipPercentage) / networkSkipPercentage
		}

		// Find associated votekey for this nodekey
		votekey := c.findVotekeyForNodekey(nodekey)
		if votekey != "" {
			ch <- c.ValidatorSkipDelta.MustNewConstMetric(skipDelta, votekey, nodekey)
		}
	}

	c.logger.Debug("Validator skip delta collected.")
}

func (c *SolanaCollector) collectNetworkDelinquentPercentage(ctx context.Context, ch chan<- prometheus.Metric) {
	if c.config.LightMode {
		c.logger.Debug("Skipping network delinquent percentage collection in light mode.")
		return
	}
	c.logger.Debug("Collecting network delinquent percentage...")

	voteAccounts, err := c.rpcClient.GetVoteAccounts(ctx, rpc.CommitmentConfirmed)
	if err != nil {
		c.logger.Errorf("failed to get vote accounts: %v", err)
		ch <- c.NetworkDelinquentPercentage.NewInvalidMetric(err)
		return
	}

	delinquentPercentage := c.calculateNetworkDelinquentPercentage(voteAccounts)
	ch <- c.NetworkDelinquentPercentage.MustNewConstMetric(delinquentPercentage)

	c.logger.Debug("Network delinquent percentage collected.")
}

func (c *SolanaCollector) collectNetworkEpochElapsedPercentage(ctx context.Context, ch chan<- prometheus.Metric) {
	if c.config.LightMode {
		c.logger.Debug("Skipping network epoch elapsed percentage collection in light mode.")
		return
	}
	c.logger.Debug("Collecting network epoch elapsed percentage...")

	epochInfo, err := c.rpcClient.GetEpochInfo(ctx, rpc.CommitmentConfirmed)
	if err != nil {
		c.logger.Errorf("failed to get epoch info: %v", err)
		ch <- c.NetworkEpochElapsedPercentage.NewInvalidMetric(err)
		return
	}

	epochElapsedPercentage := c.calculateNetworkEpochElapsedPercentage(epochInfo)
	ch <- c.NetworkEpochElapsedPercentage.MustNewConstMetric(epochElapsedPercentage)

	c.logger.Debug("Network epoch elapsed percentage collected.")
}

func (c *SolanaCollector) collectValidatorVotePerformancePercentage(ctx context.Context, ch chan<- prometheus.Metric) {
	if c.config.LightMode {
		c.logger.Debug("Skipping validator vote performance percentage collection in light mode.")
		return
	}
	c.logger.Debug("Collecting validator vote performance percentage...")

	// Get epoch info to calculate epoch elapsed percentage
	epochInfo, err := c.rpcClient.GetEpochInfo(ctx, rpc.CommitmentConfirmed)
	if err != nil {
		c.logger.Errorf("failed to get epoch info: %v", err)
		ch <- c.ValidatorVotePerformancePercentage.NewInvalidMetric(err)
		return
	}

	epochElapsedPercentage := c.calculateNetworkEpochElapsedPercentage(epochInfo)
	if epochElapsedPercentage <= 0 {
		c.logger.Debug("Epoch elapsed percentage is 0, skipping vote performance collection")
		return
	}

	// Process each configured validator
	for _, nodekey := range c.config.Nodekeys {
		votekey := c.findVotekeyForNodekey(nodekey)
		if votekey == "" {
			c.logger.Debugf("No votekey found for nodekey %s, skipping vote performance collection", nodekey)
			continue
		}

		// Get vote account data to get current epoch credits
		var voteAccountData rpc.VoteAccountData
		_, err := rpc.GetAccountInfo(ctx, c.rpcClient, rpc.CommitmentConfirmed, votekey, &voteAccountData)
		if err != nil {
			c.logger.Errorf("failed to get vote account data for %s: %v", votekey, err)
			continue
		}

		// Count current votes (credits) from the Votes array
		// This is equivalent to what the CLI "vote-account" command shows as "credits/slots"
		currentVotes := int64(len(voteAccountData.Votes))

		if currentVotes <= 0 {
			c.logger.Debugf("No votes found for validator %s, skipping vote performance collection", nodekey)
			continue
		}

		// Calculate vote performance percentage
		votePerformancePercentage := c.calculateValidatorVotePerformancePercentage(currentVotes, epochElapsedPercentage)
		ch <- c.ValidatorVotePerformancePercentage.MustNewConstMetric(votePerformancePercentage, votekey, nodekey)
	}

	c.logger.Debug("Validator vote performance percentage collected.")
}

func (c *SolanaCollector) collectValidatorNewerVersionsPercentage(ctx context.Context, ch chan<- prometheus.Metric) {
	if c.config.LightMode {
		c.logger.Debug("Skipping validator newer versions percentage collection in light mode.")
		return
	}
	c.logger.Debug("Collecting validator newer versions percentage...")

	// Get current validator's version
	currentVersion, err := c.rpcClient.GetVersion(ctx)
	if err != nil {
		c.logger.Errorf("failed to get current validator version: %v", err)
		ch <- c.ValidatorNewerVersionsPercentage.NewInvalidMetric(err)
		return
	}

	// Process each configured validator
	for _, nodekey := range c.config.Nodekeys {
		votekey := c.findVotekeyForNodekey(nodekey)
		if votekey == "" {
			c.logger.Debugf("No votekey found for nodekey %s, skipping newer versions percentage collection", nodekey)
			continue
		}

		// Calculate newer versions percentage
		newerVersionsPercentage := c.calculateValidatorNewerVersionsPercentage(currentVersion)
		ch <- c.ValidatorNewerVersionsPercentage.MustNewConstMetric(newerVersionsPercentage, votekey, nodekey)
	}

	c.logger.Debug("Validator newer versions percentage collected.")
}

// findVotekeyForNodekey finds the associated votekey for a given nodekey
func (c *SolanaCollector) findVotekeyForNodekey(nodekey string) string {
	// Find the index of the nodekey in the config
	for i, configNodekey := range c.config.Nodekeys {
		if configNodekey == nodekey && i < len(c.config.Votekeys) {
			return c.config.Votekeys[i]
		}
	}
	return ""
}

// getBlockProductionData gets block production data for the current epoch
func (c *SolanaCollector) getBlockProductionData(ctx context.Context) (*rpc.BlockProduction, error) {
	// Get current epoch info to determine the slot range
	epochInfo, err := c.rpcClient.GetEpochInfo(ctx, rpc.CommitmentConfirmed)
	if err != nil {
		return nil, fmt.Errorf("failed to get epoch info: %w", err)
	}

	// Calculate epoch bounds
	firstSlot, lastSlot := GetEpochBounds(epochInfo)

	// Limit the query to the current slot to avoid querying future slots
	currentSlot := epochInfo.AbsoluteSlot
	if lastSlot > currentSlot {
		lastSlot = currentSlot
	}

	// Get block production data for the current epoch (up to current slot)
	blockProduction, err := c.rpcClient.GetBlockProduction(ctx, rpc.CommitmentConfirmed, firstSlot, lastSlot)
	if err != nil {
		return nil, fmt.Errorf("failed to get block production: %w", err)
	}

	return blockProduction, nil
}

// calculateValidatorSkipPercentage calculates skip percentage for a single validator
func (c *SolanaCollector) calculateValidatorSkipPercentage(production rpc.HostProduction) float64 {
	if production.LeaderSlots > 0 {
		skippedSlots := production.LeaderSlots - production.BlocksProduced
		return float64(skippedSlots) / float64(production.LeaderSlots) * 100
	}
	return 0
}

// calculateNetworkSkipPercentage calculates network-wide skip percentage
func (c *SolanaCollector) calculateNetworkSkipPercentage(blockProduction *rpc.BlockProduction) float64 {
	if blockProduction == nil || len(blockProduction.ByIdentity) == 0 {
		return 0
	}

	// Calculate network-wide totals
	var totalLeaderSlots, totalBlocksProduced int64
	for _, production := range blockProduction.ByIdentity {
		totalLeaderSlots += production.LeaderSlots
		totalBlocksProduced += production.BlocksProduced
	}

	// Calculate network-wide skip percentage
	if totalLeaderSlots > 0 {
		totalSkippedSlots := totalLeaderSlots - totalBlocksProduced
		return float64(totalSkippedSlots) / float64(totalLeaderSlots) * 100
	}
	return 0
}

// calculateNetworkDelinquentPercentage calculates the percentage of total stake that is delinquent
func (c *SolanaCollector) calculateNetworkDelinquentPercentage(voteAccounts *rpc.VoteAccounts) float64 {
	if voteAccounts == nil {
		return 0
	}

	// Calculate total active stake (current + delinquent)
	var totalActiveStake, totalDelinquentStake int64
	for _, account := range voteAccounts.Current {
		totalActiveStake += account.ActivatedStake
	}
	for _, account := range voteAccounts.Delinquent {
		totalActiveStake += account.ActivatedStake
		totalDelinquentStake += account.ActivatedStake
	}

	// Calculate delinquent percentage: 100 * totalDelinquentStake / totalActiveStake
	if totalActiveStake > 0 {
		return float64(totalDelinquentStake) / float64(totalActiveStake) * 100
	}
	return 0
}

// calculateNetworkEpochElapsedPercentage calculates how far through the current epoch (0-100%)
func (c *SolanaCollector) calculateNetworkEpochElapsedPercentage(epochInfo *rpc.EpochInfo) float64 {
	if epochInfo == nil || epochInfo.SlotsInEpoch <= 0 {
		return 0
	}

	// Calculate epoch elapsed percentage: 100 * slotIndex / slotsInEpoch
	return float64(epochInfo.SlotIndex) / float64(epochInfo.SlotsInEpoch) * 100
}

// calculateValidatorVotePerformancePercentage calculates validator voting performance vs expected
func (c *SolanaCollector) calculateValidatorVotePerformancePercentage(currentVotes int64, epochElapsedPercentage float64) float64 {
	if currentVotes <= 0 || epochElapsedPercentage <= 0 {
		return 0
	}

	// The reference script calculation:
	// voteElapsed = pctEpochElapsed / 100 * 432000
	// pctVote = validatorCreditsCurrent / voteElapsed * 100
	//
	// Where validatorCreditsCurrent comes from CLI "vote-account" command
	// and represents the current votes (credits) earned so far

	// Expected total votes per epoch is 432000 (from reference script)
	const expectedVotesPerEpoch = 432000.0

	// Calculate expected votes by this point in the epoch
	expectedVotes := epochElapsedPercentage / 100.0 * expectedVotesPerEpoch

	// Calculate vote performance percentage: 100 * currentVotes / expectedVotes
	return float64(currentVotes) / expectedVotes * 100
}

// calculateValidatorNewerVersionsPercentage calculates percentage of stake running newer software versions
func (c *SolanaCollector) calculateValidatorNewerVersionsPercentage(currentValidatorVersion string) float64 {
	if currentValidatorVersion == "" {
		return 0
	}

	c.logger.Debugf("Newer versions percentage calculation not fully implemented - requires CLI data not available via RPC")
	return 0
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
	c.collectValidatorSkipPercentage(ctx, ch)
	c.collectNetworkSkipPercentage(ctx, ch)
	c.collectValidatorSkipDelta(ctx, ch)
	c.collectNetworkDelinquentPercentage(ctx, ch)
	c.collectNetworkEpochElapsedPercentage(ctx, ch)
	c.collectValidatorVotePerformancePercentage(ctx, ch)
	c.collectValidatorNewerVersionsPercentage(ctx, ch)

	c.logger.Info("=========== END COLLECTION ===========")
}
