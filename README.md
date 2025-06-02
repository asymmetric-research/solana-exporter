# Solana Exporter
## Overview

The Solana Exporter exports basic monitoring data from a Solana node, using the 
[Solana RPC API](https://solana.com/docs/rpc).

### Example Usage

To use the Solana Exporter, simply run the program with the desired 
[command line configuration](#Command-Line-Arguments), e.g.,

```shell
solana-exporter \
  -nodekey <VALIDATOR_IDENTITY_1> -nodekey <VALIDATOR_IDENTITY_2> \
  -balance-address <ADDRESS_1> -balance-address <ADDRESS_2> \
  -comprehensive-slot-tracking \
  -monitor-block-sizes
  -active-identity <MY_ACTIVE_IDENTITY>
```

![Solana Exporter Dashboard Sample](assets/solana-dashboard-screenshot.png)

### Features
#### Balance Tracking

Using the `-balance-address <ADDRESS>` configuration parameter, the exporter can be used to monitor any account's
SOL balance. This parameter can be set multiple times to track multiple accounts. Additionally, the balance of all 
configured `-nodekey`'s is automatically tracked.

#### Block Sizes

If the `-monitor-block-sizes` flag is set, then the exporter will export the number of transactions (both vote-only and 
non-vote transactions) in blocks produced by the monitored validators. This is a critical validator performance metric. 

Cluster average block size can be inferred by dividing total network transactions by total block height.

#### Income Reporting

The exporter exports metrics regarding total priority fee revenue and inflation reward revenue earned by the 
monitored validators.

#### Skip Rate

The exporter does not directly export skip rate, as this needs to be defined as an average over a desired timeframe. 
However, the exporter does track the monitored validators leader slots and whether they are `valid` or `skipped`.

The example prometheus setup contains [recording rules](prometheus/solana-rules.yml) for measuring average skip rate 
for both individual validators and a cluster-level over hourly, daily and epoch intervals.

#### Active/Passive Monitoring

The `solana_node_is_active` metric simply reports whether the node (on which the exporter is running) has the same 
identity-keypair as that configured with the `-active-identity` flag. The `-active-identity` flag should be used to 
specify the primary identity when using a 
[non-delinquent backup validator](https://pumpkins-pool.gitbook.io/pumpkins-pool).

#### Light Mode

Certain metrics, such as validator leader slots, income, block size and active stake, are visible on-chain through any 
trusted node. However, other metrics such as node health and block height can only be viewed from an exporter running 
on the node in question. Thus, on a node in which fine margins of performance are of critical interest, the exporter 
can be set to `-light-mode`. In light mode, it will only export metrics that cannot be viewed from other nodes.

This is particularly useful in setups that contain an important validator and utility RPC node - the exporter can be 
run in light mode on the validator and in full capacity on the RPC node (configured to monitor the validator through 
use of the `-nodekey` parameter).

#### General Performance and Health

In addition to the above features, the exporter provides key metrics for monitoring Solana node health and performance. 
See [Metrics](#metrics) below for more details.

## Installation
### Build

Assuming you already have [Go installed](https://go.dev/doc/install), the `solana-exporter` can be installed by 
cloning this repository and building the binary:

```shell
git clone https://github.com/asymmetric-research/solana-exporter.git
cd solana-exporter
CGO_ENABLED=0 go build ./cmd/solana-exporter
```

## Configuration
### Command Line Arguments

The exporter is configured via the following command line arguments:

| Option                                 | Description                                                                                                                                                                                                             | Default                   |
|----------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------|
| `-balance-address`                     | Address to monitor SOL balances for, in addition to the identity and vote accounts of the provided nodekeys - can be set multiple times.                                                                                | N/A                       |
| `-comprehensive-slot-tracking`         | Set this flag to track `solana_leader_slots_by_epoch` for all validators.                                                                                                                                               | `false`                   |
| `-comprehensive-vote-account-tracking` | Set this flag to track vote-account metrics for all validators.                                                                                                                                                         | `false`                   |
| `-http-timeout`                        | HTTP timeout to use, in seconds.                                                                                                                                                                                        | `60`                      |
| `-light-mode`                          | Set this flag to enable light-mode. In light mode, only metrics unique to the node being queried are reported (i.e., metrics such as `solana_inflation_rewards` which are visible from any RPC node, are not reported). | `false`                   |
| `-listen-address`                      | Prometheus listen address.                                                                                                                                                                                              | `":8080"`                 |
| `-monitor-block-sizes`                 | Set this flag to track block sizes (number of transactions) for the configured validators.                                                                                                                              | `false`                   |
| `-nodekey`                             | Solana nodekey (identity account) representing a validator to monitor - can set multiple times.                                                                                                                         | N/A                       |
| `-rpc-url`                             | Solana RPC URL (including protocol and path), e.g., `"http://localhost:8899"` or `"https://api.mainnet-beta.solana.com"`                                                                                                | `"http://localhost:8899"` |
| `-slot-pace`                           | This is the time (in seconds) between slot-watching metric collections                                                                                                                                                  | `1`                       |
| `-active-identity`                     | Validator identity public key used to determine if the node is considered active in the `solana_node_is_active` metric.                                                                                                 | N/A                       |
| `-epoch-cleanup-time`                  | The time to wait before cleaning old epoch metrics from the prometheus endpoint.                                                                                                                                        | `60`                      |
| `-firedancer-metrics-port`             | Port number for Firedancer metrics endpoint.                                                                                                                                                                            | `7999`                    |

### Notes on Configuration

* `-light-mode` is incompatible with `-nodekey`, `-balance-address`, `-monitor-block-sizes`, and 
`-comprehensive-slot-tracking`, as these options control metrics which are not monitored in `-light-mode`.
* ***WARNING***:
  * Configuring `-comprehensive-slot-tracking` will lead to potentially thousands of new Prometheus metrics being 
  created every epoch.
  * Configuring `-monitor-block-sizes` with many `-nodekey`'s can potentially strain the node - every block produced 
  by a configured `-nodekey` is fetched, and a typical block can be as large as 5MB.

## Metrics
### Overview

The tables below describes all the metrics collected by the `solana-exporter`:

| Metric                                         | Description                                                                                                           | Labels                        |
|------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------|-------------------------------|
| `solana_validator_active_stake`                | Active stake (in SOL) per validator.                                                                                  | `votekey`, `nodekey`          |
| `solana_cluster_active_stake`                  | Total active stake (in SOL) of the cluster.                                                                           | N/A                           |
| `solana_validator_last_vote`                   | Last voted-on slot per validator.                                                                                     | `votekey`, `nodekey`          |
| `solana_cluster_last_vote`                     | Most recent voted-on slot of the cluster.                                                                             | N/A                           |
| `solana_validator_root_slot`                   | Root slot per validator.                                                                                              | `votekey`, `nodekey`          |
| `solana_cluster_root_slot`                     | Max root slot of the cluster.                                                                                         | N/A                           |
| `solana_validator_delinquent`                  | Whether a validator is delinquent.                                                                                    | `votekey`, `nodekey`          |
| `solana_cluster_validator_count`               | Total number of validators in the cluster.                                                                            | `state`                       |
| `solana_account_balance`                       | Solana account balances.                                                                                              | `address`                     |
| `solana_node_version`                          | Node version of solana.                                                                                               | `version`                     |
| `solana_node_is_healthy`                       | Whether the node is healthy.                                                                                          | N/A                           |
| `solana_node_num_slots_behind`                 | The number of slots that the node is behind the latest cluster confirmed slot.                                        | N/A                           |
| `solana_node_minimum_ledger_slot`              | The lowest slot that the node has information about in its ledger.                                                    | N/A                           |
| `solana_node_first_available_block`            | The slot of the lowest confirmed block that has not been purged from the node's ledger.                               | N/A                           |
| `solana_node_transactions_total`               | Total number of transactions processed without error since genesis.                                                   | N/A                           |
| `solana_node_slot_height`                      | The current slot number.                                                                                              | N/A                           |
| `solana_node_epoch_number`                     | The current epoch number.                                                                                             | N/A                           |
| `solana_node_epoch_first_slot`                 | Current epoch's first slot \[inclusive\].                                                                             | N/A                           |
| `solana_node_epoch_last_slot`                  | Current epoch's last slot \[inclusive\].                                                                              | N/A                           |
| `solana_validator_leader_slots_total`          | Number of slots processed.                                                                                            | `status`, `nodekey`           |
| `solana_validator_leader_slots_by_epoch_total` | Number of slots processed per validator.                                                                              | `status`, `nodekey`, `epoch`  |
| `solana_cluster_slots_by_epoch_total`          | Number of slots processed by the cluster.                                                                             | `status`, `epoch`             |
| `solana_validator_inflation_rewards`           | Inflation reward earned.                                                                                              | `votekey`, `epoch`            |
| `solana_validator_fee_rewards`                 | Transaction fee rewards earned.                                                                                       | `nodekey`, `epoch`            |
| `solana_validator_block_size`                  | Number of transactions per block.                                                                                     | `nodekey`, `transaction_type` |
| `solana_node_block_height`                     | The current block height of the node.                                                                                 | N/A                           |
| `solana_node_is_active`                        | Whether the node is active and participating in consensus.                                                            | `identity`                    |

#### Vote Account Metrics

The following metrics are all received from the `getVoteAccounts` [RPC endpoint](https://solana.com/docs/rpc/http/getvoteaccounts):
* `solana_validator_active_stake`
* `solana_validator_last_vote`
* `solana_validator_root_slot`
* `solana_validator_delinquent`

***NOTE***: If `-comprehensive-vote-account-tracking` is configured, then these metrics are tracked for **all** 
validators. Regardless of comprehensive tracking, the above metrics' cluster counterparts are always tracked for easy 
cluster-level comparison.

### Labels

The table below describes the various metric labels:

| Label              | Description                                   | Options / Example                                    | 
|--------------------|-----------------------------------------------|------------------------------------------------------|
| `nodekey`          | Validator identity account address.           | e.g, `Certusm1sa411sMpV9FPqU5dXAYhmmhygvxJ23S6hJ24`  | 
| `votekey`          | Validator vote account address.               | e.g., `CertusDeBmqN8ZawdkxK5kFGMwBXdudvWHYwtNgNhvLu` |
| `address`          | Solana account address.                       | e.g., `Certusm1sa411sMpV9FPqU5dXAYhmmhygvxJ23S6hJ24` |
| `version`          | Solana node version.                          | e.g., `v1.18.23`                                     |
| `state`            | Whether a validator is current or delinquent. | `current`, `delinquent`                              |
| `status`           | Whether a slot was skipped or valid.          | `valid`, `skipped`                                   |
| `epoch`            | Solana epoch number.                          | e.g., `663`                                          |
| `transaction_type` | General transaction type.                     | `vote`, `non_vote`                                   |
