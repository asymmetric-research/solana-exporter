# v3.0.2

## Key Changes

Added the `-votekey` config parameter, and in the process allowed monitoring of unstaked validators.

## What's Changed.

* Added the `-votekey` config parameter.
* Allowed monitoring of unstaked validators.

# v3.0.1

## Key Changes

Fixed the unpacking bug that caused the exporter to crash when receiving the target node was unhealthy.

## What's Changed

* Fixed the unpacking bug that caused the exporter to crash when receiving the target node was unhealthy (**[@Managarmrr](https://github.com/Managarmrr)**).
* Added tests for the collection of `solana_node_is_healthy` and `solana_node_num_slots_behind` (**[@johnstonematt](https://github.com/johnstonematt)**)

## New Contributors

* **[@Managarmrr](https://github.com/Managarmrr)** made their first contribution in **[#92](https://github.com/asymmetric-research/solana-exporter/pull/92)**.

# v3.0.0

## Key Changes

The new `solana-exporter` (renamed from `solana_exporter`) contains many new metrics, standardised naming conventions 
and more configurability.

## What's Changed
### Metric Updates
#### New Metrics

Below is a list of newly added metrics (see the [README](README.md) 
for metric descriptions):

* `solana_account_balance` (**[@johnstonematt](https://github.com/johnstonematt)**)
* `solana_node_is_healthy` (**[@GranderStark](https://github.com/GranderStark)**)
* `solana_node_num_slots_behind` (**[@GranderStark](https://github.com/GranderStark)**)
* `solana_node_minimum_ledger_slot` (**[@GranderStark](https://github.com/GranderStark)**)
* `solana_node_first_available_block` (**[@GranderStark](https://github.com/GranderStark)**)
* `solana_cluster_slots_by_epoch_total` (**[@johnstonematt](https://github.com/johnstonematt)**) 
* `solana_validator_fee_rewards` (**[@johnstonematt](https://github.com/johnstonematt)**)
* `solana_validator_block_size` (**[@johnstonematt](https://github.com/johnstonematt)**)
* `solana_node_block_height` (**[@GranderStark](https://github.com/GranderStark)**)
* `solana_cluster_active_stake` (**[@johnstonematt](https://github.com/johnstonematt)**)
* `solana_cluster_last_vote` (**[@johnstonematt](https://github.com/johnstonematt)**)
* `solana_cluster_root_slot` (**[@johnstonematt](https://github.com/johnstonematt)**)
* `solana_cluster_validator_count` (**[@johnstonematt](https://github.com/johnstonematt)**)
* `solana_node_identity` (**[@impactdni2](https://github.com/impactdni2)**)
* `solana_node_is_active` (**[@andreclaro](https://github.com/andreclaro)**)

#### Renamed Metrics

The table below contains all metrics renamed in `v3.0.0` (**[@johnstonematt](https://github.com/johnstonematt)**):

| Old Name                              | New Name                                       |
|---------------------------------------|------------------------------------------------|
| `solana_validator_activated_stake`    | `solana_validator_active_stake`                |
| `solana_confirmed_transactions_total` | `solana_node_transactions_total`               |
| `solana_confirmed_slot_height`        | `solana_node_slot_height`                      |
| `solana_confirmed_epoch_number`       | `solana_node_epoch_number`                     |
| `solana_confirmed_epoch_first_slot`   | `solana_node_epoch_first_slot`                 |
| `solana_confirmed_epoch_last_slot`    | `solana_node_epoch_last_slot`                  |
| `solana_leader_slots_total`           | `solana_validator_leader_slots_total`          |
| `solana_leader_slots_by_epoch`        | `solana_validator_leader_slots_by_epoch_total` |
| `solana_active_validators`            | `solana_cluster_validator_count`               |

Metrics were renamed to:
* Remove commitment levels from metric names.
* Standardise naming conventions:
  * `solana_validator_*`: Validator-specific metrics which are trackable from any RPC node (i.e., active stake).
  * `solana_node_*`: Node-specific metrics which are not trackable from other nodes (i.e., node health).

#### Label Updates

The following labels were renamed (**[@johnstonematt](https://github.com/johnstonematt)**):
 * `pubkey` was renamed to `votekey`, to clearly identity that it refers to the address of a validators vote account.

### Config Updates
#### New Config Parameters

Below is a list of newly added config parameters (see the [README](README.md) 
for parameter descriptions) (**[@johnstonematt](https://github.com/johnstonematt)**):

 * `-balance-address`
 * `-nodekey`
 * `-comprehensive-slot-tracking`
 * `-monitor-block-sizes`
 * `-slot-pace`
 * `-light-mode`
 * `-http-timeout`
 * `-comprehensive-vote-account-tracking`
 * `-active-identity`
 * `epoch-cleanup-time`

#### Renamed Config Parameters

The table below contains all config parameters renamed in `v3.0.0` (**[@johnstonematt](https://github.com/johnstonematt)**):

| Old Name                            | New Name          |
|-------------------------------------|-------------------|
| `-rpcURI`                           | `-rpc-url`        |
| `addr`                              | `-listen-address` |

#### Removed Config Parameters

The following metrics were removed (**[@johnstonematt](https://github.com/johnstonematt)**):

 * `votepubkey`. Configure validator tracking using the `-nodekey` parameter.

### General Updates

* The project was renamed from `solana_exporter` to `solana-exporter`, to conform with 
[Go naming conventions](https://github.com/unknwon/go-code-convention/blob/main/en-US.md) (**[@johnstonematt](https://github.com/johnstonematt)**).
* Testing was significantly improved (**[@johnstonematt](https://github.com/johnstonematt)**).
* [klog](https://github.com/kubernetes/klog) logging was removed and replaced with [zap](https://github.com/uber-go/zap)
  (**[@johnstonematt](https://github.com/johnstonematt)**)
* Easy usage (**[@johnstonematt](https://github.com/johnstonematt)**):
  * The example dashboard was updated.
  * An example prometheus config was added, as well as recording rules for tracking skip rate.

## New Contributors

* **[@GranderStark](https://github.com/GranderStark)** made their first contribution in **[#33](https://github.com/asymmetric-research/solana-exporter/pull/33)**.
* **[@dylanschultzie](https://github.com/dylanschultzie)** made their first contribution in **[#49](https://github.com/asymmetric-research/solana-exporter/pull/49)**.
* **[@impactdni2](https://github.com/impactdni2)** made their first contribution in **[#83](https://github.com/asymmetric-research/solana-exporter/pull/83)**.
* **[@andreclaro](https://github.com/andreclaro)** made their first contribution in **[#84](https://github.com/asymmetric-research/solana-exporter/pull/84)**.
