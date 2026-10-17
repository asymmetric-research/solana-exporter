---
name: e2e-testing
description: End-to-end test the exporter by running it against Solana mainnet, monitoring real validators under several configurations, and checking the scraped metrics are sensible. Use when asked to e2e test, smoke test, or sanity-check the exporter against a real node, or to confirm a change works on mainnet (not just in unit tests).
---

# E2E Testing

Unit tests run against `MockServer`, so they cannot catch drift between the exporter and real RPC responses (new
transaction versions, changed error codes, renamed fields). This skill runs the real binary against mainnet, monitors
real validators, and checks the metrics.

The goal is **judgement, not just "it started"**: every scraped value should be one you can justify against an
independent source (a direct RPC call, arithmetic, or the code).

## Ground rules

- **Do not fix anything you find** unless the user asks. Report it (see [Report](#report)).
- **This is a public repo.** Never write an RPC URL that carries an API key into a file, commit, or PR. Redact it in
  your report (e.g. `https://<provider>/<redacted>`).
- **Run configurations sequentially.** The public endpoint rate-limits per connection; parallel exporters get HTTP
  429s on most calls, and those make results meaningless (see [Pitfalls](#pitfalls)).
- **Always stop every exporter you start**, including on failure. Keep all artifacts (binary, logs, scrapes) in your
  scratchpad directory, not the repo.

## 1. Setup

Pick the RPC endpoint. Use `$SOLANA_RPC_URL` if it is set (a private mainnet endpoint, much faster and without the
tight rate limits); otherwise fall back to the public endpoint and tell the user the run is rate-limited.

```bash
RPC="${SOLANA_RPC_URL:-https://api.mainnet-beta.solana.com}"
OUT=<scratchpad>/e2e && mkdir -p "$OUT"
CGO_ENABLED=0 go build -o "$OUT/solana-exporter" ./cmd/solana-exporter

rpc() { curl -s "$RPC" -H 'content-type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-[]}}"; }

# confirm it is mainnet: expect 5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d
rpc getGenesisHash | jq -r .result
```

If testing a specific change, also build `main` (`git worktree add` into the scratchpad) so you can diff a metric's
behaviour before and after.

## 2. Pick targets

Choose validators live from `getVoteAccounts`; never hardcode keys (stake and delinquency change every epoch).

```bash
rpc getVoteAccounts '[{"commitment":"finalized"}]' > "$OUT/vote-accounts.json"
# top-stake current validators: lead most often, so slot-watcher metrics appear quickly
jq -r '.result.current | sort_by(-.activatedStake) | .[0:2][] | "\(.nodePubkey) \(.votePubkey)"' \
  "$OUT/vote-accounts.json"
# a delinquent validator (exercises delinquent=1 and stale last_vote)
jq -r '.result.delinquent | sort_by(-.activatedStake) | .[0] | "\(.nodePubkey) \(.votePubkey)"' \
  "$OUT/vote-accounts.json"
```

Call them `NK1/VK1` and `NK2/VK2` (top stake) and `DNK/DVK` (delinquent). The top validator holds ~4% of stake, so it
leads a 4-slot window roughly once a minute. To know when instead of guessing, look up its next leader slot:

```bash
rpc getLeaderSchedule "[null,{\"identity\":\"$NK1\"}]" | jq ".result[\"$NK1\"]"   # epoch-relative indices
rpc getEpochInfo | jq '{slotIndex, absoluteSlot}'
```

## 3. Run harness

Each configuration: start the exporter, wait for `/metrics`, scrape once early and once later (to compare counters and
moving gauges), then stop it.

```bash
run() {  # usage: run <name> <seconds> <flags...>
  local name=$1 secs=$2; shift 2
  "$OUT/solana-exporter" -rpc-url "$RPC" -listen-address 127.0.0.1:9179 "$@" > "$OUT/$name.log" 2>&1 &
  local pid=$!
  for _ in $(seq 30); do curl -sf -o /dev/null 127.0.0.1:9179/metrics && break; sleep 2; done
  sleep 10  # let the slot watcher tick; its gauges read 0 until then
  curl -s -o "$OUT/$name.1.prom" -w "$name scrape1 http=%{http_code}\n" 127.0.0.1:9179/metrics
  sleep "$secs"
  curl -s -o "$OUT/$name.2.prom" -w "$name scrape2 http=%{http_code}\n" 127.0.0.1:9179/metrics
  kill "$pid"; wait "$pid" 2>/dev/null
  echo "errors: $(grep -Ec '"level":"(error|fatal)"' "$OUT/$name.log")"
  grep -E '"level":"(error|fatal)"' "$OUT/$name.log" | jq -r .msg | cut -c1-200 | sort | uniq -c
}
```

On the public endpoint add `-slot-pace 3` to every run and `sleep 5` between runs. Each scrape fires ~10 RPC calls.

For configurations that need a leader slot from a tracked validator (fee rewards, block sizes, `by_epoch` counters),
the run must span one. Confirm it did by checking the log for `Fetching fee rewards for <nodekey>`. If it did not,
**extend the run** rather than reporting the metric as missing.

## 4. Configuration matrix

Run at least these. Add a row exercising whatever the change under test touches.

| Name        | Flags                                                                                         | Duration |
|-------------|-----------------------------------------------------------------------------------------------|---------:|
| `light`     | `-light-mode -active-identity "$(rpc getIdentity \| jq -r .result.identity)"`                 |      30s |
| `nodekey`   | `-nodekey NK1 -balance-address <any funded address>`                                          | ≥ 1 lead |
| `full`      | `-nodekey NK1 -votekey VK2 -balance-address NK1 -monitor-block-sizes -active-identity NK1`    | ≥ 1 lead |
| `delinq`    | `-votekey DVK`                                                                                |      30s |
| `compr`     | `-comprehensive-vote-account-tracking -comprehensive-slot-tracking`                           |      60s |
| `rejected`  | each invalid config below; expect a fast `fatal` exit with a clear message                    |        - |

Invalid configs that must be rejected at startup, each with a message naming the problem:

- `-light-mode` combined with any of `-nodekey`, `-votekey`, `-balance-address`, `-monitor-block-sizes`,
  `-comprehensive-slot-tracking`, `-comprehensive-vote-account-tracking`.
- The same `-nodekey` (or `-votekey`) passed twice.
- A `-nodekey` with no vote account (e.g. `11111111111111111111111111111111`).
- A `-votekey` that is not a vote account (e.g. `NK1`, an identity). A JSON decode error is a rejection, but an unclear
  one; report it.

## 5. What "sensible" means

Derive the expected metric set from the code, not memory: `collector.go` (snapshot metrics) and `slots.go`
(accumulated metrics) are the source of truth, and the `config.LightMode` / `ComprehensiveSlotTracking` /
`MonitorBlockSizes` guards there say which configuration emits what. If the README disagrees with the code (names,
labels, which flags gate what), report it as doc drift.

### Every configuration

- Both scrapes return HTTP 200. Any 500 means at least one RPC call failed during collection; read the body for the
  cause.
- No `error` or `fatal` log lines, except ones you can attribute to the environment (429 rate limits, timeouts). Any
  other RPC error, especially decode or "not supported" errors, is a real finding, even if the metrics look fine.
- No `NaN`, `+Inf`, or negative values. No empty label values.
- Every `*_total` counter in scrape 2 is ≥ its value in scrape 1.
- `solana_node_slot_height` advances ~2.5 slots/s between scrapes; `solana_node_block_height` advances slightly less
  (skipped slots).
- Only the series the configuration should produce are present, and nothing the configuration excludes.

### Per metric

Cross-check against a direct RPC call wherever one exists. Allow for the few seconds between the scrape and your call.

| Metric                                         | Sensible when                                                                                       |
|------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| `solana_node_epoch_number`                     | Equals `getEpochInfo.epoch`.                                                                        |
| `solana_node_epoch_first_slot` / `_last_slot`  | Mainnet has no warmup: `first = epoch * 432000`, `last = first + 431999`; slot height lies between. |
| `solana_node_transactions_total`               | Equals `getEpochInfo.transactionCount` (order 10^11) and grows between scrapes.                     |
| `solana_node_is_healthy`                       | `1` for a healthy endpoint; `solana_node_num_slots_behind` is then `0` or small.                    |
| `solana_node_version`                          | One series; label equals `getVersion["solana-core"]`.                                               |
| `solana_node_identity`                         | One series; label equals `getIdentity.identity` (the RPC node, not a monitored validator).          |
| `solana_node_is_active`                        | `1` only if `-active-identity` equals the node's identity, else `0`. Label is the node's identity.  |
| `solana_node_minimum_ledger_slot`              | Below current slot; equals `minimumLedgerSlot`.                                                     |
| `solana_node_first_available_block`            | Equals `getFirstAvailableBlock` (`0` on BigTable-backed public RPC is normal).                      |
| `solana_validator_active_stake`                | Equals `activatedStake / 1e9` for that vote account in `getVoteAccounts`.                           |
| `solana_cluster_active_stake`                  | Sum over current + delinquent; order 10^8 SOL. Each validator's stake is below it.                  |
| `solana_validator_last_vote` / `_root_slot`    | Healthy: within ~150 slots of `solana_cluster_*`; root < last vote. Delinquent: far behind.         |
| `solana_validator_delinquent`                  | Matches which list (`current`/`delinquent`) the vote account is in.                                 |
| `solana_validator_commission`                  | 0-100 and matches `getVoteAccounts`.                                                                |
| `solana_validator_bls_pubkey_set`              | 0 or 1, only for configured validators, never for comprehensive-only ones.                          |
| `solana_cluster_validator_count`               | `current` + `delinquent` equals the lengths of the two `getVoteAccounts` lists.                     |
| `solana_account_balance`                       | Equals `getBalance / 1e9`; covers each `-balance-address` plus configured identities and vote keys. |
| `solana_validator_leader_slots_total`          | Present for **every** leader seen since startup (not just configured ones). `skipped` ≪ `valid`.    |
| `solana_validator_leader_slots_by_epoch_total` | Only configured nodekeys, or all leaders with `-comprehensive-slot-tracking`. Current epoch only.   |
| `solana_cluster_slots_by_epoch_total`          | `valid + skipped` ≈ slots elapsed since startup; skip rate a few percent at most.                   |
| `solana_validator_fee_rewards_total`           | Present once a tracked validator has led; ~0.01-1 SOL per block; no error log for those slots.      |
| `solana_validator_block_size`                  | Only with `-monitor-block-sizes`; `vote` and `non_vote` both > 0, hundreds to low thousands total.  |
| `solana_validator_inflation_rewards_total`     | Only emitted at epoch rollover; see [Epoch boundaries](#epoch-boundaries).                          |

Configuration-specific expectations:

- `light`: only node-local metrics (health, version, identity, `is_active`, epoch/slot/block height,
  `transactions_total`). No `solana_validator_*`, `solana_cluster_*`, or `solana_account_balance` series.
- `delinq`: `solana_validator_delinquent` is `1`; its `last_vote` is thousands of slots behind the cluster.
- `compr`: `solana_validator_active_stake` has one series per vote account (current + delinquent);
  `leader_slots_by_epoch_total` covers every leader seen; no `bls_pubkey_set` or `account_balance` series.

### Epoch boundaries

Inflation rewards, epoch rollover (`closeCurrentEpoch`) and old-epoch cleanup only happen when an epoch ends, which a
short run will not cover. Compute the time left: `(slotsInEpoch - slotIndex) / 2.5` seconds. If it is under ~30 min,
offer the user a long `full` run spanning the boundary plus `-epoch-cleanup-time` (default 60s), and check that the
watcher survives the rollover, inflation rewards appear for the closed epoch, and the closed epoch's `epoch`-labelled
series disappear after the cleanup delay. Otherwise list these paths as **untested** in the report.

## Report

Summarise for the user:

1. **Environment**: endpoint (redacted if private), node version, epoch and progress, validators used, commit tested.
2. **Matrix**: one line per configuration: pass/fail, series count, any HTTP 500s, error-log count.
3. **Findings**, most severe first, each with its evidence (the log line or scrape excerpt and the direct RPC result it
   contradicts). Classify each as:
   - **bug**: the exporter emits a wrong value, misses a metric it should produce, or logs a non-environmental error.
   - **doc drift**: the code and README disagree.
   - **environment**: rate limits, endpoint quirks. Not an exporter defect, but say what it prevented you testing.
4. **Untested**: anything the run could not cover (epoch rollover, a config whose leader window never came).

## Pitfalls

- **One failed RPC call fails the whole scrape.** Collectors emit `NewInvalidMetric` on error, so promhttp returns
  HTTP 500 with no metrics at all. A burst of 429s looks like "everything is broken"; check the body before concluding.
- **No backfill.** The watermark starts at the current slot, so slot-watcher counters start from zero at startup and
  only cover slots seen since.
- **Fee rewards and block sizes use different `getBlock` options.** `-monitor-block-sizes` switches
  `transactionDetails` from `none` to `full`, which decodes every transaction and is the path that breaks when mainnet
  ships a new transaction version. Always test with and without it.
- **The RPC node is not the validator.** On a public endpoint `solana_node_identity` is the RPC node, so
  `solana_node_is_active` is `0` unless `-active-identity` is that identity.
- **The public endpoint is load-balanced.** Consecutive calls can hit different nodes, so `getIdentity`, `getVersion`
  and health can change between your call and the exporter's. A mismatch on those metrics there is not a bug, and
  `solana_node_is_active` cannot reliably be driven to `1`; use a single-node `$SOLANA_RPC_URL` to test it.
- **Startup needs RPC.** Outside light mode, config resolution calls `getVoteAccounts`/`getAccountInfo` before the
  server listens; an unreachable or rate-limited endpoint fails startup, not a scrape.
