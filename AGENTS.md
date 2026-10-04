# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Overview

`solana-exporter` is a Prometheus exporter that scrapes monitoring data from a Solana node via the
[Solana JSON-RPC API](https://solana.com/docs/rpc). It runs as a single Go binary that exposes a `/metrics` endpoint.
Go 1.25, no CGO.

## Commands

```shell
# Build
CGO_ENABLED=0 go build ./cmd/solana-exporter

# Run all tests (with coverage, as CI does)
go test ./...

# Run a single package's tests
go test -v ./pkg/rpc
go test -v ./cmd/solana-exporter

# Run a single test
go test -v ./cmd/solana-exporter -run TestSolanaCollector_Collect

# Formatting — CI fails if `gofmt -l .` reports any file. Fix with:
gofmt -w .

# Lint (golangci-lint v2, pinned in the isolated tools/ module) and auto-format (gofumpt):
make lint         # go tool -modfile=tools/go.mod golangci-lint run
make lint-fix     # same, with --fix
make fmt          # gofumpt, via golangci-lint's formatters
```

Linting uses `golangci-lint` v2, configured in `.golangci.yml` and pinned in `tools/go.mod` (an isolated Go tool
module, so its large dependency tree stays out of the root `go.mod`). Keep the version in `tools/go.mod` and
`.github/workflows/golangci-lint.yml` in sync. CI (`.github/workflows/`) runs the tests, the gofmt check, and
golangci-lint on every push/PR; the lint job uses `only-new-issues: true`, so it flags only newly changed lines and
does not block on the pre-existing backlog.

## Architecture

Two independent collection mechanisms run concurrently, both registered with the default Prometheus registry and served
over one HTTP handler (`cmd/solana-exporter/main.go`):

1. **`SolanaCollector`** (`collector.go`) — a pull-based `prometheus.Collector`. Its `Collect()` runs on every scrape
and issues fresh RPC calls for point-in-time state: vote accounts (stake, delinquency, commission), version,
identity, health, balances, ledger slots. All its metrics are `GaugeDesc` const-metrics rebuilt each scrape.
2. **`SlotWatcher`** (`slots.go`) — a background goroutine (`WatchSlots`) driven by a ticker (`-slot-pace`, default 1s).
3. It maintains a running `slotWatermark` and continuously advances it, emitting counter/gauge metrics for cumulative,
4. slot-range-based data: leader slots (valid/skipped), fee rewards, inflation rewards, block sizes, epoch bounds.
5. These metrics are registered directly (not via the Collector interface) and persist/accumulate across scrapes.

The split matters: point-in-time snapshots go through `SolanaCollector`; anything that must be tracked slot-by-slot or
accumulated over an epoch belongs in `SlotWatcher`.

### SlotWatcher epoch lifecycle

The watcher is stateful and asserts consistency as it advances (see `assertf`). Key flow:
- `trackEpoch` — on startup sets `currentEpoch`/`firstSlot`/`lastSlot` and the leader schedule; does **not** backfill
  (watermark starts at `currentSlot - 1`).
- `moveSlotWatermark` — advances the watermark to a target slot, fetching block production + per-block info for the
  range in between.
- On epoch rollover, `closeCurrentEpoch` finishes the old epoch's slots, emits inflation rewards, then spawns
  `cleanEpoch` (a goroutine that waits `-epoch-cleanup-time`, default 60s, then deletes the previous epoch's labelled
  metrics so they don't grow unbounded). `EpochTrackedValidators` (`utils.go`) records which nodekeys had metrics in each
  epoch so cleanup knows what to delete.

### RPC layer (`pkg/rpc`)

`client.go` holds one method per RPC endpoint. All calls funnel through the generic `getResponse[T]` helper, which
marshals the JSON-RPC envelope and unmarshals into `Response[T]` (`responses.go`). RPC-level errors surface as
`*rpc.Error` (`errors.go`) — callers type-assert on it (e.g. `SlotSkippedCode` is handled specially when fetching
blocks). Commitment levels and cluster genesis hashes are constants here.

Tests use `MockServer` (`pkg/rpc/mock.go`), an in-process `httptest` server whose canned responses are keyed by
`MockOpt`. Prefer extending the mock over hitting a real node.

### Config

`config.go` defines `ExporterConfig` and parses CLI flags in `NewExporterConfigFromCLI`. Note two behaviors when
adding/changing flags:
- **Light mode** (`-light-mode`) is validated as mutually exclusive with `-nodekey`, `-votekey`, `-balance-address`,
  `-comprehensive-slot-tracking`, `-comprehensive-vote-account-tracking`, `-monitor-block-sizes`, and
  `-monitor-alpenglow-vote-inclusion`. Every collection
  path checks `config.LightMode` and skips metrics observable from any RPC node, exporting only node-local ones.
- On startup (non-light-mode) config makes RPC calls via `GetAssociatedValidatorAccounts` to resolve/pair the provided
  nodekeys and votekeys, so constructing a config requires a reachable RPC node.

## Conventions

- New metrics: add a `GaugeDesc` field + `Describe`/`Collect` wiring in `collector.go` for snapshot metrics, or
  register a prometheus vector in `NewSlotWatcher` for accumulated metrics. Metric names are `solana_*`; keep the README
  metrics/labels tables in sync when adding metrics or flags.
- Label constants (`NodekeyLabel`, `EpochLabel`, `StatusValid`, etc.) live at the top of `collector.go` — reuse them
  rather than string literals.
- Logging is via `pkg/slog` (a zap wrapper); get the logger with `slog.Get()`.
- `mj_utils.go` files contain `prettyPrint` debugging helpers — not for production paths.
- `cmd/playground` is a scratch main for manual RPC experimentation, not part of the exporter.

## Example run

```shell
solana-exporter \
  -nodekey <VALIDATOR_IDENTITY> -votekey <VALIDATOR_VOTEKEY> \
  -balance-address <ADDRESS> \
  -comprehensive-slot-tracking -monitor-block-sizes \
  -active-identity <MY_ACTIVE_IDENTITY>
```

See `README.md` for the full flag/metric/label reference and `prometheus/` for an example Prometheus setup, recording
rules (skip rate), and Grafana dashboard.