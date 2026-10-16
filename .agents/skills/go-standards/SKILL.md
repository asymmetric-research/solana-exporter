---
name: go-standards
description: Idiomatic Go conventions — naming, error handling, concurrency, interfaces, testing, and API design. Use when writing, reviewing, or refactoring any .go file.
---

# Go Standards

Idiomatic Go for this codebase. Distilled from Effective Go, the Google Go Style Guide, and Go Code Review Comments.
When in doubt, optimize for the reader: **clarity over cleverness, simplicity over abstraction.**

Always run `gofmt -w .` before finishing. CI fails on any unformatted file. Prefer `goimports` to keep imports grouped
and sorted.

## Naming

- **Packages**: short, lowercase, no underscores or camelCase (`rpc`, `slog`, not `rpcClient` or `rpc_client`). The
  package name is part of every identifier's path — avoid stutter: `rpc.Client`, not `rpc.RPCClient`.
- **Exported identifiers**: `MixedCaps`. Unexported: `mixedCaps`. Never `snake_case`.
- **Getters**: no `Get` prefix. A field `owner` is read via `Owner()`, not `GetOwner()`. (RPC method names mirroring an
  external API like `GetVoteAccounts` are the exception — they name the wire call, not a Go getter.)
- **Interfaces**: single-method interfaces take the method name + `-er` (`Reader`, `Watcher`, `Collector`).
- **Length tracks scope**: `i`, `r`, `b` are fine in a 3-line loop; use descriptive names for package-level or
  long-lived values. Receiver names are 1–2 chars and consistent across all methods of a type (`c *Client`, not
  `this` or `self`).
- **Acronyms keep their case**: `URL`, `ID`, `RPC`, `HTTP` — `parseURL`, `userID`, `serveHTTP`. Not `parseUrl` or
  `userId`.
- **Errors**: sentinel values are `ErrFoo`; error types are `FooError`.

## Errors

- Return `error` as the **last** return value. Handle it — never discard with `_` unless you can articulate why.
- Add context when propagating, and wrap with `%w` so callers can `errors.Is`/`errors.As`:
  ```go
  if err != nil {
      return fmt.Errorf("fetching block %d: %w", slot, err)
  }
  ```
- Error strings are lowercase, no trailing punctuation (they get wrapped): `"connection refused"`, not
  `"Connection refused."`.
- Compare with `errors.Is` (sentinels) and `errors.As` (typed errors). Do **not** compare with `==` across wrap
  boundaries or string-match on `err.Error()`.
- Keep the happy path at minimum indentation. Return early on error rather than nesting the success case in an `else`:
  ```go
  if err != nil {
      return err
  }
  // happy path continues unindented
  ```
- `panic` is for programmer bugs / truly unrecoverable state, not ordinary error flow. Library code returns errors.

## Control Flow & Style

- No `else` after a block that ends in `return`/`continue`/`break`.
- Use `defer` for cleanup (`Close`, `Unlock`, `Done`) immediately after acquiring the resource — it runs even on panic
  and keeps acquire/release adjacent.
- Prefer `for` range. Zero values are usable: a `nil` slice appends fine, a `nil` map reads fine (writes panic), a
  zero `sync.Mutex` is unlocked and ready.
- Slices: `make([]T, 0, n)` when you know the capacity. Distinguish `nil` from empty only when the API contract does.
- Accept interfaces, return concrete types. Don't define an interface until there are ≥2 implementations or a real
  seam for testing — Go interfaces are satisfied implicitly, so add them at the consumer, not preemptively at the
  producer.
- Keep interfaces small. The bigger the interface, the weaker the abstraction.

## Concurrency

- "Don't communicate by sharing memory; share memory by communicating" — but a plain `sync.Mutex` is often the
  simplest correct choice. Pick the clearest tool, not the cleverest.
- The goroutine that creates a channel usually owns closing it. Never close a channel from the receiver side or close
  it twice.
- Every goroutine needs a clear exit path. Thread a `context.Context` for cancellation; pass it as the **first**
  parameter (`ctx context.Context`) and never store it in a struct.
- Protect shared mutable state with a mutex; keep the critical section small. Guard-then-`defer Unlock` at the top of
  the method when the whole body is critical.
- Run tests with `-race` when touching concurrent code: `go test -race ./...`.

## Comments & Docs

- Every exported identifier has a doc comment, starting with the identifier's name: `// Client issues RPC calls…`,
  `// WatchSlots advances the watermark…`.
- Comments explain **why**, not **what** the code plainly shows. Delete comments that restate the code.
- Package doc: one `// Package x …` comment, on the primary file.

## Testing

- Table-driven tests are the default. Name cases and run subtests so failures are addressable:
  ```go
  tests := []struct {
      name string
      in   int
      want int
  }{
      {"zero", 0, 0},
      {"positive", 2, 4},
  }
  for _, tt := range tests {
      t.Run(tt.name, func(t *testing.T) {
          if got := Double(tt.in); got != tt.want {
              t.Errorf("Double(%d) = %d, want %d", tt.in, got, tt.want)
          }
      })
  }
  ```
- Message format: `t.Errorf("Func(%v) = %v, want %v", in, got, want)` — got before want, always.
- Use `t.Helper()` in assertion helpers. Use `t.Cleanup` over bare `defer` for test teardown. Use `t.Parallel()`
  where cases are independent.
- Prefer the in-repo `MockServer` (`pkg/rpc/mock.go`) over hitting a real node; extend it rather than adding new
  test infra.
- `testify/require` (stop on failure) vs `assert` (continue) — use `require` for preconditions that make the rest of
  the test meaningless.

## Project-Specific

- Go 1.27, `CGO_ENABLED=0`. No new CGO dependencies.
- Logging goes through `pkg/slog` (zap wrapper): `slog.Get()`. Don't use the standard `log` package or `fmt.Println`
  in production paths.
- Keep the README metrics/labels/flags tables in sync when adding metrics or flags (see AGENTS.md).

## Quick Checklist

Before finishing any Go change:

1. `gofmt -w .` (or `goimports -w .`) — CI gate.
2. `go build ./...` and `go test ./...` pass (`-race` if concurrency changed).
3. `go vet ./...` clean.
4. Errors wrapped with context; no silent `_ = err`.
5. Exported symbols documented; happy path un-nested.
