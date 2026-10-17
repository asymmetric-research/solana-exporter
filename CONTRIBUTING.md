# Contributing

Thanks for your interest in improving `solana-exporter`! This document describes how to propose a change and the
standards we hold contributions to.

## Process

1. **Open an issue first.** Before writing any code, [open an issue](https://github.com/asymmetric-research/solana-exporter/issues/new)
   describing the bug or feature. For bugs, include the exporter version, the flags you run it with, and any relevant
   logs or metric output. Discussing the change up front avoids work on a PR we can't merge.
2. **Open a PR once the issue discussion has settled on an approach.** If you'd like to implement the change yourself,
   fork the repo, make the change on a branch, and open a PR against `main`. Fill in the
   [PR template](.github/PULL_REQUEST_TEMPLATE.md) and link the issue under "Linked Issues" (e.g. `Closes #123`).
   You're welcome to leave the implementation to the maintainers instead.
3. **Allow edits from maintainers.** If possible, tick
   [**Allow edits by maintainers**](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/allowing-changes-to-a-pull-request-branch-created-from-a-fork)
   when opening the PR. This lets us resolve merge conflicts and make small fixes directly on your branch, which keeps
   the review process much smoother.

## Standards

Contributions should follow the conventions documented in this repo:

- [`AGENTS.md`](AGENTS.md) — architecture overview and codebase conventions (where new metrics belong, label
  constants, light mode, logging).
- [`.agents/skills/`](.agents/skills) — guides written for coding agents that apply equally to human contributors:
  - [`go-standards`](.agents/skills/go-standards/SKILL.md) — idiomatic Go conventions.
  - [`writing-markdown`](.agents/skills/writing-markdown/SKILL.md) — markdown formatting.
  - [`creating-prs`](.agents/skills/creating-prs/SKILL.md) — PR titles (Conventional Commits) and descriptions.
  - [`e2e-testing`](.agents/skills/e2e-testing/SKILL.md) — running against mainnet and sanity-checking the metrics.
- [`README.md`](README.md) — keep the flag, metric, and label tables in sync when you add or change any of them.

Where possible, add unit tests for your change. Prefer extending the in-process RPC mock (`pkg/rpc/mock.go`) over
tests that need a real node.

Before pushing, run the same checks CI runs:

```shell
make test
gofmt -l .   # must print nothing; fix with `gofmt -w .`
make lint
```
