---
name: creating-prs
description: How to open a pull request and write its description. Use when creating a PR, opening a PR, or writing a PR description/title (e.g. with `gh pr create`).
---

# Creating PRs

Guidance for opening a pull request in this repo and, above all, writing its description.

**This is a public repo.** Everything in the PR title, description, and commits is visible to anyone. Do not
reference internal tooling or context: no Jira tickets, Slack threads, internal docs or hostnames, customer or
validator-operator names, or private RPC endpoints and keys.

## Follow the PR template

The repo's template lives at `.github/PULL_REQUEST_TEMPLATE.md`. The PR description **must** follow it exactly:

- Keep every section heading the template defines, in the same order.
- Fill in each section; do not leave placeholder comments (`<!-- ... -->`) behind.
- In "Type of Change", delete the options that do not apply rather than leaving the full list.

Read the template file at PR-creation time and mirror its current structure — do not rely on a remembered
version.

## Linking issues

Search the repo's GitHub issues for any the change addresses. The branch name, PR title, and the actual diff are
the strongest signals; use them to pick search terms (metric names, flag names, RPC methods, error text):

```bash
gh issue list --state open --search "<terms>"
gh issue list --state all --search "<terms>" --limit 20
gh issue view <number>
```

Read each candidate issue before linking it. Under "Linked Issues":

- `Closes #N` when merging this PR fully resolves the issue (GitHub closes it automatically on merge).
- `Related to #N` when the PR addresses only part of the issue, or is connected to it without resolving it.

Only link an issue you are **highly confident** is relevant. If you cannot find a clear match — or you find
several plausible ones and cannot tell which applies — leave the "Linked Issues" section with a default "N/A" and flag 
this to the dev in your output. A wrong link (especially a wrong `Closes`, which closes an unrelated issue) is worse 
than no link; a human can add the correct one.

## Writing the Description

The "Description" section must be concise. Describe **either**:

- the feature the PR adds, or
- the problem that existed and the solution this PR makes.

Keep it to a few sentences. Do not pad it with implementation play-by-play, restated diffs, or a file-by-file
tour — the diff already shows that. Aim for what a reviewer needs to understand the change, nothing more. If the
PR adds or changes a metric, label, or flag, name it — operators read these PRs to see what changed.

**Do not state that tests pass** (or that you added/ran tests, linting, gofmt, etc.). The CI workflows on each PR
verify that; asserting it in the description is noise.

Good:

```markdown
## Description

Adds a `solana_validator_bls_pubkey_set` gauge reporting whether each tracked vote account has a BLS public key
registered, so operators can confirm Alpenglow readiness.
```

Bad (verbose, narrates the diff, claims tests pass):

```markdown
## Description

This PR modifies collector.go by adding a new GaugeDesc field. First it fetches the vote accounts, then for each
one it checks the BLS key and emits a metric. I also updated the README and added three test cases which all
pass locally and in CI.
```

## Title

Use Conventional Commits — `type(scope): summary`, e.g. `feat: add solana_validator_bls_pubkey_set gauge` or
`fix(rpc): decode vote accounts migrated to Alpenglow`. Match the prefixes and scopes already in `git log`
(`feat`, `fix`, `docs`, `ci`, ...).

## Mechanics

- Before creating, check whether the branch already has an open PR (`gh pr view` or
  `gh pr list --head <branch>`).
  - If one exists: push the new commits to the branch (the PR updates itself), and update the PR
    title/description with `gh pr edit` only if the change made them stale. Do **not** open a second PR.
  - **Never force-push without explicit approval** — use a plain `git push`. If the branch has diverged so a
    normal push is rejected, stop and ask rather than reaching for `--force` / `--force-with-lease`.
- Otherwise, push the branch, then open the PR with `gh pr create`.
- Pass the body via `--body-file` (write it to a temp file first) so the markdown — headings, lists, blank
  lines — is preserved verbatim; inline `--body` strings mangle newlines.
- Never open a PR from the default branch (`main`). Branch first if needed.
- Only create or push a PR when the user has asked for it.

## After opening

- **Assign the PR to its opener** so they can track it: pass `--assignee @me` to `gh pr create` (or
  `gh pr edit <number> --add-assignee @me` after the fact).
- **Request a review from the `swe` team if it has access to the repo.** Check with
  `gh api "repos/{owner}/{repo}/teams" --jq '.[].slug'` and look for `swe` in the output. If it is present,
  request the review with `gh pr edit <number> --add-reviewer asymmetric-research/swe` (or pass
  `--reviewer asymmetric-research/swe` to `gh pr create`). If the team is not listed, or the call fails because
  you lack permission to list the repo's teams (e.g. you are an outside contributor), skip this step.
