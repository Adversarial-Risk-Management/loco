---
name: fork-sync
description: Sync this fork with upstream loco-rs/loco and cut a fork release. Use when asked to "sync upstream", "pull in upstream changes", "rebase our patches", "cut a fork release", or "tag a new arm version". Fetches upstream, fast-forwards master (a pure upstream mirror), rebases the active version-line branch and every patch branch in the FORK.md ledger, runs the CI style gate, and proposes the next v<upstream>-arm.N tag on the line branch. Dry-run by default; mutating steps require explicit confirmation.
---

# Fork sync & release

Automates the upstream-sync workflow documented in `FORK.md`. Read `FORK.md` first — its patch
ledger is the list of branches this skill operates on.

## Operating mode

**Default to a dry run.** Inspect and report; do not push, force-push, tag, or delete anything
until the user explicitly confirms. State clearly which actions are read-only and which mutate
the remote.

## Steps

### 1. Survey current state (read-only)
- `git fetch upstream && git fetch origin`
- Determine the new upstream version: read `version` from upstream's `Cargo.toml`
  (`git show upstream/master:Cargo.toml`) and compare to the last `v*-arm.*` tag
  (`git tag --list 'v*-arm.*'`).
- Report the commit delta: `git log --oneline master..upstream/master`.
- Parse the ledger table in `FORK.md` to get the list of `(patch, branch)` rows.

### 2. Bring upstream into master and the version-line branch
- Fast-forward `master`: `git checkout master && git merge --ff-only upstream/master`. If it
  refuses, something fork-only landed on `master` — surface that instead of merging.
- Same upstream version line: rebase the active `N.x-arm` branch onto the new `master`, dropping
  any patch upstream absorbed (record it in the ledger).
- New upstream version line: create `M.x-arm` from `master` and cherry-pick each still-needed
  patch commit from the previous line branch, one commit per patch, so every patch stays
  individually backportable.

### 3. Rebase each open patch branch onto the active line branch
For every branch in the ledger that is not yet merged into the line branch:
- `git rebase --onto <line-branch> <old-base> <branch>` (or plain `git rebase <line-branch> <branch>`).
- Drop any CHANGELOG-only commits and resolve `CHANGELOG.md` conflicts by keeping master's
  version (we don't carry changelog edits in patches).
- Run the **CI style gate** and fix fallout (newer toolchains add lints):
  ```sh
  cargo fmt --all
  cargo clippy --all-features -- -D warnings -W clippy::pedantic -W clippy::nursery -W rust-2018-idioms
  ```
  Fold formatting/lint fixes into the patch commits (amend the tip), keeping history linear.
- `cargo check --workspace --all-features` must pass.
- Report which branches rebased cleanly and which needed conflict resolution.

### 4. Confirm, then push (mutating — needs explicit OK)
- Force-push each rebased branch (`git push --force-with-lease origin <branch>`).
- Push `master` (fast-forward) and force-push the rebased line branch (`--force-with-lease`).
- Open/refresh PRs as needed; squash-merge any patch that is ready into the active line branch.

### 5. Tag the release (mutating — needs explicit OK)
- Compute the tag: `v<new-upstream-version>-arm.1` (reset N to 1 for a new upstream version;
  bump N for fork-only changes on the same base). Confirm the exact tag with the user.
- `git tag <tag> <line-branch> && git push origin <tag>` (tags are cut on the version-line
  branch tip, not master).

### 6. Update the ledger
- Edit the patch-ledger table in `FORK.md`: update statuses, add new rows, mark merged/upstreamed
  patches. Commit on the `fork-meta` branch (or its successor).

## Guardrails
- Never use plain `git push --force`; always `--force-with-lease`.
- `master` is the default branch — confirm before force-pushing it.
- Do not edit `CHANGELOG.md`, `CONTRIBUTING.md`, or `DEVELOPMENT.md` with fork-specific content.
- If a rebase conflict is non-trivial (touches feature logic, not just CHANGELOG/formatting),
  stop and surface it rather than guessing.
