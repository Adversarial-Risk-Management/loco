---
name: fork-sync
description: Sync this fork with upstream loco-rs/loco and cut a fork release. Use when asked to "sync upstream", "pull in upstream changes", "rebase our patches", "cut a fork release", or "tag a new arm version". Fetches upstream, merges into master, rebases every patch branch in the FORK.md ledger, runs the CI style gate, and proposes the next v<upstream>-arm.N tag. Dry-run by default; mutating steps require explicit confirmation.
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

### 2. Bring upstream into master
- Merge upstream into `master`: `git merge upstream/master` (a real merge commit; do NOT
  squash — this preserves the squashed patch commits already on `master`).
- Resolve conflicts if any. `CHANGELOG.md` conflicts: keep both upstream and our content as
  appropriate, but remember we add **no** fork entries to it.

### 3. Rebase each patch branch onto the new master
For every branch in the ledger that is not yet merged into `master`:
- `git rebase --onto master <old-base> <branch>` (or plain `git rebase master <branch>`).
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
- Push `master`.
- Open/refresh PRs as needed; squash-merge any patch that is ready and should ship in `master`.

### 5. Tag the release (mutating — needs explicit OK)
- Compute the tag: `v<new-upstream-version>-arm.1` (reset N to 1 for a new upstream version;
  bump N for fork-only changes on the same base). Confirm the exact tag with the user.
- `git tag <tag> master && git push origin <tag>`.

### 6. Update the ledger
- Edit the patch-ledger table in `FORK.md`: update statuses, add new rows, mark merged/upstreamed
  patches. Commit on the `fork-meta` branch (or its successor).

## Guardrails
- Never use plain `git push --force`; always `--force-with-lease`.
- `master` is the default branch — confirm before force-pushing it.
- Do not edit `CHANGELOG.md`, `CONTRIBUTING.md`, or `DEVELOPMENT.md` with fork-specific content.
- If a rebase conflict is non-trivial (touches feature logic, not just CHANGELOG/formatting),
  stop and surface it rather than guessing.
