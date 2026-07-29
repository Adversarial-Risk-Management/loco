# Working in this repository

This is **`Adversarial-Risk-Management/loco`, a fork of [`loco-rs/loco`](https://github.com/loco-rs/loco)**.
Read [`FORK.md`](FORK.md) before changing how patches are organized — it is the source of truth
for the fork model, the patch ledger, the release-tag scheme, and the upstream-sync workflow.

## Fork rules

- **`master` mirrors upstream exactly** — never commit fork-only changes to it; syncs are
  fast-forwards.
- **Patches live on the version-line branch** (`1.0.x-arm`, previously `0.16.x-arm`): one commit
  per patch, linear, so any patch can be cherry-picked/backported in isolation. New patches get
  their own branch + PR targeting the active line branch, and a row in the `FORK.md` ledger.
- **One branch per patch**, kept rebased on the active line branch. The repo is squash-merge only.
- **Releases are git tags** `v<upstream-version>-arm.<N>` (e.g. `v1.0.0-arm.1`), cut on the
  version-line branch tip. The `Cargo.toml` version stays at upstream's value. Never add fork
  releases to `CHANGELOG.md`.
- To sync upstream or cut a release, use the `fork-sync` skill (`.claude/skills/fork-sync/`).

## Before pushing any Rust change

CI's `style` gate fails the build on either of these, so run both locally first:

```sh
cargo fmt --all -- --check
cargo clippy --all-features -- -D warnings -W clippy::pedantic -W clippy::nursery -W rust-2018-idioms
```

## Existing upstream docs (don't duplicate — link to them)

- [`DEVELOPMENT.md`](DEVELOPMENT.md) — dev/test setup (blessed dependency versions, running the
  test suite; tests need redis running and the saas starter frontend built).
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — etiquette for contributing **upstream**. Relevant
  because we float patches back to `loco-rs/loco` (e.g. PRs #1742, #1624).
- [`CHANGELOG.md`](CHANGELOG.md) — upstream's per-PR changelog. Treat as upstream-owned; do not
  add fork entries (they conflict on every sync).
- [`FORK.md`](FORK.md) — everything fork-specific.
