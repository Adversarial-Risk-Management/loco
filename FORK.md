# Maintaining this fork

`Adversarial-Risk-Management/loco` is a fork of [`loco-rs/loco`](https://github.com/loco-rs/loco).
This file documents how we carry our patches on top of upstream. It is the only
fork-specific doc — upstream's `DEVELOPMENT.md`, `CONTRIBUTING.md`, and `CHANGELOG.md` are left
untouched so they never conflict on sync.

## Model

- **`master` mirrors upstream `master` exactly.** No fork commits ever land on it; syncing is a
  fast-forward.
- **One branch per upstream version line carries the patches** — `0.16.x-arm`, `1.0.x-arm`, … Each
  starts at an upstream **release tag** (`1.0.x-arm` starts even with `v1.0.0`) and carries one
  commit per patch, kept linear so any single patch can be cherry-picked (e.g. backported from
  `1.0.x-arm` to `0.16.x-arm`) in isolation. The newest line branch is the integration branch we
  build and release from.
- **One branch per patch for review.** A new patch gets its own branch and PR targeting the
  active version-line branch, plus a row in the ledger below. Squash-merge keeps it one commit.
- **Never commit fork-only changes straight to `master`** — it must stay a pure upstream mirror.
- **`git fetch upstream` only tracks upstream `master`** (narrowed refspec) so we don't mirror
  hundreds of upstream branches locally.

## Versioning / releases

Fork releases are **git tags**, not Cargo version bumps:

```
v<upstream-version>-arm.<N>
```

e.g. `v0.16.4-arm.1`, `v1.0.0-arm.1`. Tags are cut on the **version-line branch** tip. The
workspace `Cargo.toml` version stays at upstream's value; downstream consumers pin the fork by
git tag or rev. Reset `N` to `1` on each new upstream version; bump `N` for additional fork-only
changes on the same upstream base. Do **not** record releases in `CHANGELOG.md` (that file is
upstream's and would conflict) — the tag + the ledger below are the record.

## Syncing with upstream

The `fork-sync` Claude Code skill (`.claude/skills/fork-sync/`) automates this; the manual steps:

1. `git fetch upstream`
2. Fast-forward `master` to `upstream/master` (`git checkout master && git merge --ff-only
   upstream/master`). If it won't fast-forward, something fork-only landed on `master` — fix
   that instead of merging.
3. Same upstream version line (e.g. upstream tags `v1.0.1`): **merge the new release tag into
   `N.x-arm`** (`git merge v1.0.1`) — append-only, no force-push, existing patch commits stay
   cherry-pickable — dropping any patch upstream has absorbed (record it in the ledger). Rebasing
   the patch stack onto the tag is the alternative when a linear history is worth a force-push.
   New upstream version
   line: start `M.x-arm` from `master` and cherry-pick each still-needed patch commit from the
   previous line, one commit per patch.
4. Rebase open patch branches in the ledger onto the active line branch; run `cargo fmt --all`
   and `cargo clippy --all-features -- -D warnings -W clippy::pedantic -W clippy::nursery
   -W rust-2018-idioms` on each (this is the CI `style` gate); force-push (`--force-with-lease`).
5. Squash-merge any patch branch that is ready into the active line branch.
6. Tag `v<upstream-version>-arm.<N>` on the line-branch tip and push the tag.
7. Update the ledger.

The fork is configured for **squash-merge only**, so each merged patch is a single clean commit
on the line branch that is easy to rebase, cherry-pick across version lines, and drop when
upstream absorbs it.

## Patch ledger

Current base: **upstream v1.0.0** (synced 2026-07-29). Patches carried on top, in commit order:

| Patch | Branch | Local PR | Upstream PR | Status |
|---|---|---|---|---|
| Fork docs + tooling | `fork-meta` | [#5](https://github.com/Adversarial-Risk-Management/loco/pull/5) | — | carried (re-applied on 1.0) |
| Default auth for GCP/Azure storage drivers (`new()` uses ambient creds; `with_credentials(...)` for explicit, credential last) | `feat/storage-default-auth` | [#14](https://github.com/Adversarial-Risk-Management/loco/pull/14) | candidate | carried (re-applied on 1.0 / opendal 0.57) |
| Testing deps: axum-test 20 (upstream pins 17; also drops the now-unrepresentable `RequestConfig.default_scheme`) | `deps/testing` | [#8](https://github.com/Adversarial-Risk-Management/loco/pull/8) | — | carried (residual — the rest of #8 landed upstream) |
| Queue provider downcast: `QueueProvider::as_any` + `Queue::downcast_provider::<T>()`, restoring app access to the queue backend (e.g. `PgQueue.pool`) that the 1.0 `Queue` enum removal took away | `feat/queue-provider-downcast` | — | candidate | carried (new on 1.0; successor to `feature/expose-worker-job-ids` / `feat/work-queue-pagination`) |
| Testing: Postgres per-test DB teardown uses `DROP DATABASE ... WITH (FORCE)` (PG 13+), so app-held pools outside loco's own (e.g. a session store on a different sqlx major) can't fail cleanup with SQLSTATE 55006 | `fix/testing-drop-db-force` | — | candidate | carried (new on 1.0) |
| `perform_all_later` / `Queue::enqueue_batch` batch enqueueing (atomic multi-row INSERT on pg/sqlite, `MULTI`/`EXEC` pipeline on redis; `QueueProvider::enqueue_batch` has a non-atomic loop default for third-party providers) | `perform-all-later` | [#3](https://github.com/Adversarial-Risk-Management/loco/pull/3) | — | carried (reworked for the 1.0 provider architecture; returns job ids, shared tags/priority per batch) |
| Model field encryption (`encryption` feature): AES-256-GCM `Encryptable`/`ModelDecryption`, Rails-shaped envelope, HKDF per-field keys, deterministic mode, `previous_keys` rotation with lazy re-encrypt on save, row-scoped AAD (`aad_fields`) + per-row `provider_for`, `KeyProvider` trait, loco-gen `:encrypted`, `testing::encryption` helpers | `encryption` | [#19](https://github.com/Adversarial-Risk-Management/loco/pull/19) | candidate | open (new on 1.0) |

### Dropped on the v1.0.0 sync

Revivable from the `v0.16.4-arm.*` tags if ever needed:

| Patch | Was | Why dropped |
|---|---|---|
| Allow running scheduler and server without worker | #1 / upstream [#1742](https://github.com/loco-rs/loco/pull/1742) | Landed in 1.0 (`--scheduler` flag; identical `StartMode` resolution semantics) |
| Expose worker queue / job IDs | #2 / upstream [#1624](https://github.com/loco-rs/loco/pull/1624) | Job-ID portion landed in 1.0 (`perform_later` → `Result<String>`); the query surface had no consumer and is superseded by the downcast patch |
| Multiple recipients in mailer | #4 | Landed in 1.0 via upstream [#1764](https://github.com/loco-rs/loco/pull/1764) (`MultiArgs`/`MultiEmail`, plus `headers` on single-recipient `Args`). Caveat: upstream does **not** auto-register `MultiMailerWorker` — register it in `Hooks::connect_workers` if `mail_multi` is ever adopted in `BackgroundQueue` mode |
| Clippy fixes for Rust 1.96 (loco, loco-new) | #6, #10, #12 | 1.0 passes the style gate on current stable (verified on 1.97) |
| Testing dep bumps besides axum-test | #8 | testcontainers 0.27 / rstest 0.26 landed upstream; the scraper/reqwest deltas were loco-internal |
| Runtime dep majors (thiserror 2, tower 0.5, heck 0.5, jsonwebtoken 10, rand 0.10, toml 1) | #9 | thiserror/tower/heck landed upstream; the jsonwebtoken 10.3/10.4, rand 0.9/0.10 and toml 0.8/1 deltas are loco-internal and semver-resolvable |
| loco-new deps (rand 0.9, thin-vec) | #11 | Superseded by upstream 1.0's loco-new |
| Cap `time` below 0.3.52 | #15 | Upstream 1.0 resolves time 0.3.54 alongside cookie 0.18.1 — the incompatibility is gone |
| Bump rand | #16 | loco-internal; upstream 1.0 pins rand 0.9 |

The unmerged pre-1.0 branches `feature/expose-worker-job-ids`, `feat/mailer-multi`, and
`feat/work-queue-pagination` are superseded per the table above and can be closed.

Keep this table current whenever a patch is added, merged, or upstreamed.
