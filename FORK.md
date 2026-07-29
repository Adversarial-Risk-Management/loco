# Maintaining this fork

`Adversarial-Risk-Management/loco` is a fork of [`loco-rs/loco`](https://github.com/loco-rs/loco).
This file documents how we carry our patches on top of upstream. It is the only
fork-specific doc — upstream's `DEVELOPMENT.md`, `CONTRIBUTING.md`, and `CHANGELOG.md` are left
untouched so they never conflict on sync.

## Model

- **`master` = upstream `master` + our patches.** It is the integration branch we build and
  release from. Its delta from upstream is only our patch commits (one squashed commit per
  patch).
- **One branch per patch.** Each carried change lives on its own branch and has its own PR into
  `master`. Branches are kept rebased on the current `master`.
- **Never commit fork-only changes straight to `master`.** Add a patch branch + PR, and a row in
  the ledger below.
- **`git fetch upstream` only tracks upstream `master`** (narrowed refspec) so we don't mirror
  hundreds of upstream branches locally.

## Versioning / releases

Fork releases are **git tags**, not Cargo version bumps:

```
v<upstream-version>-arm.<N>
```

e.g. `v0.16.4-arm.1`. The workspace `Cargo.toml` version stays at upstream's value; downstream
consumers pin the fork by git tag or rev. Reset `N` to `1` on each new upstream version; bump
`N` for additional fork-only changes on the same upstream base. Do **not** record releases in
`CHANGELOG.md` (that file is upstream's and would conflict) — the tag + the ledger below are the
record.

## Syncing with upstream

The `fork-sync` Claude Code skill (`.claude/skills/fork-sync/`) automates this; the manual steps:

1. `git fetch upstream`
2. Merge `upstream/master` into `master` (a real merge commit; the squashed patch commits on
   `master` are preserved).
3. Rebase each patch branch in the ledger onto the new `master`; run `cargo fmt --all` and
   `cargo clippy --all-features -- -D warnings -W clippy::pedantic -W clippy::nursery
   -W rust-2018-idioms` on each (this is the CI `style` gate); force-push.
4. Squash-merge any patch branch not yet in `master`.
5. Tag `v<new-upstream-version>-arm.1` on the `master` tip and push the tag.
6. Update the ledger.

The fork is configured for **squash-merge only**, so each merged patch is a single clean commit
that is easy to rebase and fix up.

## Patch ledger

Current base: **upstream v1.0.0** (synced 2026-07-29). Patches carried on top, in commit order:

| Patch | Branch | Local PR | Upstream PR | Status |
|---|---|---|---|---|
| Fork docs + tooling | `fork-meta` | [#5](https://github.com/Adversarial-Risk-Management/loco/pull/5) | — | carried (re-applied on 1.0) |
| Default auth for GCP/Azure storage drivers (`new()` uses ambient creds; `with_credentials(...)` for explicit, credential last) | `feat/storage-default-auth` | [#14](https://github.com/Adversarial-Risk-Management/loco/pull/14) | candidate | carried (re-applied on 1.0 / opendal 0.57) |
| Testing deps: axum-test 20 (upstream pins 17; also drops the now-unrepresentable `RequestConfig.default_scheme`) | `deps/testing` | [#8](https://github.com/Adversarial-Risk-Management/loco/pull/8) | — | carried (residual — the rest of #8 landed upstream) |
| Queue provider downcast: `QueueProvider::as_any` + `Queue::downcast_provider::<T>()`, restoring app access to the queue backend (e.g. `PgQueue.pool`) that the 1.0 `Queue` enum removal took away | `feat/queue-provider-downcast` | — | candidate | carried (new on 1.0; successor to `feature/expose-worker-job-ids` / `feat/work-queue-pagination`) |

### Dropped on the v1.0.0 sync

Revivable from the `v0.16.4-arm.*` tags if ever needed:

| Patch | Was | Why dropped |
|---|---|---|
| Allow running scheduler and server without worker | #1 / upstream [#1742](https://github.com/loco-rs/loco/pull/1742) | Landed in 1.0 (`--scheduler` flag; identical `StartMode` resolution semantics) |
| Expose worker queue / job IDs | #2 / upstream [#1624](https://github.com/loco-rs/loco/pull/1624) | Job-ID portion landed in 1.0 (`perform_later` → `Result<String>`); the query surface had no consumer and is superseded by the downcast patch |
| `perform_all_later` batch enqueue | #3 | No consumer in the backend monorepo; a revival would be a full rework onto the 1.0 provider architecture |
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
