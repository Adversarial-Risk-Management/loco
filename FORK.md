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

| Patch | Branch | Local PR | Upstream PR | Status |
|---|---|---|---|---|
| Allow running scheduler and server without worker | `separate-sched-flag` | [#1](https://github.com/Adversarial-Risk-Management/loco/pull/1) | [#1742](https://github.com/loco-rs/loco/pull/1742) | merged to `master` |
| Expose methods for querying worker queue / job IDs | `feature/expose-worker-job-ids` | [#2](https://github.com/Adversarial-Risk-Management/loco/pull/2) | [#1624](https://github.com/loco-rs/loco/pull/1624) | in review |
| `perform_all_later` for batch job enqueueing | `perform-all-later` | [#3](https://github.com/Adversarial-Risk-Management/loco/pull/3) | — | in review |
| Multiple recipients in mailer (`to`/`cc`/`bcc` → `Vec<String>`; flexible `string`-or-`seq` deserializer keeps legacy single-string `Email` payloads readable) | `feat/multi-recipient-email` | [#4](https://github.com/Adversarial-Risk-Management/loco/pull/4) | — | in review |
| Fix clippy lints for Rust 1.96 | `clippy-rust-1.96` | [#6](https://github.com/Adversarial-Risk-Management/loco/pull/6) | — | merged to `master` (transient; drop when upstream ships a 1.96 clippy fix) |
| Fix loco-new CI: Rust 1.96 clippy + fluent-templates 0.13.3 i18n layout | `clippy-rust-1.96-loco-new` | [#10](https://github.com/Adversarial-Risk-Management/loco/pull/10), [#12](https://github.com/Adversarial-Risk-Management/loco/pull/12) | — | merged to `master` (drop when upstream fixes loco-new CI) |
| Fork docs + tooling | `fork-meta` | [#5](https://github.com/Adversarial-Risk-Management/loco/pull/5) | — | merged to `master` |
| Testing deps: axum-test 20, testcontainers 0.27 (RUSTSEC-2025-0111), scraper 0.27, rstest 0.26, reqwest 0.13 | `deps/testing` | [#8](https://github.com/Adversarial-Risk-Management/loco/pull/8) | — | merged to `master` (drop if upstream bumps these) |
| Runtime dep majors: thiserror 2, tower 0.5, heck 0.5, jsonwebtoken 10, rand 0.10, toml 1 | `deps/runtime-majors` | [#9](https://github.com/Adversarial-Risk-Management/loco/pull/9) | — | merged to `master` (drop if upstream bumps these) |
| loco-new deps: rand 0.9, thin-vec 0.2.18 (dependabot + API migration) | `dependabot/cargo/cargo-01ced5c6fb` | [#11](https://github.com/Adversarial-Risk-Management/loco/pull/11) | — | merged to `master` (drop if upstream bumps these) |

Keep this table current whenever a patch is added, merged, or upstreamed.
