# P0 — Bootstrap

## Goal

A workspace skeleton that passes every quality gate while doing nothing, so later phases only add code.

## Build

- Workspace `Cargo.toml` with `crates/sweepky-core` and `crates/sweepky-cli` (stub `lib.rs` / `main.rs`).
- `rust-toolchain.toml` (stable), `deny.toml`, `rustfmt.toml`. [P2a](P2a-cli-identity.md) later pinned the toolchain to 1.96.0 and records why.
- `web/` placeholder (`package.json` with a `test` script that passes; the real scaffold lands in P4).
- `.github/workflows/ci.yml`: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo nextest run`, `cargo deny check`, `pnpm --dir web test`. A Postgres service container with `TEST_PUBKY_CONNECTION_STRING` set, because the CLI's testnet test, which starts in [P2a](P2a-cli-identity.md), runs an ephemeral testnet that needs it.
- `skills/sweepky/` directory with a `README.md` stating what will live there. [`fixtures/`](../../../fixtures/README.md) already exists, with its `README.md` and `trust-labels.json`.
- `PLAN.md` at the root pointing at `docs/plan/`.

## Done when

- `cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo nextest run && cargo deny check` pass on the skeleton.
- CI runs green on the branch's first pull-request run (the merge ref) and on main after each merge.

## Notes

- Pin exact crate versions from the start, from the list in [03](../03-cli-and-skill.md#dependencies). `cargo-deny` is configured with advisories enabled and the licence allowlist as SPDX ids: MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Unicode-3.0, Zlib, and CDLA-Permissive-2.0 (webpki-roots, a direct dependency of `pubky`); a per-crate exception for `option-ext` (MPL-2.0, pulled in through `pubky-testnet`) rather than allowing MPL-2.0 globally. Dev-dependencies are licence-checked too (`include-dev = true`; cargo-deny 0.19 skips them by default), because `option-ext` arrives only through the `pubky-testnet` dev-dependency. Re-run `cargo deny check licenses` once `pubky` is added to `sweepky-cli` in [P2a](P2a-cli-identity.md) (`sweepky-core` never depends on it).
- No application code in this phase.
- CI runs on pull requests and on pushes to `main`, not on every branch push. A `pull_request` run tests the merge ref, the branch merged into `main` as `main` stood when the PR was opened or last pushed to, which a run on the branch tip does not: P2d and P4 are built in parallel, so a branch can pass on its own and still break `main` once the other one merges. Running on both events would pay twice for every branch push. CI does not re-run when `main` moves, so merge `main` into the branch to test the new result before merging.
