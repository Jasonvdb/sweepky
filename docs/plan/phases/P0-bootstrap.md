# P0 — Bootstrap

## Goal

A workspace skeleton that passes every quality gate while doing nothing, so later phases only add code.

## Build

- Workspace `Cargo.toml` with `crates/sweepky-core` and `crates/sweepky-cli` (stub `lib.rs` / `main.rs`).
- `rust-toolchain.toml` (stable), `deny.toml`, `rustfmt.toml`.
- `web/` placeholder (`package.json` with a `test` script that passes; the real scaffold lands in P4).
- `.github/workflows/ci.yml`: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo nextest run`, `cargo deny check`, `pnpm --dir web test`. A Postgres service container with `TEST_PUBKY_CONNECTION_STRING` set, because the P2 end-to-end test's ephemeral testnet needs it.
- `fixtures/` and `skills/sweepky/` directories with a `README.md` each stating what will live there.
- `PLAN.md` at the root pointing at `docs/plan/`.

## Done when

- `cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo nextest run && cargo deny check` pass on the skeleton.
- CI runs green on the first push.

## Notes

- Pin exact crate versions from the start, from the list in [03](../03-cli-and-skill.md#dependencies). `cargo-deny` is configured with advisories enabled and the licence allowlist as SPDX ids: MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Unicode-3.0, Zlib, and CDLA-Permissive-2.0 (webpki-roots, a direct dependency of `pubky`); a per-crate exception for `option-ext` (MPL-2.0, pulled in through `pubky-testnet`) rather than allowing MPL-2.0 globally. Re-run `cargo deny check licenses` once `pubky` is added to `sweepky-cli` in P2 (`sweepky-core` never depends on it).
- No application code in this phase.
