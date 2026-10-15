# P0 — Bootstrap

## Goal

A workspace skeleton that passes every quality gate while doing nothing, so later phases only add code.

## Build

- Workspace `Cargo.toml` with `crates/sweepky-core` and `crates/sweepky-cli` (stub `lib.rs` / `main.rs`).
- `rust-toolchain.toml` (stable), `deny.toml`, `rustfmt.toml`.
- `web/` placeholder (`package.json` with a `test` script that passes; the real scaffold lands in P4).
- `.github/workflows/ci.yml`: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo nextest run`, `cargo deny check`, `pnpm --dir web test`.
- `fixtures/` and `skill/sweepky/` directories with a `README.md` each stating what will live there.
- `PLAN.md` at the root pointing at `docs/plan/`.

## Done when

- `cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo nextest run && cargo deny check` pass on the skeleton.
- CI runs green on the first push.

## Notes

- Pin exact crate versions from the start; `cargo-deny` is configured with the licence allowlist (MIT, Apache-2.0, BSD, ISC, Unicode) and advisories enabled.
- No application code in this phase.
