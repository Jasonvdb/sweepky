# P1 — `sweepky-core`

## Goal

Everything that can be tested without a network: records, paths, ids, trust labels, the events-feed parser, encryption, and packing. No I/O in this crate.

## Build

- **Records:** `Circle`, `DeviceKey`, `Bounty { readers, open, reward }`, `Target { kind }`, `Sweep { targets[] }`, `Attestation`, `Manifest`. Every record has `schemaVersion`; open-string enums with `as_known()`; `#[serde(flatten)] extra` to preserve unknown fields.
- **Ids and paths:** timestamp-sortable ids; builders for every path under `/pub/sweepky/`; `pubky://` URL parsing for bounty and sweep references.
- **Targets:** types for `pr`, `commit`, `repo`, `crate`; the per-kind scope description handed to the skill.
- **Trust labels:** `circle` / `known { confirmed, owners }` / `unknown`, computed from a roster plus a set of attestations.
- **Feed parser:** the `/events/` plain-text format (`PUT|DEL pubky://…` lines, `cursor:` line), tolerant of malformed lines.
- **Encryption:** age wrap/unwrap to N recipients; size-bucket padding; `manifest.json` first in the plaintext; manifest-binding check (sweeper, bounty, targets must match the record's path and contents).
- **Packing:** `tar.zst` of the canonical run files only; unpack with path-traversal protection.
- **Secrets:** identities and grants wrapped in `secrecy` / `Zeroizing`.
- **Fixtures:** synthetic run directory, roster, attestations, and a Rust-encrypted `.age` under `fixtures/` for the P4 interop test.

## Done when

- Unit tests pass for: round-trip of every record including unknown fields and unknown kinds; pack → encrypt → decrypt → unpack of the synthetic run dir; padding buckets; manifest binding (wrong path or wrong sweeper rejected); feed parsing including malformed lines and the cursor; trust label from the fixture roster and attestations.
- `cargo clippy -- -D warnings` and `cargo deny check` clean.
- Public API documented with `///` and `cargo doc --no-deps` warning-free.

## Notes

- Keep `age` without the `plugin` feature.
- The crate must not depend on `tokio`, `reqwest` or `pubky`; the CLI owns those.
