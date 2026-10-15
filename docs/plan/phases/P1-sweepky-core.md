# P1 — `sweepky-core`

## Goal

Everything that can be tested without a network: records, paths, ids, trust labels, the events-feed parser, encryption, and the package envelope. No I/O in this crate.

## Build

- **Records:** `Circle`, `DeviceKey`, `Bounty { focus, brief, playbook, open, reward, status, credits, doneAt }`, `Target { kind }`, `Sweep { targets[], playbook }`, `Manifest`, and the common `Findings` format. Every record has `schemaVersion`; open-string enums with `as_known()`; `#[serde(flatten)] extra` to preserve unknown fields. A `Bounty::mark_done(credits)` that produces the rewritten record.
- **Converters:** Cloudflare `findings.json` → common `Findings` (`fingerprint` → `id`, verdict branches → `status`), with a round-trip test on a synthetic Cloudflare-shaped fixture.
- **Merge:** combine several `Findings` by `id`, keeping `reportedBy: [sweeper, …]` in upload order; a `propose_credits()` that returns every sweeper who contributed at least one finding.
- **Ids and paths:** timestamp-sortable ids; builders for every path under `/pub/sweepky/`; `pubky://` URL parsing for bounty and sweep references.
- **Targets:** types for `pr`, `commit`, `repo`; the per-kind scope description handed to the skill.
- **Trust labels:** `circle` / `known { bounties, owners }` / `unknown`, computed from a roster plus a set of done bounties and their credits.
- **Feed parser:** the `/events/` plain-text format (`PUT|DEL pubky://…` lines, `cursor:` line), tolerant of malformed lines.
- **Encryption:** age wrap/unwrap to N recipients; size-bucket padding; manifest-binding check on the decrypted envelope (sweeper, bounty, targets must match the record's path and contents); C2SP CCTV vectors.
- **Package envelope:** build the one-document package from a sweep directory (`findings.json` → `findings`, every other UTF-8 file → `attachments` keyed by relative path, non-text files skipped with a warning) and write it back out to a directory. No archive format, no compression.
- **Secrets:** identities and grants wrapped in `secrecy` / `Zeroizing`.
- **Fixtures:** synthetic run directories (one Cloudflare-shaped, one common-format), a roster, and a set of bounties with credits, under `fixtures/`.

## Done when

- Unit tests pass for: round-trip of every record including unknown fields and unknown kinds; `mark_done` preserving unknown fields; envelope → encrypt → decrypt → directory round-trip of the synthetic run dir, with one non-text file skipped; a recipient added after encryption cannot decrypt; padding buckets; manifest binding (wrong path or wrong sweeper rejected); feed parsing including malformed lines and the cursor; merge keeps both reporters of a shared `id` and `propose_credits` returns both; trust label from the fixture roster and credited bounties.
- `cargo clippy -- -D warnings` and `cargo deny check` clean.
- Public API documented with `///` and `cargo doc --no-deps` warning-free.

## Notes

- Keep `age` without the `plugin` feature.
- The crate must not depend on `tokio`, `reqwest` or `pubky`; the CLI owns those.
