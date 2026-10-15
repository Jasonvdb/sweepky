# P1 — `sweepky-core`

## Goal

Everything that can be tested without a network: records, paths, ids, trust labels, finding groups, the events-feed parser, encryption, and the package envelope. No I/O in this crate.

## Build

- **Records:** `Circle`, `DeviceKey`, `Bounty { focus, brief, playbook, open, reward, status, credits, doneAt }`, `Discovered { sweeps, cursors }`, `Target { kind }`, `Sweep { targets[], playbook }`, `Manifest`, and the common `Findings` format with nullable `severity` and `confidence`. Every record has `schemaVersion`; open-string enums with `as_known()`; `#[serde(flatten)] extra` to preserve unknown fields. A `Bounty::mark_done(owner, credits)` that produces the rewritten record and returns an error if `credits` contains `owner`. A `playbook` string validator for the pattern in [01](../01-records-and-discovery.md#records-v1).
- **Ids and pubkys:** 13-character Crockford timestamps via `pubky-timestamp`, validated on parse; a `Pubky` newtype that parses both `pubky<z32>` and raw z32, validates, and compares by key bytes; builders for every path under `/pub/sweepky/`; `pubky://` URL parsing for bounty and sweep references.
- **Converters:** Cloudflare `findings.json` → common `Findings`, detected by shape: `fingerprint` → `id`, verdict → `status`, severity and confidence filled only from `confirmed` records (`informational` → `info`), locations from `trace` then `evidence` with `kind` and `scope`, the original record verbatim in `extra.cloudflare`. Round-trip test on a synthetic Cloudflare-shaped fixture that rebuilds the original exactly.
- **Groups:** combine several `Findings` into groups by location (file plus sink scope where present, else line proximity), with equal ids as a second hint; keep every raw record; `reportedBy: [sweeper, …]` per group in upload order; a `trusted` flag per sweep that decides whether its content enters the merged output while attribution counts it either way; `propose_credits(owner)` returns every sweeper other than `owner` who contributed to at least one group.
- **Targets:** types for `pr` (with `mergeBase`), `commit`, `repo`; the per-kind scope description handed to the skill (three-dot PR diff, `diff-tree --root` for commits with the first-parent note for merges, `paths` for repos).
- **Trust labels:** `circle` / `known { bounties, owners }` / `unknown`, computed from a roster plus a set of done bounties and their credits, skipping any credit that names the bounty's owner.
- **Feed parser:** the `/events/` plain-text format (`PUT|DEL pubky://…` lines, a `cursor:` line anywhere, an empty body meaning caught up), tolerant of malformed lines; dedupe of several events for one URI.
- **Encryption:** age wrap/unwrap to N recipients; padding of the plaintext to size buckets before encryption; manifest-binding check on the decrypted envelope (sweeper, bounty, targets must match the record's path and contents); strict parsing of `age1…` recipients and `alg`; C2SP CCTV vectors.
- **Package envelope:** build the one-document package from an in-memory list of (relative path, bytes): `findings.json` → `findings`, every other UTF-8 file → `attachments` keyed by relative path, non-text entries reported for the CLI to warn about; and split it back out. No archive format, no compression. The directory walk and its safety rules are the CLI's.
- **Secrets:** `age::x25519::Identity` held directly (it zeroizes itself); `SecretString` for identity strings, passphrases and the grant token; `Zeroizing<Vec<u8>>` for buffers.
- **Fixtures:** synthetic run directories (one Cloudflare-shaped, one common-format) whose findings share one location under different ids, plus a pair sharing an id at unrelated locations; a roster; a set of bounties with credits (one of them self-credited by its owner); a `discovered.json`; a tiny bare git repository for the CLI's target tests, under `fixtures/`.

## Done when

- Unit tests pass for: round-trip of every record including unknown fields and unknown kinds; `mark_done` preserving unknown fields and rejecting a credit for the owner; ids and both pubky forms parsing and comparing correctly, bad ones rejected; the Cloudflare converter round-trip, with `severity` null on a `needs_validation` record; envelope → pad → encrypt → decrypt → files round-trip of the synthetic run dir, with one non-text file reported; the padding test asserting the final ciphertext length lands on the bucket; a recipient added after encryption cannot decrypt; manifest binding (wrong path or wrong sweeper rejected); feed parsing including malformed lines, the empty body, the cursor line out of order, and duplicate URIs; grouping puts the shared location in one group with both reporters and keeps the shared-id pair apart, `propose_credits` returns both and leaves out the owner when the owner also reported it, and an untrusted sweep is attributed but not merged; trust label from the fixture roster and credited bounties, where a fixture bounty whose owner credited themselves adds nothing to the owner's count.
- `cargo clippy -- -D warnings` and `cargo deny check` clean.
- Public API documented with `///` and `cargo doc --no-deps` warning-free.

## Notes

- Keep `age` on default features: no `plugin`, no `ssh`.
- The crate must not depend on `tokio`, `reqwest` or `pubky`; it may depend on `pubky-timestamp`. The CLI owns the network.
