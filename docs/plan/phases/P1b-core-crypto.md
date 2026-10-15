# P1b — `sweepky-core`: encryption, envelope and groups

## Goal

The security half of `sweepky-core`, built on the records from [P1a](P1a-core-records.md): encryption, padding, manifest binding, the package envelope, secret handling, and finding groups with proposed credits. Everything here is tested without a network. No I/O in this crate.

## Build

- **Encryption:** age wrap/unwrap to N recipients; padding of the plaintext to size buckets before encryption; manifest-binding check on the decrypted envelope (sweeper, bounty, targets must match the record's path and contents); strict parsing of `age1…` recipients and `alg`; C2SP CCTV vectors.
- **Package envelope:** build the one-document package from an in-memory list of (relative path, bytes): `findings.json` → `findings`, every other UTF-8 file → `attachments` keyed by relative path, non-text entries reported for the CLI to warn about; and split it back out. No archive format, no compression. The directory walk and its safety rules are the CLI's.
- **Secrets:** `age::x25519::Identity` held directly (it zeroizes itself); `SecretString` for identity strings, passphrases and the grant token; `Zeroizing<Vec<u8>>` for buffers.
- **Groups:** combine several `Findings` into groups by location (file plus sink scope where present, else line proximity), with equal ids as a second hint; keep every raw record; `reportedBy: [sweeper, …]` per group in upload order; a `trusted` flag per sweep that decides whether its content enters the merged output while attribution counts it either way; `propose_credits(owner)` returns every sweeper other than `owner` who contributed to at least one group.
- **Fixtures:** synthetic run directories (one Cloudflare-shaped, reusing P1a's Cloudflare fixture, and one common-format) whose findings share one location under different ids, plus a pair sharing an id at unrelated locations, and one non-text file, under `fixtures/`.

## Done when

- Unit tests pass for: envelope → pad → encrypt → decrypt → files round-trip of the synthetic run dir, with one non-text file reported; the padding test asserting the final ciphertext length lands on the bucket; a recipient added after encryption cannot decrypt; manifest binding (wrong path or wrong sweeper rejected); strict recipient and `alg` parsing, bad ones rejected; the C2SP CCTV age vectors (hybrid ones skipped); grouping puts the shared location in one group with both reporters and keeps the shared-id pair apart, `propose_credits` returns both and leaves out the owner when the owner also reported it, and an untrusted sweep is attributed but not merged.
- `cargo clippy -- -D warnings` and `cargo deny check` clean.
- Public API documented with `///` and `cargo doc --no-deps` warning-free.

## Notes

- Keep `age` on default features: no `plugin`, no `ssh`.
- The crate must not depend on `tokio`, `reqwest` or `pubky`. The CLI owns the network.
- No secret type implements `Debug`, `Display` or `Serialize` in a way that prints the secret. Errors never include key material or plaintext.
