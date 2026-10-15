# P1a — `sweepky-core`: records and parsing

## Goal

The data half of `sweepky-core`: records, paths, ids, targets, the Cloudflare converter, trust labels, and the events-feed parser. Everything here is tested without a network. No I/O in this crate. Encryption, the package envelope and finding groups follow in [P1b](P1b-core-crypto.md).

## Build

- **Records:** `Circle`, `DeviceKey`, `Bounty { focus, brief, playbook, open, reward, status, credits, doneAt }`, `Discovered { sweeps, cursors }`, `Target { kind }`, `Sweep { targets[], playbook }`, `Manifest`, and the common `Findings` format with nullable `severity` and `confidence`. Every record has `schemaVersion`; open-string enums with `as_known()`; `#[serde(flatten)] extra` to preserve unknown fields. A `Bounty::mark_done(owner, credits)` that produces the rewritten record and returns an error if `credits` contains `owner`. A `playbook` string validator for the pattern in [01](../01-records-and-discovery.md#records-v1).
- **Ids and pubkys:** 13-character Crockford timestamps via `pubky-timestamp`, validated on parse; a `Pubky` newtype that parses both `pubky<z32>` and raw z32, validates, and compares by key bytes; builders for every path under `/pub/sweepky/`; `pubky://` URL parsing for bounty and sweep references.
- **Converters:** Cloudflare `findings.json` → common `Findings`, detected by shape: `fingerprint` → `id`, verdict → `status`, severity and confidence filled only from `confirmed` records (`informational` → `info`), locations from `trace` then `evidence` with `kind` and `scope`, the original record verbatim in `extra.cloudflare`. Round-trip test on a synthetic Cloudflare-shaped fixture that rebuilds the original exactly.
- **Targets:** types for `pr` (with `mergeBase`), `commit`, `repo`; the per-kind scope description handed to the skill (three-dot PR diff, `diff-tree --root` for commits with the first-parent note for merges, `paths` for repos).
- **Trust labels:** `circle` / `known { bounties, owners }` / `unknown`, computed from a roster plus the whole list of bounties and their credits. The function itself, not its caller, counts only `done` bounties from trusted owners (roster members in v1) and skips any credit that names the bounty's owner. The API returns every pubky's label with its credit tally, `{ bounties, owners }`: the number of counted bounties that credit it and of their distinct owners. Circle members get a tally too, because their label is always `circle` and only the tally shows that a self-credit added nothing. The test loads [`fixtures/trust-labels.json`](../../../fixtures/trust-labels.json) and asserts the label and the tally of every `expected` entry.
- **Feed parser:** the `/events/` plain-text format (`PUT|DEL pubky://…` lines, a `cursor:` line anywhere, an empty body meaning caught up), tolerant of malformed lines; dedupe of several events for one URI.
- **Fixtures:** a synthetic Cloudflare-shaped `findings.json` with at least one `confirmed` and one `needs_validation` record; a `discovered.json`; a tiny bare git repository for the CLI's target tests, under `fixtures/`. The roster and the credited bounties for the trust-label test come from `fixtures/trust-labels.json`, which already exists.

## Done when

- Unit tests pass for: round-trip of every record including unknown fields and unknown kinds; `mark_done` preserving unknown fields and rejecting a credit for the owner; ids and both pubky forms parsing and comparing correctly, bad ones rejected; path builders; target scope descriptions for each kind; the Cloudflare converter round-trip, with `severity` null on a `needs_validation` record; feed parsing including malformed lines, the empty body, the cursor line out of order, and duplicate URIs; the trust label and tally of every `expected` entry in `fixtures/trust-labels.json`, where the fixture bounty whose owner credited themselves adds nothing to the owner's count.
- `cargo clippy -- -D warnings` and `cargo deny check` clean.
- Public API documented with `///` and `cargo doc --no-deps` warning-free.

## Notes

- The crate must not depend on `tokio`, `reqwest` or `pubky`; it may depend on `pubky-timestamp`. The CLI owns the network.
- It also depends on `base32` =0.5.1 directly, for z-base32 in `Pubky`: the release `pubky-timestamp`'s `base32` feature already pulls in (see [03](../03-cli-and-skill.md#dependencies)). `Pubky` checks the length and alphabet [01](../01-records-and-discovery.md#compatibility-rules-every-client-follows) asks for, and the canonical form, but not that the bytes are a valid Ed25519 point, since this crate has no Ed25519 code; the CLI's SDK parse does that before it uses a key on the network.
- Every parser here reads data a stranger may have written. Malformed input returns an error or is skipped; it never panics.
- Every from-bytes parse checks the input's length before parsing: at most 1 MiB (`MAX_RECORD_BYTES`) for a public record and 16 MiB (`MAX_FINDINGS_BYTES`) for a findings document. These caps are P1a's choice; 01 sets none.
- [01](../01-records-and-discovery.md) does not say how `createdAt`, `startedAt`, `finishedAt`, `doneAt` and `revokedAt` are encoded, so `RecordTime` keeps them opaque: 1 to 64 printable ASCII characters, no whitespace. Those limits are P1a's choice, not 01's.
