# 05 — Extension points (reserved in v1, built later)

v1 touches only path strings and JSON. No `paykit` or `locks` crates in v1: they pin `pubky` 0.15 and 0.11, and we are on 0.14.

## E1. Sats bounties (Paykit)

Reserve `reward: null | {kind: "sats", perSeverity: {critical, high, medium, low}, capSats}` on bounties. v1 writes `null`. Severity is the owner's private judgement from the decrypted findings; it never appears in a public record.

Later flow:

1. Owner marks a bounty done and credits the sweepers.
2. For each credited sweeper the board or CLI reads their `/pub/paykit/v0/app-registry.json` and `apps/*/endpoints/btc-lightning-bolt11|lnurl|bolt12` with the plain pubky SDK and renders a `lightning:` QR.
3. Owner pays with Bitkit, which already publishes these endpoints and registers the `lightning:` scheme. Optionally `sweepky pay` uses the owner's own node through a trait we own.
4. Owner writes `payouts/<bounty>/<sweeper>.json`: `{sweeper, amountSats, method, reference: "sweepky:<bounty>:<sweeper>", proof?: {kind: "bolt11-preimage", invoice, preimage}, paidAt}`.
5. Sweeper's agent sees it and writes `received/<bounty>/<sweeper>.json`.
6. A leaderboard counts only **double-attested** payouts: both records exist, authors match, amounts agree.

Wording: "double-attested", never "proven". Paykit receipts are unsigned and encrypted to the payer; third parties can check record authorship and `sha256(preimage) == payment_hash`, not that sats moved. `reference` fits Paykit's 256-character `PaymentReference`, so a later Encrypted-Link receipt flow can be feature-gated in without changing records.

## E2. Locks

Locks is a trusted plaintext proxy: the Lock Server reads guarded bytes from `/priv/locks.app/content/` with a creator-granted session and forwards them to viewers who satisfy criteria. Today the only production criterion is `paykit-payment` (recipient must be the creator); locks are immutable; it pins `pubky` 0.11 and has a default `max_resources: 10`.

The one honest use is a sweeper selling the full depth of an **already-disclosed** report. Reserve `access: {kind: "lock", lock: "pubky://<sweeper>/pub/locks.app/<id>.json"}` on sweep records (absent in v1, where every sweep is owner-only); a client that sees it renders "paid, not available". Build only if Locks leaves alpha and ships on `pubky` ≥ 0.14. "Pay to unlock a finding inside the circle" contradicts pooled capacity and is not planned.

## E3. Other showcases, ranked useful → gimmick

1. **"Swept by Sweepky" badge JSON** at `disclosures/<repoSlug>.json` `{repo, sha, bounties[], sweepers[]}`: README-linkable, verifiable by homeserver ownership. Severity counts only if the owner chooses to disclose them.
2. **`sweepky verify <pubky-url>`**: pkarr → homeserver → record. Cheap; it is what the badge needs.
3. **Disclosure post on pubky.app** crediting sweepers: separate `/pub/pubky.app/posts/:w` grant, opt-in per disclosure.
4. **Cross-app Nexus tags** at `tags/<id>`: the later cross-homeserver discovery path. Reserve the directory name.
5. **Bitkit deep links**: free with E1.
6. Not planned: pubky-noise owner↔sweeper Q&A (1000-byte frames, two-party, and a Ring-authenticated app would still have to publish a key of its own).

## E4. Reading findings in the browser

The board stays public-only in v1. If an owner wants to read findings on the board instead of through their agent:

- Ring sign-in with a grant narrowed to `/pub/sweepky/keys/:rw`, the one path the board would write. The QR/deeplink pattern is in `pubky-marketplace/src/hooks/useStepUpReauth/useStepUpReauth.ts`.
- A non-extractable WebCrypto X25519 key in IndexedDB, published as `keys/web-<id>.json`. XSS, extensions and clipboard history cannot read it.
- `age-encryption` (typage 0.3.x) decrypting into a memory-only store slice, cleared on sign-out; interop fixtures in both directions plus the C2SP CCTV vectors on the JS side.
- A banner: "Sweeps uploaded before this key existed can't be read here."

No record changes: sweepers' CLIs already encrypt to every unrevoked owner key they find under `keys/`. Trigger: an owner asks for it.

## Deferred, with the trigger that justifies each

| Item | Trigger |
|---|---|
| E4 reading in the browser | An owner asks to read findings on the board |
| Event streams instead of polling | Circle passes ~30 or polling visibly lags |
| Relay / prior-sweep seeding | >50% duplicate `id`s across sweeps on a bounty |
| Verify tasks | `needs_validation` dominates and owners cannot resolve them alone |
| Docker runner meeting the skill's sandbox bar | First owner needs confirmed, not needs-validation, findings |
| Leaderboard from credits | Two or more members ask who helped most |
| Quota-aware auto mode | Sweepers say they forget to run it, and Claude Code exposes stable usage data |
| Multi-circle | Someone asks |
| `crate` target kind (published tarball, checksum-verified against the crates.io index) | Someone wants to sweep what ships on crates.io rather than the repo |
| Terminal live view (`sweepky watch`) | Someone wants to follow sweeps without a browser |
| Nexus tags for discovery | First open bounty with sweepers on homeservers outside the watch list |
| E2 Locks | Locks leaves alpha |
