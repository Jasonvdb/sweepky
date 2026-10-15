# 05 — Extension points (reserved in v1, built later)

v1 touches only path strings and JSON. No `paykit` or `locks` crates in v1: they pin `pubky` 0.15 and 0.11, and we are on 0.14.

## E1. Sats bounties (Paykit)

Reserve `reward: null | {kind: "sats", perSeverity: {critical, high, medium, low}, capSats}` on bounties. v1 writes `null`.

Later flow:

1. Owner confirms a finding on the board.
2. Board reads the sweeper's `/pub/paykit/v0/app-registry.json` and `apps/*/endpoints/btc-lightning-bolt11|lnurl|bolt12` with the plain pubky SDK and renders a `lightning:` QR.
3. Owner pays with Bitkit, which already publishes these endpoints and registers the `lightning:` scheme. Optionally `sweepky pay` uses the owner's own node through a trait we own.
4. Owner writes `payouts/<bounty>/<finding>.json`: `{sweeper, amountSats, method, reference: "sweepky:<bounty>:<finding>", proof?: {kind: "bolt11-preimage", invoice, preimage}, paidAt}`.
5. Sweeper's agent sees it and writes `received/<bounty>/<finding>.json`.
6. A leaderboard counts only **double-attested** payouts: both records exist, authors match, amounts agree.

Wording: "double-attested", never "proven". Paykit receipts are unsigned and encrypted to the payer; third parties can check record authorship and `sha256(preimage) == payment_hash`, not that sats moved. `reference` fits Paykit's 256-character `PaymentReference`, so a later Encrypted-Link receipt flow can be feature-gated in without changing records.

## E2. Locks

Locks is a trusted plaintext proxy: the Lock Server reads guarded bytes from `/priv/locks.app/content/` with a creator-granted session and forwards them to viewers who satisfy criteria. Today the only production criterion is `paykit-payment` (recipient must be the creator); locks are immutable; it pins `pubky` 0.11 and has a default `max_resources: 10`.

The one honest use is a sweeper selling the full depth of an **already-disclosed** report. Reserve `access.kind: "lock"` + `access.lock: "pubky://<sweeper>/pub/locks.app/<id>.json"` on sweep records; v1 renders it as "paid, not available". Build only if Locks leaves alpha and ships on `pubky` ≥ 0.14. "Pay to unlock a finding inside the circle" contradicts pooled capacity and is not planned.

## E3. Other showcases, ranked useful → gimmick

1. **"Swept by Sweepky" badge JSON** at `disclosures/<repoSlug>.json` `{repo, sha, bounties[], severityCounts, sweepers[]}`: README-linkable, verifiable by homeserver ownership.
2. **`sweepky verify <pubky-url>`**: pkarr → homeserver → record. Cheap; it is what the badge needs.
3. **Disclosure post on pubky.app** crediting sweepers: separate `/pub/pubky.app/posts/:w` grant, opt-in per disclosure.
4. **Cross-app Nexus tags** at `tags/<id>`: the later cross-homeserver discovery path. Reserve the directory name.
5. **Bitkit deep links**: free with E1.
6. Not planned: pubky-noise owner↔sweeper Q&A (1000-byte frames, two-party, and age-to-device-keys already delivers owner-only material).

## Deferred, with the trigger that justifies each

| Item | Trigger |
|---|---|
| Event streams instead of polling | Circle passes ~30 or polling visibly lags |
| Relay / prior-sweep seeding | >50% duplicate fingerprints across sweeps on circle-readable bounties |
| Verify tasks | `needs_validation` dominates and owners cannot resolve them alone |
| Docker runner meeting the skill's sandbox bar | First owner needs confirmed, not needs-validation, findings |
| Published triage → leaderboard | Two or more members ask who found what |
| Quota-aware auto mode | Sweepers say they forget to run it, and Claude Code exposes stable usage data |
| Multi-circle | Someone asks |
| Nexus tags for discovery | First open bounty with sweepers on homeservers outside the watch list |
| E2 Locks | Locks leaves alpha |
