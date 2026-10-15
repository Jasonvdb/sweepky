# 04 — The board (web)

## Stack

Standalone static SPA scaffolded from `npx tiged pubky/pubky-app-templates/basic-pubky-app web`, bumped to `@synonymdev/pubky` 0.14. React 19 + TypeScript, react-router, Zustand, `age-encryption`, hand-written CSS using Vibes' token names. Static hosting with HTTPS (Vercel or Cloudflare Pages); `/health.json` for the Vibes 15-minute poll. The circle is selected by `?circle=<admin pubky>` with a built-in default.

**Not** a pubky-app fork. The local "pubky-app" checkout is the marketplace fork (SDK 0.11, cookie auth, Nexus + Postgres BFF, commerce UI), and Nexus doesn't index `/pub/sweepky/` anyway. A static SPA can do everything: homeserver CORS is permissive, pkarr and auth go through HTTPS relays, path-addressed storage is handled by the SDK.

## Sign-in

`pubky.startGrantAuthFlow("/pub/sweepky/keys/:rw", AuthFlowKind.signin(), {clientId, relay})` → QR on desktop, `location.href` deeplink on mobile → `await flow.awaitApproval()`. Copy the generation-counter + `visibilitychange` cancel pattern from `pubky-marketplace/src/hooks/useStepUpReauth/useStepUpReauth.ts`. Persist with `browserSessionStore`.

On first sign-in the board generates a non-extractable WebCrypto X25519 key in IndexedDB, derives the age recipient, writes `keys/<deviceId>.json`, and shows the banner: "Sweeps uploaded before this key existed can't be read on this device."

Dev mode (`VITE_PUBKY_TESTNET=1`): `Pubky.testnet()`, and the auth URL is approved with `sweepky dev approve <url>`; the sign-in code is identical to production.

## Views (5 routes)

| Route | Public visitors | Members add |
|---|---|---|
| `/` Board | floor plan of open bounties, sweeps in progress, activity ticker, sweeps today | "Needs you": sweeps you can decrypt and haven't opened |
| `/b/:owner/:id` Bounty | targets at pinned SHA, sweeps per target, sweeper timeline, `open` marker | decrypted severity rollup, open report |
| `/s/:owner/:sweep` Sweep | sweep record only (sweeper, duration, status, trust badge) | findings grouped verdict → severity; detail: title, root cause, `trace`/`evidence` as `github.com/<repo>/blob/<sha>/<file>#L<line>` links, remediation diffs, confidence pill |
| `/keys` Keys | — | this device's key, other devices, revoke |
| `/circle` Circle | members, homeserver, last activity, attestation counts | — |

## Live-ness

Poll: roster → `getHomeserverOf(pk)` per member (undefined = no record, throw = lookup failure; show "unreachable", retry hourly) → `publicStorage.list` of `bounties/`, `sweeps/`, `keys/`, `attestations/` per member every 30 s → Zustand reducer → derived views. Open bounties add the events-feed watcher with the same cursor logic as the CLI (cursor in `localStorage`).

Signals are honest: a sweeper arrives (`running` PUT), a sweep is in progress (pulsing while `running` and younger than 6 h; older fades to "left"), a sweep completes (`done`), aborted (struck). Nothing is faked; a closed tab misses nothing because the next poll catches up.

Decrypted plaintext lives only in a non-persisted store slice, cleared on sign-out.

## Visual direction

A counter-surveillance sweep, not brooms. Dark base from Vibes (bg `oklch(0.118 0.014 284.115)`, card `oklch(0.232 0.006 285.946)`, Inter Tight) with one accent. Bounties are rooms on a floor plan; a sweep in progress is a detector pulsing in its room; a completed sweep leaves the room marked swept; decrypted findings pin where they were found. Unknown sweepers are drawn hollow until an attestation fills them in. Severity is luminance of the single accent (critical hottest, informational ash); verdicts are shape (filled / outlined / struck). Motion is slow and idle-driven; the ticker scrolls only on real events.

Signature moments: a detector settling when a sweep lands; a sweep wipe across the room as decrypted findings populate; the public/member toggle lifting a frosted cover off the floor plan; the Circle page as a ring of members whose brightness is recent activity.

## Writer table (one writer per record kind)

CLI: bounties, sweeps, attestations, `keys/cli-<host>.json`. Board: `keys/web-<id>.json` only. The human on the board watches, reads, decides; the agent posts, sweeps, uploads, drafts, fixes.

## v1 cut lines

No bounty posting from the board, no triage writes, no disclosure editor, no notifications, no server or indexer, single circle, no search, no key export or recovery.
