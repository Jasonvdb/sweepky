# 04 — The board (web)

## What it is in v1

A public, read-only page. It shows bounties, sweeps landing, done bounties with their credits, and the circle. It signs nobody in and never decrypts anything: findings are read through the owner's agent (`sweepky pull`). That removes Ring sign-in, browser keys, a second age implementation and every write path from the board. Reading findings in the browser is a reserved extension ([05](05-extensions.md#e4-reading-findings-in-the-browser)) that needs no record change.

## Stack

Standalone static SPA scaffolded from `npx tiged pubky/pubky-app-templates/basic-pubky-app web`, bumped to `@synonymdev/pubky` 0.14 and stripped of its sign-in scaffolding. The SDK is used only for pkarr resolution (`getHomeserverOf`) and public reads (`publicStorage`). React 19 + TypeScript, react-router, Zustand, hand-written CSS using Vibes' token names. Static hosting with HTTPS (Vercel or Cloudflare Pages); `/health.json` for the Vibes 15-minute poll. The circle is selected by `?circle=<admin pubky>` with a built-in default.

**Not** a pubky-app fork. The local "pubky-app" checkout is the marketplace fork (SDK 0.11, cookie auth, Nexus + Postgres BFF, commerce UI), and Nexus doesn't index `/pub/sweepky/` anyway. A static SPA can do everything: homeserver CORS is permissive, pkarr goes through HTTPS relays, path-addressed storage is handled by the SDK.

Dev mode (`VITE_PUBKY_TESTNET=1`): `Pubky.testnet()`.

## Views (4 routes)

| Route | Shows |
|---|---|
| `/` Board | floor plan of open bounties, sweeps in progress, activity ticker, sweeps today, recently done bounties |
| `/b/:owner/:id` Bounty | targets at pinned SHA, sweeps per target, sweeper timeline, `open` marker; once done, the credited sweepers |
| `/s/:owner/:sweep` Sweep | the sweep record only: sweeper, duration, status, playbook, trust badge. Never findings |
| `/circle` Circle | members, homeserver, last activity, credits received |

## Live-ness

Poll: roster → `getHomeserverOf(pk)` per member (undefined = no record, throw = lookup failure; show "unreachable", retry hourly) → `publicStorage.list` of `bounties/` and `sweeps/` per member every 30 s → Zustand reducer → derived views. Open bounties add the events-feed watcher with the same cursor logic as the CLI (cursor in `localStorage`). Trust badges are computed from the roster plus the `credits` on done bounties, the same rule as the CLI.

Signals are honest: a sweeper arrives (`running` PUT), a sweep is in progress (pulsing while `running` and younger than 6 h; older fades to "left"), a sweep completes (`done`), aborted (struck), a bounty is marked done (credits appear). Nothing is faked; a closed tab misses nothing because the next poll catches up.

## Visual direction

A counter-surveillance sweep, not brooms. Dark base from Vibes (bg `oklch(0.118 0.014 284.115)`, card `oklch(0.232 0.006 285.946)`, Inter Tight) with one accent. Bounties are rooms on a floor plan; a sweep in progress is a detector pulsing in its room; a completed sweep leaves the room marked swept; a done bounty is a room with the lights off and the credited sweepers' marks on the door. Unknown sweepers are drawn hollow until a credit fills them in. Motion is slow and idle-driven; the ticker scrolls only on real events.

Signature moments: a detector settling when a sweep lands; a room going dark as its bounty is marked done and the credits appear; the Circle page as a ring of members whose brightness is recent activity.

## Writer table

The CLI writes everything: bounties (including `done` and `credits`), sweeps, keys. The board writes nothing. The human on the board watches; the agent posts, sweeps, uploads, pulls, drafts, fixes, and marks done.

## v1 cut lines

No sign-in, no decryption, no bounty posting, no writes of any kind, no notifications, no server or indexer, single circle, no search.
