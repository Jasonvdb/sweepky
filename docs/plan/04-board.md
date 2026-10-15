# 04 — The board (web)

## What it is in v1

A public, read-only page. It shows bounties, sweeps landing, done bounties with their credits, and the circle. It signs nobody in and never decrypts anything: findings are read through the owner's agent (`sweepky pull`). That removes Ring sign-in, browser keys, a second age implementation and every write path from the board. Reading findings in the browser is a reserved extension ([05](05-extensions.md#e4-reading-findings-in-the-browser)) that needs no record change.

## Stack

Standalone static SPA: `pnpm create vite web --template react-ts`, then `@synonymdev/pubky` 0.16.1, `react-router` and `zustand`, all pinned exactly ([03](03-cli-and-skill.md#dependencies)); `tsconfig` `lib` includes `esnext` for the SDK's disposable types. The `basic-pubky-app` template is vanilla TypeScript, so it is a reference for the testnet switch and client construction only, not the scaffold. The SDK is used only for pkarr resolution (`getHomeserverOf`, which takes a `PublicKey`) and public reads (`publicStorage`). React 19 + TypeScript, react-router, Zustand, hand-written CSS using Vibes' token names, Inter Tight loaded by the board itself because Vibes' font does not carry into an iframe. Static hosting with HTTPS (Vercel or Cloudflare Pages) with a SPA fallback so deep links resolve; `/health.json` for the Vibes 15-minute poll. The circle is selected by `?circle=<admin pubky>` with a built-in default.

**Not** a pubky-app fork. `pubky/pubky-marketplace` shows what a fork drags in (SDK 0.11, grant plus cookie auth, Nexus + Postgres BFF, commerce UI), and Nexus doesn't index `/pub/sweepky/` anyway. A static SPA can do everything: homeserver CORS is permissive, pkarr goes through HTTPS relays, path-addressed storage is handled by the SDK.

Dev mode is opt-in: `VITE_PUBKY_TESTNET=1` → `Pubky.testnet()`, whose pkarr relay is the local `15411`. The template's default-to-testnet config is not inherited, and a production build asserts the variable is unset.

The board runs inside an iframe on vibes.pubky.app once listed. It sends no `X-Frame-Options` or `frame-ancestors` that excludes that origin, and keeps no state in `localStorage` that it cannot afford to lose, because Safari drops it inside a cross-site frame.

## Views (4 routes)

| Route | Shows |
|---|---|
| `/` Board | floor plan of open bounties, sweeps in progress, activity ticker, sweeps today, recently done bounties |
| `/b/:owner/:id` Bounty | targets at pinned SHA, sweeps per target, sweeper timeline, `open` marker; once done, the credited sweepers |
| `/s/:sweeper/:id` Sweep | the sweep record only: sweeper, duration, status, playbook, trust badge. Never findings. Addressed by the sweeper, because sweep records live on the sweeper's homeserver and ids are unique per writer |
| `/circle` Circle | members, homeserver, last activity, credits received |

## Live-ness

Poll, the same rules as the CLI ([01](01-records-and-discovery.md#discovery)):

- Roster → `getHomeserverOf(PublicKey.from(pk))` per member once at load, cached, re-resolved hourly or on failure (undefined = no record, throw = lookup failure; show "unreachable"). A member whose homeserver has no public domain and TLS is shown as "not browser-reachable": the browser SDK can only use ICANN HTTPS endpoints, the CLI is not limited that way.
- `publicStorage.list` of `bounties/` and `sweeps/` per member every 30 s, `reverse=true`, explicit limit, paged by cursor until a known id. A 404 on a listing means empty.
- Re-GET only records that can still change (open bounties, `running` sweeps) with `cache: 'no-cache'`, so the browser revalidates by ETag and unchanged records cost a 304.
- Open bounties: read the owner's `bounties/<id>.discovered.json`, then each listed sweeper's record from their own homeserver. The board never reads an events feed; a fresh browser cannot replay a homeserver's whole public history, and does not need to.
- Every request goes through `pubky.client.fetch` with `credentials: 'omit'`, so a legacy homeserver cookie from another app never rides along.
- Zustand reducer → derived views. Trust badges and credits received are computed from the roster plus the `credits` on done bounties, the same rule as the CLI, including ignoring self-credits.

Signals are honest: a sweeper arrives (`running` PUT), a sweep is in progress (pulsing while `running` and younger than 6 h; older fades to "left"), a sweep completes (`done`), aborted (struck), a bounty is marked done (credits appear), a stranger's sweep appears once the owner's `pull` has published it. Nothing is faked; a closed tab misses nothing because every view is derived from current records, not from a stream.

## Visual direction

A counter-surveillance sweep, not brooms. Dark base from Vibes (bg `oklch(0.118 0.014 284.115)`, card `oklch(0.232 0.006 285.946)`, Inter Tight) with one accent. Bounties are rooms on a floor plan; a sweep in progress is a detector pulsing in its room; a completed sweep leaves the room marked swept; a done bounty is a room with the lights off and the credited sweepers' marks on the door. Unknown sweepers are drawn hollow until a credit fills them in. Motion is slow and idle-driven; the ticker scrolls only on real events.

Signature moments: a detector settling when a sweep lands; a room going dark as its bounty is marked done and the credits appear; the Circle page as a ring of members whose brightness is recent activity.

## Writer table

The CLI writes everything: bounties (including `done` and `credits`), the discovered-sweeps file, sweeps, keys. The board writes nothing. The human on the board watches; the agent posts, pulls, drafts, fixes, and marks done; the human runs `sweepky run` and `sweepky submit` around the agent's sweep.

## v1 cut lines

No sign-in, no decryption, no bounty posting, no writes of any kind, no feed scanning, no notifications, no server or indexer, single circle, no search.
