# 04 — The web app: landing page and board

## What it is in v1

One static app with two faces: a **landing page** at `/` that explains Sweepky and invites people in ([below](#landing-page-)), and the **board** at `/board`.

The board is a public, read-only page. It shows bounties, sweeps landing, done bounties with their credits, and the circle. It signs nobody in and never decrypts anything: findings are read through the owner's agent (`sweepky pull`). That removes Ring sign-in, browser keys, a second age implementation and every write path from the board. Reading findings in the browser is a reserved extension ([05](05-extensions.md#e4-reading-findings-in-the-browser)) that needs no record change.

## Stack

Standalone static SPA: `pnpm create vite web --template react-ts`, then `@synonymdev/pubky`, `react-router` and `zustand`, all pinned exactly ([03](03-cli-and-skill.md#dependencies)); `tsconfig` `lib` includes `esnext` for the SDK's disposable types. The `basic-pubky-app` template is vanilla TypeScript, so it is a reference for the testnet switch and client construction only, not the scaffold. The SDK is used only for pkarr resolution (`getHomeserverOf`, which takes a `PublicKey`) and public reads, which the board sends through `pubky.client.fetch` on `resolvePubky` URLs with its own query, not through `publicStorage`, because at 0.16.2 `publicStorage` sends credentials ([P4](phases/P4-board.md#notes)). React 19 + TypeScript, react-router, Zustand, hand-written CSS using pubky-app's token names and values ([design reference](#design-reference-pubky-app)), Inter Tight loaded by the board itself because Vibes' font does not carry into an iframe. Static hosting with HTTPS (Vercel or Cloudflare Pages) with a SPA fallback so deep links resolve; `/health.json` for the Vibes 15-minute poll. The circle is selected by `?circle=<admin pubky>` (raw or `pubky`-prefixed) over a default set at build time in `VITE_SWEEPKY_CIRCLE`; a query value that is not a key is ignored with a visible notice, and with neither no circle is selected, so the board sends nothing and says "No circle selected". Every internal link keeps a `?circle=` from the address, hash links included (`/?circle=<k>#sweep`).

**Not** a pubky-app fork. `pubky/pubky-marketplace` shows what a fork drags in (SDK 0.11, grant plus cookie auth, Nexus + Postgres BFF, commerce UI), and Nexus doesn't index `/pub/sweepky/` anyway. A static SPA can do everything: homeserver CORS is permissive, pkarr goes through HTTPS relays, path-addressed storage is handled by the SDK.

Dev mode is opt-in: `VITE_PUBKY_TESTNET=1` → `Pubky.testnet()`, whose pkarr relay is the local `15411`. The template's default-to-testnet config is not inherited, and a production build asserts the variable is unset.

The board runs inside an iframe on vibes.pubky.app once listed; the listing's `hosted.url` points at `/board`, which the Vibes schema allows (any HTTPS URL), so Vibes visitors land on the board, not the landing page. The app sends no `X-Frame-Options` or `frame-ancestors` that excludes that origin, and keeps no state in `localStorage` that it cannot afford to lose, because Safari drops it inside a cross-site frame.

## Views (5 routes)

| Route | Shows |
|---|---|
| `/` Landing | what Sweepky is, how owners and sweepers use it, why it is safe, how to start ([below](#landing-page-)) |
| `/board` Board | intro strip, floor plan of open bounties, sweeps in progress, activity ticker, sweeps today, recently done bounties |
| `/b/:owner/:id` Bounty | targets at pinned SHA, sweeps per target, sweeper timeline, `open` marker; once done, the credited sweepers |
| `/s/:sweeper/:id` Sweep | the sweep record only: sweeper, duration, status, playbook, trust badge. Never findings. Addressed by the sweeper, because sweep records live on the sweeper's homeserver and ids are unique per writer |
| `/circle` Circle | members, homeserver, last activity, credits received |

## Live-ness

Poll, the same rules as the CLI ([01](01-records-and-discovery.md#discovery)):

- Roster → `getHomeserverOf(PublicKey.from(pk))` per member once at load, cached, re-resolved hourly or on failure (undefined = no record, throw = lookup failure; show "unreachable"). A member whose homeserver has no public domain and TLS is shown as "not browser-reachable": the browser SDK can only use ICANN HTTPS endpoints, the CLI is not limited that way.
- A listing of `bounties/` and `sweeps/` per member every 30 s, read through `pubky.client.fetch` on the directory's `resolvePubky` URL with the board's own query, as the CLI spells it: an explicit `limit`, `reverse=true`, and paged by `cursor` (the last entry's `pubky://` URL) until a known id. A 404 on a listing means empty.
- Re-GET only records that can still change (open bounties, `running` sweeps) with `cache: 'no-cache'`, so the browser revalidates by ETag and unchanged records cost a 304.
- Open bounties: read the owner's `bounties/<id>.discovered.json`, then each listed sweeper's record from their own homeserver. The board never reads an events feed; a fresh browser cannot replay a homeserver's whole public history, and does not need to.
- Every request goes through `pubky.client.fetch` with `credentials: 'omit'`, so a legacy homeserver cookie from another app never rides along.
- Zustand reducer → derived views. Trust badges and credits received are computed from the roster plus the `credits` on done bounties, the same rule as the CLI, including ignoring self-credits.

Signals are honest: a sweeper arrives (`running` PUT), a sweep is in progress (pulsing while `running` and younger than 6 h; older fades to "left"), a sweep completes (`done`), aborted (struck), a bounty is marked done (credits appear), a stranger's sweep appears once the owner's `pull` has published it. Nothing is faked; a closed tab misses nothing because every view is derived from current records, not from a stream.

## Design reference: pubky-app

The board and the landing page take their look from `pubky/pubky-app` (the pubky.app client, MIT) at commit `ef6ad207e680169b1b01a6fb92695ffc646583b2` on `dev`, so Sweepky reads as part of the Pubky ecosystem and sits naturally inside Vibes. It is a reference, not a dependency: fetch it at that commit to read it, copy values by hand, and never import, vendor or build from it. Where to look: `src/app/globals.css` (tokens), `src/components/atoms/Button/Button.tsx` (button variants), `src/components/molecules/Home/Home.tsx` (hero), `src/components/templates/Public/Landing/` (landing sections).

Taken:

- **Tokens**, under pubky-app's names: `--background` `oklch(0.118 0.014 284.115)` and `--card` `oklch(0.232 0.006 285.946)` (the same values Vibes uses), `--foreground` `oklch(1 0 0)`, `--card-foreground` `oklch(0.951 0.011 286.195)`, `--muted-foreground` `#89898f`, `--secondary` `#303034`, `--border` `oklch(0.311 0.007 285.98)`, `--brand` `oklch(0.928 0.23 123.978)`, `--destructive` `oklch(0.628 0.258 29.234)`, `--radius` `0.625rem`.
- **Type:** Inter Tight throughout, monospace for commands and pubkys; layouts work from 375 px wide.
- **Buttons:** pills. Primary is solid `--brand` with `--background` text; default is `--brand` at 16 % fill with a brand border and brand text; secondary is `--secondary` with `--foreground` text (pubky-app's `--secondary-foreground` is not taken).
- **Section pattern:** a small uppercase eyebrow in `--brand` with wide tracking ("The problem"), a large heading with one word in `--brand`, a one-line subtitle in `--muted-foreground`, then a grid of cards (`--card` at 80 % opacity, medium radius, 24 px padding, a small shadow).
- **Landing structure:** hero (heading, subtitle, actions and footer on the left, a visual on the right), the problem, how it works, a final call to action.

Not taken:

- Next.js, Tailwind, the shadcn components, the service worker and the analytics consent banner. The app stays a Vite SPA with hand-written CSS.
- Pubky's and Synonym's logos, mascot illustrations, videos and the Synonym/Tether footer. Sweepky has its own mark and art, and says "Built on Pubky" as a text link. Using their marks would suggest an endorsement nobody has given.
- Motion that ignores `prefers-reduced-motion`. The pinned `globals.css` stops only its own landing animations under `reduce` (`.landing-swirl-background__graphic` and `.landing-scroll-cue__icon`); Sweepky stops all of its own motion, pulses, ticker and landing motion included, with one global rule under `reduce`.

## Visual direction

A counter-surveillance sweep, not brooms. pubky-app's dark tokens with exactly one accent, `--brand` (Pubky's lime), read as a detector's phosphor glow. It marks detectors, swept rooms, primary buttons and eyebrows, and nothing else. `--destructive` red appears only on `aborted` sweeps and "unreachable" members, as a mark beside a label in `--foreground`, because red text on a card falls below 4.5:1. There is no red/blue palette: red already means "failed", a second hue would compete with the one signal that matters (something is being swept), and Vibes frames the board beside apps that all use the Pubky palette. State is carried by shape, fill, brightness and motion, always with a text label, so nothing depends on colour alone. Lime on the background and background-coloured text on lime both clear WCAG AA by a wide margin.

Bounties are rooms on a floor plan; a sweep in progress is a detector pulsing in its room; a completed sweep leaves the room marked swept; a done bounty is a room with the lights off and the credited sweepers' marks on the door. Trust badges: `circle` is a solid brand mark, `known N` a brand outline with the count, `unknown` a hollow muted outline that a credit fills in. Motion is slow and idle-driven; the ticker scrolls only on real events.

Signature moments: a detector settling when a sweep lands; a room going dark as its bounty is marked done and the credits appear; the Circle page as a ring of members whose brightness is recent activity.

### Intro strip and empty state

Vibes opens the board directly, so its visitors never see the landing page. A one-line strip at the top of `/board` says what they are looking at ("Coding agents sweeping code for bugs. Findings go only to each bounty's owner.") with links to **How it works** (`/`) and **Run a sweep** (`/#sweep`). Dismissing it leaves a small "?" in its place; the dismissal lives in `localStorage`, which is fine to lose.

With no bounties, the floor plan is drawn empty: one outlined room labelled "No open bounties yet", and under it the two ways in, side by side. Owners ask their agent to post a bounty (`sweepky post`). Sweepers run `sweepky run`, then `/sweepky` in Claude Code, then `sweepky submit`. Nothing placeholder is drawn as if it were real: no sample rooms, no demo detectors.

## Landing page (`/`)

The front door: one scroll that explains Sweepky and sends people to the board, the owner flow or the sweeper flow. Same app, tokens and build as the board; static content except the hero visual. All copy below is a draft, approved with the P5 demo.

**Every claim must hold under the [known limits](06-verification-and-limits.md#known-limits-say-them-in-the-readme)**, and the page links to that list as published in the README. "Only the owner can read the findings" is true; "private" on its own is not, because metadata is public. No number appears without a source.

Sections, in order, on the pubky-app pattern:

| # | Eyebrow | Content |
|---|---|---|
| 1 | (hero) | H1 "Your spare tokens, **sweeping** for bugs." Subtitle: "Point your coding agent at other people's code. The findings are encrypted to the bounty's owner, and when the bounty is done the owner credits every sweeper who helped." Actions: **Watch the board** (primary, `/board`), **Run a sweep** (`#sweep`), **Post a bounty** (`#post`). Right column: the board's floor plan in a compact read-only frame, live from the same store, or the empty state when there are no bounties. Never a mock-up. |
| 2 | The problem | "One pass **misses** things." Three cards: *One run finds about half* (Cloudflare's README: a single run of their skill found roughly half of what repeated runs found); *Unused plan capacity* (sweepers spend their own unused plan capacity in their own unmodified Claude Code, which never has its credentials read or proxied); *No claims, no locks* (sweeps are non-exclusive, and the owner gets every independent report the CLI discovers: circle members' sweeps, and strangers' sweeps on watched homeservers). |
| 3 | How it works | "Post. **Sweep.** Credit." Two lanes showing the real commands. **Owners** (`id="post"`): your agent posts a bounty (`sweepky post`), a repo, PR or commit pinned to an exact revision; `sweepky pull` decrypts new sweeps on your machine and groups findings that point at the same code; `sweepky done` closes the bounty and credits everyone who helped. **Sweepers** (`id="sweep"`): `sweepky run` fetches the pinned target into a sandboxed project; `/sweepky` in Claude Code audits it with no network and no secrets in reach; `sweepky submit` encrypts the findings to the owner and uploads them to your own homeserver. One line under both: log in once by scanning a QR code with Pubky Ring. |
| 4 | Safe by design | Four cards: *Only the owner reads findings* (encrypted with age to the owner's keys, and the sweeper can read their own; everyone else sees only that sweeps happened and who was credited); *The agent works offline* (sandboxed: no network, no CLI secrets, the target's own agent-instruction files stripped); *Credit when the bounty is done* (credits are published when the bounty is done, never per finding, so public credit never points at an unpatched issue); *Records stay with their authors* (every record sits on its author's own Pubky homeserver; Sweepky runs no indexer of its own). Then the limits a reader most needs (public metadata, an active operator adding a reading key, permanence) and a **Known limits** link. |
| 5 | Reputation | "Credit you can **check**." The three trust labels as the board draws them (`circle`, `known N`, `unknown`): derived from the credits owners publish, counted only from owners you trust, never a global score. |
| 6 | (final) | "Start **sweeping**." The install block, **Watch the board**, the GitHub repo, "Built on Pubky". MIT. |

The install channel for the CLI is not decided yet. Until it is, the install block links to the README; the page never ships a guessed command.

Page rules:

- `index.html` carries the title, description and Open Graph tags with Sweepky's own cover (`public/og-cover.svg`, rendered to `og-cover.png`), so link previews work without JavaScript. `og:image` is site-relative until the app has a host.
- Every claim on the page lives in `web/src/landing/copy.ts` with the headings of 00, 02 or 06's known limits it rests on; a claim that traces to none of them is reworded, not shipped.
- No analytics and no third-party scripts. The hero is the only part that reads homeservers, and only through the board's store.
- Works from 375 px wide with no horizontal scroll, keyboard navigable, contrast at WCAG AA, all motion off under `prefers-reduced-motion: reduce`.

## Writer table

The CLI writes everything: bounties (including `done` and `credits`), the discovered-sweeps file, sweeps, keys. The board writes nothing. The human on the board watches; the agent posts, pulls, drafts, fixes, and marks done; the human runs `sweepky run` and `sweepky submit` around the agent's sweep.

## v1 cut lines

No sign-in, no decryption, no bounty posting, no writes of any kind, no feed scanning, no notifications, no server or indexer, single circle, no search, no analytics.
