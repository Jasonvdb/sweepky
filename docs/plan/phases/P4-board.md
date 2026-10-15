# P4 — The landing page and the board

## Goal

A static, read-only SPA: a landing page that explains Sweepky and invites owners and sweepers in, and the board where anyone watches bounties, sweeps and credits. No sign-in, no decryption, no writes, no feed scanning.

## Build

- Scaffold: `pnpm create vite web --template react-ts`; add `@synonymdev/pubky` 0.16.1, `react-router`, `zustand` at the exact versions in [03](../03-cli-and-skill.md#dependencies); `tsconfig` `lib` includes `esnext`. Load Inter Tight in the page.
- `VITE_PUBKY_TESTNET=1` → `Pubky.testnet()`, opt-in only; the production build asserts it is unset.
- Routes: `/` (landing), `/board`, `/b/:owner/:id`, `/s/:sweeper/:id`, `/circle`.
- Tokens, type, buttons and section pattern from the pubky-app design reference in [04](../04-board.md#design-reference-pubky-app), copied by hand into the app's CSS from the pinned commit. One accent (`--brand`); `--destructive` only for `aborted` and "unreachable".
- Polling store (30 s) per [04](../04-board.md#live-ness): cached homeserver resolution, reverse paged listings with 404 as empty, conditional re-GET of non-terminal records, open bounties through `bounties/<id>.discovered.json`, every request with `credentials: 'omit'`.
- Trust badge per sweep (`circle` / `known N` / `unknown`) computed from the roster plus `credits` on done bounties from trusted owners (roster members in v1), ignoring a credit that names the bounty's owner; `open` marker on bounties; done bounties show their credited sweepers; credits received on the Circle page; "not browser-reachable" for members whose homeserver has no ICANN HTTPS endpoint. The trust-badge unit test loads [`fixtures/trust-labels.json`](../../../fixtures/trust-labels.json), the file [P1a](P1a-core-records.md)'s Rust test loads. It passes the badge function the whole `bounties` list, so the function itself, not its caller, drops open bounties and bounties from owners outside the roster. For every `expected` entry the test asserts the label, and the `bounties` and `owners` counts behind "credits received" on the Circle page.
- Visual direction from [04-board.md](../04-board.md#visual-direction): floor plan, detectors, swept rooms, rooms going dark when done, hollow unknown sweepers; the board's intro strip and empty state.
- Landing page per [04](../04-board.md#landing-page-): six sections, the hero showing the live floor plan (or the empty state) from the board's store, `#post` and `#sweep` anchors, Open Graph tags in `index.html`, the install block linking to the README until a release channel exists.
- All motion stops under `prefers-reduced-motion: reduce`.
- `/health.json`; no `X-Frame-Options` or `frame-ancestors` that excludes vibes.pubky.app; nothing essential in `localStorage`.

## Done when

- `pnpm build` and `pnpm test` clean (unit tests for the trust-badge rule against `fixtures/trust-labels.json`, the listing pager and the record reducer).
- Playwright or manual against the testnet: the public view shows a `running` → `done` sweep transition within one poll, a stranger's sweep appearing with the `unknown` badge after the owner's `pull` has published it to `discovered.json`, and the bounty flipping to done with its credits and the stranger's badge becoming `known 1`.
- The network log shows every request sent without credentials and nothing written; the board never requests `/events/`; apart from the font, the landing page requests nothing but what its hero's store reads.
- Against an empty testnet, `/board` and the landing hero both show the empty state, with no sample rooms.
- The landing page and the board render at 375 px and at desktop width with no horizontal scroll, are keyboard navigable, and show no motion under reduced-motion emulation.
- The verifier traces every claim on the landing page to [00](../00-overview.md), [02](../02-encryption-and-safety.md) or the known limits in [06](../06-verification-and-limits.md#known-limits-say-them-in-the-readme), and finds none that a known limit contradicts.

## Notes

- pubky-app is read at its pinned commit for reference only; nothing in `web/` imports, vendors or fetches it at build time, and none of Pubky's or Synonym's logos or illustrations ship.
- The board writes nothing. If a later phase adds E4 (reading in the browser), that is where sign-in and keys arrive.
- The pkarr relay under `Pubky.testnet()` is `http://<host>:15411`; resolved. Production uses the SDK's default HTTPS relays.
- Hosting (post-approval): Vercel needs a rewrite of every path to `index.html`; Cloudflare Pages treats a project without a `404.html` as a SPA. Deployment protection must be off so the Vibes health cron gets a 200.
