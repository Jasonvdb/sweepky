# P4 — The board

## Goal

A static, read-only SPA where anyone watches bounties, sweeps and credits. No sign-in, no decryption, no writes, no feed scanning.

## Build

- Scaffold: `pnpm create vite web --template react-ts`; add `@synonymdev/pubky` 0.16.1, `react-router`, `zustand` at the exact versions in [03](../03-cli-and-skill.md#dependencies); `tsconfig` `lib` includes `esnext`. Load Inter Tight in the page.
- `VITE_PUBKY_TESTNET=1` → `Pubky.testnet()`, opt-in only; the production build asserts it is unset.
- Routes: `/`, `/b/:owner/:id`, `/s/:sweeper/:id`, `/circle`.
- Polling store (30 s) per [04](../04-board.md#live-ness): cached homeserver resolution, reverse paged listings with 404 as empty, conditional re-GET of non-terminal records, open bounties through `bounties/<id>.discovered.json`, every request with `credentials: 'omit'`.
- Trust badge per sweep (`circle` / `known N` / `unknown`) computed from the roster plus `credits` on done bounties, ignoring a credit that names the bounty's owner; `open` marker on bounties; done bounties show their credited sweepers; credits received on the Circle page; "not browser-reachable" for members whose homeserver has no ICANN HTTPS endpoint.
- Visual direction from [04-board.md](../04-board.md): floor plan, detectors, swept rooms, rooms going dark when done, hollow unknown sweepers.
- `/health.json`; no `X-Frame-Options` or `frame-ancestors` that excludes vibes.pubky.app; nothing essential in `localStorage`.

## Done when

- `pnpm build` and `pnpm test` clean (unit tests for the trust-badge rule, the listing pager and the record reducer).
- Playwright or manual against the testnet: the public view shows a `running` → `done` sweep transition within one poll, a stranger's sweep appearing with the `unknown` badge after the owner's `pull` has published it to `discovered.json`, and the bounty flipping to done with its credits and the stranger's badge becoming `known 1`.
- The network log shows every request sent without credentials and nothing written; the board never requests `/events/`.

## Notes

- The board writes nothing. If a later phase adds E4 (reading in the browser), that is where sign-in and keys arrive.
- The pkarr relay under `Pubky.testnet()` is `http://<host>:15411`; resolved. Production uses the SDK's default HTTPS relays.
- Hosting (post-approval): Vercel needs a rewrite of every path to `index.html`; Cloudflare Pages treats a project without a `404.html` as a SPA. Deployment protection must be off so the Vibes health cron gets a 200.
