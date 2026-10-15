# P4 — The board

## Goal

A static, read-only SPA where anyone watches bounties, sweeps and credits. No sign-in, no decryption, no writes.

## Build

- Scaffold: `npx tiged pubky/pubky-app-templates/basic-pubky-app web`, bump to `@synonymdev/pubky` 0.14, remove the template's sign-in scaffolding, add react-router and Zustand.
- `VITE_PUBKY_TESTNET=1` toggle → `Pubky.testnet()`.
- Routes: `/`, `/b/:owner/:id`, `/s/:owner/:sweep`, `/circle`.
- Polling store (30 s) over roster members' `bounties/` and `sweeps/`, plus the events-feed watcher for open bounties (cursor in `localStorage`).
- Trust badge per sweep (`circle` / `known N` / `unknown`) computed from the roster plus `credits` on done bounties, ignoring a credit that names the bounty's owner; `open` marker on bounties; done bounties show their credited sweepers; credits received on the Circle page.
- Visual direction from [04-board.md](../04-board.md): floor plan, detectors, swept rooms, rooms going dark when done, hollow unknown sweepers.
- `/health.json`.

## Done when

- `pnpm build` and `pnpm test` clean (unit tests for the trust-badge rule and the feed parser port).
- Playwright or manual against the testnet: the public view shows a `running` → `done` sweep transition within one poll, a stranger's sweep arriving via the feed with the `unknown` badge, and the bounty flipping to done with its credits and the stranger's badge becoming `known 1`.
- No network request from the board carries a session or writes anything (check the network log).

## Notes

- The board writes nothing. If a later phase adds E4 (reading in the browser), that is where sign-in and keys arrive.
- Verify the pkarr relay default under `Pubky.testnet()` early in the phase.
