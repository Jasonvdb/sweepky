# P4 — The board

## Goal

A static SPA where visitors watch sweeps happen and members sign in with Ring to read findings.

## Build

- Scaffold: `npx tiged pubky/pubky-app-templates/basic-pubky-app web`, bump to `@synonymdev/pubky` 0.14, add react-router, Zustand, `age-encryption`.
- `VITE_PUBKY_TESTNET=1` toggle → `Pubky.testnet()`.
- Ring sign-in with grant `/pub/sweepky/keys/:rw` (QR + deeplink, cancel on visibility change); `browserSessionStore` persistence.
- Device key: non-extractable WebCrypto X25519 in IndexedDB → `keys/web-<id>.json`; the "older sweeps can't be read here" banner.
- Routes: `/`, `/b/:owner/:id`, `/s/:owner/:sweep`, `/keys`, `/circle`.
- Polling store (30 s) over roster members plus the events-feed watcher for open bounties (cursor in `localStorage`).
- Trust badge per sweep (`circle` / `known N` / `unknown`), `open` marker on bounties, attestation counts on the Circle page.
- typage decryption into a memory-only slice; findings grouped verdict → severity with GitHub links at the pinned SHA.
- Visual direction from [04-board.md](../04-board.md): floor plan, detectors, swept rooms, hollow unknown sweepers.
- `/health.json`.

## Done when

- `pnpm test` decrypts `fixtures/rust.age` with typage; a Rust test decrypts `fixtures/typage.age`.
- `pnpm build` clean.
- Playwright or manual against the testnet: the public view shows a `running` → `done` transition and a stranger's sweep arriving via the feed; the signed-in view (approved with `sweepky dev approve`) decrypts a synthetic sweep and shows correct trust badges.
- Non-extractable X25519 `deriveBits` confirmed on the browsers installed on this machine.

## Notes

- The board writes exactly one record kind: its own device key.
- Verify the grant-flow relay default under `Pubky.testnet()` early in the phase.
