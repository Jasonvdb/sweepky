# Sweepky web

The landing page and the read-only board, a static React app. The design is
in [docs/plan/04-board.md](../docs/plan/04-board.md); the build phase is
[P4](../docs/plan/phases/P4-board.md).

Run every command from this directory, or add `--dir web` from the repository
root. Install the pinned dependencies first:

```sh
pnpm install --frozen-lockfile
```

## Develop

```sh
VITE_PUBKY_TESTNET=1 pnpm dev
```

`VITE_PUBKY_TESTNET=1` reads from the local Pubky testnet (pkarr relay on
`localhost:15411`). Without it, the dev server reads from production. Pick a
circle with `?circle=<admin pubky>` in the address, for example
`http://localhost:5173/board?circle=<key>`.

## Test

```sh
pnpm test
```

Runs the unit tests under `src/` with vitest in Node. CI runs this after the
build.

## Build

```sh
pnpm build
```

Type-checks the app, the unit tests and the browser specs, then writes the
static site to `dist/`. The build fails if `VITE_PUBKY_TESTNET` is set to any
value.

## Browser checks

```sh
pnpm e2e
```

Runs the Playwright specs in `e2e/` on the Google Chrome installed on this
machine. Do not run `playwright install`: the specs use the installed Chrome
and need no downloaded browser. Playwright starts the dev server on the
testnet switch at port 5179 and stops it when the run ends, so that port must
be free.

The specs check layout at 375 px and 1440 px, the keyboard walk, reduced
motion, the intro strip's link to `#sweep`, and the network log. The layout and
network specs use a new random circle and answer the testnet relay's lookups
themselves, so they write nothing and need no testnet running.

Neither `pnpm test` nor CI runs these specs. Results go to `test-results/`,
which Git ignores.

### Against the local testnet

Two specs need the local testnet answering on its fixed ports (pkarr relay
`15411`, homeserver `6286`; see
[06](../docs/plan/06-verification-and-limits.md)). Both are skipped unless
`SWEEPKY_E2E_TESTNET=1` is set:

```sh
# Reads only: a fresh random key shows the empty state.
SWEEPKY_E2E_TESTNET=1 pnpm e2e --grep @empty

# Writes: signs up three new keys and seeds synthetic records.
SWEEPKY_E2E_TESTNET=1 pnpm e2e --grep @testnet
```

`@testnet` writes to the testnet. `e2e/seed.ts` signs up an owner, a circle
member and a stranger on the testnet homeserver, then writes the records the
CLI would write. The spec watches the board follow each change within one
30-second poll, so a run takes a few minutes. The seed talks only to
`localhost`. To use another testnet homeserver key, set
`SWEEPKY_E2E_HOMESERVER`.
