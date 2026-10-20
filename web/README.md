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
motion, the intro strip's link to `#sweep`, and the network log. Each spec
uses a new random circle and answers the testnet relay's lookups itself, so
the specs write nothing and need no testnet running.

Neither `pnpm test` nor CI runs these specs. Results go to `test-results/`,
which Git ignores.
