# P5 — Local demo

## Goal

One script that reproduces the whole flow on a clean local testnet, ending with the board open in a browser. Approval of this demo gates deployment, the Vibes listing and the production check.

## Inputs (environment, never committed)

| Variable | Meaning |
|---|---|
| `SWEEPKY_DEMO_RUN_DIR` | Path to a real local `security-audit` run directory to submit as the circle sweeper's sweep |
| `SWEEPKY_DEMO_TARGETS` | JSON array of the targets that run covered (repo + pinned SHA + paths, plus any companion), used to post the bounty |

The demo report may describe unpatched findings in a real repository. It is read from this path only, uploaded only to the local testnet, and nothing from it is committed to this repo or sent anywhere else. Committed fixtures remain synthetic.

## `scripts/demo-local.sh`

1. Start the testnet (`TEST_PUBKY_CONNECTION_STRING` against local Postgres).
2. `sweepky dev identity new owner`, `new sweeper`, `new stranger`.
3. `sweepky circle create` as owner; add `sweeper`.
4. `sweepky post --open` the bounty from `SWEEPKY_DEMO_TARGETS` as owner.
5. `sweepky run --as sweeper` then `sweepky submit --run-dir "$SWEEPKY_DEMO_RUN_DIR"`.
6. `sweepky run --as stranger` then `sweepky submit` a synthetic run dir.
7. `sweepky pull --as owner`; show the merged findings and the `untrusted/` summary.
8. `sweepky confirm` one of the stranger's findings as owner.
9. `pnpm --dir web dev` with `VITE_PUBKY_TESTNET=1`; print the board URL and the `sweepky dev approve` line for the sign-in QR.

## Done when

- The board at `http://localhost:5173` shows the bounty, both sweeps landing, and (signed in as owner) every finding from the demo report with GitHub links at the pinned SHA.
- The stranger's sweep shows as `unknown`, then `known: 1` after the confirm.
- `sweepky watch` in a terminal shows the same state.
- Jason approves the look and the flow.

## After approval (not part of this phase)

Production one-write check under `/pub/sweepky/`, static hosting, `vibe/vibe.json` (`pubkyAppFork: false`, `stack.target: "production"`, `capabilities: ["/pub/sweepky/keys/:rw"]`) and the PR to `pubky/vibes`, then the extensions in [05-extensions.md](../05-extensions.md).
