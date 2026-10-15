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

Three identities run side by side, each with its own `SWEEPKY_HOME`; below, `as owner` means `SWEEPKY_HOME=$DEMO/owner sweepky …`.

1. Start the testnet (`TEST_PUBKY_CONNECTION_STRING` against local Postgres).
2. `sweepky login --signer owner`, `--signer sweeper`, `--signer stranger`, each under its own home; each login publishes a device key. No QR codes anywhere in the demo.
3. `sweepky circle create` as owner; add `sweeper`.
4. `sweepky post --open` the bounty from `SWEEPKY_DEMO_TARGETS` as owner.
5. `sweepky run` as sweeper, then `sweepky submit --run-dir "$SWEEPKY_DEMO_RUN_DIR"`.
6. `sweepky run` as stranger, then `sweepky submit` a synthetic run dir that shares one finding `id` with the real one.
7. `sweepky pull` as owner; show the merged findings (the shared finding lists both reporters) and the `untrusted/` summary.
8. `sweepky done` as owner: the proposal is {sweeper, stranger}; accept.
9. `pnpm --dir web dev` with `VITE_PUBKY_TESTNET=1`; print the board URL.

## Done when

- `sweepky pull` as the owner prints every finding from the demo report with GitHub links at the pinned SHA.
- The board at `http://localhost:5173` shows the bounty, both sweeps landing, the stranger's sweep as `unknown`, then the bounty done with both credits and the stranger as `known 1`.
- `sweepky watch` in a terminal shows the same state.
- Jason approves the look and the flow.

## After approval (not part of this phase)

Production one-write check under `/pub/sweepky/`, static hosting, `vibe/vibe.json` (`pubkyAppFork: false`, `stack.target: "production"`, `capabilities: []` since the board writes nothing) and the PR to `pubky/vibes`, then the extensions in [05-extensions.md](../05-extensions.md).
