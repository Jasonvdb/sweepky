# P5 — Local demo

## Goal

One script that reproduces the whole flow on a clean local testnet, ending with the board open in a browser. Approval of this demo gates the production homeserver, the Vibes listing and hosting. There is no staging step.

## Inputs (environment, never committed)

| Variable | Meaning |
|---|---|
| `SWEEPKY_DEMO_RUN_DIR` | Path to a real local `security-audit` run directory whose contents are copied into the sweep the circle sweeper submits |
| `SWEEPKY_DEMO_TARGETS` | JSON array of the targets that run covered (repo + pinned SHA + paths, plus any companion), used to post the bounty |

The demo report may describe unpatched findings in a real repository. It is read from this path only, uploaded only to the local testnet, and nothing from it is committed to this repo or sent anywhere else. Committed fixtures remain synthetic.

## `scripts/demo-local.sh`

Three identities run side by side, each with its own `SWEEPKY_HOME`; below, `as owner` means `SWEEPKY_HOME=$DEMO/owner sweepky --testnet …`.

1. Start the pinned testnet binary (`pubky-testnet` 0.16.1, `TEST_PUBKY_CONNECTION_STRING` against local Postgres). The script stops it with `kill -INT` at the end so it drops its database.
2. `sweepky --testnet login --identity owner`, `--identity sweeper`, `--identity stranger`, each under its own home; each login publishes a device key, which is also the write check. No QR codes anywhere in the demo.
3. `sweepky circle create` as owner; add `sweeper`.
4. `sweepky post --open` the bounty from `SWEEPKY_DEMO_TARGETS` as owner; this also writes `bounties/<id>.discovered.json` with the testnet homeserver's starting cursor.
5. As sweeper, in an `init` project: `sweepky run <bounty-url>`, then copy the contents of `$SWEEPKY_DEMO_RUN_DIR` into the `audit/` directory `run` created, then `sweepky submit`. No agent runs in the demo; the report stands in for its output.
6. As stranger, in another `init` project: `sweepky run <bounty-url>`, then a synthetic `audit/` whose one finding points at the same file and scope as one real finding under a different id, then `sweepky submit`.
7. `sweepky pull` as owner; show the groups (the shared location lists both reporters), the `untrusted/` directory holding the stranger's content, and the updated `discovered.json`.
8. `sweepky done` as owner: the proposal is {sweeper, stranger}; accept.
9. `pnpm --dir web dev` with `VITE_PUBKY_TESTNET=1`; print the board URL.

## Done when

- `sweepky pull` as the owner prints every finding from the demo report with GitHub links at the pinned SHA.
- The board at `http://localhost:5173` shows the bounty, both sweeps landing, the stranger's sweep as `unknown` once the owner's pull has published it, then the bounty done with both credits and the stranger as `known 1`.
- Jason approves the look and the flow.

## After approval (not part of this phase)

`sweepky login` against `homeserver.pubky.app`, where the key write is the per-identity check and a 403 means that identity's token forbids the path; static hosting with the SPA fallback; `vibe/vibe.json` (`pubkyAppFork: false`, `stack.target: "production"`, `capabilities: ["homeserver.read"]`, plus the required `authors`, `tags`, `category`, `covers`, `license`, `version`, `repo.url`, `schemaVersion`, a directory named after the id) and the PR to `pubky/vibes`, then the extensions in [05-extensions.md](../05-extensions.md).
