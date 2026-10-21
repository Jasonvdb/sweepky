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

1. Start the pinned testnet binary with the install and run commands in [06](../06-verification-and-limits.md#local-environment-this-machine) (`TEST_PUBKY_CONNECTION_STRING` against local Postgres). The script stops it with `kill -INT` at the end, then drops the testnet's database itself if the testnet left it behind.
2. `sweepky --testnet login --identity owner`, `--identity sweeper`, `--identity stranger`, each under its own home; each login publishes a device key, which is also the write check. No QR codes anywhere in the demo.
3. `sweepky circle create` as owner; add `sweeper`.
4. `sweepky post --open` the bounty from `SWEEPKY_DEMO_TARGETS` as owner; this also writes `bounties/<id>.discovered.json` with the testnet homeserver's starting cursor.
5. As sweeper, in an `init` project: `sweepky run <bounty-url>`, then copy the contents of `$SWEEPKY_DEMO_RUN_DIR` into the `audit/` directory `run` created, then `sweepky submit`. No agent runs in the demo; the report stands in for its output.
6. As stranger, in another `init` project: `sweepky run <bounty-url>`, then a synthetic `audit/` whose one finding points at the same file and scope as one real finding under a different id, then `sweepky submit`.
7. `sweepky pull --findings` as owner; show the groups (the shared location lists both reporters), the `untrusted/` directory holding the stranger's content, and the updated `discovered.json`.
8. `sweepky done` as owner: the proposal is {sweeper, stranger}; accept.
9. `pnpm --dir web dev` with `VITE_PUBKY_TESTNET=1` and `VITE_SWEEPKY_CIRCLE=<owner pubky>`, so `/` and `/board` show the owner's circle with no `?circle=` in the address; print the landing and board URLs.

## Done when

- `sweepky pull --findings` as the owner prints every finding from the demo report with GitHub links at the pinned SHA.
- The board at `http://localhost:5173/board` shows the bounty, both sweeps landing, the stranger's sweep as `unknown` once the owner's pull has published it, then the bounty done with both credits and the stranger as `known 1`.
- The landing page at `http://localhost:5173/` shows the same bounty live in its hero.
- Jason approves the look, the landing copy and the flow.

## Notes

Deviations from the plan as first written, each recorded where the design says otherwise too.

- **`pull --findings` (Done when 1).** P2c's `pull` prints no finding text (03, 02 "Untrusted reports are data"), so Done when 1 and 06's P5 acceptance now name an opt-in flag; plain `pull`'s report is unchanged. With the flag, after the report, `pull` prints the circle's merged findings (`pull/show.rs`: what `merged.json` holds, trusted sweeps only, never anything under `untrusted/`), newest bounty first, each string sanitised and capped, each location linked as `https://github.com/<owner>/<name>/blob/<sha>/<file>#L<line>` at the commit the bounty pins for review. A sweep of several targets links only files written under `<tid>/`; a repo not on github.com prints `(no GitHub link)`.
- **The extra reads.** To build the links, `--findings` reads the owner's own bounty records once more, after the report and still under the pull lock: one read per bounty with merged findings to print, through the opener's read (the owner's homeserver from the run's cache, `PublicRecords::get_bounty`, `MAX_RECORD_BYTES`, the unredirected GET), at most 32 a run (`MAX_BOUNTIES_SHOWN`, the roster poll's per-key re-read cap); the targets come from that record alone. A missing, failed or oversized read prints that bounty's findings without links and one fixed-text warning on standard error, and the run still succeeds. The flag writes nothing, takes no new lock, and changes no local state format; each bounty's findings are grouped again from the stored copies within triage's caps, one bounty at a time, rather than kept for the whole run. 03's `pull` row says so.

- **The headless check (`scripts/check-demo.sh`, `crates/sweepky-cli/examples/demo_check.rs`).** The headless counterpart of steps 2 to 8, not a run of `scripts/demo-local.sh` (Root decision 3: the static testnet ports on this machine are held by the Docker homeserver-testnet behind colima, which the check never stops, reconfigures or touches). `scripts/check-demo.sh` takes no arguments. It checks `pg_isready` against `TEST_PUBKY_CONNECTION_STRING` (default from [06](../06-verification-and-limits.md#local-environment-this-machine)), builds the example, snapshots the `pubky_test_*` databases with `psql -lqt`, and runs the example in a `mktemp -d` scratch directory under `$TMPDIR`, removed by a trap on every exit (Ctrl-C and `TERM` included); `SWEEPKY_DEMO_RUN_DIR` and `SWEEPKY_DEMO_TARGETS` pass through, and with neither the example uses `fixtures/demo`. The example runs every command through the library on an in-process `EphemeralTestnet` on random ports, reading github.com anonymously and nothing else. The script prints the example's PASS and FAIL lines from its `results.json` (fixed text compiled into the example, never a finding), then its own two checks: no process whose command line names the scratch directory is left, and no `pubky_test_*` database appeared that was not in the first snapshot. A database that did is a FAIL and is dropped, but only when its name is exactly `pubky_test_` and 32 hex digits and nobody holds a connection to it (`DROP DATABASE` without `FORCE`), so a concurrent test's live database is kept and reported; no other database is touched. An interrupted run stops the example with `SIGTERM` (bash starts a background job with `SIGINT` ignored) and does the same database step. The exit status is non-zero on any FAIL. Nothing writes to `~/.cargo`, `~/.config/sweepky` or `~/.local/share/sweepky`.

  **Results, `scripts/check-demo.sh` on 2026-10-21** (commit `e348c91` plus this script, the fixture inputs, Postgres 18 from brew, the Docker `homeserver` container up throughout, exit status 0):

  ```text
  PASS  the open bounty is public at its URL with status open
  PASS  the bounty pins each target at the full SHA its input names
  PASS  post --open published the bounty's discovered.json with no sweep yet
  PASS  the sweeper's sweep record reads running after run
  PASS  every file a sweeper location names was fetched with at least that many lines
  PASS  the sweeper's sweep record reads done after submit
  PASS  submit moved audit/ out of the project into the sweeper's data directory
  PASS  the stranger's sweep record reads running after run
  PASS  the stranger's sweep record reads done after submit
  PASS  the pull report labels the sweeper's sweep circle
  PASS  the pull report labels the stranger's sweep unknown
  PASS  pull --findings prints the title of every finding of the run directory
  PASS  pull --findings links every location of the run directory at the pinned commit
  PASS  pull --findings prints none of the stranger's finding text
  PASS  discovered.json lists the stranger's sweep after the owner's pull
  PASS  the stranger's sweep is stored under untrusted/
  PASS  groups.json has one group reported by the sweeper and the stranger
  PASS  the bounty is done, crediting exactly the sweeper and the stranger
  PASS  the next pull labels the stranger's sweep known: 1
  PASS  the demo flow ran to its end
  PASS  no process this run started is still running
  PASS  no pubky_test_* database left behind
  inputs: fixtures/demo; PASS 22, FAIL 0
  ```

  Two broken inputs, the same day: `SWEEPKY_DEMO_TARGETS` set to a missing file's path (with `SWEEPKY_DEMO_RUN_DIR` a missing directory) exits 1 with `FAIL  demo_check exited 1 and wrote no results.json: Error: SWEEPKY_DEMO_TARGETS is not JSON` before any testnet starts; `SWEEPKY_DEMO_RUN_DIR` an empty directory with the fixture targets fails after `post` (`FAIL  the demo flow ran to its end`) and exits 1. Both left no process, no scratch directory and no new `pubky_test_*` database (five older ones, from before this phase, were there throughout and left alone). The real report and the browser board are not covered: those stay with `scripts/demo-local.sh` and Jason's approval.

## After approval (not part of this phase)

`sweepky login` against `homeserver.pubky.app`, where the key write is the per-identity check and a 403 means that identity's token forbids the path; static hosting with the SPA fallback; `vibe/vibe.json` (`hosted.url` pointing at `/board`, `hosted.healthPath` `/health.json`, `pubkyAppFork: false`, `stack.target: "production"`, `capabilities: ["homeserver.read"]`, plus the required `authors`, `tags`, `category`, `covers`, `license`, `version`, `repo.url`, `schemaVersion`, a directory named after the id) and the PR to `pubky/vibes`, then the extensions in [05-extensions.md](../05-extensions.md).
