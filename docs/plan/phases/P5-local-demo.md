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

- **`scripts/demo-local.sh` as written.** The script follows the nine steps above, with these differences. Each one is also in the script's header comment, which `scripts/demo-local.sh --help` prints.
  - **The synthetic fallback.** Set both inputs or neither. With neither set, the script uses `fixtures/demo` (`targets.json`, `sweeper-run/`, made-up findings against this repository's `docs/plan/` at `be535e6`; see [its README](../../../fixtures/demo/README.md)) and says so twice: once before step 2 and once before the findings in step 7. With only one set, or one set to the empty string, preflight refuses to start. The script never prints the contents of either input. It copies a real run directory only into its scratch directory and uploads it only to the local testnet.
  - **`--step` starts the board early.** Without the flag, the board starts at step 9, as written above. With `--step`, the script starts the board right after step 3, then waits for Enter before each of steps 4 to 8, so the board can be watched while each step lands. Standard input must be a terminal; preflight refuses `--step` otherwise.
  - **Extras in steps 4, 5, 6 and 8.** Step 4 also prints `discovered.json` as `post --open` left it. Steps 5 and 6 run `init --no-playbook`, so npx never runs, and pass `--playbook` to `submit`: `cloudflare/security-audit@c1c8a8c1471069fb0e188eeaff69b8e8db6564a8` for the sweeper and `careful-review` for the stranger. In step 6 the stranger's one finding is moved, with jq, to the locations of the run directory's first finding, so the two share a group whatever the run directory holds. Step 8 runs `pull` once more after `done`, which labels the stranger `known: 1`.
  - **Preflight and cleanup.** Before the script starts or creates anything, it checks the following. It prints every problem it finds and, if there is any, exits 1:
    - the static ports (TCP 6881, 15411, 15412, 6286 to 6288 and 5173, and UDP 6881) are free, and it names whatever holds one;
    - `pubky-testnet` and `pnpm` are at the versions [06](../06-verification-and-limits.md#local-environment-this-machine) pins, checked as its table says;
    - Postgres answers;
    - `web/node_modules` is installed;
    - the other tools are on `PATH`;
    - the inputs are usable: the run directory holds `findings.json` and the targets are a non-empty JSON array, checked without printing either;
    - with `--step`, standard input is a terminal.

    On every exit, Ctrl-C and `TERM` included, the script stops what it started: the dev server and its vite child, then the testnet with `kill -INT`, then any `pubky_test_*` database the testnet left behind (the same name and idle rules as the headless check). Last, it removes its `mktemp -d` scratch directory. It never touches a process it did not start.
- **The curl read of `discovered.json`, unverified here.** Steps 4 and 7 read `discovered.json` anonymously with `curl -sf --max-time 10 --max-filesize 1048576 -H "pubky-host: <owner pubky>" http://localhost:6286/pub/sweepky/bounties/<id>.discovered.json` and print it with `jq -ac`. Nobody has tested that request form against the pinned testnet's homeserver on this machine, because `scripts/demo-local.sh` has not run here (see the next note). If the read fails, the script prints `(could not read discovered.json from the testnet homeserver)` and carries on, so a wrong form cannot stop the demo. The headless check reads the same file through the library's public read and passes (`discovered.json lists the stranger's sweep after the owner's pull`).
- **What the headless check covers, and the hand checks.** `scripts/demo-local.sh` has not run on this machine: the Docker homeserver-testnet behind colima holds the static testnet ports, and nothing in this phase stops it. Each Done-when item maps to a check as follows.

  | Done when | Covered by |
  |---|---|
  | 1. `pull --findings` prints every finding with links at the pinned SHA | The headless check, with the fixtures (`pull --findings prints the title of every finding of the run directory`, `… links every location of the run directory at the pinned commit`), and hand check 4 for the real report and the links opening |
  | 2. The board shows the bounty, both sweeps, `unknown`, then done with both credits and `known 1` | Hand check 5. The headless check covers the state behind it: the records' statuses, the `unknown` and `known: 1` labels, and the done bounty's credits |
  | 3. The landing page shows the bounty live in its hero | Hand check 6 |
  | 4. Jason approves the look, the landing copy and the flow | Hand checks 1 to 8, by Jason |

  Run the hand checks on a machine where nothing holds TCP 6881, 15411, 15412, 6286, 6287, 6288 or 5173, or UDP 6881. The script's preflight names any holder.

  1. Install the pinned testnet: `cargo install pubky-testnet --version '=0.16.2' --locked`. Keep the quotes.
  2. Start Postgres with `brew services start postgresql@18`. Then run `psql postgres://jason@localhost:5432/postgres -lqt | cut -d'|' -f1 | tr -d ' ' | grep '^pubky_test_'` and note which databases it lists.
  3. Install the board's dependencies with `pnpm --dir web install --frozen-lockfile`, and check that `git status --short` is empty.
  4. Run `scripts/demo-local.sh --step`. To use a real report, first set `SWEEPKY_DEMO_RUN_DIR` and `SWEEPKY_DEMO_TARGETS` in the shell; never write them to a file in the repository. After step 7's `pull --findings`, check that every finding of the report is listed and that each `https://github.com/<owner>/<name>/blob/<sha>/<file>#L<line>` link opens that line at the SHA the bounty pins.
  5. Keep `http://localhost:5173/board` open from step 3 on, and press Enter for each of steps 4 to 8. Check that:
     - step 4 shows the bounty;
     - steps 5 and 6 show each sweep landing;
     - step 7 shows the stranger's sweep as `unknown`;
     - step 8 shows the bounty done, crediting the sweeper and the stranger, with the stranger as `known 1`.
  6. Open `http://localhost:5173/` and check that the hero shows the same bounty, live.
  7. Read through the look, the landing copy and the flow. This is Jason's approval.
  8. Press Ctrl-C. Check that the script exits and that nothing it started is left: `pgrep -fl pubky-testnet` prints nothing, and `lsof -nP -iTCP:5173 -sTCP:LISTEN` and `lsof -nP -iTCP:6286 -sTCP:LISTEN` print nothing. Then run the `psql` line from hand check 2 again and check that it lists no `pubky_test_*` database that was not there before. Last, check that `git status --short` is still empty.

  Nobody has run these steps yet. They are recorded here for Jason's approval run.

## After approval (not part of this phase)

`sweepky login` against `homeserver.pubky.app`, where the key write is the per-identity check and a 403 means that identity's token forbids the path; static hosting with the SPA fallback; `vibe/vibe.json` (`hosted.url` pointing at `/board`, `hosted.healthPath` `/health.json`, `pubkyAppFork: false`, `stack.target: "production"`, `capabilities: ["homeserver.read"]`, plus the required `authors`, `tags`, `category`, `covers`, `license`, `version`, `repo.url`, `schemaVersion`, a directory named after the id) and the PR to `pubky/vibes`, then the extensions in [05-extensions.md](../05-extensions.md).
