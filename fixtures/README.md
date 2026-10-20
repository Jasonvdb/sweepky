# Fixtures

Synthetic test data for the Rust tests in `crates/` and the TypeScript tests in `web/`. The table below lists every file here and the tests that load it. Two directories, [`cloudflare/`](#run-directories) and [`common/`](#run-directories), are the synthetic run directories [P1b](../docs/plan/phases/P1b-core-crypto.md) adds: what a sweeper's agent leaves for `submit` to package.

Nothing real lands here. Every pubky, id, finding and commit is made up for the test that uses it. The one set not made up here is [`cctv-age/`](#cctv-age): public test vectors copied from C2SP, whose keys are published test keys. The local demo's audit report is read from a path in an environment variable and is never committed ([P5](../docs/plan/phases/P5-local-demo.md#inputs-environment-never-committed)).

| File | What it is | Loaded by |
|---|---|---|
| [`trust-labels.json`](trust-labels.json) | A roster, bounties with credits, and the trust label and credit tally every pubky in it should get | P1a's trust-label test (Rust), P4's trust-badge test (TypeScript) |
| [`discovered.json`](discovered.json) | An open bounty's discovered-sweeps file: two strangers' sweeps and the feed cursors of two homeservers | P1a's `Discovered` round-trip test (Rust) |
| [`cloudflare/findings.json`](cloudflare/findings.json) | A `findings.json` in the shape Cloudflare's `security-audit` skill writes: a `confirmed`, a `needs_validation` and a `rejected` record, sorted by fingerprint. Also the findings of the Cloudflare-shaped run directory | P1a's Cloudflare converter tests and P1b's package-build tests in `sweepky-core`, [`run_dir_round_trip.rs`](../crates/sweepky-core/tests/run_dir_round_trip.rs) and [`fixture_groups.rs`](../crates/sweepky-core/tests/fixture_groups.rs); P2b's `submit` tests in `sweepky-cli` and its [`end_to_end.rs`](../crates/sweepky-cli/tests/end_to_end.rs); P2c's triage tests in `sweepky-cli` ([`pull/triage.rs`](../crates/sweepky-cli/src/pull/triage.rs)) (Rust) |
| [`cloudflare/REPORT.md`](cloudflare/REPORT.md) | The Cloudflare-shaped run directory's report, laid out the way Cloudflare's skill writes its `REPORT.md` | [`run_dir_round_trip.rs`](../crates/sweepky-core/tests/run_dir_round_trip.rs); P2b's `submit` tests and [`end_to_end.rs`](../crates/sweepky-cli/tests/end_to_end.rs) (Rust) |
| [`cloudflare/coverage-ledger.json`](cloudflare/coverage-ledger.json) | The Cloudflare-shaped run directory's coverage ledger: four units, valid against Cloudflare's own ledger validator | [`run_dir_round_trip.rs`](../crates/sweepky-core/tests/run_dir_round_trip.rs); P2b's `submit` tests and [`end_to_end.rs`](../crates/sweepky-cli/tests/end_to_end.rs) (Rust) |
| [`common/findings.json`](common/findings.json) | A hand-written `findings.json` in Sweepky's common format: one finding at the same sink as a Cloudflare record under another id, and one with a Cloudflare record's id at an unrelated sink | [`run_dir_round_trip.rs`](../crates/sweepky-core/tests/run_dir_round_trip.rs) and [`fixture_groups.rs`](../crates/sweepky-core/tests/fixture_groups.rs); P2c's triage tests in `sweepky-cli` ([`pull/triage.rs`](../crates/sweepky-cli/src/pull/triage.rs)) (Rust) |
| [`common/REPORT.md`](common/REPORT.md) | The common-format run directory's report | [`run_dir_round_trip.rs`](../crates/sweepky-core/tests/run_dir_round_trip.rs) (Rust) |
| [`common/notes/triage.md`](common/notes/triage.md) | Triage notes one directory down, with a non-ASCII character (`→`) | [`run_dir_round_trip.rs`](../crates/sweepky-core/tests/run_dir_round_trip.rs) (Rust) |
| [`common/capture.bin`](common/capture.bin) | 16 bytes that are not UTF-8: the one non-text file, which `submit` must report and leave out | [`run_dir_round_trip.rs`](../crates/sweepky-core/tests/run_dir_round_trip.rs) (Rust) |
| [`target-repo.git/`](target-repo.git) | A tiny bare git repository (`HEAD`, `config`, four loose refs and one pack): a root commit with planted agent files, a normal commit with an annotated tag, a merge commit on `main`, and a PR head whose merge base is not the base tip | P1a's fixture check (Rust); P2b's fixture `TargetResolver` and the target tests of P2b and P3 |
| [`make-target-repo.sh`](make-target-repo.sh) | The script that regenerates `target-repo.git/` | Run by hand ([Regenerating](#regenerating)) |
| [`cctv-age/`](cctv-age) | The 147 age test vectors of C2SP's CCTV at commit `50a8ecf2a220f4c8bdc4f085789b8e85c26829e7`, byte for byte | P1b's CCTV test, [`cctv_age.rs`](../crates/sweepky-core/tests/cctv_age.rs) (Rust) |
| [`fetch-cctv-age.sh`](fetch-cctv-age.sh) | The script that re-vendors `cctv-age/` from that commit | Run by hand ([Re-vendoring](#re-vendoring)) |

## `trust-labels.json`

The trust-label rule has two implementations: the Rust one in `sweepky-core`, which the CLI uses, and the TypeScript one in the board. [P1a](../docs/plan/phases/P1a-core-records.md)'s Rust test and [P4](../docs/plan/phases/P4-board.md)'s TypeScript test both load this file and assert the label and both counts of every `expected` entry, so the CLI and the board agree on every case it covers. When you change this file, update the tables below and make both tests pass in the same change.

### Shape

```json
{
  "roster": { "schemaVersion": 1, "name": "…", "admin": "<pubky>", "members": [{ "pubky": "<pubky>", "label": "A" }] },
  "bounties": [{ "id": "<13-char id>", "owner": "<pubky>", "status": "done|open", "credits": ["<pubky>"] }],
  "expected": { "<pubky>": { "label": "circle|known|unknown", "bounties": 0, "owners": 0 } }
}
```

- `roster` is a full `circle.json` record as [01](../docs/plan/01-records-and-discovery.md#records-v1) defines it. The admin is also listed in `members`, which changes no expected value: the admin is in the roster either way.
- A `bounties` entry, `{id, owner, status, credits}`, is a reduced test shape, not the bounty record from [01](../docs/plan/01-records-and-discovery.md#the-bounty-post). The real record has no `owner` or `id` field, because both come from its path (`pubky://<owner>/pub/sweepky/bounties/<id>.json`). This file inlines them so one file holds the whole case. `credits` is always present and can be empty.
- `expected` has exactly one entry per pubky in the file, circle members included.

Pubkys are random Ed25519 public keys in raw z-base32, generated for this file with the private keys discarded. None is a real identity or the testnet homeserver's key. Ids are synthetic `pubky-timestamp` values from August to October 2026.

### The rule

The rule comes from [01](../docs/plan/01-records-and-discovery.md#records-v1), plus the owner count that [00](../docs/plan/00-overview.md#trust-model-the-circle-is-a-default-not-the-protocol) adds to the `known` label. Only credits from trusted owners count, and in v1 the trusted owners are the roster's members. For each pubky:

- `bounties` is the number of `done` bounties whose owner is a roster member and whose `credits` name the pubky. A credit that names the bounty's own owner counts for nothing.
- `owners` is the number of distinct owners among those bounties.
- `label` is `circle` if the pubky is in the roster, else `known` if `bounties` > 0, else `unknown`.

"In the roster" and "roster member" mean the `admin` or an entry in `members`. 01 calls the whole `circle.json` record the roster, so the admin is in it whether or not `members` lists them too, both for the label and for counting an owner as trusted. `Circle::is_in_roster` in `sweepky-core` applies this rule and P4's TypeScript badge must apply the same one. This file lists its admin in `members`, so it cannot catch the two disagreeing about an admin left out of `members`; P1a's Rust tests build that roster in code.

The status and owner filters belong in the trust-label function, not in its caller: each test passes the function the whole `bounties` list, including the open bounties and the bounty from an owner outside the roster.

### Who is who

| Pubky (first 8 characters) | Role | Expected label, bounties / owners |
|---|---|---|
| `ybymzxgk` A | admin, also listed in `members` | `circle`, 0 / 0 |
| `btyoe954` B | member | `circle`, 1 / 1 |
| `5ymaqd61` D | member | `circle`, 1 / 1 (2 / 2 would mean the self-credit counted) |
| `z5quft98` X | owner outside the roster | `unknown`, 0 / 0 |
| `a8fyof86` S1 | sweeper | `known`, 2 / 2 (3 / 3 would mean X's credit counted) |
| `kmjs3ec6` S2 | sweeper | `known`, 2 / 2 |
| `qwujy4ep` S3 | sweeper | `unknown`, 0 / 0 (`known`, 1 / 1 would mean X's credit counted) |
| `3rus98p3` S4 | sweeper | `known`, 2 / 1 (3 / 1 would mean the duplicate credit counted) |

### Cases covered

| Case | Where | What it checks |
|---|---|---|
| Self-credit | D's done bounty `0035JREYBXX7T` credits D and S2 | D's tally gets nothing from it; S2's does |
| Credits from two owners | S1 credited by A and B; S2 by D and A | `owners` counts distinct owners |
| One owner, two bounties | S4 credited by A on two bounties | `bounties` > `owners`, so reputation from one owner reads as `owners: 1` ([06](../docs/plan/06-verification-and-limits.md#known-limits-say-them-in-the-readme)) |
| Duplicate credit | A's done bounty `0035G87EK4XFE` names S4 twice | the tally counts bounties, not credit entries, so S4 stays at 2 / 1 |
| Open bounty with credits | A's open bounty `0035Q0RCGQAHP` credits S3 | credits on a bounty that is not `done` do not count, so S3 stays `unknown` |
| Owner outside the roster | X's done bounty `0035TR7XPGKP0` credits S3 and S1 | a done bounty from an owner who is not a roster member counts for nothing, so S3 stays `unknown` and S1 stays at 2 / 2 |
| Done bounty with no credits | D's `0035R9NS7T33M` | a done bounty with an empty `credits` list adds nothing |
| Circle members credited | B by A, D by B | a roster member is `circle` whatever its tally, and the tally is still counted |

## `discovered.json`

A `bounties/<id>.discovered.json` record as [01](../docs/plan/01-records-and-discovery.md#records-v1) defines it, with the `schemaVersion` that 01 gives every record. It has no bounty id of its own, because on a homeserver the id is in the file's path.

The file is in the form `sweepky-core` writes: keys in raw z-base32 in the sweep URLs and as the `cursors` keys, and each cursor a decimal string. So the Rust test can parse it and check that writing it back gives the same JSON. A test that needs an unknown field adds it in code, which keeps this file in that form.

- The two sweepers are S1 (`a8fyof86`) and S3 (`qwujy4ep`) from `trust-labels.json`: sweepers outside the roster, the only kind discovery adds. The sweep ids are synthetic `pubky-timestamp` values from October 2026.
- The two homeserver keys (`1nepshaq` and `iod35orp`) are random Ed25519 public keys generated for this file with the private keys discarded. Neither is a real homeserver or the testnet homeserver's key. The event ids are made up.

## `cloudflare/findings.json`

A `findings.json` in the shape that Cloudflare's `security-audit` skill writes at the pinned commit `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`: a top-level array of records, each `confirmed`, `needs_validation` or `rejected`, sorted by `fingerprint`. It keeps the file name Cloudflare's skill uses, so the Cloudflare-shaped [run directory](#run-directories) `cloudflare/` uses it as it is.

- Every record is made up. The code paths, line numbers, scopes and text describe an imagined auth module, not any real audit. The locations point at `src/auth/session.rs` and `src/auth/handler.rs` in [`target-repo.git`](#target-repogit), where each line named holds the code its record describes, at every commit. `make-target-repo.sh` checks those lines when it builds the repository; no test reads them.
- The `confirmed` record has `overall_severity` `informational`, which converts to `info`. The `needs_validation` and `rejected` records carry no severity or confidence, as Cloudflare's schema requires, so they convert with both `null`.
- The converter test turns the file into common findings, writes them to bytes, reads them back and rebuilds the array from each finding's `extra.cloudflare`; the result must equal this file's JSON value exactly. `fix` comes from `remediation.strategy` alone, so the record's `code_changes` survive only in `extra.cloudflare`.
- The file is valid against Cloudflare's own schema. After changing it, check it again: fetch `report-schema.json` and `validate-findings.cjs` from `skills/security-audit/` at the pinned commit into a scratch directory outside the repository (never commit them), then run `node <scratch>/validate-findings.cjs fixtures/cloudflare/findings.json` from the repository root. It prints `PASS: 3 findings valid`.

## Run directories

A run directory is what a sweeper's agent leaves behind for `submit` to package: `findings.json`, in Cloudflare's format or the common one, plus any other files the playbook wrote. `submit` walks it, reads each plain file, and hands the list to `SweepPackage::build` with paths relative to the directory ([01](../docs/plan/01-records-and-discovery.md#the-sweep-package)). These two are synthetic, and their findings point at [`target-repo.git`](#target-repogit).

| Directory | Format | Sweeper | Files |
|---|---|---|---|
| `cloudflare/` | Cloudflare's `security-audit` output | B (`btyoe954`), a circle member | `findings.json` (P1a's fixture, unchanged), `REPORT.md`, `coverage-ledger.json` |
| `common/` | Sweepky's common format, written by hand | C, the stranger S3 (`qwujy4ep`) | `findings.json`, `REPORT.md`, `notes/triage.md`, `capture.bin` |

The pubkys are from [`trust-labels.json`](#who-is-who), with A (`ybymzxgk`) as the bounty's owner. The directories hold no keys, manifests or sweep records: [`run_dir_round_trip.rs`](../crates/sweepky-core/tests/run_dir_round_trip.rs) builds each sweep's manifest and sweep record in code (A's bounty, target `t1` at commit M), generates the age keys at run time, and takes each directory through build, seal, open and split. It lists each directory's files itself, because it reads them with `include_bytes!` when it compiles and never at run time, so a file added here is tested only once it is added to that list too.

[`fixture_groups.rs`](../crates/sweepky-core/tests/fixture_groups.rs) groups the two directories' findings, B's converted from Cloudflare's format, with a sweep by the owner A built in code at the shared location, and checks the two cases below, the credits `done` proposes ({B, C}, never A), and that a sweep marked untrusted is attributed but kept out of the merged report. It reads only the two `findings.json` files, also with `include_bytes!`.

`sweepky-cli` reads `cloudflare/`'s three files at run time, each test naming them, so a file added here reaches those tests only once it is added to their lists: [P2b](../docs/plan/phases/P2b-cli-sweep.md)'s `submit` unit tests copy its three files into a sweep directory's `audit/`, and P2b's [end-to-end test](../crates/sweepky-cli/tests/end_to_end.rs) copies them into B's first sweep and submits it, then opens the package with A's device key and checks its findings are this `findings.json`, converted. [P2c](../docs/plan/phases/P2c-cli-pull-done.md)'s end-to-end test adds C's sweep: B is the Cloudflare-format sweep and C the common-format one ([06](../docs/plan/06-verification-and-limits.md#verification)). P2c's triage tests read only the two `findings.json` files, with `include_bytes!` as `fixture_groups.rs` does: they store B's, converted, and C's as `pull` stores them, with A's circle of A and B, and check that `groups.json` groups the shared location with `reportedBy` [B, C] and keeps the shared-id pair apart, and that `merged.json` holds B's findings and nothing of C's.

### The shared location

Each directory has a finding whose sink is `src/auth/session.rs` line 88, scope `fn is_expired`: the off-by-one in the expiry check. Cloudflare's record calls it `auth-expiry-inclusive` and the common one `session-expiry-off-by-one`. Ids are local to a sweep, so the owner's grouping goes by the sink's file and scope, and the two belong in one group reported by B and C.

### The shared-id pair

Each directory also has a finding with the id `auth-token-compare-timing`, at unrelated sinks. Cloudflare's is the token comparison at `src/auth/session.rs` line 120, scope `fn validate`; the common one is the header-name lookup at `src/http.rs` line 12, scope `fn header`. Equal ids are only a second hint, so these stay in two groups. Each common finding has its sink as its only location, so no entrypoint or evidence line of its own can tie it to another group.

### The non-text file

`common/capture.bin` is 16 bytes: `0xFF`, then the ASCII text `SWEEPKY FIXTURE`. `0xFF` never occurs in UTF-8, so `build` reports the file as `NotText` and leaves it out, and the test checks that it never comes back out of the split. The repository's [`.gitattributes`](../.gitattributes) marks it `binary`, so git never converts its bytes.

### What the content keeps to

- Every finding, text and line is made up. The common fixture's two lines exist at every commit of `target-repo.git` (R, A, B, T1, F1, F2 and M): line 88 of `src/auth/session.rs` is in `fn is_expired`, and line 12 of `src/http.rs`, the signature of `fn header`. `make-target-repo.sh` checks only the lines `cloudflare/findings.json` names, not these, and the repository is not regenerated to add them, since that would change its pack bytes. Check them by hand with `git --git-dir=fixtures/target-repo.git show <sha>:src/http.rs`.
- `common/findings.json` is a static review, so both findings are `needs_validation` with `severity` and `confidence` `null`. Its `playbook` is the plain string `careful-review`. Each finding has a `fix` string: the common format leaves out a `fix` that is absent, so a `null` there would not come back from the split as written, and the test compares the split `findings.json` with this file as JSON values.
- `cloudflare/coverage-ledger.json` is a `quick` run scoped to `src/auth/`: three units with candidates (one per fingerprint in `cloudflare/findings.json`) and `src/http.rs` as `out_of_scope`. It is valid against Cloudflare's own ledger validator. After changing it, check it again the way `cloudflare/findings.json` is checked: fetch `validate-coverage-ledger.cjs` from `skills/security-audit/` at the pinned commit into a scratch directory outside the repository, then run `node <scratch>/validate-coverage-ledger.cjs fixtures/cloudflare/coverage-ledger.json` from the repository root. It prints `PASS: 4 coverage units valid`.
- The attachments are compared byte for byte after the split, and the split `findings.json` of `cloudflare/` must give back `cloudflare/findings.json` through `to_cloudflare`, value for value.

## `target-repo.git`

A tiny bare git repository for the CLI's target tests. [P2b](../docs/plan/phases/P2b-cli-sweep.md)'s fixture `TargetResolver` maps a synthetic repository name (one under `example.invalid`, say) onto this directory, so `post` pins targets in it and `run` fetches them from it without reaching a real host, and [P3](../docs/plan/phases/P3-skill-and-sandbox.md)'s checks find its planted agent files gone from a sweep's `target/`. [`make-target-repo.sh`](make-target-repo.sh) builds it, and [`fixture_target_repo.rs`](../crates/sweepky-cli/tests/fixture_target_repo.rs) checks it: the files before any git command runs, then every SHA in the tables below.

### History

```
              T1 -------------.       refs/heads/topic
             /                 \
  R ------- A ------- B ------- M     refs/heads/main (HEAD)
            |          \
         v0.1.0         F1 --- F2     refs/pull/1/head
```

Time runs left to right, from 3 to 10 August 2026. The test reads the SHAs from the two tables below, so keep each row's name in the first column and its SHA, in backticks, in the second.

| Commit | SHA | Parents | What it does |
|---|---|---|---|
| R | `6c2b4dd0e54b483491a4b5645d3fb8c1c882e636` | none | The root commit: `README.md`, `src/lib.rs`, `src/http.rs`, `src/auth/session.rs` and `src/auth/handler.rs`, plus the [planted agent files](#planted-agent-files) |
| A | `6a0e0f6f873af85d97788783fde43f3e3fa83133` | R | Shortens `SESSION_TTL_SECS` in `session.rs` |
| T1 | `cd9e1316947d82e69f10a084f48ef0e106d283bb` | A | On `topic`: adds a Sessions section to `README.md` |
| B | `e41e2e2980af48ae99674cfcc95960969a7e55df` | A | On `main`: moves `LOGIN_PATH` in `handler.rs` to `/sign-in` |
| F1 | `930ab9117f15602f7b212d86ad5f16423f96a051` | B | In the PR: adds `revoke` at the end of `session.rs` |
| F2 | `3a894646ffcff78074b2a9a58c4d035a4d3cb1d2` | F1 | In the PR: adds `handle_logout` at the end of `handler.rs` |
| M | `791991b2e79a7fe8371635dc377b9cc620032465` | B, T1 | Merges `topic` into `main` with `--no-ff` |

| Tag | SHA | Points at | What it is |
|---|---|---|---|
| `v0.1.0` | `34cbfe12b3494be656721c9841b2789f887c9035` | A | An annotated tag object, so a resolver has to peel it (`v0.1.0^{commit}`) to reach A |

| Ref | Points at |
|---|---|
| `HEAD` | `refs/heads/main`, as a symbolic ref |
| `refs/heads/main` | M |
| `refs/heads/topic` | T1 |
| `refs/tags/v0.1.0` | the tag object `v0.1.0`, which peels to A |
| `refs/pull/1/head` | F2, with no branch: the ref a repository host keeps for pull request 1's head |

### What each target kind gets

- **`pr`:** pull request 1 has `base` M (main's tip), `head` F2 and `mergeBase` B. The three-dot diff `main...refs/pull/1/head` runs from B to F2 and holds only F1's and F2's additions. The two-dot `git diff M F2` also takes out T1's README section, which reached `main` after the PR branched, so the two differ: the case for [01](../docs/plan/01-records-and-discovery.md#target-kinds-and-how-a-sweep-is-scoped)'s three-dot rule. F2's depth-2 history is F2 and F1, without B, so `run` has to fetch `mergeBase` by its SHA as well as `head`.
- **`commit`:** R is a root commit (`git diff-tree -p --root R`), A and B are ordinary commits, and M is a merge commit, for which `diff-tree -p --root` prints nothing and `git diff-tree -p M^1 M` shows T1's change against the first parent.
- **`repo`:** any commit, narrowed to `src/auth/` or left whole.
- **What `run` fetches:** each target by its exact SHA at depth 2, a pull request's head and merge base together, so a copy holds the commit and one generation of parents. [`run/fetch.rs`](../crates/sweepky-cli/src/run/fetch.rs)'s tests check what git leaves: `.git/shallow` lists B and T1 after M's fetch, and F1 and A after pull request 1's (F2 and B); R's fetch holds its whole history, R alone, so git writes no `.git/shallow`; and R is never in M's copy.

### Planted agent files

The root commit holds `CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md`, `.claude/settings.json`, `.mcp.json` and a nested `src/auth/CLAUDE.md`: the files [02](../docs/plan/02-encryption-and-safety.md#sweeper-safety) says would load as instructions, which `run` must strip from a target copy. Each says in its own text that it is a fixture `run` must strip, and none gives an instruction. The two JSON files set nothing: `.claude/settings.json` has no permissions, hooks or environment, and `.mcp.json` declares no MCP server. No later commit removes them, so every commit has them. [`run/fetch.rs`](../crates/sweepky-cli/src/run/fetch.rs)'s tests check that every one is gone from each target `run` fetches and listed in that target's `stripped` in `scope.json`.

### Synthetic and inert

- Every commit and the tag are by `Sweepky Fixture <fixture@example.invalid>`, at fixed times in August 2026 (UTC), and unsigned. The script runs git with no system or user config, so no real name, email or signing key reaches the objects.
- The code is made up and never built or run. The lines `cloudflare/findings.json` points at hold the code its records describe at every commit, and the script checks them. The two lines `common/findings.json` points at exist at every commit too, but the script does not check them ([Run directories](#run-directories)).
- Nothing in the directory runs. There is no `hooks/`, and `config` is exactly `repositoryformatversion = 0`, `filemode = true` and `bare = true` under `[core]`: a repository's own config can name programs for git to run, and every test that fetches from it would run them. macOS's `git init` adds `ignorecase` and `precomposeunicode`, which the script removes.
- The refs are loose files, not `packed-refs`: git accepts a directory as a repository only when `refs/` exists, and git cannot commit an empty directory.
- The repository's [`.gitattributes`](../.gitattributes) marks everything under `target-repo.git/` as `binary`, so git never converts its line endings.

### Regenerating

Run `fixtures/make-target-repo.sh`, from any directory, with git 2.45 or later. It builds the repository in a temporary directory, checks it (the file list, the config, the lines `cloudflare/findings.json` names, and `git fsck --strict`), and only then replaces `target-repo.git/` and prints the SHAs.

The commit and tag SHAs come out the same on every run, because the script fixes every name, email, date, message and file. The pack's name and bytes depend on the git version that compressed it, so regenerate only after changing what the script writes. Then copy the printed SHAs into the tables above, stage the new `.pack` and `.idx` by name, remove the old pair with `git rm`, and run `cargo nextest run -p sweepky-cli`.

## `cctv-age`

The age test vectors from C2SP's [CCTV](https://github.com/C2SP/CCTV) (Community Cryptography Test Vectors): every file of `age/testdata` at commit `50a8ecf2a220f4c8bdc4f085789b8e85c26829e7`, the `main` commit of 25 September 2026, copied byte for byte. That is 147 files, about 160 KB. [`crates/sweepky-core/tests/cctv_age.rs`](../crates/sweepky-core/tests/cctv_age.rs) reads them at run time. It is the one sweepky-core test that reads files; the library itself reads none.

- **Licence.** CCTV's `age/README.md` offers the vectors under the Zero-Clause BSD licence (0BSD), CC0 1.0 or the Unlicense, at the user's choice. None of the three asks for attribution or a copy of its text, so nothing else is vendored with them.
- **Format.** Each file is a few `key: value` lines, an empty line, then an age file, zlib-compressed when the file says `compressed: zlib`. CCTV's `age/README.md` at the pinned commit defines the eight keys and the expected results. CCTV says to ignore a file with any other key; the test fails on one instead, so a re-vendored set cannot drop vectors quietly.
- **Not secrets.** The `identity:` lines hold `AGE-SECRET-KEY-1…` and `AGE-SECRET-KEY-PQ-1…` strings. They are CCTV's published test keys and protect nothing, but a secret scanner (gitleaks, GitHub push protection) may still flag them. These files are the one place the repository commits an age secret key: Sweepky's own source and tests generate their keys at run time ([P1b](../docs/plan/phases/P1b-core-crypto.md#notes)).
- **Byte for byte.** The repository's [`.gitattributes`](../.gitattributes) marks everything under `cctv-age/` as `binary`. Some vectors (`header_crlf`, `armor_crlf`) hold CRLF line endings on purpose and every age file is binary, so git must never convert their line endings.

### What the test does with them

Every vector lands in exactly one group, and the test asserts each group's exact size, so no vector is skipped without the test failing:

| Group | How many | Which | What the test checks |
|---|---|---|---|
| Hybrid | 19 | an `AGE-SECRET-KEY-PQ-` identity: the 18 `hybrid*` files and `armor_hybrid` | Skipped: age 0.12.1 has no hybrid post-quantum identity |
| Armored | 36 | `armored: yes`, not hybrid | `decrypt` refuses each at the header, with the vector's X25519 identity or, for `armor_empty` and `armor_scrypt`, a generated one: `InvalidHeader`, or `HeaderTooLarge` for `armor_garbage_encoded`, which inflates past the 8 KiB header cap. Sweep packages are binary and age's `armor` feature is not compiled in. CCTV allows ignoring these; checking the refusal is stricter |
| Scrypt | 24 | a passphrase and no identity | age's own `age::scrypt::Identity` with a maximum work factor of 16, so `scrypt_work_factor_23` is a header failure |
| X25519 | 68 | the rest | `decrypt`, with the identity read by `DeviceIdentity::from_secret` (a generated one for `empty`, which has none) |

In the scrypt and X25519 groups each `expect` value allows exactly one result: `success` is `Ok` with the plaintext's SHA-256 equal to `payload`; `no match`, `header failure`, `HMAC failure` and `payload failure` are `NoMatchingKey`, `InvalidHeader`, `InvalidMac` and `InvalidPayload`. `HeaderTooLarge` fails the test, since no header-failure vector is longer than 1,674 bytes. Compressed vectors are inflated with a 32 MiB limit; the largest inflates to 16,847,065 bytes.

Two vectors are lenient. `stanza_missing_body` and `stanza_missing_final_line` expect a header failure, but age 0.12.1 still accepts stanzas in that older form and decrypts them, the same exception age's own CCTV test makes. The test allowlists exactly those two and asserts that they still decrypt, so it fails if a later age starts refusing them.

Last, every vector, hybrid ones included, goes through `decrypt` once more with a key it was not written to. Each must be refused at the header, and none may panic.

### Re-vendoring

Run `fixtures/fetch-cctv-age.sh` from any directory, with `curl` and `tar`. It downloads `https://codeload.github.com/C2SP/CCTV/tar.gz/<commit>` into a new temporary directory, extracts only `age/testdata`, checks that it holds exactly 147 plain files with plain names, and only then replaces `cctv-age/`. It runs nothing from the download, and no test runs it, so the tests stay offline. Run again at the same commit, it leaves `git status` clean.

To move the pin, change `commit` and `expected_files` in the script and run it, then review `git status fixtures/cctv-age`. Update the commit here and in the test's module docs, and the group counts and the lenient-vector list in the test, until `cargo nextest run -p sweepky-core` passes.
