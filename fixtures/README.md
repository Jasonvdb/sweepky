# Fixtures

Synthetic test data for the Rust tests in `crates/` and the TypeScript tests in `web/`. The table below lists every file here and the tests that load it. [P1b](../docs/plan/phases/P1b-core-crypto.md) adds the synthetic run directories.

Nothing real lands here. Every pubky, id, finding and commit is made up for the test that uses it. The local demo's audit report is read from a path in an environment variable and is never committed ([P5](../docs/plan/phases/P5-local-demo.md#inputs-environment-never-committed)).

| File | What it is | Loaded by |
|---|---|---|
| [`trust-labels.json`](trust-labels.json) | A roster, bounties with credits, and the trust label and credit tally every pubky in it should get | P1a's trust-label test (Rust), P4's trust-badge test (TypeScript) |
| [`discovered.json`](discovered.json) | An open bounty's discovered-sweeps file: two strangers' sweeps and the feed cursors of two homeservers | P1a's `Discovered` round-trip test (Rust) |
| [`cloudflare/findings.json`](cloudflare/findings.json) | A `findings.json` in the shape Cloudflare's `security-audit` skill writes: a `confirmed`, a `needs_validation` and a `rejected` record, sorted by fingerprint | P1a's Cloudflare converter tests (Rust) |
| [`target-repo.git/`](target-repo.git) | A tiny bare git repository (`HEAD`, `config`, four loose refs and one pack): a root commit with planted agent files, a normal commit with an annotated tag, a merge commit on `main`, and a PR head whose merge base is not the base tip | P1a's fixture check (Rust); P2b's fixture `TargetResolver` and the target tests of P2b and P3 |
| [`make-target-repo.sh`](make-target-repo.sh) | The script that regenerates `target-repo.git/` | Run by hand ([Regenerating](#regenerating)) |

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

- `roster` is a full `circle.json` record as [01](../docs/plan/01-records-and-discovery.md#records-v1) defines it. The admin is also listed in `members`.
- A `bounties` entry, `{id, owner, status, credits}`, is a reduced test shape, not the bounty record from [01](../docs/plan/01-records-and-discovery.md#the-bounty-post). The real record has no `owner` or `id` field, because both come from its path (`pubky://<owner>/pub/sweepky/bounties/<id>.json`). This file inlines them so one file holds the whole case. `credits` is always present and can be empty.
- `expected` has exactly one entry per pubky in the file, circle members included.

Pubkys are random Ed25519 public keys in raw z-base32, generated for this file with the private keys discarded. None is a real identity or the testnet homeserver's key. Ids are synthetic `pubky-timestamp` values from August to October 2026.

### The rule

The rule comes from [01](../docs/plan/01-records-and-discovery.md#records-v1), plus the owner count that [00](../docs/plan/00-overview.md#trust-model-the-circle-is-a-default-not-the-protocol) adds to the `known` label. Only credits from trusted owners count, and in v1 the trusted owners are the roster's members. For each pubky:

- `bounties` is the number of `done` bounties whose owner is a roster member and whose `credits` name the pubky. A credit that names the bounty's own owner counts for nothing.
- `owners` is the number of distinct owners among those bounties.
- `label` is `circle` if the pubky is in the roster, else `known` if `bounties` > 0, else `unknown`.

"In the roster" and "roster member" mean listed in `members`: `admin` alone does not make a pubky a member, for the label or for counting an owner as trusted. `Circle::is_member` in `sweepky-core` applies this rule and P4's TypeScript badge must apply the same one; this file lists its admin in `members`, so it cannot catch the two disagreeing.

The status and owner filters belong in the trust-label function, not in its caller: each test passes the function the whole `bounties` list, including the open bounties and the bounty from an owner outside the roster.

### Who is who

| Pubky (first 8 characters) | Role | Expected label, bounties / owners |
|---|---|---|
| `ybymzxgk` A | admin, also a member | `circle`, 0 / 0 |
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

A `findings.json` in the shape that Cloudflare's `security-audit` skill writes at the pinned commit `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`: a top-level array of records, each `confirmed`, `needs_validation` or `rejected`, sorted by `fingerprint`. It keeps the file name Cloudflare's skill uses, so a Cloudflare-shaped run directory can reuse it as it is.

- Every record is made up. The code paths, line numbers, scopes and text describe an imagined auth module, not any real audit. The locations point at `src/auth/session.rs` and `src/auth/handler.rs` in [`target-repo.git`](#target-repogit), where each line named holds the code its record describes, at every commit. `make-target-repo.sh` checks those lines when it builds the repository; no test reads them.
- The `confirmed` record has `overall_severity` `informational`, which converts to `info`. The `needs_validation` and `rejected` records carry no severity or confidence, as Cloudflare's schema requires, so they convert with both `null`.
- The converter test turns the file into common findings, writes them to bytes, reads them back and rebuilds the array from each finding's `extra.cloudflare`; the result must equal this file's JSON value exactly. `fix` comes from `remediation.strategy` alone, so the record's `code_changes` survive only in `extra.cloudflare`.
- The file is valid against Cloudflare's own schema. After changing it, check it again: fetch `report-schema.json` and `validate-findings.cjs` from `skills/security-audit/` at the pinned commit into a scratch directory outside the repository (never commit them), then run `node <scratch>/validate-findings.cjs fixtures/cloudflare/findings.json` from the repository root. It prints `PASS: 3 findings valid`.

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

### Planted agent files

The root commit holds `CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md`, `.claude/settings.json`, `.mcp.json` and a nested `src/auth/CLAUDE.md`: the files [02](../docs/plan/02-encryption-and-safety.md#sweeper-safety) says would load as instructions, which `run` must strip from a target copy. Each says in its own text that it is a fixture `run` must strip, and none gives an instruction. The two JSON files set nothing: `.claude/settings.json` has no permissions, hooks or environment, and `.mcp.json` declares no MCP server. No later commit removes them, so every commit has them.

### Synthetic and inert

- Every commit and the tag are by `Sweepky Fixture <fixture@example.invalid>`, at fixed times in August 2026 (UTC), and unsigned. The script runs git with no system or user config, so no real name, email or signing key reaches the objects.
- The code is made up and never built or run. The lines `cloudflare/findings.json` points at hold the code its records describe at every commit, and the script checks them.
- Nothing in the directory runs. There is no `hooks/`, and `config` is exactly `repositoryformatversion = 0`, `filemode = true` and `bare = true` under `[core]`: a repository's own config can name programs for git to run, and every test that fetches from it would run them. macOS's `git init` adds `ignorecase` and `precomposeunicode`, which the script removes.
- The refs are loose files, not `packed-refs`: git accepts a directory as a repository only when `refs/` exists, and git cannot commit an empty directory.
- The repository's [`.gitattributes`](../.gitattributes) marks everything under `target-repo.git/` as `binary`, so git never converts its line endings.

### Regenerating

Run `fixtures/make-target-repo.sh`, from any directory, with git 2.45 or later. It builds the repository in a temporary directory, checks it (the file list, the config, the lines `cloudflare/findings.json` names, and `git fsck --strict`), and only then replaces `target-repo.git/` and prints the SHAs.

The commit and tag SHAs come out the same on every run, because the script fixes every name, email, date, message and file. The pack's name and bytes depend on the git version that compressed it, so regenerate only after changing what the script writes. Then copy the printed SHAs into the tables above, stage the new `.pack` and `.idx` by name, remove the old pair with `git rm`, and run `cargo nextest run -p sweepky-cli`.
