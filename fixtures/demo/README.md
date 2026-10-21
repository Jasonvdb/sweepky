# Demo fixtures

The synthetic inputs of [P5](../../docs/plan/phases/P5-local-demo.md)'s local demo. `scripts/demo-local.sh` and its headless check fall back to them when `SWEEPKY_DEMO_RUN_DIR` and `SWEEPKY_DEMO_TARGETS` are unset, and say so when they do. A real run directory named by `SWEEPKY_DEMO_RUN_DIR` is read from that path only and never copied here.

**Every finding here is made up.** No audit or review was run. Each title starts with `Made-up demo finding`, and each `REPORT.md` says so in its first paragraph. The findings point at lines of Sweepky's own plan documents and describe wording, not code, so none reads as a vulnerability. The directories hold no keys, pubkys, manifests or sweep records.

| File | What it is | Demo step |
|---|---|---|
| [`targets.json`](targets.json) | The value of `SWEEPKY_DEMO_TARGETS`: a JSON array of one `repo` target, `github.com/Jasonvdb/sweepky` at commit `be535e6c056b864f2f93dc64218dd418c3fc5856`, narrowed to `docs/plan/` | 4, the bounty `post` publishes |
| [`sweeper-run/`](sweeper-run) | The stand-in for `SWEEPKY_DEMO_RUN_DIR`: `findings.json` in Cloudflare's `security-audit` format (three `needs_validation` records, sorted by fingerprint) and a `REPORT.md` laid out as Cloudflare's skill lays it out | 5, copied into the circle sweeper's `audit/` and submitted with `--playbook cloudflare/security-audit@c1c8a8c1471069fb0e188eeaff69b8e8db6564a8` |
| [`stranger-audit/`](stranger-audit) | The stranger's `audit/`: `findings.json` in Sweepky's common format with one finding, and a `REPORT.md` | 6, copied into the stranger's `audit/` and submitted with `--playbook careful-review` |

## The target

The target is this public repository at a full SHA, never a branch name, so the commit `post` pins is the one the findings were written against, and the links `pull --findings` prints (`https://github.com/Jasonvdb/sweepky/blob/<sha>/<file>#L<line>`) never move. `post` fetches the target for real, so the fallback needs GitHub to be reachable.

## The shared location

The sweeper's `docs-decisions-reading-key-installs` and the stranger's `overview-owner-installs-unclear` both have their sink at `docs/plan/00-overview.md` line 16, scope `Decisions (locked)`. The ids differ, so the owner's `pull` groups them by file and scope: one group with both sweepers in `reportedBy`. The sweeper's other two findings are in other files and are a group each. Every scope is the name of the section heading the line is under.

| Id | File | Line | Scope |
|---|---|---|---|
| `docs-decisions-reading-key-installs` (sweeper) | `docs/plan/00-overview.md` | 16 | `Decisions (locked)` |
| `docs-device-keys-logout-order` (sweeper) | `docs/plan/02-encryption-and-safety.md` | 68 | `Device keys` |
| `docs-known-limits-recipient-count` (sweeper) | `docs/plan/06-verification-and-limits.md` | 20 | `Known limits (say them in the README)` |
| `overview-owner-installs-unclear` (stranger) | `docs/plan/00-overview.md` | 16 | `Decisions (locked)` |

## Checks

[`fixture_groups.rs`](../../crates/sweepky-core/tests/fixture_groups.rs) (its `demo` module, in `sweepky-core`) reads the five files with `include_bytes!` and `include_str!` and checks that `targets.json` is one `repo` target at the pinned SHA with the field names `post`'s draft takes; that both `findings.json` files parse, the sweeper's as Cloudflare's format; that every location is a line of a file under `docs/plan/`; that every title and both reports carry the notice; that grouping gives the one shared group and two others; and that the merged report, with the stranger untrusted, is the sweeper's three findings.

Two checks are by hand, after changing these files:

- **The lines exist at the pinned commit.** On 2026-10-21, `git show be535e6c056b864f2f93dc64218dd418c3fc5856:<file> | wc -l` gave 56 lines for `docs/plan/00-overview.md`, 105 for `docs/plan/02-encryption-and-safety.md` and 84 for `docs/plan/06-verification-and-limits.md`, and `git show be535e6c056b864f2f93dc64218dd418c3fc5856:<file> | sed -n <line>p` showed that each line in the table above is the bullet its finding describes, under the heading its scope names.
- **The sweeper's `findings.json` is valid against Cloudflare's own schema.** Check it as [`cloudflare/findings.json`](../README.md#cloudflarefindingsjson) is checked: fetch `report-schema.json` and `validate-findings.cjs` from `skills/security-audit/` of `cloudflare/security-audit-skill` at commit `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8` into a scratch directory outside the repository (never commit them), then run `node <scratch>/validate-findings.cjs fixtures/demo/sweeper-run/findings.json` from the repository root. On 2026-10-21 it printed `PASS: 3 findings valid`.
