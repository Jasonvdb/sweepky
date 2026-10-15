# P3 — Skill and sweeper sandbox

## Goal

The `/sweepky` skill an agent follows, and the sandboxed project a sweep runs in.

## Build

- `skill/sweepky/SKILL.md`: roles `run` (default), `post`, `pull`, `done`. Playbook-agnostic: reads the bounty's `brief`, `focus` and suggested playbook; follows the suggestion if installed, else the sweeper's configured playbook, else a careful review guided by the brief; records which was used. Carries the common findings schema. References `cloudflare/security-audit-skill` at `c1c8a8c` as the default suggestion for `security` bounties, with its install line; per-kind scoping via `scope.json`; output dir `./sweeps/<id>/`; the trust rule for untrusted sweeps. In `done`, shows the proposed credits with what each sweeper contributed and leaves the decision to the human.
- `sweepky init <dir>`: writes `.claude/settings.json` (sandbox enabled, `failIfUnavailable: true`, `allowUnsandboxedCommands: false`, `network.allowedDomains: []`, `filesystem.denyRead: ["~/"]`, `allowRead: ["."]`, `permissions.blockReadsOutsideWorkingDirectories`, `WebFetch`/`WebSearch` denied, `sandbox.excludedCommands: ["sweepky"]`), a `CLAUDE.md` for the project, and a `.gitignore` that excludes `sweeps/`.

## Done when

- In an `init` project: a Bash `curl` to the internet fails; reading `~/.config/sweepky/` fails; `sweepky --version` runs.
- The observed behaviour of `sandbox.excludedCommands` is documented in the skill (does `sweepky submit` reach the network from inside the agent, or must the human run it afterwards?).
- Skill text reviewed against the Cloudflare `SKILL.md` lines 49–52 (output dir) and 111–116 (profiles and scoped runs).

## Notes

- The skill is referenced, not vendored. If it is ever vendored, keep the MIT notice.
- Only Bash is sandboxed; say so in the skill so the agent does not read outside the project with file tools.
