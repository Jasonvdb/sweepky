# P3 — Skill and sweeper sandbox

## Goal

The `/sweepky` skill an agent follows, and the sandboxed project a sweep runs in. The agent only audits; `sweepky run` and `sweepky submit` are terminal commands around it.

## Build

- `skills/sweepky/SKILL.md` with `disable-model-invocation: true`: roles `run` (default), `post`, `pull`, `done`. In `run` it reads `./sweeps/<id>/scope.json` and the brief, follows the suggested playbook if installed in the project, else the sweeper's configured one, else a careful review guided by the brief, and records which. It phrases the Cloudflare request explicitly (full audit mode with report artifacts, absolute target path under `sweeps/<id>/target/`, the scope in words, the profile, the new output directory `sweeps/<id>/audit/`, "no prior runs; do not read other `sweeps/` directories"). It carries the common findings schema, including that `severity` and `confidence` are null unless established. It tells the agent it has no network, must not run `sweepky`, and that the trust rule for untrusted sweeps is attribution yes, merge no. In `done`, it shows the proposed credits with each sweeper's finding groups and leaves the decision to the human.
- `sweepky init <dir>`, on top of the minimal half that [P2a](P2a-cli-identity.md) built (the directory, the `.sweepky` marker and a `.gitignore` with `sweeps/`): writes the `.claude/settings.json` from [02](../02-encryption-and-safety.md#sweeper-safety) with the absolute `claudeMdExcludes` path filled in, a `CLAUDE.md` for the project (what the agent will find, where to write, what not to do), copies the skill into `.claude/skills/sweepky/`, and, when the sweeper agrees, installs the Cloudflare playbook project-local with the pinned `npx skills@1.7.2 add …#<full sha> --copy` line from [03](../03-cli-and-skill.md#the-sweepky-skill) and records the commit for `submit`. Prints the launch line `claude --setting-sources project,local` and the Node-outside-`$HOME` requirement.

## Done when

- In an `init` project launched with `claude --setting-sources project,local`, in manual mode and in auto mode: a Bash `curl` to the internet fails; `cat ~/.config/sweepky/*` fails; `cat ./sweeps/<id>/scope.json` works; a `CLAUDE.md`, an `AGENTS.md` and a `.claude/settings.json` planted in a fixture target are gone from `sweeps/<id>/target/` after `run` and listed in `scope.json`; the project-local playbook files are readable from a sandboxed command.
- `sweepky submit` run from a terminal afterwards succeeds on the fixture sweep and refuses one with a planted symlink.
- Skill text reviewed against the Cloudflare `SKILL.md` fetched at the pinned commit (not any install on the machine), lines 12–17 (modes), 51 (output dir) and 107–117 (profiles and scoped runs).

## Notes

- The skill is referenced, not vendored. If it is ever vendored, keep the MIT notice.
- The sandbox covers Bash, PowerShell and Monitor; `blockReadsOutsideWorkingDirectories` covers the file tools. MCP and Artifact are denied by rule. User-level hooks and MCP servers stay out through `--setting-sources`.
- The template's deny rules apply in every permission mode, including bypass; the sandbox's own network behaviour does not, which is why the network deny is a permission rule. Never run a sweep in bypass mode anyway.
