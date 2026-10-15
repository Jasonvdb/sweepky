# The `/sweepky` skill

Nothing lives here yet except this README. [P3](../../docs/plan/phases/P3-skill-and-sandbox.md) adds two things:

- `SKILL.md`, the `/sweepky` agent skill, with four roles: `run` (the default), `post`, `pull` and `done`. See [03](../../docs/plan/03-cli-and-skill.md#the-sweepky-skill).
- The sandbox template that becomes a sweeper project's `.claude/settings.json`. It keeps the agent off the network and away from the CLI's secrets. See [02](../../docs/plan/02-encryption-and-safety.md#sweeper-safety).

`sweepky init <dir>` copies both into a sweeper project: the skill into `.claude/skills/sweepky/`, and the template into `.claude/settings.json` with the project's absolute `claudeMdExcludes` path filled in. Before P3, [P2a](../../docs/plan/phases/P2a-cli-identity.md) builds a minimal `init` that writes only the `.sweepky` marker and a `.gitignore` containing `sweeps/`.

The Cloudflare `security-audit` playbook is referenced, not vendored here. `init` offers to install it into the project at the pinned commit.
