# The `/sweepky` skill

[P3](../../docs/plan/phases/P3-skill-and-sandbox.md) adds two things here:

- `SKILL.md`, the `/sweepky` agent skill, with four roles: `run` (the default), `post`, `pull` and `done`. See [03](../../docs/plan/03-cli-and-skill.md#the-sweepky-skill). `run` is for a sweeper's `init` project; `post`, `pull` and `done` are for the owner's ordinary session, because an `init` project has no network and cannot read the data directory `pull` writes. `crates/sweepky-cli/tests/skill_text.rs` checks the rules the text must carry. Write it one paragraph or list item per line, so the test's phrases never break across lines.
- `settings.json`, the sandbox template that becomes a sweeper project's `.claude/settings.json`. It keeps the agent off the network and away from the CLI's secrets. It must stay the JSON in [02](../../docs/plan/02-encryption-and-safety.md#sweeper-safety), placeholder included; a test compares the two.
- `project-CLAUDE.md`, the project's `CLAUDE.md`: what the agent finds, where it writes and what it must not do.

`sweepky init <dir>` builds all three into the binary with `include_str!` and writes them into a sweeper project: the skill to `.claude/skills/sweepky/SKILL.md` byte for byte, `project-CLAUDE.md` to `CLAUDE.md`, and the template to `.claude/settings.json` with `claudeMdExcludes` set to the project's canonical path followed by `/sweeps/**/target/**`. Before P3, [P2a](../../docs/plan/phases/P2a-cli-identity.md) built a minimal `init` that writes only the `.sweepky` marker and a `.gitignore` containing `sweeps/`.

The Cloudflare `security-audit` playbook is referenced, not vendored here. `init` offers to install it into the project at the pinned commit.
