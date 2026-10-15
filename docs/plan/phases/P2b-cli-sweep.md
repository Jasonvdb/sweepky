# P2b — `sweepky-cli`: post, run and submit

## Goal

`post` for closed bounties, `run` and `submit`, so a circle member can sweep a closed bounty end to end on the testnet. It builds on [P2a](P2a-cli-identity.md) for the network config, the `--identity` login, the circle, the writers' lock, the config directories, the minimal `init` with its marker, and the testnet test; on [P1a](P1a-core-records.md) for targets, the Cloudflare converter and the bare fixture repo; and on [P1b](P1b-core-crypto.md) for the package envelope, padding and encryption. `post --open`, `pull` and `done` follow in [P2c](P2c-cli-pull-done.md).

## Build

- **`post` (without `--open`):** pins SHAs through a `TargetResolver` trait: the real one runs `git -c credential.helper= -c core.askPass= ls-remote` with `GIT_TERMINAL_PROMPT=0` (peeling annotated tags, storing full SHAs) and GitHub's unauthenticated REST API for PR head, base and merge base; the fixture one serves a bare repo under `fixtures/`. Refuses repos that are not anonymously readable. `title` and `brief` are shown for confirmation.
- **`run [<bounty-url>] [--target <tid>]`:** must be run inside an `init` project; picks or checks the bounty (circle or `open`); writes `running`; fetches each target into `./sweeps/<id>/target/<tid>/` by exact SHA (https only, depth 2, no submodules, no LFS, credential helpers disabled; PR heads from the base repo's `refs/pull/<n>/head`); removes `CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md`, `.claude/` and `.mcp.json` from the copy and lists them in `scope.json`; writes `scope.json`, the brief and `.sweepky/sweep.json` (sweep URL, bounty URL, target ids, playbook id from `init`); aborts if the SHA is not served.
- **`submit [--run-dir] [--playbook]`:** canonicalise; require a direct child of `<init dir>/sweeps/` with the marker; walk with `symlink_metadata`, accept regular files with one link only, skip `agents/*/scratch/` and `target/`, cap per-file and total size, print the list; detect Cloudflare output in `audit/` and convert; read the bounty, list the owner's unrevoked `keys/`, compare with the pinned set and warn on new keys (ask, or fail with `--no-input`); refuse an owner with no keys; pad, encrypt to those plus this install's key, upload `.age`, flip to `done` (or `aborted` on failure), handling 413, 429 and 507 with clear messages.

## Done when

- The testnet test from [P2a](P2a-cli-identity.md) continues, with targets from the fixture repo: A, the owner, creates a circle with B in it and posts a closed bounty; B, a circle member, runs it inside a minimal `init` project and submits a Cloudflare-format sweep.
- `submit` refuses a run directory holding a planted symlink and a hard link to `~/.config/sweepky/*`, as in [06](../06-verification-and-limits.md#verification).
- B's first `submit` pins A's key set, and a key the test then adds under A's `keys/` makes B's next `submit` warn.
- Two `submit`s by B, of two separate runs, run concurrently and both succeed, each taking the writers' lock in turn.
- `cargo clippy -- -D warnings`, `cargo deny check` and `cargo nextest run` clean.

## Notes

- The per-sweep marker `sweeps/<id>/.sweepky/sweep.json` that `run` writes is separate from the project's `.sweepky` marker that the minimal `init` writes.
- Until [P3](P3-skill-and-sandbox.md)'s `init` records a playbook, the playbook comes from `submit --playbook`.
- Under `--identity` each command signs in afresh ([03](../03-cli-and-skill.md#two-ways-to-log-in), "Session per command"), so the two concurrent `submit`s hold separate sessions. This check shows only that the lock lets both finish; the lock unit test in [P2a](P2a-cli-identity.md) shows that it serialises them. The case the lock exists for, two commands sharing one bearer, needs a restored Ring token, so [P2d](P2d-cli-ring-login.md#done-when) checks it. That is why this check rewords the former P2 item "Two `submit`s run concurrently under one grant both succeed (the lock serialises them)".
