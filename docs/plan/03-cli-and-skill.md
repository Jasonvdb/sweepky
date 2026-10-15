# 03 — CLI, skill and Rust conventions

## Repo layout

```
sweepky/
  Cargo.toml              workspace
  crates/sweepky-core/    records, paths, ids, target pinning, trust labels, feed parser,
                          age wrap/unwrap, pack/unpack, manifest — no network or file I/O
  crates/sweepky-cli/     the `sweepky` binary (clap, tokio)
  skill/sweepky/          SKILL.md + the .claude/settings.json sandbox template
  web/                    the board (Vite + React + TS, read-only)
  fixtures/               synthetic records and run directories for tests
  vibe/                   vibe.json + cover for the pubky/vibes PR (post-approval)
  docs/plan/              these docs
```

## The `sweepky` CLI (v1)

| Command | Does |
|---|---|
| `login [--signer <name>]` | Ring QR via the grant auth flow; grant `/pub/sweepky/:rw` saved to a 0600 file; generates this install's age key and publishes `keys/<deviceId>.json`; reminds the user to back up `~/.config/sweepky/`. `--signer` (testnet only, hidden elsewhere) skips the QR: the CLI makes or reuses a local keypair under that name, signs up on the testnet homeserver and holds the session itself |
| `logout` | Revokes the grant and marks this device key revoked |
| `init <dir>` | Writes the sandbox settings and a `CLAUDE.md` for a sweeper project |
| `circle create\|add\|remove\|show` | Roster admin |
| `keys list\|revoke` | This identity's published device keys |
| `post [--open]` | Pins SHAs via `git ls-remote`/`gh`, crate sha256 from the index; refuses non-public repos |
| `run` | Picks the target with the fewest sweeps, writes `running`, fetches the target, writes `scope.json` and the bounty's brief into the sweep directory |
| `submit --run-dir <dir> [--playbook <name>]` | Builds the package (manifest, `findings.json`, attachments), converting Cloudflare output when detected; encrypts to the bounty owner's unrevoked keys plus its own; uploads `.age`; flips to `done` (or `aborted`) |
| `pull` | Roster polling plus the events-feed watcher for open bounties (persisted cursors); prints each sweep's trust label; decrypts to `~/.local/share/sweepky/<bounty>/`; merges trusted findings by `id`, recording every sweeper that reported each one; untrusted into `untrusted/` |
| `done <bounty> [--credit <pubky>]… [--no-credit <pubky>]…` | Rewrites the bounty with `status: "done"`, `doneAt` and `credits`. With no flags it proposes every sweeper whose sweep contributed at least one finding and asks for confirmation; the flags add or drop names. Two sweepers who reported the same finding are both proposed |
| `watch [--add-homeserver <pk>]` | Terminal live view |

Ten commands. There is no `dev` group: the testnet-only `--signer` flag on `login` is the whole Ring stand-in, and `SWEEPKY_HOME` points the CLI at a different config and state directory so a script can run several identities side by side. There is no `confirm`, `resolve` or `close`: triage is local, and `done` is the only public write after `post`.

`submit` packages whatever is in the sweep directory: `findings.json` (required; converted from Cloudflare's format when that is what it finds), and everything else as `attachments/`. The sweeper's agent is told to keep scratch files out of the sweep directory.

## The `/sweepky` skill

One skill, four roles: `run` (default), `post`, `pull`, `done`. Only `run` requires an `init` project.

- Playbook-agnostic. In `run` it reads the bounty's `brief`, `focus` and `playbook.suggested`, then follows the suggested playbook if the agent has it installed, otherwise whatever playbook the sweeper has configured, otherwise a plain careful review guided by the brief. It records which one it used.
- Carries the common findings schema and tells the agent to produce `findings.json` in it (or to leave Cloudflare's output for the CLI to convert).
- References `cloudflare/security-audit-skill` at commit `c1c8a8c` as the default suggestion for `security` bounties, with its install line (`npx skills add https://github.com/cloudflare/security-audit-skill --skill security-audit --global`). It does not vendor it and does not require it.
- Run flow: `sweepky run` → follow the playbook with the per-kind scope, output dir `./sweeps/<id>/` → `sweepky submit`.
- Tells the agent the trust rule: untrusted sweeps are summarised, never merged.
- In `done`, tells the agent to show the proposed credits with the findings each sweeper contributed, and to let the human decide.

## Dependencies

`pubky` 0.14 · `age` 0.12.x (no `plugin`) · `clap` · `tokio` · `serde` / `serde_json` · `secrecy` + `zeroize` · `qrcode` · `thiserror` (core) / `anyhow` (CLI) · `zstd` + `tar`. Tooling: stable toolchain, `cargo nextest`, `cargo-deny`, clippy with `-D warnings`, exact version pins.

No `paykit` or `locks` crates in v1: they pin `pubky` 0.15 and 0.11 respectively.

## Rust conventions (teaching notes, keep in code comments)

- `sweepky-core` does no network or file I/O, so it is unit-testable and could compile to WASM later.
- Typed errors with `thiserror` in the library; `anyhow` only in the binary, which only needs a good message.
- Secrets live in `secrecy::SecretString` / `Zeroizing<[u8; 32]>`: wiped on drop, unprintable via `Debug`.
- Open enums (`kind`, `status`, `alg`) are newtype `String`s with `as_known() -> Option<Known>` helpers, never closed serde enums, so unknown values from newer clients are skipped rather than failing the whole feed.
- Unknown top-level fields are preserved with `#[serde(flatten)] extra: Map` so rewrites do not drop them. `done` is a rewrite, so this is tested from the start.
- Pin `age` exactly: it is pre-1.0 and its docs call releases "beta". Leaving out `plugin` avoids the code path behind its one security advisory.
