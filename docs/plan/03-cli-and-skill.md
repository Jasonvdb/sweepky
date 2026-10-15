# 03 — CLI, skill and Rust conventions

## Repo layout

```
sweepky/
  Cargo.toml              workspace
  crates/sweepky-core/    records, paths, ids, target pinning, trust labels, feed parser,
                          age wrap/unwrap, pack/unpack, manifest — no network or file I/O
  crates/sweepky-cli/     the `sweepky` binary (clap, tokio)
  skill/sweepky/          SKILL.md + the .claude/settings.json sandbox template
  web/                    the board (Vite + React + TS)
  fixtures/               synthetic .age + plaintext for cross-implementation tests
  vibe/                   vibe.json + cover for the pubky/vibes PR (post-approval)
  docs/plan/              these docs
```

## The `sweepky` CLI (v1)

| Command | Does |
|---|---|
| `login` | Ring QR via the grant auth flow; grant `/pub/sweepky/:rw` saved to a 0600 file; publishes this CLI's device key |
| `logout` | Revokes the grant |
| `init <dir>` | Writes the sandbox settings and a `CLAUDE.md` for a sweeper project |
| `circle create\|add\|remove\|show` | Roster admin |
| `keys add\|list\|revoke` | Device keys |
| `post [--open] [--readers circle\|owner\|<pubky>…]` | Pins SHAs via `git ls-remote`/`gh`, crate sha256 from the index; refuses non-public repos |
| `run` | Picks the target with the fewest sweeps, writes `running`, fetches the target, writes `scope.json` and the bounty's brief into the sweep directory |
| `submit --run-dir <dir> [--playbook <name>]` | Builds the package (manifest, `findings.json`, attachments), converting Cloudflare output when detected; encrypts to readers' unrevoked keys; uploads `.age`; flips to `done` (or `aborted`) |
| `pull` | Roster polling plus the events-feed watcher for open bounties (persisted cursors); prints each sweep's trust label; decrypts to `~/.local/share/sweepky/<bounty>/`; merges trusted findings by `id`, untrusted into `untrusted/` |
| `confirm <sweep> <finding>` | Marks a finding confirmed in local triage state |
| `resolve <sweep> <finding>` | Writes the public attestation for a confirmed finding (fixed, or safe to disclose) |
| `close <bounty>` | Closes a bounty |
| `watch [--add-homeserver <pk>]` | Terminal live view |
| `dev identity\|approve` | Testnet only: create identities, play Ring's part by approving an auth URL (`PubkySigner::approve_auth`) |

Thirteen commands plus the hidden `dev` group, which only appears in testnet mode.

`submit` packages whatever is in the sweep directory: `findings.json` (required; converted from Cloudflare's format when that is what it finds), and everything else as `attachments/`. The sweeper's agent is told to keep scratch files out of the sweep directory.

## The `/sweepky` skill

One skill, six roles: `run` (default), `post`, `pull`, `confirm`, `resolve`, `close`. Only `run` requires an `init` project.

- Playbook-agnostic. In `run` it reads the bounty's `brief`, `focus` and `playbook.suggested`, then follows the suggested playbook if the agent has it installed, otherwise whatever playbook the sweeper has configured, otherwise a plain careful review guided by the brief. It records which one it used.
- Carries the common findings schema and tells the agent to produce `findings.json` in it (or to leave Cloudflare's output for the CLI to convert).
- References `cloudflare/security-audit-skill` at commit `c1c8a8c` as the default suggestion for `security` bounties, with its install line (`npx skills add https://github.com/cloudflare/security-audit-skill --skill security-audit --global`). It does not vendor it and does not require it.
- Run flow: `sweepky run` → follow the playbook with the per-kind scope, output dir `./sweeps/<id>/` → `sweepky submit`.
- Tells the agent the trust rule: untrusted sweeps are summarised, never merged.

## Dependencies

`pubky` 0.14 · `age` 0.12.x (no `plugin`) · `clap` · `tokio` · `serde` / `serde_json` · `secrecy` + `zeroize` · `qrcode` · `thiserror` (core) / `anyhow` (CLI) · `zstd` + `tar`. Tooling: stable toolchain, `cargo nextest`, `cargo-deny`, clippy with `-D warnings`, exact version pins.

No `paykit` or `locks` crates in v1: they pin `pubky` 0.15 and 0.11 respectively.

## Rust conventions (teaching notes, keep in code comments)

- `sweepky-core` does no network or file I/O, so it is unit-testable and could compile to WASM later.
- Typed errors with `thiserror` in the library; `anyhow` only in the binary, which only needs a good message.
- Secrets live in `secrecy::SecretString` / `Zeroizing<[u8; 32]>`: wiped on drop, unprintable via `Debug`.
- Open enums (`kind`, `status`, `alg`, `access.kind`) are newtype `String`s with `as_known() -> Option<Known>` helpers, never closed serde enums, so unknown values from newer clients are skipped rather than failing the whole feed.
- Unknown top-level fields are preserved with `#[serde(flatten)] extra: Map` so rewrites do not drop them.
- Pin `age` exactly: it is pre-1.0 and its docs call releases "beta". Leaving out `plugin` avoids the code path behind its one security advisory.
