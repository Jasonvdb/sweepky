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
| `run` | Picks the target with the fewest sweeps, writes `running`, fetches the target |
| `submit --run-dir <dir>` | Packs canonical files, encrypts to readers' unrevoked keys, uploads `.age`, flips to `done` (or `aborted`) |
| `pull` | Roster polling plus the events-feed watcher for open bounties (persisted cursors); prints each sweep's trust label; decrypts to `~/.local/share/sweepky/<bounty>/`; merges trusted `findings.json` by `fingerprint`, untrusted into `untrusted/` |
| `confirm <sweep> <fingerprint>` | Writes the attestation record |
| `close <bounty>` | Closes a bounty |
| `watch [--add-homeserver <pk>]` | Terminal live view |
| `dev identity\|approve` | Testnet only: create identities, play Ring's part by approving an auth URL (`PubkySigner::approve_auth`) |

Twelve commands plus the hidden `dev` group, which only appears in testnet mode.

Canonical run files that `submit` packs: `findings.json`, `REPORT.md`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md`, `coverage-ledger.json`, `run-metadata.json`, `architecture.md`. Working directories, scripts and inboxes are excluded.

## The `/sweepky` skill

One skill, five roles: `run` (default), `post`, `pull`, `confirm`, `close`. Only `run` loads `security-audit` and requires an `init` project.

- References `cloudflare/security-audit-skill` pinned at commit `c1c8a8c` with its install line (`npx skills add https://github.com/cloudflare/security-audit-skill --skill security-audit --global`). It does not vendor the skill.
- Run flow: `sweepky run` → run the audit with the bounty's profile and the per-kind scope, output dir `./sweeps/<id>/` → `sweepky submit`.
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
