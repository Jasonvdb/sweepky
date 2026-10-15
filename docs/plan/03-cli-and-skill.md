# 03 — CLI, skill and Rust conventions

## Repo layout

```
sweepky/
  Cargo.toml              workspace
  crates/sweepky-core/    records, paths, ids, target pinning, trust labels, feed parser,
                          age wrap/unwrap, package envelope, manifest — no network or file I/O
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
| `login [--identity <name>] [--homeserver <pk>] [--signup-token <code>]` | Default: Pubky Ring, via a sign-in page the CLI opens in the browser. `--identity` creates a dedicated identity instead. See [Two ways to log in](#two-ways-to-log-in). Either way it generates this install's age key, publishes `keys/<deviceId>.json`, and reminds the user to back up `~/.config/sweepky/` |
| `logout` | Revokes the grant and marks this device key revoked |
| `init <dir>` | Writes the sandbox settings and a `CLAUDE.md` for a sweeper project |
| `circle create\|add\|remove\|show` | Roster admin |
| `keys list\|revoke` | This identity's published device keys |
| `post [--open]` | Pins SHAs via `git ls-remote`/`gh`; refuses non-public repos |
| `run` | Picks the target with the fewest sweeps, writes `running`, fetches the target, writes `scope.json` and the bounty's brief into the sweep directory |
| `submit --run-dir <dir> [--playbook <name>]` | Builds the package (one JSON document: manifest, findings, text attachments), converting Cloudflare output when detected; encrypts to the bounty owner's unrevoked keys plus its own; uploads `.age`; flips to `done` (or `aborted`) |
| `pull` | Roster polling plus the events-feed watcher for open bounties (persisted cursors); prints each sweep's trust label; decrypts to `~/.local/share/sweepky/<bounty>/`; merges trusted findings by `id`, recording every sweeper that reported each one; untrusted into `untrusted/` |
| `done <bounty> [--credit <pubky>]… [--no-credit <pubky>]…` | Rewrites the bounty with `status: "done"`, `doneAt` and `credits`. With no flags it proposes every sweeper whose sweep contributed at least one finding and asks for confirmation; the flags add or drop names. Two sweepers who reported the same finding are both proposed |

Nine commands. There is no `watch`: the board is the live view, `pull` prints the state it finds, and the open-bounty homeserver watch list is a config entry. There is no `dev` group: `login --identity` doubles as the testnet stand-in for Ring, and `SWEEPKY_HOME` points the CLI at a different config and state directory so a script can run several identities side by side. There is no `confirm`, `resolve` or `close`: triage is local, and `done` is the only public write after `post`.

`submit` packages whatever is in the sweep directory into one JSON document: `findings.json` (required; converted from Cloudflare's format when that is what it finds) becomes `findings`, and every other UTF-8 text file becomes an `attachments` entry keyed by its relative path. Non-text files are skipped with a warning. The sweeper's agent is told to keep scratch files out of the sweep directory.

## Two ways to log in

Most people will use the pubky they already have in Ring, so that is the default. The dedicated identity exists for agents, CI, the testnet, and anyone who prefers one.

| | A. Pubky Ring (default) | B. CLI-held identity |
|---|---|---|
| Flag | none | `--identity <name>` |
| Whose identity | the one already in Ring | a new pubky the CLI creates, or one it created earlier under that name |
| Human steps | scan one QR, once | none |
| What is stored (0600, in `~/.config/sweepky/`) | a grant scoped to `/pub/sweepky/:rw` plus the CLI's client key | the identity secret, optionally passphrase-wrapped |
| Lifetime | until the grant expires (Ring sets it; the CLI warns ahead) or is revoked, from Ring or by `logout` | until the file is deleted |
| If the file leaks | someone can write Sweepky records as you until you revoke; nothing else | that identity is theirs; your main identity is untouched |
| Homeserver | wherever the Ring identity lives | `--homeserver <pubkey>`; defaults to the testnet homeserver in testnet mode, else to `homeserver.pubky.app`, which needs `--signup-token` |

Credits accrue to whichever pubky is used; a dedicated identity can be mentioned from a pubky.app profile if its owner wants the two linked. The official `pubky-cli` already creates identities from a recovery file and signs up with a code, so B is an established pattern, not a Sweepky invention.

**How the Ring sign-in looks.** `sweepky login` starts the SDK's grant flow (`PubkyGrantAuthFlow`), which yields a `pubkyauth://` URL, then:

- Serves a single page on `127.0.0.1:<random port>/<random path>` and opens it in the default browser. The page shows a large QR of that URL, a "copy link" button (Ring accepts a pasted link too), what is being requested (`/pub/sweepky/:rw` and the client id Ring will display), and a live status that flips to "approved, you can close this tab" when `await_approval()` returns.
- Prints the same URL and a small QR in the terminal as the fallback for SSH sessions and machines without a browser.
- Hygiene: loopback only, random path so no other local page or process can guess it, serves exactly one flow, exits on approval or after a timeout. The URL carries the relay channel secret, so it is never logged or written to disk.

An agent can run `sweepky login` on a human's laptop: the page opens, the human scans, the agent carries on. Fully unattended setups use `--identity`.

**Refused:** importing an existing identity's secret or recovery file into the CLI. That secret controls the identity forever, including moving it to another homeserver, and this CLI runs under agents that read untrusted code. Ring exists to keep that secret off the laptop; `login` rejects recovery files and says why.

## The `/sweepky` skill

One skill, four roles: `run` (default), `post`, `pull`, `done`. Only `run` requires an `init` project.

- Playbook-agnostic. In `run` it reads the bounty's `brief`, `focus` and `playbook.suggested`, then follows the suggested playbook if the agent has it installed, otherwise whatever playbook the sweeper has configured, otherwise a plain careful review guided by the brief. It records which one it used.
- Carries the common findings schema and tells the agent to produce `findings.json` in it (or to leave Cloudflare's output for the CLI to convert).
- References `cloudflare/security-audit-skill` at commit `c1c8a8c` as the default suggestion for `security` bounties, with its install line (`npx skills add https://github.com/cloudflare/security-audit-skill --skill security-audit --global`). It does not vendor it and does not require it.
- Run flow: `sweepky run` → follow the playbook with the per-kind scope, output dir `./sweeps/<id>/` → `sweepky submit`.
- Tells the agent the trust rule: untrusted sweeps are summarised, never merged.
- In `done`, tells the agent to show the proposed credits with the findings each sweeper contributed, and to let the human decide.

## Dependencies

`pubky` 0.14 · `age` 0.12.x (no `plugin`) · `clap` · `tokio` · `serde` / `serde_json` · `secrecy` + `zeroize` · `qrcode` · `thiserror` (core) / `anyhow` (CLI). Tooling: stable toolchain, `cargo nextest`, `cargo-deny`, clippy with `-D warnings`, exact version pins.

No `paykit` or `locks` crates in v1: they pin `pubky` 0.15 and 0.11 respectively.

## Rust conventions (teaching notes, keep in code comments)

- `sweepky-core` does no network or file I/O, so it is unit-testable and could compile to WASM later.
- Typed errors with `thiserror` in the library; `anyhow` only in the binary, which only needs a good message.
- Secrets live in `secrecy::SecretString` / `Zeroizing<[u8; 32]>`: wiped on drop, unprintable via `Debug`.
- Open enums (`kind`, `status`, `alg`) are newtype `String`s with `as_known() -> Option<Known>` helpers, never closed serde enums, so unknown values from newer clients are skipped rather than failing the whole feed.
- Unknown top-level fields are preserved with `#[serde(flatten)] extra: Map` so rewrites do not drop them. `done` is a rewrite, so this is tested from the start.
- Pin `age` exactly: it is pre-1.0 and its docs call releases "beta". Leaving out `plugin` avoids the code path behind its one security advisory.
