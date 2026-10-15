# P2 — `sweepky-cli`

## Goal

The `sweepky` binary, end to end against a local testnet, including open-bounty discovery and attestations.

## Build

- `login` (Ring QR via `PubkyGrantAuthFlow`, grant to a 0600 file, device key published), `logout` (revoke).
- `dev identity new|list`, `dev approve <url> --as <name>` (testnet only, via `PubkySigner::approve_auth`).
- `circle create|add|remove|show`; `keys add|list|revoke`.
- `post`: pins SHAs via `git ls-remote` / `gh`, crate sha256 from the crates.io index; refuses non-public repos; `--open`, `--readers`.
- `run`: picks the target with the fewest sweeps, writes `running`, fetches the target into the sweeper project.
- `submit --run-dir`: canonical files → encrypt to the readers' unrevoked device keys → upload `.age` → flip to `done` (or `aborted` on failure).
- `pull`: roster polling plus the events-feed watcher for open bounties with persisted cursors; trust labels; decrypt to `~/.local/share/sweepky/<bounty>/`; merge trusted `findings.json` by `fingerprint`; untrusted into `untrusted/`.
- `confirm <sweep> <fingerprint>`: writes the attestation record.
- `close`; `watch [--add-homeserver <pk>]` (terminal live view).
- Config and state under `~/.config/sweepky/` (secrets, 0600) and `~/.local/share/sweepky/` (pulled sweeps, cursors).

## Done when

- `#[pubky_testnet::test]` end-to-end: identities A (admin/owner), B (circle sweeper), C (stranger); circle = {A, B}; A posts an `open` bounty with two targets; B submits a synthetic sweep; C submits another; A pulls: B's sweep is `circle` and merged, C's is discovered via the testnet homeserver's `/events/` feed, labelled `unknown`, and lands in `untrusted/`; A confirms one of C's findings → C's label becomes `known: 1`; a device key added after a sweep cannot decrypt it; `logout` invalidates the grant; the events cursor survives a restart.
- Manual: QR login against the testnet approved with `sweepky dev approve`.
- Clippy, deny, nextest clean.

## Open question to resolve in this phase

The `/events/` feed's default cursor is the beginning of history. Find a cheap way to obtain the current cursor (inspect `EventsService::parse_cursor` / `EventCursor` in the homeserver); fallback: page once with a large `limit` and persist. Document whichever works.

## Notes

- `anyhow` in the binary; typed errors stay in core.
- The grant is scoped to `/pub/sweepky/:rw` and nothing else.
