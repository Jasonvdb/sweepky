# P2 — `sweepky-cli`

## Goal

The `sweepky` binary, end to end against a local testnet, including open-bounty discovery and credits.

## Build

- `login --ring` (option A): Ring QR via `PubkyGrantAuthFlow`, grant to a 0600 file, expiry shown and warned about ahead of time.
- `login --identity <name> [--homeserver <pk>] [--signup-token <code>]` (option B): local keypair under that name (created or reused), `PubkySigner::signup` then `signin`, secret to a 0600 file, optional passphrase wrap. Homeserver defaults to the testnet's in testnet mode, else `homeserver.pubky.app`.
- Shared tail of `login`: age key generated and published, backup reminder printed. Interactive `login` with no flag asks A or B; non-interactive without a flag errors with the two choices. Recovery files and raw secrets of existing identities are rejected with a one-line reason.
- `logout`: revoke the grant or forget the identity; mark the device key revoked.
- `circle create|add|remove|show`; `keys list|revoke`.
- `post [--open]`: pins SHAs via `git ls-remote` / `gh`, crate sha256 from the crates.io index; refuses non-public repos.
- `run`: picks the target with the fewest sweeps, writes `running`, fetches the target into the sweeper project, writes `scope.json` and the brief.
- `submit --run-dir [--playbook]`: build the package (manifest, `findings.json`, attachments), converting Cloudflare output when detected → read the bounty, list the owner's unrevoked `keys/` → encrypt to those plus this install's key → upload `.age` → flip to `done` (or `aborted` on failure).
- `pull`: roster polling plus the events-feed watcher for open bounties with persisted cursors; trust labels from roster plus credits; decrypt to `~/.local/share/sweepky/<bounty>/`; merge trusted findings by `id` keeping `reportedBy`; untrusted into `untrusted/`.
- `done <bounty> [--credit] [--no-credit]`: proposes credits from the merged findings, confirms interactively unless flags settle it, rewrites the bounty with `status: "done"`, `doneAt`, `credits`, preserving unknown fields.
- `watch [--add-homeserver <pk>]` (terminal live view).
- Config and state under `~/.config/sweepky/` (secrets, 0600) and `~/.local/share/sweepky/` (pulled sweeps, merged findings, cursors); `SWEEPKY_HOME` overrides both so a script can run several identities side by side.

## Done when

- `#[pubky_testnet::test]` end-to-end: identities A (admin/owner), B (circle sweeper), C (stranger); circle = {A, B}; A posts an `open` bounty with two targets; B submits a synthetic sweep; C submits another sharing one finding `id` with B's; A pulls: B's sweep is `circle` and merged, C's is discovered via the testnet homeserver's `/events/` feed, labelled `unknown`, and lands in `untrusted/`; the merged finding lists reporters {B, C}; A runs `done`, the proposal is {B, C}, A accepts, the bounty is `done` with both credits, and C's label is `known: 1` on the next pull; one of the two synthetic sweeps uses Cloudflare-format output and the other a hand-written common-format `findings.json`, and both decrypt and merge; a device key published after a sweep cannot decrypt it; a second install of A logged in before a third sweep decrypts that third sweep; `logout` invalidates the grant; the events cursor survives a restart.
- Both login options are covered in the same test: A logs in with `--ring`, the test approves the printed `pubkyauth` URL in-process with `PubkySigner::approve_auth`, and the resulting grant writes a record. B and C use `--identity`. A recovery file passed to `login` is rejected.
- Clippy, deny, nextest clean.

## Open questions to resolve in this phase

- The `/events/` feed's default cursor is the beginning of history. Find a cheap way to obtain the current cursor (inspect `EventsService::parse_cursor` / `EventCursor` in the homeserver); fallback: page once with a large `limit` and persist. Document whichever works.
- How a person obtains a raw signup token for option B on the production homeserver. Today the web signup flow hands the token to Ring inside a QR code; find out whether it can be copied, or whether Homegate's API can be driven from the CLI. Until answered, option B on production is documented as "bring a token".

## Notes

- `anyhow` in the binary; typed errors stay in core.
- The grant is scoped to `/pub/sweepky/:rw` and nothing else.
- `done` is the only command that rewrites an existing public record; test that a bounty posted by a newer client with extra fields survives it intact.
