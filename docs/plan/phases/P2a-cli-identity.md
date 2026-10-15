# P2a — `sweepky-cli`: identity, keys and circle

## Goal

The first part of the `sweepky` binary: the network config and library entry point, `login --identity` with the shared tail of `login`, `keys`, `logout`, the circle, the writers' lock, the config and state directories, and a minimal `init`. It builds on the records, the `Pubky` newtype and the path builders from [P1a](P1a-core-records.md), and on the age keys and secret types from [P1b](P1b-core-crypto.md). The Ring login (option A) follows in [P2d](P2d-cli-ring-login.md).

## Build

- **Network config and entry point.** A library function runs every command given a `Pubky` client, the auth relay URL and the default homeserver; the binary builds those from `--testnet` / `SWEEPKY_TESTNET=1` (testnet client, `http://localhost:15412/inbox`, the testnet homeserver) or the production defaults. The end-to-end test injects an `EphemeralTestnet`'s client instead. The watch list defaults to the selected homeserver.
- **`login --identity <name> [--homeserver <pk>] [--signup-token <code>]` (option B):** local keypair under that name (created or reused), `PubkySigner::signup` then `signin_blocking` on first login, secret in a Sweepky 0600 file, optional scrypt passphrase wrap. Homeserver defaults to the testnet's under `--testnet`, else `homeserver.pubky.app`. On production, warn that this creates a separate public pubky and spends a signup token. Later commands sign in and sign out per run.
- **Shared tail of `login`:** age key generated; `keys/<deviceId>.json` written as the capability probe, mapping 403 ("this identity's signup token does not allow `/pub/sweepky/`; use a dedicated identity") and 507 ("storage quota full") to messages and aborting; device id recorded in the local list of this owner's installs; backup reminder printed. Recovery files (fixed first line) and anything shaped like a raw key or mnemonic are rejected with a one-line reason.
- **Writers' lock.** `post`, `run`, `submit`, `done`, `circle`, `keys` and `logout` take an exclusive `fd-lock` on `~/.config/sweepky/credential.lock` around session restore plus writes, because each restore replaces the grant's bearer. `pull` reads public data without a session except for its one `discovered.json` write, which also takes the lock.
- **`logout`:** mark the device key revoked, then `signout()` (which revokes the grant) or forget the identity, then delete the local files.
- **`circle create|add|remove|show`; `keys list|revoke`.** `keys list` and `pull` compare `keys/` against the list of device ids this owner's own installs created and alarm on unknown ids.
- Config and state under `~/.config/sweepky/` (secrets, install list, pinned owner keys, 0600) and `~/.local/share/sweepky/` (pulled sweeps, groups, cursors); `SWEEPKY_HOME` overrides both.
- **`sweepky init <dir>` (minimal):** creates the directory, writes the `.sweepky` marker and a `.gitignore` containing `sweeps/`, and nothing else. `run` ([P2b](P2b-cli-sweep.md)) requires that marker. The rest of `init` belongs to [P3](P3-skill-and-sandbox.md): the sandbox `.claude/settings.json`, the project `CLAUDE.md`, the skill copy into `.claude/skills/sweepky/`, the playbook install and the launch line.

## Done when

- Unit tests pass for: the requested capability string; the lock serialising two writers; the 403 and 507 mapping to their messages; a recovery file rejected.
- A testnet test logs in a throwaway identity with `--identity`, publishes a key, lists it, revokes it and logs out; after `logout` this install's key record has `revokedAt` set, and the identity and its local files are gone. The throwaway identity is not one of A, B or C from the end-to-end test in [06](../06-verification-and-limits.md#verification). The test runs as `#[tokio::test]` + `#[pubky_testnet::test]` over an `EphemeralTestnet` with the HTTP relay, the client injected.
- `cargo clippy -- -D warnings`, `cargo deny check` and `cargo nextest run` clean.

## Resolved questions

- **Signup token for option B on production.** Plain text, three ways to get one ([06](../06-verification-and-limits.md#production-homeserver-as-deployed-on-2026-10-15)). v1 is bring-a-token.

## Notes

- `anyhow` in the binary; typed errors stay in core.
- A unit test pins the requested capability string to exactly `/pub/sweepky/:rw`; without the trailing slash it would be a file scope. The constant and its test land here, but the first code that requests the capability is [P2d](P2d-cli-ring-login.md)'s grant flow, because `--identity` signs in with the root signer.
- The testnet test is the start of the end-to-end test from [06](../06-verification-and-limits.md#verification). [P2b](P2b-cli-sweep.md) and [P2c](P2c-cli-pull-done.md) extend this same test and [P2d](P2d-cli-ring-login.md) completes it, so no phase adds a second one. P2a's own steps use the throwaway identity rather than A, B or C because `logout` deletes the identity it runs on, and B's `submit` in P2b needs A to hold an unrevoked key. No later phase uses the throwaway identity, so P2b–P2d extend the test without reordering these steps. Restoring a saved token after `logout` is checked in P2d, the first phase that saves one.
- Never call the deprecated cookie sign-in; add a clippy `disallowed-methods` entry for it.
