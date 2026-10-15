# 02 — Encryption, keys and sweeper safety

## What Pubky gives us, and the one gap

Checked against the homeserver, Ring and Paykit source (paths in [06](06-verification-and-limits.md#key-references)):

- **Two access tiers only.** `/pub/` is readable by everyone. `/priv/` is readable and writable only by sessions of the path's owner (`has_read_permission` rejects any session whose user is not the tenant). There is no "share this file with user X".
- **Writes are always owner-only**, scoped by the grant path. Marking a bounty done is a rewrite of the owner's own record and needs nothing extra.
- **Pubky Ring approves auth requests and nothing else.** It cannot sign or decrypt for an app, and an app signed in through Ring never holds the identity secret.
- **pubky-noise is a live two-party channel**: a handshake, then 1000-byte frames. Paykit can use it because Bitkit holds the identity secret and derives the Noise key from it (`paykit-lib/src/noise_key.rs`). A Ring-authenticated CLI has no such secret, so it would have to generate and publish a key anyway, and a sweeper would still need the owner online for the handshake.

So "only the owner can read findings" is the one requirement Pubky cannot meet natively, and all of Sweepky's cryptography is the smallest fix for it: the owner's CLI generates one encryption key and publishes the public half; sweepers encrypt to it. Everything else is plain public JSON.

## What is sealed and what is public

| Public (anyone can read) | Sealed (only the owner can open) |
|---|---|
| The bounty post, including its brief | The whole sweep package: `manifest.json`, `findings.json`, attachments |
| Sweep records: who swept which bounty, when, with which playbook, status | |
| Every CLI's public encryption key (`keys/`) | |
| The roster (`circle.json`) | |
| Done bounties and their `credits` | |

Timing and sizes of uploads are visible too; payloads are padded to blunt the sizes.

## Who can read a sweep

The owner of the bounty, on any CLI install whose key was published before the sweep was uploaded, and the sweeper who wrote it. Nobody else: not the circle, not the homeserver operator, not someone who downloads the file.

How it works: at `sweepky login` the CLI generates an age key pair, keeps the private half in a 0600 file, and publishes the public half at `keys/<deviceId>.json`. At `sweepky submit` the sweeper's CLI reads the bounty, lists the owner's unrevoked keys, and encrypts the package to all of them plus its own key. The homeserver stores opaque bytes.

Three consequences to state plainly in the CLI:

- Fixed at upload. Nothing is re-encrypted; a key published later opens only later sweeps.
- The sweeper can always read their own sweep.
- Lose the key file, lose the sweeps not yet pulled. `pull` keeps decrypted copies under `~/.local/share/sweepky/`, so anything already pulled survives. `login` tells the owner to back up `~/.config/sweepky/` the way they would an SSH key.

## Encryption

- **Format:** age v1 with X25519 recipients, stored as binary (no armor). Rust `age` 0.12.x without the `plugin` feature. No browser implementation in v1.
- **Recipients at upload time:** every unrevoked `keys/*.json` of the bounty's owner, plus the sweeper's own device key.
- **Sweeps are never re-encrypted.**
- **Padding:** `.age` payloads are padded to size buckets (for example 64 KiB steps) to blunt size metadata.
- **Test vectors:** the Rust tests run the C2SP CCTV age vectors.

Why age: it encrypts to several recipients natively (an owner with two laptops, plus the sweeper), has a maintained Rust implementation, and has a browser implementation (typage) for the day the board learns to read. HPKE and sealed boxes are single-recipient, so multi-recipient would mean hand-rolling the key wrapping age already defines. `/priv/` cannot be shared with another user, and pubky-noise is the wrong shape (above).

## Authorship without signatures

age has no sender authentication, and Pubky Ring cannot sign arbitrary data. Authorship therefore rests on two facts:

1. The record sits at the writer's own path on their own homeserver, which only their session can write.
2. The `manifest.json` inside the ciphertext echoes sweeper, bounty and targets, so a copied report does not check out anywhere else.

Clients reject records whose path owner does not match the sweeper named inside, and, for closed bounties, records from pubkys outside the roster.

A CLI-held identity could also sign the manifest, which a Ring grant cannot. v1 does not use this, so both login options behave identically; it is a door left open for signed sweeps later.

## Device keys

- **CLI:** the age identity and the Pubky credential live in `~/.config/sweepky/` as 0600 files (the SSH model); either may be passphrase-wrapped with `age::EncryptedIdentity`. Not the OS keychain, because headless sweepers have no unlocked keychain. The credential is one of two ([03](03-cli-and-skill.md#two-ways-to-log-in)): a Ring grant scoped to `/pub/sweepky/:rw`, whose leak bounds to forging bounties and sweeps as that user until revoked; or the secret of a dedicated identity the CLI created, whose leak loses that identity and nothing else. An existing identity's secret is never imported. `sweepky logout` revokes the grant (or forgets the identity) and marks the device key revoked.
- Every CLI install publishes its own `keys/<deviceId>.json`. An owner with two laptops has two keys and sweepers encrypt to both. `keys list|revoke` manages them.
- **Browser:** not in v1. When the board learns to read ([05](05-extensions.md#e4-reading-findings-in-the-browser)) it generates a non-extractable WebCrypto X25519 key and publishes it the same way. Sweepers' CLIs already encrypt to every published owner key, so no record changes; the board will only ever open sweeps uploaded after its key existed.

## Sweeper safety

The sweeper's agent reads untrusted code, and the owner's agent reads untrusted reports. Defences:

- **The CLI does all network I/O.** It fetches the target before the agent starts and uploads after the agent stops.
- **Sandbox template.** `sweepky init <dir>` writes `.claude/settings.json` with the sandbox enabled, `failIfUnavailable: true`, `allowUnsandboxedCommands: false`, `network.allowedDomains: []`, `filesystem.denyRead: ["~/"]`, `allowRead: ["."]`, `permissions.blockReadsOutsideWorkingDirectories`, `WebFetch` and `WebSearch` denied, and `sandbox.excludedCommands: ["sweepky"]` so `sweepky submit` can reach the network. P3 verifies how `excludedCommands` actually matches; the fallback is the human running `sweepky submit` after the audit.
- **Static review only in v1.** The skill refuses to execute target code without a full OS sandbox (no network, empty environment, resource limits), which Claude Code's Bash-only sandbox does not meet. Expect many `needs_validation` records; that is honest. A Docker runner that meets the skill's bar is deferred.
- **Only Bash is sandboxed.** File tools, MCP servers and hooks are not, so the sweeper project directory should be the only thing on disk the agent can read.
- **Untrusted reports are data.** On open bounties, sweeps from unknown sweepers are decrypted into a separate `untrusted/` directory; the owner's agent summarises them but never applies their suggested fixes without a human.

## Plan-usage rules

Each developer runs their own unmodified Claude Code on their own plan. The tool never reads, stores or proxies Claude credentials, and never pools usage across accounts. Advertised plan limits assume ordinary individual use; a quota-aware auto mode is deferred until sweepers ask for it.
