# 02 — Encryption, keys and sweeper safety

## What is sealed and what is public

| Public (anyone can read) | Sealed (only the chosen readers can open) |
|---|---|
| The bounty post, including its brief | The whole sweep package: `manifest.json`, `findings.json`, attachments |
| Sweep records: who swept which bounty, when, with which playbook, status | |
| Everyone's device public keys (`keys/`) | |
| The roster (`circle.json`) | |
| Attestations: sweeper, bounty, severity, resolved date (published only at resolution) | |

Timing and sizes of uploads are visible too; payloads are padded to blunt the sizes.

## How an owner chooses who can read

The owner sets `readers` when posting: `"circle"`, `"owner"`, or an explicit list of pubkys. Control is purely cryptographic. Every reader publishes one public key per device (`keys/<deviceId>.json`); when a sweeper submits, their CLI encrypts the package to all of those keys at once, plus the sweeper's own. Anyone can download the ciphertext; only a device holding one of those private keys can open it. The homeserver stores opaque bytes and cannot read them either.

Three consequences to state in the UI:

- Readers are fixed per sweep at upload time. Widening `readers` later applies only to later sweeps; nothing is re-encrypted.
- The sweeper can always read their own sweep.
- A reader's new device can only open sweeps uploaded after that device published its key.

## Encryption

- **Format:** age v1 with X25519 recipients, stored as binary (no armor). Rust `age` 0.12.x (without the `plugin` feature) in the CLI; `age-encryption` (typage 0.3.x) in the board.
- **Recipients at upload time:** every unrevoked `keys/*.json` of the bounty's readers (circle or owner), plus the sweeper's own device key.
- **Sweeps are never re-encrypted.** A new device reads only sweeps uploaded after its key was published. The board says this plainly.
- **Padding:** `.age` payloads are padded to size buckets (for example 64 KiB steps) to blunt size metadata.
- **Cross-implementation guarantee:** `fixtures/` holds a Rust-encrypted `.age` that a typage test in `web/` decrypts, and a typage-encrypted `.age` that a Rust test decrypts. Both sides also run the C2SP CCTV age test vectors.

Why age and not alternatives: HPKE and sealed boxes encrypt to one recipient, so multi-recipient means hand-rolling the key wrapping age already defines. pubky-noise is a two-party channel for 1000-byte messages, the wrong shape for a document many people read. The homeserver's `/priv/` is alpha, readable by the operator, and cannot be shared with other readers.

## Authorship without signatures

age has no sender authentication, and Pubky Ring cannot sign arbitrary data (its only actions are auth, signup and similar). Authorship therefore rests on two facts:

1. The record sits at the writer's own path on their own homeserver, which only their session can write.
2. The `manifest.json` inside the ciphertext echoes sweeper, bounty and targets, so a copied report does not check out anywhere else.

Clients reject records whose path owner does not match the sweeper named inside, and, for closed bounties, records from pubkys outside the roster.

## Device keys

- **CLI:** the age identity and the Pubky grant live in `~/.config/sweepky/` as 0600 files (the SSH model); the identity may be passphrase-wrapped with `age::EncryptedIdentity`. Not the OS keychain, because headless sweepers have no unlocked keychain. The grant is scoped to `/pub/sweepky/:rw`, so a leak bounds to forging bounties and sweeps as that user; `sweepky logout` revokes it.
- **Browser:** a non-extractable WebCrypto X25519 key in IndexedDB. XSS, extensions and clipboard history cannot read it, which is why one pasted identity per member was rejected.
- Each device publishes its own `keys/<deviceId>.json`. Losing a device loses only owner-only sweeps encrypted before another device existed; circle-readable sweeps survive.

## Sweeper safety

The sweeper's agent reads untrusted code, and the owner's agent reads untrusted reports. Defences:

- **The CLI does all network I/O.** It fetches the target before the agent starts and uploads after the agent stops.
- **Sandbox template.** `sweepky init <dir>` writes `.claude/settings.json` with the sandbox enabled, `failIfUnavailable: true`, `allowUnsandboxedCommands: false`, `network.allowedDomains: []`, `filesystem.denyRead: ["~/"]`, `allowRead: ["."]`, `permissions.blockReadsOutsideWorkingDirectories`, `WebFetch` and `WebSearch` denied, and `sandbox.excludedCommands: ["sweepky"]` so `sweepky submit` can reach the network. P3 verifies how `excludedCommands` actually matches; the fallback is the human running `sweepky submit` after the audit.
- **Static review only in v1.** The skill refuses to execute target code without a full OS sandbox (no network, empty environment, resource limits), which Claude Code's Bash-only sandbox does not meet. Expect many `needs_validation` records; that is honest. A Docker runner that meets the skill's bar is deferred.
- **Only Bash is sandboxed.** File tools, MCP servers and hooks are not, so the sweeper project directory should be the only thing on disk the agent can read.
- **Untrusted reports are data.** On open bounties, sweeps from unknown sweepers are decrypted into a separate `untrusted/` directory; the owner's agent summarises them but never merges their `remediation.code_changes`.

## Plan-usage rules

Each developer runs their own unmodified Claude Code on their own plan. The tool never reads, stores or proxies Claude credentials, and never pools usage across accounts. Advertised plan limits assume ordinary individual use; a quota-aware auto mode is deferred until sweepers ask for it.
