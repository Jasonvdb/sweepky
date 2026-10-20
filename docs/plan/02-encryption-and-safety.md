# 02 — Encryption, keys and sweeper safety

## What Pubky gives us, and the one gap

Checked against the homeserver, Ring and Paykit source (paths in [06](06-verification-and-limits.md#key-references)):

- **Two access tiers only.** `/pub/` is readable by everyone. `/priv/` is readable and writable only by sessions of the path's owner (`has_read_permission` rejects any session whose user is not the tenant). There is no "share this file with user X".
- **Writes are always owner-only**, scoped by the grant path. Marking a bounty done is a rewrite of the owner's own record and needs nothing extra. Whether an identity may write a given `/pub/` path at all is decided by its signup token (`allowed_write_paths`, enforced per user), see [06](06-verification-and-limits.md#production-homeserver-as-deployed-on-2026-10-15).
- **Pubky Ring signs grants and nothing else.** It cannot decrypt for an app, and an app signed in through Ring never holds the identity secret. From SDK 0.16 a grant holder can sign JSON with its own client key (custom grant proofs), but those proofs stop verifying when the grant expires and ignore revocation, so they are no good for a permanent public record. 0.16 also adds scoped encryption keys: symmetric, derived from the user's own identity, for the user's own data. They cannot encrypt to another user and today's Ring does not issue them.
- **pubky-noise is a live two-party channel**: a handshake, then 1000-byte frames. Paykit can use it because Bitkit holds the identity secret and derives the Noise key from it (`paykit-lib/src/noise_key.rs`). A Ring-authenticated CLI has no such secret, so it would have to generate and publish a key anyway, and the owner would have to answer the handshake before a sweeper could send anything.

So "only the owner can read findings" is the one requirement Pubky cannot meet natively, and all of Sweepky's cryptography is the smallest fix for it: the owner's CLI generates one encryption key and publishes the public half; sweepers encrypt to it. Everything else is plain public JSON.

## What is sealed and what is public

| Public (anyone can read) | Sealed (only the owner can open) |
|---|---|
| The bounty post, including its brief | The whole sweep package: manifest, findings, attachments |
| Sweep records: who swept which bounty, when, with which playbook, status | |
| Every CLI's public encryption key (`keys/`) | |
| The roster (`circle.json`) | |
| Done bounties and their `credits`; the discovered-sweeps list of an open bounty | |

Timing and sizes of uploads are visible too; payloads are padded before encryption to blunt the sizes.

## Who can read a sweep

The owner of the bounty, on any CLI install whose key was published before the sweep was uploaded, and the sweeper who wrote it. Not the circle, not someone who downloads the file, and not a homeserver operator who only reads.

The honest caveat: `keys/*.json` are plain JSON that sweepers trust, and a homeserver operator can write any tenant's files through the admin API. An **active** operator of the owner's homeserver, or anyone holding the owner's leaked grant (its scope covers `keys/`), can publish an extra key under the owner's `keys/` and read every sweep uploaded after that. Two cheap defences, both in v1:

- The owner's CLI keeps the list of device ids its own installs created, each with the public key it published, and **alarms** on `pull`, `keys list` and `login` when `keys/` holds one it does not know, or a known id whose record names another key, unless that record is revoked already (a record under an unknown id that it cannot read still alarms). A check that cannot finish within its bounds (too many records or bytes, a failed listing, a known id's record it cannot read; [P2c](phases/P2c-cli-pull-done.md#notes)) never passes for no alarm: `pull` alarms on it, and `login` warns and points at `keys list`. Recovery: `keys revoke` the injected or rewritten id, and if a grant leaked, revoke it in Ring and `login` again. A revoked record is what the recovery leaves, so it no longer raises the alarm; rewritten unrevoked, it raises it again. The list is local, the installs that share one config directory, and never published, since whoever can write the owner's storage could write a published list too. So two installs on two machines each alarm on the other's key, and the owner tells them apart with `keys list` on the other machine.
- A sweeper's CLI **pins** each owner's key set on first use and warns, asking before it continues, when a new key appears. It also refuses to encrypt when an owner has no unrevoked key, accepts only `alg: "age-x25519"` with a strictly parsed recipient, and caps how many recipients it will take from one owner.

How it works: at `sweepky login` the CLI generates an age key pair, keeps the private half in a 0600 file, and publishes the public half at `keys/<deviceId>.json`. At `sweepky submit` the sweeper's CLI reads the bounty, lists the owner's unrevoked keys, and encrypts the package to all of them plus its own key. The homeserver stores opaque bytes.

Three consequences to state plainly in the CLI:

- Fixed at upload. Nothing is re-encrypted; a key published later opens only later sweeps.
- The sweeper can always read their own sweep.
- Lose the key file, lose the sweeps not yet pulled. `pull` keeps decrypted copies under `~/.local/share/sweepky/`, so anything already pulled survives. `login` tells the owner to back up `~/.config/sweepky/` the way they would an SSH key.

## Encryption

- **Format:** age v1 with X25519 recipients, stored as binary (no armor). Rust `age` 0.12.1 with default features; never `plugin` (removes that attack surface) and never `ssh` (pulls in an `rsa` crate with an unpatched advisory). No browser implementation in v1.
- **Recipients at upload time:** every unrevoked `keys/*.json` of the bounty's owner, plus the sweeper's own device key.
- **Sweeps are never re-encrypted.**
- **Padding:** the plaintext JSON is padded with trailing whitespace to the next size bucket (64 KiB steps) before encryption. age rejects bytes after its payload, so the ciphertext itself is never padded; the test asserts on the final ciphertext length. That length is the header, then a 16-byte nonce, the bucket, and a 16-byte tag per 64 KiB chunk. age adds a random grease stanza of up to about 190 bytes to every header, so the header's length varies between encryptions and the test reads it from the ciphertext; the bucket alone sets the length after it.
- **Test vectors:** the Rust tests run the C2SP CCTV age vectors (hybrid post-quantum ones skipped, which Rust age cannot run yet; armored ones checked to be refused, since packages are binary and armor is not compiled in).

Why age: it encrypts to several recipients natively (an owner with two laptops, plus the sweeper), has a maintained Rust implementation, and has a browser implementation (typage) for the day the board learns to read. HPKE and sealed boxes are single-recipient, so multi-recipient would mean hand-rolling the key wrapping age already defines. `/priv/` cannot be shared with another user, and pubky-noise is the wrong shape (above).

## Authorship without signatures

age has no sender authentication, and Pubky Ring signs nothing for apps. Authorship therefore rests on two facts:

1. The record sits at the writer's own path on their own homeserver, which only their session can write, as reported by that homeserver. The homeserver operator is trusted for integrity and availability; confidentiality survives a passive operator, not an active one (above).
2. The manifest inside the ciphertext echoes sweeper, bounty and targets, so a copied report does not check out under another sweeper, another bounty or other targets. `submit` binds the manifest to the revisions `run` fetched, kept in the data directory, and refuses a sweep whose bounty changed since. The manifest has no sweep id, so a sweeper's own package uploaded again under another of their sweep records, for the same bounty and targets, does check out there.

Clients reject records whose path owner does not match the sweeper named inside, and, for closed bounties, records from pubkys outside the roster.

A CLI-held identity could sign the manifest with its root key, and a 0.16 grant holder could attach a custom grant proof; v1 uses neither, so both login options behave identically. Signed sweeps are a door left open, with the proof-expiry caveat above.

## Device keys

- **CLI:** the age identity and the Pubky credential live in `~/.config/sweepky/` as 0600 files (the SSH model). Either may be passphrase-wrapped with age's scrypt recipient (`age::scrypt::Recipient` at a fixed work factor, through `age::Encryptor::with_recipients`, to write, and `age::scrypt::Identity` with a capped work factor to read); not `age::Encryptor::with_user_passphrase`, which calibrates the work factor on the writing machine without saying which it picked, so a fast machine could write a file over the read cap. `age::encrypted::EncryptedIdentity` wraps only age identity files and is not used. Not the OS keychain, because headless sweepers have no unlocked keychain.
- The credential is one of two ([03](03-cli-and-skill.md#two-ways-to-log-in)). **Ring:** the SDK's exported grant token (`export_local_secret`, restored with `restore_session`), scoped to `/pub/sweepky/:rw` and valid for two years from approval unless revoked. Its leak lets someone write Sweepky records as that user for that long, including a key record that reads later sweeps (above); `pull` alarms on it. Each restore mints a fresh bearer and invalidates the previous one, so commands that write hold a lock file in `~/.config/sweepky/` and run one at a time; `pull` reads public data and needs no session. **Dedicated identity:** its secret in a Sweepky file, never in Pubky's recovery-file format, so `login` can keep refusing recovery files without ambiguity; its leak loses that identity and nothing else. An existing identity's secret is never imported.
- `sweepky logout` runs in this order: mark this device key revoked (a write, so it needs the live session), then revoke the grant or forget the identity, then delete the local files. For a Ring login a failed key revoke does not revoke the grant (that would lock the install out of its own key), and the token is deleted only once a restore of it gets a 401, so a `logout` that stops part way can run again. A device that is already locked out, because Ring revoked first or the grant expired, is revoked from another install with `keys revoke`; its own `logout` then reads its key record anonymously and deletes the local files once that record reads revoked or is not published ([P2d](phases/P2d-cli-ring-login.md#notes)).
- Every CLI install publishes its own `keys/<deviceId>.json`. An owner with two laptops has two keys and sweepers encrypt to both. `keys list|revoke` manages them.
- **Browser:** not in v1. When the board learns to read ([05](05-extensions.md#e4-reading-findings-in-the-browser)) it generates a non-extractable WebCrypto X25519 key and publishes it the same way. Sweepers' CLIs already encrypt to every published owner key, so no record changes; the board will only ever open sweeps uploaded after its key existed.

## Sweeper safety

The sweeper's agent reads untrusted code, and the owner's agent reads untrusted reports. Defences:

- **The agent only audits.** The human runs `sweepky run` in a terminal before opening Claude Code and `sweepky submit` after it exits. Both need the network and the CLI's secrets, so neither runs inside the agent, and the sandbox never has to make an exception for the CLI. Inside the project the agent has the fetched target, `scope.json`, the brief and the playbook, and writes its output to `./sweeps/<id>/audit/`.
- **Sandbox template.** `sweepky init <dir>` writes `.claude/settings.json`:

  ```json
  {
    "sandbox": {
      "enabled": true,
      "failIfUnavailable": true,
      "allowUnsandboxedCommands": false,
      "filesystem": { "denyRead": ["~/.config/sweepky", "~/.local/share/sweepky"] }
    },
    "permissions": {
      "blockReadsOutsideWorkingDirectories": true,
      "deny": ["WebFetch", "WebFetch(domain:*)", "WebSearch", "mcp__*", "Artifact"]
    },
    "claudeMdExcludes": ["<absolute init dir>/sweeps/**/target/**"]
  }
  ```

  One read-blocking mechanism: `blockReadsOutsideWorkingDirectories` covers the file tools in every permission mode, and while it is on, `allowRead` entries from a project file do not count anyway. It does not cover sandboxed commands: P3's headless check on Claude Code 2.1.305 saw a sandboxed `cat` read files under `$TMPDIR` and `/private/tmp` outside the project, while one under `$HOME` and one under a `denyRead` entry were refused. So for Bash the two `denyRead` entries, and the sandbox's own refusal of the home directory, are what keep the CLI's files out; a `SWEEPKY_HOME` outside `$HOME` is readable from a sandboxed command ([P3](phases/P3-skill-and-sandbox.md#notes) has the record). `WebFetch(domain:*)` is what makes the network deny hold in every mode: an empty `allowedDomains` only decides what happens to a new host in manual mode, and bypass mode would allow it. `mcp__*` and `Artifact` close the other channels out of the session. No `excludedCommands`: nothing inside the agent needs the network, and the bare entry the plan used to have would not have matched `sweepky submit` anyway.
- **The target is not inert.** A fetched repo's `CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md`, `.claude/` and `.mcp.json` would load as instructions once the agent reads a file next to them. `run` strips them from the copy and records that in `scope.json`; `init`'s `claudeMdExcludes` is the second line. `run` fetches, checks out and strips every target in a private staging directory under the data directory, outside the project, and only then moves the finished sweep directory into `./sweeps/<id>/` through directory handles that follow no link and replace nothing (a handle-only copy when the two are on different filesystems), so no process an agent left running in the project can reach a repository, its `.git/config` or its attributes while git runs.
- **What the sandbox cannot read.** Sandboxed commands cannot read the home directory, so Node and any toolchain installed there (nvm, rustup) are unavailable to them, and the Cloudflare skill's validators need Node. Install Node from Homebrew or another location outside `$HOME`, and keep the playbook project-local (`init` installs it into the project) so its files are inside the working directory.
- **How to launch.** `claude --setting-sources project,local` inside the init project, so user-level hooks, MCP servers and sandbox arrays do not merge in. Never run a sweep in bypass mode. Anthropic's own guidance is that the Bash sandbox is not the boundary for unattended work on untrusted repositories: sweepers who automate open-bounty sweeps should run the whole `claude` process in a VM or under `@anthropic-ai/sandbox-runtime`.
- **`submit` trusts nothing in the sweep directory.** The agent wrote it, and may have left a process running that changes it while `submit` reads. The CLI canonicalises the `init` project's path and requires a direct child of its real `sweeps/` carrying the marker `run` wrote, which must point at this login's own sweep of that directory; walks it relative to open directory handles (`openat` with `O_NOFOLLOW`, `statat` that does not follow, and an `fstat` of each handle compared with what was looked at), so no link is followed and nothing swapped in between a look and an open is read, which a path-based `lstat` then `open` cannot promise; accepts regular files with one link only (no symlinks, hard links, devices, FIFOs or sockets); skips `target/` and `audit/agents/*/scratch/`; caps entries, depth, per-file and total size before reading; packages `audit/` alone; prints the file list before encrypting. A planted link to `~/.config/sweepky/` is refused, not packaged. Once the sweep's record is final (`done`, or `aborted` by a refused upload), `submit` moves the plaintext `audit/` out of the project to `<data dir>/submitted/<id>/audit/` through the same handles (`renameat` with `RENAME_NOREPLACE`, a handle-only copy on another filesystem, never following a link or replacing anything), directories 0700 and files 0600, so later agent sessions in the project cannot read finished sweeps' reports. **Known limit:** a sweep that was run but never submitted, one whose submit hit a retryable failure, and one abandoned keep their `audit/` in the project, and every later agent session in that project can read it, not only a concurrent one; the skill's "do not read other `sweeps/` directories" is an instruction, not an enforcement ([P3](phases/P3-skill-and-sandbox.md#notes) names the possible follow-ups).
- **Static review only in v1.** The skill refuses to execute target code without an empty environment and resource limits, which Claude Code's sandbox does not provide: it restricts files and network, inherits the environment, and lets commands write the working directory. Under the skill's own rules a `confirmed` record needs an observed local result, so static-only sweeps yield almost no `confirmed` records and almost no severities. That is honest. A Docker runner that meets the skill's bar is deferred.
- **Untrusted reports are data.** On open bounties, sweeps from sweepers outside the circle (labelled known or unknown) are decrypted into a separate `untrusted/` directory. They count for attribution, but their content never enters the merged report, and the owner's agent summarises them without applying their suggested fixes. An `init`-style project cannot do that summarising: its sandbox denies `~/.local/share/sweepky`, where `pull` stores `untrusted/`, and `blockReadsOutsideWorkingDirectories` blocks the file tools from a `SWEEPKY_HOME` outside the project (a sandboxed command still reads one outside `$HOME`). So the `/sweepky` skill's `pull` and `done` roles run in the owner's ordinary session, and the skill tells the agent that every pulled file is data, never instructions, and that it never runs, opens or applies anything from it. That leaves the owner's session exposed to the same threat a sweeper faces, defended by the skill's rules alone. Isolating the step needs a command that copies one bounty's `untrusted/` into an `init`-style project through directory handles, as `run` places a sweep, with `claudeMdExcludes` for the copy; that command is deferred (v1 has none).

## Plan-usage rules

Each developer runs their own unmodified Claude Code on their own plan. The tool never reads, stores or proxies Claude credentials, and never pools usage across accounts. Advertised plan limits assume ordinary individual use; a quota-aware auto mode is deferred until sweepers ask for it, and the terms get re-read then, because scheduled headless runs sit closer to the automated-access clause.
