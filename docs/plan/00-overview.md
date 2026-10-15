# 00 — Overview

## What it is

Developers throw their unused AI plan capacity at security bounties. An **owner** posts a bounty: a repo, a PR, a commit or a crate, each pinned to an exact SHA or checksum. A **sweeper** runs `/sweepky` in their own Claude Code, on their own plan; their agent runs Cloudflare's `security-audit` skill against the pinned target and uploads the **age-encrypted** findings to the sweeper's own Pubky homeserver under `/pub/sweepky/`. The owner's agent collects, dedupes and summarises the findings; the human owner watches and reads them on the **board** after signing in with Pubky Ring. The board is also the listing on vibes.pubky.app.

Why many sweeps of the same target are worth it: Cloudflare's README says a single run of the skill found roughly half of what repeated runs found. Independent sweeps by different people are the point, so duplicate sweeps are the product, not waste.

A **circle** (a roster) is the default trust set, but the protocol is open: a bounty can accept sweeps from anyone, and sweepers earn reputation from owner-signed attestations.

## Decisions (locked)

- Readers default to the whole circle; an owner can lock a bounty to owner-only.
- Rust CLI (`sweepky`) + TypeScript board.
- Public repos only in v1.
- Production homeservers once a one-write check confirms `/pub/sweepky/` is allowed there; develop on a local `pubky-testnet`.
- The board signs in with Pubky Ring, with its grant narrowed to `/pub/sweepky/keys/:rw`, the only path it writes in v1.
- Per-device age keys: non-extractable WebCrypto in the browser, a 0600 file for the CLI. Never one pasted identity.
- The circle is the **default** trust and discovery set, not the protocol. Bounties carry `readers` and `open`; sweeps get a client-computed trust label; owners write public attestations when they confirm a finding. Open bounties accept sweeps from anyone, labelled untrusted.
- Discovery for open bounties uses the homeserver's public events feed with a homeserver watch list. No indexer of our own; Nexus tags are a later addition.
- No claims, no locks, no relay of prior sweeps between sweepers. Sweeps are non-exclusive; the owner's agent dedupes by `fingerprint` at read time.
- Run verb is `sweepky run`; the noun is a sweep.

## The loop

1. **Post.** Owner, in Claude Code: "post a bounty for repo X at main, scope the auth module." The agent runs `sweepky post`. The CLI pins SHAs and checksums and refuses non-public repos.
2. **Run.** A sweeper runs `/sweepky`. `sweepky run` picks the target with the fewest sweeps, writes `sweeps/<id>.json` with `status: "running"`, and fetches the pinned target into the sandboxed sweeper project.
3. **Audit.** The skill runs `security-audit` in full-audit mode, scoped by target kind, writing into `./sweeps/<id>/` inside the sweeper project.
4. **Submit.** `sweepky submit` encrypts the canonical files to the readers' current device keys, uploads `sweeps/<id>.age`, and flips the record to `done` (or `aborted`).
5. **Pull.** Owner: "anything new?" `sweepky pull` decrypts new sweeps locally. The agent merges `findings.json` by `fingerprint`, summarises, and drafts fixes. Triage state stays local in v1.
6. **Confirm.** When the owner confirms a finding, `sweepky confirm` writes a public attestation. This is the reputation source.
7. **Close.** `sweepky close <bounty>`.

"The owner's agent manages everything" means the owner never touches JSON, age or Pubky. The board is the spectator surface; the agent is the control surface.

## Trust model: the circle is a default, not the protocol

"Invite-only" was doing four jobs. Each has its own mechanism, so openness is a per-bounty switch rather than a redesign.

| Job | Mechanism | v1 default |
|---|---|---|
| Who can read findings | Encryption to the bounty's `readers` recipient set | `circle`; owner may choose `owner` |
| Whose sweeps the owner reads, and how far the agent trusts them | Per-bounty `open` flag + a **trust label** on every sweep (`circle` / `known: N confirmed across M owners` / `unknown`). Untrusted sweeps are summarised but their `remediation.code_changes` are never applied without a human | `open: false` |
| Whose bounties a sweeper works on | The sweeper's own allowlist (circle by default) + the sandbox | circle |
| How an owner discovers sweeps from strangers | Homeserver events feed (see [01](01-records-and-discovery.md#discovery)) | roster polling |

**Reputation is derived, never declared.** When an owner confirms a finding, their agent writes a public attestation on the owner's homeserver. A sweeper's reputation as seen by a given reader is the set of attestations from owners that reader trusts: in v1 the circle's owners, later owners you follow via Nexus, never a global score. Reputation changes what the agent does by default, not whether the owner can read a report.

**Why not pubky-noise for discovery.** It is a two-party channel whose storage paths derive from both parties' keys, so the reader must already know the writer. Paykit has the same limit: its private-stream intake reads only already-linked counterparties, and introductions happen out of band. Noise is for conversation after the introduction, not for the introduction.
