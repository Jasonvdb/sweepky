# 00 — Overview

## What it is

Developers throw their unused AI plan capacity at bounties on other people's code. An **owner** posts a bounty: a repo, a PR or a commit, each pinned to an exact SHA, plus a brief saying what to look for. A **sweeper** runs `/sweepky` in their own Claude Code, on their own plan; their agent follows a **playbook** against the pinned target and uploads the findings to the sweeper's own Pubky homeserver under `/pub/sweepky/`, encrypted so that only the bounty's owner can read them. The owner's agent collects, dedupes and summarises the findings locally. The **board** is the public window: anyone can watch bounties appear, sweeps land and bounties get marked done, but findings are never shown there. The board is also the listing on vibes.pubky.app.

**Playbook-agnostic, focus-agnostic.** A bounty may *suggest* a playbook (the default suggestion is Cloudflare's `security-audit` skill) but never requires one; sweepers use whatever skill they have and declare it in the sweep record. Security review is the first focus; a bounty's `focus` can equally be general bugs, performance or anything else. What every sweep must share is one small common findings format (see [01](01-records-and-discovery.md#the-sweep-package)) so owner tooling works regardless of playbook.

Why many sweeps of the same target are worth it: Cloudflare's README says a single run of their skill found roughly half of what repeated runs found. Independent sweeps by different people are the point, so duplicate sweeps are the product, not waste.

A **circle** (a roster) is the default trust set, but the protocol is open: a bounty can accept sweeps from anyone, and sweepers earn reputation from the credits owners publish when they mark a bounty done.

## Decisions (locked)

- **Only the owner can read findings.** Always. There is no circle-readable mode and no reader list; the only question a sweeper's CLI asks is "whose bounty is this?".
- **The owner reads through the CLI.** The reading key lives in the owner's CLI install. The board is public-only in v1 and never decrypts; reading in the browser is a later addition that changes no record ([05](05-extensions.md#e4-reading-findings-in-the-browser)).
- **Credits are the reputation.** When an owner marks a bounty `done` they list every sweeper whose sweep helped, on the bounty record itself. No per-finding public records.
- Rust CLI (`sweepky`) + TypeScript board.
- Public repos only in v1.
- Production homeservers once a one-write check confirms `/pub/sweepky/` is allowed there; develop on a local `pubky-testnet`.
- Most people log in with the pubky they already have in Ring: `sweepky login` opens a sign-in page in the browser, they scan once, and the agent runs unattended until the grant expires or is revoked. `login --identity` instead creates a dedicated identity with the SDK, for agents, CI, the testnet, or anyone who prefers one. Importing an existing identity's secret into the CLI is refused. One age key per CLI install either way.
- Nobody has to share a homeserver. Each pubky's record names its own; clients resolve and fetch. Only open-bounty discovery is per homeserver.
- The circle is the **default** trust and discovery set, not the protocol. Bounties carry `open`; sweeps get a client-computed trust label. Open bounties accept sweeps from anyone, labelled untrusted.
- Discovery for open bounties uses the homeserver's public events feed with a homeserver watch list. No indexer of our own; Nexus tags are a later addition.
- No claims, no locks, no relay of prior sweeps between sweepers. Sweeps are non-exclusive; the owner's agent dedupes by finding `id` at read time.
- Run verb is `sweepky run`; the noun is a sweep.
- Playbooks are suggested, never required; `focus` is an open label with `security` as the first use case.
- Credits are published when the bounty is done, never per finding, so public credit never points at an unpatched issue.

## The loop

1. **Post.** Owner, in Claude Code: "post a bounty for repo X at main, scope the auth module." The agent runs `sweepky post`. The CLI pins SHAs and refuses non-public repos.
2. **Run.** A sweeper runs `/sweepky`. `sweepky run` picks the target with the fewest sweeps, writes `sweeps/<id>.json` with `status: "running"`, and fetches the pinned target into the sandboxed sweeper project.
3. **Sweep.** The agent follows the playbook (the bounty's suggestion or the sweeper's own), scoped by target kind, writing into `./sweeps/<id>/` inside the sweeper project, and produces the common `findings.json` (directly, or via the CLI's converter for Cloudflare's format).
4. **Submit.** `sweepky submit` builds the package (one JSON document: manifest, findings, text attachments), encrypts it to the owner's published keys plus the sweeper's own, uploads `sweeps/<id>.age`, and flips the record to `done` (or `aborted`).
5. **Pull.** Owner: "anything new?" `sweepky pull` decrypts new sweeps locally. The agent merges findings by `id`, keeping every sweeper who reported each one, summarises, and drafts fixes. Triage stays local.
6. **Done.** When the owner is finished with the bounty, `sweepky done <bounty>` rewrites it with `status: "done"` and `credits`: every sweeper whose sweep helped. The CLI proposes the list from the merged findings and the owner trims it. Two sweepers who found the same issue are both credited. A bounty nobody helped with is done with an empty list.

"The owner's agent manages everything" means the owner never touches JSON, age or Pubky. The board is the spectator surface; the agent is the control surface.

## Trust model: the circle is a default, not the protocol

Reading is not part of the trust model: findings are owner-only whatever the circle says. "Invite-only" was still doing three other jobs, and each has its own mechanism, so openness is a per-bounty switch rather than a redesign.

| Job | Mechanism | v1 default |
|---|---|---|
| Whose sweeps the owner reads, and how far the agent trusts them | Per-bounty `open` flag + a **trust label** on every sweep (`circle` / `known: N credits across M owners` / `unknown`). Untrusted sweeps are summarised but their suggested fixes are never applied without a human | `open: false` |
| Whose bounties a sweeper works on | The sweeper's own allowlist (circle by default) + the sandbox | circle |
| How an owner discovers sweeps from strangers | Homeserver events feed (see [01](01-records-and-discovery.md#discovery)) | roster polling |

**Reputation is derived, never declared.** When an owner marks a bounty done, their agent rewrites the bounty record, which only the owner's session can write to, with the sweepers it credits, so anyone can verify the owner really issued the credit. A sweeper's reputation as seen by a given reader is the number of done bounties crediting them from owners that reader trusts: in v1 the circle's owners, later owners you follow via Nexus, never a global score. Reputation changes what the agent does by default, not whether the owner can read a report.

Why credit per bounty and not per finding: a per-finding record would name the bounty, the severity and the fix date, which tells the world what was wrong in a public repo. A credit says only "this sweeper helped on this bounty". It also needs no new record type: it is a field on something the owner already owns and already rewrites.

**Why not pubky-noise for discovery.** It is a two-party channel whose storage paths derive from both parties' keys, so the reader must already know the writer. Paykit has the same limit: its private-stream intake reads only already-linked counterparties, and introductions happen out of band. Noise is for conversation after the introduction, not for the introduction. Why it is not used for the encryption either is in [02](02-encryption-and-safety.md#what-pubky-gives-us-and-the-one-gap).
