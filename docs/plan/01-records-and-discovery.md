# 01 — Records and discovery

## Records (v1)

All records live under `/pub/sweepky/` on the **writer's own** homeserver. IDs are timestamp-sortable. Every record has `schemaVersion: 1`. **Nothing agent-written ever appears in a public record**; `/pub/` is world-readable, so even a severity count on a public repo is a disclosure.

| Path | Writer | Shape |
|---|---|---|
| `circle.json` | admin | `{name, admin, members: [{pubky, label?}]}` — the roster; the default trust set and the default discovery set |
| `keys/<deviceId>.json` | each CLI install, at `login` | `{alg: "age-x25519", recipient: "age1…", label, createdAt, revokedAt: null}` — a sweeper's CLI encrypts to the bounty owner's unrevoked keys |
| `bounties/<id>.json` | owner | see [The bounty post](#the-bounty-post); rewritten by `sweepky done` |
| `sweeps/<id>.json` | sweeper | `{bounty: "pubky://<owner>/pub/sweepky/bounties/<id>.json", targets: ["t1", "t2"], playbook: "<open string>", status: "running"\|"done"\|"aborted", startedAt, finishedAt?, sha256?}` |
| `sweeps/<id>.age` | sweeper | the encrypted sweep package; see [The sweep package](#the-sweep-package) |

Five record kinds. There is no per-finding public record: credit lives on the bounty.

The **trust label** is computed client-side, never stored: `circle` if the sweeper is in the roster; else `known: N` where N is the number of `done` bounties from trusted owners whose `credits` include the sweeper; else `unknown`.

Reserved and empty in v1: `payouts/`, `received/`, `disclosures/`, `tags/`, `triage/`.

Sweep records carry `targets` as an array because one run can cover a primary target plus companions.

## The bounty post

A fixed envelope that tools act on, with a freeform brief inside for humans and agents:

```json
{
  "schemaVersion": 1,
  "title": "Auth and session handling before the 0.15 release",
  "focus": "security",
  "brief": "Markdown. What to look for, context, what is out of scope, how to report. No secrets: this is public.",
  "playbook": { "suggested": "cloudflare/security-audit@c1c8a8c", "required": false },
  "targets": [ { "id": "t1", "kind": "repo", "repo": "github.com/org/name", "rev": "<sha>", "paths": ["src/auth/"] } ],
  "open": false,
  "reward": null,
  "status": "open",
  "credits": [],
  "createdAt": "<timestamp>",
  "doneAt": null
}
```

- **Fixed:** `title`, `targets` (pinned), `open`, `status`, `credits`, dates, `reward` (reserved).
- **Freeform:** `brief` (markdown), `focus` (open label; `security` is the first use case, `bugs`, `perf`, anything else is valid), `playbook.suggested` (an open string naming a skill, URL or procedure; `required` is always `false` in v1 and exists only so the field has an obvious shape).
- **Status and credits.** `status` is `open` or `done`. `sweepky done` sets `done`, `doneAt`, and `credits`: the pubkys of every sweeper whose sweep helped. Several sweepers who reported the same issue before it was fixed are all credited. An abandoned bounty is `done` with an empty `credits`. The owner can rewrite the record later to adjust credits; it is theirs.
- The post is public. The brief must not contain anything the owner would not put in a public issue. Credits reveal only "this sweeper helped on this bounty", never which finding or how severe.

## The sweep package

The encrypted `.age` payload is a `tar.zst` containing:

| Entry | Required | Contents |
|---|---|---|
| `manifest.json` | yes | `{sweeper, bounty, targets, targetShas, playbook, startedAt, finishedAt}` — binds the package to its record |
| `findings.json` | yes | the common Sweepky findings format below |
| `attachments/…` | no | anything the playbook produced: full reports, coverage ledgers, logs. Freeform |

**Common findings format.** Small on purpose, so any playbook can emit it and owner tooling can merge it:

```json
{
  "schemaVersion": 1,
  "playbook": "cloudflare/security-audit@c1c8a8c",
  "findings": [
    {
      "id": "stable-fingerprint-for-dedupe",
      "title": "…",
      "severity": "critical|high|medium|low|info",
      "confidence": "high|medium|low",
      "status": "confirmed|needs_validation|rejected",
      "locations": [ { "file": "src/auth/session.rs", "line": 120 } ],
      "description": "Markdown",
      "fix": "Markdown or a diff, optional",
      "extra": { }
    }
  ]
}
```

`id` is the dedupe key across sweeps. The CLI ships a converter from Cloudflare's `findings.json` (its `fingerprint` becomes `id`, its verdict branches become `status`); a sweeper using another playbook has their agent write this format directly, and the `/sweepky` skill carries the schema. `extra` preserves anything playbook-specific.

When the owner's CLI merges sweeps it keeps, locally and never published, `reportedBy: [sweeper, …]` for each `id` in upload order. That list is what `sweepky done` uses to propose credits.

## Target kinds and how a sweep is scoped

| Kind | Fields | Scope handed to the playbook |
|---|---|---|
| `pr` | `{repo, number, base, head}` | diff `base..head` on the `head` checkout |
| `commit` | `{repo, rev}` | diff `rev^..rev` |
| `repo` | `{repo, rev, paths?}` | the whole tree narrowed to `paths`; the CLI warns if a whole repo has no `paths`, because a long run can outlast a 5-hour plan window |
| `crate` | `{name, version, sha256}` | the published tarball, checksum-verified against the crates.io index: sweep what ships, not what is on GitHub |

The CLI writes the scope as a small `scope.json` in the sweep directory; the `/sweepky` skill tells the agent to pass it to whichever playbook it uses. Cloudflare's skill, for reference, supports scoping to "named paths, one subsystem, one companion domain, or the diff between two source refs".

## Discovery

**Circle.** Poll each roster member's `/pub/sweepky/` (`bounties/`, `sweeps/`, `keys/`) every 30–60 s. Credits ride on the bounty records, so reputation needs no extra fetch. For a circle of under ~30 this is a handful of requests, and a sweep takes an hour, so 30 s is live. Event streams are deferred: the SDK has no auto-reconnect, a 50-user cap per stream, and returns 404 if any listed user moved homeserver.

**Open bounties.** Follow the homeserver's all-users public events feed for each homeserver on a small **watch list** (default: the production homeserver; in dev, the local testnet homeserver).

- Endpoint: `GET <homeserver>/events/?cursor=<c>&limit=<n>`. Plain text, one `PUT|DEL pubky://<user>/<path>` per line, then a `cursor: <next>` line. Public paths only. No SDK wrapper exists, so `sweepky-core` parses it and the CLI and board fetch it over HTTP.
- Filter for `/pub/sweepky/sweeps/*.json` PUTs, fetch the record, keep those whose `bounty` URL is one of ours and whose sweeper is not in the roster.
- Persist the cursor per homeserver. The default cursor `0` is the beginning of history, so P2 must find a cheap "current cursor" (inspect the homeserver's `EventsService::parse_cursor` / `EventCursor`; fallback: page once with a large `limit` and persist).
- Known gap: a sweeper on a homeserver not on the watch list is not seen. That is the credible-exit trade-off; `sweepky watch --add-homeserver <pk>` extends the list.

**Never an indexer of our own.** Nexus cross-app tags (`/pub/sweepky/tags/<id>` tagging the bounty URL; Nexus ingests cross-app tags with any URL as `uri`) are the later addition for cross-homeserver coverage, once the Nexus query side is verified live.

## Compatibility rules every client follows

- `schemaVersion` on every record; reject only when the major is greater than supported.
- Open-string enums (`kind`, `status`, `alg`, `method`, `proof.kind`): plain strings with an `as_known()` helper, never closed serde enums.
- Unknown top-level fields: ignore, and preserve on rewrite. `sweepky done` rewrites the bounty, so this rule is exercised from day one.
- Unknown `kind`: skip that record and show a placeholder; never reject the whole feed.
- `keys/*.json` always carries `alg` and `revokedAt` so post-quantum keys can be added later without a migration.
