# 01 — Records and discovery

## Records (v1)

All records live under `/pub/sweepky/` on the **writer's own** homeserver. IDs are 13-character Crockford base32 timestamps (`pubky-timestamp`, the format pubky-app-specs uses), so the homeserver's byte-order listings come out chronological; clients validate length and alphabet on parse. Every record has `schemaVersion: 1`. **Nothing from a sweep's findings ever appears in a public record**; `/pub/` is world-readable, so even a severity count on a public repo is a disclosure. The free-text public fields an agent can fill, `title` and `brief` on `post`, are confirmed by the human before the write; `playbook` on a sweep record must match a short name pattern (`^[A-Za-z0-9._/-]{1,64}(@[0-9a-f]{7,40})?$`).

| Path | Writer | Shape |
|---|---|---|
| `circle.json` | admin | `{name, admin, members: [{pubky, label?}]}` — the roster; the default trust set and the default discovery set |
| `keys/<deviceId>.json` | each CLI install, at `login` | `{alg: "age-x25519", recipient: "age1…", label, createdAt, revokedAt: null}` — a sweeper's CLI encrypts to the bounty owner's unrevoked keys |
| `bounties/<id>.json` | owner | see [The bounty post](#the-bounty-post); rewritten by `sweepky done` |
| `bounties/<id>.discovered.json` | owner's CLI, open bounties only | `{sweeps: ["pubky://<sweeper>/pub/sweepky/sweeps/<id>.json", …], cursors: {"<homeserver pk>": "<event id>"}}` — written by `post --open` with the starting feed cursors and an empty list, appended to by `pull` as it finds strangers' sweeps. The board reads this and never reads a feed |
| `sweeps/<id>.json` | sweeper | `{bounty: "pubky://<owner>/pub/sweepky/bounties/<id>.json", targets: ["t1", "t2"], playbook: "<open string>", status: "running"\|"done"\|"aborted", startedAt, finishedAt?, sha256?}` |
| `sweeps/<id>.age` | sweeper | the encrypted sweep package; see [The sweep package](#the-sweep-package) |

Six record kinds. There is no per-finding public record: credit lives on the bounty.

The **trust label** is computed client-side, never stored: `circle` if the sweeper is in the roster; else `known: N` where N is the number of `done` bounties from trusted owners whose `credits` include the sweeper; else `unknown`. A credit that names the bounty's own owner counts for nothing.

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
- **Status and credits.** `status` is `open` or `done`. `sweepky done` sets `done`, `doneAt`, and `credits`: the pubkys of every sweeper whose sweep helped. Several sweepers who reported the same issue before it was fixed are all credited. An abandoned bounty is `done` with an empty `credits`. The owner can rewrite the record later to adjust credits; it is theirs. Two owner installs rewriting at once is last-writer-wins, deliberately.
- **No self-credit.** An owner may sweep their own bounty, and their findings group like anyone's, but `done` never credits them: they resolve the bounty and credit only the other sweepers who helped. The CLI refuses to write the owner's pubky into `credits`. Because anyone can hand-write their own records, the rule that matters is on the read side: the trust label and the board ignore any credit naming the bounty's owner. This stops the trivial case only; see [06](06-verification-and-limits.md#known-limits-say-them-in-the-readme) for alternate identities.
- The post is public. The brief must not contain anything the owner would not put in a public issue. Credits reveal only "this sweeper helped on this bounty", never which finding or how severe.

## The sweep package

The encrypted `.age` payload is **one JSON document**. No archive format and no compression: the CLI builds the document, pads it, encrypts it.

```json
{
  "schemaVersion": 1,
  "manifest": {
    "sweeper": "<pubky>",
    "bounty": "pubky://<owner>/pub/sweepky/bounties/<id>.json",
    "targets": ["t1"],
    "targetShas": { "t1": "<sha>" },
    "playbook": "cloudflare/security-audit@c1c8a8c",
    "startedAt": "<timestamp>",
    "finishedAt": "<timestamp>"
  },
  "findings": { "…": "the common findings format below" },
  "attachments": { "REPORT.md": "…", "coverage-ledger.json": "…" }
}
```

| Field | Required | Contents |
|---|---|---|
| `manifest` | yes | binds the package to its record: sweeper, bounty, targets and their SHAs, playbook, timestamps |
| `findings` | yes | the common Sweepky findings format below |
| `attachments` | no | relative file name → UTF-8 text, for whatever else the playbook produced: full reports, coverage ledgers, logs. The CLI collects them under the safety rules in [02](02-encryption-and-safety.md#sweeper-safety): plain files only, no links, scratch and target directories skipped, size caps. Anything that is not text is skipped with a warning |

**Common findings format.** Small on purpose, so any playbook can emit it and owner tooling can group it:

```json
{
  "schemaVersion": 1,
  "playbook": "cloudflare/security-audit@c1c8a8c",
  "findings": [
    {
      "id": "sweep-local-id",
      "title": "…",
      "severity": "critical|high|medium|low|info|null",
      "confidence": "high|medium|low|null",
      "status": "confirmed|needs_validation|rejected",
      "locations": [ { "file": "src/auth/session.rs", "line": 120, "kind": "sink", "scope": "fn validate" } ],
      "description": "Markdown",
      "fix": "Markdown or a diff, optional",
      "extra": { }
    }
  ]
}
```

`id` is local to the sweep that produced it. Cloudflare's `fingerprint` is a free-text slug the model writes, constrained only by a format regex, so two independent runs name the same bug differently and may name different bugs alike, and no playbook offers a cross-run key. Dedupe therefore never keys on `id`. The owner's CLI **groups** findings from all sweeps by location: file plus the sink's enclosing scope where the playbook gives one, else line proximity; equal ids are a second hint. It keeps every raw record under its sweep and records `reportedBy: [sweeper, …]` per group in upload order, locally and never published. The owner's agent shows the groups, the owner confirms or splits them, and `sweepky done` proposes credits from them.

`severity` and `confidence` are `null` unless the playbook established them. Cloudflare's schema carries both only on `confirmed` records, and under its own rules a `confirmed` record needs an observed local execution result, so static-only sweeps produce almost none. Owner tooling, the board and `done` all work without severity.

The CLI ships a converter from Cloudflare's `findings.json`, detected by shape (a top-level array whose items carry `verdict` and `fingerprint`): `fingerprint` → `id`, verdict → `status`, `overall_severity` → `severity` (`informational` → `info`) and `confidence.score` → `confidence` on confirmed records only, `locations` from `trace` then `evidence` in order with their `kind` and `scope`, `fix` from the remediation, and the whole original record kept verbatim in `extra.cloudflare` so it can be rebuilt exactly. A sweeper using another playbook has their agent write this format directly, and the `/sweepky` skill carries the schema.

**Attribution and content are two different steps.** Attribution counts every sweep the owner decrypts, trusted or not: an unknown sweeper who reported the same location as a circle member is in that group's `reportedBy` and gets proposed for credit. Content is stricter: only trusted sweeps' findings enter the merged report; untrusted content stays in `untrusted/` ([02](02-encryption-and-safety.md#sweeper-safety)).

## Target kinds and how a sweep is scoped

| Kind | Fields | Scope handed to the playbook |
|---|---|---|
| `pr` | `{repo, number, base, head, mergeBase}` | the diff from the merge base to `head` (three-dot `base...head`, which is what GitHub shows; two-dot `base..head` includes unrelated commits that landed on the base). `post` reads `head` and `base` from GitHub's unauthenticated API and stores the merge base; `run` fetches `head` from the base repository's `refs/pull/<n>/head`, never from the fork. GitHub only in v1 |
| `commit` | `{repo, rev}` | `git diff-tree -p --root <rev>`, which works for a root commit too; for a merge commit, for which that command prints nothing, `git diff-tree -p <rev>^1 <rev>`, so the diff is against the first parent and `scope.json` says so; `run` fetches with depth 2 so the parent is present |
| `repo` | `{repo, rev, paths?}` | the whole tree narrowed to `paths`; the CLI warns if a whole repo has no `paths`, because a long run can outlast a 5-hour plan window |

Three kinds, all fetched with git: https only, by exact SHA, no submodules, no LFS smudge, credential helpers disabled, into `./sweeps/<id>/target/<tid>/` inside the `init` project. If the pinned SHA is no longer served (a force-push), `run` aborts instead of falling back to a branch tip. A `crate` kind (the published tarball, checksum-verified against the crates.io index, to sweep what ships rather than what is on GitHub) is deferred: it would be the only kind with a non-git fetch path. See [05](05-extensions.md#deferred-with-the-trigger-that-justifies-each).

The CLI writes the scope as a small `scope.json` in the sweep directory. Cloudflare's skill has no machine-readable scope input, so the `/sweepky` skill turns `scope.json` into the plain-words request the playbook expects: the absolute target path, the paths or the diff, the profile, and a new output directory. Cloudflare's skill, for reference, supports scoping to "named paths, one subsystem, one companion domain, or the diff between two source refs".

## Discovery

**Homeservers.** Nobody needs to share one. Every pubky's pkarr record names its homeserver; a client resolves the key, finds the homeserver, and fetches. Writes always go to the writer's own homeserver. An owner on `homeserver.pubky.app`, one sweeper on the same server and another self-hosting all interoperate: the sweeper reads the bounty and the owner's keys from the owner's server and uploads to their own; the owner's `pull` resolves each sweeper and fetches from wherever they live. The only place the homeserver matters is the open-bounty feed below.

**Circle.** Poll each roster member's `/pub/sweepky/` every 30–60 s:

- Resolve each member's homeserver once, cache it, and re-resolve hourly or on failure. The pkarr relay is rate-limited per IP. A one-shot `pull` resolves each key once per run, and once more after a read of it fails; re-resolving hourly is for a poller that keeps running, such as the board.
- `pull` lists `bounties/` and `sweeps/` with `reverse=true` and an explicit limit, paging by cursor until an id already seen. The default page is 100 entries and `sweeps/` holds two files per sweep, so an unpaged list silently stops at 50 sweeps. A 404 on a listing means the directory is empty, not that the member is unreachable. `keys/` is read where it is used: `pull` reads the owner's own for the alarm, and `submit` reads a bounty owner's to encrypt to.
- A listing returns names only, so a status change inside a record needs a re-GET. Re-fetch only records that can still change: open bounties and `running` sweeps, with `If-None-Match`, so unchanged records answer 304.
- Credits ride on the bounty records, so reputation needs no extra fetch. For a circle of under ~30 this stays cheap, and a sweep takes an hour, so 30 s is live.

Event streams (the SDK's non-live `/events-stream`, up to 50 users per request with a path filter) are Pubky's documented pattern for watching known users and the upgrade listed in [05](05-extensions.md#deferred-with-the-trigger-that-justifies-each). v1 polls because it needs no per-user cursors. A multi-user stream returns 404 if any listed user has no account on that homeserver; a user who moved merely goes silent there.

**Open bounties.** The owner's CLI follows the homeserver's all-users public events feed for each homeserver on a small **watch list** (default: the production homeserver; under `--testnet`, the local testnet homeserver). Only the CLI does this; the board reads what the CLI publishes.

- Endpoint: `GET /events/?cursor=<c>&limit=<n>`, sent with the SDK's HTTP client to `https://<homeserver pk>/events/` so watch-list entries stay pubkeys and work on the testnet. Plain text, one `PUT|DEL pubky://<user>/<path>` per line and a `cursor: <next>` line that must not be assumed last; an empty body means caught up. `limit` caps at 1000 silently, so loop while a page is full. No SDK wrapper exists for this all-users feed, so `sweepky-core` parses it.
- Filter for `/pub/sweepky/sweeps/*.json` PUTs. One sweep produces several PUTs (`running`, then `done`, plus the `.age`), so dedupe by URI; a DEL removes the sweep. The feed is a hint only: re-fetch each record through pkarr-resolved public storage for that user, never from the feed's host, because a homeserver can return any bytes for a path. Keep records whose `bounty` URL is one of ours and whose sweeper is not in the roster.
- **Starting cursor.** The default cursor is the beginning of history and the feed has no "latest" shortcut, so `post --open` finds the current head once and stores it in `bounties/<id>.discovered.json`. On the owner's own homeserver: a non-live SDK event stream for the owner, path the bounty's own `/pub/sweepky/bounties/<id>.json`, `reverse`, `limit 1`, right after the bounty PUT returns the global event id of that write. On any other watched homeserver: exponential then binary search with `?cursor=c&limit=1`, where an empty body means `c` is at or past the head; about 2 × log2(head) tiny requests, around 50 for event ids near 10^7, once. That is more than the feed's burst, so the search is paced to its rate limit ([06](06-verification-and-limits.md#production-homeserver-as-deployed-on-2026-10-15)). Every consumer then starts at bounty creation, not at zero and not at "now".
- `pull` advances a cursor only after the whole batch is processed, persists cursors locally per homeserver, and appends every sweep it accepts to `bounties/<id>.discovered.json`, which is the one public write `pull` makes. That write also sets the file's cursors to the ones this install has read to, so another install of the owner with no cursor of its own reads on from there and finds the sweeps before them in the file's list ([P2c](phases/P2c-cli-pull-done.md#notes)).
- Known gap: a sweeper on a homeserver not on the watch list is not seen. That is the credible-exit trade-off; the watch list is a config entry the owner can extend.

**Never an indexer of our own.** Publishing `discovered.json` is the owner publishing their own data about their own bounty. Nexus cross-app tags (`/pub/sweepky/tags/<id>` tagging the bounty URL) are the later addition for cross-homeserver coverage ([05](05-extensions.md#e3-other-showcases-ranked-useful--gimmick)).

## Compatibility rules every client follows

- `schemaVersion` on every record; reject only when the major is greater than supported.
- Open-string enums (`kind`, `status`, `alg`, `method`, `proof.kind`): plain strings with an `as_known()` helper, never closed serde enums.
- Unknown top-level fields: ignore, and preserve on rewrite. `sweepky done` rewrites the bounty, so this rule is exercised from day one.
- Unknown `kind`: skip that record and show a placeholder; never reject the whole feed.
- `keys/*.json` always carries `alg` and `revokedAt` so post-quantum keys can be added later without a migration.
- Pubkys in records are raw z-base32 strings and URLs are `pubky://<z32>/…`. The SDK prints a key as `pubky<z32>` and its resources accept both forms, so `sweepky-core` has a `Pubky` newtype that parses either, validates alphabet and length, and compares by key bytes. Never compare pubky strings.
