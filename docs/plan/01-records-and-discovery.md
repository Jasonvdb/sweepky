# 01 — Records and discovery

## Records (v1)

All records live under `/pub/sweepky/` on the **writer's own** homeserver. IDs are timestamp-sortable. Every record has `schemaVersion: 1`. **Nothing agent-written ever appears in a public record**; `/pub/` is world-readable, so even a severity count on a public repo is a disclosure.

| Path | Writer | Shape |
|---|---|---|
| `circle.json` | admin | `{name, admin, members: [{pubky, label?}]}` — the roster; the default trust set and the default discovery set |
| `keys/<deviceId>.json` | each user, per device | `{alg: "age-x25519", recipient: "age1…", label, createdAt, revokedAt: null}` — strangers publish these too, so an owner can encrypt to anyone |
| `bounties/<id>.json` | owner | `{title, targets: […], profile: "quick"\|"standard"\|"deep", readers: "circle"\|"owner"\|[pubky…], open: false, reward: null, status: "open"\|"closed", createdAt}` |
| `sweeps/<id>.json` | sweeper | `{bounty: "pubky://<owner>/pub/sweepky/bounties/<id>.json", targets: ["t1", "t2"], status: "running"\|"done"\|"aborted", startedAt, finishedAt?, profile, access: {kind: "circle"\|"owner"}, sha256?}` |
| `sweeps/<id>.age` | sweeper | age-encrypted `tar.zst` of the canonical run files; the plaintext starts with `manifest.json` `{sweeper, bounty, targets, targetShas, startedAt, finishedAt}` to bind authorship |
| `attestations/<sweeper>/<fingerprint>.json` | owner | `{bounty, sweep, sweeper, severity, confirmedAt}` — public; written by `sweepky confirm` for a finding the owner has confirmed and acknowledged |

The **trust label** is computed client-side, never stored: `circle` if the sweeper is in the roster, else `known` with counts from trusted owners' `attestations/`, else `unknown`.

Reserved and empty in v1: `payouts/`, `received/`, `disclosures/`, `tags/`, `triage/`.

Sweep records carry `targets` as an array because one audit run can cover a primary target plus companions, matching the skill's own `companion_targets`.

## Target kinds and how the skill is scoped

| Kind | Fields | Scope passed to the skill |
|---|---|---|
| `pr` | `{repo, number, base, head}` | diff `base..head` on the `head` checkout |
| `commit` | `{repo, rev}` | diff `rev^..rev` |
| `repo` | `{repo, rev, paths?}` | full audit narrowed to `paths`; the CLI warns if a whole repo has no `paths`, because a `standard` run can outlast a 5-hour plan window |
| `crate` | `{name, version, sha256}` | the published tarball, checksum-verified against the crates.io index: audit what ships, not what is on GitHub |

The skill supports scoping to "named paths, one subsystem, one companion domain, or the diff between two source refs" and lets the output directory be an explicitly chosen path inside the target when that directory is gitignored.

## Discovery

**Circle.** Poll each roster member's `/pub/sweepky/` (`bounties/`, `sweeps/`, `keys/`, `attestations/`) every 30–60 s. For a circle of under ~30 this is a handful of requests, and a sweep takes an hour, so 30 s is live. Event streams are deferred: the SDK has no auto-reconnect, a 50-user cap per stream, and returns 404 if any listed user moved homeserver.

**Open bounties.** Follow the homeserver's all-users public events feed for each homeserver on a small **watch list** (default: the production homeserver; in dev, the local testnet homeserver).

- Endpoint: `GET <homeserver>/events/?cursor=<c>&limit=<n>`. Plain text, one `PUT|DEL pubky://<user>/<path>` per line, then a `cursor: <next>` line. Public paths only. No SDK wrapper exists, so `sweepky-core` parses it and the CLI and board fetch it over HTTP.
- Filter for `/pub/sweepky/sweeps/*.json` PUTs, fetch the record, keep those whose `bounty` URL is one of ours and whose sweeper is not in the roster.
- Persist the cursor per homeserver. The default cursor `0` is the beginning of history, so P2 must find a cheap "current cursor" (inspect the homeserver's `EventsService::parse_cursor` / `EventCursor`; fallback: page once with a large `limit` and persist).
- Known gap: a sweeper on a homeserver not on the watch list is not seen. That is the credible-exit trade-off; `sweepky watch --add-homeserver <pk>` extends the list.

**Never an indexer of our own.** Nexus cross-app tags (`/pub/sweepky/tags/<id>` tagging the bounty URL; Nexus ingests cross-app tags with any URL as `uri`) are the later addition for cross-homeserver coverage, once the Nexus query side is verified live.

## Compatibility rules every client follows

- `schemaVersion` on every record; reject only when the major is greater than supported.
- Open-string enums (`kind`, `status`, `alg`, `access.kind`, `method`, `proof.kind`): plain strings with an `as_known()` helper, never closed serde enums.
- Unknown top-level fields: ignore, and preserve on rewrite.
- Unknown `kind`: skip that record and show a placeholder; never reject the whole feed.
- `keys/*.json` always carries `alg` and `revokedAt` so post-quantum keys can be added later without a migration.
