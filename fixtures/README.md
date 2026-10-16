# Fixtures

Synthetic test data for the Rust tests in `crates/` and the TypeScript tests in `web/`. So far it holds `trust-labels.json` and `discovered.json`. The rest of [P1a](../docs/plan/phases/P1a-core-records.md) adds the Cloudflare-shaped `findings.json` and the small bare git repository the CLI's target tests fetch from, and [P1b](../docs/plan/phases/P1b-core-crypto.md) adds the synthetic run directories.

Nothing real lands here. Every pubky, id and finding is made up for the test that uses it. The local demo's audit report is read from a path in an environment variable and is never committed ([P5](../docs/plan/phases/P5-local-demo.md#inputs-environment-never-committed)).

| File | What it is | Loaded by |
|---|---|---|
| [`trust-labels.json`](trust-labels.json) | A roster, bounties with credits, and the trust label and credit tally every pubky in it should get | P1a's trust-label test (Rust), P4's trust-badge test (TypeScript) |
| [`discovered.json`](discovered.json) | An open bounty's discovered-sweeps file: two strangers' sweeps and the feed cursors of two homeservers | P1a's `Discovered` round-trip test (Rust) |

## `trust-labels.json`

The trust-label rule has two implementations: the Rust one in `sweepky-core`, which the CLI uses, and the TypeScript one in the board. [P1a](../docs/plan/phases/P1a-core-records.md)'s Rust test and [P4](../docs/plan/phases/P4-board.md)'s TypeScript test both load this file and assert the label and both counts of every `expected` entry, so the CLI and the board agree on every case it covers. When you change this file, update the tables below and make both tests pass in the same change.

### Shape

```json
{
  "roster": { "schemaVersion": 1, "name": "…", "admin": "<pubky>", "members": [{ "pubky": "<pubky>", "label": "A" }] },
  "bounties": [{ "id": "<13-char id>", "owner": "<pubky>", "status": "done|open", "credits": ["<pubky>"] }],
  "expected": { "<pubky>": { "label": "circle|known|unknown", "bounties": 0, "owners": 0 } }
}
```

- `roster` is a full `circle.json` record as [01](../docs/plan/01-records-and-discovery.md#records-v1) defines it. The admin is also listed in `members`.
- A `bounties` entry, `{id, owner, status, credits}`, is a reduced test shape, not the bounty record from [01](../docs/plan/01-records-and-discovery.md#the-bounty-post). The real record has no `owner` or `id` field, because both come from its path (`pubky://<owner>/pub/sweepky/bounties/<id>.json`). This file inlines them so one file holds the whole case. `credits` is always present and can be empty.
- `expected` has exactly one entry per pubky in the file, circle members included.

Pubkys are random Ed25519 public keys in raw z-base32, generated for this file with the private keys discarded. None is a real identity or the testnet homeserver's key. Ids are synthetic `pubky-timestamp` values from August to October 2026.

### The rule

The rule comes from [01](../docs/plan/01-records-and-discovery.md#records-v1), plus the owner count that [00](../docs/plan/00-overview.md#trust-model-the-circle-is-a-default-not-the-protocol) adds to the `known` label. Only credits from trusted owners count, and in v1 the trusted owners are the roster's members. For each pubky:

- `bounties` is the number of `done` bounties whose owner is a roster member and whose `credits` name the pubky. A credit that names the bounty's own owner counts for nothing.
- `owners` is the number of distinct owners among those bounties.
- `label` is `circle` if the pubky is in the roster, else `known` if `bounties` > 0, else `unknown`.

"In the roster" and "roster member" mean listed in `members`: `admin` alone does not make a pubky a member, for the label or for counting an owner as trusted. `Circle::is_member` in `sweepky-core` applies this rule and P4's TypeScript badge must apply the same one; this file lists its admin in `members`, so it cannot catch the two disagreeing.

The status and owner filters belong in the trust-label function, not in its caller: each test passes the function the whole `bounties` list, including the open bounties and the bounty from an owner outside the roster.

### Who is who

| Pubky (first 8 characters) | Role | Expected label, bounties / owners |
|---|---|---|
| `ybymzxgk` A | admin, also a member | `circle`, 0 / 0 |
| `btyoe954` B | member | `circle`, 1 / 1 |
| `5ymaqd61` D | member | `circle`, 1 / 1 (2 / 2 would mean the self-credit counted) |
| `z5quft98` X | owner outside the roster | `unknown`, 0 / 0 |
| `a8fyof86` S1 | sweeper | `known`, 2 / 2 (3 / 3 would mean X's credit counted) |
| `kmjs3ec6` S2 | sweeper | `known`, 2 / 2 |
| `qwujy4ep` S3 | sweeper | `unknown`, 0 / 0 (`known`, 1 / 1 would mean X's credit counted) |
| `3rus98p3` S4 | sweeper | `known`, 2 / 1 (3 / 1 would mean the duplicate credit counted) |

### Cases covered

| Case | Where | What it checks |
|---|---|---|
| Self-credit | D's done bounty `0035JREYBXX7T` credits D and S2 | D's tally gets nothing from it; S2's does |
| Credits from two owners | S1 credited by A and B; S2 by D and A | `owners` counts distinct owners |
| One owner, two bounties | S4 credited by A on two bounties | `bounties` > `owners`, so reputation from one owner reads as `owners: 1` ([06](../docs/plan/06-verification-and-limits.md#known-limits-say-them-in-the-readme)) |
| Duplicate credit | A's done bounty `0035G87EK4XFE` names S4 twice | the tally counts bounties, not credit entries, so S4 stays at 2 / 1 |
| Open bounty with credits | A's open bounty `0035Q0RCGQAHP` credits S3 | credits on a bounty that is not `done` do not count, so S3 stays `unknown` |
| Owner outside the roster | X's done bounty `0035TR7XPGKP0` credits S3 and S1 | a done bounty from an owner who is not a roster member counts for nothing, so S3 stays `unknown` and S1 stays at 2 / 2 |
| Done bounty with no credits | D's `0035R9NS7T33M` | a done bounty with an empty `credits` list adds nothing |
| Circle members credited | B by A, D by B | a roster member is `circle` whatever its tally, and the tally is still counted |

## `discovered.json`

A `bounties/<id>.discovered.json` record as [01](../docs/plan/01-records-and-discovery.md#records-v1) defines it, with the `schemaVersion` that 01 gives every record. It has no bounty id of its own, because on a homeserver the id is in the file's path.

The file is in the form `sweepky-core` writes: keys in raw z-base32 in the sweep URLs and as the `cursors` keys, and each cursor a decimal string. So the Rust test can parse it and check that writing it back gives the same JSON. A test that needs an unknown field adds it in code, which keeps this file in that form.

- The two sweepers are S1 (`a8fyof86`) and S3 (`qwujy4ep`) from `trust-labels.json`: sweepers outside the roster, the only kind discovery adds. The sweep ids are synthetic `pubky-timestamp` values from October 2026.
- The two homeserver keys (`1nepshaq` and `iod35orp`) are random Ed25519 public keys generated for this file with the private keys discarded. Neither is a real homeserver or the testnet homeserver's key. The event ids are made up.
