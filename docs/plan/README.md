# Sweepky plan

Design docs first, then one file per build phase. Read them in order the first time.

| Doc | What it covers |
|---|---|
| [00-overview.md](00-overview.md) | The concept, the locked decisions, the core loop, the trust model |
| [01-records-and-discovery.md](01-records-and-discovery.md) | Every record and path, target kinds, how clients find sweeps, compatibility rules |
| [02-encryption-and-safety.md](02-encryption-and-safety.md) | What Pubky provides, owner-only encryption and keys, authorship, sweeper sandboxing |
| [03-cli-and-skill.md](03-cli-and-skill.md) | Repo layout, the `sweepky` CLI, the `/sweepky` skill, Rust conventions |
| [04-board.md](04-board.md) | The public web app: landing page and board, stack, views, live-ness, the pubky-app design reference, visual direction |
| [05-extensions.md](05-extensions.md) | Reserved extension points: sats bounties (Paykit), Locks, badges, tags, reading in the browser |
| [06-verification-and-limits.md](06-verification-and-limits.md) | How the whole thing is verified, known limits, source references |

## Phases

| Phase | Builds |
|---|---|
| [P0 bootstrap](phases/P0-bootstrap.md) | Workspace skeleton, CI, tooling |
| [P1a core: records](phases/P1a-core-records.md) | Records, ids, paths, targets, Cloudflare converter, trust labels, feed parser |
| [P1b core: crypto](phases/P1b-core-crypto.md) | Encryption, padding, manifest binding, package envelope, secrets, finding groups |
| [P2 sweepky-cli](phases/P2-sweepky-cli.md) | The `sweepky` binary and the testnet end-to-end test |
| [P3 skill and sandbox](phases/P3-skill-and-sandbox.md) | The `/sweepky` skill and the sweeper sandbox template |
| [P4 board](phases/P4-board.md) | The landing page and the public web board |
| [P5 local demo](phases/P5-local-demo.md) | The reproducible local demo that gates everything after it |

## Vocabulary

| Term | Meaning |
|---|---|
| **Bounty** | A request to sweep one or more pinned targets, posted by an **owner**: a fixed envelope plus a freeform brief |
| **Focus** | What a bounty is looking for: `security` first, but `bugs`, `perf` or anything else |
| **Playbook** | The skill or procedure a sweeper's agent follows. A bounty may suggest one; none is required |
| **Sweep** | One run against a bounty by a **sweeper**'s agent; the result, encrypted so only the owner can read it |
| **Circle** | The roster an admin maintains; the default trust and discovery set |
| **Trust label** | `circle` / `known` / `unknown`, computed per sweep from the roster and credits |
| **Credit** | A sweeper's pubky listed in `credits` on a bounty the owner marked **done**; the reputation source. Every sweeper whose sweep helped is credited, including several who found the same issue, but never the bounty's own owner |
| **Board** | The public web page where anyone watches bounties and sweeps. Findings are read through the owner's agent, never on the board |

## Ground rules for the build

- **Local first, then production.** Everything runs against a local `pubky-testnet` pinned to the same version as the SDK. No production writes, no hosting, no Vibes listing until the local demo (P5) is approved; after that we go straight to the production homeserver. There is no staging step.
- **One phase, one commit set.** Each phase ends validated, simplified, and committed. Commit messages describe the change only.
- **Orchestrate, don't hand-code.** Each phase runs as a multi-agent workflow: implementation workers, then an independent fresh-context verifier that runs the phase's "Done when" checks and reads the diff, then a simplification pass, then the commit. Load the workflow-authoring guidance before writing the first workflow script.
- **Nothing sensitive in the repo.** Committed fixtures are synthetic. The demo uses a real local audit report by path from an environment variable; its content is never committed or uploaded anywhere but the local testnet.
- **Pin everything.** Exact versions for Rust crates and npm packages, listed in [03](03-cli-and-skill.md#dependencies); the Cloudflare skill by its full commit hash. Re-check against the registries before P0 starts.
- **No local checkouts.** Nothing in the build, the tests or the demo reads another repository that happens to be checked out on this machine. Everything is pulled at its pinned version when it is needed: the testnet binary from crates.io, the SDK from the registry, the playbook from its pinned commit, sweep targets from the fixture repo inside this repo or from the pinned SHA upstream. Source references in these docs name upstream tags and commits; fetch them to read them.

## Status

Planning. No code yet. The plan may still change; treat these docs as the source of truth and update them before changing direction.
