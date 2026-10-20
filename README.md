# Sweepky

Put your spare AI tokens to work sweeping other people's code for bugs, and get credited for what you find.

Owners post **bounties** on the [Pubky](https://pubky.org) stack: a repo, a PR or a commit, each pinned to an exact revision, with a brief saying what to look for. Anyone with spare plan capacity runs a **sweep**: their own coding agent follows a playbook (the bounty suggests one, such as Cloudflare's [`security-audit`](https://github.com/cloudflare/security-audit-skill) skill, but any playbook works) and uploads the findings to their own homeserver, encrypted so that **only the bounty's owner can read them**. The owner's agent collects the findings locally, groups the ones that point at the same code, and summarises. Everyone else sees only that sweeps happened. When the owner marks the bounty done they credit every sweeper who helped, and those public credits are the reputation that later bounties rely on. The board shows it all happening.

Log in once: the CLI opens a page in your browser, you scan it with Pubky Ring, done. Or let the CLI create a dedicated identity if you prefer. After that the owner's agent posts, pulls and marks bounties done. A sweep is two terminal commands around one agent session: `sweepky run` fetches the target into a sandboxed project, the agent audits it with no network and no secrets in reach, and `sweepky submit` encrypts and uploads what it wrote.

Security review is the first use case; the design is focus-agnostic.

**Status: the build has started.** Nothing is usable yet. The design and the phased build plan live in [`docs/plan/`](docs/plan/README.md); its [phase table](docs/plan/README.md#phases) lists what each phase adds.

## Install

Not yet. The install channel for the `sweepky` CLI is not decided, so there is no command to copy. This section will say how to install it once there is one.

## Known limits

Sweepky's design has limits, listed here as [06](docs/plan/06-verification-and-limits.md#known-limits-say-them-in-the-readme) states them. The landing page links to this list.

- Only the owner can read findings. The circle, and everyone else, sees only that sweeps happened and who was credited.
- Key records are trusted as published. An active operator of the owner's homeserver, or someone holding the owner's leaked grant, can add a reading key; the owner's CLI alarms on keys it did not create and sweepers pin an owner's key set and warn on changes.
- Some identities cannot write `/pub/sweepky/` at all: production's free IP-verified signup tokens, the path Bitkit uses, allow only Paykit and Bitkit paths and 2 MB. `login` explains the 403 and suggests a dedicated identity.
- No age implementation has a published independent audit; some primitives it builds on had point-in-time audits of older versions.
- Metadata is public: paths, timing, padded sizes, recipient count (reveals how many devices the owner has).
- No forward secrecy: the ciphertext is public forever, and whoever holds the owner's key file later can read every sweep encrypted to it. Won't-fix findings stay out of the system. Rust age has no post-quantum recipients yet; `alg` on key records is the migration hook.
- Losing the owner's key file loses sweeps not yet pulled; pulled sweeps are on local disk.
- Production writes are permanent in practice: paths, timing and content hashes stay in the public event history, and anyone may have copied the ciphertext.
- Static review only, and under the Cloudflare skill's own rules a `confirmed` record needs an observed local result, so static-only sweeps yield essentially no `confirmed` records and no severities until a sandboxed runner exists.
- Finding ids are local to a sweep. Grouping by location is a heuristic the owner confirms; a bug reported at two sites is two groups until merged by hand. Untrusted sweeps group like trusted ones, so a stranger's finding can join two findings into one group, and reporting a location is enough to be in its `reportedBy` and proposed for credit. Only their content is kept out of the merged report; the owner confirms the groups and trims the proposal.
- Pro/Max 5-hour windows: a `standard` whole-repo sweep can hit the limit mid-phase; scope with `paths` or use `quick`.
- Open-bounty discovery sees only homeservers on the watch list. Circle members can live on any homeserver. The board additionally needs members' homeservers to have a public domain and TLS.
- Sweepky's checks of the hosts strangers name are advisory. Before it contacts a target's repository host or GitHub's API, the CLI resolves the host and refuses one with an address that is not public. On production, before `pull` reads the storage of any key but the owner's, it checks that the key's pkarr record names one homeserver and, unless that is the owner's own, resolves the homeserver through its pkarr record and refuses one with an address that is not public; `run` and `submit` read a bounty owner's storage without that check. git, reqwest and the Pubky SDK resolve again when they connect, so DNS rebinding, or a pkarr record republished in between, is not caught ([P2b](docs/plan/phases/P2b-cli-sweep.md#notes), [P2c](docs/plan/phases/P2c-cli-pull-done.md#notes)). Requests the CLI sends itself refuse a redirected answer, but only after reqwest has followed the redirect, since pubky 0.16.2 sets no redirect policy; git follows none.
- A dedicated CLI identity on the production homeserver needs a signup token from Pubky's gate, like any other identity.
- Self-credit is ignored, but an owner can still sweep their own bounty with a second identity and credit that one. Nobody can tell an alternate identity from a different person. The defence is that credits count only from owners the reader trusts, and the `known` label shows how many distinct owners the credits came from, so reputation built by one owner reads as `owners: 1`.
- Credits are per bounty, not per finding, so a sweeper's public record says how many bounties they helped on and nothing about severity.
- Each developer runs their own unmodified Claude Code on their own plan. The tool never reads or proxies Claude credentials.

## Layout (planned)

```
crates/sweepky-core/   records, paths, ids, target pinning, encryption, manifest — no I/O
crates/sweepky-cli/    the `sweepky` binary
skills/sweepky/        the /sweepky agent skill + sweeper sandbox template (`sweepky init` copies it into a project)
web/                   the landing page and the board (static, read-only SPA)
fixtures/              synthetic test data
vibe/                  listing for vibes.pubky.app
docs/plan/             design docs and phase plans
```

## License

MIT. See [LICENSE](LICENSE).
