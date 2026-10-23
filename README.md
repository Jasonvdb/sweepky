# Sweepky

Put your spare AI tokens to work sweeping other people's code for bugs, and get credited for what you find.

## How it works

1. An **owner** posts a **bounty** on [Pubky](https://pubky.org): a repo, a PR or a commit, pinned to an exact revision, with a brief saying what to look for.
2. A **sweeper** with spare plan capacity runs a **sweep**. Their own coding agent follows a playbook, such as Cloudflare's [`security-audit`](https://github.com/cloudflare/security-audit-skill) skill, in a sandbox with no network and no secrets in reach.
3. The findings go to the sweeper's own homeserver, encrypted so that **only the bounty's owner can read them**. Everyone else sees only that a sweep happened.
4. The owner pulls the findings. Sweepky groups the ones that point at the same code.
5. When the owner marks the bounty done, they credit the sweepers who helped. Those public credits are the reputation later bounties rely on.

A public board shows bounties, sweeps and credits as they happen. Security review is the first use case, but the design isn't tied to it.

## Status

Every phase of the [build plan](docs/plan/README.md#phases) is merged, and the whole flow runs on a local Pubky testnet. Sweepky hasn't been used against the production homeserver yet. That, hosting the board and the Vibes listing wait on approval of the [local demo](docs/plan/phases/P5-local-demo.md).

## Install

There's no release yet, and the install channel isn't decided. To build the `sweepky` CLI from source:

```sh
cargo build --release -p sweepky-cli --locked
```

The binary is `target/release/sweepky`. `rust-toolchain.toml` picks the Rust version.

## Use it

Log in once. `sweepky login` opens a page in your browser that you approve with Pubky Ring. Or run `sweepky login --identity <name>` to have the CLI create a dedicated identity.

As an owner:

| Command | What it does |
|---|---|
| `sweepky circle create <name>` | Create your circle, the people whose sweeps you read |
| `sweepky circle add <pubky>` | Add someone to your circle |
| `sweepky post <draft.json>` | Post a bounty. Add `--open` to also accept sweeps from outside your circle |
| `sweepky pull` | Download and decrypt new sweeps, and group their findings |
| `sweepky done <bounty-url>` | Mark a bounty done and credit the sweepers who helped |

As a sweeper:

| Command | What it does |
|---|---|
| `sweepky init <dir>` | Create a sandboxed sweeper project |
| `sweepky run <bounty-url>` | Fetch the bounty's targets into the project |
| _(your agent)_ | Run Claude Code in the project and type `/sweepky` |
| `sweepky submit` | Encrypt the findings to the owner and upload them |

Add `--testnet` to any command to use a local Pubky testnet. Run `sweepky --help` or `sweepky <command> --help` for the details.

## Try the local demo

`scripts/demo-local.sh` runs the whole flow on a local testnet with three identities (owner, sweeper and stranger), then serves the board at `http://localhost:5173/board`. It needs `pubky-testnet` 0.16.2, Postgres, pnpm 10.33.0, Node, `jq` and free testnet ports. It checks all of these first and tells you what's missing. See [P5](docs/plan/phases/P5-local-demo.md) for the steps and [06](docs/plan/06-verification-and-limits.md#local-environment-this-machine) for setting up the testnet.

## What's in the repo

| Path | Contents |
|---|---|
| `crates/sweepky-core/` | Records, paths, ids, target pinning, encryption and finding groups. No I/O |
| `crates/sweepky-cli/` | The `sweepky` binary |
| `skills/sweepky/` | The `/sweepky` agent skill and the sandbox template `sweepky init` copies into a project |
| `web/` | The landing page and the board, a static read-only web app |
| `scripts/` | The local demo and its checks |
| `fixtures/` | Synthetic test data and pinned test vectors |
| `docs/plan/` | The design and the phase plans |

## Known limits

The design has limits. [06](docs/plan/06-verification-and-limits.md#known-limits-say-them-in-the-readme) is the source for this list, and the landing page links here.

**Privacy**

- Only the owner can read findings. The circle, and everyone else, sees only that sweeps happened and who was credited.
- Metadata is public: paths, timing, padded sizes and the number of recipients (which reveals how many devices the owner has).
- There's no forward secrecy. The ciphertext is public forever, so whoever later holds the owner's key file can read every sweep encrypted to it. Keep won't-fix findings out of the system.
- Production writes are permanent in practice. Paths, timing and content hashes stay in the public event history, and anyone may have copied the ciphertext.

**Keys and encryption**

- Key records are trusted as published. An active operator of the owner's homeserver, or someone holding the owner's leaked grant, can add a reading key. The owner's CLI alarms on keys it didn't create, and sweepers pin an owner's key set and warn when it changes.
- No age implementation has a published independent audit. Some primitives it builds on had point-in-time audits of older versions.
- Rust age has no post-quantum recipients yet. The `alg` field on key records is the migration hook.
- Losing the owner's key file loses the sweeps not yet pulled. Pulled sweeps are on local disk.

**Identities and credit**

- Some identities can't write `/pub/sweepky/` at all. Production's free IP-verified signup tokens, which Bitkit uses, allow only Paykit and Bitkit paths and 2 MB. `login` explains the 403 and suggests a dedicated identity.
- A dedicated CLI identity on the production homeserver needs a signup token from Pubky's gate, like any other identity.
- Self-credit is ignored, but an owner can sweep their own bounty with a second identity and credit that one. Nobody can tell an alternate identity from a different person. The defence is that credits count only from owners the reader trusts, and the `known` label shows how many distinct owners the credits came from, so reputation built by one owner reads as `owners: 1`.
- Credits are per bounty, not per finding. A sweeper's public record says how many bounties they helped on, not how severe their findings were.

**Findings**

- Sweeps are static review only. Under the Cloudflare skill's own rules, a `confirmed` record needs an observed local result, so static-only sweeps produce almost no `confirmed` records and no severities until a sandboxed runner exists.
- Finding ids are local to a sweep. Grouping by location is a heuristic the owner confirms, and a bug reported at two places is two groups until merged by hand.
- Untrusted sweeps group like trusted ones. A stranger's finding can join two findings into one group, and reporting a location is enough to be listed in its `reportedBy` and proposed for credit. Only their content is kept out of the merged report. The owner confirms the groups and trims the proposal.
- On Claude Pro or Max, a `standard` whole-repo sweep can hit the 5-hour usage limit mid-phase. Narrow it with `paths` or use `quick`.

**Discovery and network**

- Open-bounty discovery sees only homeservers on the watch list. Circle members can be on any homeserver. The board also needs members' homeservers to have a public domain and TLS.
- Sweepky's checks of hosts that strangers name are advisory. The CLI refuses a repository host that resolves to a non-public address. On production, `pull` does the same for every homeserver it reads other than the owner's. `run` and `submit` read a bounty owner's storage without that check. git, reqwest and the Pubky SDK resolve the name again when they connect, so DNS rebinding, or a pkarr record republished in between, isn't caught. The CLI refuses redirected answers, but only after reqwest has followed the redirect, because pubky 0.16.2 sets no redirect policy. git follows none. See the notes in [P2b](docs/plan/phases/P2b-cli-sweep.md#notes) and [P2c](docs/plan/phases/P2c-cli-pull-done.md#notes).

**Your agent**

- Each developer runs their own unmodified Claude Code on their own plan. Sweepky never reads or proxies Claude credentials.

## License

MIT. See [LICENSE](LICENSE).
