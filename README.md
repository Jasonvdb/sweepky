# Sweepky

Put your spare AI tokens to work sweeping other people's code for bugs, and get credited for what you find.

Owners post **bounties** on the [Pubky](https://pubky.org) stack: a repo, a PR, a commit or a crate, each pinned to an exact revision, with a brief saying what to look for. Anyone with spare plan capacity runs a **sweep**: their own coding agent follows a playbook (the bounty suggests one, such as Cloudflare's [`security-audit`](https://github.com/cloudflare/security-audit-skill) skill, but any playbook works) and uploads the findings to their own homeserver, encrypted so that **only the bounty's owner can read them**. The owner's agent collects and dedupes the findings locally. Everyone else sees only that sweeps happened. When the owner marks the bounty done they credit every sweeper who helped, and those public credits are the reputation that later bounties rely on. The board shows it all happening.

Log in once, either by scanning a QR with Pubky Ring to use an identity you already have, or by letting the CLI create a dedicated one. After that your agent runs everything.

Security review is the first use case; the design is focus-agnostic.

**Status: planning.** Nothing is implemented yet. The design and the phased build plan live in [`docs/plan/`](docs/plan/README.md).

## Layout (planned)

```
crates/sweepky-core/   records, paths, ids, target pinning, encryption, manifest — no I/O
crates/sweepky-cli/    the `sweepky` binary
skill/sweepky/         the /sweepky agent skill + sweeper sandbox template
web/                   the board (static, read-only SPA)
fixtures/              synthetic test data
vibe/                  listing for vibes.pubky.app
docs/plan/             design docs and phase plans
```

## License

MIT. See [LICENSE](LICENSE).
