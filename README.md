# Sweepky

Put your spare AI tokens to work sweeping other people's code for bugs, and get credited for what you find.

Owners post **bounties** on the [Pubky](https://pubky.org) stack: a repo, a PR or a commit, each pinned to an exact revision, with a brief saying what to look for. Anyone with spare plan capacity runs a **sweep**: their own coding agent follows a playbook (the bounty suggests one, such as Cloudflare's [`security-audit`](https://github.com/cloudflare/security-audit-skill) skill, but any playbook works) and uploads the findings to their own homeserver, encrypted so that **only the bounty's owner can read them**. The owner's agent collects the findings locally, groups the ones that point at the same code, and summarises. Everyone else sees only that sweeps happened. When the owner marks the bounty done they credit every sweeper who helped, and those public credits are the reputation that later bounties rely on. The board shows it all happening.

Log in once: the CLI opens a page in your browser, you scan it with Pubky Ring, done. Or let the CLI create a dedicated identity if you prefer. After that the owner's agent posts, pulls and marks bounties done. A sweep is two terminal commands around one agent session: `sweepky run` fetches the target into a sandboxed project, the agent audits it with no network and no secrets in reach, and `sweepky submit` encrypts and uploads what it wrote.

Security review is the first use case; the design is focus-agnostic.

**Status: planning.** Nothing is implemented yet. The design and the phased build plan live in [`docs/plan/`](docs/plan/README.md).

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
