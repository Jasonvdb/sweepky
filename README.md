# Sweepky

Put your spare AI tokens to work sweeping code for security bugs, and get paid for what you find.

Owners post **bounties** on the [Pubky](https://pubky.org) stack: a repo, a PR, a commit or a crate, each pinned to an exact revision. Anyone with spare plan capacity runs a **sweep**: their own coding agent runs Cloudflare's [`security-audit`](https://github.com/cloudflare/security-audit-skill) skill locally and uploads the **age-encrypted** findings to their own homeserver. The owner's agent collects and dedupes the findings; the owner reads them on the board after signing in with Pubky Ring. Findings are never public. Confirmed findings earn the sweeper public, owner-signed attestations, the reputation that later bounties pay on.

**Status: planning.** Nothing is implemented yet. The design and the phased build plan live in [`docs/plan/`](docs/plan/README.md).

## Layout (planned)

```
crates/sweepky-core/   records, paths, ids, target pinning, encryption, manifest — no I/O
crates/sweepky-cli/    the `sweepky` binary
skill/sweepky/         the /sweepky agent skill + sweeper sandbox template
web/                   the board (static SPA)
fixtures/              synthetic test data for cross-implementation checks
vibe/                  listing for vibes.pubky.app
docs/plan/             design docs and phase plans
```

## License

MIT. See [LICENSE](LICENSE).
