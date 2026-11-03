<!--
Each release's section is written by hand in the PR that bumps the version.
On a tag push, the release workflow requires a section `## [X.Y.Z] - YYYY-MM-DD`
for the tag's version, with a real date: replace "Unreleased" in that
heading with the release date before tagging. The section becomes the
release notes on GitHub.
-->

# Changelog

All notable changes to Sweepky are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - Unreleased

The first release of the `sweepky` CLI, for macOS (Apple silicon and Intel)
and Linux (x86_64 and arm64).

### Added

- Owner commands: `circle create` and `circle add` to choose whose sweeps you
  read, `post` to post a bounty pinned to an exact revision (`--open` also
  accepts sweeps from outside your circle), `pull` to download, decrypt and
  group the findings, and `done` to mark a bounty done and credit the sweepers
  who helped.
- Sweeper commands: `init` to create a sandboxed sweeper project, `run` to
  fetch a bounty's targets into it, and `submit` to encrypt the findings to
  the bounty's owner and upload them.
- `login`, through Pubky Ring or with a dedicated identity (`--identity`),
  plus `logout` and `keys`. Secret files can be wrapped with a passphrase
  (`--passphrase-file`).
- The `/sweepky` agent skill and the sandbox settings `init` copies into a
  project, so your own Claude Code sweeps with no network and no secrets in
  reach.
- The board, a static, read-only web app (`web/`) that shows bounties, sweeps
  and credits as they happen.
- `--testnet` on every command, to use a local Pubky testnet.

[Unreleased]: https://github.com/Jasonvdb/sweepky/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Jasonvdb/sweepky/releases/tag/v0.1.0
