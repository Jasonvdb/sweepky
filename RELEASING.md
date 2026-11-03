# Releasing Sweepky

This is the maintainer's guide to publishing a release of the `sweepky` CLI. Users verify what you publish with the steps in [SECURITY.md](SECURITY.md).

A release is a Git tag `vX.Y.Z`. Pushing the tag runs [`.github/workflows/release.yml`](.github/workflows/release.yml), which builds, tests and publishes the release. Nothing becomes public until every gate has passed. You never build or upload anything by hand.

## What a release contains

Each release has binaries for four targets. Each one is built natively on a GitHub-hosted runner of its own OS and architecture, so nothing is cross-compiled.

| Platform | Target | Runner |
|---|---|---|
| Linux, x86_64 | `x86_64-unknown-linux-musl` | `ubuntu-24.04` |
| Linux, arm64 | `aarch64-unknown-linux-musl` | `ubuntu-24.04-arm` |
| macOS, Apple silicon | `aarch64-apple-darwin` | `macos-15` |
| macOS, Intel | `x86_64-apple-darwin` | `macos-15-intel` |

The Linux binaries are static (musl), so they run on any distribution. There's no Windows build. [03](docs/plan/03-cli-and-skill.md#releases-and-the-install-channel) records why, and the build settings.

The release on GitHub has six files:

- `sweepky-vX.Y.Z-<target>.tar.gz`, one per target. Each holds one directory, `sweepky-vX.Y.Z-<target>/`, with the `sweepky` binary, `LICENSE`, `README.md` and `CHANGELOG.md`.
- `SHA256SUMS`, the SHA-256 of each tarball and of `install.sh`.
- `install.sh`, the installer. Its name never changes, so `https://github.com/Jasonvdb/sweepky/releases/latest/download/install.sh` always serves the latest one.

Every tarball, and the `sweepky` binary inside it, also gets a build provenance attestation. It ties the file's SHA-256 to this repository, the release workflow and the tagged commit. It's signed through Sigstore with the job's short-lived OIDC token, so there's no signing key to keep. The attestations go to the public Sigstore transparency log, permanently. `install.sh` isn't attested; `SHA256SUMS` covers it.

The release notes are the version's section of [CHANGELOG.md](CHANGELOG.md), followed by a fixed "Verify this release" block.

## Versioning

- Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The tag is exactly `v` and the version, such as `v0.2.1`. There are no pre-release tags: the workflow refuses any other form, and the test `version_is_major_minor_patch` in `crates/sweepky-cli/src/lib.rs` refuses a version that isn't `X.Y.Z`.
- While the version is `0.x`, a minor bump (`0.1.0` to `0.2.0`) may break things, such as a command's flags or a local file's format. A patch bump (`0.1.0` to `0.1.1`) only fixes things. Say what breaks in the CHANGELOG section.
- Two strings never change between releases, whatever the version: the client id `sweepky-cli` and the capability `/pub/sweepky/:rw` (`CLIENT_ID` and `SWEEPKY_CAPABILITY` in `crates/sweepky-cli/src/network.rs`). Saved logins and Ring grants depend on them. See [Two ways to log in](docs/plan/03-cli-and-skill.md#two-ways-to-log-in).
- Public records follow the [compatibility rules](docs/plan/01-records-and-discovery.md#compatibility-rules-every-client-follows) in every release, so older and newer clients can read each other's records.
- Only the latest release is supported. A fix ships in a new release; older releases aren't patched.

## Before the first release

The repository needs one thing set up in GitHub: a tag ruleset for release tags. It's configured in the repository's settings (**Settings > Rules > Rulesets**), not in this repository, so nothing here can check it. It must have these effects on tags that match `v*`:

- Only the repository admin can create one.
- Nobody can update (move) or delete one, the admin included.

A ruleset's bypass list skips every rule in that ruleset. So if the admin role bypasses the creation rule, put the update and deletion rules in a second ruleset with an empty bypass list.

To see which rulesets exist, run:

```sh
gh api repos/Jasonvdb/sweepky/rulesets
```

Nothing else is needed. The workflow uses only the job's own `GITHUB_TOKEN`, and there are no secrets to set up.

## Release checklist

Replace `X.Y.Z` with the new version throughout.

1. Start a branch from the latest `main`.
2. In [Cargo.toml](Cargo.toml), set `version` under `[workspace.package]` to `X.Y.Z`. Both crates inherit it, and it's what `sweepky --version` prints.
3. Refresh `Cargo.lock`, which records the two crates' versions too:

   ```sh
   cargo check --workspace
   ```

   Commit `Cargo.lock` with `Cargo.toml`. Every build in CI runs with `--locked` and fails if the lock file is out of date.
4. In [CHANGELOG.md](CHANGELOG.md):
   - Move the entries under `## [Unreleased]` into a new section, `## [X.Y.Z] - YYYY-MM-DD`, dated the day you plan to tag. Leave an empty `## [Unreleased]` heading above it.
   - The section must not be empty: it becomes the release notes. Use full URLs in it, because the same text is the release page's notes and ships in every tarball.
   - At the bottom, point the `[Unreleased]` link at `compare/vX.Y.Z...HEAD`, and add a `[X.Y.Z]` link to `releases/tag/vX.Y.Z`.
5. If `vibe/vibe.json` is in the repository by then, set its `version` to `X.Y.Z` too.
6. Open a pull request and merge it once its checks pass. A change to `Cargo.toml` also starts a dry run of the Release workflow on the pull request (see [Dry runs](#dry-runs)), and it must pass too.
7. Optional: run a dry run on `main` by hand, from **Actions > Release > Run workflow**, with **verify_tag** left empty. Or run:

   ```sh
   gh workflow run release.yml --repo Jasonvdb/sweepky --ref main
   ```

8. Tag the merge commit and push the tag:

   ```sh
   git fetch origin
   git log -1 --format='%H %s' origin/main    # the merge commit of your pull request
   git tag -a vX.Y.Z -m vX.Y.Z <merge-sha>
   git push origin vX.Y.Z
   ```

   Name the commit explicitly rather than tagging whatever you have checked out. Check the SHA before you push: once the tag is on GitHub, it can't be moved or deleted.
9. Watch the run:

   ```sh
   gh run list --repo Jasonvdb/sweepky --workflow release.yml --event push --limit 1
   gh run watch <run-id> --repo Jasonvdb/sweepky
   ```

10. Confirm that all four `verify` jobs passed. Only then is the release done. The release page should list the six files above, plus the source code archives GitHub adds to every release.

## What each job does

The jobs run in this order. Each one gates the next.

| Job | What it does | A failure means |
|---|---|---|
| `check` | Checks that the tag is `vX.Y.Z`, equals the workspace version, and points at a commit on `main`. Checks that CHANGELOG.md has exactly one `## [X.Y.Z] - YYYY-MM-DD` heading with a real date and a non-empty section, and turns that section into the release notes. The checks are [`scripts/release/check.sh`](scripts/release/check.sh); run `IS_RELEASE=false scripts/release/check.sh /tmp/notes.md` to try a CHANGELOG edit before pushing | The tagged commit isn't releasable: the version, the tag or the CHANGELOG is wrong, or the tag isn't on `main`. The error says which |
| `ci` | Release runs only. Runs [`ci.yml`](.github/workflows/ci.yml) on the tagged commit: fmt, clippy, tests, cargo-deny, shellcheck and the web build and tests | The commit fails a pull request gate. `cargo deny check` reads the RustSec database at run time, so a new advisory can fail a commit that passed on its pull request |
| `build` | Builds each target with `cargo build --profile dist --locked`, with no cache, then runs [`scripts/release/smoke.sh`](scripts/release/smoke.sh) on the binary: `--version`, `--help`, `init`, private file modes and static linking | The target doesn't compile, or its binary fails a smoke check. smoke.sh prints a `FAIL` line for each failed check |
| `e2e` | Runs [`scripts/demo-local.sh`](scripts/demo-local.sh) `--ci` with each built binary: the local demo's whole flow on a local Pubky testnet, with its checks | The binary fails the demo flow, or the test setup failed: installing `pubky-testnet`, starting Postgres, or reading github.com. [P5](docs/plan/phases/P5-local-demo.md#notes) lists the checks |
| `package` | Packs the four tarballs with [`scripts/release/package.sh`](scripts/release/package.sh), and writes `SHA256SUMS` | A target's binary is missing, or packing failed |
| `install` | Runs `install.sh` on each target against the staged files. Also checks that a `SHA256SUMS` with wrong hashes stops the install | install.sh is broken on that platform, or it no longer refuses a bad checksum |
| `publish` | Tag push only. Attests every tarball and binary, creates a draft release, uploads the files, then makes the release public | GitHub refused a step. See [When a run fails](#when-a-run-fails) |
| `verify` | Tag push only, on fresh runners with no checkout. Installs from the public release with the one-line `install.sh` command, then checks `SHA256SUMS` and the attestations by hand and runs the binary. Last, checks that the latest-release install command installs this version | The public release doesn't install or verify the way users will do it |

## Dry runs

Every run that isn't a tag push is a dry run. These start one:

- running the workflow by hand with **verify_tag** empty,
- the weekly schedule, Mondays at 05:23 UTC, and
- a pull request that changes the release workflow, `ci.yml`, `install.sh`, `scripts/release/`, `scripts/demo-local.sh`, `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `deny.toml` or `crates/`.

A dry run tests the version in `Cargo.toml` and runs every job up to `install`. It never runs `publish` or `verify`. A dry run also accepts `## [X.Y.Z] - Unreleased` as the CHANGELOG heading, with a warning. The `ci` job runs only on a release: a dry run's commit already ran `ci.yml` when it was pushed or opened as a pull request.

The staged release files are kept as the workflow artifact `release-assets` for 14 days. To inspect them, run:

```sh
gh run download <run-id> --repo Jasonvdb/sweepky --name release-assets
```

## When a run fails

The run's summary page names the failed job, and its log names the failed step.

**Before `publish`, nothing is public.** If the failure is a flake, such as a runner or network error, select **Re-run failed jobs** on the run. If the tagged commit itself is wrong, the tag is used up: it can't be moved or deleted. Fix the problem on `main` and release the next patch version, `X.Y.(Z+1)`. Reuse the unreleased version's CHANGELOG section for it, and add a line saying `vX.Y.Z` was tagged but never released.

**If `publish` fails**, look at the repository's Releases page:

- No release for the tag: select **Re-run failed jobs**.
- A draft release for the tag: delete the draft, then select **Re-run failed jobs**. A re-run can't continue a draft, because `gh release create` refuses a release that exists. A draft was never public, so nobody can have downloaded it. This deletes the release and keeps the tag:

  ```sh
  gh release delete vX.Y.Z --repo Jasonvdb/sweepky --yes
  ```

**If `verify` fails, the release is already public.** If the step that failed waited for the release to be served, or hit a network error, re-run the failed jobs or [re-verify the release](#re-verify-a-release) later. If a checksum or an attestation didn't verify, or the binary didn't run or reported the wrong version, the release is broken.

## If a release is broken

- **Never edit, replace or delete a published release's files, and never move or delete its tag.** People may already have downloaded the files and checked them against `SHA256SUMS` and the attestations. A changed file breaks that, and looks the same as an attack.
- Fix the problem on `main`, and publish the next patch version with the [release checklist](#release-checklist). In its CHANGELOG section, say what was wrong with the broken release and who it affects.
- Mark the broken release in its notes on GitHub: add a warning at the top that names the release that replaces it. The notes are text, not one of the release's files. For example, save the new notes to `notes.md` and run:

  ```sh
  gh release edit vX.Y.Z --repo Jasonvdb/sweepky --notes-file notes.md
  ```

- If the problem is a vulnerability, also follow [SECURITY.md](SECURITY.md).

## Re-verify a release

The `verify` job can run on its own against any published release. Run the workflow by hand from **Actions > Release > Run workflow**, with **verify_tag** set to the release's tag. Or run:

```sh
gh workflow run release.yml --repo Jasonvdb/sweepky --ref main -f verify_tag=vX.Y.Z
```

Only `verify` runs, on all four targets, against the public release. It skips the check that the release is the latest. It uses the workflow from the branch you run it on, so it checks an old release's files with today's checks.

Re-verify a release when someone reports a bad download, when runner images change, or before you point someone at an older version.
