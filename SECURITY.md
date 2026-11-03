# Security

Sweepky handles encryption keys and runs next to coding agents that read untrusted code, so security reports are welcome. This page says which versions get fixes, how to report a vulnerability, and how to check that a `sweepky` binary is an official release.

## Supported versions

Only the latest release gets security fixes. A fix ships in a new release, and older releases aren't patched. To upgrade, install the latest release again.

Sweepky is at `0.x`, so a minor release may change commands or file formats. The release's CHANGELOG section says so when it does.

## Report a vulnerability

Please don't report a vulnerability in a public issue, pull request or discussion.

<!-- Requires private vulnerability reporting to be enabled in repo settings. -->
Report it privately instead: on the repository's [Security tab](https://github.com/Jasonvdb/sweepky/security), select **Report a vulnerability**. Only you and the maintainers can see the report and the conversation that follows.

Include as much of this as you can:

- the version (`sweepky --version`) and your platform,
- what an attacker can do, and what they need first,
- steps to reproduce it, ideally on a local testnet (`--testnet`).

Please test only against a local testnet or your own data. Writes to the production homeserver are permanent in practice, and other people's records aren't yours to test on.

The README lists the design's [known limits](README.md#known-limits). They aren't vulnerabilities in themselves, but a way around one that the README doesn't describe is worth reporting.

## Verify a download by hand

Every release on [GitHub Releases](https://github.com/Jasonvdb/sweepky/releases) has one tarball per platform, a `SHA256SUMS` file and `install.sh`. Every tarball, and the `sweepky` binary inside it, has a build provenance attestation.

Pick the tarball for your platform:

| Platform | Tarball |
|---|---|
| macOS, Apple silicon | `sweepky-vX.Y.Z-aarch64-apple-darwin.tar.gz` |
| macOS, Intel | `sweepky-vX.Y.Z-x86_64-apple-darwin.tar.gz` |
| Linux, x86_64 | `sweepky-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz` |
| Linux, arm64 | `sweepky-vX.Y.Z-aarch64-unknown-linux-musl.tar.gz` |

The steps below need `curl` and the [GitHub CLI](https://cli.github.com/) (`gh`), logged in with `gh auth login`. Replace the version and the target with yours.

1. Download the tarball and `SHA256SUMS` into an empty directory:

   ```sh
   version=v0.1.0
   file=sweepky-$version-aarch64-apple-darwin.tar.gz
   base=https://github.com/Jasonvdb/sweepky/releases/download/$version
   curl --proto '=https' --tlsv1.2 -fsSL -O "$base/$file" -O "$base/SHA256SUMS"
   ```

2. Check the checksum. On macOS, run:

   ```sh
   shasum -a 256 -c --ignore-missing SHA256SUMS
   ```

   On Linux, run:

   ```sh
   sha256sum -c --ignore-missing SHA256SUMS
   ```

   The output must be one line, `<tarball>: OK`. `--ignore-missing` skips the files in `SHA256SUMS` you didn't download. If the output says `no file was verified`, the tarball's name doesn't match a line in `SHA256SUMS`.

3. Check the attestation:

   ```sh
   gh attestation verify "$file" --repo Jasonvdb/sweepky
   ```

   That accepts an attestation from any workflow in the repository. To hold the tarball to the release workflow, for this tag, on a GitHub-hosted runner, as the release workflow's own `verify` job does, run this instead:

   ```sh
   gh attestation verify "$file" --repo Jasonvdb/sweepky \
       --signer-workflow Jasonvdb/sweepky/.github/workflows/release.yml \
       --source-ref "refs/tags/$version" \
       --deny-self-hosted-runners
   ```

4. Extract the binary and install it, for example into `~/.local/bin`:

   ```sh
   tar -xzf "$file"
   mkdir -p ~/.local/bin
   cp "${file%.tar.gz}/sweepky" ~/.local/bin/sweepky
   ~/.local/bin/sweepky --version
   ```

The binary has an attestation of its own, so you can check an installed `sweepky` at any time:

```sh
gh attestation verify "$(command -v sweepky)" --repo Jasonvdb/sweepky
```

The macOS binaries aren't notarized by Apple. If you download a tarball with a web browser, macOS may refuse to run the binary. Downloads with `curl`, as above and in `install.sh`, aren't affected. After you've checked the tarball, you can clear the browser's quarantine flag on the extracted binary with `xattr -d com.apple.quarantine <path to sweepky>`.

### What the checks prove

- **The checksum** proves the tarball is the one `SHA256SUMS` names. It catches a corrupted or truncated download. It doesn't prove where the tarball came from: anyone who could replace the tarball on the release could replace `SHA256SUMS` too.
- **The attestation** proves that a file with this exact SHA-256 was built by a GitHub Actions workflow in `Jasonvdb/sweepky`, from a commit in this repository, and not uploaded by hand. With the extra flags in step 3, it also proves the workflow was the release workflow, run for that tag on GitHub's own runners. The attestation is signed through Sigstore and recorded in its public transparency log.

Neither check proves that the code is free of bugs or was reviewed. The release workflow builds only commits on `main`, but the attestation doesn't say who wrote or approved them. Both checks rest on GitHub, on Sigstore and on TLS to github.com. Someone who controlled the repository's admin account could publish a release that passes both.

## install.sh

`install.sh` installs a release with the same checks. It's attached to every release, and it's the file at the release's tag in this repository.

It does this, in order:

1. Works out your platform from `uname`. On an Apple silicon Mac it picks the arm64 build even under Rosetta. Any other platform stops with a message.
2. Finds the version: the one you pass with `--version`, or the latest release.
3. Downloads the tarball and `SHA256SUMS` over HTTPS only, into a temporary directory it always removes.
4. Checks the tarball against `SHA256SUMS`, and stops on a mismatch.
5. Checks the attestation with `gh attestation verify`, and stops if it fails. If `gh` isn't installed or isn't logged in, it prints the command to run yourself and goes on. `--no-attest` skips this step.
6. Extracts only the `sweepky` binary, after refusing a tarball with an absolute path or `..` in it.
7. Runs the new binary's `--version`, and only if it reports the version asked for, moves it into place as `~/.local/bin/sweepky` (or into `--to DIR`).

It never uses `sudo`, never edits your shell profile, and downloads only from GitHub. If the install directory isn't on your `PATH`, it prints the line to add.

To read `install.sh` before you run it, download it and run it as a file rather than piping it into `sh`:

```sh
version=v0.1.0
base=https://github.com/Jasonvdb/sweepky/releases/download/$version
curl --proto '=https' --tlsv1.2 -fsSL -O "$base/install.sh" -O "$base/SHA256SUMS"
shasum -a 256 -c --ignore-missing SHA256SUMS    # on Linux: sha256sum -c --ignore-missing SHA256SUMS
less install.sh
sh install.sh --version "$version"
```

`install.sh` has no attestation of its own. To check it against the source instead, compare it with the file at the release's tag in a clone of this repository: `git show v0.1.0:install.sh | diff - install.sh` prints nothing when they match.

Its options:

| Option | Does |
|---|---|
| `--version vX.Y.Z` | Install that release. The default is the latest |
| `--to DIR` | Install into `DIR`. The default is `~/.local/bin` |
| `--no-attest` | Skip the attestation check |
| `-h`, `--help` | Print the usage |

The comments at the top of [install.sh](install.sh) describe each step in more detail.
