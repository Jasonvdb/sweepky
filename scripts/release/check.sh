#!/usr/bin/env bash
# The release workflow's first gate: works out which release a run is for,
# refuses a tag that must not be released, and writes the release notes.
#
#   scripts/release/check.sh NOTES_FILE
#
# Environment:
#
#   IS_RELEASE  `true` for a release run (a pushed tag), anything else for a
#               dry run. The workflow sets it.
#   TAG         the pushed tag, read only when IS_RELEASE is true.
#
# On success it writes the notes to NOTES_FILE and prints, on standard output,
# the lines the workflow appends to $GITHUB_OUTPUT:
#
#   tag=vX.Y.Z
#   is_release=true|false
#   source_date_epoch=<the checked-out commit's time>
#
# Errors go to standard error, as GitHub `::error::` annotations, and exit 1.
#
# What it checks:
#
# - Both crates inherit [workspace.package] version, so there is exactly one
#   version, the one `sweepky --version` prints, and it is a plain X.Y.Z.
# - On a release run: the tag is exactly vX.Y.Z and equals v<version>, and the
#   checked-out (tagged) commit is already on main, so a release is built only
#   from reviewed code. That needs the whole history (the workflow checks out
#   with fetch-depth 0) and fetches main from `origin`.
# - CHANGELOG.md has exactly one `## [X.Y.Z] - YYYY-MM-DD` heading with a real
#   date. A dry run also accepts `Unreleased` for the date, the state between
#   the version bump and the tag, with a warning.
# - That section has a body; the body, followed by the fixed "Verify this
#   release" block, becomes the release notes.
#
# It runs on the workflow's Linux runner, and also on macOS to try a CHANGELOG
# edit locally before pushing: `IS_RELEASE=false scripts/release/check.sh
# /tmp/notes.md` (a dry run needs no tag and no fetch).

set -euo pipefail

[ $# -eq 1 ] || {
    echo "usage: scripts/release/check.sh NOTES_FILE" >&2
    exit 2
}
notes=$1

die() {
    echo "::error::$*" >&2
    exit 1
}

# Prints DAY back when it is a real calendar date, with GNU date on Linux
# and BSD date on macOS; prints nothing for a date like 2026-02-30.
normal_date() {
    date -u -d "$1" +%F 2> /dev/null || date -u -j -f %F "$1" +%F 2> /dev/null || true
}

repo=$(cd "$(dirname "$0")/../.." && pwd -P)
cd "$repo"

release=false
[ "${IS_RELEASE:-}" = true ] && release=true

version=$(cargo metadata --no-deps --format-version 1 |
    jq -r '[.packages[].version] | unique | if length == 1 then .[0] else "several" end')
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
    die "the workspace version is '$version', not one plain X.Y.Z"

if $release; then
    tag=${TAG:-}
    [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
        die "tag '$tag' is not vX.Y.Z; release tags have no prefix or suffix"
    [ "$tag" = "v$version" ] ||
        die "tag $tag does not match the workspace version $version in Cargo.toml"
    # The repository is public, so this fetch needs no token.
    git fetch --quiet --no-tags origin +refs/heads/main:refs/remotes/origin/main
    git merge-base --is-ancestor HEAD origin/main ||
        die "tag $tag points at $(git rev-parse HEAD), which is not on main"
else
    # A dry run tests the version the next release would have.
    tag=v$version
fi

# The lines that start with `## [X.Y.Z]` are found with a plain string match,
# so the dots in the version need no escaping.
heading=$(awk -v start="## [$version]" 'index($0, start) == 1' CHANGELOG.md)
[ -n "$heading" ] || die "CHANGELOG.md has no '## [$version] - YYYY-MM-DD' section"
[ "$(printf '%s\n' "$heading" | wc -l)" -eq 1 ] ||
    die "CHANGELOG.md has more than one section for $version"
dated='^ - ([0-9]{4}-[0-9]{2}-[0-9]{2})$'
if [[ "${heading#"## [$version]"}" =~ $dated ]]; then
    day=${BASH_REMATCH[1]}
    [ "$(normal_date "$day")" = "$day" ] ||
        die "CHANGELOG.md dates $version $day, which is not a real date"
elif [ "$heading" = "## [$version] - Unreleased" ] && ! $release; then
    echo "::warning::CHANGELOG.md still says Unreleased for $version; date it before tagging" >&2
else
    die "CHANGELOG.md's heading for $version is '$heading'; it must be '## [$version] - YYYY-MM-DD'"
fi

# The section's body: every line after the heading up to the next `## `
# heading or the link definitions at the end of the file, without the blank
# lines around it.
awk -v heading="$heading" '
    $0 == heading { on = 1; next }
    on && (/^## / || /^\[.*\]: /) { exit }
    on {
        line[++n] = $0
        if ($0 ~ /[^[:space:]]/) { if (!first) first = n; last = n }
    }
    END { for (i = first; i && i <= last; i++) print line[i] }
' CHANGELOG.md > "$notes"
[ -s "$notes" ] || die "CHANGELOG.md's section for $version is empty"

# The fixed block every release's notes end with: the same commands as
# SECURITY.md's "Verify a download by hand". @TAG@ is replaced after the
# quoted heredoc has kept every $ and backtick as written.
sed "s/@TAG@/$tag/g" >> "$notes" << 'EOF'

## Verify this release

`SHA256SUMS` lists the SHA-256 of every tarball and of `install.sh`, and every tarball and the `sweepky` binary inside it have a build provenance attestation signed by this repository's release workflow. `install.sh` checks the checksum, and the attestation too when the [GitHub CLI](https://cli.github.com/) is installed and logged in. To check a download by hand, run this where the tarball and `SHA256SUMS` are, with the name of the tarball you downloaded (see [SECURITY.md](https://github.com/Jasonvdb/sweepky/blob/@TAG@/SECURITY.md#verify-a-download-by-hand) for what each check proves):

```sh
shasum -a 256 -c --ignore-missing SHA256SUMS      # on Linux: sha256sum -c --ignore-missing SHA256SUMS
gh attestation verify sweepky-@TAG@-aarch64-apple-darwin.tar.gz --repo Jasonvdb/sweepky
```
EOF

# Every file in the tarballs gets this commit's time, so the same commit
# always packs into the same bytes.
echo "tag=$tag"
echo "is_release=$release"
echo "source_date_epoch=$(git log -1 --format=%ct HEAD)"
