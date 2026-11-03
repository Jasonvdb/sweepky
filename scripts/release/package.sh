#!/usr/bin/env bash
# Packages one built `sweepky` binary as a release tarball. The release
# workflow runs it on Linux for every target, macOS ones included, so that
# GNU tar and GNU gzip make every tarball the same way.
#
#   scripts/release/package.sh BINARY TARGET TAG OUTDIR
#
#   SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) \
#       scripts/release/package.sh dist/sweepky x86_64-unknown-linux-musl v0.1.0 out
#
# It writes OUTDIR/sweepky-TAG-TARGET.tar.gz (creating OUTDIR if needed) and
# prints its path. The tarball holds one directory, sweepky-TAG-TARGET/, and in
# it:
#
#   sweepky       BINARY, mode 0755
#   LICENSE       from the repository root, mode 0644
#   README.md     the same
#   CHANGELOG.md  the same
#
# It sets the binary's mode itself: a binary downloaded from a GitHub Actions
# artifact has lost its executable bit.
#
# The tarball is deterministic: the same inputs give the same bytes, so anyone
# can rebuild one and compare. Entries are sorted by name, every mtime is
# SOURCE_DATE_EPOCH (required; the release workflow sets it from the tagged
# commit), owner and group are 0 with no user or group names, the format is
# fixed (gnu), and `gzip -n` leaves out the name and time gzip would
# otherwise record. That needs GNU tar for --sort and the owner flags, so on
# any other tar (macOS's bsdtar, say) it stops without writing anything.
#
# TARGET must be one of the four release targets and TAG a vX.Y.Z tag. It
# stages the files in one directory from mktemp, removed on every exit, and
# writes the tarball under a temporary name before renaming it into place, so
# OUTDIR never holds a half-written tarball.

set -euo pipefail

usage() {
    echo "usage: scripts/release/package.sh BINARY TARGET TAG OUTDIR" >&2
    exit 2
}

die() {
    echo "package.sh: $*" >&2
    exit 1
}

[ $# -eq 4 ] || usage
binary=$1
target=$2
tag=$3
outdir=$4

[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "TAG must be vX.Y.Z, not '$tag'"
case "$target" in
aarch64-apple-darwin | x86_64-apple-darwin | x86_64-unknown-linux-musl | aarch64-unknown-linux-musl) ;;
*) die "TARGET must be one of the release targets, not '$target'" ;;
esac
[ -f "$binary" ] || die "$binary is not a file"
[[ "${SOURCE_DATE_EPOCH:-}" =~ ^[0-9]+$ ]] ||
    die "SOURCE_DATE_EPOCH must be set to a Unix time (the tagged commit's: git log -1 --format=%ct)"
tar --version 2> /dev/null | grep -q 'GNU tar' ||
    die "needs GNU tar (for --sort, --owner and --mtime); this tar is: $(tar --version 2>&1 | head -n 1)"

repo=$(cd "$(dirname "$0")/../.." && pwd -P)
for doc in LICENSE README.md CHANGELOG.md; do
    [ -f "$repo/$doc" ] || die "$repo/$doc is missing"
done

name="sweepky-$tag-$target"
mkdir -p "$outdir"
tarball="$outdir/$name.tar.gz"
partial="$tarball.partial"
scratch=$(mktemp -d "${TMPDIR:-/tmp}/sweepky-package.XXXXXX")
# The partial tarball goes too, if tar or gzip failed before the rename.
trap 'rm -rf "$scratch"; rm -f "$partial"' EXIT
# Turning a signal into an exit runs the EXIT trap, so Ctrl-C cleans up too.
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir "$scratch/$name"
cp "$binary" "$scratch/$name/sweepky"
cp "$repo/LICENSE" "$repo/README.md" "$repo/CHANGELOG.md" "$scratch/$name/"
# Every mode set here, rather than left to the umask or to what the inputs
# had, so the tarball is the same on any machine.
chmod 0755 "$scratch/$name" "$scratch/$name/sweepky"
chmod 0644 "$scratch/$name/LICENSE" "$scratch/$name/README.md" "$scratch/$name/CHANGELOG.md"

tar -C "$scratch" \
    --sort=name \
    --mtime="@$SOURCE_DATE_EPOCH" \
    --owner=0 --group=0 --numeric-owner \
    --format=gnu \
    -cf - "$name" | gzip -n -9 > "$partial"
mv -f "$partial" "$tarball"
echo "$tarball"
