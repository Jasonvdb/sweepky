#!/bin/sh
# Re-vendors fixtures/cctv-age/: the age test vectors from C2SP's CCTV
# (Community Cryptography Test Vectors), every file of age/testdata at one
# pinned commit, byte for byte. See the `cctv-age` section of
# fixtures/README.md.
#
# Usage: fixtures/fetch-cctv-age.sh   (from any directory; needs curl and tar)
#
# Run by hand only, to move the pin; no test or build step runs it. The tests
# read the vendored copy, so they stay offline.
#
# It downloads one tarball of the repository at the pinned commit, over https,
# into a new temporary directory from mktemp (removed on exit), extracts only
# age/testdata from it, checks that it holds exactly the expected number of
# plain files with plain names, and only then replaces fixtures/cctv-age. It
# runs nothing from the download: the files are only read and copied. It never
# stages or commits anything in this repository.

set -eu

commit=50a8ecf2a220f4c8bdc4f085789b8e85c26829e7
expected_files=147
url="https://codeload.github.com/C2SP/CCTV/tar.gz/$commit"

die() {
	echo "fetch-cctv-age.sh: $*" >&2
	exit 1
}

script_dir=$(cd "$(dirname "$0")" && pwd -P)
out="$script_dir/cctv-age"
case $out in
*/fixtures/cctv-age) ;;
*) die "refusing to write $out: this script lives in fixtures/" ;;
esac

export LC_ALL=C

work=$(mktemp -d "${TMPDIR:-/tmp}/sweepky-cctv-age.XXXXXX")
trap 'rm -rf "$work"' EXIT
trap 'exit 1' HUP INT TERM

# -q, which must come first, skips the caller's ~/.curlrc, so no saved option
# changes what is fetched. https only, on redirects too; fail on an HTTP error
# instead of saving the error page; give up after two minutes or past 64 MiB
# (the tarball is about 2.5 MB).
curl -q --fail --silent --show-error --location \
	--proto '=https' --proto-redir '=https' \
	--max-time 120 --max-filesize 67108864 \
	--output "$work/cctv.tar.gz" "$url"

# GitHub's tarball puts everything under one top directory,
# CCTV-<commit>/. Only */age/testdata/* is extracted, named exactly as that
# member rather than by a wildcard, which GNU tar and bsdtar read
# differently. Both refuse absolute paths and `..` in member names by default.
mkdir "$work/extract"
top="CCTV-$commit"
tar -xzf "$work/cctv.tar.gz" -C "$work/extract" "$top/age/testdata" ||
	die "the tarball has no $top/age/testdata"

# Nothing else may have come out, and the vectors must be plain files with
# plain names: no links, devices, FIFOs or subdirectories, and only letters,
# digits, `_` and `-`, so no name can start an option or escape the directory.
[ "$(ls -A "$work/extract")" = "$top" ] || die "unexpected top-level entries"
[ "$(ls -A "$work/extract/$top")" = age ] || die "unexpected entries beside age/"
[ "$(ls -A "$work/extract/$top/age")" = testdata ] || die "unexpected entries in age/"
src="$work/extract/$top/age/testdata"
[ -d "$src" ] && [ ! -L "$src" ] || die "age/testdata is not a directory"
count=0
# The three patterns cover every name, dot files included; one that matches
# nothing stays as written and is skipped.
for path in "$src"/* "$src"/.[!.]* "$src"/..?*; do
	[ -e "$path" ] || [ -L "$path" ] || continue
	name=${path##*/}
	case $name in
	'' | -* | *[!A-Za-z0-9_-]*) die "unexpected file name: $name" ;;
	esac
	[ -f "$path" ] && [ ! -L "$path" ] || die "not a plain file: $name"
	count=$((count + 1))
done
[ "$count" -eq "$expected_files" ] ||
	die "expected $expected_files files in age/testdata, found $count"

# Every check passed: replace the vendored copy. After the checks above,
# "$src"/* is exactly the checked files. Each is made 0644, whatever mode the
# tarball gave it.
rm -rf "$out"
mkdir "$out"
cp "$src"/* "$out/"
chmod 0644 "$out"/*

echo "fetch-cctv-age.sh: wrote $count vectors from C2SP/CCTV $commit to $out"
echo "fetch-cctv-age.sh: review with: git status fixtures/cctv-age"
