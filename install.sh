#!/bin/sh
# Installs the `sweepky` CLI from an official GitHub Release of
# Jasonvdb/sweepky.
#
#   curl --proto '=https' --tlsv1.2 -fsSL \
#       https://github.com/Jasonvdb/sweepky/releases/latest/download/install.sh | sh
#
#   sh install.sh [--version vX.Y.Z] [--to DIR] [--no-attest]
#
#   --version vX.Y.Z  install that release (default: the latest release)
#   --to DIR          install into DIR (default: $HOME/.local/bin)
#   --no-attest       skip the build attestation check described below
#   -h, --help        print this usage
#
# What it does, in order:
#
# 1. Works out the release target from `uname -s` and `uname -m`: macOS or
#    Linux, on arm64/aarch64 or x86_64/amd64. On a Mac with Apple silicon it
#    picks the arm64 build even when this shell runs under Rosetta
#    (`sysctl -n hw.optional.arm64` says 1). Anything else stops with a
#    message; build from source there instead.
# 2. Finds the version: the one --version names, or the latest release, read
#    from where https://github.com/Jasonvdb/sweepky/releases/latest
#    redirects to (one request for its headers; no API call, so no rate
#    limit).
# 3. Downloads sweepky-<tag>-<target>.tar.gz and SHA256SUMS from that release,
#    over https only (curl --proto '=https' --tlsv1.2), into one temporary
#    directory from mktemp, which is removed on every exit, Ctrl-C included.
# 4. Checks the tarball's SHA-256 against its line in SHA256SUMS, with
#    sha256sum or `shasum -a 256`, and stops on a mismatch, a missing line,
#    or when neither tool is there.
# 5. Checks the build attestation, unless --no-attest: when the GitHub CLI
#    (gh) is installed and logged in, `gh attestation verify <tarball> --repo
#    Jasonvdb/sweepky`, and stops if that fails. Without gh, or when gh is
#    not logged in, it prints the command to run by hand and goes on.
# 6. Extracts only sweepky-<tag>-<target>/sweepky, after refusing an archive
#    with any absolute path or `..` in it, and only if it is a regular file.
# 7. Installs it as DIR/sweepky (DIR is created if missing): copied to a
#    temporary name in DIR and made executable; then, once that copy has
#    run and reported the version asked for, renamed over the old one, so
#    DIR never holds a half-written or wrong sweepky. It never uses sudo.
#    Then it prints the path and the version, and how to add DIR to PATH if
#    it is not on it.
#
# The trust model. The checksum proves the tarball is the one SHA256SUMS
# names, and both come from the same release, so it catches a corrupted or
# truncated download, but anyone who could replace the tarball on the
# release could replace SHA256SUMS too. The attestation closes that gap: it
# proves, through GitHub's signed build provenance, that the tarball was
# built by this repository's release workflow from a commit in it, not
# uploaded by hand. Both rest on GitHub and on TLS to github.com.
#
# For testing, SWEEPKY_INSTALL_BASE_URL replaces the download base,
# https://github.com/Jasonvdb/sweepky/releases/download, with an https:// or
# file:// URL under which <tag>/ holds the release's assets. With it set,
# --version is required. It is read from your own environment, so it trusts
# no one new.
#
# POSIX sh with no bashisms, so any sh runs it: dash, bash, busybox.

set -eu

repo=Jasonvdb/sweepky
default_base=https://github.com/$repo/releases/download
latest_url=https://github.com/$repo/releases/latest

say() { printf 'install.sh: %s\n' "$*" >&2; }
die() {
    printf 'install.sh: error: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat << 'EOF'
Installs the sweepky CLI from an official GitHub Release of Jasonvdb/sweepky.

usage: install.sh [--version vX.Y.Z] [--to DIR] [--no-attest]

  --version vX.Y.Z  install that release (default: the latest release)
  --to DIR          install into DIR (default: $HOME/.local/bin)
  --no-attest       skip the check of the build attestation with gh
  -h, --help        print this usage
EOF
}

# True when $1 is a release tag, vX.Y.Z. The `case` first refuses any
# character but v, digits and dots, a newline included, so the one-line grep
# below cannot be fooled by a second line.
is_tag() {
    case $1 in
    '' | *[!v0-9.]*) return 1 ;;
    esac
    printf '%s\n' "$1" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'
}

# ----- Arguments -----

version=""
to_dir=""
attest=true
while [ $# -gt 0 ]; do
    case $1 in
    --version)
        [ $# -ge 2 ] || die "--version needs a value, such as v0.1.0"
        is_tag "$2" || die "--version takes a release tag such as v0.1.0, not '$2'"
        version=$2
        shift 2
        ;;
    --to)
        if [ $# -lt 2 ] || [ -z "$2" ]; then die "--to needs a directory"; fi
        # A relative DIR gets a ./ so that one starting with - is never
        # read as an option by mkdir or cd.
        case $2 in
        /*) to_dir=$2 ;;
        *) to_dir=./$2 ;;
        esac
        shift 2
        ;;
    --no-attest)
        attest=false
        shift
        ;;
    -h | --help)
        usage
        exit 0
        ;;
    *) die "unknown argument '$1' (see --help)" ;;
    esac
done

if [ -z "$to_dir" ]; then
    [ -n "${HOME:-}" ] || die "HOME is not set; choose a directory with --to DIR"
    to_dir=$HOME/.local/bin
fi

base=${SWEEPKY_INSTALL_BASE_URL:-}
if [ -n "$base" ]; then
    [ -n "$version" ] || die "SWEEPKY_INSTALL_BASE_URL is set, so --version vX.Y.Z is required"
else
    base=$default_base
fi
base=${base%/}
# curl may use only these protocols, for the request and any redirect it
# follows: https, plus file for a file:// base. Never plain http.
case $base in
https://*) protocols='=https' ;;
file://*) protocols='=https,file' ;;
*) die "SWEEPKY_INSTALL_BASE_URL must start with https:// or file://" ;;
esac

for tool in curl tar; do
    command -v "$tool" > /dev/null 2>&1 || die "$tool is needed and is not on PATH"
done

# ----- 1. The target -----

os=$(uname -s)
arch=$(uname -m)
case $os in
Darwin)
    os_part=apple-darwin
    # Under Rosetta, uname -m says x86_64 on an Apple silicon Mac. The
    # native build is the one to install there.
    if [ "$(sysctl -n hw.optional.arm64 2> /dev/null || true)" = 1 ]; then
        arch=arm64
    fi
    ;;
Linux) os_part=unknown-linux-musl ;;
*) die "there is no sweepky release for $os; build it from source instead (see the README)" ;;
esac
case $arch in
arm64 | aarch64) arch=aarch64 ;;
x86_64 | amd64) arch=x86_64 ;;
*) die "there is no sweepky release for $os on $arch; build it from source instead (see the README)" ;;
esac
target=$arch-$os_part

# ----- 2. The version -----

if [ -z "$version" ]; then
    # The redirect's Location header ends in /releases/tag/<tag>. `tr -d`
    # drops the carriage returns HTTP headers end in. A failed request
    # leaves `version` empty, which is_tag refuses.
    version=$(curl --proto '=https' --tlsv1.2 -fsSI "$latest_url" | tr -d '\r' |
        sed -n 's|^[Ll][Oo][Cc][Aa][Tt][Ii][Oo][Nn]: *.*/releases/tag/||p' | head -n 1)
    is_tag "$version" ||
        die "could not find the latest release at $latest_url (no network, or no release yet); or pass --version vX.Y.Z"
fi

# ----- 3. Download -----

tmp=$(mktemp -d "${TMPDIR:-/tmp}/sweepky-install.XXXXXX") || die "could not make a temporary directory"
partial=""
cleanup() {
    rm -rf "$tmp"
    if [ -n "$partial" ]; then rm -f "$partial"; fi
}
trap cleanup EXIT
# Turning a signal into an exit runs the EXIT trap, so Ctrl-C cleans up too.
trap 'exit 130' INT
trap 'exit 143' TERM

name=sweepky-$version-$target
tarball=$name.tar.gz
download() {
    curl --proto "$protocols" --tlsv1.2 -fsSL -o "$2" "$1" || die "could not download $1"
}
say "downloading sweepky $version for $target"
download "$base/$version/$tarball" "$tmp/$tarball"
download "$base/$version/SHA256SUMS" "$tmp/SHA256SUMS"

# ----- 4. Checksum -----

# A SHA256SUMS line is "<64 hex digits>  <file name>"; sha256sum writes a `*`
# before the name in binary mode.
expected=$(awk -v f="$tarball" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")
case $expected in
'') die "SHA256SUMS has no line for $tarball; not installing" ;;
*[!0-9a-f]*) die "SHA256SUMS has no single well-formed line for $tarball; not installing" ;;
esac
[ ${#expected} -eq 64 ] || die "SHA256SUMS has no single well-formed line for $tarball; not installing"
if command -v sha256sum > /dev/null 2>&1; then
    actual=$(sha256sum "$tmp/$tarball" | awk '{ print $1 }')
elif command -v shasum > /dev/null 2>&1; then
    actual=$(shasum -a 256 "$tmp/$tarball" | awk '{ print $1 }')
else
    die "neither sha256sum nor shasum is on PATH, so the download cannot be checked; not installing"
fi
[ "$actual" = "$expected" ] ||
    die "$tarball does not match its SHA-256 in SHA256SUMS; not installing (expected $expected, got $actual)"
say "checksum OK: $tarball matches SHA256SUMS"

# ----- 5. Attestation -----

if $attest; then
    if command -v gh > /dev/null 2>&1 && gh auth status > /dev/null 2>&1; then
        say "checking the build attestation with gh"
        gh attestation verify "$tmp/$tarball" --repo "$repo" >&2 ||
            die "the build attestation of $tarball did not verify; not installing"
    else
        say "warning: gh is not installed or not logged in, so the build attestation was not checked."
        say "To check it yourself, download $tarball from the release and run: gh attestation verify $tarball --repo $repo"
    fi
fi

# ----- 6. Extract -----

entries=$(tar -tzf "$tmp/$tarball") || die "could not read $tarball"
# `..` anywhere in a name, not only as a whole component, is refused: no
# release entry has it.
case $entries in
/* | *"
/"* | *..*) die "$tarball holds an absolute path or '..'; not installing" ;;
esac
mkdir "$tmp/x"
tar -xzf "$tmp/$tarball" -C "$tmp/x" "$name/sweepky" || die "$tarball holds no $name/sweepky"
binary=$tmp/x/$name/sweepky
if [ -L "$binary" ] || ! [ -f "$binary" ]; then
    die "$name/sweepky in $tarball is not a regular file; not installing"
fi

# ----- 7. Install -----

mkdir -p "$to_dir" || die "could not create $to_dir; choose another directory with --to DIR"
to_dir=$(cd "$to_dir" && pwd)
[ -w "$to_dir" ] || die "$to_dir is not writable; choose another directory with --to DIR (this script never uses sudo)"
dest=$to_dir/sweepky
# mv onto a directory, or a link to one, would move the binary into it.
[ ! -d "$dest" ] || die "$dest is a directory; not replacing it"
partial=$to_dir/.sweepky.tmp.$$
# Removed first, so cp cannot write through a link left at that name.
rm -f "$partial"
cp "$binary" "$partial"
chmod 755 "$partial"
# Run the copy before it replaces anything: a binary for the wrong machine,
# or one that reports another version, stops here and installs nothing.
reported=$("$partial" --version 2> /dev/null) || die "the downloaded sweepky does not run on this machine; not installing"
[ "$reported" = "sweepky ${version#v}" ] ||
    die "the downloaded sweepky reports '$reported', not sweepky ${version#v}; not installing"
mv -f "$partial" "$dest"
partial=""

echo "installed $dest ($reported)"
case ":${PATH:-}:" in
*":$to_dir:"*) ;;
*)
    echo "$to_dir is not on your PATH. To add it, put this line in your shell's profile:"
    echo "  export PATH=\"$to_dir:\$PATH\""
    ;;
esac
