#!/usr/bin/env bash
# Smoke-tests one built `sweepky` binary before it is packaged for a release:
# the release workflow runs it on every target, on the same kind of runner the
# binary was built on, and it works the same by hand on macOS or Linux.
#
#   scripts/release/smoke.sh BINARY TAG
#
#   scripts/release/smoke.sh target/dist/sweepky v0.1.0
#
# BINARY is the executable to test and TAG the release tag it is meant for,
# vX.Y.Z. It prints one PASS or FAIL line per check and exits 1 if any check
# failed (2 for a usage error). The checks:
#
# 1. version: `BINARY --version` prints exactly `sweepky X.Y.Z`, the TAG
#    without its `v`. clap prints the command's name, a space and
#    crate::VERSION (crates/sweepky-cli/src/cli.rs and lib.rs), which is
#    `version` from Cargo.toml, so a binary built from the wrong commit fails
#    here.
# 2. help: `BINARY --help` exits 0.
# 3. init: `BINARY --no-input init --no-playbook DIR` exits 0 and writes the
#    sweeper project's files, the ones the binary carries inside itself (the
#    sandbox settings, CLAUDE.md, the /sweepky skill) included. init builds
#    no network client at all (main.rs runs it before one exists) and,
#    with --no-playbook, never runs npx, so it is offline by construction.
#    It writes only into DIR, never under SWEEPKY_HOME.
# 4. private files: `BINARY logout`, with an empty SWEEPKY_HOME, creates the
#    config directory and its writers' lock, the first thing every
#    signed-in command does, then finds no login and exits 1 before it sends
#    any request. Every file it created must be mode 0600 and every
#    directory 0700, and there must be nothing else (no link). It is the
#    command that writes private files with no network at all: `login
#    --identity`, which writes a real identity secret, goes on to sign up on
#    a homeserver, and whether that works depends on whether a local testnet
#    is running. The end-to-end run on the testnet covers those files.
# 5. linkage: on Linux, `ldd` must report a static binary ("not a dynamic
#    executable", or "statically linked"), or `file` must say "statically
#    linked" or "static-pie linked"; the Linux release builds are static
#    musl. On macOS, `otool -L` may list only libraries under /usr/lib/ and
#    /System/, which every Mac has.
#
# Every command runs with SWEEPKY_TESTNET=1, so nothing can reach the
# production network, and with HOME and SWEEPKY_HOME pointing into one
# scratch directory from mktemp, removed on every exit, so the real
# ~/.config/sweepky and ~/.local/share/sweepky are never touched. Written for
# bash 3.2, the one macOS ships, as well as Linux's bash.

set -euo pipefail

usage() {
    echo "usage: scripts/release/smoke.sh BINARY TAG   (TAG is vX.Y.Z)" >&2
    exit 2
}

[ $# -eq 2 ] || usage
binary=$1
tag=$2
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || usage
if ! [ -f "$binary" ] || ! [ -x "$binary" ]; then
    echo "error: $binary is not an executable file" >&2
    exit 2
fi
# An absolute path, so the binary runs the same from any directory.
binary="$(cd "$(dirname "$binary")" && pwd -P)/$(basename "$binary")"

scratch=$(mktemp -d "${TMPDIR:-/tmp}/sweepky-smoke.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
# Turning a signal into an exit runs the EXIT trap, so Ctrl-C cleans up too.
trap 'exit 130' INT
trap 'exit 143' TERM

export SWEEPKY_TESTNET=1
export HOME="$scratch/home"
export SWEEPKY_HOME="$scratch/sweepky-home"
mkdir "$HOME"

failed=0
pass() { echo "PASS  $*"; }
fail() {
    echo "FAIL  $*"
    failed=1
}

# ----- 1. version -----

want="sweepky ${tag#v}"
got=$("$binary" --version < /dev/null 2>&1) || true
if [ "$got" = "$want" ]; then
    pass "version: --version prints '$want'"
else
    fail "version: --version printed '$got', expected '$want'"
fi

# ----- 2. help -----

if "$binary" --help < /dev/null > /dev/null 2>&1; then
    pass "help: --help exits 0"
else
    fail "help: --help exited non-zero"
fi

# ----- 3. init -----

project="$scratch/project"
missing=""
if "$binary" --no-input init --no-playbook "$project" < /dev/null > "$scratch/init.log" 2>&1; then
    for file in .gitignore .claude/settings.json CLAUDE.md .claude/skills/sweepky/SKILL.md .sweepky; do
        [ -f "$project/$file" ] || missing="$missing $file"
    done
    if [ -z "$missing" ]; then
        pass "init: init --no-playbook wrote the sweeper project"
    else
        fail "init: init --no-playbook exited 0 but did not write:$missing"
    fi
else
    fail "init: init --no-playbook exited non-zero: $(tail -n 3 "$scratch/init.log")"
fi

# ----- 4. private files -----

status=0
"$binary" logout < /dev/null > "$scratch/logout.log" 2>&1 || status=$?
lock="$SWEEPKY_HOME/config/credential.lock"
if [ "$status" -ne 1 ]; then
    fail "private files: logout with no login exited $status, expected 1: $(tail -n 3 "$scratch/logout.log")"
elif ! [ -f "$lock" ]; then
    fail "private files: logout did not create $lock"
else
    # `-perm 600` without a `-` or `/` matches the mode exactly, in BSD and
    # GNU find alike. -mindepth 1 leaves out SWEEPKY_HOME itself, which this
    # script made.
    loose=$(find "$SWEEPKY_HOME" -mindepth 1 \
        \( \( -type f ! -perm 600 \) -o \( -type d ! -perm 700 \) -o \( ! -type f ! -type d \) \) \
        -print)
    if [ -z "$loose" ]; then
        pass "private files: every file logout created is 0600 and every directory 0700"
    else
        fail "private files: not a 0600 file or a 0700 directory: $(echo "$loose" | paste -sd ' ' -)"
    fi
fi

# ----- 5. linkage -----

case "$(uname -s)" in
Linux)
    ldd_out=$(ldd "$binary" 2>&1) || true
    file_out=$(file -b "$binary" 2>&1) || true
    case "$ldd_out$file_out" in
    *"not a dynamic executable"* | *"statically linked"* | *"static-pie linked"*)
        pass "linkage: statically linked"
        ;;
    *)
        fail "linkage: not statically linked: ldd says '$(echo "$ldd_out" | paste -sd ' ' -)'"
        ;;
    esac
    ;;
Darwin)
    if ! command -v otool > /dev/null; then
        fail "linkage: otool is not on PATH (install the Xcode command line tools)"
    else
        # The first line names the binary itself; each line after it is one
        # library, its path first. Every Mach-O executable links at least
        # libSystem, so no library line at all means otool could not read
        # the file (it exits 0 even then).
        libs=$(otool -L "$binary" | tail -n +2 | awk '{ print $1 }')
        foreign=$(echo "$libs" | grep -v -e '^/usr/lib/' -e '^/System/' || true)
        if [ -z "$libs" ]; then
            fail "linkage: otool lists no libraries, so this is not a Mach-O executable"
        elif [ -z "$foreign" ]; then
            pass "linkage: links only /usr/lib/ and /System/ libraries"
        else
            fail "linkage: links libraries outside /usr/lib/ and /System/: $(echo "$foreign" | paste -sd ' ' -)"
        fi
    fi
    ;;
*)
    fail "linkage: no check for $(uname -s)"
    ;;
esac

exit "$failed"
