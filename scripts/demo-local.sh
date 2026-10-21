#!/usr/bin/env bash
# Runs P5's local demo on this machine (docs/plan/phases/P5-local-demo.md,
# "scripts/demo-local.sh").
#
#   scripts/demo-local.sh
#
# Preflight: before it starts, writes or creates anything, it checks that
# the static testnet ports (TCP 15411, 15412, 6286-6288, UDP and TCP 6881)
# and the board's dev-server port 5173 are free, naming whatever holds one;
# that pubky-testnet is on PATH (and at 0.16.2, when its install record
# says); that Postgres answers on TEST_PUBKY_CONNECTION_STRING (defaulting
# to the one in docs/plan/06); and that cargo, pnpm 10.33.0, node, jq, psql,
# pg_isready and lsof are there. It prints every problem it finds and exits
# 1 without starting anything.
#
# Then it builds the release binary, makes one scratch directory under
# $TMPDIR (mode 0700) and runs the demo's steps:
# 1. Starts the pinned testnet binary against local Postgres and waits until
#    it says it is running and holds the homeserver port.
#
# On every exit (the end, an error, Ctrl-C or TERM) it stops what it
# started: the testnet with kill -INT, as docs/plan/06 says, then drops a
# pubky_test_* database the testnet left behind (only one that was not there
# before the start, idle, and named the way the testnet names them), stops
# the board's dev server, and deletes its own scratch directory. It never
# touches a process it did not start, such as the Docker homeserver-testnet
# behind colima that holds the static ports on this machine.
#
# Nothing here writes to ~/.cargo, ~/.config/sweepky or ~/.local/share/sweepky,
# and nothing talks to a service other than the local testnet and Postgres.

set -euo pipefail

usage() {
    echo "usage: scripts/demo-local.sh" >&2
    exit 2
}

[ $# -le 1 ] || usage
case "${1:-}" in
"") ;;
-h | --help)
    # The comment block above, without its "# ".
    sed -n '2,/^$/s/^# \{0,1\}//p' "$0"
    exit 0
    ;;
*) usage ;;
esac

repo=$(cd "$(dirname "$0")/.." && pwd -P)
cd "$repo"

export TEST_PUBKY_CONNECTION_STRING=${TEST_PUBKY_CONNECTION_STRING:-postgres://jason@localhost:5432/postgres}
testnet_install="cargo install pubky-testnet --version '=0.16.2' --locked"
pnpm_version=10.33.0
# The ports the testnet binds at 0.16.2 (docs/plan/06), then the dev server's.
tcp_ports="6881 15411 15412 6286 6287 6288 5173"

# ----- Preflight: read-only checks, nothing started or created -----

problems=0
problem() {
    echo "preflight: $*" >&2
    problems=$((problems + 1))
}

for tool in cargo node jq psql pg_isready lsof; do
    command -v "$tool" > /dev/null || problem "$tool is not on PATH"
done

if ! command -v pnpm > /dev/null; then
    problem "pnpm is not on PATH (the board needs pnpm $pnpm_version)"
else
    # From /, so no package.json's packageManager field makes pnpm fetch
    # another version of itself just to answer.
    found=$(cd / && pnpm --version 2> /dev/null || echo unknown)
    [ "$found" = "$pnpm_version" ] ||
        problem "pnpm is $found, the board pins $pnpm_version"
fi

# Prints "<command> (pid <pid>)" for each process listening on a port, or
# nothing. lsof's first output line is its header, and lsof exits 1 when it
# finds nothing, which pipefail would otherwise turn into an exit here.
port_holders() {
    { lsof -nP "$@" 2> /dev/null || true; } | awk 'NR > 1 { print $1 " (pid " $2 ")" }' |
        sort -u | paste -sd ',' - | sed 's/,/, /g'
}
if command -v lsof > /dev/null; then
    for port in $tcp_ports; do
        holders=$(port_holders -iTCP:"$port" -sTCP:LISTEN)
        [ -z "$holders" ] || problem "TCP port $port is held by $holders"
    done
    holders=$(port_holders -iUDP:6881)
    [ -z "$holders" ] || problem "UDP port 6881 is held by $holders"
fi

# pubky-testnet 0.16.2 has no --version flag (clap refuses it) and run with
# no argument it starts, so its version comes from the install record cargo
# keeps next to the bin/ directory it installed into. One installed some other way
# cannot say, and is used with a warning.
testnet_bin=$(command -v pubky-testnet || true)
if [ -z "$testnet_bin" ]; then
    problem "pubky-testnet is not on PATH; install it with: $testnet_install"
else
    install_record="$(dirname "$(dirname "$testnet_bin")")/.crates.toml"
    installed=$(grep -o '"pubky-testnet [^ ]*' "$install_record" 2> /dev/null |
        cut -d' ' -f2 || true)
    if [ -z "$installed" ]; then
        echo "preflight: warning: cannot tell which pubky-testnet $testnet_bin is; the demo expects 0.16.2" >&2
    elif [ "$installed" != 0.16.2 ]; then
        problem "pubky-testnet is $installed, the demo needs 0.16.2: $testnet_install"
    fi
fi

if command -v pg_isready > /dev/null &&
    ! pg_isready -q -d "$TEST_PUBKY_CONNECTION_STRING"; then
    problem "Postgres is not accepting connections on TEST_PUBKY_CONNECTION_STRING"
fi

if [ "$problems" -ne 0 ]; then
    echo "preflight: $problems problem(s); nothing was started" >&2
    exit 1
fi

# ----- Stopping and cleaning up, on every exit -----

# Each stays empty until this run starts or makes the thing it names, so
# cleanup only ever acts on what this run created.
demo=""
testnet_pid=""
dev_pid=""
databases_before=""

test_databases() {
    psql "$TEST_PUBKY_CONNECTION_STRING" -lqt | cut -d'|' -f1 | tr -d ' ' |
        grep '^pubky_test_' | sort || true
}

# stop_process <name> <pid> <signal>: sends <signal> to a process this run
# started, waits up to 10 s for it to exit, then sends TERM and, after
# another 5 s, KILL. A background job of a script starts with SIGINT
# ignored, so an INT the process has not yet installed a handler for (the
# testnet only listens for Ctrl-C once it is up) needs the fallback.
stop_process() {
    local name=$1 pid=$2 signal=$3 tenths
    kill "-$signal" "$pid" 2> /dev/null || true
    for tenths in $(seq 1 150); do
        kill -0 "$pid" 2> /dev/null || break
        [ "$tenths" -ne 100 ] || kill -TERM "$pid" 2> /dev/null || true
        sleep 0.1
    done
    if kill -0 "$pid" 2> /dev/null; then
        echo "demo-local: $name (pid $pid) ignored INT and TERM; killing it" >&2
        kill -KILL "$pid" 2> /dev/null || true
    fi
    # Reaps it, so its pid is not reused while this script still names it.
    wait "$pid" 2> /dev/null || true
}

# Drops each pubky_test_* database that was not there before the testnet
# started. Only a name of the exact form the testnet gives (pubky_test_ and
# 32 hex digits) is ever quoted into SQL, and DROP DATABASE without FORCE
# refuses one someone is still connected to, so a concurrent test's live
# database is kept, never dropped.
drop_leaked_databases() {
    local db
    for db in $(comm -13 <(echo "$databases_before") <(test_databases)); do
        if [[ "$db" =~ ^pubky_test_[0-9a-f]{32}$ ]] &&
            psql "$TEST_PUBKY_CONNECTION_STRING" -v ON_ERROR_STOP=1 -qc \
                "DROP DATABASE \"$db\"" > /dev/null 2>&1; then
            echo "demo-local: dropped $db, which the testnet left behind" >&2
        else
            echo "demo-local: kept $db (in use, or not the testnet's)" >&2
        fi
    done
}

cleanup() {
    local status=$?
    # A failing step here must not end the cleanup before the rest has run.
    set +e
    # Once in cleanup, a second Ctrl-C must not cut it short.
    trap '' INT TERM
    if [ -n "$dev_pid" ]; then
        # pnpm runs vite as its child; stop the child too, then pnpm.
        pkill -TERM -P "$dev_pid" 2> /dev/null || true
        stop_process "dev server" "$dev_pid" TERM
    fi
    if [ -n "$testnet_pid" ]; then
        stop_process testnet "$testnet_pid" INT
        if [ "$status" -ne 0 ] && [ -f "$demo/testnet.log" ]; then
            echo "demo-local: stopped early; the testnet's log ends:" >&2
            tail -n 20 "$demo/testnet.log" >&2 || true
        fi
        drop_leaked_databases || true
    fi
    # Only ever the directory mktemp made, by its name.
    if [ -n "$demo" ]; then
        case "$(basename "$demo")" in
        sweepky-demo-local.??????) rm -rf "$demo" ;;
        *) echo "demo-local: not deleting unexpected path $demo" >&2 ;;
        esac
    fi
    exit "$status"
}
trap cleanup EXIT
# Turning a signal into an exit runs the EXIT trap, so Ctrl-C cleans up too.
trap 'exit 130' INT
trap 'exit 143' TERM

# ----- Build and scratch directory -----

cargo build --release -p sweepky-cli --locked
sweepky="$repo/target/release/sweepky"
[ -x "$sweepky" ] || {
    echo "error: $sweepky is missing after the release build" >&2
    exit 1
}

# mktemp -d makes the directory 0700; the identities' homes go inside it.
demo=$(mktemp -d "${TMPDIR:-/tmp}/sweepky-demo-local.XXXXXX")
demo=$(cd "$demo" && pwd -P)

# ----- 1. The testnet -----

databases_before=$(test_databases)
# exec, so $! is the testnet itself and not a subshell around it; started
# from the scratch directory so nothing it might write lands in the repo.
(cd "$demo" && NO_COLOR=1 exec pubky-testnet) > "$demo/testnet.log" 2>&1 &
testnet_pid=$!

echo "demo-local: waiting for the testnet (pid $testnet_pid)..."
ready=false
for _ in $(seq 1 600); do
    if ! kill -0 "$testnet_pid" 2> /dev/null; then
        echo "error: the testnet exited before it was ready" >&2
        exit 1
    fi
    # Ready once it logs that it runs and itself holds the homeserver port.
    if grep -q 'Testnet running' "$demo/testnet.log" &&
        lsof -nP -a -p "$testnet_pid" -iTCP:6286 -sTCP:LISTEN > /dev/null 2>&1; then
        ready=true
        break
    fi
    sleep 0.1
done
$ready || {
    echo "error: the testnet was not ready after 60 s" >&2
    exit 1
}
echo "demo-local: testnet up: homeserver http://localhost:6286, relay http://localhost:15412/inbox"

# Steps 2 to 9 (identities, circle, bounty, sweeps, pull, done, board) are
# not written yet; the EXIT trap now stops the testnet.
