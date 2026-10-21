#!/usr/bin/env bash
# Runs the headless check of P5's local demo on this machine
# (docs/plan/phases/P5-local-demo.md, Notes, "The headless check").
#
#   scripts/check-demo.sh
#
# 1. Checks that Postgres is up (TEST_PUBKY_CONNECTION_STRING, defaulting to
#    the one in docs/plan/06) and builds the demo_check example
#    (crates/sweepky-cli/examples/demo_check.rs).
# 2. Runs it in a scratch directory under $TMPDIR, outside the repository
#    and outside ~/.config and ~/.local: steps 2 to 8 of the demo, owner,
#    sweeper and stranger, on an in-process EphemeralTestnet on random
#    ports. It never touches the static testnet ports or whatever holds
#    them (the Docker homeserver-testnet behind colima, on this machine).
#    SWEEPKY_DEMO_RUN_DIR and SWEEPKY_DEMO_TARGETS pass through to it; with
#    neither set it uses the synthetic fixtures/demo.
# 3. Prints the example's PASS and FAIL lines from its results.json (fixed
#    text, never a finding), then checks that nothing this run started is
#    still running and that no test database leaked. A pubky_test_*
#    database that was not there before the run is reported as a FAIL and
#    dropped; any other database is never touched.
# 4. Deletes the scratch directory, on every exit, Ctrl-C included.
#
# The exit status is non-zero on any FAIL. Nothing here writes to
# ~/.config/sweepky, ~/.local/share/sweepky or ~/.cargo; the example reads
# github.com anonymously and writes only to its own in-process testnet.

set -euo pipefail

if [ $# -ne 0 ]; then
    echo "usage: scripts/check-demo.sh" >&2
    exit 2
fi

repo=$(cd "$(dirname "$0")/.." && pwd -P)
cd "$repo"

# ----- 1. Preflight and build -----

for tool in jq psql pg_isready pgrep; do
    if ! command -v "$tool" > /dev/null; then
        echo "error: $tool is not on PATH" >&2
        exit 1
    fi
done

export TEST_PUBKY_CONNECTION_STRING=${TEST_PUBKY_CONNECTION_STRING:-postgres://jason@localhost:5432/postgres}
if ! pg_isready -q -d "$TEST_PUBKY_CONNECTION_STRING"; then
    echo "error: Postgres is not accepting connections" >&2
    exit 1
fi

cargo build -p sweepky-cli --example demo_check
demo_bin="$repo/target/debug/examples/demo_check"
if [ ! -x "$demo_bin" ]; then
    echo "error: $demo_bin is missing after the build" >&2
    exit 1
fi

# The pubky_test_* databases there before this run. One that appears later
# and is idle once the example has stopped is this run's own.
test_databases() {
    psql "$TEST_PUBKY_CONNECTION_STRING" -lqt | cut -d'|' -f1 | tr -d ' ' |
        grep '^pubky_test_' | sort || true
}
databases_before=$(test_databases)

# `pwd -P` resolves the links in $TMPDIR (/var is /private/var on macOS), so
# the path pgrep looks for below is the one the example was started with.
scratch=$(mktemp -d "${TMPDIR:-/tmp}/sweepky-demo.XXXXXX")
scratch=$(cd "$scratch" && pwd -P)
results="$scratch/results.txt"
: > "$results"
failed=0

pass() { echo "PASS  $*" >> "$results"; }
fail() {
    echo "FAIL  $*" >> "$results"
    failed=1
}

# ----- Stopping and cleaning up, on every exit -----

demo_pid=""
finished=false

stop_demo() {
    [ -n "$demo_pid" ] || return 0
    # SIGTERM, not SIGINT: bash starts a background job with SIGINT
    # ignored, and the example inherits that. It dies without dropping its
    # test database, which drop_leaked_databases then picks up.
    kill -TERM "$demo_pid" 2> /dev/null || true
    wait "$demo_pid" 2> /dev/null || true
    demo_pid=""
}

# Drops each pubky_test_* database that was not there before this run, and
# prints one line per database: "dropped <name>" or "kept <name>".
#
# Only a name of the exact form the testnet gives (pubky_test_ and 32 hex
# digits) is ever quoted into SQL. DROP DATABASE without FORCE refuses a
# database someone is connected to, so one a concurrent test created and
# still holds is kept, never dropped.
drop_leaked_databases() {
    local db
    for db in $(comm -13 <(echo "$databases_before") <(test_databases)); do
        if [[ "$db" =~ ^pubky_test_[0-9a-f]{32}$ ]] &&
            psql "$TEST_PUBKY_CONNECTION_STRING" -v ON_ERROR_STOP=1 -qc \
                "DROP DATABASE \"$db\"" > /dev/null 2>&1; then
            echo "dropped $db"
        else
            echo "kept $db"
        fi
    done
}

cleanup() {
    stop_demo
    if ! $finished; then
        echo "check-demo: stopped early; the example's log follows." >&2
        tail -n 40 "$scratch/demo.log" >&2 2> /dev/null || true
        drop_leaked_databases >&2 || true
    fi
    # Only ever the directory mktemp made, by its name.
    case "$(basename "$scratch")" in
    sweepky-demo.??????) rm -rf "$scratch" ;;
    *) echo "check-demo: not deleting unexpected path $scratch" >&2 ;;
    esac
}
trap cleanup EXIT
# Turning a signal into an exit runs the EXIT trap, so Ctrl-C cleans up too.
trap 'exit 130' INT
trap 'exit 143' TERM

# ----- 2. The demo -----

# A directory that does not exist yet: the example creates it and refuses
# one that is not empty, and its log stays outside it.
run_dir="$scratch/run"
# In the background, so an interrupt reaches the trap at once and
# stop_demo can stop the example by its pid.
"$demo_bin" "$run_dir" > "$scratch/demo.log" 2>&1 &
demo_pid=$!
demo_status=0
wait "$demo_pid" || demo_status=$?
demo_pid=""

# ----- 3. Results -----

demo_results="$run_dir/results.json"
if [ -f "$demo_results" ]; then
    # Fixed text only: each check's name is compiled into the example.
    jq -r '.results[] | "\(.result)  \(.check)"' "$demo_results" >> "$results"
    inputs=$(jq -r .inputs "$demo_results")
    if jq -e 'all(.results[]; .result == "PASS")' "$demo_results" > /dev/null; then
        [ "$demo_status" -eq 0 ] || fail "demo_check exited $demo_status with every check passing"
    else
        failed=1
    fi
else
    inputs="none read"
    fail "demo_check exited $demo_status and wrote no results.json: $(grep -m 1 -i '^error' "$scratch/demo.log" || echo 'no error line')"
fi

if pgrep -f "$scratch" > /dev/null; then
    fail "processes started by this run are still running: $(pgrep -f "$scratch" | tr '\n' ' ')"
else
    pass "no process this run started is still running"
fi
leaked=$(drop_leaked_databases | tr '\n' ' ')
if [ -n "${leaked// /}" ]; then
    fail "test databases left behind by demo_check: $leaked"
else
    pass "no pubky_test_* database left behind"
fi

finished=true
count() { grep -c "^$1 " "$results" || true; }
cat "$results"
echo "inputs: $inputs; PASS $(count PASS), FAIL $(count FAIL)"
exit "$failed"
