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
#    Only the example gets a connection string tagged with this run's
#    application name, so while it runs the script reads the exact name
#    of the test database it created from pg_stat_activity.
# 3. Prints the example's PASS and FAIL lines from its results.json (fixed
#    text, never a finding), then checks that nothing this run started is
#    still running and that the test database this run created is gone.
#    One the example left behind is reported as a FAIL and dropped by that
#    name; no other database is ever touched. New idle pubky_test_*
#    databases that are not this run's are only listed, in a NOTE line.
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

# The application name only the example's connections carry. Made of
# [a-z0-9_] only, so it is safe to quote into SQL as it is.
tag="sweepky_demo_check_$$"
if [[ "$TEST_PUBKY_CONNECTION_STRING" =~ [?\&]application_name= ]]; then
    echo "error: TEST_PUBKY_CONNECTION_STRING already sets application_name;" \
        "this script sets its own to find the example's test database" >&2
    exit 1
fi
# The homeserver keeps every query parameter of this URL when it points the
# pool at its new pubky_test_* database, so that database's connections
# carry the tag too.
case "$TEST_PUBKY_CONNECTION_STRING" in
*\?*) demo_connection_string="$TEST_PUBKY_CONNECTION_STRING&application_name=$tag" ;;
*) demo_connection_string="$TEST_PUBKY_CONNECTION_STRING?application_name=$tag" ;;
esac

cargo build -p sweepky-cli --example demo_check
demo_bin="$repo/target/debug/examples/demo_check"
if [ ! -x "$demo_bin" ]; then
    echo "error: $demo_bin is missing after the build" >&2
    exit 1
fi

# The script's own psql calls use the untagged URL, so they are never
# mistaken for the example's.
sql() { psql "$TEST_PUBKY_CONNECTION_STRING" -v ON_ERROR_STOP=1 -tAc "$1"; }

# Every pubky_test_* database, sorted, for the informational NOTE at the
# end. LC_ALL=C keeps sort in the byte order comm expects there.
test_databases() {
    psql "$TEST_PUBKY_CONNECTION_STRING" -lqt | cut -d'|' -f1 | tr -d ' ' |
        grep '^pubky_test_' | LC_ALL=C sort || true
}
databases_before=$(test_databases)

# `pwd -P` resolves the links in $TMPDIR (/var is /private/var on macOS), so
# the path pgrep looks for below is the one the example was started with.
scratch=$(mktemp -d "${TMPDIR:-/tmp}/sweepky-demo.XXXXXX")
scratch=$(cd "$scratch" && pwd -P)
results="$scratch/results.txt"
: > "$results"
# The names of the test databases the example created, one per line.
recorded="$scratch/databases.txt"
: > "$recorded"
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
    # test database, which drop_recorded_databases then drops by name.
    kill -TERM "$demo_pid" 2> /dev/null || true
    wait "$demo_pid" 2> /dev/null || true
    demo_pid=""
}

# Adds to $recorded each pubky_test_* database a connection tagged with
# this run's application name is using now. Only a name of the exact form
# the testnet gives (pubky_test_ and 32 hex digits) is recorded, so only
# such a name is ever quoted into SQL later.
record_test_databases() {
    local db
    for db in $(sql "SELECT DISTINCT datname FROM pg_stat_activity
                     WHERE application_name = '$tag'
                       AND datname LIKE 'pubky_test_%'" 2> /dev/null || true); do
        if [[ "$db" =~ ^pubky_test_[0-9a-f]{32}$ ]] && ! grep -qxF "$db" "$recorded"; then
            echo "$db" >> "$recorded"
        fi
    done
}

# Drops each recorded database that still exists, once the example has
# stopped, and prints one line per such database: "dropped <name>" or
# "kept <name>". A recorded database already gone prints nothing.
# DROP DATABASE without FORCE refuses a database someone is connected to,
# so one still in use is kept and reported, never forced.
drop_recorded_databases() {
    local db
    while read -r db; do
        [ -n "$(sql "SELECT 1 FROM pg_database WHERE datname = '$db'")" ] || continue
        if sql "DROP DATABASE \"$db\"" > /dev/null 2>&1; then
            echo "dropped $db"
        else
            echo "kept $db"
        fi
    done < "$recorded"
}

cleanup() {
    if ! $finished; then
        # The example may still be running: learn its database's name
        # before stopping it, so the drop below can find it.
        [ -z "$demo_pid" ] || record_test_databases
        stop_demo
        echo "check-demo: stopped early; the example's log follows." >&2
        tail -n 40 "$scratch/demo.log" >&2 2> /dev/null || true
        drop_recorded_databases >&2 || true
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
# In the background, so the script can poll pg_stat_activity while it runs
# and stop_demo can stop it by its pid. Only this process gets the tagged
# connection string: `VAR=value command` sets it for that command alone.
TEST_PUBKY_CONNECTION_STRING="$demo_connection_string" \
    "$demo_bin" "$run_dir" > "$scratch/demo.log" 2>&1 &
demo_pid=$!
# kill -0 sends no signal; it only asks whether the process still exists.
while kill -0 "$demo_pid" 2> /dev/null; do
    record_test_databases
    sleep 1
done
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
if [ -s "$recorded" ]; then
    echo "NOTE  the test database this run created: $(paste -sd ' ' "$recorded")" >> "$results"
    leaked=$(drop_recorded_databases | paste -sd ' ' -)
    if [ -n "$leaked" ]; then
        fail "the test database this run created was left behind: $leaked"
    else
        pass "the test database this run created is gone"
    fi
else
    echo "NOTE  no connection carried this run's application name, so no test database was checked" >> "$results"
fi
# Informational only, never dropped: idle pubky_test_* databases that
# appeared during the run and are not this run's, such as one a crash
# left before its name could be learned.
connected=$(sql "SELECT DISTINCT datname FROM pg_stat_activity
                 WHERE datname LIKE 'pubky_test_%'" | LC_ALL=C sort || true)
untouched=$(LC_ALL=C comm -13 <(echo "$databases_before") <(test_databases) |
    LC_ALL=C comm -23 - <(LC_ALL=C sort "$recorded") |
    LC_ALL=C comm -23 - <(echo "$connected") | paste -sd ' ' -)
if [ -n "$untouched" ]; then
    echo "NOTE  new idle pubky_test_* databases, not this run's, left alone: $untouched" >> "$results"
fi

finished=true
count() { grep -c "^$1 " "$results" || true; }
cat "$results"
echo "inputs: $inputs; PASS $(count PASS), FAIL $(count FAIL)"
exit "$failed"
