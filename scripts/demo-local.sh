#!/usr/bin/env bash
# Runs P5's local demo on this machine (docs/plan/phases/P5-local-demo.md,
# "scripts/demo-local.sh").
#
#   scripts/demo-local.sh [--step]
#   scripts/demo-local.sh --ci --binary PATH
#
# Inputs: SWEEPKY_DEMO_RUN_DIR, a security-audit run directory whose
# contents become the circle sweeper's audit/, and SWEEPKY_DEMO_TARGETS, the
# JSON array of the targets that run covered. Set both or neither: with
# neither it uses the synthetic fixtures in fixtures/demo, whose findings
# are made up, and says so. A real report is copied only into the scratch
# directory below and uploaded only to the local testnet.
#
# Preflight: before it starts, writes or creates anything, it checks that
# the static testnet ports (TCP 15411, 15412, 6286-6288, UDP and TCP 6881)
# and the board's dev-server port 5173 are free, naming whatever holds one;
# that pubky-testnet is on PATH (and at 0.16.2, when its install record
# says); that Postgres answers on TEST_PUBKY_CONNECTION_STRING (defaulting
# to the one in docs/plan/06); that cargo, pnpm 10.33.0, node, jq, curl,
# psql, pg_isready and lsof are there and web/node_modules is installed;
# that TEST_PUBKY_CONNECTION_STRING does not set application_name itself;
# and that the inputs are usable. It prints every problem it finds and
# exits 1 without starting anything.
#
# Then it builds the release binary (--ci, below, runs PATH instead),
# makes one scratch directory under $TMPDIR (mode 0700) and runs the
# demo's steps:
# 1. Starts the pinned testnet binary against local Postgres and waits until
#    it says it is running and holds the homeserver port. Only the testnet
#    gets a connection string tagged with this run's application name, so
#    the script then reads the exact name of the test database it created
#    from pg_stat_activity, and prints it.
# 2. login --identity owner, sweeper and stranger, each under its own
#    SWEEPKY_HOME in the scratch directory. No QR code, no browser.
# 3. circle create as owner, then circle add the sweeper.
# 4. post --open as owner, from a draft built out of SWEEPKY_DEMO_TARGETS,
#    then shows the bounty's discovered.json.
# 5. As sweeper, in an init --no-playbook project: run, copy the run
#    directory into audit/, submit.
# 6. As stranger, in another project: run, a synthetic audit/ whose one
#    finding shares the place of the sweeper's first finding, submit.
# 7. pull --findings as owner; then groups.json, the untrusted/ names and
#    discovered.json, each shown escaped (jq -ac) or with every byte that
#    is not printable ASCII replaced.
# 8. done as owner, accepting the proposal {sweeper, stranger}; then pull
#    once more, which labels the stranger known: 1.
# 9. The board: pnpm --dir web dev on http://localhost:5173 with
#    VITE_PUBKY_TESTNET=1 and VITE_SWEEPKY_CIRCLE set to the owner. It
#    prints the landing and board URLs and runs until Ctrl-C.
#
# --step starts the board right after step 3 instead and waits for Enter
# before each of steps 4 to 8, so the board can be watched as they land.
#
# --ci --binary PATH is the headless run the release workflow makes of a
# built release binary. It takes both flags together, never --step, and
# never waits for input. It runs PATH, which must be an executable file,
# instead of building one, and leaves out the board: step 9, and pnpm,
# node, cargo, web/node_modules and port 5173 in preflight. Steps 1 to 8
# run as above, and it checks what each should have done, the checks of
# crates/sweepky-cli/examples/demo_check.rs (scripts/check-demo.sh) made
# through the binary instead: its exit statuses, its output, the files
# under each SWEEPKY_HOME, and the public records, read anonymously from
# the testnet homeserver as the board reads them:
# - every sweepky command exits 0 (a command that fails ends the run
#   there, as every later step needs it);
# - login gave the three identities three pubkys, and circle add put the
#   sweeper in the owner's public circle;
# - the bounty is public, open, pinned at each full SHA its input names,
#   with a discovered.json that lists no sweep yet;
# - each sweep record reads running after run and done after submit, every
#   file a sweeper location names was fetched with at least that many
#   lines, and submit moved the sweeper's audit/ to its data directory;
# - pull --findings labels the sweeper circle and the stranger unknown,
#   prints the title of every finding of the run directory and each of its
#   locations' GitHub links at the pinned commit, and none of the
#   stranger's finding text; then discovered.json lists the stranger's
#   sweep, which is stored under untrusted/, and groups.json has one group
#   reported by the sweeper and the stranger;
# - done credits exactly the sweeper and the stranger, the next pull
#   labels the stranger known: 1, and every file under each SWEEPKY_HOME is
#   0600 and every directory 0700;
# - and, once cleanup below has run, the testnet has stopped and holds no
#   testnet port, and the test database this run created is gone.
# It prints one "PASS <name>" or "FAIL <name>: <why>" line per check, fixed
# text and paths only, never a finding, then a summary line, and exits 1
# if any check failed. The links check percent-encodes each path segment
# as jq's @uri does, which the CLI's spelling matches for the fixtures'
# plain paths, not for every name a real report may hold.
#
# On every exit (the end, an error, Ctrl-C or TERM) it stops what it
# started: first the board's dev server and its vite child, then the testnet
# with kill -INT, as docs/plan/06 says (it drops its own test database
# then). If the database step 1 named is still there, it drops it by that
# name; no other database is ever dropped, and new idle pubky_test_*
# databases that are not this run's are only named on standard error. Last
# it deletes its own scratch directory. It never touches a process it did
# not start, such as the Docker homeserver-testnet behind colima that holds
# the static ports on this machine.
#
# Nothing here writes to ~/.cargo, ~/.config/sweepky or ~/.local/share/sweepky,
# and nothing talks to a service other than the local testnet, Postgres and,
# for post and run, github.com read anonymously.

set -euo pipefail

usage() {
    echo "usage: scripts/demo-local.sh [--step]" >&2
    echo "       scripts/demo-local.sh --ci --binary PATH" >&2
    exit 2
}

step_mode=false
ci_mode=false
binary=""
while [ $# -gt 0 ]; do
    case "$1" in
    --step) step_mode=true ;;
    --ci) ci_mode=true ;;
    --binary)
        [ $# -ge 2 ] || usage
        binary=$2
        shift
        ;;
    -h | --help)
        # The comment block above, without its "# ".
        sed -n '2,/^$/s/^# \{0,1\}//p' "$0"
        exit 0
        ;;
    *) usage ;;
    esac
    shift
done
# --ci and --binary go together, and --ci never waits for Enter.
if $ci_mode; then
    { [ -n "$binary" ] && ! $step_mode; } || usage
elif [ -n "$binary" ]; then
    usage
fi

# Checked, and made absolute, here, against the directory the script was
# started from: the steps run it from other directories. Preflight
# reports one that is not an executable file.
binary_ok=false
if [ -f "$binary" ] && [ -x "$binary" ]; then
    binary_ok=true
    binary="$(cd "$(dirname "$binary")" && pwd -P)/$(basename "$binary")"
fi

repo=$(cd "$(dirname "$0")/.." && pwd -P)
cd "$repo"

export TEST_PUBKY_CONNECTION_STRING=${TEST_PUBKY_CONNECTION_STRING:-postgres://jason@localhost:5432/postgres}
testnet_install="cargo install pubky-testnet --version '=0.16.2' --locked"
pnpm_version=10.33.0
# The ports the testnet binds at 0.16.2 (docs/plan/06). The board's dev
# server port is added below, unless --ci leaves the board out.
testnet_tcp_ports="6881 15411 15412 6286 6287 6288"
tcp_ports=$testnet_tcp_ports

# ----- Preflight: read-only checks, nothing started or created -----

problems=0
problem() {
    echo "preflight: $*" >&2
    problems=$((problems + 1))
}

for tool in jq curl psql pg_isready lsof; do
    command -v "$tool" > /dev/null || problem "$tool is not on PATH"
done

if $ci_mode; then
    $binary_ok || problem "--binary $binary is not an executable file"
else
    # Everything only the cargo build and the board need, which --ci
    # leaves out: cargo, node, the pinned pnpm, web/node_modules and the
    # dev server's port.
    tcp_ports="$tcp_ports 5173"
    for tool in cargo node; do
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
    [ -d web/node_modules ] ||
        problem "web/node_modules is missing; install it with: pnpm --dir web install --frozen-lockfile"
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

# The application name only the testnet's connections carry. Made of
# [a-z0-9_] only, so it is safe to quote into SQL as it is.
tag="sweepky_demo_local_$$"
if [[ "$TEST_PUBKY_CONNECTION_STRING" =~ [?\&]application_name= ]]; then
    problem "TEST_PUBKY_CONNECTION_STRING already sets application_name;" \
        "this script sets its own to find the testnet's database"
fi
# The homeserver keeps every query parameter of this URL when it points the
# pool at its new pubky_test_* database, so that database's connections
# carry the tag too.
case "$TEST_PUBKY_CONNECTION_STRING" in
*\?*) testnet_connection_string="$TEST_PUBKY_CONNECTION_STRING&application_name=$tag" ;;
*) testnet_connection_string="$TEST_PUBKY_CONNECTION_STRING?application_name=$tag" ;;
esac

# Both inputs or neither. `${VAR+set}` is "set" when VAR is set at all, even
# to the empty string, so an empty value is refused rather than taken as
# unset. Their contents are never printed: a real report may describe
# unpatched findings.
using_fixtures=false
if [ -n "${SWEEPKY_DEMO_RUN_DIR+set}" ] && [ -n "${SWEEPKY_DEMO_TARGETS+set}" ]; then
    run_dir=$SWEEPKY_DEMO_RUN_DIR
    targets_json=$SWEEPKY_DEMO_TARGETS
elif [ -z "${SWEEPKY_DEMO_RUN_DIR+set}" ] && [ -z "${SWEEPKY_DEMO_TARGETS+set}" ]; then
    using_fixtures=true
    run_dir=$repo/fixtures/demo/sweeper-run
    targets_json=$(cat "$repo/fixtures/demo/targets.json")
else
    problem "set both SWEEPKY_DEMO_RUN_DIR and SWEEPKY_DEMO_TARGETS, or neither"
fi
if [ -n "${targets_json+set}" ]; then
    if [ -d "$run_dir" ] && [ -f "$run_dir/findings.json" ]; then
        # Absolute, because the copy in step 5 runs from another directory.
        run_dir=$(cd "$run_dir" && pwd -P)
    else
        problem "SWEEPKY_DEMO_RUN_DIR is not a directory holding findings.json"
    fi
    # jq's own message could quote the value, so only the verdict is kept.
    jq -e 'type == "array" and length > 0' <<< "$targets_json" > /dev/null 2>&1 ||
        problem "SWEEPKY_DEMO_TARGETS is not a non-empty JSON array"
fi

if $step_mode && ! [ -t 0 ]; then
    problem "--step waits for Enter, so standard input must be a terminal"
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
# The file of the test database names this run recorded, one per line.
recorded=""
# The file of --ci's PASS and FAIL lines, set only under --ci, and whether
# the steps ran to their end.
results=""
finished=false

# pass <name> and fail <name> <why>: one line of --ci's results, printed
# on file descriptor 3, the script's own standard output (see the scratch
# directory below), so a check made where a step's output is captured
# still shows, and added to $results, so one made in a subshell still
# counts. Each name and reason is fixed text or paths, never a finding.
pass() { echo "PASS $1" | tee -a "$results" >&3; }
fail() { echo "FAIL $1: $2" | tee -a "$results" >&3; }

# check <name> <why> <command...>: PASS <name> when the command succeeds,
# FAIL <name>: <why> when it does not. The command's output is dropped.
check() {
    local name=$1 why=$2
    shift 2
    if "$@" > /dev/null 2>&1; then
        pass "$name"
    else
        fail "$name" "$why"
    fi
}

# ci <command...>: runs the command only under --ci, for its checks.
ci() {
    if $ci_mode; then
        "$@"
    fi
}

# The script's own psql calls use the untagged URL, so they are never
# mistaken for the testnet's.
sql() { psql "$TEST_PUBKY_CONNECTION_STRING" -v ON_ERROR_STOP=1 -tAc "$1"; }

# Every pubky_test_* database, sorted, for the informational line in
# cleanup. LC_ALL=C keeps sort in the byte order comm expects there.
test_databases() {
    psql "$TEST_PUBKY_CONNECTION_STRING" -lqt | cut -d'|' -f1 | tr -d ' ' |
        grep '^pubky_test_' | LC_ALL=C sort || true
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

# Drops each recorded database that still exists, once the testnet has
# stopped, and prints one line per such database: dropped or kept. A
# recorded database already gone (the testnet drops its own on SIGINT)
# prints nothing. DROP DATABASE without FORCE refuses a database someone is
# connected to, so one still in use is kept and reported, never forced.
drop_recorded_databases() {
    local db
    if ! [ -s "$recorded" ]; then
        echo "demo-local: no connection carried this run's application name, so no test database was dropped" >&2
        return 0
    fi
    while read -r db; do
        [ -n "$(sql "SELECT 1 FROM pg_database WHERE datname = '$db'")" ] || continue
        if sql "DROP DATABASE \"$db\"" > /dev/null 2>&1; then
            echo "demo-local: dropped $db, which the testnet left behind" >&2
        else
            echo "demo-local: kept $db (still in use)" >&2
        fi
    done < "$recorded"
}

# Informational only, never dropped: idle pubky_test_* databases that
# appeared during the run and are not this run's, such as a concurrent
# test's, or one a crash left before its name could be learned.
note_untouched_databases() {
    local connected untouched
    connected=$(sql "SELECT DISTINCT datname FROM pg_stat_activity
                     WHERE datname LIKE 'pubky_test_%'" | LC_ALL=C sort || true)
    untouched=$(LC_ALL=C comm -13 <(echo "$databases_before") <(test_databases) |
        LC_ALL=C comm -23 - <(LC_ALL=C sort "$recorded") |
        LC_ALL=C comm -23 - <(echo "$connected") | paste -sd ' ' -)
    [ -z "$untouched" ] ||
        echo "demo-local: new idle pubky_test_* databases, not this run's, left alone: $untouched" >&2
}

# --ci's last two checks, scripts/check-demo.sh's own, once the testnet has
# been stopped and the recorded databases dropped: nothing this run
# started still runs or holds a testnet port, and the test database it
# created is gone, whoever dropped it. A lookup that fails counts against
# the check. With no database recorded there is nothing to look for, and a
# NOTE says so.
check_stopped() {
    local name port holders held="" db present left=""
    name="the testnet this run started has stopped and holds no testnet port"
    for port in $testnet_tcp_ports; do
        holders=$(port_holders -iTCP:"$port" -sTCP:LISTEN)
        [ -z "$holders" ] || held="$held TCP $port by $holders;"
    done
    holders=$(port_holders -iUDP:6881)
    [ -z "$holders" ] || held="$held UDP 6881 by $holders;"
    if kill -0 "$testnet_pid" 2> /dev/null; then
        fail "$name" "pid $testnet_pid is still running"
    elif [ -n "$held" ]; then
        fail "$name" "held:$held"
    else
        pass "$name"
    fi

    name="the test database this run created is gone"
    if ! [ -s "$recorded" ]; then
        echo "NOTE no connection carried this run's application name, so no test database was checked" >&3
        return 0
    fi
    while read -r db; do
        present=$(sql "SELECT 1 FROM pg_database WHERE datname = '$db'") || present="unknown"
        [ -z "$present" ] || left="$left $db"
    done < "$recorded"
    if [ -z "$left" ]; then
        pass "$name"
    else
        fail "$name" "still there, or could not be looked up:$left"
    fi
}

cleanup() {
    local status=$? passed failed
    # A failing step here must not end the cleanup before the rest has run.
    set +e
    # Once in cleanup, a second Ctrl-C must not cut it short.
    trap '' INT TERM
    # Under --ci, a run that stopped before its end has failed, whatever
    # its checks said up to there.
    if [ -n "$results" ] && ! $finished; then
        fail "the demo flow ran to its end" "it stopped with exit status $status"
    fi
    if [ -n "$dev_pid" ]; then
        # pnpm runs vite as its child; stop the child too, then pnpm.
        pkill -TERM -P "$dev_pid" 2> /dev/null || true
        stop_process "dev server" "$dev_pid" TERM
    fi
    if [ -n "$testnet_pid" ]; then
        # Once more while the testnet still runs, in case it stopped early
        # before step 1 learned its database's name.
        record_test_databases
        stop_process testnet "$testnet_pid" INT
        if [ "$status" -ne 0 ] && [ -f "$demo/testnet.log" ]; then
            echo "demo-local: stopped early; the testnet's log ends:" >&2
            tail -n 20 "$demo/testnet.log" >&2 || true
        fi
        drop_recorded_databases || true
        note_untouched_databases || true
        [ -z "$results" ] || check_stopped
    fi
    if [ -n "$results" ]; then
        # grep -c prints 0 and exits 1 when nothing matches.
        passed=$(grep -c '^PASS ' "$results" || true)
        failed=$(grep -c '^FAIL ' "$results" || true)
        echo "demo-local --ci: PASS $passed, FAIL $failed" >&3
        [ "$failed" -eq 0 ] || status=1
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

if $ci_mode; then
    sweepky=$binary
else
    cargo build --release -p sweepky-cli --locked
    sweepky="$repo/target/release/sweepky"
    [ -x "$sweepky" ] || {
        echo "error: $sweepky is missing after the release build" >&2
        exit 1
    }
fi

# mktemp -d makes the directory 0700; the identities' homes go inside it.
demo=$(mktemp -d "${TMPDIR:-/tmp}/sweepky-demo-local.XXXXXX")
demo=$(cd "$demo" && pwd -P)
recorded="$demo/databases.txt"
: > "$recorded"
if $ci_mode; then
    results="$demo/results.txt"
    : > "$results"
    # File descriptor 3 is this standard output, for pass and fail.
    exec 3>&1
fi

# ----- 1. The testnet -----

databases_before=$(test_databases)
# exec, so $! is the testnet itself and not a subshell around it; started
# from the scratch directory so nothing it might write lands in the repo.
# Only the testnet gets the tagged connection string: `VAR=value command`
# sets it for that command alone.
(cd "$demo" && NO_COLOR=1 TEST_PUBKY_CONNECTION_STRING="$testnet_connection_string" \
    exec pubky-testnet) > "$demo/testnet.log" 2>&1 &
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

# The name of the test database the testnet created, from the connections
# that carry this run's tag; cleanup drops it by that name if the testnet
# leaves it behind. kill -0 sends no signal; it only asks whether the
# process still exists.
for _ in $(seq 1 60); do
    record_test_databases
    if [ -s "$recorded" ] || ! kill -0 "$testnet_pid" 2> /dev/null; then
        break
    fi
    sleep 1
done
if [ -s "$recorded" ]; then
    echo "demo-local: the testnet's database: $(paste -sd ' ' "$recorded")"
else
    echo "demo-local: warning: no connection carried this run's application name after 60 s; cleanup will drop no database" >&2
fi

# ----- Helpers for steps 2 to 9 -----

# Upper-case Crockford base32, 13 characters: a record id (01).
record_id='[0-9A-HJKMNP-TV-Z]{13}'
# z-base32, 52 characters: a pubky in its raw form, as login.json holds it.
z32_key='[ybndrfg8ejkmcpqxot1uwisza345h769]{52}'
board=http://localhost:5173
playbook_sweeper=cloudflare/security-audit@c1c8a8c1471069fb0e188eeaff69b8e8db6564a8
playbook_stranger=careful-review

step() {
    echo
    echo "== $*"
}

# Under --step, waits for Enter before the step that follows, so the board,
# already open, shows each step land.
pause() {
    $step_mode || return 0
    read -r -p "demo-local: press Enter for step $1 " _
}

# as <identity> <args...>: sweepky on the testnet as that identity. Its
# standard input is /dev/null, so a question fails at once instead of
# waiting (or reading the terminal under --step).
as() {
    local who=$1
    shift
    SWEEPKY_HOME="$demo/homes/$who" "$sweepky" --testnet "$@" < /dev/null
}

# yes_as <identity> <args...>: the same, answering its one question (post's
# and done's "publish?", which they ask on standard error) with y.
yes_as() {
    local who=$1
    shift
    printf 'y\n' | SWEEPKY_HOME="$demo/homes/$who" "$sweepky" --testnet "$@"
}

# as_in <directory> <identity> <args...>: `as`, from <directory>, the
# project run and submit find from the working directory.
as_in() {
    (cd "$1" && shift && as "$@")
}

# cli <name> <command...>: runs one sweepky step. One that fails ends the
# run with its exit status, as set -e would; under --ci, each step is also
# a check, "<name> exits 0".
cli() {
    local name=$1 status=0
    shift
    "$@" || status=$?
    if [ "$status" -ne 0 ]; then
        ci fail "$name exits 0" "it exited $status"
        exit "$status"
    fi
    ci pass "$name exits 0"
}

# The pubky an identity is logged in as, from its login.json: the one field
# read, checked to be a key before it goes into a URL or the board's env.
pubky_of() {
    local key
    key=$(jq -r '.pubky // empty' "$demo/homes/$1/config/login.json")
    [[ "$key" =~ ^$z32_key$ ]] || {
        echo "error: the $1 login.json holds no pubky" >&2
        exit 1
    }
    echo "$key"
}

# Prints standard input with every byte that is not printable ASCII (or a
# newline) replaced by ?, so a name a stranger chose cannot move the cursor,
# recolour the terminal or hide text with a bidirectional override.
printable() {
    LC_ALL=C tr -c '[:print:]\n' '?'
}

# public_record <pubky> <path>: the public file at <path> of <pubky>, read
# anonymously from the testnet homeserver, as the board reads it. Fails
# when it cannot be read.
public_record() {
    curl -sf --max-time 10 --max-filesize 1048576 -H "pubky-host: $1" "http://localhost:6286$2"
}

# The public paths of a bounty record, its discovered.json and a sweep
# record, for an id already checked to be a record id.
bounty_path() { echo "/pub/sweepky/bounties/$1.json"; }
discovered_path() { echo "/pub/sweepky/bounties/$1.discovered.json"; }
sweep_path() { echo "/pub/sweepky/sweeps/$1.json"; }

# The bounty's discovered.json, read anonymously from the testnet
# homeserver and printed by jq -ac: one line, with every control and
# non-ASCII character escaped. Its sweep URLs are the strangers' own.
show_discovered() {
    local body
    if body=$(public_record "$owner" "$(discovered_path "$bounty_id")"); then
        jq -ac . <<< "$body" 2> /dev/null || echo "(discovered.json is not JSON)"
    else
        echo "(could not read discovered.json from the testnet homeserver)"
    fi
}

# Starts the board's dev server against the testnet, with the owner's
# circle as its default, and waits until it answers.
start_board() {
    # exec, as for the testnet, so $! is pnpm; cleanup stops pnpm's vite
    # child too. From the scratch directory, so nothing lands in the repo.
    (cd "$demo" && VITE_PUBKY_TESTNET=1 VITE_SWEEPKY_CIRCLE=$owner \
        npm_config_update_notifier=false \
        exec pnpm --dir "$repo/web" dev --port 5173 --strictPort) > "$demo/board.log" 2>&1 &
    dev_pid=$!
    echo "demo-local: waiting for the board (pid $dev_pid)..."
    for _ in $(seq 1 600); do
        if ! kill -0 "$dev_pid" 2> /dev/null; then
            echo "error: the board's dev server exited; its log ends:" >&2
            tail -n 20 "$demo/board.log" | printable >&2
            exit 1
        fi
        curl -s -o /dev/null --max-time 1 "$board/" && {
            echo "demo-local: board up: landing $board/  board $board/board"
            return 0
        }
        sleep 0.1
    done
    echo "error: the board did not answer after 60 s" >&2
    exit 1
}

# The one sweep directory `run` made in a project; its name is checked to
# be a record id before it is used in a path.
sweep_dir_of() {
    local names
    names=$(ls "$1/sweeps")
    [[ "$names" =~ ^$record_id$ ]] || {
        echo "error: run did not leave exactly one sweep directory in $1/sweeps" >&2
        exit 1
    }
    echo "$1/sweeps/$names"
}

# The draft post reads: the targets as given, under a fixed title and
# brief. `--argjson` parses SWEEPKY_DEMO_TARGETS as JSON, so its text can
# only ever become the draft's targets, never part of the jq program.
# shellcheck disable=SC2016 # $targets is a jq variable (--argjson), not the shell's
draft_filter='{title: "Demo bounty", brief: "The bounty of Sweepky'"'"'s local demo.\n", targets: $targets}'

# The stranger's findings.json: the fixture's one finding, moved to the
# locations of the run directory's first finding, so the two group by place
# whatever the run directory holds. A Cloudflare findings.json (an array)
# gives them as submit converts them: each trace step's file, line, kind
# and scope, then each evidence entry's file and line, absent fields left
# out. Sweepky's common format (an object) holds them as they are.
# shellcheck disable=SC2016 # $run is a jq variable (--slurpfile), not the shell's
stranger_filter='
def first_locations:
  if type == "array" then
    (.[0] // error("the run directory has no finding"))
    | [(.trace // [])[] | {file, line, kind, scope}] + [(.evidence // [])[] | {file, line}]
    | map(with_entries(select(.value != null)))
  else
    .findings[0].locations // error("the run directory has no finding")
  end;
.findings[0].locations = ($run[0] | first_locations)'

# ----- Helpers for --ci's checks -----

# Set by step 6; empty for the checks before it.
stranger_sweep_url=""

# jq with the run's values as jq variables, each passed as data, never as
# part of a filter: $targets (the input targets), $sweeper, $stranger and
# $stranger_sweep (the URL of the stranger's sweep).
jq_demo() {
    jq --argjson targets "$targets_json" --arg sweeper "$sweeper" --arg stranger "$stranger" \
        --arg stranger_sweep "$stranger_sweep_url" "$@"
}

# record_is <pubky> <path> <filter>: whether the public record at <path> of
# <pubky> reads as JSON and <filter> holds of it.
record_is() {
    local body
    body=$(public_record "$1" "$2") && jq_demo -e "$3" <<< "$body"
}

# check_record <name> <pubky> <path> <filter>: record_is as a check.
check_record() {
    check "$1" "$3 could not be read or does not say so" record_is "$2" "$3" "$4"
}

# The definitions the jq checks share. The run directory's findings.json is
# Cloudflare's array or Sweepky's object, and its locations are read as
# stranger_filter reads them. locate and link_line are demo_check.rs's
# locate and linked_line: the target a location's file is in and its path
# there (null when no covered target holds it), and the line pull
# --findings prints for it with its GitHub link at the target's reviewed
# commit (null when it gets none). printed is what pull --findings printed
# from its findings heading on.
# shellcheck disable=SC2016 # $file, $targets and the rest are jq variables
jq_defs='
def run_findings: if type == "array" then .[] else .findings[] end;
def run_locations:
  if type == "array" then .[] | (.trace // [])[], (.evidence // [])[]
  else .findings[].locations[] end
  | {file, line};
def locate($targets; $covered):
  . as $file
  | if ($covered | length) == 1 then
      first($targets[] | select(.id == $covered[0]) | {target: ., file: $file})
    else
      first($covered[] as $id | $targets[] | select(.id == $id)
            | ($file | ltrimstr($id + "/")) as $rest | select($rest != $file)
            | {target: ., file: $rest})
    end // null;
def link_line($targets; $covered):
  . as $l
  | ($l.file | locate($targets; $covered)) as $at
  | if $at == null or (($at.target.repo // "") | startswith("github.com/") | not) then null
    else "  at \($l.file)" + (if $l.line == null then "" else ":\($l.line)" end)
      + " https://github.com/" + ($at.target.repo | ltrimstr("github.com/"))
      + "/blob/" + ($at.target | if .kind == "pr" then .head else .rev end)
      + "/" + ($at.file | split("/") | map(@uri) | join("/"))
      + (if ($l.line // 0) > 0 then "#L\($l.line)" else "" end) + "\n"
    end;
def printed:
  "Findings of your circle" as $heading
  | split($heading) | if length < 2 then "" else .[1:] | join($heading) end;
'

# Whether the bounty record pins each target at its input ref, where that
# ref is a full SHA: a pull request at its head, any other kind at its rev.
# shellcheck disable=SC2016 # $targets is a jq variable
pinned_filter='
(.targets | length) == ($targets | length)
and all([.targets, $targets] | transpose[];
        .[1].ref as $rev
        | ($rev | type) != "string" or ($rev | length) != 40
          or (.[0] | if .kind == "pr" then .head else .rev end) == $rev)'

# login gave the three identities three different pubkys.
three_differ() {
    [ "$1" != "$2" ] && [ "$1" != "$3" ] && [ "$2" != "$3" ]
}

# audit_moved <sweep dir> <moved audit>: submit left no audit/ in the
# sweep directory, not even a link, and a directory where it moves it.
audit_moved() {
    ! [ -e "$1/audit" ] && ! [ -L "$1/audit" ] && [ -d "$2" ]
}

# After step 5: sets bounty_targets and sweeper_covered, the bounty's targets
# and the ones the sweeper's sweep covered as their public records say
# ("[]" when one cannot be read, which fails the checks that use them),
# for this check and links_printed. Then checks that every file a location
# of the run directory names was fetched into the sweep directory <dir>,
# under target/<tid>/, with at least as many lines as the location's line.
# awk counts a last line with no newline too.
check_fetched() {
    local dir=$1 name found tid file line path short=0
    name="every file a sweeper location names was fetched with at least that many lines"
    bounty_targets=$(public_record "$owner" "$(bounty_path "$bounty_id")" | jq -c .targets) ||
        bounty_targets="[]"
    sweeper_covered=$(public_record "$sweeper" "$(sweep_path "$(basename "$dir")")" | jq -c .targets) ||
        sweeper_covered="[]"
    # One line per location, its fields split by the unit separator (a tab
    # is whitespace to read, which would merge an empty field away):
    # whether a covered target holds it, that target's id, its path there
    # and its line (0 when none). A jq that fails adds a line that fails.
    while IFS=$'\x1f' read -r found tid file line; do
        path="$dir/target/$tid/$file"
        if [ "$found" != found ] || ! [ -f "$path" ] ||
            [ "$(awk 'END { print NR }' "$path")" -lt "$line" ]; then
            short=$((short + 1))
        fi
    done < <(jq -r --argjson targets "$bounty_targets" --argjson covered "$sweeper_covered" \
        "$jq_defs"'run_locations | (.file | locate($targets; $covered)) as $at
         | if $at == null then ["missing", "", .file, 0]
           else ["found", $at.target.id, $at.file, (.line // 0)] end
         | map(tostring) | join("\u001f")' "$run_dir/findings.json" || echo "unreadable")
    if [ "$short" -eq 0 ]; then
        pass "$name"
    else
        fail "$name" "$short location(s) not in a fetched file of that length"
    fi
}

# Whether the pull output in the file <out> prints, under its findings
# heading, the title of every finding of the run directory.
titles_printed() {
    jq -e --rawfile text "$1" "$jq_defs"'($text | printed) as $p
        | all(run_findings; .title as $t | $p | contains("  title: \($t)\n"))' "$run_dir/findings.json"
}

# Whether it prints, there, every location of the run directory with its
# GitHub link at the pinned commit.
links_printed() {
    jq -e --rawfile text "$1" --argjson targets "$bounty_targets" --argjson covered "$sweeper_covered" \
        "$jq_defs"'($text | printed) as $p
        | all(run_locations; link_line($targets; $covered) as $line
              | $line != null and ($p | contains($line)))' "$run_dir/findings.json"
}

# Whether it holds, anywhere, none of the stranger's finding text: no
# title, description or fix of the findings.json step 6 made.
stranger_text_absent() {
    jq -e --rawfile text "$1" 'all(.findings[]; . as $f
        | $text | (contains($f.title) or contains($f.description)
                   or ($f.fix != null and contains($f.fix))) | not)' "$demo/stranger-findings.json"
}

# Every file under each identity's SWEEPKY_HOME is 0600 and every directory
# 0700, with nothing else there (no link). `-perm 600` without a `-` or `/`
# matches the mode exactly, in BSD and GNU find alike; -mindepth 1 leaves
# out the home itself, which this script made. Up to five offenders are
# named, through printable, as some names are the stranger's.
check_private_homes() {
    local who home loose
    for who in owner sweeper stranger; do
        home="$demo/homes/$who"
        loose=$(find "$home" -mindepth 1 \
            \( \( -type f ! -perm 600 \) -o \( -type d ! -perm 700 \) -o \( ! -type f ! -type d \) \) -print)
        if [ -z "$loose" ]; then
            pass "every file under the $who's SWEEPKY_HOME is 0600 and every directory 0700"
        else
            fail "every file under the $who's SWEEPKY_HOME is 0600 and every directory 0700" \
                "not so: $(awk 'NR <= 5' <<< "$loose" | printable | paste -sd ' ' -)"
        fi
    done
}

if $using_fixtures; then
    echo "demo-local: SWEEPKY_DEMO_RUN_DIR and SWEEPKY_DEMO_TARGETS are unset: using the synthetic fixtures in fixtures/demo. Every finding in them is made up."
fi

# ----- 2. Three identities -----

step "2. login --identity owner, sweeper and stranger, each under its own SWEEPKY_HOME"
for who in owner sweeper stranger; do
    mkdir -p "$demo/homes/$who"
    cli "login --identity $who" as "$who" login --identity "$who"
done
owner=$(pubky_of owner)
sweeper=$(pubky_of sweeper)
stranger=$(pubky_of stranger)
echo "owner    $owner"
echo "sweeper  $sweeper"
echo "stranger $stranger"
ci check "login --identity gave the three identities three different pubkys" \
    "two of them share one" three_differ "$owner" "$sweeper" "$stranger"

# ----- 3. The owner's circle -----

step "3. circle create as owner; add the sweeper"
cli "circle create" as owner circle create "Demo circle"
cli "circle add" as owner circle add "$sweeper" --label Sweeper
# shellcheck disable=SC2016 # $sweeper and the rest are jq variables (jq_demo), not the shell's
ci check_record "circle add put the sweeper in the owner's public circle" \
    "$owner" /pub/sweepky/circle.json 'any(.members[]; .pubky == $sweeper)'

if $step_mode; then
    start_board
fi

# ----- 4. The open bounty -----

pause 4
step "4. post --open as owner"
jq -n --argjson targets "$targets_json" "$draft_filter" > "$demo/bounty.json"
# Standard output only: standard error carries post's question and any
# grant-expiry warning. Its last line is the bounty's URL.
post_out=$(cli "post --open" yes_as owner post "$demo/bounty.json" --open)
echo "$post_out"
bounty_url=$(tail -n 1 <<< "$post_out")
[[ "$bounty_url" =~ ^pubky://$owner/pub/sweepky/bounties/($record_id)\.json$ ]] || {
    echo "error: post did not end with the owner's bounty URL" >&2
    exit 1
}
bounty_id=${BASH_REMATCH[1]}
echo "discovered.json:"
show_discovered
ci check_record "the open bounty is public at its URL with status open" \
    "$owner" "$(bounty_path "$bounty_id")" '.open == true and .status == "open"'
ci check_record "the bounty pins each target at the full SHA its input names" \
    "$owner" "$(bounty_path "$bounty_id")" "$pinned_filter"
ci check_record "post --open published the bounty's discovered.json with no sweep yet" \
    "$owner" "$(discovered_path "$bounty_id")" '.sweeps == []'

# ----- 5. The circle sweeper's sweep -----

pause 5
step "5. As sweeper: init, run, copy the run directory into audit/, submit"
cli "init as sweeper" as sweeper init "$demo/sweeper-project" --no-playbook
cli "run as sweeper" as_in "$demo/sweeper-project" sweeper run "$bounty_url"
sweeper_sweep=$(sweep_dir_of "$demo/sweeper-project")
sweeper_id=$(basename "$sweeper_sweep")
sweeper_sweep_url="pubky://$sweeper$(sweep_path "$sweeper_id")"
ci check_record "the sweeper's sweep record reads running after run" \
    "$sweeper" "$(sweep_path "$sweeper_id")" '.status == "running"'
ci check_fetched "$sweeper_sweep"
mkdir -p "$sweeper_sweep/audit"
# The contents, before submit, which then moves audit/ out of the project.
# No -L: a symlink in the run directory is copied as a link, and submit,
# which walks without following links, refuses it.
cp -R "$run_dir"/. "$sweeper_sweep/audit/"
cli "submit as sweeper" as_in "$demo/sweeper-project" sweeper --no-input submit \
    --run-dir "sweeps/$sweeper_id" --playbook "$playbook_sweeper"
ci check_record "the sweeper's sweep record reads done after submit" \
    "$sweeper" "$(sweep_path "$sweeper_id")" '.status == "done"'
ci check "submit moved audit/ out of the project into the sweeper's data directory" \
    "audit/ is still in the project, or not in share/submitted/$sweeper_id/" \
    audit_moved "$sweeper_sweep" "$demo/homes/sweeper/share/submitted/$sweeper_id/audit"

# ----- 6. A stranger's sweep -----

pause 6
step "6. As stranger: init, run, a synthetic audit/ sharing one location, submit"
cli "init as stranger" as stranger init "$demo/stranger-project" --no-playbook
cli "run as stranger" as_in "$demo/stranger-project" stranger run "$bounty_url"
stranger_sweep=$(sweep_dir_of "$demo/stranger-project")
stranger_id=$(basename "$stranger_sweep")
stranger_sweep_url="pubky://$stranger$(sweep_path "$stranger_id")"
ci check_record "the stranger's sweep record reads running after run" \
    "$stranger" "$(sweep_path "$stranger_id")" '.status == "running"'
mkdir -p "$stranger_sweep/audit"
cp "$repo/fixtures/demo/stranger-audit/REPORT.md" "$stranger_sweep/audit/"
# Made in the scratch directory and copied, so a check can read it after
# submit has moved audit/ away.
jq --slurpfile run "$run_dir/findings.json" "$stranger_filter" \
    "$repo/fixtures/demo/stranger-audit/findings.json" > "$demo/stranger-findings.json"
cp "$demo/stranger-findings.json" "$stranger_sweep/audit/findings.json"
cli "submit as stranger" as_in "$demo/stranger-project" stranger --no-input submit \
    --run-dir "sweeps/$stranger_id" --playbook "$playbook_stranger"
ci check_record "the stranger's sweep record reads done after submit" \
    "$stranger" "$(sweep_path "$stranger_id")" '.status == "done"'

# ----- 7. The owner's pull -----

pause 7
step "7. pull --findings as owner"
if $using_fixtures; then
    echo "demo-local: the findings below are the made-up ones of fixtures/demo."
fi
# tee keeps a copy of the report for --ci's checks; it prints as before.
cli "pull --findings" as owner pull --findings | tee "$demo/pull-findings.txt"
pulled="$demo/homes/owner/share/$bounty_id"
echo
echo "groups.json (each group's reporters and the places it was grouped by):"
jq -ac '.groups[] | {reportedBy, anchors: [.members[].anchor]}' "$pulled/groups.json"
echo "untrusted/ (the stranger's sweep, kept out of the merged report):"
# -print0 and the tr pair: a newline inside a name becomes ?, then each
# name ends its own line, so one name cannot pose as two.
(cd "$pulled/untrusted" && find . -mindepth 1 -maxdepth 2 -print0) |
    LC_ALL=C tr '\n\0' '?\n' | printable
echo "discovered.json, after the pull:"
show_discovered
ci check "the pull report labels the sweeper's sweep circle" "no '<sweep>: circle; ' line" \
    grep -qF "  $sweeper_sweep_url: circle; " "$demo/pull-findings.txt"
ci check "the pull report labels the stranger's sweep unknown" "no '<sweep>: unknown; ' line" \
    grep -qF "  $stranger_sweep_url: unknown; " "$demo/pull-findings.txt"
ci check "pull --findings prints the title of every finding of the run directory" \
    "a title is missing under its findings heading" titles_printed "$demo/pull-findings.txt"
ci check "pull --findings links every location of the run directory at the pinned commit" \
    "a location or its link is missing under its findings heading" links_printed "$demo/pull-findings.txt"
ci check "pull --findings prints none of the stranger's finding text" \
    "its output holds some" stranger_text_absent "$demo/pull-findings.txt"
# shellcheck disable=SC2016 # $sweeper and the rest are jq variables (jq_demo), not the shell's
ci check_record "discovered.json lists the stranger's sweep after the owner's pull" \
    "$owner" "$(discovered_path "$bounty_id")" 'any(.sweeps[]; . == $stranger_sweep)'
ci check "the stranger's sweep is stored under untrusted/" \
    "no untrusted/<stranger>-$stranger_id/findings.json" \
    test -f "$pulled/untrusted/$stranger-$stranger_id/findings.json"
# shellcheck disable=SC2016 # $sweeper and the rest are jq variables (jq_demo), not the shell's
ci check "groups.json has one group reported by the sweeper and the stranger" "it has not" \
    jq_demo -e '[.groups[] | select((.reportedBy | unique) == ([$sweeper, $stranger] | unique))]
                | length == 1' "$pulled/groups.json"

# ----- 8. Done -----

pause 8
step "8. done as owner, accepting the proposal {sweeper, stranger}; pull again"
# Quoted so shellcheck does not read the argument as the `done` keyword.
cli "done" yes_as owner "done" "$bounty_url"
# shellcheck disable=SC2016 # $sweeper and the rest are jq variables (jq_demo), not the shell's
ci check_record "the bounty is done, crediting exactly the sweeper and the stranger" \
    "$owner" "$(bounty_path "$bounty_id")" \
    '.status == "done" and (.credits | unique) == ([$sweeper, $stranger] | unique)'
cli "pull after done" as owner pull | tee "$demo/pull-again.txt"
ci check "the next pull labels the stranger's sweep known: 1" "no '<sweep>: known: 1 ' line" \
    grep -qF "  $stranger_sweep_url: known: 1 " "$demo/pull-again.txt"
ci check_private_homes

# Under --ci the run ends here, without the board; cleanup makes its last
# checks and prints the summary.
if $ci_mode; then
    pass "the demo flow ran to its end"
    finished=true
    exit 0
fi

# ----- 9. The board -----

step "9. The board"
if ! $step_mode; then
    start_board
fi
echo "landing  $board/"
echo "board    $board/board"
echo "bounty   $board/b/$owner/$bounty_id"
echo "demo-local: the board runs until Ctrl-C; then everything this run started stops."
# A Ctrl-C from here on is the demo's normal end, not a failure.
trap 'exit 0' INT
wait "$dev_pid" || true
echo "error: the board's dev server stopped on its own" >&2
exit 1
