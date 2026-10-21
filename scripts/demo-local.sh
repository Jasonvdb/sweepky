#!/usr/bin/env bash
# Runs P5's local demo on this machine (docs/plan/phases/P5-local-demo.md,
# "scripts/demo-local.sh").
#
#   scripts/demo-local.sh [--step]
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
# and that the inputs are usable. It prints every problem it finds and
# exits 1 without starting anything.
#
# Then it builds the release binary, makes one scratch directory under
# $TMPDIR (mode 0700) and runs the demo's steps:
# 1. Starts the pinned testnet binary against local Postgres and waits until
#    it says it is running and holds the homeserver port.
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
# On every exit (the end, an error, Ctrl-C or TERM) it stops what it
# started: first the board's dev server and its vite child, then the testnet
# with kill -INT, as docs/plan/06 says, then drops a pubky_test_* database
# the testnet left behind (only one that was not there before the start,
# idle, and named the way the testnet names them), and last deletes its own
# scratch directory. It never touches a process it did not start, such as
# the Docker homeserver-testnet behind colima that holds the static ports on
# this machine.
#
# Nothing here writes to ~/.cargo, ~/.config/sweepky or ~/.local/share/sweepky,
# and nothing talks to a service other than the local testnet, Postgres and,
# for post and run, github.com read anonymously.

set -euo pipefail

usage() {
    echo "usage: scripts/demo-local.sh [--step]" >&2
    exit 2
}

step_mode=false
[ $# -le 1 ] || usage
case "${1:-}" in
"") ;;
--step) step_mode=true ;;
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

for tool in cargo node jq curl psql pg_isready lsof; do
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

[ -d web/node_modules ] ||
    problem "web/node_modules is missing; install it with: pnpm --dir web install --frozen-lockfile"

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

# The bounty's discovered.json, read anonymously from the testnet
# homeserver and printed by jq -ac: one line, with every control and
# non-ASCII character escaped. Its sweep URLs are the strangers' own.
show_discovered() {
    local body
    if body=$(curl -sf --max-time 10 --max-filesize 1048576 \
        -H "pubky-host: $owner" "http://localhost:6286/pub/sweepky/bounties/$bounty_id.discovered.json"); then
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
draft_filter='{title: "Demo bounty", brief: "The bounty of Sweepky'"'"'s local demo.\n", targets: $targets}'

# The stranger's findings.json: the fixture's one finding, moved to the
# locations of the run directory's first finding, so the two group by place
# whatever the run directory holds. A Cloudflare findings.json (an array)
# gives them as submit converts them: each trace step's file, line, kind
# and scope, then each evidence entry's file and line, absent fields left
# out. Sweepky's common format (an object) holds them as they are.
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

if $using_fixtures; then
    echo "demo-local: SWEEPKY_DEMO_RUN_DIR and SWEEPKY_DEMO_TARGETS are unset: using the synthetic fixtures in fixtures/demo. Every finding in them is made up."
fi

# ----- 2. Three identities -----

step "2. login --identity owner, sweeper and stranger, each under its own SWEEPKY_HOME"
for who in owner sweeper stranger; do
    mkdir -p "$demo/homes/$who"
    as "$who" login --identity "$who"
done
owner=$(pubky_of owner)
sweeper=$(pubky_of sweeper)
stranger=$(pubky_of stranger)
echo "owner    $owner"
echo "sweeper  $sweeper"
echo "stranger $stranger"

# ----- 3. The owner's circle -----

step "3. circle create as owner; add the sweeper"
as owner circle create "Demo circle"
as owner circle add "$sweeper" --label Sweeper

if $step_mode; then
    start_board
fi

# ----- 4. The open bounty -----

pause 4
step "4. post --open as owner"
jq -n --argjson targets "$targets_json" "$draft_filter" > "$demo/bounty.json"
# Standard output only: standard error carries post's question and any
# grant-expiry warning. Its last line is the bounty's URL.
post_out=$(yes_as owner post "$demo/bounty.json" --open)
echo "$post_out"
bounty_url=$(tail -n 1 <<< "$post_out")
[[ "$bounty_url" =~ ^pubky://$owner/pub/sweepky/bounties/($record_id)\.json$ ]] || {
    echo "error: post did not end with the owner's bounty URL" >&2
    exit 1
}
bounty_id=${BASH_REMATCH[1]}
echo "discovered.json:"
show_discovered

# ----- 5. The circle sweeper's sweep -----

pause 5
step "5. As sweeper: init, run, copy the run directory into audit/, submit"
as sweeper init "$demo/sweeper-project" --no-playbook
(cd "$demo/sweeper-project" && as sweeper run "$bounty_url")
sweeper_sweep=$(sweep_dir_of "$demo/sweeper-project")
mkdir -p "$sweeper_sweep/audit"
# The contents, before submit, which then moves audit/ out of the project.
# No -L: a symlink in the run directory is copied as a link, and submit,
# which walks without following links, refuses it.
cp -R "$run_dir"/. "$sweeper_sweep/audit/"
(cd "$demo/sweeper-project" &&
    as sweeper --no-input submit --run-dir "sweeps/$(basename "$sweeper_sweep")" \
        --playbook "$playbook_sweeper")

# ----- 6. A stranger's sweep -----

pause 6
step "6. As stranger: init, run, a synthetic audit/ sharing one location, submit"
as stranger init "$demo/stranger-project" --no-playbook
(cd "$demo/stranger-project" && as stranger run "$bounty_url")
stranger_sweep=$(sweep_dir_of "$demo/stranger-project")
mkdir -p "$stranger_sweep/audit"
cp "$repo/fixtures/demo/stranger-audit/REPORT.md" "$stranger_sweep/audit/"
jq --slurpfile run "$run_dir/findings.json" "$stranger_filter" \
    "$repo/fixtures/demo/stranger-audit/findings.json" > "$stranger_sweep/audit/findings.json"
(cd "$demo/stranger-project" &&
    as stranger --no-input submit --run-dir "sweeps/$(basename "$stranger_sweep")" \
        --playbook "$playbook_stranger")

# ----- 7. The owner's pull -----

pause 7
step "7. pull --findings as owner"
if $using_fixtures; then
    echo "demo-local: the findings below are the made-up ones of fixtures/demo."
fi
as owner pull --findings
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

# ----- 8. Done -----

pause 8
step "8. done as owner, accepting the proposal {sweeper, stranger}; pull again"
yes_as owner done "$bounty_url"
as owner pull

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
