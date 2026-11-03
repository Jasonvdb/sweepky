#!/usr/bin/env bash
# Starts a throwaway Postgres for the release workflow's end-to-end job, on a
# GitHub Actions runner, and tells the job's later steps where it is.
#
#   scripts/release/start-postgres.sh
#
# The end-to-end job runs `scripts/demo-local.sh --ci --binary PATH`, whose
# pinned pubky-testnet keeps its homeserver's data in Postgres: it creates
# one pubky_test_<uuid> database per run through
# TEST_PUBKY_CONNECTION_STRING. ci.yml's test job gets Postgres as a
# service container, but service containers exist only on Linux runners,
# and the release workflow runs the end-to-end job on macOS too. So this
# script starts one by hand, the same way on every runner it supports:
#
# - Linux: `docker run` of postgres:18.4, the image tag ci.yml's service
#   uses, published on localhost:5432, with trust authentication (no
#   password: the server is reachable only from this runner, and it lives
#   only as long as the job). The superuser is postgres. psql and
#   pg_isready, which the demo's preflight and cleanup need, come from the
#   runner image; apt installs postgresql-client only when either is
#   missing.
# - macOS: `brew install postgresql@18`. Homebrew pins only the major
#   version, so the minor version floats: the one test-only piece of the
#   release that is not pinned exactly. initdb makes a cluster in
#   $RUNNER_TEMP/pgdata, owned by and trusting the runner's own user, which
#   is its superuser, and pg_ctl starts it on port 5432, logging to
#   $RUNNER_TEMP/postgres.log. The formula is keg-only (not linked onto
#   PATH), so its bin/ directory is added to $GITHUB_PATH for the steps
#   after this one.
#
# Then it waits up to 60 s for pg_isready to answer, and appends
#
#   TEST_PUBKY_CONNECTION_STRING=postgres://<user>@localhost:5432/postgres
#
# to $GITHUB_ENV, so every later step of the job sees it, and prints it.
# The URL holds no secret: trust authentication needs no password.
#
# CI only. It refuses to run unless CI=true, which GitHub Actions sets on
# every runner, because on a developer's machine it would start a second
# Postgres on the port the shared local one uses (docs/plan/06), install
# packages system-wide, and write to files Actions owns. A developer runs
# the demo against their own Postgres instead. Nothing here stops the server:
# the runner is thrown away with the job. Written for bash 3.2, the one
# macOS ships, as well as Linux's bash.

set -euo pipefail

if [ $# -ne 0 ]; then
    echo "usage: scripts/release/start-postgres.sh" >&2
    exit 2
fi

if [ "${CI:-}" != true ]; then
    echo "error: start-postgres.sh runs only in CI (CI=true); locally, use your own Postgres" >&2
    exit 2
fi
for var in GITHUB_ENV GITHUB_PATH RUNNER_TEMP; do
    if [ -z "${!var:-}" ]; then
        echo "error: $var is not set; run this as a GitHub Actions step" >&2
        exit 2
    fi
done

case "$(uname -s)" in
Linux)
    user=postgres
    docker run -d --name sweepky-e2e-postgres -e POSTGRES_HOST_AUTH_METHOD=trust \
        -p 5432:5432 postgres:18.4 > /dev/null
    if ! command -v psql > /dev/null || ! command -v pg_isready > /dev/null; then
        sudo apt-get update -q
        sudo apt-get install -y -q postgresql-client
    fi
    ;;
Darwin)
    user=$(id -un)
    brew install postgresql@18
    bin="$(brew --prefix postgresql@18)/bin"
    export PATH="$bin:$PATH"
    echo "$bin" >> "$GITHUB_PATH"
    data="$RUNNER_TEMP/pgdata"
    initdb -D "$data" -U "$user" --auth=trust --encoding=UTF8 > /dev/null
    # -w waits for the server to start; -o passes the port to it.
    pg_ctl -D "$data" -l "$RUNNER_TEMP/postgres.log" -o "-p 5432" -w start
    ;;
*)
    echo "error: no Postgres recipe for $(uname -s)" >&2
    exit 1
    ;;
esac

url="postgres://$user@localhost:5432/postgres"
ready=false
for _ in $(seq 1 60); do
    if pg_isready -q -d "$url"; then
        ready=true
        break
    fi
    sleep 1
done
if ! $ready; then
    echo "error: Postgres did not accept connections on localhost:5432 within 60 s" >&2
    exit 1
fi

echo "TEST_PUBKY_CONNECTION_STRING=$url" >> "$GITHUB_ENV"
echo "TEST_PUBKY_CONNECTION_STRING=$url"
