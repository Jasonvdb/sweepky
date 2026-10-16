#!/bin/sh
# Regenerates fixtures/target-repo.git, the tiny bare git repository the
# CLI's target tests fetch from. See the `target-repo.git` section of
# fixtures/README.md for the history it builds and the SHAs it should print.
#
# Usage: fixtures/make-target-repo.sh   (from any directory; needs git 2.45+)
#
# Every name, email, date, message and file is fixed here, so the commit and
# tag SHAs come out the same on every run. The pack's file name and bytes
# depend on the git version that compresses it, so only regenerate after
# changing what this script writes.
#
# It writes only two places: a temporary directory from mktemp, removed on
# exit, and fixtures/target-repo.git, which it replaces once the new copy has
# passed its checks. It never stages or commits anything in this repository.

set -eu

die() {
	echo "make-target-repo.sh: $*" >&2
	exit 1
}

script_dir=$(cd "$(dirname "$0")" && pwd -P)
out="$script_dir/target-repo.git"
case $out in
*/fixtures/target-repo.git) ;;
*) die "refusing to write $out: this script lives in fixtures/" ;;
esac

# Drop every GIT_* variable from the caller (GIT_DIR, GIT_CONFIG_PARAMETERS,
# GIT_AUTHOR_NAME, ...), then set only the ones below.
for var in $(env | sed -n 's/^\(GIT_[A-Za-z0-9_]*\)=.*/\1/p'); do
	unset "$var"
done

work=$(mktemp -d "${TMPDIR:-/tmp}/sweepky-target-repo.XXXXXX")
trap 'rm -rf "$work"' EXIT
trap 'exit 1' HUP INT TERM

# Nobody's config, ignore rules or attributes take part: no system or user
# config (so no signing setup, hooks path or identity), and a HOME inside the
# temporary directory, so git finds no ~/.config/git/ignore (which could hide
# CLAUDE.local.md) or attributes file (which could convert line endings).
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_TERMINAL_PROMPT=0
export HOME="$work/home"
export XDG_CONFIG_HOME="$HOME/.config"
export LC_ALL=C
mkdir "$HOME"

# The one synthetic identity. Each commit sets its own date below.
export GIT_AUTHOR_NAME='Sweepky Fixture'
export GIT_AUTHOR_EMAIL='fixture@example.invalid'
export GIT_COMMITTER_NAME='Sweepky Fixture'
export GIT_COMMITTER_EMAIL='fixture@example.invalid'

src="$work/src"
bare="$work/target-repo.git"

# sha1 objects and loose-file refs, named explicitly in case a future git
# changes either default. --template= copies no hooks, info/ or description.
git init --quiet --template= --initial-branch=main --object-format=sha1 \
	--ref-format=files "$src"
cd "$src"

# commit <when> <message> <path>...: stage the named paths and commit them,
# authored and committed at <when>, unsigned whatever the caller's setup.
commit() {
	when=$1
	message=$2
	shift 2
	git add -- "$@"
	GIT_AUTHOR_DATE=$when GIT_COMMITTER_DATE=$when \
		git commit --quiet --no-verify --no-gpg-sign -m "$message"
}

# edit <file> <old> <new>: replace the one line that is exactly <old> with
# <new>. awk -v reads backslash escapes, so neither may contain a backslash.
edit() {
	count=$(grep -c -x -F -- "$2" "$1" || true)
	[ "$count" = 1 ] || die "$1: expected one line '$2', found $count"
	awk -v old="$2" -v new="$3" '$0 == old { print new; next } { print }' \
		"$1" >"$1.new"
	mv "$1.new" "$1"
}

# line_is <file> <n> <text>: fail unless line <n> of <file> is exactly <text>.
line_is() {
	[ "$(sed -n "$2p" "$1")" = "$3" ] || die "$1:$2 is not '$3'"
}

# A short, harmless file in Markdown, planted where an agent would look for
# instructions. It asks for nothing.
planted_markdown() {
	cat >"$1" <<EOF
# Sweepky fixture: planted agent file

File: \`$1\`

It is planted in Sweepky's synthetic test repository and gives no
instructions. \`sweepky run\` must strip it from the target copy before an
agent sees it, so a test that finds it in a sweep's \`target/\` has found a
bug.
EOF
}

# ---------------------------------------------------------------------------
# R: the root commit on main.

mkdir -p src/auth .claude

cat >README.md <<'EOF'
# Example service

Synthetic code for Sweepky's tests. It is never built or run, and everything
in it is made up.

The agent files here (`CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md`,
`.claude/settings.json`, `.mcp.json` and `src/auth/CLAUDE.md`) are planted on
purpose: `sweepky run` must strip them from the copy it hands an agent.
EOF

cat >src/lib.rs <<'EOF'
//! An example service. Synthetic code in Sweepky's test fixture repository:
//! it is never built or run.

pub mod http;

pub mod auth {
    pub mod handler;
    pub mod session;
}
EOF

cat >src/http.rs <<'EOF'
//! The request and response types the handlers use. Synthetic code in
//! Sweepky's test fixture repository: it is never built or run.

/// An incoming request.
pub struct Request {
    headers: Vec<(String, String)>,
    query: Vec<(String, String)>,
}

impl Request {
    /// The first header named `name`, if any.
    pub fn header(&self, name: &str) -> Option<&str> {
        find(&self.headers, name)
    }

    /// The first query parameter named `name`, if any.
    pub fn query(&self, name: &str) -> Option<&str> {
        find(&self.query, name)
    }
}

/// An outgoing response.
pub enum Response {
    /// 200 with a text body.
    Ok(String),
    /// 303 to a path on this site.
    Redirect(String),
}

impl Response {
    /// A 200 response with `body`.
    pub fn ok(body: &str) -> Self {
        Response::Ok(body.to_owned())
    }

    /// A 303 response to `location`.
    pub fn redirect(location: &str) -> Self {
        Response::Redirect(location.to_owned())
    }
}

fn find<'a>(pairs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}
EOF

cat >src/auth/session.rs <<'EOF'
//! Sessions for the example service. Synthetic code in Sweepky's test
//! fixture repository: it is never built or run.

/// How long a new session lasts, in seconds.
pub const SESSION_TTL_SECS: u64 = 3600;

/// A signed-in session.
pub struct Session {
    /// The user the session belongs to.
    pub user: String,
    /// The secret token the client presents.
    token: Vec<u8>,
    /// The first second, since the epoch, in which the session is invalid.
    expires_at: u64,
}

/// Why a presented token was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum SessionError {
    /// The request has no `Authorization` header.
    MissingHeader,
    /// The header is not `Bearer <hex>`.
    MalformedHeader,
    /// The token is not valid hex.
    BadEncoding,
    /// The token does not match this session's.
    WrongToken,
    /// The session has expired.
    Expired,
}

impl Session {
    /// Starts a session for `user` that lasts [`SESSION_TTL_SECS`].
    pub fn new(user: String, token: Vec<u8>, now: u64) -> Self {
        Session {
            user,
            token,
            expires_at: now + SESSION_TTL_SECS,
        }
    }

    /// The first second in which the session is invalid.
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Reads the token from an `Authorization: Bearer <hex>` header value
    /// and checks it against this session at `now`.
    ///
    /// The header comes from the client, so every step can fail: it may be
    /// missing, may not start with `Bearer `, or may not be hex.
    pub fn from_header(
        &self,
        header: Option<&str>,
        now: u64,
    ) -> Result<(), SessionError> {
        let value = header.ok_or(SessionError::MissingHeader)?;
        let hex = value
            .strip_prefix("Bearer ")
            .ok_or(SessionError::MalformedHeader)?;
        let presented = decode_hex(hex).ok_or(SessionError::BadEncoding)?;
        // The decoded bytes go to `validate` as they are, with no checks
        // of their own.
        self.validate(&presented, now)
    }

    /// Extends the session by [`SESSION_TTL_SECS`] from `now`.
    ///
    /// Only a session that is still valid can be extended; the caller
    /// checks that first.
    pub fn extend(&mut self, now: u64) {
        self.expires_at = now + SESSION_TTL_SECS;
    }

    /// Whether the session has run out at `now`.
    ///
    /// `expires_at` is the first second in which the session is invalid,
    /// so the session is expired from that second on.
    ///
    /// The clock is the caller's: the service passes the system time and
    /// tests pass a fixed one. Nothing here reads the clock, which keeps
    /// the check easy to test at the boundary.
    ///
    /// Seconds are whole: a session that expires at second `n` is valid
    /// for all of second `n - 1` and for none of second `n`.
    /// The comparison below has to say the same.
    pub fn is_expired(&self, now: u64) -> bool {
        now > self.expires_at
    }

    /// Checks a presented token at `now`.
    ///
    /// An expired session is refused before the token is compared, so
    /// the comparison only runs for a live session. Returns `Ok(())` when
    /// the token matches and the session is live.
    ///
    /// # Errors
    ///
    /// [`SessionError::Expired`] when [`Session::is_expired`] says so,
    /// and [`SessionError::WrongToken`] when the bytes differ.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let session = Session::new("ada".into(), vec![1, 2, 3], 0);
    /// assert_eq!(session.validate(&[1, 2, 3], 10), Ok(()));
    /// assert_eq!(
    ///     session.validate(&[1, 2, 4], 10),
    ///     Err(SessionError::WrongToken),
    /// );
    /// ```
    pub fn validate(
        &self,
        presented: &[u8],
        now: u64,
    ) -> Result<(), SessionError> {
        if self.is_expired(now) {
            return Err(SessionError::Expired);
        }
        if presented == self.token {
            Ok(())
        } else {
            Err(SessionError::WrongToken)
        }
    }
}

/// Decodes lower-case hex, or returns `None`.
fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}
EOF

cat >src/auth/handler.rs <<'EOF'
//! Request handlers for the example service. Synthetic code in Sweepky's
//! test fixture repository: it is never built or run.

use crate::auth::session::{Session, SessionError};
use crate::http::{Request, Response};

/// Where the sign-in form lives.
pub const LOGIN_PATH: &str = "/login";

/// Handles a request that needs a signed-in session.
///
/// The `Authorization` header is the client's text, so it is checked first.
pub fn handle_request(
    request: &Request,
    session: &Session,
    now: u64,
) -> Result<Response, SessionError> {
    session.from_header(request.header("Authorization"), now)?;
    Ok(Response::ok("signed in"))
}

/// Handles a successful sign-in.
///
/// The form posts back to [`LOGIN_PATH`] with the page the user came
/// from in `next`, so the user lands back where they started.
///
/// `next` is the client's text too. It goes through [`safe_redirect`]
/// before it reaches a response, so a sign-in link cannot send the user
/// to another site.
pub fn handle_login(request: &Request) -> Response {
    let next = request.query("next").unwrap_or("/");
    redirect_after_login(next)
}

/// Keeps a redirect target only if it is a path on this site.
///
/// A path starts with exactly one `/`. A target that starts with `//`
/// is scheme-relative and names another host, and anything else may
/// carry a scheme, so both fall back to `/`.
pub fn safe_redirect(target: &str) -> &str {
    let on_this_site = target.starts_with('/') && !target.starts_with("//");
    if on_this_site { target } else { "/" }
}

/// Builds the redirect sent after a successful sign-in.
fn redirect_after_login(next: &str) -> Response {
    Response::redirect(safe_redirect(next))
}
EOF

# The lines fixtures/cloudflare/findings.json points at hold the code its
# records describe. No commit below moves them.
line_is src/auth/session.rs 12 '    token: Vec<u8>,'
line_is src/auth/session.rs 64 '        self.validate(&presented, now)'
line_is src/auth/session.rs 88 '        now > self.expires_at'
line_is src/auth/session.rs 120 '        if presented == self.token {'
line_is src/auth/handler.rs 18 '    session.from_header(request.header("Authorization"), now)?;'
line_is src/auth/handler.rs 31 '    let next = request.query("next").unwrap_or("/");'
line_is src/auth/handler.rs 42 '    if on_this_site { target } else { "/" }'
line_is src/auth/handler.rs 47 '    Response::redirect(safe_redirect(next))'

planted_markdown CLAUDE.md
planted_markdown CLAUDE.local.md
planted_markdown AGENTS.md
planted_markdown src/auth/CLAUDE.md

# JSON has no comments, so the note is a string field. Neither file sets
# anything: no permissions, hooks, environment or MCP server command.
cat >.claude/settings.json <<'EOF'
{
  "sweepkyFixture": "Planted in Sweepky's synthetic test repository. It sets nothing. sweepky run must strip .claude/ from the target copy."
}
EOF
cat >.mcp.json <<'EOF'
{
  "sweepkyFixture": "Planted in Sweepky's synthetic test repository. It declares no MCP server. sweepky run must strip it from the target copy.",
  "mcpServers": {}
}
EOF

commit 2026-08-03T09:00:00+0000 'Add the example service with its auth module' \
	README.md src/lib.rs src/http.rs src/auth/session.rs src/auth/handler.rs \
	CLAUDE.md CLAUDE.local.md AGENTS.md src/auth/CLAUDE.md \
	.claude/settings.json .mcp.json
R=$(git rev-parse HEAD)

# ---------------------------------------------------------------------------
# A: a normal commit on main, tagged v0.1.0 with an annotated tag.

edit src/auth/session.rs 'pub const SESSION_TTL_SECS: u64 = 3600;' \
	'pub const SESSION_TTL_SECS: u64 = 1800;'
commit 2026-08-04T09:00:00+0000 'Shorten sessions to 30 minutes' src/auth/session.rs
A=$(git rev-parse HEAD)

GIT_COMMITTER_DATE=2026-08-04T10:00:00+0000 \
	git tag --no-sign -a -m 'v0.1.0' v0.1.0 "$A"
TAG=$(git rev-parse refs/tags/v0.1.0)

# ---------------------------------------------------------------------------
# T1: the topic branch, from A. M merges it into main later.

git checkout --quiet -b topic
cat >>README.md <<'EOF'

## Sessions

A session lasts 30 minutes from sign-in (`SESSION_TTL_SECS` in
`src/auth/session.rs`) and is valid up to, but not including, its
`expires_at` second.
EOF
commit 2026-08-05T09:00:00+0000 'Describe sessions in the README' README.md
T1=$(git rev-parse HEAD)

# ---------------------------------------------------------------------------
# B: main moves on from A. It becomes the PR's merge base.

git checkout --quiet main
edit src/auth/handler.rs 'pub const LOGIN_PATH: &str = "/login";' \
	'pub const LOGIN_PATH: &str = "/sign-in";'
commit 2026-08-06T09:00:00+0000 'Move the sign-in form to /sign-in' src/auth/handler.rs
B=$(git rev-parse HEAD)

# ---------------------------------------------------------------------------
# F1 and F2: the PR's commits, from B. They are pushed only as
# refs/pull/1/head, the ref a host keeps for a PR's head, with no branch.

git checkout --quiet -b pr
cat >>src/auth/session.rs <<'EOF'

/// Ends `session` at `now`: from that second on it is expired.
pub fn revoke(session: &mut Session, now: u64) {
    session.expires_at = now;
}
EOF
commit 2026-08-07T09:00:00+0000 'Add session revocation' src/auth/session.rs
F1=$(git rev-parse HEAD)

cat >>src/auth/handler.rs <<'EOF'

/// Handles a sign-out: the session ends at once.
pub fn handle_logout(session: &mut Session, now: u64) -> Response {
    crate::auth::session::revoke(session, now);
    Response::redirect(LOGIN_PATH)
}
EOF
commit 2026-08-08T09:00:00+0000 'Add a sign-out handler' src/auth/handler.rs
F2=$(git rev-parse HEAD)

# ---------------------------------------------------------------------------
# M: main merges topic with a merge commit, after the PR branched from B.
# So the PR's base tip (M) is not its merge base (B).

git checkout --quiet main
GIT_AUTHOR_DATE=2026-08-10T09:00:00+0000 GIT_COMMITTER_DATE=2026-08-10T09:00:00+0000 \
	git merge --quiet --no-ff --no-verify --no-gpg-sign -m "Merge branch 'topic'" topic
M=$(git rev-parse HEAD)

# ---------------------------------------------------------------------------
# The bare repository: push the four refs into an empty one, pack everything
# into one pack, and leave only the files fixtures/README.md lists.

git init --quiet --bare --template= --initial-branch=main --object-format=sha1 \
	--ref-format=files "$bare"
# Exactly the config the test expects. `git init` on macOS adds ignorecase
# and precomposeunicode, which must not be committed.
printf '[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = true\n' \
	>"$work/config"
cp "$work/config" "$bare/config"

# receive.autogc=false: no background maintenance in the new repository.
git -c receive.autogc=false push --quiet --no-verify "$bare" \
	refs/heads/main:refs/heads/main \
	refs/heads/topic:refs/heads/topic \
	refs/heads/pr:refs/pull/1/head \
	refs/tags/v0.1.0:refs/tags/v0.1.0

# One pack with its index and nothing else: no bitmap, no reverse index (.rev),
# no objects/info/packs (-n). One thread, so the same git version makes the
# same pack.
git --git-dir="$bare" -c pack.writeReverseIndex=false -c pack.threads=1 \
	repack -a -d -n -q --no-write-bitmap-index
git --git-dir="$bare" prune-packed
find "$bare" -type d -empty -delete

# Check the result before it replaces the committed copy.
cmp -s "$work/config" "$bare/config" || die "config changed"
[ -z "$(find "$bare" ! -type f ! -type d)" ] || die "something that is not a file"
set -- "$bare"/objects/pack/pack-*.pack
[ "$#" = 1 ] && [ -f "$1" ] || die "expected exactly one pack"
pack=$(basename "$1" .pack)
actual=$(cd "$bare" && find . -type f | sort)
expected=$(printf '%s\n' ./HEAD ./config "./objects/pack/$pack.idx" \
	"./objects/pack/$pack.pack" ./refs/heads/main ./refs/heads/topic \
	./refs/pull/1/head ./refs/tags/v0.1.0 | sort)
[ "$actual" = "$expected" ] || die "unexpected files:
$actual"
git --git-dir="$bare" fsck --strict --no-progress >"$work/fsck.txt"
[ ! -s "$work/fsck.txt" ] || die "fsck reported: $(cat "$work/fsck.txt")"

rm -rf "$out"
mv "$bare" "$out"

echo "Wrote $out ($pack). Record these SHAs in fixtures/README.md:"
printf '%-7s %s\n' R "$R" A "$A" T1 "$T1" B "$B" F1 "$F1" F2 "$F2" M "$M" v0.1.0 "$TAG"
