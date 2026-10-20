//! The `sweepky` command-line tool, as a library. `src/main.rs` is a thin
//! binary on top of it.
//!
//! Why a library: [`run`](fn@run) executes a command given a [`Context`], and the
//! context carries the [`Network`] to talk to: the Pubky client, the auth relay
//! URL and the default homeserver. The binary builds that from `--testnet` /
//! `SWEEPKY_TESTNET` or the production defaults; the end-to-end test builds it
//! from a local `EphemeralTestnet` instead ([`Network::injected`]), so the same
//! code runs against a throwaway network with nothing reaching production.
//!
//! What is here so far (P2a, then P2b, P2c and P2d):
//!
//! - [`Cli`] and [`Command`], the arguments, parsed with clap. `--testnet`,
//!   `--passphrase-file` and `--no-input` are global flags, so each goes
//!   before or after the command.
//! - [`Network`], its pure [`NetworkSettings`] and [`NetworkKind`], and
//!   [`select_kind`], which turns the flag and the variable into a kind and
//!   refuses a value it does not know instead of falling back to production.
//! - [`CLIENT_ID`] and [`SWEEPKY_CAPABILITY`], the client id and the
//!   capability Sweepky asks for when it signs in through a grant.
//! - `init <dir>`, the first command: it creates the directory, a
//!   `.gitignore` with `sweeps/`, the sandbox settings, a `CLAUDE.md` and a
//!   copy of the `/sweepky` skill for Claude Code, and the `.sweepky` marker.
//!   It needs no [`Context`], so
//!   the binary runs it through [`run_without_context`] before it reads
//!   HOME or the passphrase file or builds a network.
//! - `clock::now()`, the current time for a record's time fields
//!   (`createdAt`, `revokedAt`, ...), as RFC 3339 in UTC to the second, and
//!   `clock::new_record_id()`, the id of a new bounty, sweep or device key.
//! - [`Dirs`], the config and data directories (`~/.config/sweepky/` and
//!   `~/.local/share/sweepky/`, or both under `SWEEPKY_HOME`) and the paths
//!   of the files in them.
//! - `identity`, the local material of `login --identity`: [`IdentityName`],
//!   the checked name of a dedicated identity (lower case, at most 32
//!   characters, so no key is ever a valid name); its secret, in Sweepky's
//!   own `sweepky-identity/v1` file and never a Pubky recovery file; its
//!   public details; and the classifier that refuses a recovery file, a raw
//!   key or a recovery phrase with a one-line reason that never quotes it.
//! - `private_fs`, the owner-only file primitives every secret or state file
//!   goes through: directories 0700 and files 0600, each mode set when it is
//!   created, files written to a temp file then renamed, no links followed,
//!   and loose or oversized files refused on read.
//! - `lock`, the writers' lock: an exclusive `flock` on `credential.lock`,
//!   waited for without blocking the async runtime, which every command that
//!   opens a session holds around the session restore and its writes.
//! - `remote`, the network helpers every command shares: reads of public
//!   records and of the user's own (a 404 is no record), directory listings
//!   (a 404 is an empty directory), every body capped before it is buffered
//!   and every listing capped by line, page and total, and every request
//!   Sweepky sends itself refusing an answer that came through a redirect;
//!   the messages for a refused write (403 and 507), a refused upload of a
//!   sweep package (413, 429 and 507) and every other SDK error, which never
//!   quote the server or the request URL; and the conversions between core's
//!   `Pubky` and the SDK's `PublicKey`.
//! - `display`, the terminal sanitiser: a stranger's text with its control,
//!   bidi and invisible characters written as visible `\u{..}` escapes, cut
//!   to a length; a multi-line form that keeps newlines and tabs; and where
//!   either would first change a text.
//! - `login --identity <name>` (`login`): creates or reuses a dedicated
//!   identity, signs it up on its homeserver the first time, signs in,
//!   runs the shared tail on this install's first login, records the login
//!   in `login.json` and signs out again. The shared tail makes this
//!   install's age device key, records its id in `installs.json` and
//!   publishes `keys/<deviceId>.json`, the write that checks the identity
//!   may write under `/pub/sweepky/`; a refused write (403, 507 or any
//!   other) removes what the tail made and aborts.
//! - `device`, this install's device key: its secret in `device.key` (the
//!   age identity string alone, 0600, never written over an existing key),
//!   its public record, and `PublicKeys` and `KeyStore`, the seams anyone's
//!   `keys/` is read through and this user's own `keys/<deviceId>.json` is
//!   read and written through, with a fake for the unit tests.
//! - `installs`, `installs.json`: per owner, the device ids this owner's
//!   installs created here, which `login`, `keys list` and `pull` compare
//!   `keys/` against, and the alarm for an id it does not hold.
//! - `pins`, `owner-keys.json`: per bounty owner, the device keys `submit`
//!   last encrypted a sweep to, each id with its key, which `submit`
//!   compares that owner's `keys/` with the next time.
//! - `keys list` and `keys revoke <deviceId>` (`keys`): the identity's
//!   published device keys, read from public storage with no session, each
//!   unknown id alarmed on, each key this build cannot encrypt to flagged by
//!   its device id, and every string from a record sanitised; and the
//!   revoke, which sets `revokedAt` under the writers' lock and keeps every
//!   other field. `login` runs the same unknown-id check after its tail.
//! - `logout` (`logout`): under the writers' lock, revokes this install's
//!   device key while a fresh session is live, signs out, forgets the
//!   dedicated identity, and only then deletes `device.key`, `login.json`
//!   and this owner's entry in `installs.json`. When the key cannot be
//!   revoked it deletes nothing.
//! - `circle create|add|remove|show` (`circle`): the roster this identity
//!   keeps as its admin, `/pub/sweepky/circle.json`. The three writes read
//!   the record back under the writers' lock with a session of their own,
//!   change it with a pure function that keeps every field this build does
//!   not know, and write it again; every pubky is checked by the SDK and
//!   compared by its bytes, and every name and label is checked before it
//!   is written. `show` reads anyone's circle from public storage with no
//!   session, and sanitises the name and the labels it prints.
//! - `state`, this install's own state files: `login.json` and a dedicated
//!   identity's key and details files, read and written together.
//! - `session`, the per-command session every writing command runs in: the
//!   writers' lock, a fresh session (a sign-in with a dedicated identity's
//!   key, or a restore from a Ring login's grant token, refused before any
//!   request once the grant has expired and checked after it), the
//!   command's work, and the end of the session: an identity session is
//!   always signed out, a Ring session only dropped, since signing it out
//!   would revoke the grant.
//! - `passphrase`, [`Passphrase`], read from the global `--passphrase-file`,
//!   and the one way every secret file is written and read: wrapped with
//!   that passphrase through age's scrypt recipient when one is given
//!   (`login` wraps the identity file and `device.key` it creates), and
//!   unwrapped on read whenever a file starts with an age header, a wrapped
//!   file read without the passphrase being an error that says how to give
//!   it.
//! - `prompt`, standard input and the one question a command asks on it:
//!   [`StdinReader`], the context's standard input, and `confirm`, a
//!   yes-or-no question on standard error whose answer is one line of at
//!   most 1 KiB, `y` or `yes` in any case being yes and anything else no.
//!   Under the global `--no-input` it fails at once and reads nothing.
//! - `git`, the one way `post` and `run` run git: `GitRunner`, behind the
//!   `RunGit` seam, starts git with its arguments as an argv vector, an
//!   environment that is an allowlist of what `main.rs` captured
//!   ([`GitEnv`]), no system or user config, every credential path off,
//!   only allowlisted transports, no redirects, hooks, submodules or LFS,
//!   and a fresh private `HOME` under the data directory, removed when the
//!   runner is dropped; each run is timed and its output capped, and an
//!   error never quotes git. `ls-remote` and `fetch` name their repository
//!   only through a checked `git::Remote`. With it, the parser of
//!   `git ls-remote`'s output.
//! - `targets`, where `post` and `run` get a target's repository from:
//!   the `TargetResolver` seam, which pins a revision to a full SHA with
//!   an anonymous `git ls-remote` (annotated tags peeled), gives a pull
//!   request's base, head and merge base (from GitHub's unauthenticated
//!   API, for the real source), names the remote `run` fetches from and
//!   applies the target policy; [`TargetSource`], the context's
//!   choice of source; the real source, over https only, and the fixture
//!   source over the bare repository under `fixtures/`, for the tests; the
//!   checked revision; and the host policy (`targets::host`): `is_public`,
//!   the pure classifier that refuses loopback, private, link-local and
//!   otherwise reserved addresses, IPv6 forms that carry such an IPv4
//!   address included, the `ResolveHost` seam, over the system resolver,
//!   and `HttpsRemote`, the `https://<repo>` remote that git's network
//!   commands take, made only for a host whose every address is public.
//! - `post <draft.json> [--open]` (`post`): the bounty draft, read with a
//!   cap and checked as strictly as a stranger's record, its public text
//!   held to what the sanitiser prints unchanged; every target checked
//!   against the target policy and pinned through the context's target
//!   source; the bounty shown, sanitised, on standard error, and published
//!   as `bounties/<id>.json` under the writers' lock with a fresh session
//!   only once the owner says yes. With `--open` the record says `open:
//!   true`, and `post` also writes `bounties/<id>.discovered.json` with the
//!   bounty's starting cursors and no sweeps: each watched homeserver's
//!   feed head, searched after the yes and before the PUT, and the owner's
//!   own homeserver's event of the PUT, read from its stream right after
//!   it. The same cursors go into `feed-cursors.json`, never raising a
//!   lower one there.
//! - `own_storage`, `OwnStorage`: the seam through which `post`, `run` and
//!   `submit` write the signed-in user's own records and read them back,
//!   with a fake for the unit tests that can refuse a chosen write.
//! - `records`, `PublicRecords`: the seam through which `run` and `submit`
//!   read anyone's public bounty, circle and sweep records, and `run` lists
//!   their bounties and sweeps, with no session, each capped and parsed by
//!   core, each listing bounded, with a fake for the unit tests.
//! - `run [<bounty-url>] [--target <tid>] [--circle <admin>]` (`run`): in
//!   the `init` project it must be run in, whose marker may name a
//!   playbook, it checks the bounty's `pubky://` URL (anything else refused
//!   unquoted), whether this sweeper may run the bounty (status `open`,
//!   then `open: true` or the owner's own circle listing the sweeper, or
//!   with `--circle` both in that circle) and which targets it sweeps
//!   (every one this build can, or `--target`'s, case-colliding ids and
//!   the target policy refused), and shows the bounty, its title and focus
//!   sanitised and never its brief. Then it publishes `sweeps/<id>.json` as
//!   `running` under the writers' lock with a fresh session, and, outside
//!   the lock, fetches each target by its exact SHA, at depth 2, into
//!   `./sweeps/<id>/target/<tid>/`, links checked out as plain files, the
//!   agent-instruction files stripped at every depth and in any case,
//!   writes `scope.json` and `brief.md` beside them, and last the marker
//!   `sweeps/<id>/.sweepky/sweep.json`. If any of that fails, the sweep
//!   directory is removed and the record flipped to `aborted`. The report
//!   says what to run next. Without a URL it first picks, from the open
//!   bounties of the circle's members (`--circle`'s, else this install's
//!   own circle), the target their sweep records name least, reading
//!   within fixed bounds, and then runs it as for its URL and `--target`.
//! - `submit [--run-dir <dir>] [--playbook <name>]` (`submit`): it finds
//!   and checks the sweep directory, walks it through open handles without
//!   following a link, refusing links, hard links and special files within
//!   caps, and reads `audit/`; reads the sweep's own record, which must say
//!   `running`, and its bounty; builds the manifest from those two and the
//!   commits `run` fetched, which the bounty must still pin, and the
//!   package from `audit/`, Cloudflare's findings converted; checks
//!   the owner's keys against their pin, asking about new ones (or failing
//!   under `--no-input`); prints the file list; and seals the package to
//!   the owner's keys and this install's own. Then, under the writers' lock
//!   with a fresh session, it reads the record back, writes the pin,
//!   uploads `sweeps/<id>.age` and flips the record to `done`; a refused
//!   upload flips it to `aborted`, which is final, and a 429 or a network
//!   error leaves it `running`. Last, it stamps the sweep directory as
//!   submitted.
//! - `sweep_state`, `<data dir>/sweeps/<id>.json`: what `run` fetched for
//!   a sweep, each target's pins and the commit checked out, kept where
//!   the agent cannot write, which `submit` builds the manifest's
//!   `targetShas` from and removes once the record is final.
//! - `pull` (P2c): the logged-in owner and this install's device key, both
//!   read before any network read; the roster poll of the owner's circle,
//!   each key's homeserver looked up once a run and, on production, checked
//!   against the host policy; the check of the owner's `keys/` for keys
//!   this owner's installs did not create, where a check that cannot finish
//!   is an alarm too; the watched homeservers' events feeds and each open
//!   bounty's `discovered.json`, for strangers' sweeps of the owner's open
//!   bounties; each new done sweep opened with the device key, checked and
//!   stored owner-only in the data directory, strangers' in `untrusted/`;
//!   each bounty's findings grouped into `groups.json` and `merged.json`,
//!   the circle's content alone in the second; and last, under the writers'
//!   lock with a fresh session, its one public write, each open bounty's
//!   `discovered.json`, made only when its sweeps change. The report gives
//!   each feed's start and where it came from, and each sweep's trust
//!   label, status and place, a stranger's text sanitised, never a finding.
//!   Between runs it keeps two files in the data directory, one entry per
//!   owner: `feed-cursors.json`, each watched homeserver's feed cursor,
//!   which `post --open` lowers to a new bounty's starting cursor; and
//!   `poll-state.json`, what the roster poll and the feeds have seen. Both
//!   are capped, owner-only and keep the fields a newer Sweepky adds.
//! - `events` (P2c), the seam `post --open` and `pull` read a homeserver's
//!   public events through, with no session: one page of its `/events/`
//!   feed, capped and parsed by core, a page with more events than were
//!   asked for refused; and the id of the owner's latest event of one file
//!   from its non-live `/events-stream`, which must be a PUT of exactly that
//!   file. The real one asks each homeserver by its key through the SDK's
//!   HTTP client and `remote`'s unredirected `GET`, and the unit tests use a
//!   fake. With it, `find_head`, the search for a watched homeserver's last
//!   public event, an open bounty's starting cursor there: exponential, then
//!   binary, with `limit=1`, bounded in its requests, never past cursor
//!   2^62, paced for production's rate limit and stopped by a 429.
//! - `done <bounty> [--credit <pubky>]… [--no-credit <pubky>]…` (P2c,
//!   `done`): the URL and every pubky checked as text, a `--credit` naming
//!   the bounty's owner refused in one line before any file is read; then
//!   the credits proposed from the groups `pull` wrote, the sweepers of the
//!   done sweeps in them and never the owner, each shown with its trust
//!   label and the places it reported, sanitised; the flags applied; a
//!   question unless they name every proposed sweeper; and, under the
//!   writers' lock with a fresh session, the bounty read back, marked done
//!   by core with the time and the credits, checked against the record cap
//!   and written again with every field this build does not know kept.
//! - `ring` (P2d), the Pubky Ring login: the check
//!   that an approved grant can write under `/pub/sweepky/`, the notice
//!   within 30 days of the grant's expiry and once it has passed, and
//!   `grant.token`, the owner-only file that holds the grant token the SDK
//!   exports, optionally passphrase-wrapped, read back within a cap and
//!   refused in fixed text when it is not a token. `login.json` records a
//!   Ring login as the kind `ring`, with the grant's expiry. And the sign-in
//!   page, one HTML string with the QR code as an inline SVG, a copy button
//!   and a live status, made to run under a strict nonce CSP, plus the QR
//!   code the terminal prints as the fallback; the loopback server that
//!   serves it; and the approval flow: the SDK's grant flow on this
//!   network's own relay, the page opened in the browser beside the
//!   terminal fallback, a bounded wait, and an approval that cannot write
//!   `/pub/sweepky/` signed out again and refused; and `login` without
//!   `--identity`, which runs them and then, under the writers' lock, saves
//!   the token and runs `login`'s shared tail with the grant's session.
//!   [`run`](fn@run) prints the expiry notice once per command, before every
//!   command but `init`, `login` and `logout`, from `login.json` alone.
//!
//! The rules that hold for everything here (see "Rust conventions" in
//! `docs/plan/03-cli-and-skill.md`):
//!
//! - **`anyhow` errors.** This crate, library and binary alike, is the side
//!   that only has to tell a person what went wrong, so its functions return
//!   `anyhow::Result` and add context as an error travels up. `sweepky-core`
//!   returns typed `thiserror` errors, which this crate can `match` on where
//!   one case needs different handling.
//! - **Only `main.rs` reads the environment.** Everything here receives what
//!   it needs as arguments, so a test controls every input. (Edition 2024
//!   makes `std::env::set_var` `unsafe`, and this crate forbids `unsafe`, so a
//!   test could not set a variable anyway.)
//! - **Never talk to production by mistake.** A test never builds a
//!   production client; production's defaults are checked as plain data. A
//!   misconfigured `SWEEPKY_TESTNET` is an error, not production.
//! - **No panics outside tests**, by the lints below, and no `unsafe`.

// `forbid` is `deny` that nothing further down can switch back off: no
// `unsafe` anywhere in this crate, with no exceptions.
#![forbid(unsafe_code)]
// Every public item needs a `///` doc comment. CI runs clippy with
// `-D warnings`, which turns this warning into an error.
#![warn(missing_docs)]
// Outside tests, refuse the calls that panic on bad input: `.unwrap()`,
// `.expect()`, `panic!`, `v[i]` and `&s[a..b]`, and the placeholder macros
// `todo!`, `unimplemented!` and `unreachable!`, which panic when reached. Use
// `?`, `.get(i)` or a match instead. Tests may use them, because a panic is how
// a test reports a failure. The same list as sweepky-core's.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::string_slice,
        clippy::todo,
        clippy::unimplemented,
        clippy::unreachable
    )
)]

// How `login` opens the Ring sign-in page: the system opener in the
// binary, nothing or a channel to the test in the tests.
mod browser;
// `circle create|add|remove|show`: the roster in `circle.json`.
mod circle;
mod cli;
mod clock;
// This install's device key: its secret in `device.key`, its public record
// `keys/<deviceId>.json`, and the `PublicKeys` and `KeyStore` seams such
// records are read and written through.
mod device;
mod dirs;
// A homeserver's public events: one `/events/` page, the owner's latest
// event of a file from `/events-stream`, and the search for where a feed
// ends, which `post --open` starts an open bounty's discovery from.
mod events;
// The one way `post` and `run` run git: hardened, bounded and timed.
mod git;
// The identity name, secret file, details file and refusal rules of
// `login --identity`.
mod identity;
// The terminal sanitiser.
mod display;
// `done`: the credits proposed from `pull`'s groups, confirmed, and the
// bounty rewritten as done under the writers' lock.
mod done;
mod init;
// `installs.json`: the device ids this owner's own installs created.
mod installs;
// `keys list` and `keys revoke`.
mod keys;
mod lock;
mod login;
// `logout`: revoke this install's key, sign out, forget the identity, then
// delete this install's files, in that order.
mod logout;
mod network;
// `OwnStorage`: the signed-in user's own files, written and read back by
// `post`, `run` and `submit`.
mod own_storage;
// `--passphrase-file` and the one way every secret file is written and read,
// wrapped with that passphrase or plain.
mod passphrase;
// `owner-keys.json`: the keys of each bounty owner `submit` last encrypted
// a sweep to, pinned so a key added later is noticed.
mod pins;
// `post`: the bounty draft, checked and pinned into a bounty, shown, and
// published once the owner says yes.
mod post;
// `pull`: the command, and its steps in order: the roster poll with its
// homeserver lookups, the open-bounty feed watcher, the opens and the store
// of each sweep, the triage, and the one public write, `discovered.json`.
// The local state it keeps between runs is here too, whose feed cursors
// `post --open` writes as well.
mod pull;
// Owner-only files and directories, which every secret and state file goes
// through.
mod private_fs;
// Standard input, and the one yes-or-no question a command asks on it.
mod prompt;
// The Pubky Ring login: the check that a grant can write every Sweepky
// record, the expiry notice, `grant.token`, the grant token's file, the
// sign-in page with its QR codes, its loopback server and the approval
// flow that runs them, and `login` without `--identity`, which puts them
// together.
mod ring;
// `PublicRecords`: anyone's public bounty, circle and sweep records, read
// with a cap and parsed by core, and bounded listings of their bounties and
// sweeps, with a fake for the unit tests.
mod records;
// Bounded reads of remote records and listings, the write-error mapping and
// the key conversions. `login` and `keys` use the write errors and the
// conversions, and the key stores the reads of the user's own records, of
// anyone's public records and the listing.
mod remote;
// `run`: the bounty checked (or, without a URL, a target picked from the
// circle's open bounties), the sweep published as running, the targets
// fetched, stripped and scoped, and the per-sweep marker written last; or
// the sweep aborted.
mod run;
// `submit`: the sweep directory found, checked and walked without following
// a link; the manifest from the sweep's own record, its bounty and what `run`
// fetched; the
// package sealed to the bounty owner's pinned keys and this install's;
// uploaded, and the record flipped, under the writers' lock.
mod submit;
// What `run` fetched for each sweep, kept under the data directory, which
// `submit` builds the manifest's commits from.
mod sweep_state;
// The per-command session: the writers' lock, a fresh sign-in or Ring
// restore, and at the end a sign-out for an identity session (always
// attempted) or a plain drop for a Ring one. `login` holds its lock;
// `keys revoke` is the first command to run in a whole session; `logout`
// runs the sign-in and the sign-out itself, because it deletes files after
// the sign-out.
mod session;
mod state;
// Where `post` and `run` get a target's repository from, and the network
// policy for its host. `TargetSource` is public, for the context, and so is
// the fixture source, for the end-to-end test only.
mod targets;
// Fixtures the unit tests of several modules share. `cfg(test)` compiles it
// only for `cargo test`, so it never reaches the binary.
#[cfg(test)]
mod test_support;

use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};

use anyhow::bail;

pub use browser::Browser;
pub use cli::{CircleCommand, Cli, Command, KeysCommand};
pub use dirs::Dirs;
pub use git::GitEnv;
pub use identity::IdentityName;
pub use network::{
    CLIENT_ID, Network, NetworkKind, NetworkSettings, PRODUCTION_HOMESERVER, SWEEPKY_CAPABILITY,
    TESTNET_HOMESERVER, TESTNET_RELAY_URL, select_kind,
};
pub use passphrase::Passphrase;
pub use prompt::StdinReader;
// `targets` is a private module, but an item declared `pub` inside it can
// still be re-exported here as part of the library's public API.
pub use targets::TargetSource;
#[doc(hidden)]
pub use targets::fixture::FixtureTargets;

/// This crate's version, `version` from Cargo.toml, which `sweepky --version`
/// prints.
///
/// `env!` reads `CARGO_PKG_VERSION`, which Cargo sets while compiling, so the
/// value is baked in at compile time and cannot drift from the manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Everything a command needs from outside itself, handed in by the caller.
///
/// The binary builds one from the arguments and the environment; a test builds
/// one around a local testnet, a temporary `SWEEPKY_HOME`, the answers it
/// gives and a buffer for what would go to standard error. The working
/// directory and standard input are here too, so that no command reaches
/// for a global.
pub struct Context {
    /// The network every command talks to.
    pub network: Network,
    /// Where this install keeps its secrets and state.
    pub dirs: Dirs,
    /// The directory the command was run in, as an absolute path: the one
    /// `main.rs` reads with `std::env::current_dir()`, or one a test
    /// chooses. `run` and `submit` find their `init` project from it;
    /// nothing below `main.rs` asks the process for it.
    pub cwd: PathBuf,
    /// Where a command reads the answer to a question it asks (see
    /// [`StdinReader`]): standard input in the binary, fixed bytes in a test.
    pub stdin: StdinReader,
    /// Where a command writes what it has to say before it is done: a
    /// warning before it acts, or that it is waiting for another command.
    pub stderr: StderrWriter,
    /// The passphrase from `--passphrase-file`, which the caller reads with
    /// [`Passphrase::from_file`] before [`run`](fn@run): `login` wraps the secret
    /// files it creates with it, and every command that reads a wrapped one
    /// unwraps it with it. `None` without the flag; [`run`](fn@run) refuses a
    /// command line that has the flag when this is `None`, so the flag can
    /// never be dropped on the way and leave files written unwrapped.
    pub passphrase: Option<Passphrase>,
    /// What git may see of this process's environment: `PATH` and the
    /// proxy and CA variables, which `main.rs` captures with
    /// [`GitEnv::capture`]. Every git that `post` and `run` start gets these
    /// and the runner's own fixed values, nothing else.
    pub git_env: GitEnv,
    /// Where `post` and `run` get targets' repositories from:
    /// [`TargetSource::Real`] in the binary, the fixture repository in the
    /// tests.
    pub targets: TargetSource,
    /// How `login` opens its Pubky Ring sign-in page: [`Browser::System`]
    /// in the binary, [`Browser::None`] in most tests, and
    /// [`Browser::Notify`] in a test that plays Ring and needs the page's
    /// URL.
    pub browser: Browser,
}

/// Where a command writes the lines it says along the way, rather than in
/// its [`Report`] at the end: standard error in the binary, a buffer in the
/// tests, which then read what was said and when.
///
/// Warnings go here so they come out *before* the action they warn about;
/// the report is printed only once the command has finished.
///
/// A command holds the [`Context`] by shared reference (`&Context`), but
/// writing needs exclusive (`&mut`) access to the writer. The `Mutex` turns
/// one into the other at run time, one caller at a time: Rust calls this
/// interior mutability. `Box<dyn Write + Send>` is "any writer, chosen by
/// whoever builds the context", and `Send` (it may move between threads)
/// keeps the whole `Context` safe to share across tokio's worker threads.
pub struct StderrWriter {
    writer: Mutex<Box<dyn Write + Send>>,
}

impl StderrWriter {
    /// Lines written to `writer`. The binary passes `std::io::stderr()`.
    pub fn new(writer: impl Write + Send + 'static) -> Self {
        Self {
            writer: Mutex::new(Box::new(writer)),
        }
    }

    /// Writes `text` and a newline, and flushes, so the line is out before
    /// the command goes on.
    pub(crate) fn line(&self, text: &str) -> anyhow::Result<()> {
        self.write_flushed(&format!("{text}\n"))
    }

    /// Writes `text` as it is, adding no newline, and flushes: how a
    /// question is asked (`prompt::confirm`), so the answer is typed on the
    /// same line.
    pub(crate) fn write_flushed(&self, text: &str) -> anyhow::Result<()> {
        // `lock` fails only if another thread panicked while holding the
        // lock ("poisoned"). A writer has no state that a panic could leave
        // half-changed, so the guard is taken back with `into_inner` rather
        // than failing the command.
        let mut writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        writer.write_all(text.as_bytes())?;
        writer.flush()?;
        Ok(())
    }
}

/// What a command has to tell the user when it succeeds.
///
/// The binary prints [`Report::text`] as it is. A report must never carry text
/// a stranger wrote without it going through the terminal sanitiser first
/// (`display::sanitize`); `init`'s report is fixed text plus the user's own
/// path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    text: String,
}

impl Report {
    /// A report of `text`, which should end with a newline.
    pub fn new(text: impl Into<String>) -> Self {
        Self { text: text.into() }
    }

    /// The text to print.
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// Runs `cli` when its command needs nothing from a [`Context`], and hands
/// back `None` for every other command, which the caller then runs with
/// [`run`](fn@run).
///
/// `init <dir>` is the one such command so far: it works only in the
/// directory it is given. The binary calls this before it builds the
/// context, so `init` runs with HOME unset and no SWEEPKY_HOME, never opens
/// the `--passphrase-file` (it writes no secret file, so there is nothing to
/// wrap), and never builds a Pubky client: a production client starts a DHT
/// node that contacts public servers, which a local command has no reason
/// to do. [`run`](fn@run) still runs `init` when given a context, so a caller that
/// always builds one, such as the end-to-end test, can run every command
/// through [`run`](fn@run) alone.
///
/// `Option<Result<…>>` keeps the two answers apart: `None` is "not one of
/// mine, build the context and call [`run`](fn@run)", and `Some` carries the
/// command's own success or failure.
pub fn run_without_context(cli: &Cli) -> Option<anyhow::Result<Report>> {
    // Every variant is named, with no `_` arm, so a command added later does
    // not compile until someone decides whether it needs the context.
    // Matching on `&cli.command` borrows it, so `dir` is a `&PathBuf`.
    match &cli.command {
        Command::Init { dir } => Some(init::init(dir)),
        Command::Login { .. }
        | Command::Logout
        | Command::Keys { .. }
        | Command::Circle { .. }
        | Command::Post { .. }
        | Command::Run { .. }
        | Command::Submit { .. }
        | Command::Pull
        | Command::Done { .. } => None,
    }
}

/// Runs one parsed command.
///
/// The caller has already chosen the network: the binary from
/// [`Cli::testnet`] and `SWEEPKY_TESTNET` through [`select_kind`], a test by
/// injecting one. [`Cli::no_input`] is not in the context: `run` hands it,
/// as a `prompt::Prompting`, to each command that asks a question. `async`
/// because most commands wait on the network; `init` does only a few small
/// file operations, which are fine to do directly here.
/// (The binary runs `init` through [`run_without_context`] instead, so it
/// never builds a context for it.)
pub async fn run(cli: Cli, ctx: &Context) -> anyhow::Result<Report> {
    // The flag is read by the caller into `ctx.passphrase` (see `Context`).
    // A caller that forgot would have `login` write the user's secrets
    // unwrapped while they believe them wrapped, so that is refused here,
    // before any command runs.
    if cli.passphrase_file.is_some() && ctx.passphrase.is_none() {
        bail!(
            "--passphrase-file was given, but the passphrase was not read before the command \
             ran; this is a bug in the caller of sweepky_cli::run"
        );
    }
    // Once per command, before it starts: the warning that this install's
    // Ring grant is close to its end, or past it. Here rather than in the
    // writer session, because one command can open several sessions (`run`
    // publishes twice) or none (`keys list`), and the line should come out
    // exactly once either way. It reads `login.json` alone, so it comes
    // before any network read and works offline.
    //
    // `&& let` is a let chain (edition 2024): the `if` runs only when the
    // command shows the notice *and* there is one to show.
    if shows_expiry_notice(&cli.command)
        && let Some(notice) = ring::expiry_warning(&ctx.dirs)
    {
        // A courtesy line, as the lock's waiting line is: if standard
        // error cannot be written, the command still runs.
        let _ = ctx.stderr.line(&format!("warning: {notice}"));
    }
    match cli.command {
        Command::Init { dir } => init::init(&dir),
        Command::Login {
            identity,
            homeserver,
            signup_token,
        } => {
            // `as_deref` lends out an `Option<&str>` from an
            // `Option<String>`; `as_ref` an `Option<&SecretString>`, so the
            // token is borrowed, never copied.
            login::login(
                ctx,
                identity.as_deref(),
                homeserver.as_deref(),
                signup_token.as_ref(),
            )
            .await
        }
        Command::Logout => logout::logout(ctx).await,
        Command::Keys { command } => match command {
            KeysCommand::List => keys::list(ctx).await,
            KeysCommand::Revoke { device_id } => keys::revoke(ctx, &device_id).await,
        },
        Command::Circle { command } => match command {
            CircleCommand::Create { name } => circle::create(ctx, &name).await,
            CircleCommand::Add { pubky, label } => circle::add(ctx, &pubky, label.as_deref()).await,
            CircleCommand::Remove { pubky } => circle::remove(ctx, &pubky).await,
            CircleCommand::Show { admin } => circle::show(ctx, admin.as_deref()).await,
        },
        // `match cli.command` moved only that field out of `cli`, so
        // `cli.no_input`, another field, can still be read here.
        Command::Post { draft, open } => {
            let prompting = prompt::Prompting::from_no_input_flag(cli.no_input);
            post::post(ctx, prompting, &draft, open).await
        }
        // `run::run` is the function `run` in the module `run`: a module
        // and a function live in different namespaces, so the two names
        // do not clash with this function's own.
        Command::Run {
            bounty,
            target,
            circle,
        } => run::run(ctx, bounty.as_deref(), target.as_deref(), circle.as_deref()).await,
        Command::Submit { run_dir, playbook } => {
            let prompting = prompt::Prompting::from_no_input_flag(cli.no_input);
            submit::submit(ctx, prompting, run_dir.as_deref(), playbook.as_deref()).await
        }
        // `pull` asks nothing, so it takes no `Prompting`.
        Command::Pull => pull::pull(ctx).await,
        Command::Done {
            bounty,
            credit,
            no_credit,
        } => {
            let prompting = prompt::Prompting::from_no_input_flag(cli.no_input);
            done::done(ctx, prompting, &bounty, &credit, &no_credit).await
        }
    }
}

/// Whether [`run`](fn@run) prints the Ring grant's expiry notice before
/// `command`: every command but `init`, which has no login, and `login` and
/// `logout`, which make and end the grant the notice is about.
///
/// Every variant is named, with no `_` arm, so a new command does not
/// compile until someone decides.
fn shows_expiry_notice(command: &Command) -> bool {
    match command {
        Command::Init { .. } | Command::Login { .. } | Command::Logout => false,
        Command::Keys { .. }
        | Command::Circle { .. }
        | Command::Post { .. }
        | Command::Run { .. }
        | Command::Submit { .. }
        | Command::Pull
        | Command::Done { .. } => true,
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::io;

    use clap::Parser;
    use sweepky_core::DeviceIdentity;

    use super::{Cli, Context, VERSION, run, run_without_context};
    use crate::clock;
    use crate::device::create_device_key;
    use crate::ring::ExpiryNotice;
    use crate::state::{LoginState, write_login_state};
    use crate::test_support::{
        SharedBuffer, offline_network, private_temp, random_pubky, test_context,
    };

    /// An offline install logged in through Ring, with a device key, whose
    /// grant expires at `expires_at`; its context and standard error.
    /// Nothing is reachable, so every command fails once it needs the
    /// network: what it printed before then is what these tests look at.
    fn offline_ring_install(home: &tempfile::TempDir, expires_at: u64) -> (Context, SharedBuffer) {
        let (ctx, stderr) = test_context(offline_network(), home, io::empty());
        write_login_state(
            &ctx.dirs,
            &LoginState::ring(random_pubky(), random_pubky(), expires_at),
        )
        .expect("writes login.json");
        create_device_key(&ctx.dirs, &DeviceIdentity::generate(), None).expect("writes device.key");
        (ctx, stderr)
    }

    /// Runs `args` through `run` on `ctx`, and returns what it wrote to
    /// standard error, how many of those lines hold `notice`, and its result.
    async fn notices_printed(
        ctx: &Context,
        stderr: &SharedBuffer,
        args: &[&str],
        notice: &str,
    ) -> (String, usize, anyhow::Result<super::Report>) {
        let before = stderr.text().len();
        let cli = Cli::try_parse_from(std::iter::once("sweepky").chain(args.iter().copied()))
            .expect("parses");
        let result = run(cli, ctx).await;
        let said = stderr.text();
        let said = said.get(before..).expect("only grows").to_owned();
        let count = said.lines().filter(|line| line.contains(notice)).count();
        (said, count, result)
    }

    #[tokio::test]
    async fn the_expiry_warning_comes_once_per_command_before_any_request() {
        let home = private_temp();
        let now = clock::now_unix_seconds().expect("a clock");
        let expires_at = now + 10 * 86_400;
        let (ctx, stderr) = offline_ring_install(&home, expires_at);
        let line = format!("warning: {}", ExpiryNotice::Soon { expires_at });

        // `pull` reads login.json and device.key, then every network read
        // it tries fails on this offline network, and `keys list` needs a
        // public read: each says the warning once, as its first line, so
        // before anything a network read made it say.
        for args in [&["pull"][..], &["keys", "list"]] {
            let (said, count, _) = notices_printed(&ctx, &stderr, args, &line).await;
            assert_eq!(count, 1, "{args:?}: {said}");
            assert!(said.starts_with(&line), "{args:?}: {said}");
        }

        // `login` and `logout` make and end the grant, so they say nothing.
        for args in [&["login"][..], &["logout"]] {
            let (said, count, _) = notices_printed(&ctx, &stderr, args, "Pubky Ring grant").await;
            assert_eq!(count, 0, "{args:?}: {said}");
        }
    }

    #[tokio::test]
    async fn an_expired_grant_is_noticed_once_and_a_read_only_command_still_runs() {
        let home = private_temp();
        let expires_at = 1_000_000_000;
        let (ctx, stderr) = offline_ring_install(&home, expires_at);
        let line = format!("warning: {}", ExpiryNotice::Expired { expires_at });

        let (said, count, result) = notices_printed(&ctx, &stderr, &["keys", "list"], &line).await;
        assert_eq!(count, 1, "{said}");
        // `keys list` went on after the notice: what stopped it is the
        // offline network, not the grant, which a public read never uses.
        let error = format!("{:#}", result.expect_err("offline"));
        assert!(!error.contains("Pubky Ring grant"), "{error}");
    }

    #[tokio::test]
    async fn no_ring_login_no_notice() {
        // No login.json, and a broken one: nothing from the notice; the
        // command reports the file itself.
        let home = private_temp();
        let (ctx, stderr) = test_context(offline_network(), &home, io::empty());
        let (_, count, _) =
            notices_printed(&ctx, &stderr, &["keys", "list"], "Pubky Ring grant").await;
        assert_eq!(count, 0);
        crate::private_fs::ensure_private_dir(ctx.dirs.config()).expect("mkdir");
        crate::private_fs::write_private_file(&ctx.dirs.login_file(), b"{").expect("writes");
        let (_, count, result) =
            notices_printed(&ctx, &stderr, &["keys", "list"], "Pubky Ring grant").await;
        assert_eq!(count, 0);
        assert!(result.is_err());
    }

    #[test]
    fn init_runs_with_no_context() {
        // `run_without_context` is given the parsed arguments and nothing
        // else: no `Dirs`, so it cannot have read HOME or SWEEPKY_HOME; no
        // `Network`, so it cannot have built a Pubky client; and no
        // `Passphrase`. The `--passphrase-file` here names a file that does
        // not exist, so init succeeding shows the file is never opened.
        let temp = tempfile::tempdir().expect("temp dir");
        let dir = temp.path().join("project");
        let missing = temp.path().join("no-passphrase-here");
        let cli = Cli::try_parse_from([
            OsStr::new("sweepky"),
            OsStr::new("--passphrase-file"),
            missing.as_os_str(),
            OsStr::new("init"),
            dir.as_os_str(),
        ])
        .expect("parses");

        let report = run_without_context(&cli)
            .expect("init needs no context")
            .expect("init succeeds");

        assert!(report.text().starts_with("Initialised "), "{report:?}");
        assert!(dir.join(super::init::MARKER).is_file());
        assert!(!missing.exists());
    }

    #[test]
    fn every_other_command_needs_the_context() {
        // `None` hands the command back to the caller, which builds the
        // context (and so reads HOME and the passphrase file, and builds the
        // network) before `run`. One command line for every command but
        // `init`, down to each `keys` and `circle` subcommand. A slice of
        // slices, so adding a line needs no count updated by hand.
        let commands: &[&[&str]] = &[
            &["login", "--identity", "x"],
            &["logout"],
            &["keys", "list"],
            &["keys", "revoke", "id"],
            &["circle", "create", "name"],
            &["circle", "add", "pk"],
            &["circle", "remove", "pk"],
            &["circle", "show"],
            &["post", "draft.json"],
            &["post", "--open", "draft.json"],
            &["run"],
            &[
                "run",
                "pubky://owner/pub/sweepky/bounties/0035G87EK4XFE.json",
                "--target",
                "t1",
                "--circle",
                "admin",
            ],
            &["submit"],
            &[
                "submit",
                "--run-dir",
                "sweeps/0035G87EK4XFE",
                "--playbook",
                "cloudflare/security-audit@c1c8a8c",
            ],
            &["pull"],
            &[
                "done",
                "pubky://owner/pub/sweepky/bounties/0035G87EK4XFE.json",
                "--credit",
                "b",
                "--no-credit",
                "c",
            ],
        ];
        for args in commands {
            // With and without `--no-input`, which changes nothing here: the
            // commands that ask a question all run with the context. An
            // `Option` is an iterator of zero or one items, so `chain(flag)`
            // adds the flag only when it is `Some`.
            for flag in [None, Some("--no-input")] {
                let cli = Cli::try_parse_from(
                    std::iter::once("sweepky")
                        .chain(args.iter().copied())
                        .chain(flag),
                )
                .expect("parses");
                assert!(run_without_context(&cli).is_none(), "{args:?} {flag:?}");
            }
        }
    }

    #[test]
    fn version_is_major_minor_patch() {
        let parts: Vec<&str> = VERSION.split('.').collect();
        assert_eq!(
            parts.len(),
            3,
            "VERSION {VERSION:?} is not major.minor.patch"
        );
        for part in parts {
            assert!(
                part.parse::<u64>().is_ok(),
                "VERSION {VERSION:?}: {part:?} is not a number"
            );
        }
    }
}
