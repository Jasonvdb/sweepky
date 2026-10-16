//! The `sweepky` command-line tool, as a library. `src/main.rs` is a thin
//! binary on top of it.
//!
//! Why a library: [`run`] executes a command given a [`Context`], and the
//! context carries the [`Network`] to talk to: the Pubky client, the auth relay
//! URL and the default homeserver. The binary builds that from `--testnet` /
//! `SWEEPKY_TESTNET` or the production defaults; the end-to-end test builds it
//! from a local `EphemeralTestnet` instead ([`Network::injected`]), so the same
//! code runs against a throwaway network with nothing reaching production.
//!
//! What is here so far (P2a):
//!
//! - [`Cli`] and [`Command`], the arguments, parsed with clap. `--testnet` is a
//!   global flag, so it goes before or after the command.
//! - [`Network`], its pure [`NetworkSettings`] and [`NetworkKind`], and
//!   [`select_kind`], which turns the flag and the variable into a kind and
//!   refuses a value it does not know instead of falling back to production.
//! - [`CLIENT_ID`] and [`SWEEPKY_CAPABILITY`], the client id and the
//!   capability Sweepky asks for when it signs in through a grant.
//! - `init <dir>`, the first command: it creates the directory, the `.sweepky`
//!   marker and a `.gitignore` with `sweeps/`.
//! - `clock::now()`, the current time for a record's time fields
//!   (`createdAt`, `revokedAt`, ...), as RFC 3339 in UTC to the second.
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
//!   and every listing capped by line, page and total; and the messages for
//!   a refused write (403 and 507) and every other SDK error, which never
//!   quote the server or the request URL.
//! - `display`, the terminal sanitiser: a stranger's text with its control,
//!   bidi and invisible characters written as visible `\u{..}` escapes, cut
//!   to a length.
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
//!   its public record, and `KeyStore`, the seam `keys/<deviceId>.json` is
//!   read and written through, with a fake for the unit tests.
//! - `installs`, `installs.json`: per owner, the device ids this owner's
//!   installs created here, which `keys list` and `pull` compare `keys/`
//!   against.
//! - `state`, this install's own state files: `login.json` and a dedicated
//!   identity's key and details files, read and written together.
//! - `session`, the per-command session every writing command runs in: the
//!   writers' lock, a fresh sign-in, the command's work, and a sign-out that
//!   is always attempted.
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

mod cli;
mod clock;
// This install's device key: its secret in `device.key`, its public record
// `keys/<deviceId>.json`, and the `KeyStore` seam that record is read and
// written through.
mod device;
mod dirs;
// The identity name, secret file, details file and refusal rules of
// `login --identity`.
mod identity;
// The terminal sanitiser. Nothing outside its tests calls it yet, so the same
// `expect(dead_code)` as `private_fs` below applies.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "keys list and circle show, the next P2a steps, are the first callers"
    )
)]
mod display;
mod init;
// `installs.json`: the device ids this owner's own installs created.
mod installs;
mod lock;
mod login;
mod network;
// Owner-only files and directories, which every secret and state file goes
// through.
mod private_fs;
// Bounded reads of remote records and listings, and the write-error mapping.
// `login` uses the write errors, and its key store the reads of the user's
// own records and the listing; `get_public`, for other owners' records, has
// no caller outside its tests yet, so a build without tests would warn that
// it is unused, which CI's `-D warnings` turns into an error. `expect`
// (rather than `allow`) says that warning is wanted for now and warns in
// turn once every item has a caller, so whoever adds the last one has to
// delete this line. On a `mod`, the attribute covers everything inside it.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "get_public, for other owners' records, has no caller yet"
    )
)]
mod remote;
// The per-command session. `login` already uses its lock and sign-out
// helpers; `with_writer_session` has no caller outside its test until the
// first writing command lands, so the same `expect(dead_code)` as `remote`
// above applies. On a module, `expect` is fulfilled while any item inside is
// unused, and the used ones are unaffected.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "keys, circle and logout, the next P2a steps, are the first callers"
    )
)]
mod session;
mod state;
// Fixtures the unit tests of several modules share. `cfg(test)` compiles it
// only for `cargo test`, so it never reaches the binary.
#[cfg(test)]
mod test_support;

use std::io::Write;
use std::sync::{Mutex, PoisonError};

pub use cli::{Cli, Command};
pub use dirs::Dirs;
pub use identity::IdentityName;
pub use network::{
    CLIENT_ID, Network, NetworkKind, NetworkSettings, PRODUCTION_HOMESERVER, SWEEPKY_CAPABILITY,
    TESTNET_HOMESERVER, TESTNET_RELAY_URL, select_kind,
};

/// This crate's version, `version` from Cargo.toml, which `sweepky --version`
/// prints.
///
/// `env!` reads `CARGO_PKG_VERSION`, which Cargo sets while compiling, so the
/// value is baked in at compile time and cannot drift from the manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Everything a command needs from outside itself, handed in by the caller.
///
/// The binary builds one from the arguments and the environment; a test builds
/// one around a local testnet, a temporary `SWEEPKY_HOME` and a buffer for
/// what would go to standard error. Later commands add the standard input and
/// the passphrase source here, so that no command reaches for a global.
pub struct Context {
    /// The network every command talks to.
    pub network: Network,
    /// Where this install keeps its secrets and state.
    pub dirs: Dirs,
    /// Where a command writes what it has to say before it is done: a
    /// warning before it acts, or that it is waiting for another command.
    pub stderr: StderrWriter,
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
        // `lock` fails only if another thread panicked while holding the
        // lock ("poisoned"). A writer has no state that a panic could leave
        // half-changed, so the guard is taken back with `into_inner` rather
        // than failing the command.
        let mut writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        writer.write_all(text.as_bytes())?;
        writer.write_all(b"\n")?;
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

/// Runs one parsed command.
///
/// The caller has already chosen the network: the binary from
/// [`Cli::testnet`] and `SWEEPKY_TESTNET` through [`select_kind`], a test by
/// injecting one. `async` because most commands wait on the network; `init`
/// does only a few small file operations, which are fine to do directly here.
pub async fn run(cli: Cli, ctx: &Context) -> anyhow::Result<Report> {
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
    }
}

#[cfg(test)]
mod tests {
    use super::VERSION;

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
