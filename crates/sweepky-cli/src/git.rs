//! The one way `sweepky` runs git: `post` lists a repository's refs with
//! `ls-remote`, and `run` fetches a target by its exact SHA. Every git
//! process goes through [`GitRunner`], which makes it hold to these rules:
//!
//! - **Arguments as an argv vector, never through a shell.** Nothing is ever
//!   joined into a command line for `sh` to split, so `$`, `;` or a space in
//!   a value is just a character. Options are `&'static str`s the code
//!   itself writes ([`GitCommand::flag`]); every other argument is an
//!   operand, and an operand that starts with `-`, which git would read as
//!   an option, is refused ([`git_argv`]). `RepoName`, `GitSha` and the ref
//!   patterns are checked before they get here, so none can.
//! - **Only a checked repository is contacted.** The two subcommands that
//!   talk to a repository, `ls-remote` and `fetch`, are built only with a
//!   [`Remote`]: an [`HttpsRemote`], which exists only for a host whose
//!   every address is public (`targets::host`), or the fixture source's
//!   [`LocalRemote`]. Every other subcommand is a [`LocalSubcommand`],
//!   which works on this disk alone. So no URL that a record or a server
//!   wrote reaches git unchecked.
//! - **A pure allowlist for an environment.** The child starts from an
//!   empty environment (`env_clear`) and gets back exactly [`child_env`]'s
//!   list: `PATH`, the proxy and CA variables `main.rs` captured
//!   ([`GitEnv`]), a private `HOME`, and fixed values that switch off the
//!   system and user config, the terminal prompt and LFS. So no `GIT_DIR`,
//!   `GIT_CONFIG_PARAMETERS`, `GIT_ASKPASS` or `SSH_ASKPASS` from the
//!   user's shell reaches git.
//! - **No config but ours.** `GIT_CONFIG_NOSYSTEM=1` and
//!   `GIT_CONFIG_GLOBAL=/dev/null` skip `/etc/gitconfig` and
//!   `~/.gitconfig`; the private `HOME` has no `~/.gitconfig`,
//!   `~/.config/git/` or `~/.netrc` (curl's) either.
//!   `GIT_CEILING_DIRECTORIES` stops git's search for a repository at the
//!   data directory, so a repository higher up, such as a home directory
//!   kept in git, cannot lend its `.git/config`.
//! - **Every credential path off.** `credential.helper=` (an empty value
//!   empties the list of helpers, Apple git's bundled `osxkeychain`
//!   included), `core.askPass=`, `GIT_TERMINAL_PROMPT=0`, and standard input
//!   from `/dev/null`: git can neither find a saved password nor ask for
//!   one, so a private repository fails instead of passing through.
//! - **Only allowlisted transports, and no redirects.** `protocol.allow=never`
//!   then `protocol.https.allow=always`; `file` only for the fixture source
//!   ([`AllowedProtocols::HttpsAndFile`]). `http.followRedirects=false`,
//!   because a redirect could point an anonymous fetch at a host on the
//!   sweeper's own network.
//! - **Nothing in a repository runs or is trusted.** No hooks
//!   (`core.hooksPath=/dev/null`), no fsmonitor, symlinks checked out as
//!   plain files, no submodules, no LFS smudge, and every fetched object
//!   checked (`transfer.fsckObjects=true`).
//! - **Bounded and timed.** Standard output and standard error are read at
//!   the same time, each up to its own cap, and every run has a timeout
//!   ([`Limits`]); a child past either is killed.
//! - **git's words are never shown.** Its standard error carries
//!   `remote:` lines a server wrote, so an error says which git command
//!   failed and its exit status, in fixed text ([`GitFailed`]), and never
//!   quotes git.
//!
//! [`RunGit`] is the seam: [`GitRunner`] is the real one, and a later test
//! can record or fake invocations. [`parse_ls_remote`] reads `ls-remote`'s
//! output, and [`ls_remote`] puts the two together.
//!
//! **Limits recorded in the P2b phase doc.** git 2.32 or later
//! (`GIT_CONFIG_GLOBAL`; an older git still reads no user config, because
//! `HOME` is empty). SHA-1 repositories only: [`parse_ls_remote`] takes
//! 40-hex object names, so a SHA-256 repository is refused, although core's
//! `GitSha` also accepts 64. Killing git does not kill a helper it started
//! (`git-remote-https`); the helper dies when its pipes close.

// Nothing calls the runner yet: `post` and `run`, later in P2b, are its
// first callers, so outside the tests the compiler would warn that most of
// this module is dead code. As in `prompt.rs`, `expect` (not `allow`)
// silences that only while it is true, and the first caller removes it.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "post and run, later in P2b, are the first callers of the git runner"
    )
)]

use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use anyhow::{Context as _, bail};
use sweepky_core::{GitSha, RecordId};
// `AsyncReadExt` adds `.take()` and `.read_to_end()` to tokio's pipes; a
// trait's methods can only be called while it is in scope.
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::Dirs;
use crate::clock;
use crate::private_fs::{ensure_private_dir, lstat};
use crate::targets::fixture::LocalRemote;
use crate::targets::host::HttpsRemote;

/// The variables of this process's environment that git may see, captured
/// by `main.rs`: `PATH`, to find git, and the proxy and CA variables, so
/// git reaches the network the way the user's other tools do. Nothing else
/// of the environment reaches git.
///
/// No `Debug`, on purpose: a proxy URL can hold a password
/// (`https://user:password@proxy:8080`).
pub struct GitEnv {
    /// Each name from [`GitEnv::NAMES`] that was set, with its value, in
    /// that order. `OsString`, not `String`: a value need not be UTF-8.
    vars: Vec<(&'static str, OsString)>,
}

impl GitEnv {
    /// The names [`GitEnv::capture`] asks for. Only `https` is allowed, so
    /// `http_proxy` is not needed; curl reads the rest.
    pub const NAMES: [&'static str; 9] = [
        "PATH",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
    ];

    /// Asks `lookup` for each of [`GitEnv::NAMES`] and keeps those it has a
    /// value for. The binary passes `std::env::var_os`; a test passes a
    /// closure.
    ///
    /// The parameter is `&'static str`, not `&str`, because every name is a
    /// constant. That lets `std::env::var_os`, a generic function, be
    /// passed as it is: for `&str` the compiler would need it to accept a
    /// borrow of *any* lifetime, which a generic function picked for one
    /// type cannot promise.
    pub fn capture(mut lookup: impl FnMut(&'static str) -> Option<OsString>) -> Self {
        let vars = Self::NAMES
            .into_iter()
            .filter_map(|name| lookup(name).map(|value| (name, value)))
            .collect();
        Self { vars }
    }

    /// Whether `PATH` was set, without which there is no git to find.
    fn has_path(&self) -> bool {
        self.vars.iter().any(|(name, _)| *name == "PATH")
    }
}

/// The environment of every git child, and nothing else: `captured` (PATH
/// first, then the proxy and CA variables that were set), `HOME` the
/// private directory `home`, `GIT_CEILING_DIRECTORIES` the data directory
/// `ceiling` above it, and the fixed values that switch off the system and
/// user config, the terminal prompt and LFS, and pin messages to English.
///
/// Pure, so a test checks the whole list. [`GitRunner`] calls
/// `env_clear()` first, so this list is the child's whole environment.
pub(crate) fn child_env(
    captured: &GitEnv,
    home: &Path,
    ceiling: &Path,
) -> Vec<(OsString, OsString)> {
    let fixed = [
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_TERMINAL_PROMPT", "0"),
        ("GIT_LFS_SKIP_SMUDGE", "1"),
        ("LC_ALL", "C"),
    ];
    captured
        .vars
        .iter()
        .map(|(name, value)| (OsString::from(name), value.clone()))
        .chain([
            ("HOME".into(), home.into()),
            ("GIT_CEILING_DIRECTORIES".into(), ceiling.into()),
        ])
        .chain(fixed.map(|(name, value)| (name.into(), value.into())))
        .collect()
}

/// The `-c` settings every git run gets, before its subcommand. See the
/// module docs for why each is there.
const HARDENING: [&str; 12] = [
    "credential.helper=",
    "core.askPass=",
    "protocol.allow=never",
    "protocol.https.allow=always",
    "http.followRedirects=false",
    "core.hooksPath=/dev/null",
    "core.fsmonitor=false",
    "core.symlinks=false",
    "submodule.recurse=false",
    "fetch.recurseSubmodules=false",
    "transfer.fsckObjects=true",
    "advice.detachedHead=false",
];

/// Which transports a [`GitRunner`] lets git use; it refuses every other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AllowedProtocols {
    /// `https` only: every real target.
    Https,
    /// `https` and `file`: only for the fixture source, which serves the
    /// bare repository under `fixtures/` from this disk.
    HttpsAndFile,
}

impl AllowedProtocols {
    /// The `-c` settings this choice adds to [`HARDENING`].
    fn settings(self) -> &'static [&'static str] {
        match self {
            Self::Https => &[],
            Self::HttpsAndFile => &["protocol.file.allow=always"],
        }
    }
}

/// How long one git run may take, and how much it may write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    /// Past this, the child is killed.
    pub(crate) timeout: Duration,
    /// The most standard output may hold; one byte more and the child is
    /// killed.
    pub(crate) stdout_cap: usize,
    /// The same for standard error, which is only ever matched against
    /// fixed text ([`GitFailed::stderr_mentions`]), never shown.
    pub(crate) stderr_cap: usize,
}

/// The most standard error a git run may write: 64 KiB. git writes a line
/// or two; the rest is room for `remote:` lines.
const STDERR_CAP: usize = 64 * 1024;

/// The most lines [`parse_ls_remote`] reads: 1024. `post` asks for a
/// handful of refs by name, so a server that answers more is refused.
pub(crate) const MAX_LS_REMOTE_LINES: usize = 1024;

/// The longest `ls-remote` line [`parse_ls_remote`] reads, its newline not
/// counted: 1024 bytes, a SHA, a tab and a ref name of up to 983 bytes.
pub(crate) const MAX_LS_REMOTE_LINE_BYTES: usize = 1024;

/// `ls-remote`'s limits: 60 seconds, and standard output just large enough
/// for [`MAX_LS_REMOTE_LINES`] lines of [`MAX_LS_REMOTE_LINE_BYTES`] and
/// their newlines.
pub(crate) const LS_REMOTE_LIMITS: Limits = Limits {
    timeout: Duration::from_secs(60),
    stdout_cap: MAX_LS_REMOTE_LINES * (MAX_LS_REMOTE_LINE_BYTES + 1),
    stderr_cap: STDERR_CAP,
};

/// `run`'s fetch's limits: 10 minutes, for a large repository on a slow
/// link. `git fetch` writes its few lines to standard error and nothing to
/// standard output, so 64 KiB is room to spare.
const FETCH_LIMITS: Limits = Limits {
    timeout: Duration::from_secs(10 * 60),
    stdout_cap: 64 * 1024,
    stderr_cap: STDERR_CAP,
};

/// The repository a network subcommand (`ls-remote` or `fetch`) talks to,
/// and the only way to name one: a real target's [`HttpsRemote`], whose
/// host the policy has checked, or the fixture source's [`LocalRemote`].
///
/// No string converts into it, so an unchecked URL cannot reach git
/// through [`GitCommand::ls_remote`] or [`GitCommand::fetch`]. It borrows
/// the remote, which is why it has a lifetime `'a` and is `Copy`: copying
/// it copies a reference, never the URL.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Remote<'a> {
    /// A real target, at `https://<repo>`.
    Https(&'a HttpsRemote),
    /// The fixture source's repository on this disk, at `file://<path>`,
    /// which needs [`AllowedProtocols::HttpsAndFile`].
    Local(&'a LocalRemote),
}

impl<'a> Remote<'a> {
    /// The URL git is given. It borrows from the remote this borrows, so
    /// it lives as long as `'a`, not just as long as this copy.
    fn url(self) -> &'a str {
        match self {
            Self::Https(remote) => remote.as_str(),
            Self::Local(remote) => remote.as_str(),
        }
    }
}

/// A git subcommand that works on this disk alone and never contacts a
/// repository: every subcommand a [`GitCommand`] can run but `ls-remote`
/// and `fetch`, which have constructors of their own that take a
/// [`Remote`]. Add a variant when a command needs another local one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalSubcommand {
    /// `git init`.
    Init,
    /// `git config`.
    Config,
    /// `git rev-parse`.
    RevParse,
}

impl LocalSubcommand {
    /// The subcommand as git spells it.
    fn name(self) -> &'static str {
        match self {
            Self::Init => "init",
            Self::Config => "config",
            Self::RevParse => "rev-parse",
        }
    }
}

/// One argument after the subcommand.
#[derive(Debug, Clone, PartialEq, Eq)]
enum GitArg {
    /// An option the code itself wrote, such as `--depth=2`. A
    /// `&'static str` is a string literal in the source, so a value from a
    /// record or a server can never become one.
    Flag(&'static str),
    /// A URL, SHA, ref or pattern: [`git_argv`] refuses one that is empty
    /// or starts with `-`.
    Operand(String),
}

/// One git command to run: `git <hardening> <subcommand> <args>`, in a
/// directory, under [`Limits`].
///
/// Built by chaining (`GitCommand::local(...).flag(...).operand(...)`):
/// each method takes `self` by value and hands it back, so no `mut` binding
/// is needed. `Clone`, `Debug` and `PartialEq`, so a fake [`RunGit`] can keep
/// the commands it was given and a test compare them: they hold URLs, SHAs
/// and ref names, nothing secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GitCommand {
    subcommand: &'static str,
    args: Vec<GitArg>,
    /// Where git runs; `None` is the runner's private `HOME`, an empty
    /// directory.
    dir: Option<PathBuf>,
    limits: Limits,
}

impl GitCommand {
    /// `git <subcommand>` under `limits`, with no arguments yet. Private,
    /// so that outside this module a command is either local
    /// ([`GitCommand::local`]) or names its repository with a [`Remote`].
    fn new(subcommand: &'static str, limits: Limits) -> Self {
        Self {
            subcommand,
            args: Vec::new(),
            dir: None,
            limits,
        }
    }

    /// `git <subcommand>` under `limits`, for a subcommand that never
    /// contacts a repository.
    pub(crate) fn local(subcommand: LocalSubcommand, limits: Limits) -> Self {
        Self::new(subcommand.name(), limits)
    }

    /// `git ls-remote <remote> <patterns>…`, under [`LS_REMOTE_LIMITS`].
    pub(crate) fn ls_remote(remote: Remote<'_>, patterns: &[&str]) -> Self {
        let mut command = Self::new("ls-remote", LS_REMOTE_LIMITS).operand(remote.url());
        for pattern in patterns {
            command = command.operand(*pattern);
        }
        command
    }

    /// `git fetch <remote>`, under [`FETCH_LIMITS`]: the caller adds the
    /// options and the SHAs to fetch, which git reads after the repository
    /// as well as before it, and the repository to fetch into
    /// ([`GitCommand::in_dir`]).
    pub(crate) fn fetch(remote: Remote<'_>) -> Self {
        Self::new("fetch", FETCH_LIMITS).operand(remote.url())
    }

    /// Adds an option, such as `--depth=2`.
    pub(crate) fn flag(mut self, flag: &'static str) -> Self {
        self.args.push(GitArg::Flag(flag));
        self
    }

    /// Adds an operand: a URL, a SHA, a ref or a pattern.
    pub(crate) fn operand(mut self, operand: impl Into<String>) -> Self {
        self.args.push(GitArg::Operand(operand.into()));
        self
    }

    /// Runs git in `dir`, which must be a repository this command made, so
    /// git's search for one stops there.
    pub(crate) fn in_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.dir = Some(dir.into());
        self
    }
}

/// The arguments git is started with: `-c <setting>` for each of
/// [`HARDENING`] and `protocols`' settings, then the subcommand, then its
/// arguments.
///
/// The settings come first because git reads `-c` only before the
/// subcommand. An operand that is empty or starts with `-` is refused,
/// with an error that does not quote it: git would read `--upload-pack=…`
/// as an option, and an option can run a program.
pub(crate) fn git_argv(
    command: &GitCommand,
    protocols: AllowedProtocols,
) -> anyhow::Result<Vec<String>> {
    let mut argv = Vec::new();
    for setting in HARDENING.iter().chain(protocols.settings()) {
        argv.push("-c".to_owned());
        argv.push((*setting).to_owned());
    }
    argv.push(command.subcommand.to_owned());
    for arg in &command.args {
        match arg {
            GitArg::Flag(flag) => argv.push((*flag).to_owned()),
            GitArg::Operand(operand) => {
                if operand.is_empty() || operand.starts_with('-') {
                    bail!(
                        "an argument for git {} is empty or starts with '-', which git could \
                         read as an option, so Sweepky refused to run it",
                        command.subcommand
                    );
                }
                argv.push(operand.clone());
            }
        }
    }
    Ok(argv)
}

/// Where `post` and `run` run git: the seam between those commands and
/// the git binary.
///
/// A trait so that a test can stand in for git: a fake can record each
/// [`GitCommand`] it is given and answer with fixed output. [`GitRunner`]
/// is the real one. As with `device::PublicKeys`, the method is an `async
/// fn`, so callers take `&impl RunGit` rather than `&dyn RunGit`, and the
/// compiler makes one copy of each caller per implementation.
pub(crate) trait RunGit {
    /// Runs `command` and returns its standard output.
    ///
    /// An exit status other than success is a [`GitFailed`] error; a
    /// command past its timeout or caps is killed and is an error too.
    /// Neither quotes anything git wrote.
    async fn run(&self, command: &GitCommand) -> anyhow::Result<Vec<u8>>;
}

/// The real [`RunGit`]: git with [`git_argv`]'s arguments and
/// [`child_env`]'s environment, in a fresh private `HOME` that is removed
/// when the runner is dropped.
///
/// One runner per command: every git run of that command shares its
/// `HOME`, and the next command gets a new one.
pub(crate) struct GitRunner {
    home: PrivateHome,
    /// [`child_env`]'s list, built once.
    env: Vec<(OsString, OsString)>,
    protocols: AllowedProtocols,
}

impl GitRunner {
    /// A runner with git allowed `protocols`, its environment built from
    /// `captured`, and a new private `HOME` under `dirs`' data directory.
    ///
    /// Refused before anything is made when `captured` has no `PATH` (there
    /// would be no git to find) or the data directory's path holds a `:`,
    /// which `GIT_CEILING_DIRECTORIES`, a `:`-separated list, cannot name.
    pub(crate) fn new(
        dirs: &Dirs,
        captured: &GitEnv,
        protocols: AllowedProtocols,
    ) -> anyhow::Result<Self> {
        if !captured.has_path() {
            bail!("PATH is not set, so Sweepky cannot find git; set PATH and try again");
        }
        if dirs.data().as_os_str().as_encoded_bytes().contains(&b':') {
            bail!(
                "{} holds a ':', so Sweepky cannot keep git from reading a repository above it; \
                 choose a SWEEPKY_HOME without one",
                dirs.data().display()
            );
        }
        let home = PrivateHome::create(dirs, &clock::new_record_id()?)?;
        let env = child_env(captured, &home.path, dirs.data());
        Ok(Self {
            home,
            env,
            protocols,
        })
    }

    /// The git process for `command`, not started yet: [`git_argv`]'s
    /// arguments, [`child_env`]'s environment and nothing else, in
    /// `command`'s directory or else the private `HOME`.
    fn process(&self, command: &GitCommand) -> anyhow::Result<tokio::process::Command> {
        let mut git = tokio::process::Command::new("git");
        // `env_clear` empties the child's environment, then `envs` gives it
        // the allowlist and nothing else. With `PATH` set this way, the
        // program `git` is looked up in that `PATH`. `iter().map(...)`
        // lends each pair as two references, which is what `envs` takes.
        git.env_clear()
            .envs(self.env.iter().map(|(name, value)| (name, value)))
            .args(git_argv(command, self.protocols)?)
            .current_dir(command.dir.as_deref().unwrap_or(&self.home.path));
        Ok(git)
    }
}

impl RunGit for GitRunner {
    async fn run(&self, command: &GitCommand) -> anyhow::Result<Vec<u8>> {
        let what = format!("git {}", command.subcommand);
        let finished = run_bounded(self.process(command)?, &what, &command.limits).await?;
        if !finished.status.success() {
            return Err(GitFailed {
                subcommand: command.subcommand,
                code: finished.status.code(),
                stderr: finished.stderr,
            }
            .into());
        }
        Ok(finished.stdout)
    }
}

/// A git run that exited with a failure status: which subcommand, and its
/// exit status, in fixed text.
///
/// It keeps git's standard error, to be matched against a fixed phrase
/// ([`GitFailed::stderr_mentions`]) and never shown: neither `Display` nor
/// the hand-written `Debug` prints it, and nothing hands it out. It may
/// hold `remote:` lines a server wrote.
pub(crate) struct GitFailed {
    subcommand: &'static str,
    /// The exit code, or `None` when a signal stopped git.
    code: Option<i32>,
    stderr: Vec<u8>,
}

impl GitFailed {
    /// git's exit code, or `None` when a signal stopped it.
    pub(crate) fn code(&self) -> Option<i32> {
        self.code
    }

    /// Whether git's standard error contains `phrase`, a fixed phrase of
    /// git's own, such as `"not our ref"`: how a caller tells one failure
    /// from another without ever showing what git wrote.
    pub(crate) fn stderr_mentions(&self, phrase: &str) -> bool {
        let phrase = phrase.as_bytes();
        // `windows(n)` is every run of `n` bytes in a row; `max(1)` keeps
        // it from being asked for runs of 0, which it refuses with a panic.
        self.stderr
            .windows(phrase.len().max(1))
            .any(|window| window == phrase)
    }
}

impl fmt::Display for GitFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.code {
            Some(code) => write!(f, "git {} failed with exit status {code}", self.subcommand),
            None => write!(f, "git {} was stopped by a signal", self.subcommand),
        }
    }
}

/// Written by hand rather than derived, so it prints how much git wrote to
/// standard error but none of it. The pattern names every field, with no
/// `..`, so a field added later does not compile until someone decides
/// whether it may print.
impl fmt::Debug for GitFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            subcommand,
            code,
            stderr,
        } = self;
        f.debug_struct("GitFailed")
            .field("subcommand", subcommand)
            .field("code", code)
            .field("stderr_bytes", &stderr.len())
            .finish()
    }
}

/// Makes it an error type, so `anyhow` takes it and a caller can find it
/// again with `downcast_ref`.
impl std::error::Error for GitFailed {}

/// A fresh, empty, private directory under the data directory, used as
/// git's `HOME` and removed when this is dropped.
///
/// With it, git and curl find no `~/.gitconfig`, `~/.config/git/` or
/// `~/.netrc`, and anything git writes there goes when the command ends.
/// `tempfile` is a dev-dependency only, and `std::env::temp_dir` reads
/// `TMPDIR`, which only `main.rs` may read, so the directory lives at
/// `<data dir>/git-home-<new record id>/`.
struct PrivateHome {
    path: PathBuf,
}

impl PrivateHome {
    /// Makes `<data dir>/git-home-<id>/`, 0700, making the data directory
    /// first (0700 too). Anything already at that path, a symlink or a
    /// directory, is refused and left alone, so the home is always new.
    fn create(dirs: &Dirs, id: &RecordId) -> anyhow::Result<Self> {
        ensure_private_dir(dirs.data())?;
        let path = dirs.git_home_dir(id);
        if lstat(&path)?.is_some() {
            bail!(
                "{} is already there; Sweepky gives git a new home for every command, so it left \
                 that one alone. Remove it and try again",
                path.display()
            );
        }
        // `ensure_private_dir` creates it 0700 in the `mkdir` itself and
        // refuses a symlink that appeared there since the check above.
        ensure_private_dir(&path)?;
        // From here the directory is this command's: if the check below
        // fails, `home` is dropped on the way out and removes it.
        let home = Self { path };
        let mut entries = fs::read_dir(&home.path)
            .with_context(|| format!("could not list {}", home.path.display()))?;
        if entries.next().is_some() {
            bail!(
                "{} was not empty when Sweepky made it; try again",
                home.path.display()
            );
        }
        Ok(home)
    }
}

/// Removes the directory when the runner is dropped, whether the command
/// succeeded, failed or returned early with `?`. Best effort: `drop` cannot
/// return an error, and a directory left behind holds nothing secret.
/// std's `remove_dir_all` removes a symlink itself and never follows it.
/// A process killed outright (`kill -9`) runs no `drop`, and leaves the
/// directory behind.
impl Drop for PrivateHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// What a bounded run produced: the exit status and both outputs, each
/// within its cap.
struct Finished {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Runs `command`, reading its standard output and standard error at the
/// same time, each up to its cap, all within `limits.timeout`. `what` names
/// it in the errors, such as `git ls-remote`.
///
/// Standard input is `/dev/null`, so the child can never wait on the
/// terminal. A child past its timeout or either cap is killed and waited
/// for before this returns, and `kill_on_drop` kills it too if this future
/// is itself dropped half-way (when the command it serves is cancelled).
async fn run_bounded(
    mut command: tokio::process::Command,
    what: &str,
    limits: &Limits,
) -> anyhow::Result<Finished> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("could not start {what}; is it installed and on PATH?"))?;
    // `timeout` drops `collect`'s future when time runs out, and with it
    // the future's borrow of `child`, so `child` can be killed below.
    match tokio::time::timeout(limits.timeout, collect(&mut child, what, limits)).await {
        Ok(Ok(finished)) => Ok(finished),
        Ok(Err(error)) => {
            kill_and_wait(&mut child).await;
            Err(error)
        }
        Err(_elapsed) => {
            kill_and_wait(&mut child).await;
            bail!(
                "{what} did not finish within {:?}, so Sweepky stopped it",
                limits.timeout
            )
        }
    }
}

/// Reads `child`'s two pipes to their ends, each up to its cap in
/// `limits`, and waits for it to exit. Fails at the first error, leaving
/// the child for the caller to kill.
async fn collect(
    child: &mut tokio::process::Child,
    what: &str,
    limits: &Limits,
) -> anyhow::Result<Finished> {
    // `take` moves each pipe out of `child`, so the reads below own them
    // while `child.wait()` borrows `child` itself.
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        bail!("could not read the output of {what}");
    };
    // `try_join!` drives the three futures together on this task, so a
    // child that fills one pipe while the other is being read never stalls,
    // and it returns at the first error.
    let (stdout, stderr, status) = tokio::try_join!(
        read_capped(stdout, limits.stdout_cap, what, "standard output"),
        read_capped(stderr, limits.stderr_cap, what, "standard error"),
        async {
            child
                .wait()
                .await
                .with_context(|| format!("could not wait for {what}"))
        },
    )?;
    Ok(Finished {
        status,
        stdout,
        stderr,
    })
}

/// Kills `child` and waits until it is gone, so no process outlives the
/// run. Ignores the error a child that has already exited gives, which
/// leaves nothing to do.
async fn kill_and_wait(child: &mut tokio::process::Child) {
    let _ = child.kill().await;
}

/// Reads `pipe` to its end, or fails as soon as it holds more than `cap`
/// bytes. `what` and `stream` name it in the error.
async fn read_capped(
    pipe: impl AsyncRead + Unpin,
    cap: usize,
    what: &str,
    stream: &str,
) -> anyhow::Result<Vec<u8>> {
    // `take(cap + 1)` stops reading one byte past the cap, so a child that
    // writes for ever never fills more than that, and one byte too many is
    // enough to tell it went over.
    let limit = u64::try_from(cap).unwrap_or(u64::MAX).saturating_add(1);
    let mut bytes = Vec::new();
    pipe.take(limit)
        .read_to_end(&mut bytes)
        .await
        .with_context(|| format!("could not read the {stream} of {what}"))?;
    if bytes.len() > cap {
        bail!("{what} wrote more than {cap} bytes to its {stream}, so Sweepky stopped it");
    }
    Ok(bytes)
}

/// One line of `git ls-remote`'s output: an object name and the ref that
/// names it.
///
/// For an annotated tag, git prints two lines: `refs/tags/<tag>` with the
/// tag object, then `refs/tags/<tag>^{}` with the commit it peels to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RemoteRef {
    /// The object: a full 40-hex SHA-1.
    pub(crate) sha: GitSha,
    /// The ref as git printed it, `HEAD` or under `refs/`, with no control
    /// character.
    pub(crate) name: String,
}

/// Lists the refs of `remote` that match `patterns` (`git ls-remote
/// <remote> <patterns>…`), through `git`.
///
/// git matches a pattern against the end of a ref's name, so `main` would
/// match `refs/heads/main` and `refs/heads/x/main`: pass full names and
/// compare [`RemoteRef::name`] exactly.
pub(crate) async fn ls_remote(
    git: &impl RunGit,
    remote: Remote<'_>,
    patterns: &[&str],
) -> anyhow::Result<Vec<RemoteRef>> {
    let stdout = git.run(&GitCommand::ls_remote(remote, patterns)).await?;
    parse_ls_remote(&stdout)
}

/// Reads `git ls-remote`'s output: one `<40 lower-hex>\t<ref>\n` line per
/// ref, `refs/tags/v0.1.0^{}` included; no output is no refs.
///
/// The output comes from a server, so it is checked, never trusted: a line
/// without its tab or its ref, a SHA that is not 40 lower-case hex
/// characters (short, upper case, or a 64-character SHA-256, which this
/// build does not support), a ref with a control character or neither
/// `HEAD` nor under `refs/`, a line that is not UTF-8 or longer than
/// [`MAX_LS_REMOTE_LINE_BYTES`], more than [`MAX_LS_REMOTE_LINES`] lines,
/// and output that does not end with a newline are all errors. An error
/// gives the line's number and never quotes it. It never panics, whatever
/// the bytes.
pub(crate) fn parse_ls_remote(output: &[u8]) -> anyhow::Result<Vec<RemoteRef>> {
    if output.is_empty() {
        return Ok(Vec::new());
    }
    let Some(body) = output.strip_suffix(b"\n") else {
        bail!("git ls-remote's output does not end with a newline");
    };
    let mut refs = Vec::new();
    // `split` hands out each line as a borrowed slice of `body`, one at a
    // time, so nothing is copied before it is checked. `zip(1..)` numbers
    // them from 1.
    for (line, number) in body.split(|&byte| byte == b'\n').zip(1_usize..) {
        if number > MAX_LS_REMOTE_LINES {
            bail!("git ls-remote listed more than {MAX_LS_REMOTE_LINES} refs");
        }
        if line.len() > MAX_LS_REMOTE_LINE_BYTES {
            bail!(
                "line {number} of git ls-remote's output is longer than \
                 {MAX_LS_REMOTE_LINE_BYTES} bytes"
            );
        }
        let parsed = parse_ls_remote_line(line)
            .with_context(|| format!("line {number} of git ls-remote's output"))?;
        refs.push(parsed);
    }
    Ok(refs)
}

/// One line of `ls-remote`'s output, its newline taken off. The error says
/// what is wrong in fixed text.
fn parse_ls_remote_line(line: &[u8]) -> anyhow::Result<RemoteRef> {
    let Ok(line) = std::str::from_utf8(line) else {
        bail!("is not UTF-8");
    };
    // `split_once` splits at the first tab; any later tab stays in the
    // name, where the control-character check refuses it.
    let Some((sha, name)) = line.split_once('\t') else {
        bail!("has no tab between an object name and a ref");
    };
    if sha.len() != GitSha::SHA1_LEN {
        bail!(
            "does not start with a 40-character SHA-1 object name (SHA-256 repositories are not \
             supported)"
        );
    }
    // Core's check: lower-case hex only. Its error is replaced with fixed
    // text of our own; it quotes nothing either, but this keeps it so.
    let Ok(sha) = sha.parse::<GitSha>() else {
        bail!("does not start with a lower-case hex object name");
    };
    if name.chars().any(char::is_control) {
        bail!("has a control character in its ref");
    }
    if name != "HEAD" && !name.starts_with("refs/") {
        bail!("names something that is neither HEAD nor a ref under refs/");
    }
    Ok(RemoteRef {
        sha,
        name: name.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::Path;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    use sweepky_core::{GitSha, RecordId};
    use tokio::process::Command;

    use super::{
        AllowedProtocols, GitCommand, GitEnv, GitFailed, GitRunner, Limits, LocalSubcommand,
        MAX_LS_REMOTE_LINE_BYTES, MAX_LS_REMOTE_LINES, PrivateHome, Remote, RemoteRef, RunGit,
        child_env, git_argv, ls_remote, parse_ls_remote, run_bounded,
    };
    use crate::Dirs;
    use crate::private_fs::ensure_private_dir;
    use crate::targets::fixture::LocalRemote;
    use crate::test_support::{
        checked_remote, dirs_in, inert_target_repo, mode, private_temp, test_git_env,
    };

    /// Commits and the tag object of `fixtures/target-repo.git`, as
    /// `fixtures/README.md` records them: M is `main`'s tip and `HEAD`, and
    /// the annotated tag `v0.1.0` peels to A.
    const M: &str = "791991b2e79a7fe8371635dc377b9cc620032465";
    const A: &str = "6a0e0f6f873af85d97788783fde43f3e3fa83133";
    const TAG: &str = "34cbfe12b3494be656721c9841b2789f887c9035";

    /// The variable that tells [`env_probe`] it was started by
    /// [`git_sees_nothing_of_this_process_environment`].
    const PROBE_VAR: &str = "SWEEPKY_GIT_ENV_PROBE";

    /// Limits for the quick local git commands the tests run.
    const LOCAL: Limits = Limits {
        timeout: Duration::from_secs(30),
        stdout_cap: 64 * 1024,
        stderr_cap: 64 * 1024,
    };

    fn sha(text: &str) -> GitSha {
        text.parse().expect("a full SHA")
    }

    fn remote_ref(sha_text: &str, name: &str) -> RemoteRef {
        RemoteRef {
            sha: sha(sha_text),
            name: name.to_owned(),
        }
    }

    /// The [`GitFailed`] inside `error`: git ran and exited with a failure.
    /// `downcast_ref` finds the typed error under any context added on top.
    fn git_failed(error: &anyhow::Error) -> &GitFailed {
        error
            .downcast_ref::<GitFailed>()
            .unwrap_or_else(|| panic!("not a git failure: {error:#}"))
    }

    #[test]
    fn ls_remote_lines_parse_into_pairs() {
        // `{{}}` is a literal `{}` in `format!`: the peeled line's `^{}`.
        let output = format!(
            "{M}\tHEAD\n{M}\trefs/heads/main\n{TAG}\trefs/tags/v0.1.0\n{A}\trefs/tags/v0.1.0^{{}}\n"
        );
        assert_eq!(
            parse_ls_remote(output.as_bytes()).expect("parses"),
            [
                remote_ref(M, "HEAD"),
                remote_ref(M, "refs/heads/main"),
                remote_ref(TAG, "refs/tags/v0.1.0"),
                remote_ref(A, "refs/tags/v0.1.0^{}"),
            ]
        );
        // No ref matched: no output, which is an empty list, not an error.
        assert_eq!(parse_ls_remote(b"").expect("parses"), []);
        // A line of exactly the longest length passes.
        let longest = format!(
            "{M}\trefs/heads/{}\n",
            "x".repeat(MAX_LS_REMOTE_LINE_BYTES - GitSha::SHA1_LEN - "\trefs/heads/".len())
        );
        assert_eq!(
            parse_ls_remote(longest.as_bytes()).expect("parses").len(),
            1
        );
        // As do exactly as many lines as the cap.
        let most = format!("{M}\trefs/heads/x\n").repeat(MAX_LS_REMOTE_LINES);
        assert_eq!(
            parse_ls_remote(most.as_bytes()).expect("parses").len(),
            MAX_LS_REMOTE_LINES
        );
    }

    #[test]
    fn malformed_ls_remote_output_is_refused_and_never_quoted() {
        // Every case carries `QUOTED` in its ref name and one of the
        // fixture's SHAs, so a message that quoted any of its line would
        // contain one or the other.
        let upper = M.to_ascii_uppercase();
        let sha256 = "ab".repeat(32);
        let too_long = format!("refs/heads/QUOTED{}", "x".repeat(MAX_LS_REMOTE_LINE_BYTES));
        let line = format!("{M}\trefs/heads/QUOTED\n");
        let cases: Vec<(&str, Vec<u8>)> = vec![
            (
                "a space for the tab",
                format!("{M} refs/heads/QUOTED\n").into(),
            ),
            ("no ref name", format!("{M}\t\nQUOTED").into()),
            (
                "a short SHA",
                format!("{}\trefs/heads/QUOTED\n", &M[..39]).into(),
            ),
            ("a long SHA", format!("{M}0\trefs/heads/QUOTED\n").into()),
            (
                "an upper-case SHA",
                format!("{upper}\trefs/heads/QUOTED\n").into(),
            ),
            (
                "a SHA-256",
                format!("{sha256}\trefs/heads/QUOTED{M}\n").into(),
            ),
            (
                "a line that is not UTF-8",
                [M.as_bytes(), b"\trefs/heads/QUOTED\xff\n"].concat(),
            ),
            (
                "a line that is too long",
                format!("{M}\t{too_long}\n").into(),
            ),
            (
                "a second tab",
                format!("{M}\trefs/heads/QUOTED\tx\n").into(),
            ),
            (
                "a terminal escape",
                format!("{M}\trefs/heads/QUOTED\x1b[2J\n").into(),
            ),
            ("a name that is not a ref", format!("{M}\tQUOTED\n").into()),
            ("no final newline", format!("{M}\trefs/heads/QUOTED").into()),
            ("an empty line", format!("{line}\n{line}").into()),
            (
                "more lines than the cap",
                line.repeat(MAX_LS_REMOTE_LINES + 1).into(),
            ),
        ];
        for (what, output) in cases {
            let error = parse_ls_remote(&output).expect_err(what);
            // Lower case, so an upper-case SHA quoted back is caught too.
            let message = format!("{error:#}").to_lowercase();
            assert!(!message.contains("quoted"), "{what}: {message}");
            assert!(!message.contains(&M[..7]), "{what}: {message}");
            assert!(!message.contains(&sha256[..8]), "{what}: {message}");
        }
    }

    #[test]
    fn ls_remote_parser_never_panics() {
        // A fixed-seed xorshift generator: the same inputs on every run, so
        // a failure reproduces, and no random-number crate. `move` hands
        // `state` to the closure, which keeps it between calls (`FnMut`).
        let mut state: u64 = 0x5eed_0f5e_ed0f_5eed;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        // Bytes the parser treats specially, so the inputs reach every
        // branch; one byte in eight is any byte at all.
        let alphabet = b"0123456789abcdefABCDEF\t\n ^{}/refsheadHEAD\x00\x1b\x7f\xc3\xa9";
        let valid = format!("{M}\tHEAD\n{TAG}\trefs/tags/v0.1.0\n{A}\trefs/tags/v0.1.0^{{}}\n");
        for round in 0..20_000 {
            // Even rounds damage a valid listing; odd rounds start empty.
            let mut input = if round % 2 == 0 {
                valid.clone().into_bytes()
            } else {
                Vec::new()
            };
            for _ in 0..next() % 160 {
                let random = next();
                let byte = if random % 8 == 0 {
                    (random >> 8) as u8
                } else {
                    alphabet[(random >> 8) as usize % alphabet.len()]
                };
                let at = (random >> 16) as usize % (input.len() + 1);
                match random % 3 {
                    0 if at < input.len() => input[at] = byte,
                    1 if at < input.len() => {
                        input.remove(at);
                    }
                    _ => input.insert(at, byte),
                }
            }
            // A panic fails the test; any `Result` is fine.
            let _ = parse_ls_remote(&input);
        }
    }

    #[tokio::test]
    async fn ls_remote_of_the_fixture_pins_the_heads_and_peels_the_tag() {
        let fixture = inert_target_repo();
        let temp = private_temp();
        let git = GitRunner::new(
            &dirs_in(&temp),
            &test_git_env(),
            AllowedProtocols::HttpsAndFile,
        )
        .expect("a runner");
        let remote = LocalRemote::for_tests(&fixture).expect("an absolute UTF-8 path");
        let refs = ls_remote(
            &git,
            Remote::Local(&remote),
            &[
                "HEAD",
                "refs/heads/main",
                "refs/tags/v0.1.0",
                "refs/tags/v0.1.0^{}",
            ],
        )
        .await
        .expect("lists");
        assert_eq!(
            refs,
            [
                remote_ref(M, "HEAD"),
                remote_ref(M, "refs/heads/main"),
                remote_ref(TAG, "refs/tags/v0.1.0"),
                remote_ref(A, "refs/tags/v0.1.0^{}"),
            ]
        );
    }

    #[tokio::test]
    async fn https_only_refuses_the_local_fixture_and_never_quotes_git() {
        let fixture = inert_target_repo();
        let temp = private_temp();
        let git = GitRunner::new(&dirs_in(&temp), &test_git_env(), AllowedProtocols::Https)
            .expect("a runner");
        let remote = LocalRemote::for_tests(&fixture).expect("an absolute UTF-8 path");
        let error = ls_remote(&git, Remote::Local(&remote), &["HEAD"])
            .await
            .expect_err("the file transport is not allowed");
        // Fixed text and git's exit status, and nothing git wrote.
        assert_eq!(
            format!("{error:#}"),
            "git ls-remote failed with exit status 128"
        );
        let failed = git_failed(&error);
        assert_eq!(failed.code(), Some(128));
        // git refused for the reason the protocol allowlist gives. The
        // error keeps git's words to match against, never to print: its
        // `Debug` leaves them out as its `Display` does.
        assert!(failed.stderr_mentions("transport 'file' not allowed"));
        assert!(!format!("{failed:?}").contains("transport"), "{failed:?}");
        assert!(!format!("{error:?}").contains("transport"), "{error:?}");
    }

    #[test]
    fn child_env_is_exactly_the_allowlist() {
        // `capture` asks for exactly the names main.rs may pass on, in
        // order: a lookup that has a value for everything gets each of them.
        let mut asked = Vec::new();
        let captured = GitEnv::capture(|name| {
            asked.push(name);
            Some(OsString::from(format!("value of {name}")))
        });
        assert_eq!(
            asked,
            [
                "PATH",
                "HTTPS_PROXY",
                "https_proxy",
                "ALL_PROXY",
                "all_proxy",
                "NO_PROXY",
                "no_proxy",
                "SSL_CERT_FILE",
                "SSL_CERT_DIR",
            ]
        );
        let home = Path::new("/data/git-home-0035G87EK4XFE");
        let fixed = [
            ("HOME", "/data/git-home-0035G87EK4XFE"),
            ("GIT_CEILING_DIRECTORIES", "/data"),
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("GIT_TERMINAL_PROMPT", "0"),
            ("GIT_LFS_SKIP_SMUDGE", "1"),
            ("LC_ALL", "C"),
        ];
        let expected: Vec<(OsString, OsString)> = asked
            .iter()
            .map(|name| {
                (
                    OsString::from(name),
                    OsString::from(format!("value of {name}")),
                )
            })
            .chain(fixed.map(|(name, value)| (name.into(), value.into())))
            .collect();
        assert_eq!(child_env(&captured, home, Path::new("/data")), expected);

        // A variable that is not set is not passed on, not even empty.
        let path_only = GitEnv::capture(|name| (name == "PATH").then(|| "/usr/bin".into()));
        let names: Vec<OsString> = child_env(&path_only, home, Path::new("/data"))
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        let expected: Vec<OsString> = ["PATH"]
            .into_iter()
            .chain(fixed.map(|(name, _)| name))
            .map(OsString::from)
            .collect();
        assert_eq!(names, expected);
    }

    #[tokio::test]
    async fn argv_puts_every_hardening_option_before_the_subcommand() {
        let remote = checked_remote("github.com/org/name").await;
        let command = GitCommand::ls_remote(Remote::Https(&remote), &["HEAD", "refs/tags/v1^{}"]);
        let settings = [
            "credential.helper=",
            "core.askPass=",
            "protocol.allow=never",
            "protocol.https.allow=always",
            "http.followRedirects=false",
            "core.hooksPath=/dev/null",
            "core.fsmonitor=false",
            "core.symlinks=false",
            "submodule.recurse=false",
            "fetch.recurseSubmodules=false",
            "transfer.fsckObjects=true",
            "advice.detachedHead=false",
        ];
        // `-c <setting>` for each, then the subcommand and its arguments.
        let expected = |settings: &[&str]| -> Vec<String> {
            settings
                .iter()
                .flat_map(|setting| ["-c", setting])
                .chain([
                    "ls-remote",
                    "https://github.com/org/name",
                    "HEAD",
                    "refs/tags/v1^{}",
                ])
                .map(String::from)
                .collect()
        };
        assert_eq!(
            git_argv(&command, AllowedProtocols::Https).expect("builds"),
            expected(&settings)
        );
        // The file transport only for the fixture source, and then still
        // before the subcommand.
        let with_file = [settings.as_slice(), &["protocol.file.allow=always"]].concat();
        assert_eq!(
            git_argv(&command, AllowedProtocols::HttpsAndFile).expect("builds"),
            expected(&with_file)
        );
    }

    #[tokio::test]
    async fn argv_refuses_an_operand_that_git_could_read_as_an_option() {
        let remote = checked_remote("github.com/org/name").await;
        for operand in ["-", "--upload-pack=touch /tmp/pwned", "--", ""] {
            // As a pattern after the URL, as a refspec after it, and to a
            // local subcommand.
            for command in [
                GitCommand::ls_remote(Remote::Https(&remote), &[operand]),
                GitCommand::fetch(Remote::Https(&remote)).operand(operand),
                GitCommand::local(LocalSubcommand::RevParse, LOCAL).operand(operand),
            ] {
                let error = git_argv(&command, AllowedProtocols::Https).expect_err(operand);
                // The message names the rule, `'-'` included, so only an
                // operand longer than that could show it was quoted.
                assert!(
                    operand.len() < 2 || !format!("{error:#}").contains(operand),
                    "{error:#}"
                );
            }
        }
        // An option the code itself chose is passed as it is.
        let command = GitCommand::local(LocalSubcommand::RevParse, LOCAL).flag("--git-dir");
        let argv = git_argv(&command, AllowedProtocols::Https).expect("builds");
        assert_eq!(
            argv.get(argv.len() - 2..),
            Some(["rev-parse", "--git-dir"].map(String::from).as_slice())
        );
    }

    #[tokio::test]
    async fn network_commands_name_their_repository_only_through_a_remote() {
        // `fetch <remote>` then what the caller adds: git reads options
        // after the repository as well as before it.
        let remote = checked_remote("github.com/org/name").await;
        let command = GitCommand::fetch(Remote::Https(&remote))
            .flag("--depth=2")
            .operand(M);
        let argv = git_argv(&command, AllowedProtocols::Https).expect("builds");
        assert_eq!(
            argv.get(argv.len() - 4..),
            Some(
                ["fetch", "https://github.com/org/name", "--depth=2", M]
                    .map(String::from)
                    .as_slice()
            )
        );
        // The fixture's remote is its `file://` URL, for `fetch` and
        // `ls-remote` alike.
        let fixture = inert_target_repo();
        let local = LocalRemote::for_tests(&fixture).expect("an absolute UTF-8 path");
        for command in [
            GitCommand::fetch(Remote::Local(&local)),
            GitCommand::ls_remote(Remote::Local(&local), &[]),
        ] {
            let argv = git_argv(&command, AllowedProtocols::HttpsAndFile).expect("builds");
            assert_eq!(argv.last().map(String::as_str), Some(local.as_str()));
        }
        // Checked when the test compiles: no string or default makes a
        // `Remote`, so only the two checked types can.
        crate::test_support::assert_not_impl_any!(
            Remote<'static>: Default,
            From<String>,
            From<&'static str>,
        );
    }

    #[test]
    fn git_sees_nothing_of_this_process_environment() {
        // This test's own environment cannot be changed (`set_var` is
        // `unsafe` in edition 2024, and the crate forbids `unsafe`), so it
        // starts this very test binary again with variables that would
        // redirect or reconfigure git if they reached it, and has it run
        // `env_probe` alone. `.env()` sets them on the child only.
        let output = std::process::Command::new(std::env::current_exe().expect("the test binary"))
            .args(["--exact", "git::tests::env_probe", "--ignored"])
            .env("GIT_DIR", "/nonexistent")
            .env("GIT_CONFIG_PARAMETERS", "'core.sweepkyprobe'='leak'")
            .env(PROBE_VAR, "1")
            .output()
            .expect("the test binary runs");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        // libtest also exits 0 when no test matched, so check that the
        // probe ran.
        assert!(
            stdout.contains("test git::tests::env_probe ... ok"),
            "{stdout}"
        );
    }

    /// Run by [`git_sees_nothing_of_this_process_environment`], in a
    /// process whose environment has `GIT_DIR` and `GIT_CONFIG_PARAMETERS`
    /// set; on its own it does nothing.
    #[tokio::test]
    #[ignore = "git_sees_nothing_of_this_process_environment runs it with the variables it needs"]
    async fn env_probe() {
        if std::env::var_os(PROBE_VAR).is_none() {
            return;
        }
        let temp = private_temp();
        let git = GitRunner::new(&dirs_in(&temp), &test_git_env(), AllowedProtocols::Https)
            .expect("a runner");
        let work = private_temp();
        // `GIT_CONFIG_PARAMETERS` would set the key; `git config --get`
        // exits 1 for a key that is not set.
        let error = git
            .run(
                &GitCommand::local(LocalSubcommand::Config, LOCAL)
                    .flag("--get")
                    .operand("core.sweepkyprobe")
                    .in_dir(work.path()),
            )
            .await
            .expect_err("the key is not set");
        assert_eq!(git_failed(&error).code(), Some(1), "{error:#}");
        // `GIT_DIR=/nonexistent` would make `init` create /nonexistent
        // (or fail) and `rev-parse` name it. Without it, the repository is
        // the one `init` made here.
        git.run(
            &GitCommand::local(LocalSubcommand::Init, LOCAL)
                .flag("--quiet")
                .in_dir(work.path()),
        )
        .await
        .expect("init");
        let git_dir = git
            .run(
                &GitCommand::local(LocalSubcommand::RevParse, LOCAL)
                    .flag("--git-dir")
                    .in_dir(work.path()),
            )
            .await
            .expect("rev-parse");
        assert_eq!(git_dir, b".git\n");
    }

    #[tokio::test]
    async fn a_repository_above_the_data_dir_is_never_read() {
        // SWEEPKY_HOME itself made a repository with a config key of its
        // own, as a home directory kept in git would be.
        let temp = private_temp();
        let git = GitRunner::new(&dirs_in(&temp), &test_git_env(), AllowedProtocols::Https)
            .expect("a runner");
        let get = GitCommand::local(LocalSubcommand::Config, LOCAL)
            .flag("--get")
            .operand("core.sweepkyprobe");
        git.run(
            &GitCommand::local(LocalSubcommand::Init, LOCAL)
                .flag("--quiet")
                .in_dir(temp.path()),
        )
        .await
        .expect("init");
        git.run(
            &GitCommand::local(LocalSubcommand::Config, LOCAL)
                .operand("core.sweepkyprobe")
                .operand("from-the-repo")
                .in_dir(temp.path()),
        )
        .await
        .expect("sets the key");
        // Inside that repository, git reads the key.
        let inside = git
            .run(&get.clone().in_dir(temp.path()))
            .await
            .expect("reads the key");
        assert_eq!(inside, b"from-the-repo\n");
        // From the private HOME two levels below, where git runs by
        // default, it does not: GIT_CEILING_DIRECTORIES stops the search
        // for a repository at the data directory.
        let error = git.run(&get).await.expect_err("the key is not found");
        assert_eq!(git_failed(&error).code(), Some(1), "{error:#}");
    }

    #[test]
    fn private_home_is_new_0700_empty_and_removed_on_drop() {
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        let git =
            GitRunner::new(&dirs, &test_git_env(), AllowedProtocols::Https).expect("a runner");
        let home = git.home.path.clone();
        // `<data dir>/git-home-<new record id>/`, both directories 0700.
        assert_eq!(home.parent(), Some(dirs.data()));
        let name = home
            .file_name()
            .and_then(|name| name.to_str())
            .expect("a name");
        let id = name.strip_prefix("git-home-").expect("git-home-<id>");
        assert_eq!(dirs.git_home_dir(&id.parse().expect("a record id")), home);
        assert_eq!(mode(dirs.data()), 0o700);
        assert_eq!(mode(&home), 0o700);
        assert_eq!(fs::read_dir(&home).expect("lists").count(), 0, "empty");
        // Each runner gets its own.
        let other = GitRunner::new(&dirs, &test_git_env(), AllowedProtocols::Https)
            .expect("a second runner");
        assert_ne!(other.home.path, home);
        drop(git);
        assert!(fs::symlink_metadata(&home).is_err(), "removed on drop");
    }

    #[test]
    fn private_home_is_never_an_existing_entry_or_a_link() {
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        ensure_private_dir(dirs.data()).expect("the data dir");
        let id: RecordId = "0035G87EK4XFE".parse().expect("a record id");
        let path = dirs.git_home_dir(&id);

        // A link to a directory elsewhere is refused, not followed, and
        // left where it is.
        let elsewhere = private_temp();
        symlink(elsewhere.path(), &path).expect("a symlink");
        assert!(PrivateHome::create(&dirs, &id).is_err());
        assert!(fs::symlink_metadata(&path).expect("there").is_symlink());
        assert_eq!(fs::read_dir(elsewhere.path()).expect("lists").count(), 0);

        // A directory already there is not reused, and not removed.
        fs::remove_file(&path).expect("unlinks");
        fs::create_dir(&path).expect("a directory");
        fs::write(path.join("stale"), "x").expect("a file");
        assert!(PrivateHome::create(&dirs, &id).is_err());
        assert!(path.join("stale").is_file());
    }

    #[test]
    fn runner_refuses_an_environment_it_cannot_harden() {
        // Without PATH there is no git to find, and nothing is made.
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        assert!(
            GitRunner::new(&dirs, &GitEnv::capture(|_| None), AllowedProtocols::Https).is_err()
        );
        assert!(fs::symlink_metadata(dirs.data()).is_err(), "nothing made");
        // GIT_CEILING_DIRECTORIES is a `:`-separated list, so it cannot
        // name a data directory whose path holds a `:`.
        let colon = temp.path().join("a:b");
        let dirs = Dirs::resolve(None, Some(colon.as_os_str())).expect("absolute");
        assert!(GitRunner::new(&dirs, &test_git_env(), AllowedProtocols::Https).is_err());
    }

    #[tokio::test]
    async fn bounded_run_kills_a_child_that_outlives_its_timeout() {
        let temp = private_temp();
        let pid_file = temp.path().join("pid");
        // The shell writes its process id, then `exec` turns that same
        // process into `sleep 30`, so the id written is the sleeper's.
        let mut child = Command::new("sh");
        child
            .arg("-c")
            .arg("echo $$ > \"$0\"; exec sleep 30")
            .arg(&pid_file);
        let limits = Limits {
            timeout: Duration::from_secs(1),
            ..LOCAL
        };
        let started = Instant::now();
        // `.err().expect(…)` rather than `expect_err`, which would need
        // `Finished` to be `Debug`: it holds a child's standard error, so it
        // has none.
        let error = run_bounded(child, "sleep", &limits)
            .await
            .err()
            .expect("timed out");
        assert!(started.elapsed() < Duration::from_secs(10));
        assert_eq!(
            format!("{error:#}"),
            "sleep did not finish within 1s, so Sweepky stopped it"
        );
        // `kill -0` sends no signal and fails when no such process exists:
        // the runner killed the child and waited for it before returning.
        let pid = fs::read_to_string(&pid_file).expect("the pid");
        let alive = std::process::Command::new("sh")
            .args(["-c", "kill -0 \"$0\"", pid.trim()])
            .stderr(Stdio::null())
            .status()
            .expect("sh runs");
        assert!(!alive.success(), "process {} is still alive", pid.trim());
    }

    #[tokio::test]
    async fn bounded_run_refuses_output_past_its_caps() {
        let limits = Limits {
            stdout_cap: 1024,
            stderr_cap: 1024,
            ..LOCAL
        };
        // `yes` writes `y` lines for ever, so only the cap stops it.
        let error = run_bounded(Command::new("yes"), "yes", &limits)
            .await
            .err()
            .expect("too much output");
        assert_eq!(
            format!("{error:#}"),
            "yes wrote more than 1024 bytes to its standard output, so Sweepky stopped it"
        );
        let mut to_stderr = Command::new("sh");
        to_stderr.args(["-c", "yes >&2"]);
        let error = run_bounded(to_stderr, "yes", &limits)
            .await
            .err()
            .expect("too much output");
        assert_eq!(
            format!("{error:#}"),
            "yes wrote more than 1024 bytes to its standard error, so Sweepky stopped it"
        );
        // Exactly the cap is fine: 1024 zeros.
        let mut exact = Command::new("sh");
        exact.args(["-c", "printf '%01024d' 0"]);
        let finished = run_bounded(exact, "printf", &limits)
            .await
            .expect("within the cap");
        assert!(finished.status.success());
        assert_eq!(finished.stdout, vec![b'0'; 1024]);
    }
}
