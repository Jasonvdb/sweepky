//! The `sweepky` binary: a thin layer over the `sweepky_cli` library.
//!
//! It does five things and nothing else:
//!
//! 1. parses the arguments ([`Cli`]);
//! 2. runs `init <dir>` at once, through [`run_without_context`]: it needs
//!    only its directory, so it reads no environment variable, never opens
//!    the `--passphrase-file` and builds no network client, and works with
//!    HOME unset;
//! 3. for every other command, reads the environment. This file is the only
//!    place that does, with `std::env::var_os` and, for the working
//!    directory, `std::env::current_dir`, and it passes each value in, so
//!    the library and its tests never depend on the process environment;
//! 4. resolves the config and data directories ([`Dirs`], from `HOME` or
//!    `SWEEPKY_HOME`), reads the working directory, reads the passphrase when
//!    `--passphrase-file` names one ([`Passphrase::from_file`]), captures the
//!    variables git may see ([`GitEnv`]: `PATH` and the proxy and CA
//!    variables), builds the [`Network`] (production, or the local testnet
//!    under `--testnet` / `SWEEPKY_TESTNET`) and the [`Context`] around them,
//!    standard input, standard error and the real [`TargetSource`], then
//!    runs the command;
//! 5. prints the command's report, or `error: ...` and exits with status 1.
//!
//! `anyhow` is used here and in the library alike: this crate only has to
//! turn an error into a good message for the user. `sweepky-core` returns
//! typed `thiserror` errors that code can `match` on (see "Rust conventions"
//! in `docs/plan/03-cli-and-skill.md`).

// No `unsafe` in the binary either. The same panic lints as the library, so a
// failure here becomes an error message rather than a panic.
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::todo,
    clippy::unimplemented,
    clippy::unreachable
)]

use std::io::{BufReader, Write};
use std::process::ExitCode;

// `as _` brings `.context(...)` into scope without the name `Context`, which
// is the library's type here.
use anyhow::Context as _;
use clap::Parser;
use sweepky_cli::{
    Browser, Cli, Context, Dirs, GitEnv, Network, Passphrase, Report, StderrWriter, StdinReader,
    TargetSource, run, run_without_context, select_kind,
};

/// `#[tokio::main]` turns this `async fn main` into an ordinary `fn main`
/// that starts tokio's multi-threaded runtime and blocks on the body. Returning
/// an [`ExitCode`] instead of a `Result` lets us choose exactly what is
/// printed on failure (`error: ...`) and the status (1).
#[tokio::main]
async fn main() -> ExitCode {
    // On a usage error, or for `--help` and `--version`, clap prints its own
    // message and exits here (status 2 for an error, 0 otherwise).
    let cli = Cli::parse();
    // `and_then` runs `print_report` only when `execute` succeeded; either
    // step's error ends up in the one `Err` below.
    match execute(cli).await.and_then(|report| print_report(&report)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            print_error(&err);
            ExitCode::from(1)
        }
    }
}

/// Runs `init` with no context, or builds the context from the arguments and
/// the environment and then runs the command.
async fn execute(cli: Cli) -> anyhow::Result<Report> {
    // `init <dir>` first, before anything below can fail or reach out: it
    // takes no HOME, no passphrase and no network, so a missing HOME, an
    // unreadable passphrase file or a bad SWEEPKY_TESTNET cannot stop it, and
    // it never starts the DHT node a production client would. Every other
    // command comes back as `None` and goes on to the steps below.
    if let Some(result) = run_without_context(&cli) {
        return result;
    }
    // `var_os` returns the raw value, or `None` when the variable is unset. It
    // never fails on a value that is not UTF-8; `select_kind` refuses that.
    let testnet_env = std::env::var_os("SWEEPKY_TESTNET");
    // `as_deref` turns `Option<OsString>` (owned) into `Option<&OsStr>`
    // (borrowed), which is what `select_kind` takes.
    let kind = select_kind(cli.testnet, testnet_env.as_deref())?;
    // The directories first: resolving them touches nothing, so a bad HOME or
    // SWEEPKY_HOME fails before a network client is built.
    let home = std::env::var_os("HOME");
    let sweepky_home = std::env::var_os("SWEEPKY_HOME");
    let dirs = Dirs::resolve(home.as_deref(), sweepky_home.as_deref())?;
    // The working directory, absolute, which `run` and `submit` find their
    // project from. It fails only when the directory has gone or cannot be
    // read, and then before anything is done.
    let cwd = std::env::current_dir().context("could not read the current directory")?;
    // The passphrase, when --passphrase-file names one, also before the
    // network: a missing or unreadable file fails with nothing done. `map`
    // reads it only when the flag is there, and `transpose` turns the
    // `Option<Result<…>>` into a `Result<Option<…>>` for `?`.
    let passphrase = cli
        .passphrase_file
        .as_deref()
        .map(Passphrase::from_file)
        .transpose()?;
    let ctx = Context {
        network: Network::for_kind(kind)?,
        dirs,
        cwd,
        // The answers to a command's questions. A `BufReader` around `Stdin`,
        // because `Stdin` itself is not `BufRead` and its lock is not `Send`
        // (see `StdinReader::new`).
        stdin: StdinReader::new(BufReader::new(std::io::stdin())),
        // A command's warnings go straight to standard error, so they appear
        // before it acts; its report goes to standard output at the end.
        stderr: StderrWriter::new(std::io::stderr()),
        passphrase,
        // The only variables git will see of this environment, read here
        // so that the library reads none: `capture` asks `var_os` for each
        // name on its fixed list and keeps the ones that are set.
        git_env: GitEnv::capture(std::env::var_os),
        // Real repositories, over https alone. The binary never builds the
        // fixture source, the one that allows git's `file` transport.
        targets: TargetSource::Real,
        // The Ring sign-in page opens in the user's default browser.
        browser: Browser::System,
    };
    run(cli, &ctx).await
}

/// Writes the report to standard output.
///
/// `print!` would panic if the write fails, for example when the output is a
/// pipe whose reader has exited (`sweepky ... | head -0`). Writing through
/// `std::io::Write` returns that failure as an error instead.
fn print_report(report: &Report) -> anyhow::Result<()> {
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(report.text().as_bytes())?;
    stdout.flush()?;
    Ok(())
}

/// Writes `error: ...` to standard error.
///
/// `eprintln!` would panic if standard error is closed, for the same reason as
/// `print!` above. Here there is nowhere left to report that failure, so it is
/// ignored (`let _ =`) and the exit status 1 still says the command failed.
fn print_error(err: &anyhow::Error) {
    // `{:#}` prints the whole chain of context on one line:
    // "outer: inner: root cause".
    let _ = writeln!(std::io::stderr(), "error: {err:#}");
}
