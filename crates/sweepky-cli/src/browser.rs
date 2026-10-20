//! How `login` opens the Pubky Ring sign-in page in a browser.
//!
//! The binary starts the system's opener (`/usr/bin/open` on macOS,
//! `xdg-open` elsewhere) with the page's URL. Most tests open nothing, and
//! the end-to-end test that plays Ring takes the URL from a channel and
//! fetches the page itself, so no test ever starts a real browser.
//!
//! Opening is best effort: when it fails, the caller says so and the link
//! and the terminal QR code printed beside it still work. So nothing here
//! fails the login; a failure is a warning line on standard error.
//!
//! **Known limit.** The opener gets the page URL as an argument, so for the
//! moment it runs, any local user can read that URL with `ps`. The URL
//! works only on this machine's loopback address and only for this one
//! flow, and the loopback server's random path is already its defence
//! against local users (see `ring::loopback`).

use std::process::Stdio;
use std::time::Duration;

use anyhow::bail;
use tokio::sync::mpsc::UnboundedSender;
use url::Url;

use crate::StderrWriter;

/// How long the opener may take to exit before Sweepky stops waiting for it.
/// `open` and `xdg-open` hand the URL to the browser and exit at once; one
/// still running after this is left alone (see [`launch`]).
const OPENER_WAIT: Duration = Duration::from_secs(5);

/// How [`crate::Context`] opens the sign-in page, chosen by whoever builds
/// the context.
///
/// An enum, not a trait object, because there are exactly three ways and
/// each is plain data: the caller picks one and nothing else can be plugged
/// in.
pub enum Browser {
    /// The system's opener, which hands the URL to the user's default
    /// browser. Only the binary uses it.
    System,
    /// Opens nothing, for the tests that never reach the sign-in page.
    /// Always written `Browser::None`: the bare `None` is `Option`'s.
    None,
    /// Sends the URL down this channel, for a test that acts as the browser
    /// and fetches the page itself. Unbounded, so sending never waits; one
    /// login sends one URL.
    Notify(UnboundedSender<Url>),
}

impl Browser {
    /// Opens `url`, the sign-in page, and says whether that worked.
    ///
    /// `false` (with a warning on `stderr` when something failed) tells the
    /// caller the user may not see the page, so the terminal link and QR
    /// code are what they have. The only error is a failed write to `stderr`; a
    /// failure to open never is one.
    ///
    /// The URL is a secret (its path guards the page), so it goes to the
    /// opener and the channel only, never into a message.
    pub(crate) async fn open(&self, url: &Url, stderr: &StderrWriter) -> anyhow::Result<bool> {
        match self {
            Self::System => launch(opener_command(url), OPENER_WAIT, stderr).await,
            Self::None => Ok(false),
            // `send` fails only when the receiver is gone, that is when the
            // test stopped listening; then the page was not opened.
            // `clone` because the channel takes its own `Url`, and the
            // caller still needs the one it lent us.
            Self::Notify(sender) => Ok(sender.send(url.clone()).is_ok()),
        }
    }
}

/// The command that opens `url` in the default browser, built but not
/// started.
///
/// The URL is one argument of a fixed program, never part of a shell
/// string, so nothing in it can be read as shell syntax. `cfg!` is decided
/// at compile time, so each build names one opener. macOS's is named by its
/// full path, so no `PATH` entry can stand in for it; `xdg-open` has no
/// fixed place across Linux distributions, so it is looked up on `PATH`.
fn opener_command(url: &Url) -> tokio::process::Command {
    let program = if cfg!(target_os = "macos") {
        "/usr/bin/open"
    } else {
        "xdg-open"
    };
    let mut command = tokio::process::Command::new(program);
    command.arg(url.as_str());
    command
}

/// Starts `command` and says whether it opened the page: `true` when it
/// exited with success or is still running after `wait`; `false`, with a
/// warning line on `stderr`, when it could not start or exited with a
/// failure. The warning names the failure, never the URL.
async fn launch(
    command: tokio::process::Command,
    wait: Duration,
    stderr: &StderrWriter,
) -> anyhow::Result<bool> {
    match run_opener(command, wait).await {
        Ok(()) => Ok(true),
        // `{reason:#}` prints the error's whole chain on one line.
        Err(reason) => {
            stderr.line(&format!(
                "warning: could not open the browser ({reason:#}); open the link below instead"
            ))?;
            Ok(false)
        }
    }
}

/// Runs the opener with standard input, output and error on `/dev/null`,
/// so it can neither wait on the terminal nor print over the login's own
/// lines, and waits up to `wait` for it to exit.
///
/// A spawn error names the OS failure ("No such file or directory"), never
/// the arguments, so the URL cannot reach the warning through it.
///
/// An opener still running after `wait` counts as started and is not
/// killed (`kill_on_drop` stays off): some `xdg-open` setups run until the
/// browser they started exits, and killing them could close the user's
/// page. tokio reaps the process once it exits.
async fn run_opener(mut command: tokio::process::Command, wait: Duration) -> anyhow::Result<()> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    // `timeout` gives `Err(Elapsed)` when time ran out, and otherwise what
    // `wait()` gave: the exit status, or an error from waiting.
    let Ok(waited) = tokio::time::timeout(wait, child.wait()).await else {
        return Ok(());
    };
    let status = waited?;
    if !status.success() {
        bail!("the opener exited with {status}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use url::Url;

    use super::{Browser, launch, opener_command};
    use crate::StderrWriter;
    use crate::test_support::SharedBuffer;

    /// A page URL of the shape the loopback server gives, with a made-up
    /// path. Synthetic: nothing listens there.
    fn page_url() -> Url {
        Url::parse("http://127.0.0.1:49152/0123456789abcdef").expect("a valid URL")
    }

    fn stderr() -> (StderrWriter, SharedBuffer) {
        let buffer = SharedBuffer::default();
        (StderrWriter::new(buffer.clone()), buffer)
    }

    #[tokio::test]
    async fn notify_hands_the_url_to_the_receiver() {
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        let (stderr, said) = stderr();
        let opened = Browser::Notify(sender)
            .open(&page_url(), &stderr)
            .await
            .expect("stderr is writable");
        assert!(opened);
        assert_eq!(receiver.try_recv().expect("the URL was sent"), page_url());
        assert_eq!(said.text(), "");
    }

    #[tokio::test]
    async fn none_opens_nothing_and_says_so() {
        let (stderr, said) = stderr();
        let opened = Browser::None
            .open(&page_url(), &stderr)
            .await
            .expect("stderr is writable");
        assert!(!opened);
        assert_eq!(said.text(), "");
    }

    #[test]
    fn the_opener_is_a_fixed_program_with_the_url_as_one_argument() {
        let url = page_url();
        let command = opener_command(&url);
        let command = command.as_std();
        let expected = if cfg!(target_os = "macos") {
            "/usr/bin/open"
        } else {
            "xdg-open"
        };
        assert_eq!(command.get_program(), expected);
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(args, [url.as_str()]);
    }

    #[tokio::test]
    async fn an_opener_that_cannot_start_is_a_warning_not_an_error() {
        let (stderr, said) = stderr();
        let mut missing = tokio::process::Command::new("/nonexistent/sweepky-test-opener");
        missing.arg(page_url().as_str());
        let opened = launch(missing, Duration::from_secs(5), &stderr)
            .await
            .expect("stderr is writable");
        assert!(!opened);
        let text = said.text();
        assert!(
            text.starts_with("warning: could not open the browser"),
            "{text}"
        );
        assert!(text.ends_with('\n'));
        assert!(!text.contains("127.0.0.1"), "the page URL is never logged");
    }

    #[tokio::test]
    async fn an_opener_that_fails_is_a_warning_not_an_error() {
        let (stderr, said) = stderr();
        let mut failing = tokio::process::Command::new("false");
        failing.arg(page_url().as_str());
        let opened = launch(failing, Duration::from_secs(5), &stderr)
            .await
            .expect("stderr is writable");
        assert!(!opened);
        let text = said.text();
        assert!(
            text.starts_with("warning: could not open the browser"),
            "{text}"
        );
        assert!(!text.contains("127.0.0.1"), "the page URL is never logged");
    }
}
