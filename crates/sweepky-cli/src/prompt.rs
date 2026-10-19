//! Standard input, and the one question a command asks on it: yes or no.
//!
//! - [`StdinReader`] is the context's standard input
//!   ([`Context::stdin`](crate::Context::stdin)): the real one in the binary,
//!   fixed bytes in a test.
//! - [`confirm`] asks a yes-or-no question on standard error and reads one
//!   line of answer, at most [`MAX_ANSWER_BYTES`]. `y` or `yes`, in any
//!   case, is yes; anything else, an empty line and the end of the input
//!   included, is no, so only a clear yes goes ahead.
//! - [`Prompting`] is what the global `--no-input` flag says. `run` hands it
//!   to each command that asks, and under it [`confirm`] fails at once and
//!   reads nothing.
//!
//! `post` and `submit`, later in P2b, are the commands that ask: `post`
//! before it publishes a bounty's title and brief, and `submit` before it
//! encrypts to keys the owner added since the last submit.
//!
//! **Bounded reads.** Standard input can be a pipe from anything, so an
//! answer is never read with an unbounded `read_line`, which would buffer a
//! line with no end until memory ran out. The read stops one byte past the
//! cap, and a line that long is an error.

// Nothing calls `confirm` yet: `post` and `submit`, later in P2b, are its
// first callers, so outside the tests the compiler would warn that it and
// what only it uses are dead code. `expect` (not `allow`) silences that
// warning only while it is true: once a command calls `confirm`, the
// expectation goes unmet, which is a warning of its own, and this line has
// to go. `cfg_attr(not(test), …)` applies it to the normal build only,
// because the unit tests below do call `confirm`.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "post and submit, later in P2b, are the first callers of confirm"
    )
)]

use std::io::{BufRead, Read};
use std::sync::{Mutex, PoisonError};

use anyhow::{Context as _, bail};

use crate::Context;

/// The most an answer may take, its line ending included: 1 KiB, far more
/// than `yes\r\n` and still a cap on what is read from a pipe.
pub(crate) const MAX_ANSWER_BYTES: usize = 1024;

/// Whether a command may stop and ask the person at the terminal a
/// question, which the global `--no-input` flag forbids.
///
/// The flag stays on [`Cli`](crate::Cli): `run` turns it into this and hands
/// it to each command that asks. An enum rather than a `bool`, so a call
/// reads `confirm(ctx, Prompting::Forbidden, …)` rather than
/// `confirm(ctx, true, …)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Prompting {
    /// Ask on standard error and read the answer from standard input.
    Allowed,
    /// `--no-input`: fail where an answer is needed, reading nothing.
    Forbidden,
}

impl Prompting {
    /// What the `--no-input` flag says: forbidden when it was given.
    pub(crate) fn from_no_input_flag(no_input: bool) -> Self {
        if no_input {
            Self::Forbidden
        } else {
            Self::Allowed
        }
    }
}

/// Asks `question` on standard error, followed by ` [y/N] `, and reads the
/// answer from standard input: `true` for `y` or `yes` in any case, `false`
/// for anything else, an empty line and the end of the input included.
///
/// Under [`Prompting::Forbidden`] (`--no-input`) it fails at once, asking
/// nothing and reading nothing, with an error that names the flag and the
/// question. `question` is written as it is, so text a stranger wrote goes
/// through `display::sanitize` before it is put in one.
///
/// It blocks the thread until a line comes, which is what a command waiting
/// on a person should do.
pub(crate) fn confirm(ctx: &Context, prompting: Prompting, question: &str) -> anyhow::Result<bool> {
    if prompting == Prompting::Forbidden {
        bail!(
            "--no-input was given, so Sweepky cannot ask \"{question}\"; run the command again \
             without --no-input to answer"
        );
    }
    // Flushed, so the question is on screen before the read waits for the
    // answer.
    ctx.stderr.write_flushed(&format!("{question} [y/N] "))?;
    let line = ctx.stdin.read_answer()?;
    Ok(is_yes(&line))
}

/// Whether `line` says yes: `y` or `yes` in any case once one `\n` or
/// `\r\n` is taken off its end. Compared as bytes, so an answer that is not
/// UTF-8 is simply no.
fn is_yes(line: &[u8]) -> bool {
    // `strip_suffix` gives `None` when the ending is not there, and
    // `map_or` then keeps the line as it is.
    let answer = line
        .strip_suffix(b"\n")
        .map_or(line, |rest| rest.strip_suffix(b"\r").unwrap_or(rest));
    answer.eq_ignore_ascii_case(b"y") || answer.eq_ignore_ascii_case(b"yes")
}

/// Where a command reads the answers to its questions: standard input in
/// the binary, fixed bytes in the tests.
///
/// The same shape as [`StderrWriter`](crate::StderrWriter), for the same
/// reason: a command holds the [`Context`] by shared reference, reading
/// needs `&mut` access, and the `Mutex` hands that out to one caller at a
/// time. `BufRead` rather than `Read`, because reading a line up to its
/// `\n` without reading past it needs a buffer to keep the rest in.
pub struct StdinReader {
    reader: Mutex<Box<dyn BufRead + Send>>,
}

impl StdinReader {
    /// Answers read from `reader`.
    ///
    /// The binary passes `std::io::BufReader::new(std::io::stdin())`.
    /// `Stdin` alone is `Read` but not `BufRead`, and its locked form
    /// `StdinLock`, which is `BufRead`, is not `Send`: it holds a lock that
    /// must be released on the thread that took it, so it cannot sit in a
    /// `Context` that tokio's worker threads share. A `BufReader` around
    /// `Stdin` is both. A test passes a `Cursor` over the answers it gives.
    pub fn new(reader: impl BufRead + Send + 'static) -> Self {
        Self {
            reader: Mutex::new(Box::new(reader)),
        }
    }

    /// One line of answer, its ending included, of at most
    /// [`MAX_ANSWER_BYTES`]; empty at the end of the input. A longer line is
    /// an error that quotes none of it, and is read no further than one
    /// byte past the cap.
    fn read_answer(&self) -> anyhow::Result<Vec<u8>> {
        // A poisoned lock is taken back, as in `StderrWriter::write_flushed`:
        // a reader has no state that a panic could leave half-changed.
        let mut reader = self.reader.lock().unwrap_or_else(PoisonError::into_inner);
        let mut line = Vec::new();
        // `take` counts in `u64`; widening 1024 with `as` cannot truncate.
        let limit = MAX_ANSWER_BYTES as u64 + 1;
        // `&mut *reader` lends the boxed reader to `take`, which would
        // otherwise consume it, and the `Take` it returns stops after
        // `limit` bytes. `read_until` stops at the first `\n`, or there.
        (&mut *reader)
            .take(limit)
            .read_until(b'\n', &mut line)
            .context("could not read the answer from standard input")?;
        if line.len() > MAX_ANSWER_BYTES {
            bail!(
                "the answer is longer than {MAX_ANSWER_BYTES} bytes; run the command again and \
                 answer y or n"
            );
        }
        Ok(line)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, BufRead, BufReader, Cursor, Read};

    use super::{MAX_ANSWER_BYTES, Prompting, confirm};
    use crate::test_support::{offline_network, private_temp, test_context};

    /// Asks "Go on?" with `input` as standard input, and returns the answer
    /// and everything written to standard error.
    fn ask(input: impl BufRead + Send + 'static) -> (anyhow::Result<bool>, String) {
        let temp = private_temp();
        let (ctx, stderr) = test_context(offline_network(), &temp, input);
        let answer = confirm(&ctx, Prompting::Allowed, "Go on?");
        (answer, stderr.text())
    }

    #[test]
    fn y_or_yes_in_any_case_is_yes() {
        // Either line ending, or none at the end of the input.
        for input in ["y\n", "Y\n", "yes\n", "YES\n", "yEs\r\n", "Y\r\n", "yes"] {
            let (answer, stderr) = ask(Cursor::new(input));
            assert!(answer.expect("an answer"), "{input:?}");
            // The question goes to standard error, with no newline, so the
            // answer is typed on the same line.
            assert_eq!(stderr, "Go on? [y/N] ", "{input:?}");
        }
    }

    #[test]
    fn anything_else_is_no() {
        // `n`, an empty line, the end of the input, and every answer that is
        // not exactly y or yes once the line ending is gone.
        for input in [
            "n\n",
            "N\n",
            "no\n",
            "\n",
            "\r\n",
            "",
            "maybe\n",
            " y\n",
            "y \n",
            "yy\n",
            "ye\n",
            "yes please\n",
            "y\r\r\n",
            "\u{feff}y\n",
        ] {
            let (answer, stderr) = ask(Cursor::new(input));
            assert!(!answer.expect("an answer"), "{input:?}");
            assert_eq!(stderr, "Go on? [y/N] ", "{input:?}");
        }
    }

    #[test]
    fn each_question_reads_one_line() {
        // Two questions, two lines: the first answer is no, the second yes,
        // so the first read stopped at its line's end.
        let temp = private_temp();
        let (ctx, stderr) = test_context(offline_network(), &temp, Cursor::new("n\nyes\n"));
        assert!(!confirm(&ctx, Prompting::Allowed, "First?").expect("an answer"));
        assert!(confirm(&ctx, Prompting::Allowed, "Second?").expect("an answer"));
        assert_eq!(stderr.text(), "First? [y/N] Second? [y/N] ");
    }

    #[test]
    fn an_answer_past_the_cap_is_an_error_that_does_not_echo_it() {
        // The cap counts the line ending: a line of exactly the cap is read
        // (and is no), one byte more is refused.
        let at_cap = format!("{}\n", "n".repeat(MAX_ANSWER_BYTES - 1));
        assert!(!ask(Cursor::new(at_cap)).0.expect("an answer at the cap"));
        let past_cap = format!("{}\n", "n".repeat(MAX_ANSWER_BYTES));
        assert!(ask(Cursor::new(past_cap)).0.is_err());

        // The error names the cap and quotes none of the answer.
        let pasted = "SYNTHETIC-PASTE-".repeat(100);
        let (answer, _) = ask(Cursor::new(format!("{pasted}\n")));
        let message = format!("{:#}", answer.expect_err("refused"));
        assert!(
            message.contains(&format!("{MAX_ANSWER_BYTES} bytes")),
            "{message}"
        );
        assert!(!message.contains("SYNTHETIC"), "{message}");

        // An endless line: `io::repeat` gives `y` for ever and never a
        // newline, so an unbounded read would never return. This one stops
        // one byte past the cap.
        let (answer, _) = ask(BufReader::new(io::repeat(b'y')));
        assert!(answer.is_err());
    }

    /// A standard input that fails the test if anything reads it.
    struct PanicsIfRead;

    impl Read for PanicsIfRead {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            panic!("standard input was read")
        }
    }

    impl BufRead for PanicsIfRead {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            panic!("standard input was read")
        }

        fn consume(&mut self, _amount: usize) {
            panic!("standard input was read")
        }
    }

    #[test]
    fn no_input_fails_at_once_without_reading() {
        let temp = private_temp();
        let (ctx, stderr) = test_context(offline_network(), &temp, PanicsIfRead);
        let error = confirm(&ctx, Prompting::Forbidden, "Go on?").expect_err("refused");
        let message = format!("{error:#}");
        // It names the flag and the question that needed an answer, and
        // asks nothing.
        assert!(message.contains("--no-input"), "{message}");
        assert!(message.contains("Go on?"), "{message}");
        assert_eq!(stderr.text(), "");
    }

    #[test]
    fn prompting_follows_the_no_input_flag() {
        assert_eq!(Prompting::from_no_input_flag(false), Prompting::Allowed);
        assert_eq!(Prompting::from_no_input_flag(true), Prompting::Forbidden);
    }
}
