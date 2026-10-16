//! The clock: where `sweepky` reads the current time for a record's time
//! fields (`createdAt`, `revokedAt`, and later `startedAt`, `finishedAt` and
//! `doneAt`).
//!
//! `sweepky-core` has no clock, so that its record code gives the same output
//! for the same input. This module reads the system clock and hands core a
//! count of seconds; core's [`RecordTime::from_unix_seconds`] turns that into
//! the text Sweepky writes, RFC 3339 in UTC to the second
//! (`2026-10-16T09:41:07Z`).

use std::time::{SystemTime, UNIX_EPOCH};

// A trait's methods can only be called while the trait is in scope. `as _`
// brings `anyhow::Context`'s (`.context(...)`) in without binding the name
// `Context`, which this crate uses for its own type.
use anyhow::{Context as _, bail};
use sweepky_core::RecordTime;

/// The current time, as Sweepky writes it in a record's time fields.
///
/// Fractions of a second are dropped, so the time is rounded down to the
/// second. A clock set before 1970 or after the year 9999 is an error with a
/// message, never a panic.
// Until `login` and `logout` call this, only the test below does, so a build
// without tests would warn that it is unused, which CI's `-D warnings` turns
// into an error. `expect` (rather than `allow`) says that warning is wanted
// for now, and warns in turn once a caller exists, so whoever adds the first
// caller has to delete this line. `cfg_attr(not(test), ...)` applies it only
// to builds without tests, where nothing calls it yet.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "login and logout, the next P2a steps, call it")
)]
pub(crate) fn now() -> anyhow::Result<RecordTime> {
    // `duration_since` returns an `Err` when the clock reads earlier than the
    // epoch. Its own message ("second time provided was later than self")
    // describes the subtraction, not the problem, so `let ... else` drops it
    // and `bail!` returns a message of our own instead.
    let Ok(since_epoch) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        bail!(
            "the system clock reads earlier than 1970-01-01T00:00:00Z; set it to the right time and try again"
        );
    };
    // `as_secs` drops the fraction of a second. Core refuses a year past
    // 9999; `context` puts what to do in front of core's reason.
    RecordTime::from_unix_seconds(since_epoch.as_secs())
        .context("the system clock reads a time Sweepky cannot write; set it to the right time and try again")
}

#[cfg(test)]
mod tests {
    use super::now;

    #[test]
    fn now_is_rfc3339_utc_to_the_second() {
        let time = now().unwrap();
        let text = time.as_str();
        // `d` stands for any digit; every other character must match exactly.
        let shape = "dddd-dd-ddTdd:dd:ddZ";
        assert_eq!(text.len(), shape.len(), "{text}");
        for (byte, expected) in text.bytes().zip(shape.bytes()) {
            if expected == b'd' {
                assert!(byte.is_ascii_digit(), "{text}");
            } else {
                assert_eq!(byte, expected, "{text}");
            }
        }
    }
}
