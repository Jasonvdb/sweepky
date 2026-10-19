//! The clock: where `sweepky` reads the current time for a record's time
//! fields (`createdAt`, `revokedAt`, and later `startedAt`, `finishedAt` and
//! `doneAt`), and for the id of a new record.
//!
//! `sweepky-core` has no clock, so that its record code gives the same output
//! for the same input. This module reads the system clock and hands core a
//! count of seconds; core's [`RecordTime::from_unix_seconds`] turns that into
//! the text Sweepky writes, RFC 3339 in UTC to the second
//! (`2026-10-16T09:41:07Z`). [`new_record_id`] hands core a timestamp
//! instead, for the `<id>` of a new bounty, sweep or device key.

use std::time::{SystemTime, UNIX_EPOCH};

// A trait's methods can only be called while the trait is in scope. `as _`
// brings `anyhow::Context`'s (`.context(...)`) in without binding the name
// `Context`, which this crate uses for its own type.
use anyhow::{Context as _, bail};
use sweepky_core::{RecordId, RecordTime, Timestamp};

/// The current time, as Sweepky writes it in a record's time fields.
///
/// Fractions of a second are dropped, so the time is rounded down to the
/// second. A clock set before 1970 or after the year 9999 is an error with a
/// message, never a panic.
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

/// The id of a new record, from the clock: 13 characters of upper-case
/// Crockford base32, such as `0035G87EK4XFE`, for a new bounty
/// (`bounties/<id>.json`), sweep (`sweeps/<id>.json`) or device key.
///
/// `Timestamp::now()` is microseconds since 1970, with its last byte a
/// random "clock id" that pubky-timestamp picks once per process, so two
/// processes that start in the same microsecond still differ, and it never
/// repeats within a process: each call is later than the one before. It
/// panics on a clock set before 1970, so this function first asks [`now`],
/// which refuses such a clock with a message instead. The check lives here
/// rather than with each caller, so that no caller can forget it.
pub(crate) fn new_record_id() -> anyhow::Result<RecordId> {
    // Only the check is wanted; the time it reads is dropped.
    now()?;
    Ok(RecordId::from_timestamp(Timestamp::now()))
}

#[cfg(test)]
mod tests {
    use sweepky_core::RecordId;

    use super::{new_record_id, now};

    #[test]
    fn new_record_id_is_a_fresh_13_character_record_id() {
        let id = new_record_id().unwrap();
        let text = id.to_string();
        assert_eq!(text.len(), RecordId::LEN, "{text}");
        // It reads back through core's strict parser as the same id.
        assert_eq!(text.parse::<RecordId>().unwrap(), id);
        // pubky-timestamp never repeats a timestamp within a process, so the
        // next id differs, and sorts after this one.
        let next = new_record_id().unwrap();
        assert_ne!(next, id);
        assert!(next > id, "{next} is not after {id}");
    }

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
