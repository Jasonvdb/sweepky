//! [`RecordTime`], the timestamp strings records carry, and
//! [`RecordTime::from_unix_seconds`], which writes the form Sweepky uses.

use serde::{Deserialize, Serialize};

use crate::error::RecordError;
use crate::validated_string::validated_string;

/// The value of a time field in a record: `createdAt`, `startedAt`,
/// `finishedAt`, `doneAt` or `revokedAt`.
///
/// **Writing.** Sweepky writes every time field as RFC 3339 in UTC, to the
/// second: `YYYY-MM-DDTHH:MM:SSZ`, such as `2026-10-16T09:41:07Z`.
/// [`RecordTime::from_unix_seconds`] builds that text from a count of
/// seconds. This form is P2a's choice; 01 leaves the encoding open.
///
/// **Reading.** A record from someone else may hold any other form, so reading
/// accepts any valid value and keeps it opaque: this type never parses a value
/// as a date and has no ordering, because comparing two strings in an unknown
/// format says nothing about which time is earlier. It only checks that the
/// value is 1 to [`RecordTime::MAX_LEN`] printable ASCII characters (`!` to
/// `~`, so no spaces, tabs, newlines or control characters). That keeps a
/// stranger's record from putting a long text or a terminal escape sequence
/// into a field the CLI prints. These limits are P1a's choice, not 01's.
///
/// There is no `now()`: this crate has no clock. The CLI reads the clock and
/// passes the seconds to [`RecordTime::from_unix_seconds`], so tests can use
/// fixed values.
///
/// Serialized as a plain JSON string. Deserializing runs the same check as
/// parsing with [`FromStr`](std::str::FromStr) (`try_from = "String"` tells
/// serde to read a `String`, then call `TryFrom<String>`), so a value of this
/// type is always valid.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct RecordTime(String);

impl RecordTime {
    /// The longest value accepted: 64 characters.
    pub const MAX_LEN: usize = 64;

    /// Writes `secs`, a count of seconds since the Unix epoch
    /// (1970-01-01T00:00:00Z), as RFC 3339 in UTC to the second, such as
    /// `2026-10-16T09:41:07Z`. This is the form Sweepky writes in every time
    /// field.
    ///
    /// The input is unsigned, so it cannot be before the epoch. A time after
    /// 9999-12-31T23:59:59Z is an `Err`: RFC 3339 gives the year exactly four
    /// digits, so year 10000 has no RFC 3339 form. Leap seconds do not occur,
    /// because Unix time counts every day as 86,400 seconds.
    // The same lint as on `civil_from_days` below. Here it has nothing to flag:
    // this function only divides and takes remainders.
    #[deny(clippy::arithmetic_side_effects)]
    pub fn from_unix_seconds(secs: u64) -> Result<Self, RecordError> {
        // `filter` turns a year past 9999 into `None`, which `civil_from_days`
        // already returns on an overflow; `ok_or` turns that `None` into the
        // error, and `?` returns early with it. (`filter` hands the closure a
        // reference to the tuple, which the pattern `&(year, _, _)` unpacks.)
        let (year, month, day) = civil_from_days(secs / SECONDS_PER_DAY)
            .filter(|&(year, _, _)| year <= MAX_YEAR)
            .ok_or(RecordError::Invalid {
                field: "time",
                reason: "is after 9999-12-31T23:59:59Z, the last second RFC 3339 can write",
            })?;
        let second_of_day = secs % SECONDS_PER_DAY;
        let hour = second_of_day / SECONDS_PER_HOUR;
        let minute = second_of_day % SECONDS_PER_HOUR / SECONDS_PER_MINUTE;
        let second = second_of_day % SECONDS_PER_MINUTE;
        // `{year:04}` pads with zeros to four digits, `{month:02}` to two.
        // Through `try_from`, so even text built here passes the same `check`
        // as text read from a record: no constructor skips it.
        Self::try_from(format!(
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
        ))
    }

    fn check(value: &str) -> Result<(), RecordError> {
        let invalid = |reason| RecordError::Invalid {
            field: "time",
            reason,
        };
        if value.is_empty() {
            return Err(invalid("is empty"));
        }
        // `len()` counts bytes, not characters. That is enough here: only
        // ASCII passes the next check, and in ASCII one character is one byte.
        // `reason` is a `&'static str`, so the limit is spelled out; a test
        // keeps it in step with `MAX_LEN`.
        if value.len() > Self::MAX_LEN {
            return Err(invalid("is longer than 64 characters"));
        }
        if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(invalid(
                "has a character that is not printable ASCII, such as a space or a control character",
            ));
        }
        Ok(())
    }
}

/// The last year RFC 3339 can write: it gives the year exactly four digits,
/// so year 10000 would need a fifth.
const MAX_YEAR: u64 = 9_999;

const SECONDS_PER_DAY: u64 = 86_400;
const SECONDS_PER_HOUR: u64 = 3_600;
const SECONDS_PER_MINUTE: u64 = 60;

/// Days from 0000-03-01, where [`civil_from_days`] counts from, to the Unix
/// epoch, 1970-01-01.
const DAYS_FROM_0000_03_01_TO_EPOCH: u64 = 719_468;

/// Days in one 400-year cycle of the Gregorian calendar, after which it
/// repeats exactly: an "era".
const DAYS_PER_ERA: u64 = 146_097;

/// Turns a count of days since the Unix epoch into the Gregorian
/// `(year, month, day)`: the year 1970 or later, the month 1 to 12 and the day
/// of the month 1 to 31. This is Howard Hinnant's `civil_from_days`
/// (<https://howardhinnant.github.io/date_algorithms.html#civil_from_days>)
/// written for unsigned day counts. Apart from the two named constants, the
/// numbers below are his as he writes them, so the two can be compared line
/// by line.
///
/// `None` only if a step would overflow, which no day count made from a `u64`
/// of seconds reaches.
// This function opts in to clippy's `arithmetic_side_effects` lint, which
// flags every `+`, `-` and `*` (each could overflow: a panic in a debug build,
// a silently wrong value in a release build). So each of those is a
// `checked_*` call that returns `None` on overflow, and `?` passes that `None`
// straight out. Dividing an unsigned number by a non-zero constant, and taking
// its remainder, can neither overflow nor panic, so `/` and `%` stay as they
// are; the lint knows that and allows them.
#[deny(clippy::arithmetic_side_effects)]
fn civil_from_days(days: u64) -> Option<(u64, u64, u64)> {
    // Count days from 0000-03-01 instead of 1970-01-01. With the year
    // starting in March, the leap day is the last day of a year, and the
    // calendar repeats exactly every era.
    let from_0000_03_01 = days.checked_add(DAYS_FROM_0000_03_01_TO_EPOCH)?;
    let era = from_0000_03_01 / DAYS_PER_ERA;
    // The day within its era, 0 to 146,096.
    let day_of_era = from_0000_03_01 % DAYS_PER_ERA;
    // The year within its era, 0 to 399. The three divisions take the
    // era's leap days so far back out (one per 4 years, none per 100, one
    // again per 400), so what is left divides by 365.
    let year_of_era = day_of_era
        .checked_sub(day_of_era / 1_460)?
        .checked_add(day_of_era / 36_524)?
        .checked_sub(day_of_era / 146_096)?
        / 365;
    // The day within that March-based year, 0 to 365.
    let year_start = year_of_era
        .checked_mul(365)?
        .checked_add(year_of_era / 4)?
        .checked_sub(year_of_era / 100)?;
    let day_of_year = day_of_era.checked_sub(year_start)?;
    // The month counted from March, 0 to 11. From March, every five
    // months come to 153 days (31 + 30 + 31 + 30 + 31), so
    // `(5 * day + 2) / 153` finds a day's month, and
    // `(153 * month + 2) / 5` the day that month starts on.
    let month_from_march = day_of_year.checked_mul(5)?.checked_add(2)? / 153;
    let month_start = month_from_march.checked_mul(153)?.checked_add(2)? / 5;
    let day = day_of_year.checked_sub(month_start)?.checked_add(1)?;
    // Back to January-based months: March..December are 3..12, January
    // and February are 1 and 2 and belong to the next calendar year.
    let (month, next_year) = if month_from_march < 10 {
        (month_from_march.checked_add(3)?, 0)
    } else {
        (month_from_march.checked_sub(9)?, 1)
    };
    let year = era
        .checked_mul(400)?
        .checked_add(year_of_era)?
        .checked_add(next_year)?;
    Some((year, month, day))
}

// `as_str()`, `FromStr`, `TryFrom<String>`, `From<RecordTime> for String`
// and `Display`, each running `check` where it makes a value.
validated_string!(RecordTime);

#[cfg(test)]
mod tests {
    use super::RecordTime;
    use crate::error::RecordError;

    /// Known answers: seconds since the Unix epoch and the text
    /// `from_unix_seconds` must write for them. Each pair was checked by hand
    /// with `date -u -r <secs> +%Y-%m-%dT%H:%M:%SZ` and again with Python's
    /// `datetime.fromtimestamp(secs, timezone.utc)`.
    const KNOWN_ANSWERS: [(u64, &str); 10] = [
        // The epoch itself.
        (0, "1970-01-01T00:00:00Z"),
        // Leap days: 2000 is a leap year because it divides by 400, 2024
        // because it divides by 4. The day after 2000-02-29 is March 1.
        (951_782_400, "2000-02-29T00:00:00Z"),
        (951_868_800, "2000-03-01T00:00:00Z"),
        (1_709_210_096, "2024-02-29T12:34:56Z"),
        // The last second of a year and the first of the next.
        (1_704_067_199, "2023-12-31T23:59:59Z"),
        (1_704_067_200, "2024-01-01T00:00:00Z"),
        // 2100 divides by 100 but not by 400, so it has no February 29.
        (4_107_542_399, "2100-02-28T23:59:59Z"),
        (4_107_542_400, "2100-03-01T00:00:00Z"),
        // A time in 2026-10.
        (1_792_143_667, "2026-10-16T09:41:07Z"),
        // The last second RFC 3339 can write.
        (253_402_300_799, "9999-12-31T23:59:59Z"),
    ];

    #[test]
    fn from_unix_seconds_writes_rfc3339_utc() {
        for (secs, expected) in KNOWN_ANSWERS {
            let time = RecordTime::from_unix_seconds(secs).unwrap();
            assert_eq!(time.as_str(), expected, "{secs}");
            // What Sweepky writes also reads back through the same check as a
            // value from someone else's record.
            assert_eq!(expected.parse::<RecordTime>().unwrap(), time, "{secs}");
        }
    }

    #[test]
    fn years_past_9999_are_refused() {
        // The first second of year 10000, one after the last known answer
        // (`date -u -r 253402300800` prints 10000-01-01T00:00:00Z), and the
        // largest input there is, which must be an `Err` too rather than an
        // overflow.
        for secs in [253_402_300_800, u64::MAX] {
            assert!(
                matches!(
                    RecordTime::from_unix_seconds(secs),
                    Err(RecordError::Invalid { field: "time", .. })
                ),
                "{secs}"
            );
        }
    }

    #[test]
    fn printable_strings_round_trip_unchanged() {
        // All 94 printable ASCII characters, in two halves to fit the limit,
        // including the `"` and `\` that JSON has to escape.
        let printable: String = (b'!'..=b'~').map(char::from).collect();
        let (first, second) = printable.split_at(47);
        let longest = "a".repeat(RecordTime::MAX_LEN);
        for value in [
            "2026-10-15T12:00:00.000Z",
            "1760529600",
            "0034ABCDEFGHJ",
            "x",
            first,
            second,
            &longest,
        ] {
            let time: RecordTime = value.parse().unwrap();
            assert_eq!(time.as_str(), value);
            let json = serde_json::to_string(&time).unwrap();
            assert_eq!(json, serde_json::to_string(value).unwrap());
            let back: RecordTime = serde_json::from_str(&json).unwrap();
            assert_eq!(back, time);
        }
    }

    #[test]
    fn empty_long_whitespace_and_control_values_are_rejected() {
        let too_long = "a".repeat(RecordTime::MAX_LEN + 1);
        for value in [
            "",
            &too_long,
            "2026-10-15 12:00",
            " x",
            "x\n",
            "\t",
            "x\u{0}",
            "x\u{7f}",
            "x\u{1b}[31m",
            "caf\u{e9}",
        ] {
            assert!(
                matches!(
                    value.parse::<RecordTime>(),
                    Err(RecordError::Invalid { .. })
                ),
                "{value:?}"
            );
            let json = serde_json::to_string(value).unwrap();
            assert!(
                serde_json::from_str::<RecordTime>(&json).is_err(),
                "{value:?}"
            );
        }
    }

    #[test]
    fn the_too_long_error_names_the_limit() {
        let too_long = "a".repeat(RecordTime::MAX_LEN + 1);
        let message = too_long.parse::<RecordTime>().unwrap_err().to_string();
        assert!(
            message.contains(&RecordTime::MAX_LEN.to_string()),
            "{message}"
        );
    }
}
