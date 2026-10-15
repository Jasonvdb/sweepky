//! [`RecordTime`], the timestamp strings records carry.

use serde::{Deserialize, Serialize};

use crate::error::RecordError;
use crate::validated_string::validated_string;

/// The value of a time field in a record: `createdAt`, `startedAt`,
/// `finishedAt`, `doneAt` or `revokedAt`.
///
/// 01 does not say how these are encoded, so this type keeps the string
/// opaque: it never parses it as a date and has no ordering, because comparing
/// two strings in an unknown format says nothing about which time is earlier.
/// It only checks that the value is 1 to [`RecordTime::MAX_LEN`] printable
/// ASCII characters (`!` to `~`, so no spaces, tabs, newlines or control
/// characters). That keeps a stranger's record from putting a long text or a
/// terminal escape sequence into a field the CLI prints. These limits are
/// P1a's choice, not 01's.
///
/// There is no `now()`: this crate has no clock. The CLI reads the time and
/// passes the string in, so tests can use fixed values.
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

// `as_str()`, `FromStr`, `TryFrom<String>`, `From<RecordTime> for String`
// and `Display`, each running `check` where it makes a value.
validated_string!(RecordTime);

#[cfg(test)]
mod tests {
    use super::RecordTime;
    use crate::error::RecordError;

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
