//! [`RecordId`], the id in a record's file name, and [`EventCursor`], a
//! position in a homeserver's `/events/` feed.

use std::fmt;
use std::str::FromStr;

use pubky_timestamp::Timestamp;
use serde::{Deserialize, Serialize, Serializer};

use crate::error::RecordError;

/// Crockford's base32 alphabet, upper case only, in value order.
///
/// base32's Crockford decoder is lenient on purpose: it also reads lower case,
/// and reads `I` and `L` as `1` and `O` as `0`. Here that would let several
/// strings name one record, so every character is checked against this list
/// before the decoder sees it.
const CROCKFORD_UPPER: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// The error reason when that check fails. Named so a test can tell this
/// check's rejection apart from the decoder's.
const OUTSIDE_CROCKFORD: &str =
    "has a character outside upper-case Crockford base32 (0-9, A-Z without I, L, O, U)";

/// The id of a record, the `<id>` in `bounties/<id>.json` and
/// `sweeps/<id>.json`: a [`pubky_timestamp::Timestamp`] written as 13
/// characters of upper-case Crockford base32, the format pubky-app-specs uses.
///
/// The timestamp is microseconds since 1970, and the 13 characters encode its
/// 8 bytes big-endian, so ids sort the same way as strings and as timestamps.
/// That is what makes a homeserver's byte-order listing chronological. `Ord`
/// here compares the timestamps.
///
/// Parsing accepts only the canonical form, the exact string
/// [`Display`](fmt::Display) writes back, so two different strings never name
/// the same record. Serialized as that string.
///
/// There is no `RecordId::now()` and no `Default` (pubky-timestamp's own
/// `Default` reads the clock): this crate has no clock. The CLI makes a
/// timestamp and passes it to [`RecordId::from_timestamp`].
// The derives compare and hash the inner `Timestamp`, a `u64`. `Copy` is fine
// for an 8-byte value: copying it is as cheap as passing a reference.
//
// `Deserialize` with `try_from = "String"` reads a JSON string and then calls
// `TryFrom<String>` below, so deserializing runs the same checks as parsing.
// `Serialize` is written by hand further down rather than derived: a derive
// would serialize the inner `Timestamp` through pubky-timestamp's own serde
// support, which writes 8 raw bytes, not the id string. This crate never turns
// that feature on, but `pubky` does (pubky-common asks for pubky-timestamp's
// `full` features), and Cargo merges features, so in the CLI's build it is on.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct RecordId(Timestamp);

impl RecordId {
    /// The length of every id: 13 characters.
    pub const LEN: usize = 13;

    /// The id for `timestamp`. Every `u64` has exactly one 13-character
    /// form, so this cannot fail.
    pub const fn from_timestamp(timestamp: Timestamp) -> Self {
        Self(timestamp)
    }

    /// The timestamp this id encodes.
    pub const fn timestamp(self) -> Timestamp {
        self.0
    }
}

impl FromStr for RecordId {
    type Err = RecordError;

    /// Accepts exactly 13 characters of upper-case Crockford base32 that
    /// [`Display`](fmt::Display) would write back unchanged.
    fn from_str(value: &str) -> Result<Self, RecordError> {
        let invalid = |reason| RecordError::Invalid {
            field: "record id",
            reason,
        };
        // Length and alphabet first, before any third-party code runs on the
        // input. `len()` counts bytes, and only ASCII passes the alphabet
        // check, so here bytes and characters are the same thing.
        if value.len() != Self::LEN {
            return Err(invalid("is not 13 characters"));
        }
        if !value.bytes().all(|byte| CROCKFORD_UPPER.contains(&byte)) {
            return Err(invalid(OUTSIDE_CROCKFORD));
        }
        // pubky-timestamp's own parser. It takes a `String`, hence the copy.
        // After the checks above it cannot fail, but its error is still
        // mapped rather than unwrapped: this crate never panics on input.
        let timestamp = Timestamp::try_from(value.to_owned())
            .map_err(|_| invalid("is not valid Crockford base32"))?;
        let id = Self(timestamp);
        // 13 characters carry 65 bits for a 64-bit value, so the last
        // character holds one padding bit that decoding ignores: `…E` and
        // `…F` decode alike. Re-encoding catches the one with the bit set.
        if id.to_string() != value {
            return Err(invalid("is not in canonical form (a padding bit is set)"));
        }
        Ok(id)
    }
}

/// So `#[serde(try_from = "String")]` can call the same checks.
impl TryFrom<String> for RecordId {
    type Error = RecordError;

    fn try_from(value: String) -> Result<Self, RecordError> {
        value.parse()
    }
}

/// Writes the 13-character form.
impl fmt::Display for RecordId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // pubky-timestamp's `Display` is the definition of the format. With
        // its `base32` feature (always on here, see Cargo.toml) it writes the
        // Crockford string; without it, it would write `Timestamp (<n>)`.
        fmt::Display::fmt(&self.0, f)
    }
}

/// Shows the id string, `RecordId("0035G87EK4XFE")`, rather than the number.
impl fmt::Debug for RecordId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RecordId").field(&self.to_string()).finish()
    }
}

impl Serialize for RecordId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // `collect_str` writes the `Display` output as a string, so the JSON
        // form and the printed form are one and the same.
        serializer.collect_str(self)
    }
}

/// A position in a homeserver's public `/events/` feed: the id of the last
/// event read, as in the feed's `cursor: <id>` line and in
/// `bounties/<id>.discovered.json`'s `cursors`.
///
/// In pubky-core 0.16.2 an event id is a `u64` written in decimal, and the
/// feed returns the events whose id is greater than the cursor, so
/// `EventCursor::new(0)` reads from the beginning of history.
///
/// Parsing accepts only canonical decimal: ASCII digits, no sign, no
/// whitespace, no leading zero (except `0` itself), at most `u64::MAX`.
/// Serialized as a JSON string, the shape `discovered.json` stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct EventCursor(u64);

impl EventCursor {
    /// The cursor at the event with this id: the feed continues with the
    /// events after it.
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// The event id.
    pub const fn id(self) -> u64 {
        self.0
    }
}

impl FromStr for EventCursor {
    type Err = RecordError;

    fn from_str(value: &str) -> Result<Self, RecordError> {
        let invalid = |reason| RecordError::Invalid {
            field: "event cursor",
            reason,
        };
        if value.is_empty() {
            return Err(invalid("is empty"));
        }
        // `u64::from_str` alone would accept a leading `+` and leading zeros,
        // so `"+7"`, `"007"` and `"7"` would all be one cursor. Checking the
        // digits first leaves exactly one spelling of each number.
        if !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid("has a character that is not a decimal digit"));
        }
        if value.len() > 1 && value.starts_with('0') {
            return Err(invalid("has a leading zero"));
        }
        // Only digits are left, so the one way this can fail is a number
        // above `u64::MAX`. It returns an error for that; it never panics.
        let id = value
            .parse::<u64>()
            .map_err(|_| invalid("is larger than a 64-bit event id can be"))?;
        Ok(Self(id))
    }
}

/// So `#[serde(try_from = "String")]` can call the same checks.
impl TryFrom<String> for EventCursor {
    type Error = RecordError;

    fn try_from(value: String) -> Result<Self, RecordError> {
        value.parse()
    }
}

/// Writes the id in decimal.
impl fmt::Display for EventCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl Serialize for EventCursor {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // A string, not a JSON number, so the written form is the one the
        // feed itself uses.
        serializer.collect_str(self)
    }
}

#[cfg(test)]
mod tests {
    use pubky_timestamp::Timestamp;

    use super::{CROCKFORD_UPPER, EventCursor, OUTSIDE_CROCKFORD, RecordId};
    use crate::error::RecordError;

    /// A bounty id from fixtures/trust-labels.json.
    const FIXTURE_ID: &str = "0035G87EK4XFE";

    /// 13-character ids with a character outside upper-case Crockford. The
    /// first four the base32 decoder itself would read: lower case, and I, L
    /// and O, which it reads as 1, 1 and 0. It refuses the last one, U.
    const IDS_OUTSIDE_THE_ALPHABET: [&str; 5] = [
        "0035g87ek4xfe",
        "0035G87EK4IFE",
        "0035G87EK4LFE",
        "0035G87EK4OFE",
        "0035G87EK4UFE",
    ];

    fn id_at(micros: u64) -> RecordId {
        RecordId::from_timestamp(Timestamp::from(micros))
    }

    fn assert_invalid_id(value: &str) {
        assert!(
            matches!(
                value.parse::<RecordId>(),
                Err(RecordError::Invalid {
                    field: "record id",
                    ..
                })
            ),
            "{value:?}"
        );
        let json = serde_json::to_string(value).unwrap();
        assert!(
            serde_json::from_str::<RecordId>(&json).is_err(),
            "{value:?}"
        );
    }

    #[test]
    fn the_pre_check_alphabet_is_crockford_upper_case() {
        // The byte `value << 3` holds `value` in its top five bits, so the
        // first character of its encoding is the alphabet's character for
        // `value`.
        for (value, &expected) in (0u8..).zip(CROCKFORD_UPPER) {
            let encoded = base32::encode(base32::Alphabet::Crockford, &[value << 3]);
            assert_eq!(encoded.as_bytes()[0], expected, "{value}");
        }
    }

    #[test]
    fn a_fixture_id_parses_and_displays_unchanged() {
        let id: RecordId = FIXTURE_ID.parse().unwrap();
        assert_eq!(id.to_string(), FIXTURE_ID);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{FIXTURE_ID}\""));
        assert_eq!(serde_json::from_str::<RecordId>(&json).unwrap(), id);
        assert_eq!(RecordId::try_from(FIXTURE_ID.to_owned()).unwrap(), id);
    }

    #[test]
    fn an_id_made_from_a_timestamp_parses_back_to_itself() {
        let fixture: RecordId = FIXTURE_ID.parse().unwrap();
        for micros in [
            0,
            1,
            1_760_529_600_000_000,
            fixture.timestamp().as_u64(),
            u64::MAX,
        ] {
            let id = id_at(micros);
            let text = id.to_string();
            assert_eq!(text.len(), RecordId::LEN, "{text}");
            let back: RecordId = text.parse().unwrap();
            assert_eq!(back, id, "{text}");
            assert_eq!(back.timestamp(), Timestamp::from(micros), "{text}");
        }
    }

    #[test]
    fn ids_sort_in_timestamp_order() {
        // Each id, and each id's string, sorts before the next one's. The
        // strings agreeing is what makes a homeserver's byte-order listing
        // chronological.
        let ascending = [
            0,
            7,
            1 << 40,
            1_760_529_600_000_000,
            1_760_529_600_000_002,
            u64::MAX,
        ]
        .map(id_at);
        for pair in ascending.windows(2) {
            let (earlier, later) = (pair[0], pair[1]);
            assert!(earlier < later, "{earlier:?} {later:?}");
            assert!(
                earlier.to_string() < later.to_string(),
                "{earlier:?} {later:?}"
            );
        }
    }

    #[test]
    fn malformed_ids_are_rejected_without_panicking() {
        let other_malformed = [
            // 12 and 14 characters.
            "0035G87EK4XF",
            "0035G87EK4XFE0",
            // Non-ASCII: 13 characters but 14 bytes, and 12 characters but 13
            // bytes.
            "0035G87EK4XF\u{c9}",
            "0035G87EK4X\u{c9}",
            "",
            // The last character carries one padding bit. E is 01110 and F is
            // 01111: both decode to the same 8 bytes, so only E is canonical.
            "0035G87EK4XFF",
            " 035G87EK4XFE",
            "0035G87EK4XF\n",
        ];
        for value in IDS_OUTSIDE_THE_ALPHABET.into_iter().chain(other_malformed) {
            assert_invalid_id(value);
        }
    }

    #[test]
    fn characters_outside_crockford_stop_at_the_alphabet_check() {
        // A later check would catch each of these too (the decoder for U,
        // the re-encode check for the rest), but they must not get that far:
        // the alphabet check stops them before base32 runs.
        let outside = RecordError::Invalid {
            field: "record id",
            reason: OUTSIDE_CROCKFORD,
        };
        for value in IDS_OUTSIDE_THE_ALPHABET {
            assert_eq!(value.parse::<RecordId>().unwrap_err(), outside, "{value:?}");
        }
    }

    #[test]
    fn cursors_parse_as_canonical_decimal() {
        let max = u64::MAX.to_string();
        for (text, id) in [("0", 0), ("12345", 12345), (max.as_str(), u64::MAX)] {
            let cursor: EventCursor = text.parse().unwrap();
            assert_eq!(cursor, EventCursor::new(id));
            assert_eq!(cursor.id(), id);
            assert_eq!(cursor.to_string(), text);
        }
    }

    #[test]
    fn cursors_order_by_number_not_by_string() {
        // As strings "10" sorts before "9".
        assert!(EventCursor::new(9) < EventCursor::new(10));
    }

    #[test]
    fn malformed_cursors_are_rejected_without_panicking() {
        for value in [
            "",
            "-1",
            "+1",
            " 1",
            "1 ",
            "01",
            "00",
            "1.0",
            "abc",
            "1e3",
            "\u{661}",
            // u64::MAX + 1, and 21 digits.
            "18446744073709551616",
            "184467440737095516150",
        ] {
            assert!(
                matches!(
                    value.parse::<EventCursor>(),
                    Err(RecordError::Invalid {
                        field: "event cursor",
                        ..
                    })
                ),
                "{value:?}"
            );
            let json = serde_json::to_string(value).unwrap();
            assert!(
                serde_json::from_str::<EventCursor>(&json).is_err(),
                "{value:?}"
            );
        }
    }

    #[test]
    fn a_cursor_is_a_json_string() {
        let cursor = EventCursor::new(12345);
        assert_eq!(serde_json::to_string(&cursor).unwrap(), r#""12345""#);
        assert_eq!(
            serde_json::from_str::<EventCursor>(r#""12345""#).unwrap(),
            cursor
        );
        // A bare JSON number is not the canonical form.
        assert!(serde_json::from_str::<EventCursor>("12345").is_err());
    }
}
