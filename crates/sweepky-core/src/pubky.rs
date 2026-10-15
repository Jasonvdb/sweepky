//! [`Pubky`], a Pubky public key.

use std::fmt;
use std::str::FromStr;

use base32::Alphabet;
use serde::{Deserialize, Serialize, Serializer};

use crate::error::RecordError;

/// The z-base32 alphabet, in value order: what `base32::Alphabet::Z` uses.
/// Every character is checked against it before the decoder sees the input.
const Z32_ALPHABET: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

/// The error reason when that check fails. Named so a test can tell this
/// check's rejection apart from the decoder's.
const OUTSIDE_Z32: &str = "has a character outside the z-base32 alphabet";

/// The prefix the Pubky SDK prints before a key: `pubky<z32>`.
const SDK_PREFIX: &str = "pubky";

/// A Pubky public key: the 32 bytes of an Ed25519 public key.
///
/// Records store a key as 52 characters of raw z-base32 (01's rule), while the
/// SDK prints it as `pubky<z32>`, so parsing takes either form and both give
/// the same value. [`Display`](fmt::Display) and serializing always write the
/// raw form. Deserializing reads either.
///
/// Equality, hashing and ordering use the key bytes, never the string, so two
/// spellings of one key are one key, in a `HashMap`, a `BTreeMap` or a JSON
/// object's keys alike. Note that the order of the bytes is not the order of
/// the z-base32 strings, whose alphabet is not in ASCII order.
///
/// Parsing checks the length, the alphabet and the canonical form (the string
/// [`Display`](fmt::Display) writes back), so no two strings name one key. It
/// does not check that the bytes are a valid Ed25519 point: this crate has no
/// Ed25519 code. Where that matters, the CLI parses the key with the Pubky SDK,
/// which does check it, before it uses the key on the network.
///
/// This is a public key, so the derived `==` is not constant-time and need not
/// be: comparing public values leaks nothing. Never reuse it for secrets.
// The derives work on the `[u8; 32]` inside: arrays compare byte by byte, from
// the first byte, and hash their bytes. `Copy` is fine for 32 bytes of public
// data. `Deserialize` with `try_from = "String"` reads a string and then calls
// `TryFrom<String>` below, so deserializing runs every check that parsing
// does, for a JSON value and for a JSON object key alike.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct Pubky([u8; 32]);

impl Pubky {
    /// The length of a key in raw z-base32: 52 characters.
    pub const Z32_LEN: usize = 52;

    /// The key with these bytes. Every 32 bytes have exactly one z-base32
    /// form, so this cannot fail; like parsing, it does not check that the
    /// bytes are a valid Ed25519 point.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The key's 32 bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl FromStr for Pubky {
    type Err = RecordError;

    /// Accepts 52 characters of z-base32 (lower case), with or without the
    /// `pubky` prefix, that [`Display`](fmt::Display) would write back.
    fn from_str(value: &str) -> Result<Self, RecordError> {
        let invalid = |reason| RecordError::Invalid {
            field: "pubky",
            reason,
        };
        let raw = strip_sdk_prefix(value);
        // Length and alphabet first, before any third-party code runs on the
        // input. Only ASCII passes the alphabet check, so here `len()` (a
        // count of bytes) is also the count of characters.
        if raw.len() != Self::Z32_LEN {
            return Err(invalid(
                "is not 52 z-base32 characters, with or without the pubky prefix",
            ));
        }
        if !raw.bytes().all(|byte| Z32_ALPHABET.contains(&byte)) {
            return Err(invalid(OUTSIDE_Z32));
        }
        let decoded = base32::decode(Alphabet::Z, raw).ok_or(invalid("is not valid z-base32"))?;
        // `Vec<u8>` into `[u8; 32]` is a `TryFrom` that fails, handing the
        // vector back, unless the length is exactly 32. 52 characters always
        // decode to 32 bytes, but a length check costs nothing and a panic
        // would cost a whole `pull`.
        let bytes: [u8; 32] = decoded
            .try_into()
            .map_err(|_| invalid("does not decode to 32 bytes"))?;
        let pubky = Self(bytes);
        // 52 characters carry 260 bits for a 256-bit key, so the last
        // character holds four padding bits that decoding ignores. Re-encoding
        // catches a string with any of them set.
        if pubky.to_string() != raw {
            return Err(invalid("is not in canonical form (a padding bit is set)"));
        }
        Ok(pubky)
    }
}

/// `value` without the SDK's `pubky` prefix, or `value` unchanged when it does
/// not have one.
///
/// The prefix is stripped only when exactly 52 characters follow it, the same
/// test the SDK uses: a raw key may itself begin with the letters "pubky", and
/// must stay whole. `strip_prefix` returns `None` rather than panicking when
/// the prefix is absent, and works on any UTF-8 input.
fn strip_sdk_prefix(value: &str) -> &str {
    match value.strip_prefix(SDK_PREFIX) {
        Some(rest) if rest.len() == Pubky::Z32_LEN => rest,
        _ => value,
    }
}

/// So `#[serde(try_from = "String")]` can call the same checks.
impl TryFrom<String> for Pubky {
    type Error = RecordError;

    fn try_from(value: String) -> Result<Self, RecordError> {
        value.parse()
    }
}

/// Writes the raw z-base32 form, without the `pubky` prefix.
impl fmt::Display for Pubky {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&base32::encode(Alphabet::Z, &self.0))
    }
}

/// Shows the z-base32 string, `Pubky("8pin…")`, rather than 32 numbers.
impl fmt::Debug for Pubky {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Pubky").field(&self.to_string()).finish()
    }
}

impl Serialize for Pubky {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // `collect_str` writes the `Display` output as a string. serde_json
        // accepts a string as an object key, so a `Pubky` can key a map such
        // as `discovered.json`'s `cursors`.
        serializer.collect_str(self)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::hash_map::DefaultHasher;
    use std::collections::{BTreeMap, HashMap};
    use std::hash::{Hash, Hasher};

    use super::{OUTSIDE_Z32, Pubky, Z32_ALPHABET};
    use crate::error::RecordError;
    use crate::ids::EventCursor;

    /// The local testnet homeserver's key (pubky-testnet 0.16.2), the Ed25519
    /// public key of the all-zero seed.
    const TESTNET: &str = "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo";
    const TESTNET_HEX: &str = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";

    fn hash_of(pubky: &Pubky) -> u64 {
        let mut hasher = DefaultHasher::new();
        pubky.hash(&mut hasher);
        hasher.finish()
    }

    /// The testnet key with the character at `index` replaced by `with`.
    /// The key is ASCII, so a character index is also a byte index.
    fn testnet_with(index: usize, with: &str) -> String {
        let mut key = TESTNET.to_owned();
        key.replace_range(index..=index, with);
        key
    }

    /// 52-byte strings with a character outside the z-base32 alphabet, so
    /// they pass the length check and meet the alphabet check.
    fn keys_outside_the_alphabet() -> [String; 6] {
        [
            TESTNET.to_uppercase(),
            testnet_with(10, "0"),
            testnet_with(10, "2"),
            testnet_with(10, "l"),
            testnet_with(10, "v"),
            // Non-ASCII: 51 characters in 52 bytes.
            format!("{}\u{e9}", &TESTNET[..50]),
        ]
    }

    fn assert_invalid_pubky(value: &str) {
        assert!(
            matches!(
                value.parse::<Pubky>(),
                Err(RecordError::Invalid { field: "pubky", .. })
            ),
            "{value:?}"
        );
        let json = serde_json::to_string(value).unwrap();
        assert!(serde_json::from_str::<Pubky>(&json).is_err(), "{value:?}");
    }

    #[test]
    fn the_pre_check_alphabet_is_z_base32() {
        // The byte `value << 3` holds `value` in its top five bits, so the
        // first character of its encoding is the alphabet's character for
        // `value`.
        for (value, &expected) in (0u8..).zip(Z32_ALPHABET) {
            let encoded = base32::encode(base32::Alphabet::Z, &[value << 3]);
            assert_eq!(encoded.as_bytes()[0], expected, "{value}");
        }
    }

    #[test]
    fn the_testnet_key_decodes_to_its_bytes() {
        let pubky: Pubky = TESTNET.parse().unwrap();
        let hex: String = pubky
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(hex, TESTNET_HEX);
        assert_eq!(pubky.to_string(), TESTNET);
    }

    #[test]
    fn both_forms_parse_to_the_same_key() {
        let raw: Pubky = TESTNET.parse().unwrap();
        let prefixed: Pubky = format!("pubky{TESTNET}").parse().unwrap();
        assert_eq!(raw, prefixed);
        assert_eq!(hash_of(&raw), hash_of(&prefixed));
        assert_eq!(raw.cmp(&prefixed), std::cmp::Ordering::Equal);
        assert_eq!(Pubky::try_from(TESTNET.to_owned()).unwrap(), raw);
    }

    #[test]
    fn a_prefixed_key_is_written_back_raw() {
        let prefixed: Pubky = format!("pubky{TESTNET}").parse().unwrap();
        assert_eq!(prefixed.to_string(), TESTNET);
        assert_eq!(
            serde_json::to_string(&prefixed).unwrap(),
            format!("\"{TESTNET}\"")
        );
    }

    #[test]
    fn json_reads_either_form() {
        let raw: Pubky = TESTNET.parse().unwrap();
        for text in [TESTNET.to_owned(), format!("pubky{TESTNET}")] {
            let json = serde_json::to_string(&text).unwrap();
            assert_eq!(serde_json::from_str::<Pubky>(&json).unwrap(), raw);
        }
    }

    #[test]
    fn a_raw_key_that_starts_with_pubky_is_still_raw() {
        // 52 characters that happen to begin with "pubky": the prefix is
        // stripped only when 52 characters follow it.
        let raw = format!("pubky{}", "y".repeat(47));
        let pubky: Pubky = raw.parse().unwrap();
        assert_eq!(pubky.to_string(), raw);
        let prefixed: Pubky = format!("pubky{raw}").parse().unwrap();
        assert_eq!(prefixed, pubky);
    }

    #[test]
    fn keys_compare_by_bytes_not_by_string() {
        let zeros = Pubky::from_bytes([0; 32]);
        let ones = Pubky::from_bytes([0xff; 32]);
        // z-base32 is not in ASCII order: zero bits are 'y' and one bits '9',
        // so the strings sort the other way round from the bytes.
        assert!(zeros.to_string() > ones.to_string());
        assert!(zeros < ones);
        // `from_bytes` gives the same key as parsing its z-base32 form.
        assert_eq!(zeros.to_string().parse::<Pubky>().unwrap(), zeros);
        assert_eq!(ones.to_string().parse::<Pubky>().unwrap(), ones);
    }

    #[test]
    fn a_pubky_works_as_a_map_key() {
        let testnet: Pubky = TESTNET.parse().unwrap();
        let prefixed: Pubky = format!("pubky{TESTNET}").parse().unwrap();
        let other = Pubky::from_bytes([7; 32]);

        let mut hash_map = HashMap::new();
        hash_map.insert(testnet, 1);
        hash_map.insert(other, 2);
        assert_eq!(hash_map.get(&prefixed), Some(&1));

        let mut btree = BTreeMap::new();
        btree.insert(testnet, 1);
        btree.insert(other, 2);
        assert_eq!(btree.get(&prefixed), Some(&1));
    }

    #[test]
    fn a_pubky_works_as_a_json_object_key() {
        // As in discovered.json's `cursors`.
        let testnet: Pubky = TESTNET.parse().unwrap();
        let mut cursors = BTreeMap::new();
        cursors.insert(testnet, EventCursor::new(42));
        cursors.insert(Pubky::from_bytes([7; 32]), EventCursor::new(7));

        let json = serde_json::to_string(&cursors).unwrap();
        assert!(json.contains(&format!("\"{TESTNET}\":\"42\"")), "{json}");
        let back: BTreeMap<Pubky, EventCursor> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cursors);

        let prefixed_key = format!(r#"{{"pubky{TESTNET}":"42"}}"#);
        let back: BTreeMap<Pubky, EventCursor> = serde_json::from_str(&prefixed_key).unwrap();
        assert_eq!(back.get(&testnet), Some(&EventCursor::new(42)));
    }

    #[test]
    fn malformed_keys_are_rejected_without_panicking() {
        // Every case starts from the valid testnet key.
        let other_malformed = [
            // 51, 53, 56 and 58 characters.
            TESTNET[..51].to_owned(),
            format!("{TESTNET}y"),
            format!("{TESTNET}yyyy"),
            format!("{TESTNET}yyyyyy"),
            // An upper-case prefix.
            format!("PUBKY{TESTNET}"),
            // Non-ASCII: 52 characters in 53 bytes.
            testnet_with(10, "\u{e9}"),
            // The prefix with one character too few or too many.
            format!("pubky{}", &TESTNET[..51]),
            format!("pubky{TESTNET}y"),
            // Another SDK's prefix, which this type does not accept.
            format!("pk:{TESTNET}"),
            // The last character carries four padding bits. 'o' is 10000 and
            // 't' is 10001: both decode to the same 32 bytes, so only 'o' is
            // canonical.
            testnet_with(51, "t"),
            String::new(),
            format!("{TESTNET}\n"),
            format!(" {TESTNET}"),
        ];
        for value in keys_outside_the_alphabet().iter().chain(&other_malformed) {
            assert_invalid_pubky(value);
        }
    }

    #[test]
    fn characters_outside_z32_stop_at_the_alphabet_check() {
        // The alphabet check stops these before base32 runs.
        let outside = RecordError::Invalid {
            field: "pubky",
            reason: OUTSIDE_Z32,
        };
        for value in keys_outside_the_alphabet() {
            assert_eq!(value.parse::<Pubky>().unwrap_err(), outside, "{value:?}");
        }
    }
}
