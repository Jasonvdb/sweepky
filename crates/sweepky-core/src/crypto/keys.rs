//! The key types every encryption step uses: [`DeviceIdentity`], one
//! install's secret age key, and [`AgeRecipient`], a public `age1…` key read
//! strictly, with their errors.
//!
//! A recipient usually comes from someone else's `keys/<deviceId>.json`,
//! which anyone holding the owner's grant (or an active operator of the
//! owner's homeserver) can write, so it is parsed as hostile input. An
//! identity string comes from this install's own key file, but it is a
//! secret, so it never leaves a [`SecretString`] and no error repeats it.

use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use age::secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize, Serializer};

/// The bech32 data alphabet in value order (BIP 173), lower case only: age
/// writes recipients in lower case. Every character after `age1` is checked
/// against it before age's decoder sees the input.
const BECH32_ALPHABET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// How every accepted recipient starts: age's human-readable part `age` and
/// bech32's separator `1`. The alphabet above has no `1`, so a string that
/// starts like this and passes the alphabet check has `age` as its only
/// possible human-readable part. That shuts out every other kind of age key
/// written `age1…`, such as `age1tag1…`, `age1pq1…` and plugin recipients.
const RECIPIENT_PREFIX: &str = "age1";

/// The canonical encodings of the X25519 points of small order: the seven
/// u values in libsodium's `has_small_order` list (0, 1, the two points of
/// order 8, p - 1, and p and p + 1, which X25519 reduces to 0 and 1, for
/// p = 2^255 - 19), each with bit 255 clear and set, since X25519 ignores
/// that bit.
///
/// age 0.12.1's parser accepts all 14, and its encryptor then panics
/// ("Generated the all-zero esk"), because a Diffie-Hellman with any of them
/// gives the all-zero shared secret. A record under an owner's `keys/` could
/// carry one, so the parse refuses them, and a sweeper's `submit` gets an
/// `Err` instead of a crash.
///
/// The parse compares strings, which is enough because it has already
/// refused every string age would not write back unchanged: a key has one
/// accepted spelling per 32-byte encoding. A test re-derives this list from
/// the u values with its own bech32 encoder and shows age panics on each.
const LOW_ORDER_RECIPIENTS: [&str; 14] = [
    // 0
    "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq5cu47z",
    "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzqqsuwj9m",
    // 1
    "age1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqj7vrya",
    "age1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzqqk67yly",
    // The first point of order 8.
    "age1ur4h5lpmgxu2u9jku0a0r87ydtdqnr0tnsetrlvxvgz3vh6fhqqqzyt4v9",
    "age1ur4h5lpmgxu2u9jku0a0r87ydtdqnr0tnsetrlvxvgz3vh6fhzqqxqejhu",
    // The second point of order 8.
    "age1t7wft09r2zxzfvwsk92eeql0tvzyghxytqwgapkcyf8dm5ylz9ts6wm9s8",
    "age1t7wft09r2zxzfvwsk92eeql0tvzyghxytqwgapkcyf8dm5ylz8ts72fzt7",
    // p - 1
    "age1anlllllllllllllllllllllllllllllllllllllllllllllllals4n2t7m",
    "age1anllllllllllllllllllllllllllllllllllllllllllllllllls3hcv9z",
    // p
    "age1ahlllllllllllllllllllllllllllllllllllllllllllllllalsn46ayy",
    "age1ahlllllllllllllllllllllllllllllllllllllllllllllllllsh3g6la",
    // p + 1
    "age1amlllllllllllllllllllllllllllllllllllllllllllllllalselrwrv",
    "age1amlllllllllllllllllllllllllllllllllllllllllllllllllsam3fc4",
];

/// Why a string is not an age X25519 recipient this crate encrypts to.
///
/// The variants hold no data, so an error can never carry the input, or
/// any part of it, into a log line or a terminal. age's own error text is
/// dropped too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RecipientError {
    /// The input is not exactly [`AgeRecipient::LEN`] bytes long. Checked
    /// first, so an oversized input is never decoded.
    #[error("an age recipient is exactly 62 characters long")]
    Length,
    /// The input does not start with `age1`, or has a character after it
    /// that is not in lower-case bech32: upper case, whitespace, another
    /// kind of key, a non-ASCII look-alike.
    #[error("an age recipient is \"age1\" followed by lower-case bech32 characters")]
    Form,
    /// age's own parser refused it: most likely a bad checksum.
    #[error("not a valid age X25519 recipient: bad bech32 checksum or payload")]
    Encoding,
    /// A valid encoding of a key, but not the one age writes for it: some
    /// of the four padding bits at the end of the data are set.
    #[error("not the canonical spelling of an age recipient: padding bits are set")]
    NonCanonical,
    /// One of the X25519 points of small order, which no real key is and
    /// which age's encryptor panics on.
    #[error("an X25519 point of small order, which no real key is")]
    LowOrder,
}

/// Why a [`DeviceKey`](crate::DeviceKey) is not one to encrypt a sweep to,
/// from [`DeviceKey::encryption_recipient`](crate::DeviceKey::encryption_recipient).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DeviceKeyError {
    /// `alg` is not exactly `age-x25519`, the one kind of key this build
    /// encrypts to. A newer client's key kind lands here, which is not an
    /// error in the record: skip the key.
    #[error("device key alg is not age-x25519")]
    UnsupportedAlg,
    /// `revokedAt` is set: the key takes no further sweeps.
    #[error("device key is revoked")]
    Revoked,
    /// `recipient` fails [`AgeRecipient`]'s strict parse.
    // `#[from]` writes `impl From<RecipientError> for DeviceKeyError`, so `?`
    // converts, and makes the inner error this one's `source()`, so a caller
    // printing the whole chain (anyhow's `{:#}`) shows the reason too.
    #[error("device key recipient is not a usable age X25519 recipient")]
    Recipient(#[from] RecipientError),
}

/// A public age X25519 key, `age1…`: what a sweep is encrypted to.
///
/// [`FromStr`] (and deserializing, which goes through it) is strict, in this
/// order:
///
/// 1. exactly [`Self::LEN`] bytes, `age1` and then lower-case bech32
///    characters only, checked before anything decodes the input;
/// 2. age's own parser, which checks the checksum and the 32-byte length;
/// 3. the string must be the one age writes back for those 32 bytes, which
///    refuses set padding bits, so each 32-byte key has one accepted
///    spelling;
/// 4. not one of the 14 encodings of a point of small order, which age's
///    encryptor would panic on.
///
/// So a value of this type is always safe to hand to age's encryptor.
/// [`Display`](fmt::Display) and serializing write the string back exactly
/// as it was read.
///
/// Two recipients are equal when their strings are. This is deliberately not
/// age's own `==`, which compares the keys as X25519 numbers: it ignores bit
/// 255 and reduces modulo p, so it calls some pairs of different accepted
/// strings equal. The odd one of such a pair is never a real key (every
/// public key age computes is written below p with bit 255 clear), and age
/// mixes the bytes as written into its key derivation, so the identity behind
/// the real key could not open a file encrypted to the odd one. Comparing
/// strings means a changed key record never passes for a pinned one. This is
/// a public key, so comparing it in variable time leaks nothing.
// `Clone` is fine: this is a public key. `Deserialize` with
// `try_from = "String"` reads a string and then calls `TryFrom<String>`
// below, so deserializing runs every check that parsing does.
#[derive(Clone, Deserialize)]
#[serde(try_from = "String")]
pub struct AgeRecipient(age::x25519::Recipient);

impl AgeRecipient {
    /// The length of every accepted recipient: 62 characters (`age1`, 52
    /// data characters for the 32-byte key, and a 6-character checksum).
    pub const LEN: usize = 62;
}

impl FromStr for AgeRecipient {
    type Err = RecipientError;

    fn from_str(input: &str) -> Result<Self, RecipientError> {
        // 1. Length and form, before anything decodes the input.
        check_recipient_form(input)?;
        // 2. age's parser. Its error is a `&'static str`, so it could not
        // carry the input, but `|_|` drops it anyway: this crate's error
        // text is its own.
        let recipient =
            age::x25519::Recipient::from_str(input).map_err(|_| RecipientError::Encoding)?;
        // 3. The canonical spelling. 52 characters carry 260 bits for a
        // 256-bit key; age's decoder ignores the last 4, and writing the key
        // back sets them to zero.
        if recipient.to_string() != input {
            return Err(RecipientError::NonCanonical);
        }
        // 4. The points of small order. After step 3, comparing the string is
        // comparing the key's bytes.
        if LOW_ORDER_RECIPIENTS.contains(&input) {
            return Err(RecipientError::LowOrder);
        }
        Ok(Self(recipient))
    }
}

/// Step 1 of the parse: exactly [`AgeRecipient::LEN`] bytes, `age1`, and then
/// lower-case bech32 characters only.
// `len()` counts bytes, and only ASCII passes the alphabet check, so a
// non-ASCII character fails one check or the other. `strip_prefix` returns
// `None` rather than panicking when the prefix is missing, and never slices
// through a multi-byte character.
fn check_recipient_form(input: &str) -> Result<(), RecipientError> {
    if input.len() != AgeRecipient::LEN {
        return Err(RecipientError::Length);
    }
    let data = input
        .strip_prefix(RECIPIENT_PREFIX)
        .ok_or(RecipientError::Form)?;
    if !data.bytes().all(|byte| BECH32_ALPHABET.contains(&byte)) {
        return Err(RecipientError::Form);
    }
    Ok(())
}

/// So `#[serde(try_from = "String")]` can call the same checks.
impl TryFrom<String> for AgeRecipient {
    type Error = RecipientError;

    fn try_from(value: String) -> Result<Self, RecipientError> {
        value.parse()
    }
}

/// Writes the `age1…` string, exactly as it was parsed.
impl fmt::Display for AgeRecipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// Shows the public key, `AgeRecipient("age1…")`.
impl fmt::Debug for AgeRecipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AgeRecipient")
            .field(&self.to_string())
            .finish()
    }
}

/// Compares the strings (see the type's docs for why not age's `==`).
impl PartialEq for AgeRecipient {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
    }
}

impl Eq for AgeRecipient {}

/// Hashes the string, so that equal values hash alike, as `HashMap` and
/// `HashSet` require.
impl Hash for AgeRecipient {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_string().hash(state);
    }
}

impl Serialize for AgeRecipient {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // `collect_str` writes the `Display` output as a JSON string.
        serializer.collect_str(self)
    }
}

/// How every accepted identity starts: age's upper-case human-readable part
/// `AGE-SECRET-KEY-` and bech32's separator `1`.
const IDENTITY_PREFIX: &str = "AGE-SECRET-KEY-1";

/// The length of an age X25519 identity string: the 16-character prefix
/// above, 52 data characters for the 32-byte key and a 6-character checksum.
const IDENTITY_LEN: usize = 74;

/// Why a string is not an age X25519 identity.
///
/// Like [`RecipientError`], the variants hold no data: the input is a
/// secret, and an error must not repeat any of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    /// The input is not exactly 74 bytes long. A trailing newline is
    /// refused here too: the parse trims nothing.
    #[error("an age identity is exactly 74 characters long")]
    Length,
    /// The input does not start with the upper-case `AGE-SECRET-KEY-` and
    /// the separator `1`.
    #[error("an age identity starts with the upper-case AGE-SECRET-KEY- prefix and 1")]
    Prefix,
    /// age's own parser refused it: a bad checksum, mixed case or a wrong
    /// payload length.
    #[error("not a valid age X25519 identity")]
    Encoding,
}

/// This install's secret age key: it opens the sweeps encrypted to its
/// [`recipient`](Self::recipient).
///
/// It holds age's own `age::x25519::Identity` directly. That type wipes its
/// key bytes when it is dropped and has no `Debug`; it does not implement
/// `Zeroize`, so it cannot go inside a `SecretBox`, and does not need to.
///
/// This type implements none of `Debug`, `Display`, `Serialize`,
/// `Deserialize`, `Clone` and `PartialEq` (a test checks that at compile
/// time). So it cannot be printed, logged or serialized by accident, it is
/// never copied by cloning, and two secrets are never compared. The only
/// way to its text is [`to_secret_string`](Self::to_secret_string), which
/// returns a [`SecretString`], for the CLI to write to its 0600 key file.
///
/// Moving a value in Rust copies its bytes and does not wipe the old place,
/// so a moved identity can leave a copy in memory that is not overwritten.
/// That is a limit of Rust and of age alike; keeping one value and passing
/// references keeps it small.
pub struct DeviceIdentity(age::x25519::Identity);

impl DeviceIdentity {
    /// A new random identity, from the operating system's random number
    /// generator (age's `Identity::generate`). This crate has no seeded or
    /// test generator.
    ///
    /// # Panics
    ///
    /// Only if the operating system cannot supply random bytes, which age's
    /// generator treats as fatal rather than make a weak key.
    pub fn generate() -> Self {
        Self(age::x25519::Identity::generate())
    }

    /// The public key that sweeps for this install are encrypted to: what
    /// `login` publishes as `recipient` in `keys/<deviceId>.json`.
    pub fn recipient(&self) -> AgeRecipient {
        // Built directly, not by parsing a string: a public key computed from
        // a secret one is a multiple of the base point, never of small order,
        // and age writes it in its canonical form, so every check of the
        // strict parse holds already.
        AgeRecipient(self.0.to_public())
    }

    /// The identity as age's upper-case bech32 string, for the CLI's key
    /// file. It is a [`SecretString`], which wipes itself when dropped and
    /// prints `[REDACTED]` for `Debug`; reading it takes an explicit
    /// [`ExposeSecret::expose_secret`].
    pub fn to_secret_string(&self) -> SecretString {
        self.0.to_string()
    }

    /// Reads an identity back from the string
    /// [`to_secret_string`](Self::to_secret_string) wrote.
    ///
    /// Refuses anything that is not exactly 74 bytes
    /// ([`IdentityError::Length`]), including the same string with a
    /// trailing newline; anything that does not start with the upper-case
    /// `AGE-SECRET-KEY-` prefix and `1` ([`IdentityError::Prefix`]); and
    /// anything age's own parser refuses ([`IdentityError::Encoding`]).
    pub fn from_secret(secret: &SecretString) -> Result<Self, IdentityError> {
        // `expose_secret` lends the text as a `&str` for this function only;
        // nothing here copies it.
        let text = secret.expose_secret();
        check_identity_form(text)?;
        // age's parser wipes the key bytes it decodes once it has built the
        // identity. Its error is dropped, as for recipients.
        age::x25519::Identity::from_str(text)
            .map(Self)
            .map_err(|_| IdentityError::Encoding)
    }
}

/// The checks before age's parser: exactly [`IDENTITY_LEN`] bytes, starting
/// with [`IDENTITY_PREFIX`].
// They look only at the length and the fixed prefix, which are the same for
// every identity, so they reveal nothing about the key.
fn check_identity_form(text: &str) -> Result<(), IdentityError> {
    if text.len() != IDENTITY_LEN {
        return Err(IdentityError::Length);
    }
    if !text.starts_with(IDENTITY_PREFIX) {
        return Err(IdentityError::Prefix);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::iter;
    use std::panic;
    use std::str::FromStr;

    use age::secrecy::{ExposeSecret, SecretString};
    use serde_json::Value;

    use super::{
        AgeRecipient, BECH32_ALPHABET, DeviceIdentity, DeviceKeyError, IDENTITY_LEN,
        IDENTITY_PREFIX, IdentityError, LOW_ORDER_RECIPIENTS, RECIPIENT_PREFIX, RecipientError,
    };

    // A bech32 encoder (BIP 173) for the tests alone, written apart from age's
    // so the tests can build strings age's own encoder never writes: other
    // HRPs, other payload lengths, non-zero padding bits and the low-order
    // points.

    /// The checksum's generator polynomial, from BIP 173.
    const GENERATOR: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];

    fn polymod(values: &[u8]) -> u32 {
        let mut checksum: u32 = 1;
        for &value in values {
            let top = checksum >> 25;
            checksum = ((checksum & 0x01ff_ffff) << 5) ^ u32::from(value);
            for (bit, generator) in GENERATOR.iter().enumerate() {
                if (top >> bit) & 1 == 1 {
                    checksum ^= generator;
                }
            }
        }
        checksum
    }

    /// Bytes as 5-bit groups, most significant bit first, with the last group
    /// padded with zero bits.
    fn to_groups(bytes: &[u8]) -> Vec<u8> {
        let mut groups = Vec::new();
        let mut buffer: u32 = 0;
        let mut bits = 0;
        for &byte in bytes {
            buffer = ((buffer << 8) | u32::from(byte)) & 0x1fff;
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                groups.push(((buffer >> bits) & 31) as u8);
            }
        }
        if bits > 0 {
            groups.push(((buffer << (5 - bits)) & 31) as u8);
        }
        groups
    }

    /// `hrp`, the separator `1`, the groups and their checksum.
    fn encode_groups(hrp: &str, groups: &[u8]) -> String {
        let mut values: Vec<u8> = hrp.bytes().map(|byte| byte >> 5).collect();
        values.push(0);
        values.extend(hrp.bytes().map(|byte| byte & 31));
        values.extend_from_slice(groups);
        values.extend_from_slice(&[0; 6]);
        let checksum = polymod(&values) ^ 1;
        let checksum_groups = (0..6).map(|index| ((checksum >> (5 * (5 - index))) & 31) as u8);

        let mut text = format!("{hrp}1");
        for group in groups.iter().copied().chain(checksum_groups) {
            text.push(char::from(BECH32_ALPHABET[usize::from(group)]));
        }
        text
    }

    fn encode(hrp: &str, bytes: &[u8]) -> String {
        encode_groups(hrp, &to_groups(bytes))
    }

    /// The data groups of a 62-character recipient: the 52 characters
    /// between `age1` and the 6-character checksum, as values.
    fn data_groups(recipient: &str) -> Vec<u8> {
        recipient[4..56]
            .bytes()
            .map(|byte| {
                let position = BECH32_ALPHABET.iter().position(|&c| c == byte).unwrap();
                u8::try_from(position).unwrap()
            })
            .collect()
    }

    /// The same key with a padding bit set, and the checksum recomputed: the
    /// last data group holds the key's last bit and then four zero bits, and
    /// this sets the lowest of those.
    fn with_padding_bit_set(recipient: &str) -> String {
        let mut groups = data_groups(recipient);
        *groups.last_mut().unwrap() |= 1;
        encode_groups("age", &groups)
    }

    /// `text` with its last checksum character swapped for another: lower
    /// case for a recipient, upper case for an identity, as age writes each.
    fn with_bad_checksum(text: &str) -> String {
        let (body, last) = text.split_at(text.len() - 1);
        let swapped = match last {
            "q" | "Q" => "p",
            _ => "q",
        };
        if text.starts_with(RECIPIENT_PREFIX) {
            format!("{body}{swapped}")
        } else {
            format!("{body}{}", swapped.to_uppercase())
        }
    }

    /// A fresh recipient string, from an identity generated with age's own
    /// code, not ours.
    fn generated_recipient() -> String {
        age::x25519::Identity::generate().to_public().to_string()
    }

    /// The two points of order 8 on Curve25519, from libsodium's
    /// `has_small_order` list, little-endian as X25519 reads them.
    const ORDER_8_POINTS: [[u8; 32]; 2] = [
        [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ],
        [
            0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
            0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
            0xd0, 0x9f, 0x11, 0x57,
        ],
    ];

    /// The seven small-order u values: 0, 1, the two order-8 points, p - 1,
    /// and p and p + 1 (which X25519 reduces to 0 and 1), where
    /// p = 2^255 - 19. Little-endian, bit 255 clear.
    fn small_order_u_values() -> [[u8; 32]; 7] {
        let mut one = [0; 32];
        one[0] = 1;
        let mut p = [0xff; 32];
        p[0] = 0xed;
        p[31] = 0x7f;
        let mut p_minus_1 = p;
        p_minus_1[0] = 0xec;
        let mut p_plus_1 = p;
        p_plus_1[0] = 0xee;
        [
            [0; 32],
            one,
            ORDER_8_POINTS[0],
            ORDER_8_POINTS[1],
            p_minus_1,
            p,
            p_plus_1,
        ]
    }

    /// Starts an age encryption to one unchecked recipient (age wraps the
    /// file key for each recipient straight away), and gives the panic's
    /// message if age panicked.
    fn age_encryptor_panics_on(recipient: &age::x25519::Recipient) -> Option<String> {
        // `catch_unwind` runs the closure and turns a panic inside it into an
        // `Err` holding the panic's payload, instead of failing the test. A
        // `panic!` with a literal message carries a `&'static str`.
        let result = panic::catch_unwind(|| {
            age::Encryptor::with_recipients(iter::once(recipient as &dyn age::Recipient)).is_ok()
        });
        result.err().map(|payload| {
            payload
                .downcast_ref::<&str>()
                .map(|message| (*message).to_owned())
                .unwrap_or_default()
        })
    }

    #[test]
    fn the_test_bech32_encoder_matches_bip_173() {
        // A valid string from BIP 173's test vectors. Its data part lists
        // the alphabet in value order, so this checks the alphabet too.
        let groups: Vec<u8> = (0..32).collect();
        assert_eq!(
            encode_groups("abcdef", &groups),
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw"
        );
        // And it spells a key exactly as age does.
        let recipient = generated_recipient();
        assert_eq!(encode_groups("age", &data_groups(&recipient)), recipient);
    }

    #[test]
    fn recipient_parse_accepts_generated_keys_and_writes_them_back() {
        for _ in 0..64 {
            let text = generated_recipient();
            let recipient: AgeRecipient = text.parse().unwrap();
            assert_eq!(recipient.to_string(), text);
            assert_eq!(AgeRecipient::try_from(text.clone()).unwrap(), recipient);

            // serde reads and writes the plain string.
            let json = serde_json::to_string(&recipient).unwrap();
            assert_eq!(json, format!("\"{text}\""));
            assert_eq!(
                serde_json::from_str::<AgeRecipient>(&json).unwrap(),
                recipient
            );
        }
    }

    #[test]
    fn recipient_parse_rejects_bad_forms() {
        let good = generated_recipient();
        let secret = DeviceIdentity::generate().to_secret_string();
        let secret = secret.expose_secret();

        // The first lower-case letter after `age1`, upper-cased.
        let (letter_at, _) = good
            .char_indices()
            .skip(4)
            .find(|(_, c)| c.is_ascii_lowercase())
            .unwrap();
        let mut mixed_case = good.clone();
        mixed_case[letter_at..=letter_at].make_ascii_uppercase();

        let mut inner_space = good.clone();
        inner_space.replace_range(30..31, " ");
        let mut inserted_space = good.clone();
        inserted_space.insert(30, ' ');

        let ten_kib = format!("age1{}", "q".repeat(10 * 1024 - 4));
        let bad_checksum = with_bad_checksum(&good);
        let padded = with_padding_bit_set(&good);

        // Look-alikes: a Cyrillic `а` for the `a` of `age1`, and a Cyrillic
        // `ԛ` (2 bytes each) in place of two ASCII characters, so the input is
        // still 62 bytes long.
        let cyrillic_prefix = format!("\u{430}ge1{}", &good[4..61]);
        let cyrillic_data = format!("{}\u{51b}{}", &good[..20], &good[22..]);

        let cases: Vec<(&str, String)> = vec![
            ("upper case", good.to_uppercase()),
            ("mixed case", mixed_case),
            ("leading space", format!(" {good}")),
            ("leading space, 62 bytes", format!(" {}", &good[..61])),
            ("trailing space", format!("{good} ")),
            ("trailing newline", format!("{good}\n")),
            ("inner space", inner_space),
            ("inserted space", inserted_space),
            ("tab", format!("{}\t", &good[..61])),
            ("empty", String::new()),
            ("61 characters", good[..61].to_owned()),
            ("63 characters", format!("{good}q")),
            ("10 KiB", ten_kib.clone()),
            ("plugin recipient", encode("age1yubikey", &[2; 33])),
            ("tag recipient", encode("age1tag", &[2; 33])),
            ("pq recipient", encode("age1pq", &[7; 1216])),
            ("secret key", secret.to_owned()),
            ("lower-case secret key", secret.to_lowercase()),
            ("ssh key", format!("ssh-ed25519 {} laptop", "A".repeat(68))),
            ("bad checksum", bad_checksum.clone()),
            ("31-byte payload", encode("age", &[9; 31])),
            ("33-byte payload", encode("age", &[9; 33])),
            ("non-zero padding bits", padded.clone()),
            ("Cyrillic prefix", cyrillic_prefix),
            ("Cyrillic data", cyrillic_data.clone()),
        ];
        for (name, input) in &cases {
            assert!(input.parse::<AgeRecipient>().is_err(), "{name}");
            let json = Value::String(input.clone());
            assert!(
                serde_json::from_value::<AgeRecipient>(json).is_err(),
                "{name}"
            );
        }

        // Which check refuses some of them, to show the order: length first,
        // before any decoding, then the form, then age's decoder, then the
        // canonical form.
        let reason = |input: &str| input.parse::<AgeRecipient>().err();
        assert_eq!(reason(&ten_kib), Some(RecipientError::Length));
        assert_eq!(reason(&good.to_uppercase()), Some(RecipientError::Form));
        assert_eq!(reason(&cyrillic_data), Some(RecipientError::Form));
        assert_eq!(reason(&bad_checksum), Some(RecipientError::Encoding));
        assert_eq!(reason(&padded), Some(RecipientError::NonCanonical));
        // age itself accepts the padded string, as the same key: only the
        // write-back check refuses it.
        let lenient = age::x25519::Recipient::from_str(&padded).unwrap();
        assert_eq!(lenient.to_string(), good);
        // age also accepts upper case, which the form check refuses.
        assert!(age::x25519::Recipient::from_str(&good.to_uppercase()).is_ok());
    }

    #[test]
    fn recipient_parse_rejects_low_order_points() {
        // The 14 encodings: each small-order u value with bit 255 clear and
        // set. X25519 ignores bit 255, so both name the same point.
        let encodings: Vec<String> = small_order_u_values()
            .into_iter()
            .flat_map(|u| {
                let mut high = u;
                high[31] |= 0x80;
                [encode("age", &u), encode("age", &high)]
            })
            .collect();
        let derived: HashSet<&str> = encodings.iter().map(String::as_str).collect();
        let listed: HashSet<&str> = LOW_ORDER_RECIPIENTS.into_iter().collect();
        assert_eq!(derived.len(), 14);
        assert_eq!(derived, listed);

        for encoding in &encodings {
            assert_eq!(
                encoding.parse::<AgeRecipient>(),
                Err(RecipientError::LowOrder),
                "{encoding}"
            );
            // Without the guard: age's parser accepts the string as written,
            // and its encryptor then panics on it. That is why the guard is
            // needed, and age panics only when the shared secret is all
            // zeros, which shows each entry really is a low-order point.
            let unchecked = age::x25519::Recipient::from_str(encoding).unwrap();
            assert_eq!(unchecked.to_string(), *encoding);
            let message = age_encryptor_panics_on(&unchecked);
            assert!(
                message
                    .as_deref()
                    .is_some_and(|message| message.contains("all-zero")),
                "{encoding}: {message:?}"
            );
        }

        // The control: a generated key encrypts without a panic.
        let real = age::x25519::Identity::generate().to_public();
        assert_eq!(age_encryptor_panics_on(&real), None);
    }

    #[test]
    fn identity_round_trips_and_rejects_bad_strings() {
        let identity = DeviceIdentity::generate();
        let secret = identity.to_secret_string();
        let restored = DeviceIdentity::from_secret(&secret).unwrap();
        assert_eq!(restored.recipient(), identity.recipient());
        // A second identity is a different key.
        assert_ne!(DeviceIdentity::generate().recipient(), identity.recipient());
        // `recipient()` builds its value without parsing; the strict parse
        // agrees with it.
        let recipient = identity.recipient().to_string();
        assert_eq!(recipient.parse::<AgeRecipient>(), Ok(identity.recipient()));

        let text = secret.expose_secret();
        // The last letter lower-cased, the rest left upper case. (The last
        // character may be a digit, which has no case.)
        let last_letter = text.rfind(|c: char| c.is_ascii_uppercase()).unwrap();
        let mut mixed_case = text.to_owned();
        mixed_case[last_letter..=last_letter].make_ascii_lowercase();

        let cases = [
            ("lower case", text.to_lowercase(), IdentityError::Prefix),
            ("a recipient", recipient, IdentityError::Length),
            (
                "73 characters",
                text[..73].to_owned(),
                IdentityError::Length,
            ),
            ("75 characters", format!("{text}Q"), IdentityError::Length),
            (
                "trailing newline",
                format!("{text}\n"),
                IdentityError::Length,
            ),
            ("empty", String::new(), IdentityError::Length),
            (
                "leading space",
                format!(" {}", &text[..73]),
                IdentityError::Prefix,
            ),
            ("mixed case", mixed_case, IdentityError::Encoding),
            (
                "bad checksum",
                with_bad_checksum(text),
                IdentityError::Encoding,
            ),
        ];
        for (name, input, expected) in cases {
            // `.err()` rather than `.unwrap_err()`: the latter would need
            // `DeviceIdentity: Debug`, which a secret type must not have.
            let result = DeviceIdentity::from_secret(&SecretString::from(input));
            assert_eq!(result.err(), Some(expected), "{name}");
        }
    }

    #[test]
    fn key_errors_never_echo_input() {
        const MARKER: &str = "sweepkymarker";
        let identity = DeviceIdentity::generate();
        let secret = identity.to_secret_string();
        let secret = secret.expose_secret();
        let good = identity.recipient().to_string();
        // Pads `age1` and the marker out to a recipient's 62 bytes.
        let filler = "q".repeat(AgeRecipient::LEN - RECIPIENT_PREFIX.len() - MARKER.len());

        // Each reaches a different check. The marker is all bech32
        // characters, so the first one gets as far as age's decoder.
        let recipient_inputs = [
            format!("age1{MARKER}{filler}"),
            format!("{MARKER}{good}"),
            format!("age1{}{filler}", MARKER.to_uppercase()),
            secret.to_owned(),
            with_padding_bit_set(&good),
            LOW_ORDER_RECIPIENTS[0].to_owned(),
        ];
        let identity_inputs = [
            secret.to_lowercase(),
            with_bad_checksum(secret),
            format!("{secret}{MARKER}"),
            format!(
                "{}{}",
                &secret[..IDENTITY_LEN - MARKER.len()],
                MARKER.to_uppercase()
            ),
        ];

        let mut outputs: Vec<(String, String)> = Vec::new();
        for input in recipient_inputs {
            let error = input.parse::<AgeRecipient>().unwrap_err();
            let wrapped = DeviceKeyError::from(error);
            for text in [
                error.to_string(),
                format!("{error:?}"),
                wrapped.to_string(),
                format!("{wrapped:?}"),
            ] {
                outputs.push((input.clone(), text));
            }
        }
        for input in identity_inputs {
            let error = DeviceIdentity::from_secret(&SecretString::from(input.clone()))
                .err()
                .unwrap();
            outputs.push((input.clone(), error.to_string()));
            outputs.push((input, format!("{error:?}")));
        }

        // The secret's data part: everything after its fixed prefix.
        let secret_data = &secret[IDENTITY_PREFIX.len()..];
        for (input, output) in &outputs {
            assert!(!output.contains(input.as_str()), "{output}");
            assert!(!output.to_lowercase().contains(MARKER), "{output}");
            assert!(!output.contains(secret_data), "{output}");
            assert!(!output.contains(&good[4..]), "{output}");
        }
    }

    #[test]
    fn secret_types_have_no_debug_display_serialize() {
        // Checked when the test compiles; there is nothing left to run.
        crate::crypto::assert_not_impl_any!(
            DeviceIdentity: std::fmt::Debug,
            std::fmt::Display,
            serde::Serialize,
            serde::de::DeserializeOwned,
            PartialEq,
            Clone,
        );
    }
}
