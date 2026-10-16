//! Wrapping a small local secret with a passphrase: [`wrap_with_passphrase`]
//! writes it as a binary age v1 file encrypted to one scrypt (passphrase)
//! recipient, and [`unwrap_with_passphrase`] opens such a file again.
//!
//! The CLI wraps the two secret files `login --passphrase-file …` writes
//! with it: a dedicated identity's key file and this install's device key
//! (02, "Device keys"). age does all of the cryptography here, through the
//! same pinned crate and default features as the rest of this module: its
//! own `age::scrypt::Recipient` and `age::scrypt::Identity` derive the key
//! from the passphrase and wrap the file key. No second key-derivation
//! crate, no armor, no plugin.
//!
//! What this module decides on top of age:
//!
//! - **How much work the passphrase costs.** scrypt's cost is set by its
//!   work factor `log_n`: `N = 2^log_n`, and one derivation takes
//!   `2^(log_n + 10)` bytes of memory and time in proportion. A
//!   [`WorkFactor`] holds a `log_n` from 1 to [`MAX_WORK_FACTOR`], checked
//!   when it is made, because age's `set_work_factor` panics on 0 or on 64
//!   and above.
//!   - Writing uses the fixed [`WRITE_WORK_FACTOR`], 18: 256 MiB and about
//!     a second on a current laptop. Fixed rather than calibrated: age's
//!     `Recipient::new` picks the factor that takes about a second on this
//!     machine, but does not say which one it picked, so a fast machine
//!     could write a file above the read cap below, which no Sweepky would
//!     then open.
//!   - Reading accepts at most [`MAX_WORK_FACTOR`], 20: 1 GiB, about four
//!     seconds. age checks a file's factor against this cap before it runs
//!     scrypt, so a file asking for more costs nothing. age's own docs warn
//!     that values above 22 let a malicious file take hours and tens of GiB.
//!   - A compile-time check keeps the write factor at or below the cap.
//! - **How much input it takes.** [`unwrap_with_passphrase`] refuses input
//!   over [`MAX_WRAPPED_BYTES`] before age parses a byte, and a plaintext
//!   over [`MAX_SECRET_BYTES`]; [`wrap_with_passphrase`] refuses a secret
//!   over that size, so whatever it writes reads back.
//! - **Where the plaintext lives.** Only in a [`Zeroizing`] buffer, made at
//!   its final size before reading begins, so no reallocation leaves an
//!   unwiped copy behind. age keeps a chunk buffer of its own while it
//!   encrypts, which it frees without wiping (as `seal` notes); that copy is
//!   outside this crate's control.
//! - **The errors.** [`PassphraseError`] holds no data, and age's own errors
//!   are matched by variant, never formatted: age builds its messages
//!   through a translation library that, in a debug build, reads its message
//!   files from disk (see `seal`).
//!
//! Each `age::scrypt::Recipient::new` and `age::scrypt::Identity::new` also
//! runs age's own short calibration: one scrypt at work factor 10, about a
//! millisecond in a release build. This module overrides what it picks, but
//! cannot skip it.

use std::io::{self, Read, Write};
use std::iter;

use age::secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

/// [`WRITE_WORK_FACTOR`]'s `log_n`.
const WRITE_LOG_N: u8 = 18;

/// [`MAX_WORK_FACTOR`]'s `log_n`, and so the largest a [`WorkFactor`] can
/// hold.
const MAX_LOG_N: u8 = 20;

/// The work factor above which age's docs (`Identity::set_max_work_factor`)
/// warn that a malicious file can cost hours and tens of GiB.
const AGE_WARNING_LOG_N: u8 = 22;

// Compile-time check (`const _` is evaluated while the crate compiles, so a
// failed `assert!` is a compile error, never a run-time panic): a file this
// crate writes is always within the cap it reads with, and the cap stays
// below age's warning.
const _: () = assert!(WRITE_LOG_N <= MAX_LOG_N && MAX_LOG_N <= AGE_WARNING_LOG_N);

/// The scrypt work factor [`wrap_with_passphrase`]'s callers write with: 18,
/// so `N = 2^18`, 256 MiB of memory and about a second of work on a current
/// laptop. P2a's choice, fixed rather than calibrated (see the module docs).
pub const WRITE_WORK_FACTOR: WorkFactor = WorkFactor(WRITE_LOG_N);

/// The largest scrypt work factor [`unwrap_with_passphrase`] accepts: 20, so
/// 1 GiB of memory and about four seconds of work. A file asking for more is
/// refused before any scrypt work. P2a's choice: room above
/// [`WRITE_WORK_FACTOR`] for a file wrapped by another age tool on a fast
/// machine, and below the 22 that age's docs warn about.
pub const MAX_WORK_FACTOR: WorkFactor = WorkFactor(MAX_LOG_N);

/// The longest secret [`wrap_with_passphrase`] wraps, and the longest
/// plaintext [`unwrap_with_passphrase`] hands back: 1 KiB. Sweepky's secret
/// files are an 85-byte identity file and a 74-byte age identity.
pub const MAX_SECRET_BYTES: usize = 1024;

/// The longest input [`unwrap_with_passphrase`] reads: 4 KiB, the CLI's read
/// cap for both secret files. Anything [`wrap_with_passphrase`] writes fits
/// with room to spare (a compile-time check below).
pub const MAX_WRAPPED_BYTES: usize = 4096;

/// What starts every binary age file: its version line's
/// `age-encryption.org/`. Neither plain format Sweepky stores (an identity
/// file starts `sweepky-identity/`, an age identity `AGE-SECRET-KEY-`) can
/// start this way.
const AGE_MAGIC: &[u8] = b"age-encryption.org/";

/// What starts an armored (text) age file. Sweepky never writes one, and
/// age's `armor` feature is not compiled in, so one is refused by name.
const ARMOR_BEGIN: &[u8] = b"-----BEGIN AGE ENCRYPTED FILE-----";

/// The length of 16 bytes in the header's unpadded base64: the scrypt salt.
const BASE64_16_BYTES: usize = 22;
/// The length of 32 bytes in the header's unpadded base64: the wrapped file
/// key with its tag, and the header's MAC.
const BASE64_32_BYTES: usize = 43;
/// The most digits a stanza's work factor is written with: two, since the
/// compile-time check above keeps [`MAX_LOG_N`] at most 22.
const LOG_N_MAX_DIGITS: usize = 2;
/// The payload's nonce, which comes before its first chunk.
const PAYLOAD_NONCE_BYTES: usize = 16;
/// The authentication tag at the end of each payload chunk.
const CHUNK_TAG_BYTES: usize = 16;

/// What a wrap adds to the secret's length, at most: 182 bytes. The header
/// (the version line; the stanza line `-> scrypt <salt> <log_n>` with at
/// most two digits of work factor, and its body line, the wrapped file key;
/// and the MAC line), then the payload's 16-byte nonce and the 16-byte tag
/// of its one chunk. A secret of at most [`MAX_SECRET_BYTES`] is one chunk,
/// since age's chunks are 64 KiB. A test checks a real wrap is exactly this
/// long. Each `.len()` of a literal is worked out at compile time.
const WRAP_OVERHEAD_BYTES: usize = "age-encryption.org/v1\n".len()
    + "-> scrypt ".len()
    + BASE64_16_BYTES
    + " ".len()
    + LOG_N_MAX_DIGITS
    + "\n".len()
    + BASE64_32_BYTES
    + "\n".len()
    + "--- ".len()
    + BASE64_32_BYTES
    + "\n".len()
    + PAYLOAD_NONCE_BYTES
    + CHUNK_TAG_BYTES;

// Compile-time check: the largest secret, wrapped, is within the read cap.
const _: () = assert!(MAX_SECRET_BYTES + WRAP_OVERHEAD_BYTES <= MAX_WRAPPED_BYTES);

/// Why a passphrase wrap or unwrap refused.
///
/// The variants hold no data, so an error can carry neither the passphrase
/// nor the secret nor any byte of the file. age's own errors are dropped
/// unread.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PassphraseError {
    /// A work factor outside 1 to [`MAX_WORK_FACTOR`].
    #[error("an scrypt work factor is from 1 to {MAX_LOG_N}")]
    WorkFactorOutOfRange,
    /// [`wrap_with_passphrase`] was given an empty passphrase, which would
    /// protect nothing.
    #[error("the passphrase is empty")]
    EmptyPassphrase,
    /// The secret to wrap, or the plaintext unwrapped, is over
    /// [`MAX_SECRET_BYTES`].
    #[error("a passphrase-wrapped secret is at most {MAX_SECRET_BYTES} bytes")]
    SecretTooLarge,
    /// The input is over [`MAX_WRAPPED_BYTES`]. Checked before anything else.
    #[error("a passphrase-wrapped file is at most {MAX_WRAPPED_BYTES} bytes")]
    TooLarge,
    /// An armored (text) age file. Sweepky reads binary age only.
    #[error("an armored age file; Sweepky reads binary age files only")]
    Armored,
    /// Not an age v1 file, or one whose header age refuses: a malformed
    /// line or stanza, an unknown version, input cut short in the header.
    #[error("not a valid age v1 file")]
    InvalidHeader,
    /// An age file, but not one encrypted to a passphrase alone: for
    /// example one encrypted to an X25519 key.
    #[error("an age file, but not one wrapped with a passphrase")]
    NotPassphraseWrapped,
    /// The file asks for an scrypt work factor above the cap, so it was
    /// refused before any scrypt work.
    #[error(
        "the file asks for more scrypt work than Sweepky does (a work factor above {MAX_LOG_N})"
    )]
    ExcessiveWork,
    /// The passphrase does not open the file (or the file's key stanza was
    /// altered, which looks the same).
    #[error("the passphrase does not open this file")]
    WrongPassphrase,
    /// The passphrase opened the file, but the header's MAC or the payload
    /// does not authenticate, or the payload is cut short: the file was
    /// altered or damaged.
    #[error("the wrapped file is damaged or was altered")]
    Corrupt,
    /// age itself refused to wrap. With one scrypt recipient, a checked work
    /// factor and output to memory this does not happen; it exists so that
    /// an unexpected failure is an `Err`, not a panic.
    #[error("age could not wrap the secret")]
    Age,
}

/// An scrypt work factor, `log_n` in `N = 2^log_n`: from 1 to
/// [`MAX_WORK_FACTOR`].
///
/// A `u8` newtype whose field is private, so the only ways to get one are
/// [`WorkFactor::new`], which checks the range, and the two constants. That
/// is what makes handing it to age's `set_work_factor`, which panics on 0 or
/// on 64 and above, safe: every value is in range by construction. It is a
/// public parameter, not a secret, so it is `Copy` and prints as it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorkFactor(u8);

impl WorkFactor {
    /// The work factor `log_n`, or [`PassphraseError::WorkFactorOutOfRange`]
    /// unless it is from 1 to [`MAX_WORK_FACTOR`].
    pub fn new(log_n: u8) -> Result<Self, PassphraseError> {
        if (1..=MAX_LOG_N).contains(&log_n) {
            Ok(Self(log_n))
        } else {
            Err(PassphraseError::WorkFactorOutOfRange)
        }
    }

    /// Its `log_n`.
    pub fn log_n(self) -> u8 {
        self.0
    }
}

/// Whether `bytes` start the way an age file does, binary or armored: how
/// the CLI tells a passphrase-wrapped secret file from a plain one. A file
/// that does goes to [`unwrap_with_passphrase`], which refuses any age file
/// that is not a binary one wrapped with a passphrase.
pub fn looks_wrapped(bytes: &[u8]) -> bool {
    bytes.starts_with(AGE_MAGIC) || bytes.starts_with(ARMOR_BEGIN)
}

/// Wraps `plaintext` with `passphrase`: binary age v1, encrypted to one
/// scrypt recipient at `work_factor`, with no armor.
///
/// The result holds a random salt and file key, so two wraps of the same
/// secret differ. It is safe to store where the secret was: without the
/// passphrase it reveals only the secret's length and the work factor. It
/// comes back in a plain `Vec`, since it is no longer a secret.
///
/// # Errors
///
/// [`PassphraseError::SecretTooLarge`] for a secret over
/// [`MAX_SECRET_BYTES`], [`PassphraseError::EmptyPassphrase`], and
/// [`PassphraseError::Age`] if age itself fails, which it does not with
/// these inputs.
pub fn wrap_with_passphrase(
    plaintext: &[u8],
    passphrase: &SecretString,
    work_factor: WorkFactor,
) -> Result<Vec<u8>, PassphraseError> {
    if plaintext.len() > MAX_SECRET_BYTES {
        return Err(PassphraseError::SecretTooLarge);
    }
    if passphrase.expose_secret().is_empty() {
        return Err(PassphraseError::EmptyPassphrase);
    }
    // age's recipient takes its own `SecretString`. `clone()` makes a second
    // copy of the passphrase, which is wiped when `recipient` is dropped at
    // the end of this function. `Recipient::new` calibrates a work factor,
    // which `set_work_factor` then replaces with the checked one: it panics
    // only on 0 or 64 and above, which no `WorkFactor` holds.
    let mut recipient = age::scrypt::Recipient::new(passphrase.clone());
    recipient.set_work_factor(work_factor.log_n());
    // age takes its recipients as trait objects: `as &dyn age::Recipient`
    // turns the borrowed scrypt recipient into one, and `iter::once` makes
    // the one-item list. A passphrase recipient must be a file's only one,
    // and here it is.
    let recipients = iter::once(&recipient as &dyn age::Recipient);
    // Each `map_err(|_| ...)` drops age's error without formatting it (see
    // the module docs).
    let encryptor =
        age::Encryptor::with_recipients(recipients).map_err(|_| PassphraseError::Age)?;
    write_wrapped(encryptor, plaintext).map_err(|_| PassphraseError::Age)
}

/// Runs `encryptor` over `plaintext` and returns the whole age file. Every
/// step fails only with an `io::Error`, so `?` passes it up and the caller
/// maps it in one place.
fn write_wrapped(encryptor: age::Encryptor, plaintext: &[u8]) -> io::Result<Vec<u8>> {
    // At its final size from the start: the file is the secret plus a fixed
    // overhead, so this `Vec` does not reallocate as age writes into it.
    let mut wrapped = Vec::with_capacity(plaintext.len() + WRAP_OVERHEAD_BYTES);
    // `wrap_output` writes the header and returns a writer that encrypts
    // what is written to it, borrowing `wrapped` until `finish`.
    let mut writer = encryptor.wrap_output(&mut wrapped)?;
    writer.write_all(plaintext)?;
    // `finish` writes the final chunk; without it the file would be cut
    // short.
    writer.finish()?;
    Ok(wrapped)
}

/// Opens a file [`wrap_with_passphrase`] wrote (or any binary age file
/// encrypted to a passphrase alone), with `passphrase`, accepting a work
/// factor of at most [`MAX_WORK_FACTOR`]. The plaintext comes back in a
/// buffer that wipes itself when dropped.
///
/// The input is checked in this order, each step bounding the work of the
/// next:
///
/// 1. its length, against [`MAX_WRAPPED_BYTES`], before a byte is parsed;
/// 2. not armored;
/// 3. age parses the header;
/// 4. the header holds exactly one stanza, a passphrase one, before any
///    scrypt work, so an X25519 file costs nothing;
/// 5. age checks the stanza's work factor against the cap, and only then
///    derives the key from the passphrase and opens the file key;
/// 6. the payload is read and authenticated into one buffer allocated up
///    front.
///
/// # Errors
///
/// [`PassphraseError::TooLarge`], [`PassphraseError::Armored`],
/// [`PassphraseError::InvalidHeader`],
/// [`PassphraseError::NotPassphraseWrapped`],
/// [`PassphraseError::ExcessiveWork`], [`PassphraseError::WrongPassphrase`],
/// [`PassphraseError::Corrupt`] or [`PassphraseError::SecretTooLarge`], in
/// the order above. None holds any data.
pub fn unwrap_with_passphrase(
    wrapped: &[u8],
    passphrase: &SecretString,
) -> Result<Zeroizing<Vec<u8>>, PassphraseError> {
    unwrap_with_cap(wrapped, passphrase, MAX_WORK_FACTOR)
}

/// [`unwrap_with_passphrase`] with the cap `max_work_factor` instead of
/// [`MAX_WORK_FACTOR`]. Private: callers outside get the production cap,
/// and the tests use a lower one to stay fast.
fn unwrap_with_cap(
    wrapped: &[u8],
    passphrase: &SecretString,
    max_work_factor: WorkFactor,
) -> Result<Zeroizing<Vec<u8>>, PassphraseError> {
    // 1 and 2. The length and the armor, before age reads a byte. The length
    // also keeps the payload under one 64 KiB chunk, which puts age's one
    // payload error built from its translated messages (an empty last chunk
    // after full ones) out of reach.
    if wrapped.len() > MAX_WRAPPED_BYTES {
        return Err(PassphraseError::TooLarge);
    }
    if wrapped.starts_with(ARMOR_BEGIN) {
        return Err(PassphraseError::Armored);
    }
    // 3. The header. `&[u8]` implements `BufRead`, so the buffered parser
    // reads it without copying the input.
    let decryptor =
        age::Decryptor::new_buffered(wrapped).map_err(|_| PassphraseError::InvalidHeader)?;
    // 4. One passphrase stanza and nothing else, checked on the parsed
    // header before the scrypt identity is even made.
    if !decryptor.is_scrypt() {
        return Err(PassphraseError::NotPassphraseWrapped);
    }
    // 5. The identity, capped. age compares the stanza's work factor with
    // the cap before it runs scrypt (`age::scrypt::Identity::unwrap_stanza`
    // at age 0.12.1), so a file over the cap costs no scrypt work. Like the
    // recipient above, it holds its own copy of the passphrase, wiped when it
    // is dropped.
    let mut identity = age::scrypt::Identity::new(passphrase.clone());
    identity.set_max_work_factor(max_work_factor.log_n());
    let identities = iter::once(&identity as &dyn age::Identity);
    let reader = decryptor.decrypt(identities).map_err(file_key_error)?;
    // 6. The payload. The plaintext is shorter than the file, so a buffer of
    // the file's length never fills, and one of `MAX_SECRET_BYTES + 1` fills
    // only when the plaintext is over the cap.
    read_secret(reader, wrapped.len().min(MAX_SECRET_BYTES + 1))
}

/// age's error from opening the file key, as ours. Matched on the variant
/// only; the value is dropped here, never formatted.
fn file_key_error(error: age::DecryptError) -> PassphraseError {
    match error {
        age::DecryptError::ExcessiveWork { .. } => PassphraseError::ExcessiveWork,
        // The key derived from the passphrase does not open the stanza's
        // wrapped file key.
        age::DecryptError::DecryptionFailed => PassphraseError::WrongPassphrase,
        // The file key opened, so the passphrase is right, but the header was
        // changed after it was written.
        age::DecryptError::InvalidMac => PassphraseError::Corrupt,
        // A malformed stanza, and every other variant. age's enum is
        // `#[non_exhaustive]`, so a match on it needs this catch-all arm.
        _ => PassphraseError::InvalidHeader,
    }
}

/// Reads the whole plaintext from age's decrypting reader into one buffer
/// of `capacity` bytes, allocated up front, as `seal`'s `decrypt` does.
fn read_secret(
    mut reader: impl Read,
    capacity: usize,
) -> Result<Zeroizing<Vec<u8>>, PassphraseError> {
    // `vec![0; n]` makes the buffer at its final size, zero-filled, and
    // `Zeroizing` wipes it whenever it is dropped, on an error return below
    // as much as after the caller is done. Reading into a slice of it never
    // grows it, so no reallocation leaves an unwiped copy behind.
    let mut buffer = Zeroizing::new(vec![0_u8; capacity]);
    let mut filled = 0;
    loop {
        // The unread part of the buffer; `get_mut` is `None` rather than a
        // panic if `filled` ever passed the end.
        let rest = buffer.get_mut(filled..).ok_or(PassphraseError::Corrupt)?;
        // A full buffer before the end of the file: the plaintext is over
        // the cap.
        if rest.is_empty() {
            return Err(PassphraseError::SecretTooLarge);
        }
        match reader.read(rest) {
            // The end, reached only after age has authenticated the last
            // chunk and found nothing after it.
            Ok(0) => break,
            Ok(read) => filled = filled.saturating_add(read),
            // age reports a chunk that does not authenticate, or a cut-short
            // payload, as an I/O error. Dropped unread.
            Err(_) => return Err(PassphraseError::Corrupt),
        }
    }
    // `truncate` shortens the `Vec` without moving its buffer; the whole
    // capacity is still wiped on drop.
    buffer.truncate(filled);
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::iter;

    use age::secrecy::{ExposeSecret, SecretString};
    use zeroize::Zeroizing;

    use super::{
        MAX_SECRET_BYTES, MAX_WORK_FACTOR, MAX_WRAPPED_BYTES, PassphraseError, WRAP_OVERHEAD_BYTES,
        WRITE_WORK_FACTOR, WorkFactor, looks_wrapped, unwrap_with_cap, unwrap_with_passphrase,
        wrap_with_passphrase,
    };

    /// A synthetic secret file's content. Not a key: the tests only need
    /// bytes to tell apart.
    const SECRET: &[u8] = b"sweepky-identity/v1\nsynthetic content, not a key\n";

    /// The passphrase most tests wrap with.
    const PASSPHRASE: &str = "synthetic correct horse battery";

    fn passphrase() -> SecretString {
        SecretString::from(PASSPHRASE)
    }

    /// A work factor of 10 (1 MiB of memory, milliseconds of work), so the
    /// tests stay fast. Production writes at 18.
    fn fast() -> WorkFactor {
        WorkFactor::new(10).expect("in range")
    }

    fn wrap(secret: &[u8], work_factor: WorkFactor) -> Vec<u8> {
        wrap_with_passphrase(secret, &passphrase(), work_factor).expect("wraps")
    }

    /// The error unwrapping `wrapped` with `passphrase` and `cap` gives.
    /// A `match` rather than `expect_err`, whose panic message would print
    /// the plaintext had the unwrap wrongly succeeded.
    fn unwrap_error(wrapped: &[u8], passphrase: &SecretString, cap: WorkFactor) -> PassphraseError {
        match unwrap_with_cap(wrapped, passphrase, cap) {
            Ok(_) => panic!("unwrapped, but should have been refused"),
            Err(error) => error,
        }
    }

    /// Whether `needle` appears anywhere in `haystack`.
    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    /// `wrapped` with the stanza's work factor, written ` 10\n` by age,
    /// replaced by `log_n`. The header's MAC no longer matches, but age
    /// checks the work factor before it derives a key, let alone checks the
    /// MAC.
    fn with_stanza_work_factor(wrapped: &[u8], log_n: &str) -> Vec<u8> {
        let at = wrapped
            .windows(4)
            .position(|window| window == b" 10\n")
            .expect("the stanza's work factor");
        let mut patched = wrapped[..at].to_vec();
        patched.extend_from_slice(format!(" {log_n}\n").as_bytes());
        patched.extend_from_slice(&wrapped[at + 4..]);
        patched
    }

    /// Standard base64 with padding, in 64-character lines, as age's armor
    /// writes its body. The crate has no base64 dependency, and a test
    /// should not add one for this.
    fn armor(bytes: &[u8]) -> Vec<u8> {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut body = String::new();
        for chunk in bytes.chunks(3) {
            let byte = |i: usize| u32::from(chunk.get(i).copied().unwrap_or(0));
            let group = (byte(0) << 16) | (byte(1) << 8) | byte(2);
            for i in 0..4 {
                if i <= chunk.len() {
                    body.push(char::from(
                        ALPHABET[((group >> (18 - 6 * i)) & 0x3f) as usize],
                    ));
                } else {
                    body.push('=');
                }
            }
        }
        let mut out = String::from("-----BEGIN AGE ENCRYPTED FILE-----\n");
        for line in body.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(line).expect("ASCII"));
            out.push('\n');
        }
        out.push_str("-----END AGE ENCRYPTED FILE-----\n");
        out.into_bytes()
    }

    /// A small age file encrypted to an X25519 key, made with age directly,
    /// because core's own `encrypt` pads to 64 KiB, past the size cap.
    fn x25519_file() -> Vec<u8> {
        let recipient = age::x25519::Identity::generate().to_public();
        let encryptor =
            age::Encryptor::with_recipients(iter::once(&recipient as &dyn age::Recipient))
                .expect("an encryptor");
        let mut file = Vec::new();
        let mut writer = encryptor.wrap_output(&mut file).expect("writes");
        writer.write_all(SECRET).expect("writes");
        writer.finish().expect("finishes");
        file
    }

    #[test]
    fn wrap_unwrap_round_trip() {
        let wrapped = wrap(SECRET, fast());
        // Binary age v1 with one scrypt stanza at the factor asked for, and
        // none of the secret in the clear.
        assert!(wrapped.starts_with(b"age-encryption.org/v1\n-> scrypt "));
        assert!(contains(&wrapped, b" 10\n"));
        assert!(!contains(&wrapped, b"sweepky-identity"));
        assert!(!contains(&wrapped, b"synthetic content"));
        // Exactly the overhead the size caps are worked out from: the header,
        // the nonce and one chunk's tag.
        assert_eq!(wrapped.len(), SECRET.len() + WRAP_OVERHEAD_BYTES);
        // The header tells a wrapped file from the plain one.
        assert!(looks_wrapped(&wrapped));
        assert!(!looks_wrapped(SECRET));

        // The plaintext comes back in a buffer that wipes itself: the type
        // annotation fails to compile if it ever stops being one.
        let plain: Zeroizing<Vec<u8>> =
            unwrap_with_cap(&wrapped, &passphrase(), fast()).expect("unwraps");
        assert_eq!(plain.as_slice(), SECRET);
        // At the production cap too.
        let plain = unwrap_with_passphrase(&wrapped, &passphrase()).expect("unwraps");
        assert_eq!(plain.as_slice(), SECRET);

        // A fresh salt and file key each time.
        assert_ne!(wrap(SECRET, fast()), wrapped);
    }

    #[test]
    fn largest_secret_round_trips_and_one_byte_more_is_refused() {
        // One byte more is refused before age is called.
        let largest = vec![b'x'; MAX_SECRET_BYTES];
        let wrapped = wrap(&largest, fast());
        assert!(wrapped.len() <= MAX_WRAPPED_BYTES);
        let plain = unwrap_with_passphrase(&wrapped, &passphrase()).expect("unwraps");
        assert_eq!(plain.as_slice(), largest.as_slice());
        assert_eq!(
            wrap_with_passphrase(&[b'x'; MAX_SECRET_BYTES + 1], &passphrase(), fast()).err(),
            Some(PassphraseError::SecretTooLarge)
        );
    }

    #[test]
    fn empty_passphrase_is_refused() {
        // An empty passphrase would protect nothing.
        assert_eq!(
            wrap_with_passphrase(SECRET, &SecretString::from(""), fast()).err(),
            Some(PassphraseError::EmptyPassphrase)
        );
    }

    #[test]
    fn wrong_passphrase_is_refused() {
        let wrapped = wrap(SECRET, fast());
        let wrong = SecretString::from("synthetic wrong guess");
        let error = unwrap_error(&wrapped, &wrong, fast());
        assert_eq!(error, PassphraseError::WrongPassphrase);
        // The error is fixed text: neither passphrase is in it.
        for shown in [error.to_string(), format!("{error:?}")] {
            assert!(!shown.contains(PASSPHRASE), "{shown}");
            assert!(!shown.contains(wrong.expose_secret()), "{shown}");
        }
    }

    #[test]
    fn altered_payload_is_corrupt() {
        // A byte of the payload changed: the right passphrase finds the file
        // key, and the payload then fails to authenticate.
        let mut altered = wrap(SECRET, fast());
        *altered.last_mut().expect("not empty") ^= 1;
        assert_eq!(
            unwrap_error(&altered, &passphrase(), fast()),
            PassphraseError::Corrupt
        );
    }

    #[test]
    fn work_factor_above_the_cap_is_refused_without_scrypt_work() {
        // Written at 11, read with a cap of 10: refused as too much work.
        let wrapped = wrap(SECRET, WorkFactor::new(11).expect("in range"));
        assert_eq!(
            unwrap_error(&wrapped, &passphrase(), fast()),
            PassphraseError::ExcessiveWork
        );
        // With a wrong passphrase too, which would be `WrongPassphrase` had
        // a key been derived: the cap is checked first.
        let wrong = SecretString::from("synthetic wrong guess");
        assert_eq!(
            unwrap_error(&wrapped, &wrong, fast()),
            PassphraseError::ExcessiveWork
        );

        // The production cap: a stanza asking for 21 (2 GiB of memory) or
        // for 40 (far more than any machine has) is refused at once by
        // `unwrap_with_passphrase`, before age runs scrypt at that factor.
        let wrapped = wrap(SECRET, fast());
        for log_n in ["21", "40"] {
            let hostile = with_stanza_work_factor(&wrapped, log_n);
            assert_eq!(
                unwrap_with_passphrase(&hostile, &passphrase()).err(),
                Some(PassphraseError::ExcessiveWork),
                "{log_n}"
            );
        }
    }

    #[test]
    fn production_work_factors_are_pinned() {
        // 18 is 256 MiB of memory and about a second of work; 20 is 1 GiB.
        assert_eq!(WRITE_WORK_FACTOR.log_n(), 18);
        assert_eq!(MAX_WORK_FACTOR.log_n(), 20);
        // What Sweepky writes it can always read, and the cap stays below
        // where age's own docs warn of hours of work and tens of GiB.
        assert!(WRITE_WORK_FACTOR <= MAX_WORK_FACTOR);
        assert!(MAX_WORK_FACTOR.log_n() <= 22);
        assert_eq!(
            WorkFactor::new(MAX_WORK_FACTOR.log_n()),
            Ok(MAX_WORK_FACTOR)
        );
    }

    #[test]
    fn work_factor_newtype_refuses_out_of_range() {
        // Every `u8`: 1 to 20 are accepted, and nothing else. 0 and 64 and
        // above would make age's `set_work_factor` panic; 21 to 63 are over
        // the read cap, so a file written with one could not be read back.
        for log_n in 0..=u8::MAX {
            let made = WorkFactor::new(log_n);
            if (1..=MAX_WORK_FACTOR.log_n()).contains(&log_n) {
                assert_eq!(made.map(WorkFactor::log_n), Ok(log_n));
            } else {
                assert_eq!(made, Err(PassphraseError::WorkFactorOutOfRange), "{log_n}");
            }
        }
    }

    #[test]
    fn non_scrypt_or_armored_age_files_are_refused() {
        // An age file, but encrypted to an X25519 key, not a passphrase.
        let x25519 = x25519_file();
        assert!(looks_wrapped(&x25519));
        assert_eq!(
            unwrap_error(&x25519, &passphrase(), fast()),
            PassphraseError::NotPassphraseWrapped
        );

        // The armored (text) form of a real wrapped file: refused by name,
        // since Sweepky writes and reads binary age only.
        let armored = armor(&wrap(SECRET, fast()));
        assert!(armored.len() <= MAX_WRAPPED_BYTES);
        assert!(looks_wrapped(&armored));
        assert_eq!(
            unwrap_error(&armored, &passphrase(), fast()),
            PassphraseError::Armored
        );
    }

    #[test]
    fn oversized_input_is_refused_before_parsing() {
        // A real wrapped file followed by enough bytes to pass the cap:
        // refused on its length before age parses anything.
        let mut oversized = wrap(SECRET, fast());
        oversized.resize(MAX_WRAPPED_BYTES + 1, b'\n');
        assert_eq!(
            unwrap_error(&oversized, &passphrase(), fast()),
            PassphraseError::TooLarge
        );
    }

    #[test]
    fn malformed_or_cut_short_input_is_refused() {
        // Not age at all, empty, or cut short in the header: not a valid
        // header. Cut short in the payload: corrupt.
        let wrapped = wrap(SECRET, fast());
        for not_age in [SECRET, b"", &wrapped[..40]] {
            assert_eq!(
                unwrap_error(not_age, &passphrase(), fast()),
                PassphraseError::InvalidHeader
            );
        }
        assert_eq!(
            unwrap_error(&wrapped[..wrapped.len() - 1], &passphrase(), fast()),
            PassphraseError::Corrupt
        );
    }

    #[test]
    fn errors_hold_no_data() {
        // One byte: no variant carries a payload, so no error can hold a
        // passphrase, a secret or a byte of the file.
        assert_eq!(std::mem::size_of::<PassphraseError>(), 1);

        let wrapped = wrap(SECRET, fast());
        let mut errors = vec![
            unwrap_error(
                &wrapped,
                &SecretString::from("synthetic wrong guess"),
                fast(),
            ),
            unwrap_error(SECRET, &passphrase(), fast()),
            unwrap_error(&x25519_file(), &passphrase(), fast()),
            unwrap_error(
                &wrap(SECRET, WorkFactor::new(11).expect("in range")),
                &passphrase(),
                fast(),
            ),
        ];
        errors.extend(wrap_with_passphrase(SECRET, &SecretString::from(""), fast()).err());
        errors.extend(WorkFactor::new(0).err());
        for error in errors {
            for shown in [error.to_string(), format!("{error:?}")] {
                assert!(!shown.contains(PASSPHRASE), "{shown}");
                assert!(!shown.contains("synthetic"), "{shown}");
                assert!(!shown.contains("sweepky-identity"), "{shown}");
            }
        }
    }
}
