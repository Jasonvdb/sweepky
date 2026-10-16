//! Sealing a padded package to its readers: [`encrypt`] writes binary age v1
//! to a list of [`AgeRecipient`]s, and [`decrypt`] opens it with one
//! [`DeviceIdentity`] into a [`Plaintext`].
//!
//! age does all the cryptography. This module decides what age is handed and
//! what it is allowed to cost:
//!
//! - **Who can read.** [`encrypt`] encrypts to exactly the recipients it is
//!   given (the owner's keys plus the sweeper's own, chosen by the CLI), each
//!   once. It never adds one, never adds a passphrase, and writes binary age,
//!   never the ASCII armor.
//! - **What a stranger's file can cost.** A sweep's `.age` file comes from
//!   whoever wrote it. [`decrypt`] checks its total length and the size of its
//!   header before age parses a byte, and stops reading a plaintext that
//!   passes [`MAX_PACKAGE_BYTES`].
//! - **Where the plaintext lives.** Only in buffers that are wiped when
//!   dropped and never grow, and only once all of it has been read and
//!   authenticated.
//!
//! **age's errors are matched, never printed.** age formats its error
//! messages through a translation library that loads its message files on
//! first use, and in a debug build reads them from age's source directory at
//! run time: file I/O, which this crate never does, and a panic if that
//! directory is gone. So this module maps age's errors to its own by variant
//! and drops them unread, and it refuses up front the one malformed payload
//! age would describe with such a message as it reads it (see [`decrypt`]).

use std::fmt;
use std::io::{self, Read, Write};
use std::iter;

use age::secrecy::ExposeSecret;
use zeroize::Zeroizing;

use super::keys::{AgeRecipient, DeviceIdentity};
use super::padding::PaddedPlaintext;
use crate::schema::MAX_PACKAGE_BYTES;

/// The most distinct recipients one sweep is encrypted to: 32.
///
/// The CLI passes the bounty owner's unrevoked keys plus the sweeper's own,
/// so its per-owner cap (P2b) must leave room for that one more. Each
/// recipient adds one stanza of about 100 bytes to the public header, and
/// one Diffie-Hellman for every reader who tries a key. P1b's choice; 02
/// asks only that the CLI caps how many it takes from one owner.
pub const MAX_RECIPIENTS: usize = 32;

/// The most header bytes [`decrypt`] lets age parse before the header's MAC
/// line: 8 KiB.
///
/// The MAC line is the line starting `---` that ends every age v1 header.
/// The newline that starts it must be at most this many bytes into the file;
/// if it is not, the file is a [`DecryptError::HeaderTooLarge`]. This bounds
/// what a stranger's header can make a reader do, in two ways:
///
/// - age 0.12.1's header reader re-parses the whole header from its start
///   each time it reads another line, so its work grows with the square of
///   the header's size. A header of the tiniest valid stanzas costs about
///   0.1 s in a release build at 8 KiB; at 64 KiB it cost 6 s (96 s in a
///   debug build), before any key was tried.
/// - age tries one Diffie-Hellman for each X25519 stanza, and 8 KiB holds
///   about 80 of them.
///
/// A header this crate writes is at most 3,396 bytes, even to
/// [`MAX_RECIPIENTS`] (a compile-time check below keeps it so), and the
/// largest in the C2SP CCTV vectors is 3,184. P1b's choice; 02 sets none.
pub const MAX_HEADER_BYTES: usize = 8 * 1024;

/// The most bytes [`decrypt`] accepts at all: 33,570,881.
///
/// It is the longest header the header check lets through, the payload's
/// 16-byte nonce, [`MAX_PACKAGE_BYTES`], and the 16-byte tag age adds to
/// each 64 KiB chunk of it. That header is [`MAX_HEADER_BYTES`] before the
/// MAC line, then the newline that starts the MAC line and the 48-byte MAC
/// line itself. So any file whose MAC line starts within `MAX_HEADER_BYTES`
/// and whose plaintext fits in `MAX_PACKAGE_BYTES` fits too. Longer input is
/// refused on its length alone; the CLI uses this as its download cap for
/// `.age` files (P2c).
pub const MAX_CIPHERTEXT_BYTES: usize = header_end(MAX_HEADER_BYTES)
    + AGE_NONCE_BYTES
    + MAX_PACKAGE_BYTES
    + AGE_TAG_BYTES * (MAX_PACKAGE_BYTES / AGE_CHUNK_BYTES);

/// age's payload chunk: 64 KiB of plaintext each.
const AGE_CHUNK_BYTES: usize = 64 * 1024;
/// The Poly1305 tag age appends to each chunk.
const AGE_TAG_BYTES: usize = 16;
/// The random nonce between age's header and its payload.
const AGE_NONCE_BYTES: usize = 16;
/// One full chunk as stored: its plaintext and its tag.
const AGE_ENCRYPTED_CHUNK_BYTES: usize = AGE_CHUNK_BYTES + AGE_TAG_BYTES;

/// What starts the header's MAC line: a newline, then `---`. Nothing before
/// the MAC line in a valid header can start a line with `---` (stanza lines
/// start `->`, body lines are base64), so the first match is that line.
const MAC_LINE_MARKER: &[u8] = b"\n---";
/// The length of 32 bytes in the header's unpadded base64: 43 characters.
/// The MAC, an X25519 stanza's ephemeral key and its wrapped file key are 32
/// bytes each.
const BASE64_32_BYTES: usize = 43;
// The two lengths below add up the parts of each line. `str::len` is a
// `const fn`, so a literal's `.len()` is worked out at compile time and names
// the text it counts instead of a bare number.
/// The MAC line itself, after the marker's newline: `--- `, the MAC, and a
/// newline.
const MAC_LINE_BYTES: usize = "--- ".len() + BASE64_32_BYTES + 1;

/// Where a header ends, given `mac_line`, the index of the newline that
/// starts its MAC line: just past that newline and the MAC line after it.
/// [`MAX_CIPHERTEXT_BYTES`] and [`ends_in_empty_chunk`] both use it, so the
/// cap and the check that reads a real header cannot disagree on where it
/// ends. Being a `const fn` is what lets a constant call it.
const fn header_end(mac_line: usize) -> usize {
    mac_line + 1 + MAC_LINE_BYTES
}

/// The longest header [`encrypt`] can write: the first line, one X25519
/// stanza per recipient (`-> X25519 `, the ephemeral key and a newline, then
/// the wrapped file key and a newline), age's grease stanza (at most 55 bytes
/// of first line and 135 of body), and the MAC line.
const LONGEST_OWN_HEADER_BYTES: usize = "age-encryption.org/v1\n".len()
    + MAX_RECIPIENTS * ("-> X25519 ".len() + BASE64_32_BYTES + 1 + BASE64_32_BYTES + 1)
    + (55 + 135)
    + MAC_LINE_BYTES;

// Compile-time check (`const _` is evaluated while the crate compiles, so a
// failed `assert!` is a compile error, never a run-time panic): every file
// `encrypt` writes passes `decrypt`'s header check, so raising
// `MAX_RECIPIENTS` cannot quietly make sweeps unreadable.
const _: () = assert!(LONGEST_OWN_HEADER_BYTES <= MAX_HEADER_BYTES);

/// Why [`encrypt`] refused.
///
/// The variants hold no data, so an error can carry neither the package nor
/// a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EncryptError {
    /// The recipient list is empty: nobody could open the sweep.
    #[error("a sweep must be encrypted to at least one recipient")]
    NoRecipients,
    /// More than [`MAX_RECIPIENTS`] distinct recipients.
    #[error("a sweep is encrypted to at most {MAX_RECIPIENTS} recipients")]
    TooManyRecipients,
    /// age itself refused. With recipients that passed [`AgeRecipient`]'s
    /// strict parse and output written to memory this does not happen; it
    /// exists so that an unexpected failure is an `Err`, not a panic.
    #[error("age could not encrypt the package")]
    Age,
}

/// Why [`decrypt`] refused. Each refusal means no plaintext at all.
///
/// The variants hold no data, so an error can carry neither the plaintext
/// nor a key, nor any of a stranger's bytes. The four in the middle are age's
/// own failures, mapped by stage and matched on age's variant only, and line
/// up one to one with the C2SP CCTV test vectors' expected results: "header
/// failure", "no match", "HMAC failure" and "payload failure".
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecryptError {
    /// The input is longer than [`MAX_CIPHERTEXT_BYTES`]. Checked before
    /// anything else.
    #[error("the encrypted sweep is larger than the size limit")]
    TooLarge,
    /// The input is longer than [`MAX_HEADER_BYTES`] and its header's MAC
    /// line does not start within that span, so age was not given it.
    #[error("the encrypted sweep's header is larger than the size limit")]
    HeaderTooLarge,
    /// Not an age v1 file, or a header age refuses: a malformed line or
    /// stanza, an unknown version, a malformed X25519 stanza, input that ends
    /// inside the header or its nonce.
    #[error("not a valid age v1 header")]
    InvalidHeader,
    /// No stanza in the header opens with this identity: the sweep was not
    /// encrypted to this key, for example because the key was published
    /// after the sweep was uploaded.
    #[error("the sweep was not encrypted to this key")]
    NoMatchingKey,
    /// A stanza opened, but the header's MAC is wrong: the header was
    /// changed after it was written.
    #[error("the header's MAC does not match: the header was altered")]
    InvalidMac,
    /// The payload does not authenticate, is cut short, or has bytes after
    /// its final chunk.
    #[error("the encrypted payload is corrupt or truncated")]
    InvalidPayload,
    /// The plaintext is longer than [`MAX_PACKAGE_BYTES`]. Reading stops at
    /// that point and what was read is wiped.
    #[error("the decrypted package is larger than the 32 MiB limit")]
    PlaintextTooLarge,
}

/// A decrypted sweep package: the padded bytes exactly as they were
/// encrypted, trailing spaces included. The package is JSON, which reads
/// those spaces as whitespace, so nothing needs to strip them.
///
/// Like [`PaddedPlaintext`], it is sealed content:
///
/// - The bytes live in a [`Zeroizing`] buffer, wiped when the value is
///   dropped, which was allocated once before reading began and never grew,
///   so no unwiped copy was left behind by a reallocation.
/// - [`Debug`](fmt::Debug) prints the length only; there is no `Display`,
///   `Serialize`, `Deserialize` or `Clone` (checked at compile time).
///   Reading the bytes takes an explicit
///   [`expose_secret`](ExposeSecret::expose_secret).
///
/// age decrypts each 64 KiB chunk into a buffer of its own before it is
/// copied in here. age wipes that buffer when it moves on, but building it
/// shrinks a `Vec` into a boxed slice, which may move the chunk and free the
/// first copy unwiped. That copy is outside this crate's control.
pub struct Plaintext(Zeroizing<Vec<u8>>);

impl Plaintext {
    /// The plaintext's length in bytes. Not a secret: the ciphertext's
    /// length shows it to anyone.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the plaintext is empty. A package this crate padded never is;
    /// another age file can be.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The decrypted bytes.
impl ExposeSecret<[u8]> for Plaintext {
    fn expose_secret(&self) -> &[u8] {
        &self.0
    }
}

/// Prints `Plaintext { len: 65536, .. }`: the length, never a byte of the
/// content.
impl fmt::Debug for Plaintext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Plaintext")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

/// Encrypts a padded package to `recipients`, as binary age v1.
///
/// Each distinct recipient gets one X25519 stanza (a recipient listed twice
/// is encrypted to once), and nothing else is added: no other recipient, no
/// passphrase. age adds one random "grease" stanza that no key opens, so the
/// header's length varies by up to about 190 bytes between encryptions; the
/// payload after it is the package's length plus 16 bytes of nonce and 16
/// bytes per 64 KiB chunk, so it is set by the padding bucket alone.
///
/// Only a [`PaddedPlaintext`] is accepted, so an unpadded package cannot be
/// encrypted. The ciphertext is public, so it comes back in a plain `Vec`.
///
/// # Errors
///
/// [`EncryptError::NoRecipients`] for an empty list,
/// [`EncryptError::TooManyRecipients`] for more than [`MAX_RECIPIENTS`]
/// distinct ones, and [`EncryptError::Age`] if age itself fails, which it
/// does not with these inputs.
pub fn encrypt(
    plaintext: &PaddedPlaintext,
    recipients: &[AgeRecipient],
) -> Result<Vec<u8>, EncryptError> {
    let recipients = distinct_recipients(recipients)?;
    // age takes any kind of recipient through its `Recipient` trait, as
    // trait objects: `as &dyn age::Recipient` turns each borrowed X25519 key
    // into one. Nothing else is in the list, so no passphrase (scrypt)
    // recipient can be mixed in. Every key passed `AgeRecipient`'s strict
    // parse, which refuses the small-order points age's encryptor panics on.
    let age_recipients = recipients
        .iter()
        .map(|recipient| recipient.as_age() as &dyn age::Recipient);
    // Each `map_err(|_| ...)` drops age's error without formatting it (see
    // the module docs).
    let encryptor =
        age::Encryptor::with_recipients(age_recipients).map_err(|_| EncryptError::Age)?;
    write_ciphertext(encryptor, plaintext.expose_secret()).map_err(|_| EncryptError::Age)
}

/// `recipients` without repeats, in their first order, checked against the
/// limits. Two recipients are the same when their `age1…` strings are (see
/// [`AgeRecipient`]).
fn distinct_recipients(recipients: &[AgeRecipient]) -> Result<Vec<&AgeRecipient>, EncryptError> {
    if recipients.is_empty() {
        return Err(EncryptError::NoRecipients);
    }
    let mut distinct: Vec<&AgeRecipient> = Vec::new();
    for recipient in recipients {
        // At most `MAX_RECIPIENTS` comparisons per entry, so a long list
        // cannot make this quadratic.
        if distinct.contains(&recipient) {
            continue;
        }
        if distinct.len() == MAX_RECIPIENTS {
            return Err(EncryptError::TooManyRecipients);
        }
        distinct.push(recipient);
    }
    Ok(distinct)
}

/// Runs `encryptor` over `plaintext` and returns the whole age file. Each
/// step can fail only with an `io::Error`, so `?` passes it up unchanged and
/// [`encrypt`] maps every failure to its own error in one place.
fn write_ciphertext(encryptor: age::Encryptor, plaintext: &[u8]) -> io::Result<Vec<u8>> {
    // The ciphertext is public, so this `Vec` may grow and reallocate freely.
    let mut ciphertext = Vec::new();
    // `wrap_output` writes the header and returns a writer that encrypts what
    // is written to it, borrowing `ciphertext` until `finish` hands it back.
    let mut writer = encryptor.wrap_output(&mut ciphertext)?;
    writer.write_all(plaintext)?;
    // `finish` writes the final chunk; without it the file would be
    // truncated.
    writer.finish()?;
    Ok(ciphertext)
}

/// Opens an age file with one identity and returns the whole plaintext.
///
/// The input is a stranger's bytes, so the checks run in this order, each
/// bounding the work of the next:
///
/// 1. The length: over [`MAX_CIPHERTEXT_BYTES`] is
///    [`DecryptError::TooLarge`], before a byte is read.
/// 2. The header's size: only the first [`MAX_HEADER_BYTES`] + 4 bytes are
///    searched for the start of the MAC line (`\n---`). An input longer than
///    `MAX_HEADER_BYTES` without it there is [`DecryptError::HeaderTooLarge`].
///    A shorter input without it goes on to age, which refuses it as
///    [`DecryptError::InvalidHeader`].
/// 3. age parses the header: any failure is
///    [`DecryptError::InvalidHeader`].
/// 4. age looks for a stanza this identity opens. It is given the X25519
///    identity alone, so a passphrase (scrypt) stanza in a hostile header
///    costs no scrypt work. No stanza opens: [`DecryptError::NoMatchingKey`];
///    the header's MAC is wrong: [`DecryptError::InvalidMac`]; a malformed
///    X25519 stanza or anything else: [`DecryptError::InvalidHeader`].
/// 5. The payload is read and authenticated chunk by chunk into one buffer.
///    A chunk that does not authenticate, a cut-short payload, or bytes
///    after the final chunk: [`DecryptError::InvalidPayload`]. More than
///    [`MAX_PACKAGE_BYTES`] of plaintext: [`DecryptError::PlaintextTooLarge`].
///    A payload that would end in an empty chunk after full ones is refused
///    as `InvalidPayload` before reading starts: it can never be valid, and
///    it is the one failure age would describe through its translated
///    messages (see the module docs).
///
/// All or nothing: the plaintext comes back only once every chunk has
/// authenticated and the end of the file has been reached. On any error,
/// whatever had been decrypted is wiped and dropped.
///
/// # Errors
///
/// One [`DecryptError`] per failure above. Its variants hold no data.
pub fn decrypt(ciphertext: &[u8], identity: &DeviceIdentity) -> Result<Plaintext, DecryptError> {
    // 1 and 2. The length and the header's size, before age reads a byte.
    let mac_line = check_size_caps(ciphertext)?;
    // 3. age parses the header. `&[u8]` implements `BufRead`, so the
    // buffered parser reads it a line at a time without copying the input.
    let decryptor =
        age::Decryptor::new_buffered(ciphertext).map_err(|_| DecryptError::InvalidHeader)?;
    // 4. The file key, with this one identity. `iter::once` makes the
    // one-item list of identities age asks for.
    let identities = iter::once(identity.as_age() as &dyn age::Identity);
    let reader = decryptor.decrypt(identities).map_err(file_key_error)?;
    // 5. The payload. Once age has parsed the header, the MAC line was found
    // in step 2, because a valid header always ends with one.
    if mac_line.is_some_and(|at| ends_in_empty_chunk(ciphertext.len(), at)) {
        return Err(DecryptError::InvalidPayload);
    }
    // The plaintext is always shorter than the file, so a buffer of the
    // file's length never fills, and one of `MAX_PACKAGE_BYTES + 1` fills
    // only when the plaintext is over the cap.
    read_plaintext(reader, ciphertext.len().min(MAX_PACKAGE_BYTES + 1))
}

/// Steps 1 and 2 of [`decrypt`]: [`DecryptError::TooLarge`] for input over
/// [`MAX_CIPHERTEXT_BYTES`], then [`DecryptError::HeaderTooLarge`] for input
/// over [`MAX_HEADER_BYTES`] whose MAC line does not start within that span.
/// Otherwise, where the MAC line starts, if it was found.
fn check_size_caps(ciphertext: &[u8]) -> Result<Option<usize>, DecryptError> {
    if ciphertext.len() > MAX_CIPHERTEXT_BYTES {
        return Err(DecryptError::TooLarge);
    }
    let mac_line = find_mac_line(ciphertext);
    if mac_line.is_none() && ciphertext.len() > MAX_HEADER_BYTES {
        return Err(DecryptError::HeaderTooLarge);
    }
    Ok(mac_line)
}

/// Where the header's MAC line starts: the index of the newline in the first
/// `\n---` among the first [`MAX_HEADER_BYTES`] + 4 bytes, so the newline is
/// at most `MAX_HEADER_BYTES` bytes in.
fn find_mac_line(ciphertext: &[u8]) -> Option<usize> {
    // `.get(..n)` is `None` when the input is shorter than `n`, and then the
    // whole input is the span. `windows(4)` yields every 4-byte run in turn
    // (none at all for a shorter span), so neither can index out of bounds.
    let span = ciphertext
        .get(..MAX_HEADER_BYTES + MAC_LINE_MARKER.len())
        .unwrap_or(ciphertext);
    span.windows(MAC_LINE_MARKER.len())
        .position(|window| window == MAC_LINE_MARKER)
}

/// age's error from finding the file key, as ours. Matched on the variant
/// only; the value is dropped here, never formatted (see the module docs).
fn file_key_error(error: age::DecryptError) -> DecryptError {
    match error {
        age::DecryptError::NoMatchingKeys | age::DecryptError::DecryptionFailed => {
            DecryptError::NoMatchingKey
        }
        age::DecryptError::InvalidMac => DecryptError::InvalidMac,
        // `InvalidHeader` itself and every other variant. age's enum is
        // `#[non_exhaustive]`, so a match on it needs this catch-all arm, and
        // a variant a later age adds lands here too.
        _ => DecryptError::InvalidHeader,
    }
}

/// Whether a file whose MAC line starts at `mac_line` has a payload of one
/// or more full chunks followed by a chunk with no plaintext (a lone 16-byte
/// tag).
///
/// Such a payload is never valid: either a chunk fails to authenticate,
/// bytes follow the final chunk, or the final chunk is empty after data,
/// which age refuses with an error message it builds through its
/// translations as it reads (see the module docs). Only a file's writer can
/// make the last case, since it takes the file key, but a stranger's sweep
/// on an open bounty is written by the stranger.
fn ends_in_empty_chunk(ciphertext_len: usize, mac_line: usize) -> bool {
    // `mac_line` is at most `MAX_HEADER_BYTES`, so this cannot overflow.
    let payload_start = header_end(mac_line) + AGE_NONCE_BYTES;
    // `checked_sub` is `None` instead of wrapping below zero.
    let Some(payload_len) = ciphertext_len.checked_sub(payload_start) else {
        return false;
    };
    payload_len > AGE_TAG_BYTES
        && (payload_len - AGE_TAG_BYTES).is_multiple_of(AGE_ENCRYPTED_CHUNK_BYTES)
}

/// Reads the whole plaintext from age's decrypting reader into one buffer
/// of `capacity` bytes, allocated up front.
fn read_plaintext(mut reader: impl Read, capacity: usize) -> Result<Plaintext, DecryptError> {
    // `vec![0; n]` makes the buffer at its final size, zero-filled, and
    // `Zeroizing` wipes it whenever it is dropped: on an error return below
    // as much as after the caller is done. Reading into a slice of it never
    // grows it, so no reallocation leaves an unwiped copy behind. (The
    // standard `read_to_end` grows its `Vec` as it goes, so it is not used.)
    let mut buffer = Zeroizing::new(vec![0_u8; capacity]);
    let mut filled = 0;
    loop {
        // The unread part of the buffer. `get_mut` is `None` rather than a
        // panic if `filled` ever passed the end, which a reader keeping to
        // `Read`'s contract (never more than the slice it was given) cannot
        // make happen.
        let rest = buffer
            .get_mut(filled..)
            .ok_or(DecryptError::InvalidPayload)?;
        // A full buffer with the file not yet at its end: the plaintext is
        // over the cap. Its bytes are wiped as `buffer` drops.
        if rest.is_empty() {
            return Err(DecryptError::PlaintextTooLarge);
        }
        match reader.read(rest) {
            // The end of the file, reached only after age has authenticated
            // the final chunk and found nothing after it.
            Ok(0) => break,
            Ok(read) => filled = filled.saturating_add(read),
            // age reports a bad chunk, a truncation or trailing bytes as an
            // I/O error. It is dropped unread, like every age error here.
            Err(_) => return Err(DecryptError::InvalidPayload),
        }
    }
    // `truncate` shortens the `Vec` without moving or freeing its buffer;
    // the unused tail is zeros, and the whole capacity is wiped on drop.
    buffer.truncate(filled);
    Ok(Plaintext(buffer))
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use age::secrecy::ExposeSecret;

    use super::{
        DecryptError, EncryptError, MAX_CIPHERTEXT_BYTES, MAX_HEADER_BYTES, MAX_RECIPIENTS,
        Plaintext, check_size_caps, decrypt, encrypt,
    };
    use crate::crypto::keys::{AgeRecipient, DeviceIdentity};
    use crate::crypto::padding::{PaddedPlaintext, PaddingError};
    use crate::schema::MAX_PACKAGE_BYTES;

    /// age's chunk size, which is also the padding bucket: 64 KiB, written
    /// out so the tests do not lean on the modules' own constants.
    const CHUNK: usize = 65_536;

    /// The first line of every binary age v1 file.
    const MAGIC: &[u8] = b"age-encryption.org/v1\n";

    fn recipients(identities: &[DeviceIdentity]) -> Vec<AgeRecipient> {
        identities.iter().map(DeviceIdentity::recipient).collect()
    }

    fn identities(count: usize) -> Vec<DeviceIdentity> {
        (0..count).map(|_| DeviceIdentity::generate()).collect()
    }

    fn pad(package: &[u8]) -> PaddedPlaintext {
        PaddedPlaintext::pad(package).unwrap()
    }

    /// The header's length, read from the ciphertext: up to and including the
    /// newline that ends the first line starting with `---`, the MAC line.
    /// age adds a random "grease" stanza to every header, so the length
    /// differs from one encryption to the next and must be read, not
    /// computed.
    fn header_len(ciphertext: &[u8]) -> usize {
        let marker = ciphertext
            .windows(4)
            .position(|window| window == b"\n---")
            .unwrap();
        let mac_line = &ciphertext[marker + 1..];
        let newline = mac_line.iter().position(|&byte| byte == b'\n').unwrap();
        marker + 1 + newline + 1
    }

    /// The header's stanzas whose first line starts with `-> <tag> `.
    fn stanzas_tagged(ciphertext: &[u8], tag: &str) -> usize {
        let header = &ciphertext[..header_len(ciphertext)];
        let needle = format!("\n-> {tag} ");
        header
            .windows(needle.len())
            .filter(|window| *window == needle.as_bytes())
            .count()
    }

    /// Deterministic noise for the "random input" cases: xorshift64, seeded,
    /// so a failure reproduces. Not for anything but tests.
    fn noise(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state.to_le_bytes()[0]
            })
            .collect()
    }

    #[test]
    fn owner_keys_and_sweeper_each_decrypt() {
        // Two owner installs and the sweeper's own key, as `submit` passes them.
        let readers = identities(3);
        let padded = pad(br#"{"schemaVersion":1,"manifest":{},"findings":{}}"#);
        let ciphertext = encrypt(&padded, &recipients(&readers)).unwrap();

        // Binary age v1, not armored, with one X25519 stanza per recipient
        // and no passphrase stanza mixed in.
        assert!(ciphertext.starts_with(MAGIC));
        assert_eq!(stanzas_tagged(&ciphertext, "X25519"), 3);
        assert_eq!(stanzas_tagged(&ciphertext, "scrypt"), 0);

        for reader in &readers {
            let opened = decrypt(&ciphertext, reader).unwrap();
            assert_eq!(opened.expose_secret(), padded.expose_secret());
            assert_eq!(opened.len(), padded.len());
        }
    }

    #[test]
    fn a_recipient_added_after_encryption_cannot_decrypt() {
        let owner = DeviceIdentity::generate();
        let padded = pad(b"{}");
        let ciphertext = encrypt(&padded, &[owner.recipient()]).unwrap();

        // A key the owner publishes later opens only later sweeps.
        let later = DeviceIdentity::generate();
        assert_eq!(
            decrypt(&ciphertext, &later).err(),
            Some(DecryptError::NoMatchingKey)
        );
        // The key it was encrypted to still opens it.
        let opened = decrypt(&ciphertext, &owner).unwrap();
        assert_eq!(opened.expose_secret(), padded.expose_secret());
    }

    #[test]
    fn ciphertext_length_lands_on_the_bucket() {
        let lengths = [1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK - 5];
        for readers in [identities(1), identities(3)] {
            let recipients = recipients(&readers);
            for len in lengths {
                let package = vec![b'x'; len];
                let padded = pad(&package);
                // The next 64 KiB multiple.
                let bucket = len.div_ceil(CHUNK) * CHUNK;
                assert_eq!(padded.len(), bucket, "{len}");

                let ciphertext = encrypt(&padded, &recipients).unwrap();
                // Header, the 16-byte payload nonce, the padded package, and
                // one 16-byte tag per 64 KiB chunk of it. The bucket alone
                // sets everything after the header.
                assert_eq!(
                    ciphertext.len(),
                    header_len(&ciphertext) + 16 + bucket + 16 * (bucket / CHUNK),
                    "{len} bytes to {} recipients",
                    recipients.len()
                );
                let opened = decrypt(&ciphertext, &readers[0]).unwrap();
                assert_eq!(&opened.expose_secret()[..len], &package[..]);
            }

            // Two packages in the same bucket: their payload sections (all
            // after the header) are the same length.
            let payload_len = |len: usize| {
                let ciphertext = encrypt(&pad(&vec![b'y'; len]), &recipients).unwrap();
                ciphertext.len() - header_len(&ciphertext)
            };
            assert_eq!(payload_len(1), payload_len(CHUNK - 1));
            assert_eq!(payload_len(2 * CHUNK + 1), payload_len(3 * CHUNK - 5));
        }
    }

    #[test]
    fn encrypt_checks_its_recipient_list() {
        let padded = pad(b"{}");
        assert_eq!(
            encrypt(&padded, &[]).err(),
            Some(EncryptError::NoRecipients)
        );

        let readers = identities(MAX_RECIPIENTS + 1);
        let all = recipients(&readers);
        assert_eq!(
            encrypt(&padded, &all).err(),
            Some(EncryptError::TooManyRecipients)
        );

        // Exactly the cap works, and the last of them can read it.
        let at_cap = &all[..MAX_RECIPIENTS];
        let ciphertext = encrypt(&padded, at_cap).unwrap();
        assert_eq!(stanzas_tagged(&ciphertext, "X25519"), MAX_RECIPIENTS);
        assert!(decrypt(&ciphertext, &readers[MAX_RECIPIENTS - 1]).is_ok());

        // The cap counts distinct recipients: the cap plus a repeat of one of
        // them is fine, as when a sweeper's own key is also the owner's.
        let mut with_repeat = at_cap.to_vec();
        with_repeat.push(at_cap[0].clone());
        let ciphertext = encrypt(&padded, &with_repeat).unwrap();
        assert_eq!(stanzas_tagged(&ciphertext, "X25519"), MAX_RECIPIENTS);

        // A duplicated recipient is encrypted to once.
        let reader = &readers[0];
        let twice = [reader.recipient(), reader.recipient()];
        let ciphertext = encrypt(&padded, &twice).unwrap();
        assert_eq!(stanzas_tagged(&ciphertext, "X25519"), 1);
        assert!(decrypt(&ciphertext, reader).is_ok());
    }

    #[test]
    fn decrypt_refuses_oversized_input_before_parsing() {
        let reader = DeviceIdentity::generate();
        let ciphertext = encrypt(&pad(b"{}"), &[reader.recipient()]).unwrap();

        // One byte over the cap: refused on its length, even with a real
        // header in front.
        let mut too_large = ciphertext.clone();
        too_large.resize(MAX_CIPHERTEXT_BYTES + 1, 0);
        assert_eq!(
            decrypt(&too_large, &reader).err(),
            Some(DecryptError::TooLarge)
        );

        // At the cap, a header that never reaches its MAC line: tiny stanzas
        // with empty bodies, which age's parser would re-read line after
        // line. Only the first MAX_HEADER_BYTES + 4 bytes are looked at.
        let stanzas = b"-> a\n\n".repeat(MAX_CIPHERTEXT_BYTES / 6);
        let mut endless = MAGIC.to_vec();
        endless.extend_from_slice(&stanzas);
        endless.truncate(MAX_CIPHERTEXT_BYTES);
        let started = Instant::now();
        assert_eq!(
            decrypt(&endless, &reader).err(),
            Some(DecryptError::HeaderTooLarge)
        );
        assert!(started.elapsed() < Duration::from_secs(1));

        // The marker's newline may sit at index MAX_HEADER_BYTES and no
        // further: there age gets the input (and refuses it, since it is no
        // header); one byte later it is too large.
        for (filler, expected) in [
            (MAX_HEADER_BYTES, DecryptError::InvalidHeader),
            (MAX_HEADER_BYTES + 1, DecryptError::HeaderTooLarge),
        ] {
            let mut input = vec![b'a'; filler];
            input.extend_from_slice(b"\n--- ");
            assert_eq!(decrypt(&input, &reader).err(), Some(expected), "{filler}");
        }

        // Short inputs without the marker are age's to refuse: not a header,
        // rather than too large a one.
        let one_over = vec![b'a'; MAX_HEADER_BYTES + 1];
        let at_limit = vec![b'a'; MAX_HEADER_BYTES];
        assert_eq!(
            decrypt(&one_over, &reader).err(),
            Some(DecryptError::HeaderTooLarge)
        );
        for input in [&b""[..], MAGIC, b"age-encryption.org/v1", &at_limit] {
            assert_eq!(
                decrypt(input, &reader).err(),
                Some(DecryptError::InvalidHeader),
                "{} bytes",
                input.len()
            );
        }
    }

    #[test]
    fn the_size_checks_stop_exactly_at_both_limits() {
        // The largest file the size checks must let through: its MAC line
        // starts exactly MAX_HEADER_BYTES bytes in, and its payload holds
        // MAX_PACKAGE_BYTES of plaintext. That is MAX_CIPHERTEXT_BYTES
        // exactly, so one byte more, in the header or in all, is refused.
        let reader = DeviceIdentity::generate();
        let ciphertext = encrypt(&pad(b"{}"), &[reader.recipient()]).unwrap();
        // The real header, cut where the MAC line's marker starts: the
        // stanzas before it, then the marker's newline and the 48-byte MAC
        // line, which end the header. The assertion checks the cut landed on
        // the marker. `split_at` borrows the two halves; it copies nothing.
        let header = &ciphertext[..header_len(&ciphertext)];
        let (stanzas, mac_line) = header.split_at(header.len() - (1 + 48));
        assert!(mac_line.starts_with(b"\n--- "));

        // The real stanzas, then one that no key opens, which age skips,
        // with an argument long enough that the marker's newline lands at
        // index `marker_at`. Its body is empty, so the line that ends it is
        // that newline. Then the MAC line, a zero nonce and `payload_len`
        // zero bytes of payload.
        let file = |marker_at: usize, payload_len: usize| {
            let mut input = stanzas.to_vec();
            input.extend_from_slice(b"\n-> filler ");
            // The argument fills up to the newline that ends its line, the
            // byte just before the marker's.
            input.resize(marker_at - 1, b'a');
            input.push(b'\n');
            input.extend_from_slice(mac_line);
            input.resize(input.len() + 16 + payload_len, 0);
            input
        };
        // MAX_PACKAGE_BYTES of plaintext and a 16-byte tag per 64 KiB chunk.
        let payload_len = MAX_PACKAGE_BYTES + 16 * (MAX_PACKAGE_BYTES / CHUNK);

        let at_limits = file(MAX_HEADER_BYTES, payload_len);
        assert_eq!(at_limits.len(), MAX_CIPHERTEXT_BYTES);
        // The figure the constant's docs give.
        assert_eq!(MAX_CIPHERTEXT_BYTES, 33_570_881);
        assert_eq!(check_size_caps(&at_limits), Ok(Some(MAX_HEADER_BYTES)));
        // So age is given it: it parses the header and opens the real
        // stanza, then finds the MAC wrong, since the filler stanza was added
        // after the MAC was computed.
        assert_eq!(
            decrypt(&at_limits, &reader).err(),
            Some(DecryptError::InvalidMac)
        );

        // One byte more in the header and one less in the payload: the same
        // length, but the MAC line starts one byte too late.
        let long_header = file(MAX_HEADER_BYTES + 1, payload_len - 1);
        assert_eq!(long_header.len(), MAX_CIPHERTEXT_BYTES);
        assert_eq!(
            check_size_caps(&long_header),
            Err(DecryptError::HeaderTooLarge)
        );
        assert_eq!(
            decrypt(&long_header, &reader).err(),
            Some(DecryptError::HeaderTooLarge)
        );

        // One byte more in all: refused on its length.
        let mut one_over = at_limits;
        one_over.push(0);
        assert_eq!(check_size_caps(&one_over), Err(DecryptError::TooLarge));
        assert_eq!(
            decrypt(&one_over, &reader).err(),
            Some(DecryptError::TooLarge)
        );
    }

    #[test]
    fn the_costliest_headers_under_the_cap_stay_cheap() {
        // Bounded work. age re-parses its header from the start for every new
        // line, so the tiniest stanzas cost it the most; and it tries one
        // Diffie-Hellman per X25519 stanza. Each kind, filled up to
        // MAX_HEADER_BYTES, must reach age and come back as a plain error in
        // well under the bound below, even in a debug build: about 1.5 s for
        // the tiny stanzas at 8 KiB, against 96 s at 64 KiB.
        let reader = DeviceIdentity::generate();
        let stranger = DeviceIdentity::generate();
        let theirs = encrypt(&pad(b"{}"), &[stranger.recipient()]).unwrap();
        // The stranger's X25519 stanza: its two lines, as age wrote them.
        let lines: Vec<&[u8]> = theirs[..header_len(&theirs)]
            .split_inclusive(|&byte| byte == b'\n')
            .collect();
        let at = lines
            .iter()
            .position(|line| line.starts_with(b"-> X25519 "))
            .unwrap();
        let x25519_stanza = [lines[at], lines[at + 1]].concat();
        assert_eq!(x25519_stanza.len(), 98);

        let mac_line = format!("--- {}\n", "A".repeat(43));
        for (what, stanza) in [("tiny", &b"-> a\n\n"[..]), ("X25519", &x25519_stanza)] {
            let mut input = MAGIC.to_vec();
            while input.len() + stanza.len() <= MAX_HEADER_BYTES {
                input.extend_from_slice(stanza);
            }
            input.extend_from_slice(mac_line.as_bytes());
            // A nonce and one tag's worth of payload.
            input.extend_from_slice(&[0; 32]);

            let started = Instant::now();
            // No match: age parsed the whole header and tried every stanza.
            assert_eq!(
                decrypt(&input, &reader).err(),
                Some(DecryptError::NoMatchingKey),
                "{what}"
            );
            let elapsed = started.elapsed();
            assert!(elapsed < Duration::from_secs(15), "{what}: {elapsed:?}");
        }
    }

    #[test]
    fn trailing_bytes_after_the_payload_are_rejected() {
        let reader = DeviceIdentity::generate();
        let ciphertext = encrypt(&pad(b"{}"), &[reader.recipient()]).unwrap();
        assert!(decrypt(&ciphertext, &reader).is_ok());

        // age refuses anything after the final chunk, which is why 02 pads
        // the plaintext and never the ciphertext. 16 bytes is the length of
        // an empty chunk's tag.
        for extra in [1, 16] {
            let mut longer = ciphertext.clone();
            longer.extend(std::iter::repeat_n(0x20, extra));
            assert_eq!(
                decrypt(&longer, &reader).err(),
                Some(DecryptError::InvalidPayload),
                "{extra}"
            );
        }
    }

    #[test]
    fn malformed_ciphertext_never_panics() {
        let reader = DeviceIdentity::generate();
        let other = DeviceIdentity::generate();
        // Two chunks, so the payload has an inner chunk boundary to cut at.
        let padded = pad(&vec![b'z'; CHUNK + 1]);
        let ciphertext = encrypt(&padded, &[other.recipient(), reader.recipient()]).unwrap();
        // The header and the payload's 16-byte nonce.
        let preamble = header_len(&ciphertext) + 16;
        let boundary = preamble + CHUNK + 16;
        let payload_samples: Vec<usize> = (preamble..ciphertext.len())
            .step_by(4093)
            .chain([boundary - 1, boundary, boundary + 1, ciphertext.len() - 1])
            .collect();

        // A panic fails the test on its own; the assertion adds that every
        // case is an error.
        let refused = |input: &[u8], what: &str| {
            assert!(decrypt(input, &reader).is_err(), "{what}");
        };

        // Every truncation inside the header and nonce, and a sample of the
        // payload's.
        for len in (0..preamble).chain(payload_samples.iter().copied()) {
            refused(&ciphertext[..len], &format!("truncated to {len}"));
        }
        // A flipped bit at every header byte, and at the sampled payload
        // bytes. Which bit cycles with the position.
        let mut flipped = ciphertext.clone();
        for at in (0..preamble).chain(payload_samples.iter().copied()) {
            let bit = 1 << (at % 8);
            flipped[at] ^= bit;
            refused(&flipped, &format!("bit flipped at {at}"));
            flipped[at] ^= bit;
        }
        assert_eq!(flipped, ciphertext);

        // Empty and random input, and random input after a real first line.
        refused(b"", "empty");
        for (seed, len) in [(1, 1), (2, 100), (3, 2 * CHUNK)] {
            let random = noise(len, seed);
            refused(&random, &format!("{len} random bytes"));
            let mut after_magic = MAGIC.to_vec();
            after_magic.extend_from_slice(&random);
            refused(&after_magic, &format!("magic then {len} random bytes"));
        }
        // The real header with random bytes for a payload.
        let mut random_payload = ciphertext[..preamble].to_vec();
        random_payload.extend_from_slice(&noise(CHUNK + 40, 4));
        refused(&random_payload, "random payload");

        // And the untouched ciphertext still opens.
        assert!(decrypt(&ciphertext, &reader).is_ok());
    }

    #[test]
    fn sealed_buffers_and_errors_never_print_content() {
        const MARKER: &str = "sweepkysealedmarker";
        let package = format!(r#"{{"schemaVersion":1,"note":"{MARKER}"}}"#);
        let padded = pad(package.as_bytes());
        let reader = DeviceIdentity::generate();
        let ciphertext = encrypt(&padded, &[reader.recipient()]).unwrap();
        let opened: Plaintext = decrypt(&ciphertext, &reader).unwrap();

        let mut outputs = vec![
            format!("{padded:?}"),
            format!("{padded:#?}"),
            format!("{opened:?}"),
            format!("{opened:#?}"),
        ];
        // Debug shows the length and nothing else.
        assert_eq!(outputs[0], "PaddedPlaintext { len: 65536, .. }");
        assert_eq!(outputs[2], "Plaintext { len: 65536, .. }");

        // Every error variant there is, then the ones real failures give for
        // input that carries the marker.
        let mut decrypt_errors = vec![
            DecryptError::TooLarge,
            DecryptError::HeaderTooLarge,
            DecryptError::InvalidHeader,
            DecryptError::NoMatchingKey,
            DecryptError::InvalidMac,
            DecryptError::InvalidPayload,
            DecryptError::PlaintextTooLarge,
        ];
        let mut marked = ciphertext.clone();
        marked.extend_from_slice(MARKER.as_bytes());
        let mut marked_header = MAGIC.to_vec();
        marked_header.extend_from_slice(format!("-> {MARKER}\n\n--- {MARKER}\n").as_bytes());
        for input in [
            marked,
            marked_header,
            MARKER.as_bytes().to_vec(),
            MARKER.repeat(MAX_HEADER_BYTES).into_bytes(),
        ] {
            decrypt_errors.push(decrypt(&input, &reader).err().unwrap());
        }
        let encrypt_errors = [
            EncryptError::NoRecipients,
            EncryptError::TooManyRecipients,
            EncryptError::Age,
        ];
        let padding_errors = [PaddingError::TooLarge];
        // An error's `Display` and `Debug` text. The three error types share
        // no type, so this is generic over any that prints both ways.
        fn printed<E: std::fmt::Display + std::fmt::Debug>(error: E) -> [String; 2] {
            [error.to_string(), format!("{error:?}")]
        }
        outputs.extend(decrypt_errors.into_iter().flat_map(printed));
        outputs.extend(encrypt_errors.into_iter().flat_map(printed));
        outputs.extend(padding_errors.into_iter().flat_map(printed));

        for output in &outputs {
            assert!(!output.contains(MARKER), "{output}");
            assert!(!output.contains("schemaVersion"), "{output}");
        }
    }

    #[test]
    fn plaintext_buffers_have_no_display_serialize_or_clone() {
        // Checked when the test compiles; there is nothing left to run.
        crate::crypto::assert_not_impl_any!(
            PaddedPlaintext: std::fmt::Display,
            serde::Serialize,
            serde::de::DeserializeOwned,
            Clone,
        );
        crate::crypto::assert_not_impl_any!(
            Plaintext: std::fmt::Display,
            serde::Serialize,
            serde::de::DeserializeOwned,
            Clone,
        );
        // Debug stays (the test above shows it redacts), so a struct holding
        // one can still derive Debug.
        fn has_debug<T: std::fmt::Debug>() {}
        has_debug::<PaddedPlaintext>();
        has_debug::<Plaintext>();
    }
}
