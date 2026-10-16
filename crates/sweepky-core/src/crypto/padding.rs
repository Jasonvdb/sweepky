//! Padding a sweep package to a size bucket before it is encrypted:
//! [`PaddedPlaintext`], the only thing [`encrypt`](crate::encrypt) accepts.
//!
//! 02 pads "to blunt the sizes": an upload's size is public, so without
//! padding it would tell anyone roughly how long a sweep's findings are.
//! With it, the ciphertext says only which 64 KiB bucket the package fell in.

use std::fmt;
use std::io;

use age::secrecy::ExposeSecret;
use zeroize::Zeroizing;

use crate::schema::MAX_PACKAGE_BYTES;

/// The size step a package is padded to: 64 KiB, from 02.
///
/// It equals age's own chunk size, so a padded package is always a whole
/// number of age's 64 KiB chunks, and the encrypted payload's length is set
/// by the bucket alone.
pub const PADDING_BUCKET_BYTES: usize = 64 * 1024;

/// What the padding is made of: ASCII spaces. The package is one JSON
/// document, and JSON reads trailing spaces as whitespace, so the padded
/// bytes parse to the same document as the unpadded ones.
const PADDING_BYTE: u8 = b' ';

// A compile-time check. `const _` is an unnamed constant, evaluated while the
// crate compiles; a failed `assert!` there is a compile error, never a panic
// at run time. A package at the cap must pad to the cap itself, so the cap
// must be a whole number of buckets.
const _: () = assert!(MAX_PACKAGE_BYTES.is_multiple_of(PADDING_BUCKET_BYTES));

/// Why a package could not be padded.
///
/// Like every error in this module it holds no data, so it can never carry
/// any of the package into a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PaddingError {
    /// The package is longer than [`MAX_PACKAGE_BYTES`] (32 MiB). Checked
    /// before anything is allocated.
    #[error("the sweep package is larger than the 32 MiB limit")]
    TooLarge,
}

/// A sweep package padded with trailing spaces to the next multiple of
/// [`PADDING_BUCKET_BYTES`], ready to encrypt.
///
/// [`encrypt`](crate::encrypt) takes only this type, so an unpadded package
/// cannot be encrypted by mistake: the only ways to make one are
/// [`pad`](Self::pad) and
/// [`SweepPackage::to_padded`](crate::SweepPackage::to_padded), which both
/// pad.
///
/// The package is sealed content, so this type is careful with it:
///
/// - The bytes live in a [`Zeroizing`] buffer, which overwrites them with
///   zeros when the value is dropped.
/// - That buffer is allocated once, at its final size, and never grows. A
///   `Vec` that grows moves its bytes to a bigger allocation and frees the
///   old one without wiping it, which would leave a copy of the package in
///   freed memory that nothing ever overwrites.
/// - [`Debug`](fmt::Debug) prints the length only. There is no `Display`,
///   `Serialize`, `Deserialize` or `Clone` (a test checks that at compile
///   time), so the package cannot be printed, written out or copied by
///   accident. Reading the bytes takes an explicit
///   [`expose_secret`](ExposeSecret::expose_secret).
///
/// age copies each 64 KiB chunk into a buffer of its own while it encrypts,
/// and does not wipe that buffer afterwards; that copy is outside this
/// type's control.
pub struct PaddedPlaintext(Zeroizing<Vec<u8>>);

impl PaddedPlaintext {
    /// Copies `package` into a new buffer and pads it with trailing spaces to
    /// the next multiple of [`PADDING_BUCKET_BYTES`].
    ///
    /// A package already on a bucket boundary keeps its length. An empty one
    /// becomes one bucket of spaces: there is no zero-length bucket, so every
    /// padded package is at least 64 KiB. The caller's `package` is left as
    /// it was; wiping it is the caller's job.
    ///
    /// # Errors
    ///
    /// [`PaddingError::TooLarge`] when `package` is longer than
    /// [`MAX_PACKAGE_BYTES`]. A package of exactly that length pads to itself.
    pub fn pad(package: &[u8]) -> Result<Self, PaddingError> {
        let padded_len = padded_len(package.len())?;
        // One allocation of exactly the final size. `extend_from_slice` and
        // `resize` below stay within that capacity, so the buffer never moves
        // (see the type's docs for why that matters). `Zeroizing` wraps the
        // `Vec` before the package is copied in, so no copy ever sits in a
        // buffer that would be freed without the wipe.
        let mut buffer = Zeroizing::new(Vec::with_capacity(padded_len));
        buffer.extend_from_slice(package);
        buffer.resize(padded_len, PADDING_BYTE);
        Ok(Self(buffer))
    }

    /// The padded length in bytes: always a positive multiple of
    /// [`PADDING_BUCKET_BYTES`]. Not a secret: the ciphertext's length shows
    /// it to anyone.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Always `false`: an empty package pads to one whole bucket.
    // Clippy asks for `is_empty` next to every public `len`, so callers can
    // write the idiomatic check.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The length a package of `len` bytes pads to: the next multiple of
/// [`PADDING_BUCKET_BYTES`], and one bucket for an empty package.
/// [`PaddingError::TooLarge`] when `len` is over [`MAX_PACKAGE_BYTES`].
fn padded_len(len: usize) -> Result<usize, PaddingError> {
    if len > MAX_PACKAGE_BYTES {
        return Err(PaddingError::TooLarge);
    }
    // `div_ceil` rounds up: 1 byte is one bucket, 64 KiB is one, 64 KiB + 1
    // is two. `max(1)` gives the empty package its one bucket. `len` is at
    // most `MAX_PACKAGE_BYTES` here, a whole number of buckets, so the
    // product is at most that too and the multiplication cannot overflow.
    Ok(len.div_ceil(PADDING_BUCKET_BYTES).max(1) * PADDING_BUCKET_BYTES)
}

/// Writes a sweep package straight into the buffer it is padded in, so the
/// package never sits in an unpadded copy first. Crate-internal: it is what
/// [`SweepPackage::to_padded`](crate::SweepPackage::to_padded) serializes
/// into.
///
/// It is made for an exact package length, counted beforehand, and
/// allocates the whole padded buffer at once, wrapped in [`Zeroizing`]. It
/// then takes at most that many bytes: a write that would pass them is
/// refused whole, so the buffer never grows and never moves (see
/// [`PaddedPlaintext`] for why that matters). [`finish`](Self::finish) pads
/// with spaces only when exactly that many bytes arrived.
///
/// No `Debug`: nothing needs to print one, and it holds the package.
pub(crate) struct PaddingWriter {
    buffer: Zeroizing<Vec<u8>>,
    /// The package's length, counted beforehand: the most the writer takes.
    package_len: usize,
    /// The length it pads to, and the buffer's capacity.
    padded_len: usize,
    /// Whether a write was refused for passing `package_len`.
    overflowed: bool,
}

impl PaddingWriter {
    /// A writer for a package of exactly `package_len` bytes, with its
    /// padded buffer allocated.
    ///
    /// [`PaddingError::TooLarge`] when `package_len` is over
    /// [`MAX_PACKAGE_BYTES`], before anything is allocated.
    pub(crate) fn new(package_len: usize) -> Result<Self, PaddingError> {
        let padded_len = padded_len(package_len)?;
        Ok(Self {
            buffer: Zeroizing::new(Vec::with_capacity(padded_len)),
            package_len,
            padded_len,
            overflowed: false,
        })
    }

    /// Pads what was written with spaces and hands it over as a
    /// [`PaddedPlaintext`].
    ///
    /// `None` unless exactly `package_len` bytes were written and none was
    /// refused: then the count was wrong, and the bytes are not a whole
    /// package. The buffer is wiped as it drops.
    // `self` by value: `finish` consumes the writer, so nothing can write to
    // it afterwards. A struct with no `Drop` impl of its own can be taken
    // apart like this, moving `buffer` out without a copy.
    pub(crate) fn finish(self) -> Option<PaddedPlaintext> {
        let Self {
            mut buffer,
            package_len,
            padded_len,
            overflowed,
        } = self;
        if overflowed || buffer.len() != package_len {
            return None;
        }
        // `padded_len` is the capacity `new` allocated, so this fills the
        // buffer without growing it.
        buffer.resize(padded_len, PADDING_BYTE);
        Some(PaddedPlaintext(buffer))
    }
}

/// serde_json writes through `io::Write`, so implementing it is what lets
/// `serde_json::to_writer` fill the padded buffer directly.
impl io::Write for PaddingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        // `buffer.len()` never passes `package_len` (a write that would is
        // refused below), so this subtraction cannot underflow; `saturating_`
        // says so without a panic path.
        let room = self.package_len.saturating_sub(self.buffer.len());
        if bytes.len() > room {
            // Refused whole rather than taken in part: more bytes than were
            // counted means the count was wrong, and taking them would mean
            // growing the buffer. The error is built from its kind alone, so
            // it allocates nothing and carries none of the bytes.
            self.overflowed = true;
            return Err(io::Error::from(io::ErrorKind::Other));
        }
        self.buffer.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The padded bytes: the package, then the spaces.
// `ExposeSecret` is the trait `SecretString` uses too, so reading any sealed
// value is the same deliberate, greppable call. `[u8]` is the type it lends
// out: a borrowed slice, so nothing is copied.
impl ExposeSecret<[u8]> for PaddedPlaintext {
    fn expose_secret(&self) -> &[u8] {
        &self.0
    }
}

/// Prints `PaddedPlaintext { len: 65536, .. }`: the length, never a byte of
/// the content.
impl fmt::Debug for PaddedPlaintext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaddedPlaintext")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use age::secrecy::ExposeSecret;

    use super::{
        MAX_PACKAGE_BYTES, PADDING_BUCKET_BYTES, PaddedPlaintext, PaddingError, PaddingWriter,
    };

    const BUCKET: usize = PADDING_BUCKET_BYTES;

    #[test]
    fn padding_respects_the_package_cap() {
        assert_eq!(BUCKET, 65_536);
        assert_eq!(MAX_PACKAGE_BYTES, 32 * 1024 * 1024);

        // Exactly the cap pads, to itself.
        let at_cap = vec![b'{'; MAX_PACKAGE_BYTES];
        let padded = PaddedPlaintext::pad(&at_cap).unwrap();
        assert_eq!(padded.len(), MAX_PACKAGE_BYTES);
        assert_eq!(padded.expose_secret(), &at_cap[..]);
        // Freed now rather than at the end of the test: each is 32 MiB.
        drop(padded);
        drop(at_cap);

        // One byte more is refused.
        let over = vec![b'{'; MAX_PACKAGE_BYTES + 1];
        assert_eq!(
            PaddedPlaintext::pad(&over).err(),
            Some(PaddingError::TooLarge)
        );
        drop(over);

        // Input already on a bucket boundary keeps its length and its bytes.
        for len in [BUCKET, 2 * BUCKET, 5 * BUCKET] {
            let package = vec![b'x'; len];
            let padded = PaddedPlaintext::pad(&package).unwrap();
            assert_eq!(padded.len(), len);
            assert_eq!(padded.expose_secret(), &package[..]);
        }

        // Anything else: the package, then spaces to the next boundary.
        for (len, expected) in [(1, BUCKET), (BUCKET + 1, 2 * BUCKET), (0, BUCKET)] {
            let package = vec![b'x'; len];
            let padded = PaddedPlaintext::pad(&package).unwrap();
            assert_eq!(padded.len(), expected, "{len}");
            assert!(!padded.is_empty());
            let (head, tail) = padded.expose_secret().split_at(len);
            assert_eq!(head, &package[..]);
            assert!(tail.iter().all(|&byte| byte == b' '), "{len}");
            // Allocated once at the final size, with no room left to grow
            // into: `with_capacity` gives exactly the capacity asked for.
            assert_eq!(padded.0.capacity(), expected, "{len}");
        }
    }

    #[test]
    fn a_padding_writer_refuses_a_count_over_the_cap() {
        // Refused before anything is allocated.
        assert_eq!(
            PaddingWriter::new(MAX_PACKAGE_BYTES + 1).err(),
            Some(PaddingError::TooLarge)
        );
    }

    #[test]
    fn a_padding_writer_pads_exactly_the_counted_bytes() {
        // The package, then spaces, in the one buffer allocated at the
        // padded size.
        for (len, expected) in [
            (0, BUCKET),
            (3, BUCKET),
            (BUCKET, BUCKET),
            (BUCKET + 1, 2 * BUCKET),
        ] {
            let package = vec![b'x'; len];
            let mut writer = PaddingWriter::new(len).unwrap();
            writer.write_all(&package).unwrap();
            let padded = writer.finish().unwrap();
            assert_eq!(padded.len(), expected, "{len}");
            assert_eq!(padded.0.capacity(), expected, "{len}");
            let (head, tail) = padded.expose_secret().split_at(len);
            assert_eq!(head, &package[..]);
            assert!(tail.iter().all(|&byte| byte == b' '), "{len}");
        }
    }

    #[test]
    fn a_padding_writer_refuses_bytes_past_the_count_without_growing() {
        // The write that would pass the count is refused whole, so the
        // buffer never grows.
        let mut writer = PaddingWriter::new(3).unwrap();
        writer.write_all(b"ab").unwrap();
        assert!(writer.write_all(b"cd").is_err());
        assert_eq!(writer.buffer.len(), 2);
        assert_eq!(writer.buffer.capacity(), BUCKET);
        // A write that fits after the refusal brings the length to the
        // count, but the bytes are still not the package: `finish` gives
        // nothing, because the refusal is remembered.
        writer.write_all(b"c").unwrap();
        assert_eq!(writer.buffer.len(), 3);
        assert!(writer.finish().is_none());
    }

    #[test]
    fn a_padding_writer_gives_nothing_for_fewer_bytes_than_counted() {
        // The count was wrong, so the bytes are not a whole package.
        let mut writer = PaddingWriter::new(3).unwrap();
        writer.write_all(b"ab").unwrap();
        assert!(writer.finish().is_none());
    }
}
