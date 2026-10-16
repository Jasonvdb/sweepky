//! Padding a sweep package to a size bucket before it is encrypted:
//! [`PaddedPlaintext`], the only thing [`encrypt`](crate::encrypt) accepts.
//!
//! 02 pads "to blunt the sizes": an upload's size is public, so without
//! padding it would tell anyone roughly how long a sweep's findings are.
//! With it, the ciphertext says only which 64 KiB bucket the package fell in.

use std::fmt;

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
/// cannot be encrypted by mistake: the only way to make one is
/// [`pad`](Self::pad).
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
        if package.len() > MAX_PACKAGE_BYTES {
            return Err(PaddingError::TooLarge);
        }
        // `div_ceil` rounds up: 1 byte is one bucket, 64 KiB is one, 64 KiB + 1
        // is two. `max(1)` gives the empty package its one bucket. The package
        // is at most `MAX_PACKAGE_BYTES` here, a whole number of buckets, so
        // the product is at most that too and the multiplication cannot
        // overflow.
        let padded_len = package.len().div_ceil(PADDING_BUCKET_BYTES).max(1) * PADDING_BUCKET_BYTES;
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
    use age::secrecy::ExposeSecret;

    use super::{MAX_PACKAGE_BYTES, PADDING_BUCKET_BYTES, PaddedPlaintext, PaddingError};

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
}
