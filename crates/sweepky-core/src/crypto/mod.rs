//! Sweepky's cryptography (P1b), built on age v1 with X25519 recipients.
//!
//! - `keys`: [`DeviceIdentity`], an install's secret age key, and
//!   [`AgeRecipient`], a public `age1…` key read with a strict parse that
//!   refuses anything age's encryptor would panic on.
//! - `padding`: [`PaddedPlaintext`], a sweep package padded with trailing
//!   spaces to the next 64 KiB bucket, the only input [`encrypt`] takes.
//! - `seal`: [`encrypt`] to a list of recipients as binary age v1, and
//!   [`decrypt`] with one identity, which bounds what a stranger's file can
//!   make it do and returns the whole [`Plaintext`] or nothing.
//!
//! Nothing here rolls its own cryptography: age does the encryption, and this
//! module only decides which keys age is handed, what age may be made to
//! parse, and keeps secrets and sealed content out of logs, errors and
//! serialized output.

mod keys;
mod padding;
mod seal;

pub use keys::{AgeRecipient, DeviceIdentity, DeviceKeyError, IdentityError, RecipientError};
pub use padding::{PADDING_BUCKET_BYTES, PaddedPlaintext, PaddingError};
pub use seal::{
    DecryptError, EncryptError, MAX_CIPHERTEXT_BYTES, MAX_HEADER_BYTES, MAX_RECIPIENTS, Plaintext,
    decrypt, encrypt,
};

/// Fails to compile when `$type` implements any of the listed traits.
/// Test-only: a test module states what a secret type must never implement
/// with `crate::crypto::assert_not_impl_any!(Type: Trait, …);`.
///
/// It is the trick behind `static_assertions::assert_not_impl_any!`, written
/// out here so the crate needs no extra dependency for it. A local trait has
/// a blanket impl for every type with the parameter `()`, and one more blanket
/// impl per listed trait, each with its own private parameter type, for the
/// types that implement that trait. `<$type as AmbiguousIfImpl<_>>` asks the
/// compiler to infer the parameter. If `$type` implements none of the listed
/// traits, only the `()` impl applies and inference succeeds; if it
/// implements one, two impls apply, inference is ambiguous, and the crate
/// does not compile. So the check happens at compile time, and the test that
/// holds it has nothing left to do when it runs.
///
/// For `Deserialize`, list `serde::de::DeserializeOwned`: it is implemented
/// for every type that is `Deserialize` for every lifetime, which is what
/// `#[derive(Deserialize)]` gives.
#[cfg(test)]
macro_rules! assert_not_impl_any {
    ($type:ty: $($trait_path:path),+ $(,)?) => {
        // `const _` is an unnamed constant: it exists only to make the
        // compiler type-check the closure below. The closure is never called.
        const _: fn() = || {
            trait AmbiguousIfImpl<A> {
                fn some_item() {}
            }
            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
            $({
                // Never constructed: it only gives this impl a parameter type
                // of its own.
                #[allow(dead_code)]
                struct Invalid;
                impl<T: ?Sized + $trait_path> AmbiguousIfImpl<Invalid> for T {}
            })+
            let _ = <$type as AmbiguousIfImpl<_>>::some_item;
        };
    };
}

// A `macro_rules!` macro is visible only further down this file unless it is
// re-exported. This `use` gives it the path `crate::crypto::assert_not_impl_any`
// for test modules anywhere in the crate.
#[cfg(test)]
pub(crate) use assert_not_impl_any;
