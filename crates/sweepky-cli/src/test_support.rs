//! Helpers that the unit tests of several modules share: a private temp
//! directory and the file-mode checks around it, and a compile-time check
//! that a secret type implements none of the traits that would print or copy
//! it.
//!
//! Compiled only for `cargo test` (`#[cfg(test)]` on its `mod` line in
//! `lib.rs`), so nothing here reaches the binary, and like any test code it
//! may panic.

use std::fs::{self, Permissions};
// `MetadataExt` adds `.mode()` to `Metadata`; `PermissionsExt` adds
// `Permissions::from_mode`.
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use tempfile::TempDir;

/// A fresh private directory to work in, created 0700 (`tempfile` passes
/// `permissions` to the `mkdir` itself; its default would follow the
/// umask, usually 0755). It deletes itself when the `TempDir` is dropped.
pub(crate) fn private_temp() -> TempDir {
    let temp = tempfile::Builder::new()
        .permissions(Permissions::from_mode(0o700))
        .tempdir()
        .expect("temp dir");
    assert_eq!(mode(temp.path()), 0o700);
    temp
}

/// The permission bits of whatever is at `path`, not following a link.
///
/// `& 0o777` keeps the permission bits and drops the file-type bits that
/// `st_mode` also carries.
pub(crate) fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).expect("exists").mode() & 0o777
}

/// Sets the permission bits of `path` to `mode`.
pub(crate) fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, Permissions::from_mode(mode)).expect("chmod");
}

/// Fails to compile when `$type` implements any of the listed traits. A test
/// states what a secret type must never implement with
/// `crate::test_support::assert_not_impl_any!(Type: Trait, …);`.
///
/// A copy of `sweepky-core`'s test-only macro of the same name, which is
/// `pub(crate)` there and so cannot be used from this crate; like that one,
/// it is the trick behind `static_assertions::assert_not_impl_any!`, written
/// out so no dependency is needed for it. A local trait has a blanket impl
/// for every type with the parameter `()`, and one more blanket impl per
/// listed trait, each with its own private parameter type, for the types
/// that implement that trait. `<$type as AmbiguousIfImpl<_>>` asks the
/// compiler to infer the parameter. If `$type` implements none of the listed
/// traits, only the `()` impl applies and inference succeeds; if it
/// implements one, two impls apply, inference is ambiguous, and the crate
/// does not compile. So the check happens at compile time, and the test that
/// holds it has nothing left to do when it runs.
///
/// For `Deserialize`, list `serde::de::DeserializeOwned`: it is implemented
/// for every type that is `Deserialize` for every lifetime, which is what
/// `#[derive(Deserialize)]` gives.
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
// re-exported. This `use` gives it the path
// `crate::test_support::assert_not_impl_any` for test modules anywhere in the
// crate.
pub(crate) use assert_not_impl_any;
