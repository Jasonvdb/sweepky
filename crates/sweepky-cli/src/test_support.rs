//! Helpers that the unit tests of several modules share: a private temp
//! directory, the [`Dirs`] under it and the file-mode checks around it, a
//! [`FileSnapshot`] that tells whether a file was written at all, a random
//! public key, a [`FakeKeyStore`] in place of a homeserver's `keys/`, and a
//! compile-time check that a secret type implements none of the traits that
//! would print or copy it.
//!
//! Compiled only for `cargo test` (`#[cfg(test)]` on its `mod` line in
//! `lib.rs`), so nothing here reaches the binary, and like any test code it
//! may panic.

use std::collections::BTreeMap;
use std::fs::{self, Permissions};
use std::io::ErrorKind;
// `MetadataExt` adds `.mode()` and `.ino()` to `Metadata`; `PermissionsExt`
// adds `Permissions::from_mode`.
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Mutex;

use pubky::errors::RequestError;
use pubky::{Keypair, PublicKey, StatusCode};
use sweepky_core::{DeviceId, Pubky, Zeroizing};
use tempfile::TempDir;

use crate::Dirs;
use crate::device::{KeyIds, KeyStore};

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

/// The directories under `home`, as `SWEEPKY_HOME=<home>` gives them.
pub(crate) fn dirs_in(home: &TempDir) -> Dirs {
    Dirs::resolve(None, Some(home.path().as_os_str())).expect("absolute temp dir")
}

/// A fresh public key, made from a random keypair and converted to core's
/// `Pubky` (the same 32 bytes).
pub(crate) fn random_pubky() -> Pubky {
    Pubky::from_bytes(Keypair::random().public_key().to_bytes())
}

/// What the [`FakeKeyStore`] answers a write it refuses with: the server's
/// own words, which a test checks never reach a message.
pub(crate) const FAKE_SERVER_TEXT: &str = "fake homeserver: tenant quota and path policy say no";

/// One call a [`FakeKeyStore`] was asked to make, with what it was asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KeyStoreCall {
    /// [`KeyStore::get_own_key`] of this id.
    GetOwnKey(DeviceId),
    /// [`KeyStore::put_key`] of this id, refused or not.
    PutKey(DeviceId),
    /// [`KeyStore::list_key_ids`] of this owner.
    ListKeyIds(PublicKey),
}

/// A [`KeyStore`] in memory, in place of a homeserver: one owner's `keys/`
/// records by device id, every call it was asked to make, in order, and, if
/// set, the status it refuses every write with.
///
/// The methods take `&self`, as the trait's do, yet the fake has to change
/// what it holds. A `Mutex` gives that "interior mutability": it hands out
/// `&mut` access to one caller at a time, checked at run time.
#[derive(Default)]
pub(crate) struct FakeKeyStore {
    records: Mutex<BTreeMap<DeviceId, Vec<u8>>>,
    calls: Mutex<Vec<KeyStoreCall>>,
    refuse_puts_with: Option<StatusCode>,
}

impl FakeKeyStore {
    /// A store that refuses every write with `status` and the text
    /// [`FAKE_SERVER_TEXT`], as the SDK reports a homeserver's non-2xx answer.
    pub(crate) fn refusing_puts(status: StatusCode) -> Self {
        Self {
            refuse_puts_with: Some(status),
            ..Self::default()
        }
    }

    /// Every call so far, in order.
    pub(crate) fn calls(&self) -> Vec<KeyStoreCall> {
        self.calls.lock().expect("lock").clone()
    }

    /// The record the store holds as `keys/<id>.json`, if any. Not a call:
    /// it is the test looking at the homeserver, so it is not logged.
    pub(crate) fn record(&self, id: &DeviceId) -> Option<Vec<u8>> {
        self.records.lock().expect("lock").get(id).cloned()
    }

    /// Puts `record` in place as `keys/<id>.json`, as someone writing to the
    /// homeserver behind this install's back would. Not logged either.
    pub(crate) fn set_record(&self, id: &DeviceId, record: Vec<u8>) {
        self.records
            .lock()
            .expect("lock")
            .insert(id.clone(), record);
    }

    fn log(&self, call: KeyStoreCall) {
        self.calls.lock().expect("lock").push(call);
    }
}

impl KeyStore for FakeKeyStore {
    async fn get_own_key(&self, id: &DeviceId) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
        self.log(KeyStoreCall::GetOwnKey(id.clone()));
        Ok(self.record(id).map(Zeroizing::new))
    }

    async fn put_key(&self, id: &DeviceId, record: Vec<u8>) -> pubky::Result<()> {
        self.log(KeyStoreCall::PutKey(id.clone()));
        if let Some(status) = self.refuse_puts_with {
            return Err(pubky::Error::from(RequestError::Server {
                status,
                message: FAKE_SERVER_TEXT.to_owned(),
            }));
        }
        self.set_record(id, record);
        Ok(())
    }

    async fn list_key_ids(&self, owner: &PublicKey) -> anyhow::Result<KeyIds> {
        self.log(KeyStoreCall::ListKeyIds(owner.clone()));
        let records = self.records.lock().expect("lock");
        Ok(KeyIds {
            ids: records.keys().cloned().collect(),
            skipped: 0,
        })
    }
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

/// What a file holds at one moment, and which inode holds it.
///
/// `private_fs` writes a file by renaming a new one over it, so a file
/// written again has a new inode even when its bytes are the same: two equal
/// snapshots mean the file was not written at all in between.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FileSnapshot {
    bytes: Vec<u8>,
    inode: u64,
}

impl FileSnapshot {
    /// The file at `path` now, or `None` when there is nothing there. Any
    /// other error fails the test, so an unreadable file is never mistaken
    /// for a missing one.
    pub(crate) fn of(path: &Path) -> Option<Self> {
        let meta = match fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == ErrorKind::NotFound => return None,
            Err(error) => panic!("could not stat {}: {error}", path.display()),
        };
        Some(Self {
            bytes: fs::read(path).expect("readable"),
            inode: meta.ino(),
        })
    }
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
