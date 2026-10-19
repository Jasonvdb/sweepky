//! [`OwnStorage`], the seam through which `post`, `run` and `submit` write
//! the signed-in user's own records and read them back, and
//! [`SessionStorage`], the real one, over a command's signed-in session.
//!
//! Every such write happens inside `session::with_writer_session`, under
//! the writers' lock, so this module never signs in, never signs out and
//! never takes the lock: a [`SessionStorage`] only borrows a session that
//! its caller opened and will close. The unit tests use
//! `test_support::FakeOwnStorage` instead, which keeps the files in memory,
//! records every write and can refuse a chosen one with a status and its
//! own server text.
//!
//! **A refused write never prints the server's words.** [`OwnStorage::put`]
//! hands the SDK's error back as it is, so the caller can map it with
//! `remote::write_error` (403 and 507 to their messages, anything else to
//! fixed text and the status); the error's own `Display` holds the
//! server's text, or the request URL, and is never printed.

use pubky::PubkySession;
use sweepky_core::{MAX_RECORD_BYTES, Zeroizing};

use crate::remote;
use crate::session::WriterSession;

/// The signed-in user's own files under `/pub/sweepky/`: write a path, or
/// read one back.
///
/// A trait so that the commands can be tested without a homeserver, as
/// with `device::KeyStore`. Its methods are `async fn`s, so it cannot be a
/// `dyn OwnStorage` (each implementation's futures are a different type);
/// callers take `&impl OwnStorage`, and the compiler makes one copy of the
/// caller for the real storage and one for the fake. `pub(crate)`, so the
/// warning about `Send` bounds on public async traits does not apply.
///
/// Paths are absolute, such as `/pub/sweepky/bounties/<id>.json`, and come
/// from `sweepky_core::paths`, never from a stranger's text: a read's error
/// message names the path.
pub(crate) trait OwnStorage {
    /// Writes `bytes` at `path`, replacing whatever is there.
    ///
    /// The SDK's own error comes back, for the caller to map with
    /// `remote::write_error`. Never print the error itself.
    async fn put(&self, path: &str, bytes: Vec<u8>) -> pubky::Result<()>;

    /// The file at `path`, read as a record: at most [`MAX_RECORD_BYTES`],
    /// or `None` when there is none. The bytes are the homeserver's: parse
    /// them with the record type's `from_json`.
    // `run` and `submit`, later in P2b, are the first callers outside the
    // tests: `expect` (not `allow`) silences the dead-code warning only
    // while it is true, and the first caller removes it.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "run and submit, later in P2b, are the first callers"
        )
    )]
    async fn get_own(&self, path: &str) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>>;
}

/// The real [`OwnStorage`]: the signed-in user's storage through the
/// session a command's `with_writer_session` body is lent.
///
/// It borrows the session, which is what the `'a` says: the store cannot
/// outlive the session, keep it or sign it out; `with_writer_session` signs
/// out once the body, and the store with it, is done. (Not to be confused
/// with the SDK's own `pubky::SessionStorage`, the handle
/// `session.storage()` returns, which each call here asks for afresh.)
pub(crate) struct SessionStorage<'a> {
    session: &'a PubkySession,
}

impl<'a> SessionStorage<'a> {
    /// The storage of `signed`'s session.
    pub(crate) fn new(signed: &'a WriterSession) -> Self {
        Self {
            session: signed.session(),
        }
    }
}

impl OwnStorage for SessionStorage<'_> {
    async fn put(&self, path: &str, bytes: Vec<u8>) -> pubky::Result<()> {
        // `map(drop)` throws the successful response away unread: a 2xx is
        // all that matters, and its body is not ours to trust.
        self.session.storage().put(path, bytes).await.map(drop)
    }

    async fn get_own(&self, path: &str) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
        // A path-qualified call: `remote::get_own` is the function, capped
        // and with a 404 read as `None`, that this method is named after.
        remote::get_own(self.session, path, MAX_RECORD_BYTES).await
    }
}
