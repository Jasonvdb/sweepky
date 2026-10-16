//! The session a writing command runs in.
//!
//! Every command that writes to the homeserver (`keys revoke`, `circle`,
//! `post`, `run`, `submit`, `done`) runs its writes inside
//! [`with_writer_session`]:
//!
//! 1. take the writers' lock ([`with_writers_lock`]), so no other `sweepky`
//!    command on this install signs in or writes meanwhile;
//! 2. read `login.json` and the identity it names, and sign in afresh with
//!    the identity's own key (`PubkySigner::signin`, never the deprecated
//!    cookie sign-in);
//! 3. run the command's body with the session;
//! 4. sign out, always, whether the body succeeded or failed, so the root
//!    grant each sign-in creates (valid for two years) is revoked again and
//!    such grants do not pile up on the homeserver (03, "Two ways to log
//!    in"). A sign-out that fails is a warning, not an error: the body's
//!    work is done by then, and its result is what the command reports;
//! 5. release the lock.
//!
//! P2d adds the Pubky Ring branch to step 2: restoring the saved grant token
//! instead of signing in with a key.
//!
//! `logout` runs the same steps itself, under [`with_writers_lock`] with
//! [`sign_in`] and [`WriterSession::sign_out`], because it deletes the
//! identity and this install's files after the sign-out and before the lock
//! is released, which a body of [`with_writer_session`] cannot do.
//!
//! **Never `{:?}` a session or a signer.** `PubkySession`'s `Debug` prints
//! its credential's, and a signer holds the identity's keypair. Nothing here
//! derives or calls `Debug` on either, and [`WriterSession`] has no `Debug`.

use anyhow::{Context as _, bail};
use pubky::PubkySession;

use crate::identity::IdentitySecret;
use crate::lock::WritersLock;
use crate::network::client_id;
use crate::remote::request_error;
use crate::state::{KnownLoginKind, LoginState, StoredIdentity, read_identity, read_login_state};
use crate::{Context, Dirs};

/// What a command says while another one holds the writers' lock.
const WAITING_FOR_LOCK: &str =
    "waiting for another sweepky command on this install to finish (it holds the writers' lock)";

/// What a command that needs a login says when this install has none:
/// every writing command here, and `keys list`, which needs to know whose
/// `keys/` to read.
pub(crate) const NOT_LOGGED_IN: &str =
    "this install is not logged in; run `sweepky login --identity <name>` first";

/// Takes the writers' lock, runs `work` while holding it, then releases it.
///
/// While another command holds the lock, this says so once on standard
/// error and waits (see [`WritersLock::hold`]). `login` holds it around its
/// signup, sign-in and file writes; [`with_writer_session`] around a
/// command's sign-in, writes and sign-out.
pub(crate) async fn with_writers_lock<T>(
    ctx: &Context,
    work: impl AsyncFnOnce() -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let mut lock = WritersLock::open(&ctx.dirs)?;
    lock.hold(
        // The waiting line is a courtesy: if standard error cannot be
        // written, the command still waits and goes on, so the result is
        // dropped with `let _ =`.
        || {
            let _ = ctx.stderr.line(WAITING_FOR_LOCK);
        },
        work,
    )
    .await
}

/// Signs `session` out, revoking the grant behind it. A failure is written to
/// standard error as a warning, never returned.
///
/// Takes `session` by value because the SDK's `signout(self)` consumes it:
/// once signed out, the session cannot be used again. On failure the SDK
/// hands the session back with the error, so it could be retried; here it
/// is simply dropped.
pub(crate) async fn sign_out(ctx: &Context, session: PubkySession) {
    // `(error, _session)` destructures the pair the SDK returns; `_session`
    // is dropped at the end of this block.
    if let Err((error, _session)) = session.signout().await {
        // `request_error` turns the SDK error into fixed text and a status,
        // never the server's words or the request URL. `{:#}` prints its
        // whole chain on one line.
        let _ = ctx.stderr.line(&format!(
            "warning: could not sign out of the homeserver ({:#}); the session's grant stays \
             valid until it expires",
            request_error(&error)
        ));
    }
}

/// A command's signed-in session and the login it belongs to.
///
/// No `Debug`, on purpose: the session holds a credential (see the module
/// docs).
pub(crate) struct WriterSession {
    session: PubkySession,
    login: LoginState,
}

impl WriterSession {
    /// The signed-in session: `session().storage()` reads and writes the
    /// user's own files.
    pub(crate) fn session(&self) -> &PubkySession {
        &self.session
    }

    /// The login this session belongs to, from `login.json`.
    pub(crate) fn login(&self) -> &LoginState {
        &self.login
    }

    /// Signs the session out ([`sign_out`]): a failure is a warning on
    /// standard error. `self` by value, so the session cannot be used after.
    pub(crate) async fn sign_out(self, ctx: &Context) {
        sign_out(ctx, self.session).await;
    }
}

/// Runs `body` with a fresh session for this install's login, under the
/// writers' lock, and signs out afterwards whatever `body` returned.
///
/// `body` is an async closure, and `AsyncFnOnce(&WriterSession) -> …` is the
/// trait such a closure implements when it is called once with a borrowed
/// session. Because the closure only *borrows* the session, it cannot keep
/// it or sign it out itself; this function keeps ownership and signs out
/// once the body's future has finished. The body's own error comes back
/// unchanged.
pub(crate) async fn with_writer_session<T>(
    ctx: &Context,
    body: impl AsyncFnOnce(&WriterSession) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    // `async move ||` moves `body` into this closure, which then calls it
    // once; `ctx` is a reference, so moving it copies the reference.
    with_writers_lock(ctx, async move || {
        let signed_in = sign_in(ctx).await?;
        let result = body(&signed_in).await;
        // The body's borrow of `signed_in` ended with its future, so the
        // session can be moved into the sign-out now, success or failure.
        signed_in.sign_out(ctx).await;
        result
    })
    .await
}

/// Reads `login.json` and the identity it names, and signs in.
///
/// The caller holds the writers' lock and must sign the session out
/// ([`WriterSession::sign_out`]) whatever happens next; prefer
/// [`with_writer_session`], which does both.
pub(crate) async fn sign_in(ctx: &Context) -> anyhow::Result<WriterSession> {
    let (login, secret) = read_logged_in_identity(&ctx.dirs)?;
    // `keypair()` makes a keypair from the secret for the signer, which owns
    // it and wipes it when the signer is dropped at the end of this function.
    // `signin` (unlike `signin_blocking`) also hands a clone of the signer to
    // a short background task that republishes the pkarr record if it is
    // stale; that copy is wiped when the task ends.
    let signer = ctx.network.pubky().signer(secret.keypair());
    let session = signer
        .signin(client_id()?)
        .await
        .map_err(|err| request_error(&err))
        .context("could not sign in to the homeserver")?;
    Ok(WriterSession { session, login })
}

/// `login.json` and the secret of the identity it names, checked to be the
/// key of the pubky logged in. Files only: nothing here touches the network.
fn read_logged_in_identity(dirs: &Dirs) -> anyhow::Result<(LoginState, IdentitySecret)> {
    let Some(login) = read_login_state(dirs)? else {
        bail!(NOT_LOGGED_IN);
    };
    // Only one kind is known so far; P2d makes this a `match` with the Ring
    // branch. The unknown kind's text is not quoted: it is whatever the
    // file holds.
    let Some(KnownLoginKind::Identity) = login.kind.as_known() else {
        bail!(
            "{} records a kind of login this Sweepky does not know; use the Sweepky that wrote \
             it, or a newer one",
            dirs.login_file().display()
        );
    };
    let Some(name) = &login.name else {
        bail!(
            "{} names no identity; run `sweepky login --identity <name>` again",
            dirs.login_file().display()
        );
    };
    // The key file is what signs; the details file is only a cache, so a
    // key without its details still signs in.
    let secret = match read_identity(dirs, name)? {
        StoredIdentity::KeyOnly(secret) | StoredIdentity::Complete { secret, .. } => secret,
        StoredIdentity::Missing => bail!(
            "this install is logged in as the identity {name}, but {} is missing, so it cannot \
             sign in",
            dirs.identity_key_file(name).display()
        ),
    };
    if secret.pubky() != login.pubky {
        bail!(
            "{} is not the key of {}, the pubky this install is logged in as",
            dirs.identity_key_file(name).display(),
            login.pubky
        );
    }
    Ok((login, secret))
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};

    use anyhow::bail;
    use pubky_testnet::EphemeralTestnet;

    use super::with_writer_session;
    use crate::test_support::{dirs_in, private_temp};
    use crate::{Context, Network, StderrWriter};

    /// A writer the test keeps a handle on: the context writes into it, the
    /// test reads what was written. `Arc<Mutex<…>>` is shared ownership of
    /// one buffer, which both sides lock to use.
    #[derive(Clone, Default)]
    struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

    impl SharedBuffer {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().expect("lock").clone()).expect("UTF-8")
        }
    }

    impl Write for SharedBuffer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().expect("lock").write(bytes)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A file under the capability's directory, for the probe writes.
    const PROBE: &str = "/pub/sweepky/session-probe.txt";

    #[tokio::test]
    #[pubky_testnet::test]
    async fn writer_session_signs_in_and_always_signs_out() {
        let testnet = EphemeralTestnet::builder()
            .with_http_relay()
            .build()
            .await
            .expect("testnet starts");
        let temp = private_temp();
        let stderr = SharedBuffer::default();
        let ctx = Context {
            network: Network::injected(
                testnet.sdk().expect("client"),
                format!("{}inbox", testnet.http_relay().local_url()),
                testnet.homeserver_app().public_key(),
            ),
            dirs: dirs_in(&temp),
            stderr: StderrWriter::new(stderr.clone()),
        };

        // Without a login there is no session to open, and the body never
        // runs.
        let mut ran = false;
        let refused = with_writer_session(&ctx, async |_| {
            ran = true;
            Ok(())
        })
        .await;
        assert!(refused.is_err());
        assert!(!ran);

        crate::login::login(&ctx, Some("session-test"), None, None)
            .await
            .expect("login");

        // A body that writes, keeps a copy of the session's handle, then
        // fails. `PubkySession` is `Clone` (it shares one credential), which
        // is what lets the test try the session again after the sign-out.
        let mut kept = None;
        // `::<()>` names the body's success type, which the compiler cannot
        // infer from a body that only ever fails.
        let failed = with_writer_session::<()>(&ctx, async |signed| {
            let session = signed.session();
            assert_eq!(
                session.public_key().to_bytes(),
                *signed.login().pubky.as_bytes()
            );
            session.storage().put(PROBE, "one").await.expect("writes");
            kept = Some(session.clone());
            bail!("the body failed")
        })
        .await;
        let err = failed.expect_err("the body's error comes back");
        assert_eq!(err.to_string(), "the body failed");
        assert_eq!(stderr.text(), "", "the sign-out went through: no warning");

        // Signed out despite the failure: the grant is revoked, so the same
        // session can no longer write.
        let kept = kept.expect("the body ran");
        assert!(
            kept.storage().put(PROBE, "two").await.is_err(),
            "a signed-out session still wrote"
        );

        // A fresh session per command: the next one signs in again and
        // writes.
        with_writer_session(&ctx, async |signed| {
            signed
                .session()
                .storage()
                .put(PROBE, "three")
                .await
                .expect("writes");
            Ok(())
        })
        .await
        .expect("a new session");
    }
}
