//! The session a writing command runs in.
//!
//! Every command that writes to the homeserver (`keys revoke`, `circle`,
//! `post`, `run`, `submit`, `done`, and `pull` for its `discovered.json`)
//! runs its writes inside [`with_writer_session`]:
//!
//! 1. take the writers' lock ([`with_writers_lock`]), so no other `sweepky`
//!    command on this install signs in, restores or writes meanwhile;
//! 2. read `login.json` and open a session for the login it records
//!    ([`sign_in`]):
//!    - **a dedicated identity**: read the identity's key and sign in afresh
//!      with it (`PubkySigner::signin`, never the deprecated cookie
//!      sign-in);
//!    - **a Pubky Ring login**: refuse a grant `login.json` says has expired,
//!      read `grant.token`, restore the session from it
//!      (`Pubky::restore_session`), and check what the homeserver restored:
//!      `login.json`'s pubky, the client id `sweepky-cli`, and write on
//!      `/pub/sweepky/`;
//! 3. run the command's body with the session;
//! 4. end the session, whether the body succeeded or failed
//!    ([`WriterSession::end`]):
//!    - an identity session is **signed out**, so the root grant each
//!      sign-in creates (valid for two years) is revoked again and such
//!      grants do not pile up on the homeserver (03, "Two ways to log in").
//!      A sign-out that fails is a warning, not an error: the body's work is
//!      done by then, and its result is what the command reports;
//!    - a Ring session is **only dropped**, never signed out: signing it out
//!      would revoke the grant Ring approved, and every later command
//!      restores from that same grant;
//! 5. release the lock.
//!
//! **Why writers serialise.** Each Ring restore mints a fresh bearer for the
//! grant and the homeserver drops the one before it, so a command that
//! restored while another was still writing would cut the other off
//! mid-write (02, "Device keys"). Restoring only under the writers' lock
//! makes that impossible on one install.
//!
//! `logout` runs the same steps itself, under [`with_writers_lock`] with
//! [`sign_in`] and [`WriterSession::sign_out`], because it deletes the
//! credential and this install's files after the sign-out and before the
//! lock is released, which a body of [`with_writer_session`] cannot do. Its
//! sign-out is explicit, so it signs out a Ring session too: revoking the
//! grant is what logging out means.
//!
//! **Never `{:?}` a session, a signer or a token.** `PubkySession`'s `Debug`
//! prints its credential's, a signer holds the identity's keypair, and the
//! grant token is the grant's bearer. Nothing here derives or calls `Debug`
//! on any of them, and [`WriterSession`] has no `Debug`.
//!
//! **The passphrase.** The identity's key file, or `grant.token`, may be
//! wrapped with a passphrase (`login --passphrase-file`). Step 2 reads it
//! through [`crate::passphrase`], which unwraps it with the context's
//! passphrase, or says how to give one when there is none.
//!
//! **The expiry warning** is not printed here: `crate::run` prints it once
//! per command, however many sessions the command opens (`run` opens two).

use anyhow::{Context as _, bail};
use pubky::PubkySession;

use crate::clock;
use crate::identity::IdentitySecret;
use crate::lock::WritersLock;
use crate::network::client_id;
use crate::passphrase::Passphrase;
use crate::remote::{pubky_of, request_error};
use crate::ring::token::read_grant_token;
use crate::ring::{check_restored_session, refuse_expired_grant, restore_error};
use crate::state::{KnownLoginKind, LoginState, StoredIdentity, read_identity, read_login_state};
use crate::{Context, Dirs};

/// What a command says while another one holds the writers' lock.
const WAITING_FOR_LOCK: &str =
    "waiting for another sweepky command on this install to finish (it holds the writers' lock)";

/// What a command that needs a login says when this install has none:
/// every writing command here, and `keys list`, which needs to know whose
/// `keys/` to read.
pub(crate) const NOT_LOGGED_IN: &str = "this install is not logged in; run `sweepky login` \
     (through Pubky Ring) or `sweepky login --identity <name>` (a dedicated identity) first";

/// Takes the writers' lock, runs `work` while holding it, then releases it.
///
/// While another command holds the lock, this says so once on standard
/// error and waits (see [`WritersLock::hold`]). `login` holds it around its
/// signup, sign-in and file writes; [`with_writer_session`] around a
/// command's sign-in or restore, writes and sign-out.
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

/// A command's open session and the login it belongs to.
///
/// No `Debug`, on purpose: the session holds a credential (see the module
/// docs).
pub(crate) struct WriterSession {
    session: PubkySession,
    login: LoginState,
    /// How the session was opened, which decides how [`WriterSession::end`]
    /// ends it. A known kind only: [`sign_in`] refuses any other.
    kind: KnownLoginKind,
}

impl WriterSession {
    /// The open session: `session().storage()` reads and writes the user's
    /// own files.
    pub(crate) fn session(&self) -> &PubkySession {
        &self.session
    }

    /// The login this session belongs to, from `login.json`.
    pub(crate) fn login(&self) -> &LoginState {
        &self.login
    }

    /// Signs the session out ([`sign_out`]), whatever its kind: a failure is
    /// a warning on standard error. `self` by value, so the session cannot
    /// be used after. Only `logout` calls this directly, because for a Ring
    /// login it revokes the grant; every other command ends its session
    /// through [`with_writer_session`], which calls [`WriterSession::end`].
    pub(crate) async fn sign_out(self, ctx: &Context) {
        sign_out(ctx, self.session).await;
    }

    /// Ends the session the way an ordinary command must (step 4 of the
    /// module docs): an identity session is signed out, a Ring session is
    /// only dropped, so its grant stays valid for the next command.
    async fn end(self, ctx: &Context) {
        match self.kind {
            KnownLoginKind::Identity => self.sign_out(ctx).await,
            // `drop` ends the value here, which frees the SDK's copy of the
            // bearer without telling the homeserver anything. The next
            // restore replaces that bearer anyway.
            KnownLoginKind::Ring => drop(self),
        }
    }
}

/// Runs `body` with a fresh session for this install's login, under the
/// writers' lock, and ends it afterwards whatever `body` returned: an
/// identity session is always signed out, a Ring session only dropped.
///
/// `body` is an async closure, and `AsyncFnOnce(&WriterSession) -> …` is the
/// trait such a closure implements when it is called once with a borrowed
/// session. Because the closure only *borrows* the session, it cannot keep
/// it or sign it out itself; this function keeps ownership and ends it once
/// the body's future has finished. The body's own error comes back
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
        // session can be moved into `end` now, success or failure.
        signed_in.end(ctx).await;
        result
    })
    .await
}

/// Reads `login.json` and opens a session for the login it records: a
/// fresh sign-in for a dedicated identity, a restore from `grant.token` for
/// a Pubky Ring login (step 2 of the module docs).
///
/// The caller must hold the writers' lock, since a Ring restore replaces
/// the grant's bearer. Prefer [`with_writer_session`], which takes the lock
/// and ends the session; a caller of this must end it itself
/// ([`WriterSession::sign_out`], as `logout` does).
pub(crate) async fn sign_in(ctx: &Context) -> anyhow::Result<WriterSession> {
    let login = read_logged_in(&ctx.dirs)?;
    match login.kind.as_known() {
        Some(KnownLoginKind::Identity) => sign_in_identity(ctx, login).await,
        Some(KnownLoginKind::Ring) => restore_ring(ctx, login).await,
        None => bail!(unknown_kind(&ctx.dirs)),
    }
}

/// `login.json`, refused when there is none. Files only.
fn read_logged_in(dirs: &Dirs) -> anyhow::Result<LoginState> {
    let Some(login) = read_login_state(dirs)? else {
        bail!(NOT_LOGGED_IN);
    };
    Ok(login)
}

/// The refusal of a kind of login this build does not know. The kind is not
/// quoted: it is whatever the file holds.
fn unknown_kind(dirs: &Dirs) -> String {
    format!(
        "{} records a kind of login this Sweepky does not know; use the Sweepky that wrote it, \
         or a newer one",
        dirs.login_file().display()
    )
}

/// Step 2 for a dedicated identity: its key, then a fresh sign-in.
async fn sign_in_identity(ctx: &Context, login: LoginState) -> anyhow::Result<WriterSession> {
    let secret = read_identity_secret(&ctx.dirs, &login, ctx.passphrase.as_ref())?;
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
    Ok(WriterSession {
        session,
        login,
        kind: KnownLoginKind::Identity,
    })
}

/// Step 2 for a Pubky Ring login: everything that can be refused locally
/// first, then the one restore request, then the checks of what came back.
///
/// The token lives in a `GrantToken` (a `SecretString` inside), borrowed as
/// a `&str` only for the `restore_session` call, and wiped when `token` is
/// dropped at the end of this function. A restored session that fails a
/// check is dropped, not signed out: it may be the user's real grant behind
/// a stale `login.json`, and revoking it is `logout`'s decision, not an
/// ordinary command's.
async fn restore_ring(ctx: &Context, login: LoginState) -> anyhow::Result<WriterSession> {
    // The clock first: the SDK reads it during the restore with a function
    // that panics on a clock set before 1970, which this refuses in words.
    let now = clock::now_unix_seconds()?;
    refuse_expired_grant(&login, now)?;
    let Some(token) = read_grant_token(&ctx.dirs, ctx.passphrase.as_ref())? else {
        bail!(
            "{} records a Pubky Ring login, but {} is missing, so there is no grant to restore; \
             put it back from a backup of the config directory, or run `sweepky login` again",
            ctx.dirs.login_file().display(),
            ctx.dirs.grant_token_file().display()
        );
    };
    let session = ctx
        .network
        .pubky()
        .restore_session(token.expose_secret())
        .await
        .map_err(|error| restore_error(&error))?;
    // `as_grant` is `None` for a cookie session; `read_grant_token` only
    // takes a grant token, so this is a second check. The view borrows
    // `session`, and `session_info` hands back an owned copy, so the borrow
    // ends before `session` moves into the `WriterSession` below.
    let Some(grant) = session.as_grant() else {
        bail!("the saved Pubky Ring token did not restore a grant session");
    };
    let info = grant.session_info().await;
    check_restored_session(
        login.pubky,
        pubky_of(&info.pubky),
        info.client_id.as_str(),
        &info.capabilities,
    )?;
    Ok(WriterSession {
        session,
        login,
        kind: KnownLoginKind::Ring,
    })
}

/// The secret of the identity `login` names, checked to be the key of the
/// pubky logged in. Files only: nothing here touches the network. A wrapped
/// key file is unwrapped with `passphrase`, and without one is a
/// [`NeedsPassphrase`](crate::passphrase::NeedsPassphrase) error.
fn read_identity_secret(
    dirs: &Dirs,
    login: &LoginState,
    passphrase: Option<&Passphrase>,
) -> anyhow::Result<IdentitySecret> {
    let Some(name) = &login.name else {
        bail!(
            "{} names no identity; run `sweepky login --identity <name>` again",
            dirs.login_file().display()
        );
    };
    // The key file is what signs; the details file is only a cache, so a
    // key without its details still signs in.
    let secret = match read_identity(dirs, name, passphrase)? {
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
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use anyhow::bail;
    use pubky_testnet::EphemeralTestnet;
    use tempfile::TempDir;

    use super::{read_identity_secret, read_logged_in, with_writer_session};
    use crate::identity::{IdentityMeta, IdentityName, IdentitySecret};
    use crate::passphrase::{NeedsPassphrase, Passphrase};
    use crate::ring::token::{GrantToken, read_grant_token, write_grant_token};
    use crate::ring::{ExpiryNotice, GRANT_NOT_ACCEPTED};
    use crate::state::{LoginState, create_identity, read_login_state, write_login_state};
    use crate::test_support::{
        PLANTED, RingPage, RingStandIn, SharedBuffer, TEST_PASSPHRASE, dirs_in, offline_network,
        private_temp, random_pubky, ring_context, ring_network, ring_testnet, test_context,
    };
    use crate::{CLIENT_ID, Context, Network, clock};

    #[test]
    fn wrapped_identity_signs_in_only_with_its_passphrase() {
        // What `sign_in` reads before it signs in: login.json and the key of
        // the identity it names, here wrapped.
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        let name: IdentityName = "throwaway".parse().expect("valid");
        let secret = IdentitySecret::generate();
        let meta = IdentityMeta::new(name.clone(), secret.pubky(), random_pubky(), true);
        let passphrase = Passphrase::for_tests(TEST_PASSPHRASE);
        create_identity(&dirs, &secret, &meta, Some(&passphrase)).expect("creates");
        write_login_state(
            &dirs,
            &LoginState::identity(name.clone(), meta.pubky, meta.homeserver),
        )
        .expect("writes");

        let login = read_logged_in(&dirs).expect("reads");
        assert_eq!(login.pubky, meta.pubky);
        let read = read_identity_secret(&dirs, &login, Some(&passphrase)).expect("unwraps");
        assert_eq!(read.pubky(), meta.pubky);

        // Without the passphrase there is nothing to sign in with, and the
        // error says how to give it.
        let error = read_identity_secret(&dirs, &login, None)
            .err()
            .expect("refused");
        assert!(error.is::<NeedsPassphrase>(), "{error:#}");
        assert!(
            format!("{error:#}").contains(&dirs.identity_key_file(&name).display().to_string()),
            "{error:#}"
        );
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
        // `io::empty()` as standard input: nothing here asks a question.
        let (ctx, stderr) = test_context(
            Network::injected(
                testnet.sdk().expect("client"),
                format!("{}inbox", testnet.http_relay().local_url()),
                testnet.homeserver_app().public_key(),
            ),
            &temp,
            io::empty(),
        );

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

    /// What every expiry notice says, soon or expired.
    const EXPIRY_LINE: &str = "Pubky Ring grant";

    /// A Ring login on `testnet` in a fresh install under `home`, approved
    /// by a new [`RingStandIn`], returned with the install's context, its
    /// standard error and the stand-in.
    async fn ring_login(
        testnet: &EphemeralTestnet,
        home: &TempDir,
    ) -> (Context, SharedBuffer, RingStandIn) {
        let (ctx, stderr, mut urls) = ring_context(ring_network(testnet), home, io::empty());
        let ring = RingStandIn::sign_up(testnet).await;
        let (logged_in, ()) = tokio::join!(crate::login::login(&ctx, None, None, None), async {
            let page = RingPage::open(&mut urls).await;
            ring.approve(&page).await;
        });
        logged_in.expect("logs in through the stand-in");
        (ctx, stderr, ring)
    }

    /// Rewrites `login.json`'s `grantExpiresAt` to `now + offset` seconds
    /// (`offset` may be negative), keeping every other field.
    fn set_grant_expiry(ctx: &Context, offset: i64) {
        let mut login = read_login_state(&ctx.dirs)
            .expect("reads")
            .expect("logged in");
        let now = clock::now_unix_seconds().expect("a clock");
        login.grant_expires_at = Some(now.checked_add_signed(offset).expect("in range"));
        write_login_state(&ctx.dirs, &login).expect("writes");
    }

    #[tokio::test]
    #[pubky_testnet::test]
    async fn a_ring_session_is_restored_and_only_dropped() {
        let testnet = ring_testnet().await;
        let home = private_temp();
        let (ctx, stderr, ring) = ring_login(&testnet, &home).await;
        // Ten days left: the dispatch would warn, but a session never does.
        set_grant_expiry(&ctx, 10 * 86_400);
        let said_before = stderr.text().len();

        // The body writes under /pub/sweepky/ with the restored session, as
        // the pubky login.json records, and keeps a copy of its handle.
        let mut kept = None;
        with_writer_session(&ctx, async |signed| {
            let session = signed.session();
            assert_eq!(
                session.public_key().to_bytes(),
                *signed.login().pubky.as_bytes()
            );
            session.storage().put(PROBE, "one").await.expect("writes");
            kept = Some(session.clone());
            Ok(())
        })
        .await
        .expect("restores and writes");

        // Not signed out: Ring still lists the one sweepky-cli grant, and
        // the saved token restores again for the next command, which writes.
        assert_eq!(ring.active_grants_for(CLIENT_ID).await.len(), 1);
        with_writer_session(&ctx, async |signed| {
            signed
                .session()
                .storage()
                .put(PROBE, "two")
                .await
                .expect("writes");
            Ok(())
        })
        .await
        .expect("the token still restores");

        // The second restore replaced the grant's bearer, so the copy kept
        // from the first session can no longer write. That is why writers
        // take the lock: a restore in the middle of another command's
        // writes would cut it off.
        let kept = kept.expect("the body ran");
        assert!(
            kept.storage().put(PROBE, "three").await.is_err(),
            "a replaced bearer still wrote"
        );

        // Two sessions, and neither printed the expiry line: that is the
        // dispatch's, once per command.
        let said = stderr.text();
        let said = said.get(said_before..).expect("only grows");
        assert!(!said.contains(EXPIRY_LINE), "{said}");
    }

    #[tokio::test]
    #[pubky_testnet::test]
    async fn two_ring_writers_at_once_take_turns() {
        let testnet = ring_testnet().await;
        let home = private_temp();
        let (ctx, _stderr, _ring) = ring_login(&testnet, &home).await;

        // `inside` is set while a body runs. Each body checks it was clear,
        // writes, waits a little so an overlap would show, and clears it.
        let inside = AtomicBool::new(false);
        let writer = |text: &'static str| {
            let inside = &inside;
            let ctx = &ctx;
            async move {
                with_writer_session(ctx, async |signed| {
                    assert!(
                        !inside.swap(true, Ordering::SeqCst),
                        "the bodies overlapped"
                    );
                    signed
                        .session()
                        .storage()
                        .put(PROBE, text)
                        .await
                        .expect("writes");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    signed
                        .session()
                        .storage()
                        .put(PROBE, text)
                        .await
                        .expect("still writes: no restore replaced the bearer meanwhile");
                    inside.store(false, Ordering::SeqCst);
                    Ok(())
                })
                .await
            }
        };
        let (first, second) = tokio::join!(writer("first"), writer("second"));
        first.expect("the first writer succeeds");
        second.expect("the second writer succeeds");
    }

    #[tokio::test]
    #[pubky_testnet::test]
    async fn a_revoked_grant_says_to_log_in_again() {
        let testnet = ring_testnet().await;
        let home = private_temp();
        let (ctx, _stderr, _ring) = ring_login(&testnet, &home).await;
        // The grant is revoked behind this install's back: the test
        // restores the saved token and signs it out.
        let token = read_grant_token(&ctx.dirs, None)
            .expect("reads")
            .expect("saved");
        let Ok(session) = testnet
            .sdk()
            .expect("client")
            .restore_session(token.expose_secret())
            .await
        else {
            panic!("the saved token does not restore");
        };
        if session.signout().await.is_err() {
            panic!("the test's sign-out failed");
        }

        let mut ran = false;
        let refused = with_writer_session(&ctx, async |_| {
            ran = true;
            Ok(())
        })
        .await;
        let shown = format!("{:#}", refused.expect_err("refused"));
        assert!(!ran);
        // The fixed text alone: no SDK words, and never the token.
        assert_eq!(shown, GRANT_NOT_ACCEPTED);
        assert!(shown.contains("`sweepky login`"), "{shown}");
        assert!(!shown.contains(token.expose_secret()), "{shown}");
    }

    #[tokio::test]
    async fn an_expired_grant_is_refused_before_any_request() {
        let home = private_temp();
        // An offline network: a restore sent would fail with a network
        // error, not the expiry's text.
        let (ctx, stderr) = test_context(offline_network(), &home, io::empty());
        let expired_at = 1_000_000_000;
        write_login_state(
            &ctx.dirs,
            &LoginState::ring(random_pubky(), random_pubky(), expired_at),
        )
        .expect("writes");
        let token = GrantToken::from_exported(format!("pubky-grant-credential-v1:{PLANTED}"))
            .expect("a synthetic token");
        write_grant_token(&ctx.dirs, &token, None).expect("writes");

        let mut ran = false;
        let refused = with_writer_session(&ctx, async |_| {
            ran = true;
            Ok(())
        })
        .await;
        let shown = format!("{:#}", refused.expect_err("refused"));
        assert!(!ran);
        assert_eq!(
            shown,
            ExpiryNotice::Expired {
                expires_at: expired_at
            }
            .to_string()
        );
        assert!(!shown.contains(PLANTED), "{shown}");
        // The session printed nothing itself.
        assert_eq!(stderr.text(), "");
    }
}
