//! `sweepky login` without `--identity`: login option A, the Pubky Ring
//! sign-in, from the checks before the flow to the report (03, "Two ways to
//! log in"). The same command logs an install already logged in through
//! Ring in again, as the same pubky: the way past a grant revoked in Ring or
//! about to expire (02, "Device keys").
//!
//! In order ([`login`]):
//!
//! 1. **Checks before any request** ([`check_before_flow`]), files only:
//!    - With no `login.json`, a first Ring login: nothing may be at
//!      `device.key`, which `login.json` would then not record (P2a's rule
//!      that Sweepky never replaces a device key, run here before the human
//!      scans a code rather than after). Only the path is looked at, so a
//!      wrapped key file stops the login the same way without
//!      `--passphrase-file`. A `grant.token` that no `login.json` records
//!      (an orphan) is noted, not refused.
//!    - With a Ring `login.json`, a re-login: `device.key` is read and
//!      unwrapped, as the reuse of this install's key will need, and
//!      `grant.token`, the grant it replaces, is read too, so a wrapped file
//!      without `--passphrase-file` stops it before there is anything to
//!      scan.
//!    - An `--identity` login (or a kind this build does not know) is told
//!      to log out first or use another `SWEEPKY_HOME`.
//! 2. **The approval** ([`sign_in_with_ring`]), with no lock held: a human
//!    may take minutes to scan, and every other command on the install
//!    would wait for the lock that long. It asks no question on standard
//!    input, so `--no-input` does not stop it.
//! 3. **What the grant is** ([`ApprovedGrant::of`]): its pubky, homeserver
//!    and expiry, as the homeserver reports them with the session, and the
//!    grant token the SDK exports, moved into a [`GrantToken`] in the same
//!    statement.
//! 4. **Under the writers' lock** ([`save_grant`]): the files read again,
//!    since another login or logout may have finished meanwhile; for a
//!    re-login, the approving pubky must be the one `login.json` names; the
//!    new token saved to `grant.token` (0600, wrapped with
//!    `--passphrase-file`), the token it replaces held in memory; then P2a's
//!    shared tail with the grant's session (`login`'s
//!    [`record_login_and_check_keys`]): on a first login this install's
//!    device key made, saved, recorded and published as
//!    `keys/<deviceId>.json`, the write that proves the grant can write
//!    `/pub/sweepky/`; on a re-login the key `login.json` records reused,
//!    never replaced; then `login.json` written as a `ring` login with the
//!    new grant's expiry, then the check of `keys/`. Last, the grant the
//!    new one replaces is revoked ([`revoke_replaced`]).
//! 5. **The report** ([`report`]): who and where, the grant's expiry in RFC
//!    3339 and that it is two years from approval, the device key and the
//!    reminder to back up the config directory, the files wrapped, what
//!    became of the grant replaced, and the key check.
//!
//! **Ordering.** `login.json` never names a Ring login whose token is not
//! on disk: the token is written just before the tail, and the tail writes
//! `login.json` last. Nothing the user will not use stays valid: a grant
//! that is not saved (its details cannot be read, the lock cannot be
//! taken, another pubky approved a re-login, or the tail failed) is signed
//! out, which revokes it on the homeserver, and `grant.token` is put back
//! as it was. A grant that is saved is *not* signed out, since that would
//! revoke it; its session is dropped, and later commands restore it from
//! the token. The grant it replaces is revoked only once the new token and
//! `login.json` are both on disk, so a crash in between leaves an install
//! that still works with one of the two grants.
//!
//! **Secrets.** Neither a token nor the sign-in link is ever printed: the
//! report names the token's file only, and every SDK error reaches the
//! user through `remote::request_error` or `remote::write_error`, in fixed
//! text.

use anyhow::{Context as _, anyhow, bail};
use pubky::{PubkySession, PublicKey, StatusCode};
use sweepky_core::{DeviceId, Pubky, Zeroizing};

use super::flow::{LOGIN_TIMEOUT, sign_in_with_ring};
use super::token::{GrantToken, read_grant_token, remove_grant_token, write_grant_token};
use super::{GrantRevocation, Restored, expired_grant_at, expiry_text, revoke_grant};
use crate::clock;
use crate::device::{KeyIds, KeyStore, PublicKeys, SessionKeyStore, refuse_unrecorded_device_key};
use crate::login::{
    DeviceKeyOutcome, TailOutcome, device_key_report, read_recorded_device_key,
    record_login_and_check_keys, wrapped_report,
};
use crate::passphrase::Passphrase;
use crate::private_fs::lstat;
use crate::remote::{pubky_of, request_error, status_of};
use crate::session::{sign_out, with_writers_lock};
use crate::state::{KnownLoginKind, LoginState, read_login_state};
use crate::{Context, Dirs, Report};

/// What the error of a login that saved nothing says, once the grant Ring
/// approved has been signed out again.
const NOT_SAVED: &str = "login saved nothing and signed the grant Pubky Ring approved out again, \
     which revokes it";

/// Why the grant a login replaced is not known to be revoked, when its
/// sign-out failed or a restore after it did not get a 401.
const REVOKE_NOT_CONFIRMED: &str = "its sign-out was not confirmed";

/// Runs `sweepky login` without `--identity`: steps 1 to 5 of the module
/// docs.
pub(crate) async fn login(ctx: &Context) -> anyhow::Result<Report> {
    // 1. Files only, before any request. They are read again under the
    // lock, where they count.
    check_before_flow(&ctx.dirs, ctx.passphrase.as_ref())?;
    // 2. No lock held while the human scans.
    let session = sign_in_with_ring(ctx, LOGIN_TIMEOUT).await?;
    // 3. A grant whose details cannot be read is not saved, so it is
    // signed out before the error is returned.
    let grant = match ApprovedGrant::of(&session).await {
        Ok(grant) => grant,
        Err(error) => {
            sign_out(ctx, session).await;
            return Err(error.context(NOT_SAVED));
        }
    };
    // 4. The store owns the session from here, so whichever way
    // `save_grant` ends, it decides the session's fate: signed out on a
    // failure, dropped (still valid) on success.
    let keys = GrantKeyStore {
        session,
        client: ctx.network.pubky(),
    };
    let saved = save_grant(ctx, &grant, keys, async |keys| {
        sign_out(ctx, keys.session).await;
    })
    .await?;
    // 5.
    Ok(Report::new(report(ctx, &grant, &saved)))
}

// ---------------------------------------------------------------------------
// Before the flow, and again under the lock.

/// What this install holds before a Ring login, from its files.
///
/// No `Debug`: a re-login holds the saved grant's token, which has none.
enum Install {
    /// No `login.json`: a first Ring login. `orphan_token` says whether a
    /// `grant.token` is there all the same, as a login that stopped between
    /// the token's write and `login.json`'s leaves it.
    Free { orphan_token: bool },
    /// Logged in through Ring already: a re-login, which only the pubky
    /// `login` names may approve (P2a's rule that only the identity logged
    /// in may log in again). `old_token` is the saved grant's token, `None`
    /// when `grant.token` is missing.
    Ring {
        login: LoginState,
        old_token: Option<GrantToken>,
    },
}

/// Reads what this install holds ([`Install`]), files only, refusing an
/// install that a Ring login cannot take: one logged in with `--identity`
/// (or with a kind this build does not know), and one with a `device.key`
/// that `login.json` does not record.
///
/// A re-login's `grant.token` is read and unwrapped here, so a wrapped file
/// without `--passphrase-file`, or a file that is not a token, stops the
/// login with its own error. A first login's orphan is only looked at.
fn read_install(dirs: &Dirs, passphrase: Option<&Passphrase>) -> anyhow::Result<Install> {
    let Some(login) = read_login_state(dirs)? else {
        refuse_unrecorded_device_key(dirs)?;
        return Ok(Install::Free {
            orphan_token: lstat(&dirs.grant_token_file())?.is_some(),
        });
    };
    if login.kind.as_known() != Some(KnownLoginKind::Ring) {
        bail!(already_logged_in(&login));
    }
    // A Ring `login.json` with no device id is one whose tail never
    // finished, so the tail will make a key: the first login's rule applies.
    // With one, the tail reuses that key and reads `device.key` itself.
    if login.device_id.is_none() {
        refuse_unrecorded_device_key(dirs)?;
    }
    let old_token = read_grant_token(dirs, passphrase)?;
    Ok(Install::Ring { login, old_token })
}

/// Step 1: [`read_install`], and for a re-login the read of `device.key`
/// that the tail's reuse will make, so a missing or wrapped key file stops
/// the login with P2a's own error (such as `NeedsPassphrase`'s) before
/// there is a code to scan. The key is dropped, and wiped, at once.
fn check_before_flow(dirs: &Dirs, passphrase: Option<&Passphrase>) -> anyhow::Result<()> {
    if let Install::Ring { login, .. } = read_install(dirs, passphrase)?
        && let Some(id) = &login.device_id
    {
        read_recorded_device_key(dirs, passphrase, id)?;
    }
    Ok(())
}

/// The refusal for an install whose `login.json` records a login that a
/// Ring login cannot replace. The name and the pubky are values this
/// install wrote itself and checked when reading them, so they are safe to
/// print.
fn already_logged_in(current: &LoginState) -> String {
    match (current.kind.as_known(), &current.name) {
        (Some(KnownLoginKind::Identity), Some(name)) => format!(
            "this install is logged in with the dedicated identity {name}, pubky {}, so it \
             cannot also log in through Pubky Ring; run `sweepky logout` first, or set \
             SWEEPKY_HOME to another directory to keep a Ring login apart",
            current.pubky
        ),
        _ => format!(
            "this install is already logged in as {}; run `sweepky logout` first to log in \
             through Pubky Ring, or set SWEEPKY_HOME to another directory to keep a second \
             login apart",
            current.pubky
        ),
    }
}

/// The refusal of a re-login that Ring approved for another pubky than the
/// one `login.json` names. Only `login.json`'s pubky is printed, never the
/// approver's, which is the server's word.
fn approved_by_another_pubky(current: &LoginState) -> String {
    format!(
        "this install is already logged in through Pubky Ring as {pubky}, but Ring approved this \
         login for another pubky, so Sweepky changed nothing; approve it in Ring as {pubky} to \
         log in again, or run `sweepky logout` first to log in as another pubky",
        pubky = current.pubky
    )
}

// ---------------------------------------------------------------------------
// The approved grant.

/// What `login` keeps of the grant Ring approved: the token, and the public
/// details `login.json` records.
///
/// No `Debug`: the token has none, so the compiler could not derive one.
struct ApprovedGrant {
    /// The grant token the SDK exported, the bearer of the grant.
    token: GrantToken,
    /// The pubky that approved, as the homeserver reports it.
    pubky: Pubky,
    /// The homeserver that issued the session.
    homeserver: Pubky,
    /// When the grant expires, Unix seconds: the grant's `exp`.
    expires_at: u64,
}

impl ApprovedGrant {
    /// Reads the grant behind `session`: its details from the homeserver's
    /// session info, and its exported token.
    async fn of(session: &PubkySession) -> anyhow::Result<Self> {
        // `as_grant` is `None` for a cookie session, which a grant flow never
        // gives; the view it returns borrows `session`.
        let Some(grant) = session.as_grant() else {
            bail!("the Pubky Ring sign-in did not give a grant session");
        };
        let info = grant.session_info().await;
        // `export_local_secret` hands the token back as a plain `String`.
        // `map` moves it straight into `GrantToken::from_exported`, which
        // wipes the `String` once its one copy is in a `SecretString`, all in
        // this one statement, so no variable ever holds it as plain text.
        // `transpose` turns the `Option<Result<_>>` into a `Result<Option<_>>`
        // for the `?`. `None` is a browser-held client key, which a CLI
        // never has.
        let Some(token) = grant
            .export_local_secret()
            .await
            .map(GrantToken::from_exported)
            .transpose()?
        else {
            bail!("the Pubky SDK handed back no grant token to save");
        };
        Ok(Self {
            token,
            pubky: pubky_of(&info.pubky),
            homeserver: pubky_of(&info.homeserver),
            expires_at: info.grant_expires_at,
        })
    }
}

/// The approved grant's session, owned, as the [`KeyStore`] the shared tail
/// writes through.
///
/// [`SessionKeyStore`] only borrows a session, so a store made from one
/// would keep the session borrowed for as long as the store lives, and the
/// sign-out after a failed tail, which takes the session by value, could
/// not run. Owning it here lets [`save_grant`] hand the whole store to the
/// sign-out instead. Each call makes a borrowing store on the spot, which
/// costs nothing (two references).
///
/// No `Debug`: the session holds the grant's credential.
struct GrantKeyStore<'a> {
    session: PubkySession,
    client: &'a pubky::Pubky,
}

impl GrantKeyStore<'_> {
    /// A store borrowing this one's session and client.
    fn borrowed(&self) -> SessionKeyStore<'_> {
        SessionKeyStore::new(&self.session, self.client)
    }
}

impl PublicKeys for GrantKeyStore<'_> {
    async fn list_key_ids(&self, owner: &PublicKey) -> anyhow::Result<KeyIds> {
        self.borrowed().list_key_ids(owner).await
    }

    async fn get_key(
        &self,
        owner: &PublicKey,
        id: &DeviceId,
    ) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
        self.borrowed().get_key(owner, id).await
    }
}

impl KeyStore for GrantKeyStore<'_> {
    async fn get_own_key(&self, id: &DeviceId) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
        self.borrowed().get_own_key(id).await
    }

    async fn put_key(&self, id: &DeviceId, record: Vec<u8>) -> pubky::Result<()> {
        self.borrowed().put_key(id, record).await
    }
}

// ---------------------------------------------------------------------------
// Saving it, under the writers' lock.

/// What [`save_grant`] did.
#[derive(Debug)]
struct Saved {
    /// What the shared tail did.
    tail: TailOutcome,
    /// What became of the grant the new one replaced.
    replaced: ReplacedGrant,
}

/// The `grant.token` a login writes over: held in memory from before the
/// write until the new login is saved, to put back if it is not, and to
/// revoke if it is.
///
/// No `Debug`: it holds a token.
enum Replaced {
    /// No `grant.token` was there.
    Nothing,
    /// An orphan `grant.token` that could not be read (wrapped, with no
    /// `--passphrase-file`, or not a token), and why. Its grant cannot be
    /// revoked from here.
    Unreadable(anyhow::Error),
    /// The token of the grant replaced. `expired` is true when `login.json`
    /// says that grant has expired, so there is nothing left to revoke.
    Token { token: GrantToken, expired: bool },
}

/// What became of the grant a login replaced, once the new one was saved.
#[derive(Debug)]
enum ReplacedGrant {
    /// There was none.
    Nothing,
    /// Signed out, and its token now restores to a 401.
    Revoked,
    /// It had been revoked or had expired already.
    AlreadyEnded,
    /// It may still be live, for this reason (fixed text): a warning, since
    /// the new login is saved and works.
    NotRevoked(anyhow::Error),
}

/// Saves `grant` under the writers' lock ([`save_locked`]), with `keys` as
/// the grant's session; and when that fails, for any reason, signs the
/// grant out through `sign_out` before the error is returned.
///
/// Generic over the [`KeyStore`] `K`, with the sign-out passed in as an
/// async closure, as `logout::retire` does, so the unit tests run it with
/// a fake store and see whether, and how often, it signs out. The lock
/// work only borrows `keys` (`&keys`); that borrow ends when the work's
/// future is done, so `keys` can then move into `sign_out`, which takes it
/// by value and so ends the session. On success `keys` is dropped at the
/// end of this function instead, and the grant stays valid.
async fn save_grant<K: KeyStore>(
    ctx: &Context,
    grant: &ApprovedGrant,
    keys: K,
    sign_out: impl AsyncFnOnce(K),
) -> anyhow::Result<Saved> {
    let saved = with_writers_lock(ctx, async || save_locked(ctx, grant, &keys).await).await;
    if saved.is_err() {
        sign_out(keys).await;
    }
    saved.context(NOT_SAVED)
}

/// [`save_grant`]'s work under the lock: the files read again, the pubky
/// checked, the token written, the shared tail, and then the grant
/// replaced revoked.
///
/// A tail that fails puts `grant.token` back as it was: the tail has rolled
/// its own files back by then and left `login.json` as it was, so the new
/// token would be a secret nothing uses, and the old one is what
/// `login.json` still records. The grant replaced is revoked only after the
/// tail, which writes `login.json` last, has succeeded, and a failure to
/// revoke it is a warning in the report, never an error: the new login
/// works either way.
async fn save_locked(
    ctx: &Context,
    grant: &ApprovedGrant,
    keys: &impl KeyStore,
) -> anyhow::Result<Saved> {
    let dirs = &ctx.dirs;
    let passphrase = ctx.passphrase.as_ref();
    // The clock before any restore below: the SDK reads it during one with
    // a function that panics on a clock set before 1970, which this
    // refuses in words.
    let now = clock::now_unix_seconds()?;
    let (state, replaced) = plan_save(dirs, passphrase, grant, now)?;
    write_grant_token(dirs, &grant.token, passphrase)?;
    let tail = match record_login_and_check_keys(dirs, passphrase, keys, state).await {
        Ok(tail) => tail,
        Err(error) => return Err(put_back(dirs, &replaced, passphrase, error)),
    };
    // The new token and `login.json` are on disk (both synced) by now.
    let replaced = end_replaced(ctx.network.pubky(), replaced).await;
    Ok(Saved { tail, replaced })
}

/// What [`save_locked`] writes, from what is on disk now (another login or
/// logout may have finished while the human was scanning): the
/// `login.json` the tail is given, and the `grant.token` the new one
/// replaces. A re-login approved by another pubky is refused here, before
/// anything is written.
fn plan_save(
    dirs: &Dirs,
    passphrase: Option<&Passphrase>,
    grant: &ApprovedGrant,
    now: u64,
) -> anyhow::Result<(LoginState, Replaced)> {
    let fresh = LoginState::ring(grant.pubky, grant.homeserver, grant.expires_at);
    Ok(match read_install(dirs, passphrase)? {
        Install::Free { orphan_token } if orphan_token => (fresh, read_orphan(dirs, passphrase)),
        Install::Free { .. } => (fresh, Replaced::Nothing),
        Install::Ring { login, old_token } => {
            // `Pubky`'s `==` compares the keys' bytes.
            if login.pubky != grant.pubky {
                bail!(approved_by_another_pubky(&login));
            }
            let replaced = match old_token {
                Some(token) => Replaced::Token {
                    token,
                    expired: expired_grant_at(&login, now).is_some(),
                },
                None => Replaced::Nothing,
            };
            (relogin_state(login, fresh), replaced)
        }
    })
}

/// A first login's orphan `grant.token`, read before the new token is
/// written over it; when it cannot be read, why, which the report gives.
fn read_orphan(dirs: &Dirs, passphrase: Option<&Passphrase>) -> Replaced {
    match read_grant_token(dirs, passphrase) {
        Ok(Some(token)) => Replaced::Token {
            token,
            expired: false,
        },
        // Gone since it was looked at.
        Ok(None) => Replaced::Nothing,
        Err(error) => Replaced::Unreadable(error),
    }
}

/// Ends the grant `replaced` holds, once the new login is saved: revoked
/// when there is a live one ([`revoke_replaced`]), and otherwise what the
/// report says of it. `replaced` is taken by value, so the token it holds
/// is dropped, and wiped, here.
async fn end_replaced(client: &pubky::Pubky, replaced: Replaced) -> ReplacedGrant {
    match replaced {
        Replaced::Nothing => ReplacedGrant::Nothing,
        Replaced::Unreadable(error) => ReplacedGrant::NotRevoked(error),
        // A grant past its `grantExpiresAt` sends no request at all.
        Replaced::Token { expired: true, .. } => ReplacedGrant::AlreadyEnded,
        Replaced::Token { token, .. } => revoke_replaced(client, &token).await,
    }
}

/// The `login.json` a re-login writes: `current`, this install's, with the
/// new grant's homeserver and expiry, so its device id, and any field a
/// newer Sweepky wrote, are kept. The kept device id is what makes the
/// shared tail reuse this install's key rather than make one.
fn relogin_state(current: LoginState, fresh: LoginState) -> LoginState {
    // Struct update syntax: the fields named here come from `fresh`, every
    // other one is moved out of `current`.
    LoginState {
        homeserver: fresh.homeserver,
        grant_expires_at: fresh.grant_expires_at,
        ..current
    }
}

/// `cause`, why the tail stopped, after `grant.token` is put back as it was
/// before this login: the token `replaced` holds written back (wrapped with
/// `passphrase` when there is one), or the file removed when there was none
/// to put back. A failure to do that is added to the error.
fn put_back(
    dirs: &Dirs,
    replaced: &Replaced,
    passphrase: Option<&Passphrase>,
    cause: anyhow::Error,
) -> anyhow::Error {
    let file = dirs.grant_token_file();
    let (restored, advice) = match replaced {
        Replaced::Token { token, .. } => (
            write_grant_token(dirs, token, passphrase),
            "run `sweepky login` again",
        ),
        Replaced::Nothing | Replaced::Unreadable(_) => {
            (remove_grant_token(dirs), "delete it by hand")
        }
    };
    match restored {
        Ok(()) => cause,
        Err(left) => cause.context(format!(
            "could not put {} back as it was before this login ({left:#}); {advice}",
            file.display()
        )),
    }
}

/// Revokes the grant behind `token`, the one a login replaced, through
/// `ring::revoke_grant`, the helper `logout` uses: restore, sign out (which
/// revokes it), then a restore that must get a 401. Nothing needs the old
/// session but its sign-out, so the live-session work does nothing.
///
/// Never an error: whatever goes wrong becomes
/// [`ReplacedGrant::NotRevoked`], a warning, since the new login is
/// saved by now.
async fn revoke_replaced(client: &pubky::Pubky, token: &GrantToken) -> ReplacedGrant {
    let revoked = revoke_grant(
        async || restore_replaced(client, token).await,
        // The type of the borrowed session is spelled out, since nothing in
        // the body tells the compiler what it is.
        async |_session: &PubkySession| anyhow::Ok(()),
        async |session: PubkySession| {
            // The SDK hands the session back with its error; the pattern
            // drops it.
            session
                .signout()
                .await
                .map_err(|(error, _session)| request_error(&error))
        },
    )
    .await;
    match revoked {
        Ok(GrantRevocation::Revoked(())) => ReplacedGrant::Revoked,
        Ok(GrantRevocation::AlreadyRevoked) => ReplacedGrant::AlreadyEnded,
        Ok(GrantRevocation::NotConfirmed) => {
            ReplacedGrant::NotRevoked(anyhow!(REVOKE_NOT_CONFIRMED))
        }
        Err(error) => ReplacedGrant::NotRevoked(error),
    }
}

/// One restore from `token`, the replaced grant's, held in memory since its
/// file now holds the new one: a 401 is [`Restored::Refused`], which is how
/// a revoked grant shows; any other error is `request_error`'s fixed text.
///
/// Unlike a writing command's restore, nothing is checked about the session
/// that comes back: it is only ever signed out, which ends whatever grant
/// the token holds, and an orphan's may belong to another pubky. The token
/// is lent as a `&str` for the one call and stays in its `SecretString`.
async fn restore_replaced(
    client: &pubky::Pubky,
    token: &GrantToken,
) -> anyhow::Result<Restored<PubkySession>> {
    match client.restore_session(token.expose_secret()).await {
        Ok(session) => Ok(Restored::Live(session)),
        // A match guard: this arm takes only an error whose status is 401.
        Err(error) if status_of(&error) == Some(StatusCode::UNAUTHORIZED) => Ok(Restored::Refused),
        Err(error) => Err(request_error(&error)),
    }
}

// ---------------------------------------------------------------------------
// The report.

/// What `login` reports after a Ring login: fixed text, the user's own
/// pubky, homeserver and paths, and the grant's expiry.
fn report(ctx: &Context, grant: &ApprovedGrant, saved: &Saved) -> String {
    let dirs = &ctx.dirs;
    let token_file = dirs.grant_token_file();
    let mut text = format!(
        "Logged in through Pubky Ring as {}, on homeserver {}.\n\
         Saved the grant token in {}. The grant expires at {}, two years from your approval in \
         Ring, a lifetime the Pubky SDK fixes; Sweepky warns within 30 days of it, and `sweepky \
         login` then approves a new one.\n",
        grant.pubky,
        grant.homeserver,
        token_file.display(),
        expiry_text(grant.expires_at)
    );
    match &saved.replaced {
        // Nothing to say: no earlier grant, or one already dead.
        ReplacedGrant::Nothing | ReplacedGrant::AlreadyEnded => {}
        ReplacedGrant::Revoked => text.push_str(
            "Revoked the earlier sweepky-cli grant this install held; restoring its token now \
             gets 401.\n",
        ),
        ReplacedGrant::NotRevoked(why) => text.push_str(&format!(
            "warning: could not revoke the earlier sweepky-cli grant this install held ({why:#}); \
             it may still be listed in Pubky Ring, so revoke the older sweepky-cli grant there.\n"
        )),
    }
    text.push_str(&device_key_report(dirs, &saved.tail.device));
    // With a passphrase, the files this run wrote are wrapped: always the
    // token, and `device.key` only when the tail made a new key. A re-login
    // reuses the key and leaves its file as it is.
    if ctx.passphrase.is_some() {
        let mut wrapped = vec![token_file];
        if matches!(saved.tail.device, DeviceKeyOutcome::Published(_)) {
            wrapped.push(dirs.device_key_file());
        }
        text.push_str(&wrapped_report(&wrapped));
    }
    text.push_str(&saved.tail.key_check);
    text
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{self, Cursor};
    use std::time::{SystemTime, UNIX_EPOCH};

    use clap::Parser as _;
    use pubky::{Capabilities, StatusCode};
    use serde_json::Value;
    use sweepky_core::{
        DeviceId, DeviceIdentity, DeviceKey, MAX_RECORD_BYTES, RecordTime, SecretString,
        looks_wrapped,
    };
    use tokio::sync::mpsc::UnboundedReceiver;
    use tokio::sync::mpsc::error::TryRecvError;
    use url::Url;

    use super::{ApprovedGrant, NOT_SAVED, approved_by_another_pubky, save_grant};
    use crate::cli::Cli;
    use crate::device::{
        PublicKeyReader, PublicKeys as _, create_device_key, device_key_bytes, device_key_record,
        holds_key, read_device_key,
    };
    use crate::identity::IdentityName;
    use crate::installs::read_installs;
    use crate::passphrase::Passphrase;
    use crate::private_fs::{ensure_private_dir, lstat};
    use crate::remote::{WRITE_FORBIDDEN, pubky_of, status_of};
    use crate::ring::expiry_text;
    use crate::ring::flow::NARROWED_GRANT;
    use crate::ring::token::{GrantToken, read_grant_token, write_grant_token};
    use crate::state::{LoginState, read_login_state, write_login_state};
    use crate::test_support::{
        FAKE_SERVER_TEXT, FakeKeyStore, FileSnapshot, KeyStoreCall, PLANTED, RingPage, RingStandIn,
        TEST_PASSPHRASE, mode, offline_network, private_temp, random_pubky, ring_context,
        ring_login, ring_network, ring_testnet,
    };
    use crate::{CLIENT_ID, Context, Dirs};

    /// Two years in seconds, the grant lifetime the SDK fixes.
    const TWO_YEARS: u64 = 2 * 365 * 86_400;

    /// A synthetic token that passes `GrantToken`'s checks; only the unit
    /// tests below, which never send it anywhere, use it.
    fn synthetic_token() -> String {
        format!("pubky-grant-credential-v1:{PLANTED}")
    }

    /// Seconds since the Unix epoch, now.
    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("after 1970")
            .as_secs()
    }

    /// Asserts that nothing is at `path`, not even a dangling link.
    fn assert_gone(path: &std::path::Path) {
        assert!(
            lstat(path).expect("lstat").is_none(),
            "{} is there",
            path.display()
        );
    }

    /// Asserts that no Ring login was saved in `dirs`: no `login.json`, no
    /// `grant.token`, no `device.key`, and no install entry for `owner`.
    fn assert_nothing_saved(dirs: &Dirs, owner: &sweepky_core::Pubky) {
        assert_gone(&dirs.login_file());
        assert_gone(&dirs.grant_token_file());
        assert_gone(&dirs.device_key_file());
        assert!(read_installs(dirs).expect("reads").ids_of(owner).is_empty());
    }

    /// Asserts that no sign-in flow started: the browser seam was handed
    /// no page URL.
    fn assert_no_flow(urls: &mut UnboundedReceiver<Url>) {
        assert!(matches!(urls.try_recv(), Err(TryRecvError::Empty)));
    }

    /// An approved grant for the unit tests, with a synthetic token and
    /// random keys.
    fn approved() -> ApprovedGrant {
        ApprovedGrant {
            token: GrantToken::from_exported(synthetic_token()).expect("a token"),
            pubky: random_pubky(),
            homeserver: random_pubky(),
            expires_at: now() + TWO_YEARS,
        }
    }

    /// Runs `save_grant` for `grant` with `keys`, counting the sign-outs.
    async fn save_with(
        ctx: &Context,
        grant: &ApprovedGrant,
        keys: FakeKeyStore,
    ) -> (anyhow::Result<super::Saved>, Vec<FakeKeyStore>) {
        // The sign-out gets the store back by value, as the real one gets
        // the session; keeping it lets the test count the calls and look at
        // what the store was asked.
        let mut signed_out = Vec::new();
        let saved = save_grant(ctx, grant, keys, async |keys| signed_out.push(keys)).await;
        (saved, signed_out)
    }

    #[tokio::test]
    async fn a_failed_tail_removes_the_token_and_signs_the_grant_out() {
        let home = private_temp();
        let (ctx, stderr, _urls) = ring_context(offline_network(), &home, io::empty());
        let grant = approved();

        let (saved, signed_out) = save_with(
            &ctx,
            &grant,
            FakeKeyStore::refusing_puts(StatusCode::FORBIDDEN),
        )
        .await;
        let Err(error) = saved else {
            panic!("a refused probe saved the login");
        };
        // write_error's message for a 403, never the server's own text, and
        // never the token.
        assert_eq!(error.root_cause().to_string(), WRITE_FORBIDDEN);
        let shown = format!("{error:#}");
        assert!(shown.starts_with(NOT_SAVED), "{shown}");
        assert!(!shown.contains(FAKE_SERVER_TEXT), "{shown}");
        assert!(!shown.contains(PLANTED), "{shown}");
        assert!(!stderr.text().contains(PLANTED));

        // Signed out once, after the one PUT of the probe.
        let [keys] = signed_out.as_slice() else {
            panic!("signed out {} times", signed_out.len());
        };
        assert!(matches!(keys.calls().as_slice(), [KeyStoreCall::PutKey(_)]));
        // The token is gone again, login.json was never written, and P2a's
        // tail rolled its device key and install entry back.
        assert_nothing_saved(&ctx.dirs, &grant.pubky);
    }

    #[tokio::test]
    async fn a_login_that_finished_meanwhile_wins_and_the_grant_is_signed_out() {
        let home = private_temp();
        let (ctx, _stderr, _urls) = ring_context(offline_network(), &home, io::empty());
        let grant = approved();
        // Another `sweepky login` wrote login.json while this one waited
        // for Ring.
        let other = LoginState::ring(random_pubky(), random_pubky(), now() + TWO_YEARS);
        write_login_state(&ctx.dirs, &other).expect("writes");

        let (saved, signed_out) = save_with(&ctx, &grant, FakeKeyStore::default()).await;
        let Err(error) = saved else {
            panic!("saved over another login");
        };
        assert!(
            format!("{error:#}").contains("already logged in"),
            "{error:#}"
        );
        let [keys] = signed_out.as_slice() else {
            panic!("signed out {} times", signed_out.len());
        };
        // Refused before anything was written or sent.
        assert!(keys.calls().is_empty());
        assert_gone(&ctx.dirs.grant_token_file());
        assert_eq!(read_login_state(&ctx.dirs).expect("reads"), Some(other));
    }

    #[tokio::test]
    async fn identity_flags_without_identity_are_refused_unquoted() {
        let home = private_temp();
        let (ctx, _stderr, mut urls) = ring_context(offline_network(), &home, io::empty());
        let token = SecretString::from(PLANTED);
        for (homeserver, signup_token, flag) in [
            (Some(PLANTED), None, "--homeserver"),
            (None, Some(&token), "--signup-token"),
        ] {
            let error = crate::login::login(&ctx, None, homeserver, signup_token)
                .await
                .expect_err("refused");
            let shown = format!("{error:#}");
            assert!(shown.starts_with(flag), "{shown}");
            assert!(shown.contains("--identity"), "{shown}");
            assert!(!shown.contains(PLANTED), "{shown}");
        }
        // Before any request, and before any file: not even the config
        // directory was made.
        assert_no_flow(&mut urls);
        assert_gone(ctx.dirs.config());
    }

    #[tokio::test]
    async fn one_login_per_install_either_way_round() {
        let home = private_temp();
        let (ctx, _stderr, mut urls) = ring_context(offline_network(), &home, io::empty());
        let name: IdentityName = "throwaway".parse().expect("a name");

        // Logged in with --identity: a Ring login is refused before the flow.
        let identity = LoginState::identity(name, random_pubky(), random_pubky());
        write_login_state(&ctx.dirs, &identity).expect("writes");
        let shown = format!(
            "{:#}",
            crate::login::login(&ctx, None, None, None)
                .await
                .expect_err("refused")
        );
        for part in ["throwaway", "`sweepky logout`", "SWEEPKY_HOME"] {
            assert!(shown.contains(part), "{part:?} missing from: {shown}");
        }
        assert_no_flow(&mut urls);

        // Logged in through Ring: `login --identity` is refused by P2a's
        // plan, which allows only the identity logged in.
        let ring = LoginState::ring(random_pubky(), random_pubky(), now() + TWO_YEARS);
        write_login_state(&ctx.dirs, &ring).expect("writes");
        let shown = format!(
            "{:#}",
            crate::login::login(&ctx, Some("x"), None, None)
                .await
                .expect_err("refused")
        );
        assert!(
            shown.contains(&format!("already logged in as {}", ring.pubky)),
            "{shown}"
        );
        assert!(shown.contains("`sweepky logout`"), "{shown}");
        assert_eq!(read_login_state(&ctx.dirs).expect("reads"), Some(ring));
    }

    #[tokio::test]
    async fn an_unrecorded_device_key_stops_a_first_ring_login_before_the_flow() {
        // Plain, and wrapped with no --passphrase-file given: either way
        // only the path is looked at, so neither needs the passphrase.
        let passphrase = Passphrase::for_tests(TEST_PASSPHRASE);
        for wrap in [None, Some(&passphrase)] {
            let home = private_temp();
            let (ctx, _stderr, mut urls) = ring_context(offline_network(), &home, io::empty());
            let orphan = DeviceIdentity::generate();
            create_device_key(&ctx.dirs, &orphan, wrap).expect("writes device.key");
            let before = fs::read(ctx.dirs.device_key_file()).expect("reads");

            let error = crate::login::login(&ctx, None, None, None)
                .await
                .expect_err("refused");
            // P2a's rule, in P2a's words, and not the error any request on
            // the offline network would have given.
            let shown = format!("{error:#}");
            assert!(shown.contains("never replaces a device key"), "{shown}");
            assert_no_flow(&mut urls);
            assert_eq!(fs::read(ctx.dirs.device_key_file()).expect("reads"), before);
            assert_gone(&ctx.dirs.login_file());
            assert_gone(&ctx.dirs.grant_token_file());
        }
    }

    #[tokio::test]
    #[pubky_testnet::test]
    async fn a_first_ring_login_saves_the_grant_and_publishes_the_device_key() {
        let testnet = ring_testnet().await;
        let home = private_temp();
        let (ctx, stderr, mut urls) = ring_context(ring_network(&testnet), &home, io::empty());
        let ring = RingStandIn::sign_up(&testnet).await;

        let (logged_in, ()) = tokio::join!(crate::login::login(&ctx, None, None, None), async {
            let page = RingPage::open(&mut urls).await;
            ring.approve(&page).await;
        });
        let report = logged_in.expect("logs in");
        let report = report.text();
        let dirs = &ctx.dirs;
        let owner = pubky_of(&ring.public_key());

        // grant.token is 0600 and restores a session as the approver.
        assert_eq!(mode(&dirs.grant_token_file()), 0o600);
        let token = read_grant_token(dirs, None)
            .expect("reads")
            .expect("present");
        let Ok(restored) = testnet
            .sdk()
            .expect("client")
            .restore_session(token.expose_secret())
            .await
        else {
            panic!("the saved token does not restore");
        };
        assert_eq!(restored.public_key(), ring.public_key());

        // login.json is a `ring` login with the grant's expiry, about two
        // years from now, and no name.
        let login: Value =
            serde_json::from_slice(&fs::read(dirs.login_file()).expect("reads")).expect("JSON");
        assert_eq!(login["schemaVersion"], 1);
        assert_eq!(login["kind"], "ring");
        assert_eq!(login["pubky"], owner.to_string());
        assert_eq!(
            login["homeserver"],
            pubky_of(&testnet.homeserver_app().public_key()).to_string()
        );
        assert_eq!(login.get("name"), None);
        let expires_at = login["grantExpiresAt"].as_u64().expect("a number");
        assert!(
            expires_at.abs_diff(now() + TWO_YEARS) < 3 * 86_400,
            "expires at {expires_at}"
        );
        let id = login["deviceId"]
            .as_str()
            .expect("a device id")
            .parse()
            .expect("valid");

        // device.key is 0600, and installs.json lists its id with its key.
        assert_eq!(mode(&dirs.device_key_file()), 0o600);
        let local = read_device_key(dirs, None)
            .expect("reads")
            .expect("present")
            .recipient();
        let installs = read_installs(dirs).expect("reads");
        let [install] = installs.installs_of(&owner) else {
            panic!("one install expected");
        };
        assert_eq!(install.device_id, id);
        assert_eq!(install.recipient.as_ref(), Some(&local));

        // Done when: the grant wrote keys/<deviceId>.json, readable by
        // anyone within the record cap, unrevoked, holding device.key's key.
        let anonymous = testnet.sdk().expect("client");
        let bytes = PublicKeyReader::new(&anonymous)
            .get_key(&ring.public_key(), &id)
            .await
            .expect("reads")
            .expect("published");
        assert!(bytes.len() <= MAX_RECORD_BYTES);
        let raw: Value = serde_json::from_slice(&bytes).expect("JSON");
        assert_eq!(raw["revokedAt"], Value::Null);
        let record = DeviceKey::from_json(&bytes).expect("a device key record");
        assert!(!record.is_revoked());
        assert!(holds_key(&record, &local).expect("a usable key"));

        // The report: the expiry in RFC 3339, two years from approval, the
        // backup reminder naming the config directory, and the key check,
        // which found nothing to say. Never the token, here or on stderr.
        assert!(report.contains(&expiry_text(expires_at)), "{report}");
        assert!(report.contains("two years from your approval"), "{report}");
        assert!(
            report.contains(&format!("Back up {}", dirs.config().display())),
            "{report}"
        );
        assert!(report.contains(&format!("keys/{id}.json")), "{report}");
        assert!(!report.contains("alarm"), "{report}");
        assert!(!report.contains("could not check keys/"), "{report}");
        assert!(!report.contains("Wrapped"), "{report}");
        assert!(!report.contains(token.expose_secret()), "{report}");
        assert!(!stderr.text().contains(token.expose_secret()));
    }

    #[tokio::test]
    #[pubky_testnet::test]
    async fn a_narrowed_approval_through_login_saves_nothing() {
        let testnet = ring_testnet().await;
        let home = private_temp();
        let (ctx, _stderr, mut urls) = ring_context(ring_network(&testnet), &home, io::empty());
        let ring = RingStandIn::sign_up(&testnet).await;
        let read_only = Capabilities::builder()
            .read("/pub/sweepky/")
            .expect("a scope")
            .finish();

        let (logged_in, ()) = tokio::join!(crate::login::login(&ctx, None, None, None), async {
            let page = RingPage::open(&mut urls).await;
            ring.approve_with(&page, &read_only).await;
        });
        let error = logged_in.expect_err("refused");
        assert_eq!(format!("{error:#}"), NARROWED_GRANT);
        assert_nothing_saved(&ctx.dirs, &pubky_of(&ring.public_key()));
    }

    #[tokio::test]
    #[pubky_testnet::test]
    async fn no_input_login_wraps_both_files_and_replaces_an_orphan_token() {
        let testnet = ring_testnet().await;
        let home = private_temp();
        // Were anything asked, `--no-input` would fail it at once, and the
        // `no` waiting on stdin would stop it otherwise.
        let (mut ctx, _stderr, mut urls) =
            ring_context(ring_network(&testnet), &home, Cursor::new(b"no\n".to_vec()));
        ctx.passphrase = Some(Passphrase::for_tests(TEST_PASSPHRASE));
        // A grant.token with no login.json, as a crash between the token's
        // write and login.json's leaves.
        ensure_private_dir(ctx.dirs.config()).expect("mkdir");
        fs::write(ctx.dirs.grant_token_file(), synthetic_token()).expect("writes");
        let ring = RingStandIn::sign_up(&testnet).await;

        let cli = Cli::try_parse_from(["sweepky", "--no-input", "login"]).expect("parses");
        let (logged_in, ()) = tokio::join!(crate::run(cli, &ctx), async {
            let page = RingPage::open(&mut urls).await;
            ring.approve(&page).await;
        });
        let report = logged_in.expect("logs in");
        let report = report.text();
        let dirs = &ctx.dirs;

        // Both secret files this run wrote are wrapped, and the report
        // names both.
        let token_file = fs::read(dirs.grant_token_file()).expect("reads");
        assert!(looks_wrapped(&token_file));
        assert!(looks_wrapped(
            &fs::read(dirs.device_key_file()).expect("reads")
        ));
        for path in [dirs.grant_token_file(), dirs.device_key_file()] {
            assert!(report.contains(&path.display().to_string()), "{report}");
        }
        assert!(report.contains("Wrapped"), "{report}");
        // The orphan was replaced whole, and the report warns of its grant.
        let token = read_grant_token(dirs, ctx.passphrase.as_ref())
            .expect("unwraps")
            .expect("present");
        assert_ne!(token.expose_secret(), synthetic_token());
        assert!(
            report.contains("may still be listed in Pubky Ring"),
            "{report}"
        );
        assert!(read_login_state(dirs).expect("reads").is_some());
    }

    // -----------------------------------------------------------------------
    // Logging in again through Ring.

    /// `login.json`, `grant.token` and `device.key` as they are now: equal
    /// snapshots mean a file was not written at all.
    fn ring_files(dirs: &Dirs) -> [Option<FileSnapshot>; 3] {
        [
            dirs.login_file(),
            dirs.grant_token_file(),
            dirs.device_key_file(),
        ]
        .map(|path| FileSnapshot::of(&path))
    }

    /// Restores a session from `token` on `testnet` and says whether the
    /// homeserver answered 401, as it does for a revoked grant: `false` for
    /// a session or any other error.
    async fn restores_to_401(
        testnet: &pubky_testnet::EphemeralTestnet,
        token: &GrantToken,
    ) -> bool {
        match testnet
            .sdk()
            .expect("client")
            .restore_session(token.expose_secret())
            .await
        {
            Ok(_) => false,
            Err(error) => status_of(&error) == Some(StatusCode::UNAUTHORIZED),
        }
    }

    /// A Ring `login.json` for `pubky`, as a first login leaves it, with a
    /// `device.key` under `id` (wrapped with `wrap` when given) and a
    /// synthetic saved token, offline: returns the device key's identity.
    fn ring_logged_in_offline(
        dirs: &Dirs,
        pubky: sweepky_core::Pubky,
        id: &DeviceId,
        wrap: Option<&Passphrase>,
    ) -> DeviceIdentity {
        let identity = DeviceIdentity::generate();
        create_device_key(dirs, &identity, wrap).expect("writes device.key");
        let mut login = LoginState::ring(pubky, random_pubky(), now() + TWO_YEARS);
        login.device_id = Some(id.clone());
        write_login_state(dirs, &login).expect("writes");
        let old = GrantToken::from_exported(format!("pubky-grant-credential-v1:OLD-{PLANTED}"))
            .expect("a token");
        write_grant_token(dirs, &old, None).expect("writes");
        identity
    }

    #[tokio::test]
    async fn a_wrapped_device_key_without_its_passphrase_stops_a_relogin_before_the_flow() {
        let home = private_temp();
        let (ctx, _stderr, mut urls) = ring_context(offline_network(), &home, io::empty());
        let passphrase = Passphrase::for_tests(TEST_PASSPHRASE);
        let id: DeviceId = "this-install".parse().expect("valid");
        ring_logged_in_offline(&ctx.dirs, random_pubky(), &id, Some(&passphrase));
        let before = ring_files(&ctx.dirs);

        let error = crate::login::login(&ctx, None, None, None)
            .await
            .expect_err("refused");
        // P2a's NeedsPassphrase text, naming device.key, and nothing to scan.
        let shown = format!("{error:#}");
        assert!(
            shown.contains(&format!(
                "{} is wrapped with a passphrase: give it with --passphrase-file",
                ctx.dirs.device_key_file().display()
            )),
            "{shown}"
        );
        assert!(shown.contains("login changed nothing"), "{shown}");
        assert_no_flow(&mut urls);
        assert_eq!(ring_files(&ctx.dirs), before);
    }

    #[tokio::test]
    async fn a_refused_reuse_puts_the_old_token_back_and_signs_the_new_grant_out() {
        let home = private_temp();
        let (ctx, _stderr, _urls) = ring_context(offline_network(), &home, io::empty());
        let grant = approved();
        let id: DeviceId = "this-install".parse().expect("valid");
        let identity = ring_logged_in_offline(&ctx.dirs, grant.pubky, &id, None);
        // This install's own record, revoked from another install: the
        // reuse branch refuses it and changes nothing.
        let keys = FakeKeyStore::default();
        let at = RecordTime::from_unix_seconds(now()).expect("a time");
        let mut record = device_key_record(&identity.recipient(), at.clone());
        record.revoked_at = Some(at);
        keys.set_record(&id, device_key_bytes(&record).expect("JSON"));
        let old = read_grant_token(&ctx.dirs, None)
            .expect("reads")
            .expect("saved");
        let [login_before, _, device_key_before] = ring_files(&ctx.dirs);

        let (saved, signed_out) = save_with(&ctx, &grant, keys).await;
        let error = saved.expect_err("a revoked own record is refused");
        let shown = format!("{error:#}");
        assert!(shown.starts_with(NOT_SAVED), "{shown}");
        assert!(shown.contains("is revoked"), "{shown}");
        // The new grant is signed out once; login.json and device.key are
        // not written, and grant.token holds the old token again.
        assert_eq!(signed_out.len(), 1);
        let [login_after, _, device_key_after] = ring_files(&ctx.dirs);
        assert_eq!(login_after, login_before);
        assert_eq!(device_key_after, device_key_before);
        let token = read_grant_token(&ctx.dirs, None)
            .expect("reads")
            .expect("put back");
        assert_eq!(token.expose_secret(), old.expose_secret());
    }

    #[tokio::test]
    #[pubky_testnet::test]
    async fn a_relogin_as_the_same_pubky_reuses_the_device_key_and_revokes_the_old_grant() {
        let testnet = ring_testnet().await;
        let home = private_temp();
        let (_first, _first_stderr, ring) = ring_login(&testnet, &home).await;
        let (ctx, stderr, mut urls) = ring_context(ring_network(&testnet), &home, io::empty());
        let dirs = &ctx.dirs;
        let before = read_login_state(dirs).expect("reads").expect("logged in");
        let device_key = fs::read(dirs.device_key_file()).expect("reads");
        // The token the first login saved, copied before the re-login.
        let old = read_grant_token(dirs, None).expect("reads").expect("saved");

        let (relogged, ()) = tokio::join!(crate::login::login(&ctx, None, None, None), async {
            let page = RingPage::open(&mut urls).await;
            ring.approve(&page).await;
        });
        let report = relogged.expect("logs in again");
        let report = report.text();
        assert!(
            report.contains("Reusing this install's device key"),
            "{report}"
        );
        assert!(
            report.contains("Revoked the earlier sweepky-cli grant"),
            "{report}"
        );

        // Same device id and the same device.key bytes; a new expiry.
        let after = read_login_state(dirs).expect("reads").expect("logged in");
        assert_eq!(after.device_id, before.device_id);
        assert_eq!(after.kind, before.kind);
        assert!(after.grant_expires_at.is_some());
        assert_eq!(fs::read(dirs.device_key_file()).expect("reads"), device_key);

        // The new token restores; the old one now gets 401; Ring lists the
        // one sweepky-cli grant.
        let new = read_grant_token(dirs, None).expect("reads").expect("saved");
        assert_ne!(new.expose_secret(), old.expose_secret());
        assert!(
            testnet
                .sdk()
                .expect("client")
                .restore_session(new.expose_secret())
                .await
                .is_ok(),
            "the new token does not restore"
        );
        assert!(restores_to_401(&testnet, &old).await);
        assert_eq!(ring.active_grants_for(CLIENT_ID).await.len(), 1);
        for secret in [old.expose_secret(), new.expose_secret()] {
            assert!(!report.contains(secret), "{report}");
            assert!(!stderr.text().contains(secret));
        }
    }

    #[tokio::test]
    #[pubky_testnet::test]
    async fn a_relogin_after_the_old_grant_was_revoked_elsewhere_succeeds_quietly() {
        let testnet = ring_testnet().await;
        let home = private_temp();
        let (_first, _first_stderr, ring) = ring_login(&testnet, &home).await;
        let (ctx, _stderr, mut urls) = ring_context(ring_network(&testnet), &home, io::empty());
        // Revoked behind this install's back: the test restores the saved
        // token and signs it out, as a revoke in Ring would end it.
        let old = read_grant_token(&ctx.dirs, None)
            .expect("reads")
            .expect("saved");
        let Ok(session) = testnet
            .sdk()
            .expect("client")
            .restore_session(old.expose_secret())
            .await
        else {
            panic!("the saved token does not restore");
        };
        if session.signout().await.is_err() {
            panic!("the test's sign-out failed");
        }

        let (relogged, ()) = tokio::join!(crate::login::login(&ctx, None, None, None), async {
            let page = RingPage::open(&mut urls).await;
            ring.approve(&page).await;
        });
        let report = relogged.expect("logs in again");
        let report = report.text();
        assert!(
            report.contains("Reusing this install's device key"),
            "{report}"
        );
        // Nothing about the earlier grant, neither revoked nor a warning.
        assert!(!report.contains("earlier sweepky-cli grant"), "{report}");
        assert!(!report.contains("warning"), "{report}");
        assert_eq!(ring.active_grants_for(CLIENT_ID).await.len(), 1);
    }

    #[tokio::test]
    #[pubky_testnet::test]
    async fn a_relogin_approved_by_another_pubky_changes_nothing_and_signs_it_out() {
        let testnet = ring_testnet().await;
        let home = private_temp();
        let (_first, _first_stderr, ring) = ring_login(&testnet, &home).await;
        let (ctx, _stderr, mut urls) = ring_context(ring_network(&testnet), &home, io::empty());
        let login = read_login_state(&ctx.dirs)
            .expect("reads")
            .expect("logged in");
        let old = read_grant_token(&ctx.dirs, None)
            .expect("reads")
            .expect("saved");
        let before = ring_files(&ctx.dirs);
        let other = RingStandIn::sign_up(&testnet).await;

        let (relogged, ()) = tokio::join!(crate::login::login(&ctx, None, None, None), async {
            let page = RingPage::open(&mut urls).await;
            other.approve(&page).await;
        });
        let error = relogged.expect_err("refused");
        assert_eq!(
            format!("{error:#}"),
            format!("{NOT_SAVED}: {}", approved_by_another_pubky(&login))
        );
        // Nothing local was written, the other pubky's grant is signed out,
        // and this install's own grant still restores.
        assert_eq!(ring_files(&ctx.dirs), before);
        assert!(other.active_grants_for(CLIENT_ID).await.is_empty());
        assert_eq!(ring.active_grants_for(CLIENT_ID).await.len(), 1);
        assert!(!restores_to_401(&testnet, &old).await);
    }

    #[tokio::test]
    #[pubky_testnet::test]
    async fn an_orphan_tokens_grant_is_revoked_once_the_new_login_is_saved() {
        let testnet = ring_testnet().await;
        // A live grant's token, left as an orphan in a fresh install: a
        // crash between the token's write and login.json's leaves one.
        let first_home = private_temp();
        let (first, _first_stderr, _first_ring) = ring_login(&testnet, &first_home).await;
        let orphan = read_grant_token(&first.dirs, None)
            .expect("reads")
            .expect("saved");
        let home = private_temp();
        let (ctx, _stderr, mut urls) = ring_context(ring_network(&testnet), &home, io::empty());
        write_grant_token(&ctx.dirs, &orphan, None).expect("writes the orphan");
        let ring = RingStandIn::sign_up(&testnet).await;

        let (logged_in, ()) = tokio::join!(crate::login::login(&ctx, None, None, None), async {
            let page = RingPage::open(&mut urls).await;
            ring.approve(&page).await;
        });
        let report = logged_in.expect("logs in");
        let report = report.text();
        assert!(
            report.contains("Revoked the earlier sweepky-cli grant"),
            "{report}"
        );
        assert!(restores_to_401(&testnet, &orphan).await);
        assert!(read_login_state(&ctx.dirs).expect("reads").is_some());
    }
}
