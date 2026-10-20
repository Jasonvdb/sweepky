//! `sweepky logout`: retire this install (02, "Device keys").
//!
//! All under the writers' lock, in this order ([`logout`], [`retire`]):
//!
//! 1. Read `login.json` ([`login_to_retire`]) and sign in afresh with the
//!    identity it names (`session::sign_in`).
//! 2. Revoke this install's own `keys/<deviceId>.json` while that session is
//!    live, with `keys revoke`'s read-modify-write
//!    (`keys::revoke_if_published`): `revokedAt` is set and every other
//!    field kept. A record that is revoked already is left as it is, and a
//!    record that is gone leaves nothing to revoke.
//! 3. Sign out, always, whether step 2 worked or not. A sign-out that fails
//!    is a warning and logout goes on: the session lives only in this
//!    process, the secret it was made with is deleted next, and its grant
//!    expires.
//! 4. Forget the identity: delete `identities/<name>.json`, then
//!    `identities/<name>.key` ([`forget_credential`]).
//! 5. Delete this install's files: `device.key` (a missing one is fine),
//!    `login.json`, and this owner's whole entry in `installs.json`
//!    ([`delete_install_files`]).
//!
//! **Nothing is deleted before the revoke is written.** If step 1 or 2
//! fails, logout stops after the sign-out with every file as it was, and
//! says how to retire the key from another install. The order matters most
//! for a dedicated identity: once its secret is gone nobody here can write
//! its `keys/` again, so a key left unrevoked would stay one that sweepers
//! encrypt to for good, with its secret still recoverable from the disk
//! (below). A `device.key` that `login.json` does not record cannot be
//! revoked by id, so logout refuses to start while one is there.
//!
//! **Deleting is not shredding.** Every file goes through
//! `private_fs::remove_private_file`, which unlinks the name and never
//! follows a symlink, and does not overwrite the bytes: on an SSD, and on a
//! copy-on-write filesystem such as macOS's APFS, an overwrite need not reach
//! the old blocks anyway. The secrets can stay on the disk until it reuses
//! the space, which is why step 2 comes first, and the report says so rather
//! than promising a secure erase.
//!
//! `credential.lock` and `pull.lock` are never deleted, because a new lock
//! file would let a second command in while another still holds the old one.
//!
//! **A Pubky Ring login** ([`logout_ring`], [`retire_ring`]) runs the same
//! steps, with the grant in place of the identity:
//!
//! 1. Restore the session from `grant.token` (`session::restore_saved_grant`).
//! 2. Revoke this install's device key with that live session, as above.
//! 3. Revoke the grant: its sign-out.
//! 4. Check that restoring the saved token now gets a 401, the proof that
//!    the grant is gone ([`crate::ring::revoke_grant`] runs 1 to 4).
//! 5. Only then delete `grant.token`, and this install's files as above.
//!
//! It differs from the identity's order in three ways. A failed step 2 does
//! **not** sign out: that would revoke the grant and so lock this install
//! out of the key it could not yet revoke. A failed or unconfirmed step 3 or
//! 4 stops before anything is deleted, so `logout` can run again with the
//! token. And an install already **locked out** (its grant revoked in Ring,
//! or past `grantExpiresAt`, which is checked first, without a request) has
//! no session to revoke its key with, so it reads its own
//! `keys/<deviceId>.json` anonymously from public storage instead, through
//! the capped public read. It finishes when that record reads revoked, or
//! is not published, and stops otherwise, naming `sweepky keys revoke <id>`
//! to run from another install; that is how 02's "revoked from another
//! install with `keys revoke`" lets this logout finish.

use anyhow::{Context as _, bail};
use sweepky_core::{DeviceId, DeviceKey, RecordTime, Zeroizing};

use crate::clock;
use crate::device::{PublicKeyReader, PublicKeys, SessionKeyStore, remove_device_key};
use crate::display::sanitize;
use crate::installs::forget_owner;
use crate::keys::{Revocation, revoke_if_published};
use crate::private_fs::{lstat, remove_private_file};
use crate::remote::public_key_of;
use crate::ring::token::remove_grant_token;
use crate::ring::{GrantRevocation, Restored, expired_grant_at, expiry_text, revoke_grant};
use crate::session::{restore_saved_grant, sign_in, with_writers_lock};
use crate::state::{KnownLoginKind, LoginState, read_login_state};
use crate::{Context, Dirs, Report};

/// What `logout` says when this install has no login.
const NOTHING_TO_LOG_OUT: &str = "this install is not logged in, so there is nothing to log out of";

/// What step 2 did about this install's device key record.
#[derive(Debug, PartialEq, Eq)]
enum RetiredKey {
    /// `login.json` records no device key: the login's key write was
    /// refused and rolled back, so this install published none.
    NoneRecorded,
    /// `keys/<id>.json` was not on the homeserver, so there was nothing to
    /// revoke: no sweeper can encrypt to a record that is not there.
    NotPublished(DeviceId),
    /// `keys/<id>.json` is revoked: by this logout, or already before it.
    Revoked(DeviceId, Revocation),
}

/// How this install's Pubky Ring grant ended, for the report.
#[derive(Debug, PartialEq, Eq)]
enum EndedGrant {
    /// This logout signed it out, and a restore of the saved token then got
    /// a 401.
    Revoked,
    /// The homeserver refused the saved token with a 401 before anything
    /// was done: the grant was revoked (in Ring, say) or had expired.
    AlreadyRevoked,
    /// `login.json`'s `grantExpiresAt`, this time (Unix seconds), had passed,
    /// so nothing was sent with the token.
    Expired(u64),
}

/// What a Ring logout says when the grant may still be live, and why it
/// kept everything: the sign-out failed, or the restore after it was not a
/// 401.
const GRANT_NOT_CONFIRMED: &str = "logout could not confirm that this install's Pubky Ring grant \
     is revoked, so it deleted nothing, kept grant.token, and this install is still logged in; \
     run `sweepky logout` again, or revoke sweepky-cli in Pubky Ring and then run `sweepky \
     logout` here again";

/// Runs `logout`: steps 1 to 5 of the module docs.
pub(crate) async fn logout(ctx: &Context) -> anyhow::Result<Report> {
    with_writers_lock(ctx, async || {
        let login = login_to_retire(&ctx.dirs)?;
        // Read before the sign-in: a `?` between the sign-in and `retire`
        // would return before the sign-out.
        let now = clock::now()?;
        if login.kind.as_known() == Some(KnownLoginKind::Ring) {
            return logout_ring(ctx, &login, now).await;
        }
        // 1. The sign-in reads `login.json` again, under the same lock, with
        // the identity it names.
        let signed = sign_in(ctx)
            .await
            .with_context(|| nothing_deleted_message(&login))?;
        let key = retire(
            &ctx.dirs,
            &login,
            signed,
            // Step 2, with the live session, which `retire` lends to this
            // closure for the call. The key store borrows it in turn, so
            // both borrows end before `retire` moves the session into the
            // sign-out below. `now` is moved in: the closure runs once.
            async |signed, id| {
                let keys = SessionKeyStore::new(signed.session(), ctx.network.pubky());
                revoke_if_published(&keys, id, now).await
            },
            // Step 3, which takes the session by value and so ends it.
            async |signed| signed.sign_out(ctx).await,
        )
        .await?;
        Ok(Report::new(report(&ctx.dirs, &login, &key, None)))
    })
    .await
}

/// `logout` for a Pubky Ring login, under the writers' lock that [`logout`]
/// holds: [`retire_ring`] with the real seams.
async fn logout_ring(ctx: &Context, login: &LoginState, now: RecordTime) -> anyhow::Result<Report> {
    // The clock as Unix seconds, for `grantExpiresAt`. Read before any
    // request: the SDK's own clock read during a restore panics on a clock
    // before 1970, which this refuses in words.
    let now_unix = clock::now_unix_seconds()?;
    let owner = public_key_of(&login.pubky)?;
    let (key, grant) = retire_ring(
        &ctx.dirs,
        login,
        now_unix,
        // Called twice, so it clones the login each time: the session it
        // returns owns its copy.
        async || restore_saved_grant(ctx, login.clone()).await,
        async |signed, id| {
            let keys = SessionKeyStore::new(signed.session(), ctx.network.pubky());
            revoke_if_published(&keys, id, now).await
        },
        async |signed| signed.sign_out_checked().await,
        // The anonymous read: public storage with no session, capped at
        // `MAX_RECORD_BYTES` and refusing a redirect (`remote::get_public`).
        async |id| {
            PublicKeyReader::new(ctx.network.pubky())
                .get_key(&owner, id)
                .await
        },
    )
    .await?;
    Ok(Report::new(report(&ctx.dirs, login, &key, Some(&grant))))
}

/// The Ring branch of steps 1 to 5 (module docs), for the `login.json` that
/// `login` holds and the time `now` (Unix seconds). The four requests are
/// passed in as closures, as for [`retire`], so the unit tests run every
/// ending with fakes:
///
/// - `restore` restores a session `S` from `grant.token`, or reports a 401;
/// - `revoke` revokes `keys/<id>.json` with the borrowed live session;
/// - `sign_out` takes the session by value and revokes the grant;
/// - `read_own` reads `keys/<id>.json` anonymously, for an install that is
///   locked out.
///
/// An expired `grantExpiresAt` is checked first, so such a grant sends no
/// request with the token at all.
async fn retire_ring<S>(
    dirs: &Dirs,
    login: &LoginState,
    now: u64,
    restore: impl AsyncFn() -> anyhow::Result<Restored<S>>,
    revoke: impl AsyncFnOnce(&S, &DeviceId) -> anyhow::Result<Option<Revocation>>,
    sign_out: impl AsyncFnOnce(S) -> anyhow::Result<()>,
    read_own: impl AsyncFnOnce(&DeviceId) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>>,
) -> anyhow::Result<(RetiredKey, EndedGrant)> {
    // `read_own` is moved into one branch or the other: only one of them
    // runs, so the compiler accepts the move in both.
    let (key, grant) = if let Some(expired_at) = expired_grant_at(login, now) {
        (
            locked_out_key(login, read_own).await?,
            EndedGrant::Expired(expired_at),
        )
    } else {
        let revoked = revoke_grant(
            restore,
            async |session| revoke_recorded_key(login, session, revoke).await,
            sign_out,
        )
        .await
        .with_context(|| ring_nothing_deleted_message(login))?;
        match revoked {
            GrantRevocation::Revoked(key) => (key, EndedGrant::Revoked),
            GrantRevocation::AlreadyRevoked => (
                locked_out_key(login, read_own).await?,
                EndedGrant::AlreadyRevoked,
            ),
            GrantRevocation::NotConfirmed => bail!(GRANT_NOT_CONFIRMED),
        }
    };
    // 5. The token, then this install's files, as for an identity.
    forget_credential(dirs, login).context(
        "logout could not delete grant.token, so it left this install's other files alone; fix \
         that and run `sweepky logout` again",
    )?;
    delete_install_files(dirs, login)?;
    Ok((key, grant))
}

/// What a locked-out install knows about its own device key: its
/// `keys/<id>.json` read anonymously through `read_own`. Revoked (from
/// another install, say) or not published, logout can finish; unrevoked, or
/// unreadable, it stops, since no session here can revoke it any more.
///
/// The bytes are the homeserver's and go only through `DeviceKey::from_json`,
/// which never panics and whose error is fixed text.
async fn locked_out_key(
    login: &LoginState,
    read_own: impl AsyncFnOnce(&DeviceId) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>>,
) -> anyhow::Result<RetiredKey> {
    let Some(id) = &login.device_id else {
        return Ok(RetiredKey::NoneRecorded);
    };
    let read = read_own(id).await.with_context(|| unreadable_own_key(id))?;
    // A 404, P2a's "nothing to revoke".
    let Some(bytes) = read else {
        return Ok(RetiredKey::NotPublished(id.clone()));
    };
    // `&bytes` lends the `Zeroizing<Vec<u8>>` as the `&[u8]` `from_json`
    // takes, through `Deref`.
    let record = DeviceKey::from_json(&bytes).with_context(|| unreadable_own_key(id))?;
    match record.revoked_at {
        Some(at) => Ok(RetiredKey::Revoked(
            id.clone(),
            Revocation::AlreadyRevoked(at),
        )),
        None => bail!(
            "this install's Pubky Ring grant is revoked or expired, so this install can no longer \
             revoke its own device key keys/{id}.json, which is still unrevoked; logout deleted \
             nothing. Revoke it from another install of this identity with `sweepky keys revoke \
             {id}`, then run `sweepky logout` here again"
        ),
    }
}

/// Why a locked-out logout stopped when it could not read its own key
/// record: a failed request, a body over the cap, or a record this build
/// cannot parse.
fn unreadable_own_key(id: &DeviceId) -> String {
    format!(
        "this install's Pubky Ring grant is revoked or expired, and logout could not read \
         keys/{id}.json to tell whether this install's device key is revoked, so it deleted \
         nothing; run `sweepky logout` again later, or revoke the key from another install of \
         this identity with `sweepky keys revoke {id}` first"
    )
}

/// Why a Ring logout stopped before deleting anything, for an error from
/// the restore or the key revoke: the grant has not been revoked, so the
/// token stays, and the two ways out.
fn ring_nothing_deleted_message(login: &LoginState) -> String {
    match &login.device_id {
        Some(id) => format!(
            "logout deleted nothing, kept grant.token, and this install is still logged in, \
             because this install's device key keys/{id}.json has to be revoked before its Pubky \
             Ring grant is. Run `sweepky logout` again later; or revoke sweepky-cli in Pubky \
             Ring, revoke the key from another install of this identity with `sweepky keys \
             revoke {id}`, and then run `sweepky logout` here again"
        ),
        None => "logout deleted nothing, kept grant.token, and this install is still logged in; \
                 run `sweepky logout` again later, or revoke sweepky-cli in Pubky Ring and then \
                 run `sweepky logout` here again"
            .to_owned(),
    }
}

/// Reads `login.json` for `logout`, and refuses before anything is done
/// when this install has no login, or has a `device.key` that `login.json`
/// does not record.
///
/// Such a key file is what a login leaves whose key write failed and whose
/// rollback could not remove it. Its record may still have been published,
/// and logout cannot revoke a record without its id, so it refuses rather
/// than delete the key and forget the identity that alone could revoke it.
/// `lstat` sees a symlink at the path too, rather than what it points at.
fn login_to_retire(dirs: &Dirs) -> anyhow::Result<LoginState> {
    let Some(login) = read_login_state(dirs)? else {
        bail!(NOTHING_TO_LOG_OUT);
    };
    let device_key = dirs.device_key_file();
    if login.device_id.is_none() && lstat(&device_key)?.is_some() {
        bail!(
            "{} holds a device key that login.json does not record, so logout cannot revoke its \
             record, and changed nothing: Sweepky never deletes a device key it could not \
             revoke. Move the file somewhere safe and run `sweepky logout` again",
            device_key.display()
        );
    }
    Ok(login)
}

/// Steps 2 to 5 of the module docs, once signed in, for the `login.json`
/// that `login` holds. Steps 2 and 3 are passed in as closures, so the unit
/// tests can run the steps without a homeserver.
///
/// `session` is whatever holds the live session: the signed-in session in
/// `logout`, a fake key store in the tests. It is generic (`S`) because
/// `retire` itself never looks inside it, only hands it on:
///
/// - `revoke` (step 2) borrows it (`&S`) for one call, to revoke `keys/<id>.json`;
/// - `sign_out` (step 3) takes it by value (`S`), so the session cannot be
///   used after it; it is called whether or not `revoke` succeeded.
///
/// That split is what lets the borrow checker accept this: the borrow
/// `revoke` gets has ended by the time `session` moves into `sign_out`.
async fn retire<S>(
    dirs: &Dirs,
    login: &LoginState,
    session: S,
    revoke: impl AsyncFnOnce(&S, &DeviceId) -> anyhow::Result<Option<Revocation>>,
    sign_out: impl AsyncFnOnce(S),
) -> anyhow::Result<RetiredKey> {
    // 2. Revoke while the session is live. Not returned with `?` yet: the
    // sign-out comes first, whatever happened.
    let revoked = revoke_recorded_key(login, &session, revoke).await;
    // 3. Sign out, success or failure.
    sign_out(session).await;
    // A failed revoke stops logout here, before anything is deleted.
    let key = revoked.with_context(|| nothing_deleted_message(login))?;
    // 4. Forget the identity. Should that fail, the rest stays too, so the
    // identity can still sign in, and the next `logout` finds its key
    // revoked already and goes on.
    forget_credential(dirs, login).context(
        "logout could not forget the identity, so it left this install's other files alone; fix \
         that and run `sweepky logout` again",
    )?;
    // 5. This install's files.
    delete_install_files(dirs, login)?;
    Ok(key)
}

/// Step 2: revokes the device key `login.json` records, through `revoke`
/// with the borrowed live `session`. Its `?` returns to [`retire`], which
/// holds the error until it has signed out.
async fn revoke_recorded_key<S>(
    login: &LoginState,
    session: &S,
    revoke: impl AsyncFnOnce(&S, &DeviceId) -> anyhow::Result<Option<Revocation>>,
) -> anyhow::Result<RetiredKey> {
    let Some(id) = &login.device_id else {
        return Ok(RetiredKey::NoneRecorded);
    };
    Ok(match revoke(session, id).await? {
        Some(revocation) => RetiredKey::Revoked(id.clone(), revocation),
        None => RetiredKey::NotPublished(id.clone()),
    })
}

/// Why logout stopped before deleting anything, for an error from step 1
/// or 2, with the way out when this install cannot revoke its own key: from
/// another install of the identity, which `keys revoke` can do, after which
/// this install's `logout` finds the key revoked already.
fn nothing_deleted_message(login: &LoginState) -> String {
    match &login.device_id {
        Some(id) => format!(
            "logout deleted nothing, and this install is still logged in, because this install's \
             device key keys/{id}.json has to be revoked first. Run `sweepky logout` again later; \
             if this install can no longer write to its homeserver, revoke the key from another \
             install of this identity with `sweepky keys revoke {id}`, then run `sweepky logout` \
             here again"
        ),
        None => "logout deleted nothing, and this install is still logged in".to_owned(),
    }
}

/// Step 4: forgets the credential this install signed in with. For a
/// dedicated identity that is its two files; for a Pubky Ring login,
/// `grant.token`, whose grant is revoked or dead by now.
///
/// An identity's details go first, then the secret: should the second
/// deletion fail, the key file alone is still an identity the next `logout`
/// can sign in with. The other way round would leave details without their
/// key, which nothing signs in with any more.
fn forget_credential(dirs: &Dirs, login: &LoginState) -> anyhow::Result<()> {
    // `logout` sends a Ring login one way and every other kind through
    // `sign_in`, which refuses a kind it does not know, so the last arm is a
    // second check, not a branch that runs.
    match (login.kind.as_known(), &login.name) {
        (Some(KnownLoginKind::Identity), Some(name)) => {
            remove_private_file(&dirs.identity_file(name))?;
            remove_private_file(&dirs.identity_key_file(name))
        }
        (Some(KnownLoginKind::Ring), _) => remove_grant_token(dirs),
        _ => bail!(
            "login.json does not name a dedicated identity, so there is no identity to forget"
        ),
    }
}

/// Step 5: deletes this install's own files: `device.key`, `login.json`, and
/// this owner's entry in `installs.json`. Nothing else in the config
/// directory is touched: not `credential.lock`, nor another identity.
///
/// Each is tried even when one before it failed: the key is revoked and the
/// identity forgotten by now, so no file is needed to delete another, and
/// what could not be deleted is named in the error, to delete by hand.
fn delete_install_files(dirs: &Dirs, login: &LoginState) -> anyhow::Result<()> {
    // An array literal's elements are evaluated left to right, so all three
    // deletions run, in this order, before any result is looked at.
    let results = [
        remove_device_key(dirs),
        remove_private_file(&dirs.login_file()),
        forget_owner(dirs, login.pubky).context("could not remove this owner's entry"),
    ];
    // `filter_map(Result::err)` keeps the errors and drops the successes.
    let left: Vec<String> = results
        .into_iter()
        .filter_map(Result::err)
        .map(|error| format!("{error:#}"))
        .collect();
    if !left.is_empty() {
        bail!(
            "logout forgot this install's credential, but could not delete all of this \
             install's files ({}); delete what is left by hand",
            left.join("; ")
        );
    }
    Ok(())
}

/// What `logout` reports once it is done: fixed text, device ids, the
/// user's own paths and pubky, and the times this logout wrote or
/// `login.json` holds. `grant` is how a Ring login's grant ended, `None`
/// for an identity.
fn report(dirs: &Dirs, login: &LoginState, key: &RetiredKey, grant: Option<&EndedGrant>) -> String {
    let mut text = key.report_line();
    if let Some(grant) = grant {
        text.push_str(&grant.report_line(&login.pubky));
        text.push_str(&format!("Deleted {}.\n", dirs.grant_token_file().display()));
    }
    if let Some(name) = &login.name {
        text.push_str(&format!(
            "Forgot the identity {name}, pubky {}: deleted {} and {}.\n",
            login.pubky,
            dirs.identity_key_file(name).display(),
            dirs.identity_file(name).display()
        ));
    }
    text.push_str(&format!(
        "Deleted this install's {}, {} and this owner's entry in {}. Sweeps encrypted to this \
         install's key that were not pulled can no longer be opened.\n\
         The files were deleted, not overwritten: on an SSD or a copy-on-write filesystem such as \
         APFS their bytes can stay on the disk until it reuses the space.\n",
        dirs.device_key_file().display(),
        dirs.login_file().display(),
        dirs.installs_file().display()
    ));
    text
}

impl EndedGrant {
    /// The report's line about the grant, ending in its newline.
    fn report_line(&self, pubky: &sweepky_core::Pubky) -> String {
        match self {
            Self::Revoked => format!(
                "Revoked this install's Pubky Ring grant (sweepky-cli, pubky {pubky}) by signing \
                 it out: restoring the saved token now gets 401 from the homeserver.\n"
            ),
            Self::AlreadyRevoked => format!(
                "This install's Pubky Ring grant (sweepky-cli, pubky {pubky}) was already \
                 revoked or expired: the homeserver refused the saved token with 401.\n"
            ),
            Self::Expired(at) => format!(
                "This install's Pubky Ring grant (sweepky-cli, pubky {pubky}) had expired, at \
                 {}, so logout sent nothing with it.\n",
                expiry_text(*at)
            ),
        }
    }
}

impl RetiredKey {
    /// The report's line about this install's device key, ending in its
    /// newline. An earlier `revokedAt` is the homeserver's text, so it goes
    /// through `sanitize`, as every string from a record does.
    fn report_line(&self) -> String {
        match self {
            Self::Revoked(id, Revocation::Revoked(at)) => format!(
                "Revoked keys/{id}.json, this install's device key, at {at}: sweeps uploaded from \
                 now on are not encrypted to it.\n"
            ),
            Self::Revoked(id, Revocation::AlreadyRevoked(at)) => format!(
                "keys/{id}.json, this install's device key, was revoked already, at {}.\n",
                sanitize(at.as_str(), RecordTime::MAX_LEN)
            ),
            Self::NotPublished(id) => format!(
                "keys/{id}.json, this install's device key record, was not on the homeserver, so \
                 there was nothing to revoke.\n"
            ),
            Self::NoneRecorded => {
                "This install had published no device key, so there was nothing to revoke.\n"
                    .to_owned()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::os::unix::fs::DirBuilderExt;
    use std::path::Path;
    use std::sync::Mutex;

    use anyhow::bail;
    use pubky::StatusCode;
    use serde_json::json;
    use sweepky_core::{DeviceId, DeviceIdentity, DeviceKey, MAX_RECORD_BYTES, RecordTime, paths};
    use tempfile::TempDir;

    use super::{
        EndedGrant, GRANT_NOT_CONFIRMED, RetiredKey, login_to_retire, logout, report, retire,
        retire_ring,
    };
    use crate::Dirs;
    use crate::device::{
        PublicKeyReader, PublicKeys, create_device_key, device_key_bytes, device_key_record,
    };
    use crate::identity::{IdentityMeta, IdentityName, IdentitySecret};
    use crate::installs::{read_installs, record_install};
    use crate::keys::{Revocation, revoke_if_published};
    use crate::lock::{PullLock, WritersLock};
    use crate::private_fs::lstat;
    use crate::remote::{BodyTooLarge, public_key_of, status_of};
    use crate::ring::Restored;
    use crate::ring::token::{GrantToken, read_grant_token, write_grant_token};
    use crate::state::{
        LoginState, StoredIdentity, create_identity, read_identity, read_login_state,
        write_login_state,
    };
    use crate::test_support::{
        FAKE_READ_FAILURE, FAKE_SERVER_TEXT, FakeKeyStore, FileSnapshot, KeyStoreCall, PLANTED,
        dirs_in, mode, private_temp, random_pubky, ring_login, ring_testnet,
    };

    /// The time the revoke step is handed as "now".
    const NOW: &str = "2026-10-16T12:00:00Z";

    fn time(text: &str) -> RecordTime {
        text.parse().expect("a valid time")
    }

    fn name(text: &str) -> IdentityName {
        text.parse().expect("a valid name")
    }

    /// A temp `SWEEPKY_HOME` after a login of `throwaway` whose shared tail
    /// published this install's key into `keys`: the identity's two files,
    /// `device.key`, the id in `installs.json` and in `login.json`.
    fn logged_in(keys: &FakeKeyStore) -> (TempDir, Dirs, LoginState, DeviceId) {
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        let secret = IdentitySecret::generate();
        let meta = IdentityMeta::new(name("throwaway"), secret.pubky(), random_pubky(), true);
        create_identity(&dirs, &secret, &meta, None).expect("creates");
        let device = DeviceIdentity::generate();
        create_device_key(&dirs, &device, None).expect("writes device.key");
        let id: DeviceId = "0035G87EK4XFE".parse().expect("a valid id");
        record_install(&dirs, meta.pubky, &id).expect("records");
        let record = device_key_record(&device.recipient(), time("2026-10-16T09:41:07Z"));
        keys.set_record(&id, device_key_bytes(&record).expect("JSON"));
        let mut login = LoginState::identity(meta.name, meta.pubky, meta.homeserver);
        login.device_id = Some(id.clone());
        write_login_state(&dirs, &login).expect("writes");
        (temp, dirs, login, id)
    }

    /// Runs logout's steps after its sign-in, as `logout` does, with `keys`
    /// standing in for the live session. Returns the result and, if the
    /// session was signed out, whether the identity's key file was still
    /// there at that moment: `Some(true)` means it signed out before
    /// anything was deleted.
    async fn retire_with(
        dirs: &Dirs,
        login: &LoginState,
        keys: &FakeKeyStore,
    ) -> (anyhow::Result<RetiredKey>, Option<bool>) {
        let key_file = dirs.identity_key_file(login.name.as_ref().expect("a name"));
        let mut signed_out = None;
        let result = retire(
            dirs,
            login,
            keys,
            // `keys` arrives as `&&FakeKeyStore` (a borrow of `S`, which is
            // `&FakeKeyStore` here); `*keys` is the store itself.
            async |keys, id| revoke_if_published(*keys, id, time(NOW)).await,
            async |_keys| signed_out = Some(lstat(&key_file).expect("lstat").is_some()),
        )
        .await;
        (result, signed_out)
    }

    /// Asserts that nothing is at `path`, not even a dangling symlink:
    /// `lstat` does not follow a link, and any error but "not found" fails
    /// the test rather than passing for a missing file.
    fn assert_gone(path: &Path) {
        let found = lstat(path).expect("lstat");
        assert!(found.is_none(), "{} is still there", path.display());
    }

    /// Asserts that `login`'s identity and this install's files are gone:
    /// the identity's secret and details, device.key, login.json, and the
    /// owner's entry in installs.json.
    fn assert_retired(dirs: &Dirs, login: &LoginState) {
        let name = login.name.as_ref().expect("a name");
        assert_gone(&dirs.identity_key_file(name));
        assert_gone(&dirs.identity_file(name));
        assert_gone(&dirs.device_key_file());
        assert_gone(&dirs.login_file());
        let installs = read_installs(dirs).expect("reads");
        assert!(installs.ids_of(&login.pubky).is_empty());
    }

    /// The local files logout deletes, as snapshots: equal snapshots mean
    /// the file was neither deleted nor written.
    fn local_files(dirs: &Dirs, login: &LoginState) -> [Option<FileSnapshot>; 5] {
        let name = login.name.as_ref().expect("a name");
        [
            dirs.identity_key_file(name),
            dirs.identity_file(name),
            dirs.device_key_file(),
            dirs.installs_file(),
            dirs.login_file(),
        ]
        .map(|path| FileSnapshot::of(&path))
    }

    fn revoked_at(keys: &FakeKeyStore, id: &DeviceId) -> Option<RecordTime> {
        let bytes = keys.record(id).expect("the record is there");
        DeviceKey::from_json(&bytes).expect("a record").revoked_at
    }

    #[tokio::test]
    async fn local_files_are_kept_when_the_revoke_write_fails() {
        let keys = FakeKeyStore::refusing_puts(StatusCode::INTERNAL_SERVER_ERROR);
        let (_temp, dirs, login, id) = logged_in(&keys);
        let before = local_files(&dirs, &login);
        assert!(
            before.iter().all(Option::is_some),
            "the fixture has them all"
        );

        let (result, signed_out) = retire_with(&dirs, &login, &keys).await;
        let err = result.expect_err("logout aborts");
        let shown = format!("{err:#}");
        // It says nothing was deleted, and how to retire the key from
        // another install, never in the server's words.
        assert!(shown.contains("deleted nothing"), "{shown}");
        assert!(shown.contains("another install"), "{shown}");
        assert!(
            shown.contains(&format!("`sweepky keys revoke {id}`")),
            "{shown}"
        );
        assert!(!shown.contains(FAKE_SERVER_TEXT), "{shown}");

        // The revoke was tried, and refused: the record is still unrevoked.
        assert_eq!(
            keys.calls(),
            [
                KeyStoreCall::GetOwnKey(id.clone()),
                KeyStoreCall::PutKey(id.clone())
            ]
        );
        assert_eq!(revoked_at(&keys, &id), None);
        // The session was signed out all the same, and nothing was deleted
        // or even rewritten: the identity's key and details, device.key, the
        // install entry and login.json.
        assert_eq!(signed_out, Some(true));
        assert_eq!(local_files(&dirs, &login), before);
    }

    #[tokio::test]
    async fn deletion_removes_exactly_this_installs_files() {
        let keys = FakeKeyStore::default();
        let (_temp, dirs, login, id) = logged_in(&keys);
        // Files that are not this install's login: the locks, another
        // identity, another owner's install, a file of the user's own.
        WritersLock::open(&dirs).expect("creates credential.lock");
        PullLock::open(&dirs).expect("creates pull.lock");
        let other = IdentitySecret::generate();
        let other_meta = IdentityMeta::new(name("other"), other.pubky(), random_pubky(), true);
        create_identity(&dirs, &other, &other_meta, None).expect("creates");
        let other_owner = random_pubky();
        let other_install: DeviceId = "other-install".parse().expect("a valid id");
        record_install(&dirs, other_owner, &other_install).expect("records");
        let notes = dirs.config().join("notes.txt");
        fs::write(&notes, "the user's own").expect("write");

        let (result, signed_out) = retire_with(&dirs, &login, &keys).await;
        let retired = result.expect("logout succeeds");
        assert_eq!(
            retired,
            RetiredKey::Revoked(id.clone(), Revocation::Revoked(time(NOW)))
        );
        // Revoked while the session was live, then signed out before
        // anything was deleted.
        assert_eq!(revoked_at(&keys, &id), Some(time(NOW)));
        assert_eq!(signed_out, Some(true));

        // Gone: the identity's secret and details, device.key, login.json,
        // and this owner's entry in installs.json.
        assert_retired(&dirs, &login);

        // Kept: the lock files, which are never deleted, the other
        // identity, the other owner's install and the user's file.
        assert_eq!(mode(&dirs.credential_lock_file()), 0o600);
        assert_eq!(mode(&dirs.pull_lock_file()), 0o600);
        assert!(matches!(
            read_identity(&dirs, &other_meta.name, None).expect("reads"),
            StoredIdentity::Complete { .. }
        ));
        let installs = read_installs(&dirs).expect("reads");
        assert_eq!(installs.ids_of(&other_owner), [other_install]);
        assert_eq!(fs::read(&notes).expect("kept"), b"the user's own");
    }

    #[tokio::test]
    async fn logout_with_a_missing_device_key_still_revokes_and_cleans_up() {
        // The way out that `login` points at when device.key is gone: the
        // record is revoked all the same, and the rest is removed.
        let keys = FakeKeyStore::default();
        let (_temp, dirs, login, id) = logged_in(&keys);
        fs::remove_file(dirs.device_key_file()).expect("remove device.key");
        login_to_retire(&dirs).expect("logout goes ahead");

        let (result, signed_out) = retire_with(&dirs, &login, &keys).await;
        result.expect("logout succeeds");
        assert_eq!(revoked_at(&keys, &id), Some(time(NOW)));
        assert_eq!(signed_out, Some(true));
        assert_retired(&dirs, &login);
    }

    #[tokio::test]
    async fn a_record_already_revoked_or_gone_needs_no_write() {
        // Revoked already, by `keys revoke` from another install, say: the
        // first time is kept, and nothing is written. Gone: there is no
        // record left to revoke. Either way logout goes on.
        for already in [Some("2026-01-01T00:00:00Z"), None] {
            let keys = FakeKeyStore::default();
            let (_temp, dirs, login, id) = logged_in(&keys);
            let expected = match already {
                Some(at) => {
                    let mut record: serde_json::Value =
                        serde_json::from_slice(&keys.record(&id).expect("there")).expect("JSON");
                    record["revokedAt"] = json!(at);
                    keys.set_record(&id, serde_json::to_vec(&record).expect("JSON"));
                    RetiredKey::Revoked(id.clone(), Revocation::AlreadyRevoked(time(at)))
                }
                None => {
                    keys.remove_record(&id);
                    RetiredKey::NotPublished(id.clone())
                }
            };

            let (result, signed_out) = retire_with(&dirs, &login, &keys).await;
            assert_eq!(result.expect("logout succeeds"), expected);
            assert_eq!(keys.calls(), [KeyStoreCall::GetOwnKey(id.clone())]);
            assert_eq!(signed_out, Some(true));
            assert_retired(&dirs, &login);
        }
    }

    #[test]
    fn an_unrecorded_device_key_is_refused_before_anything_is_done() {
        // A device.key that login.json does not record, as a login whose
        // rollback could not remove it leaves: logout cannot revoke its
        // record, so it refuses before signing in and deletes nothing.
        let keys = FakeKeyStore::default();
        let (_temp, dirs, mut login, _id) = logged_in(&keys);
        login.device_id = None;
        write_login_state(&dirs, &login).expect("writes");
        let before = local_files(&dirs, &login);

        let err = login_to_retire(&dirs).expect_err("refused");
        let shown = format!("{err:#}");
        assert!(shown.contains("does not record"), "{shown}");
        assert!(shown.contains("changed nothing"), "{shown}");
        assert_eq!(local_files(&dirs, &login), before);

        // Without it, there is nothing to revoke, and logout goes ahead.
        fs::remove_file(dirs.device_key_file()).expect("remove device.key");
        assert_eq!(login_to_retire(&dirs).expect("goes ahead"), login);
    }

    // -----------------------------------------------------------------------
    // A Pubky Ring login.

    /// 2026-10-20T00:00:00Z, the time a Ring logout is handed as "now", in
    /// Unix seconds.
    const NOW_UNIX: u64 = 1_792_454_400;

    /// A grant that is still valid at [`NOW_UNIX`], and one that is not.
    const LIVE_UNTIL: u64 = NOW_UNIX + 400 * 86_400;
    const EXPIRED_AT: u64 = NOW_UNIX - 1;

    /// A temp `SWEEPKY_HOME` after a Ring login whose grant expires at
    /// `expires_at` and whose shared tail published this install's key into
    /// `keys`: a synthetic `grant.token`, `device.key`, the id in
    /// `installs.json` and in `login.json`.
    fn ring_logged_in(
        keys: &FakeKeyStore,
        expires_at: u64,
    ) -> (TempDir, Dirs, LoginState, DeviceId) {
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        let token = GrantToken::from_exported(format!("pubky-grant-credential-v1:{PLANTED}"))
            .expect("a synthetic token");
        write_grant_token(&dirs, &token, None).expect("writes grant.token");
        let device = DeviceIdentity::generate();
        create_device_key(&dirs, &device, None).expect("writes device.key");
        let id: DeviceId = "0035G87EK4XFE".parse().expect("a valid id");
        let mut login = LoginState::ring(random_pubky(), random_pubky(), expires_at);
        record_install(&dirs, login.pubky, &id).expect("records");
        let record = device_key_record(&device.recipient(), time("2026-10-16T09:41:07Z"));
        keys.set_record(&id, device_key_bytes(&record).expect("JSON"));
        login.device_id = Some(id.clone());
        write_login_state(&dirs, &login).expect("writes");
        (temp, dirs, login, id)
    }

    /// The local files a Ring logout deletes, as snapshots.
    fn ring_files(dirs: &Dirs) -> [Option<FileSnapshot>; 4] {
        [
            dirs.grant_token_file(),
            dirs.device_key_file(),
            dirs.installs_file(),
            dirs.login_file(),
        ]
        .map(|path| FileSnapshot::of(&path))
    }

    /// Asserts that a Ring login's token and this install's files are gone.
    fn assert_ring_retired(dirs: &Dirs, login: &LoginState) {
        assert_gone(&dirs.grant_token_file());
        assert_gone(&dirs.device_key_file());
        assert_gone(&dirs.login_file());
        let installs = read_installs(dirs).expect("reads");
        assert!(installs.ids_of(&login.pubky).is_empty());
    }

    /// How the fake homeserver answers one restore of the saved token.
    #[derive(Clone, Copy)]
    enum Answer {
        /// A live session.
        Session,
        /// 401: the grant is revoked.
        Unauthorized,
        /// Anything else, such as a network error.
        Fails,
    }

    /// The four seams of a Ring logout, faked: `keys` as the homeserver's
    /// `keys/` (written with the live session, read anonymously), the
    /// restores' answers in order, whether the sign-out fails, whether the
    /// anonymous read is over its cap, and the steps taken, in order.
    #[derive(Default)]
    struct RingFakes {
        keys: FakeKeyStore,
        answers: Mutex<VecDeque<Answer>>,
        sign_out_fails: bool,
        own_read_too_large: bool,
        steps: Mutex<Vec<&'static str>>,
    }

    impl RingFakes {
        fn answering(answers: &[Answer]) -> Self {
            Self {
                answers: Mutex::new(answers.iter().copied().collect()),
                ..Self::default()
            }
        }

        fn step(&self, step: &'static str) {
            self.steps.lock().expect("lock").push(step);
        }

        fn steps(&self) -> Vec<&'static str> {
            self.steps.lock().expect("lock").clone()
        }
    }

    /// Runs [`retire_ring`] at [`NOW_UNIX`] with `fakes` as its seams; the
    /// fake session is the key store itself.
    async fn retire_ring_with(
        dirs: &Dirs,
        login: &LoginState,
        fakes: &RingFakes,
    ) -> anyhow::Result<(RetiredKey, EndedGrant)> {
        let owner = public_key_of(&login.pubky).expect("a key");
        retire_ring(
            dirs,
            login,
            NOW_UNIX,
            async || {
                fakes.step("restore");
                let answer = fakes.answers.lock().expect("lock").pop_front();
                match answer.expect("a scripted answer") {
                    Answer::Session => Ok(Restored::Live(&fakes.keys)),
                    Answer::Unauthorized => Ok(Restored::Refused),
                    Answer::Fails => bail!(FAKE_READ_FAILURE),
                }
            },
            async |keys, id| {
                fakes.step("revoke key");
                revoke_if_published(*keys, id, time(NOW)).await
            },
            async |_keys| {
                fakes.step("sign out");
                if fakes.sign_out_fails {
                    bail!(FAKE_READ_FAILURE);
                }
                Ok(())
            },
            async |id| {
                fakes.step("read own");
                if fakes.own_read_too_large {
                    return Err(BodyTooLarge {
                        cap: MAX_RECORD_BYTES,
                    }
                    .into());
                }
                fakes.keys.get_key(&owner, id).await
            },
        )
        .await
    }

    /// Marks the fake's `keys/<id>.json` revoked at `at`, as `keys revoke`
    /// from another install would.
    fn revoke_behind_the_back(keys: &FakeKeyStore, id: &DeviceId, at: &str) {
        let mut record = DeviceKey::from_json(&keys.record(id).expect("there")).expect("a record");
        record.revoked_at = Some(time(at));
        keys.set_record(id, device_key_bytes(&record).expect("JSON"));
    }

    #[tokio::test]
    async fn a_ring_logout_revokes_the_key_then_the_grant_then_checks_for_401() {
        let fakes = RingFakes::answering(&[Answer::Session, Answer::Unauthorized]);
        let (_temp, dirs, login, id) = ring_logged_in(&fakes.keys, LIVE_UNTIL);

        let retired = retire_ring_with(&dirs, &login, &fakes)
            .await
            .expect("logs out");
        assert_eq!(
            retired,
            (
                RetiredKey::Revoked(id.clone(), Revocation::Revoked(time(NOW))),
                EndedGrant::Revoked
            )
        );
        // The key with the live session, then the grant, then the restore
        // that proves it gone; nothing anonymous.
        assert_eq!(
            fakes.steps(),
            ["restore", "revoke key", "sign out", "restore"]
        );
        assert_eq!(revoked_at(&fakes.keys, &id), Some(time(NOW)));
        assert_ring_retired(&dirs, &login);
    }

    #[tokio::test]
    async fn the_token_goes_before_the_install_files() {
        // A grant.token that cannot be deleted (a directory in its place):
        // the grant is revoked by then, but device.key, login.json and the
        // install entry stay, so a second logout finds them and finishes.
        let fakes = RingFakes::answering(&[Answer::Session, Answer::Unauthorized]);
        let (_temp, dirs, login, _id) = ring_logged_in(&fakes.keys, LIVE_UNTIL);
        fs::remove_file(dirs.grant_token_file()).expect("remove");
        fs::create_dir(dirs.grant_token_file()).expect("a directory in its place");
        // The files deleted after grant.token, whose snapshot cannot read a
        // directory.
        let install_files = || {
            [
                dirs.device_key_file(),
                dirs.installs_file(),
                dirs.login_file(),
            ]
            .map(|path| FileSnapshot::of(&path))
        };
        let before = install_files();

        let err = retire_ring_with(&dirs, &login, &fakes)
            .await
            .expect_err("stops");
        let shown = format!("{err:#}");
        assert!(shown.contains("could not delete grant.token"), "{shown}");
        assert_eq!(install_files(), before);
    }

    #[tokio::test]
    async fn every_failure_before_the_401_keeps_the_token_and_the_files() {
        // (answers, sign-out fails, refuse key writes, steps taken)
        let cases: [(&[Answer], bool, bool, &[&str]); 5] = [
            // The first restore fails: nothing else is tried.
            (&[Answer::Fails], false, false, &["restore"]),
            // The key revoke fails: no sign-out, so the grant stays.
            (&[Answer::Session], false, true, &["restore", "revoke key"]),
            // The sign-out fails.
            (
                &[Answer::Session],
                true,
                false,
                &["restore", "revoke key", "sign out"],
            ),
            // The token still restores after the sign-out.
            (
                &[Answer::Session, Answer::Session],
                false,
                false,
                &["restore", "revoke key", "sign out", "restore"],
            ),
            // The restore after the sign-out fails, which proves nothing.
            (
                &[Answer::Session, Answer::Fails],
                false,
                false,
                &["restore", "revoke key", "sign out", "restore"],
            ),
        ];
        for (answers, sign_out_fails, refuse_puts, steps) in cases {
            let fakes = RingFakes {
                keys: if refuse_puts {
                    FakeKeyStore::refusing_puts(StatusCode::INTERNAL_SERVER_ERROR)
                } else {
                    FakeKeyStore::default()
                },
                sign_out_fails,
                ..RingFakes::answering(answers)
            };
            let (_temp, dirs, login, _id) = ring_logged_in(&fakes.keys, LIVE_UNTIL);
            let before = ring_files(&dirs);

            let err = retire_ring_with(&dirs, &login, &fakes)
                .await
                .expect_err("stops");
            let shown = format!("{err:#}");
            assert_eq!(fakes.steps(), steps);
            assert!(shown.contains("deleted nothing"), "{shown}");
            assert!(shown.contains("kept grant.token"), "{shown}");
            assert!(shown.contains("`sweepky logout` again"), "{shown}");
            assert!(
                shown.contains("revoke sweepky-cli in Pubky Ring"),
                "{shown}"
            );
            assert!(!shown.contains(FAKE_SERVER_TEXT), "{shown}");
            assert!(!shown.contains(PLANTED), "{shown}");
            assert_eq!(ring_files(&dirs), before);
        }
        // After the key revoke, the fixed text alone.
        let fakes = RingFakes {
            sign_out_fails: true,
            ..RingFakes::answering(&[Answer::Session])
        };
        let (_temp, dirs, login, _id) = ring_logged_in(&fakes.keys, LIVE_UNTIL);
        let err = retire_ring_with(&dirs, &login, &fakes)
            .await
            .expect_err("stops");
        assert_eq!(format!("{err:#}"), GRANT_NOT_CONFIRMED);
    }

    #[tokio::test]
    async fn an_expired_grant_with_an_unrevoked_key_stops_without_a_request() {
        let fakes = RingFakes::default();
        let (_temp, dirs, login, id) = ring_logged_in(&fakes.keys, EXPIRED_AT);
        let before = ring_files(&dirs);

        let err = retire_ring_with(&dirs, &login, &fakes)
            .await
            .expect_err("stops");
        let shown = format!("{err:#}");
        // Only the anonymous read: never a restore with the token.
        assert_eq!(fakes.steps(), ["read own"]);
        assert!(shown.contains("deleted nothing"), "{shown}");
        assert!(
            shown.contains(&format!("`sweepky keys revoke {id}`")),
            "{shown}"
        );
        assert_eq!(ring_files(&dirs), before);
    }

    #[tokio::test]
    async fn an_expired_grant_with_its_key_revoked_or_gone_finishes() {
        for revoked in [true, false] {
            let fakes = RingFakes::default();
            let (_temp, dirs, login, id) = ring_logged_in(&fakes.keys, EXPIRED_AT);
            let expected = if revoked {
                revoke_behind_the_back(&fakes.keys, &id, "2026-10-19T00:00:00Z");
                RetiredKey::Revoked(
                    id.clone(),
                    Revocation::AlreadyRevoked(time("2026-10-19T00:00:00Z")),
                )
            } else {
                // A 404, as P2a's NotPublished.
                fakes.keys.remove_record(&id);
                RetiredKey::NotPublished(id.clone())
            };

            let (key, grant) = retire_ring_with(&dirs, &login, &fakes)
                .await
                .expect("logs out");
            assert_eq!(key, expected);
            assert_eq!(grant, EndedGrant::Expired(EXPIRED_AT));
            assert_eq!(fakes.steps(), ["read own"]);
            assert_ring_retired(&dirs, &login);
            let text = report(&dirs, &login, &key, Some(&grant));
            assert!(text.contains("had expired"), "{text}");
            assert!(text.contains("deleted, not overwritten"), "{text}");
            assert!(
                text.contains(&dirs.grant_token_file().display().to_string()),
                "{text}"
            );
        }
    }

    #[tokio::test]
    async fn an_own_record_that_cannot_be_read_stops_a_locked_out_logout() {
        // A failed request, a body over the cap, a record that does not
        // parse; locked out by a 401 this time.
        for case in ["transport", "too large", "not a record"] {
            let mut fakes = RingFakes::answering(&[Answer::Unauthorized]);
            let (_temp, dirs, login, id) = ring_logged_in(&fakes.keys, LIVE_UNTIL);
            match case {
                "transport" => fakes.keys.fail_reads_of(&id),
                "too large" => fakes.own_read_too_large = true,
                _ => fakes
                    .keys
                    .set_record(&id, format!("{PLANTED} not JSON").into_bytes()),
            }
            let before = ring_files(&dirs);

            let err = retire_ring_with(&dirs, &login, &fakes)
                .await
                .expect_err("stops");
            let shown = format!("{err:#}");
            assert_eq!(fakes.steps(), ["restore", "read own"], "{case}");
            assert!(
                shown.contains(&format!("could not read keys/{id}.json")),
                "{shown}"
            );
            assert!(shown.contains("deleted nothing"), "{shown}");
            assert!(!shown.contains(PLANTED), "{shown}");
            assert_eq!(ring_files(&dirs), before, "{case}");
        }
    }

    /// Reads `id`'s record under `owner` from public storage, as anyone can.
    async fn public_record(
        ctx: &crate::Context,
        owner: &pubky::PublicKey,
        id: &DeviceId,
    ) -> DeviceKey {
        let bytes = PublicKeyReader::new(ctx.network.pubky())
            .get_key(owner, id)
            .await
            .expect("reads")
            .expect("published");
        DeviceKey::from_json(&bytes).expect("a record")
    }

    /// Creates `path` with `text`, and its directory 0700 if need be.
    fn write_state_file(path: &Path, text: &str) {
        let dir = path.parent().expect("a directory");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .expect("creates");
        fs::write(path, text).expect("writes");
    }

    #[tokio::test]
    #[pubky_testnet::test]
    async fn a_ring_logout_leaves_the_saved_token_unable_to_restore() {
        let testnet = ring_testnet().await;
        let home = private_temp();
        let (ctx, _stderr, ring) = ring_login(&testnet, &home).await;
        let login = read_login_state(&ctx.dirs)
            .expect("reads")
            .expect("logged in");
        let id = login.device_id.clone().expect("a device key");
        let owner = ring.public_key();
        let published = public_record(&ctx, &owner, &id).await;
        // The token A saved at login, copied before logout.
        let saved = read_grant_token(&ctx.dirs, None)
            .expect("reads")
            .expect("saved");
        // The locks and the state files logout must leave alone.
        PullLock::open(&ctx.dirs).expect("creates pull.lock");
        write_state_file(&ctx.dirs.feed_cursors_file(), "synthetic cursors");
        write_state_file(&ctx.dirs.poll_state_file(), "synthetic poll state");
        let state = [ctx.dirs.feed_cursors_file(), ctx.dirs.poll_state_file()]
            .map(|path| FileSnapshot::of(&path));

        let report = logout(&ctx).await.expect("logs out");
        let text = report.text();
        assert!(text.contains(&format!("Revoked keys/{id}.json")), "{text}");
        assert!(
            text.contains("Revoked this install's Pubky Ring grant"),
            "{text}"
        );
        assert!(!text.contains(saved.expose_secret()), "{text}");

        // Anyone reading the record sees it revoked, with the same key.
        let retired = public_record(&ctx, &owner, &id).await;
        assert!(retired.revoked_at.is_some());
        assert_eq!(retired.recipient, published.recipient);
        assert_ring_retired(&ctx.dirs, &login);
        assert_eq!(mode(&ctx.dirs.credential_lock_file()), 0o600);
        assert_eq!(mode(&ctx.dirs.pull_lock_file()), 0o600);
        assert_eq!(
            [ctx.dirs.feed_cursors_file(), ctx.dirs.poll_state_file()]
                .map(|path| FileSnapshot::of(&path)),
            state
        );

        // Done when: the token saved at login now restores to a 401.
        let Err(error) = testnet
            .sdk()
            .expect("client")
            .restore_session(saved.expose_secret())
            .await
        else {
            panic!("the saved token still restores after logout");
        };
        assert_eq!(status_of(&error), Some(StatusCode::UNAUTHORIZED));
    }

    #[tokio::test]
    #[pubky_testnet::test]
    async fn a_grant_revoked_in_ring_logs_out_once_the_key_is_revoked_elsewhere() {
        let testnet = ring_testnet().await;
        let home = private_temp();
        let (ctx, _stderr, ring) = ring_login(&testnet, &home).await;
        let login = read_login_state(&ctx.dirs)
            .expect("reads")
            .expect("logged in");
        let id = login.device_id.clone().expect("a device key");
        // Revoked behind this install's back: the test restores the saved
        // token and signs it out.
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
        let before = ring_files(&ctx.dirs);

        // The key record is still unrevoked: logout stops and keeps it all.
        let err = logout(&ctx).await.expect_err("stops");
        let shown = format!("{err:#}");
        assert!(shown.contains("deleted nothing"), "{shown}");
        assert!(
            shown.contains(&format!("`sweepky keys revoke {id}`")),
            "{shown}"
        );
        assert_eq!(ring_files(&ctx.dirs), before);

        // Another install (here the root key) revokes the record.
        let mut record = public_record(&ctx, &ring.public_key(), &id).await;
        record.revoked_at = Some(time(NOW));
        ring.root()
            .storage()
            .put(paths::key(&id), device_key_bytes(&record).expect("JSON"))
            .await
            .expect("the root key writes");

        let report = logout(&ctx).await.expect("logs out");
        let text = report.text();
        assert!(text.contains("already revoked or expired"), "{text}");
        assert!(text.contains("was revoked already"), "{text}");
        assert_ring_retired(&ctx.dirs, &login);
    }
}
