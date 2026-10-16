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
//! `credential.lock` is never deleted, because a new lock file would let a
//! second writer in while another command still holds the old one.
//!
//! P2d slots the Pubky Ring login into steps 3 and 4: revoke the grant (its
//! sign-out), check that restoring the saved token gets a 401, and delete
//! the token instead of an identity.

use anyhow::{Context as _, bail};
use sweepky_core::{DeviceId, RecordTime};

use crate::clock;
use crate::device::{SessionKeyStore, remove_device_key};
use crate::display::sanitize;
use crate::installs::forget_owner;
use crate::keys::{Revocation, revoke_if_published};
use crate::private_fs::{lstat, remove_private_file};
use crate::session::{sign_in, with_writers_lock};
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

/// Runs `logout`: steps 1 to 5 of the module docs.
pub(crate) async fn logout(ctx: &Context) -> anyhow::Result<Report> {
    with_writers_lock(ctx, async || {
        let login = login_to_retire(&ctx.dirs)?;
        // Read before the sign-in: a `?` between the sign-in and `retire`
        // would return before the sign-out.
        let now = clock::now()?;
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
        Ok(Report::new(report(&ctx.dirs, &login, &key)))
    })
    .await
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
/// dedicated identity that is its two files.
///
/// The details go first, then the secret: should the second deletion fail,
/// the key file alone is still an identity the next `logout` can sign in
/// with. The other way round would leave details without their key, which
/// nothing signs in with any more.
fn forget_credential(dirs: &Dirs, login: &LoginState) -> anyhow::Result<()> {
    // `sign_in` has refused any other kind of login by now, so this is a
    // second check, not a branch that runs. P2d adds the Ring kind here,
    // whose credential is the saved grant token.
    let (Some(KnownLoginKind::Identity), Some(name)) = (login.kind.as_known(), &login.name) else {
        bail!("login.json does not name a dedicated identity, so there is no identity to forget");
    };
    remove_private_file(&dirs.identity_file(name))?;
    remove_private_file(&dirs.identity_key_file(name))
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
            "logout forgot the identity, but could not delete all of this install's files ({}); \
             delete what is left by hand",
            left.join("; ")
        );
    }
    Ok(())
}

/// What `logout` reports once it is done: fixed text, device ids, the
/// user's own paths and pubky, and the time this logout wrote.
fn report(dirs: &Dirs, login: &LoginState, key: &RetiredKey) -> String {
    let mut text = key.report_line();
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
    use std::fs;
    use std::path::Path;

    use pubky::StatusCode;
    use serde_json::json;
    use sweepky_core::{DeviceId, DeviceIdentity, DeviceKey, RecordTime};
    use tempfile::TempDir;

    use super::{RetiredKey, login_to_retire, retire};
    use crate::Dirs;
    use crate::device::{create_device_key, device_key_bytes, device_key_record};
    use crate::identity::{IdentityMeta, IdentityName, IdentitySecret};
    use crate::installs::{read_installs, record_install};
    use crate::keys::{Revocation, revoke_if_published};
    use crate::lock::WritersLock;
    use crate::private_fs::lstat;
    use crate::state::{
        LoginState, StoredIdentity, create_identity, read_identity, write_login_state,
    };
    use crate::test_support::{
        FAKE_SERVER_TEXT, FakeKeyStore, FileSnapshot, KeyStoreCall, dirs_in, mode, private_temp,
        random_pubky,
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
        // Files that are not this install's login: the lock, another
        // identity, another owner's install, a file of the user's own.
        WritersLock::open(&dirs).expect("creates credential.lock");
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

        // Kept: the lock file, which is never deleted, the other identity,
        // the other owner's install and the user's file.
        assert_eq!(mode(&dirs.credential_lock_file()), 0o600);
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
}
