//! This install's own state files in the config directory, and reading and
//! writing them:
//!
//! - [`LoginState`], `login.json`: which login this install uses. For a
//!   dedicated identity, `{"schemaVersion":1,"kind":"identity","name":…,
//!   "pubky":"<z32>","homeserver":"<z32>","deviceId":"<id>"}`; for a Pubky
//!   Ring login, `{"schemaVersion":1,"kind":"ring","pubky":"<z32>",
//!   "homeserver":"<z32>","grantExpiresAt":<unix seconds>,
//!   "deviceId":"<id>"}`, with no name. Either way plus any fields a newer
//!   Sweepky added; `deviceId` appears once this install's device key is
//!   published. It holds no secret, and no secret may ever be added to it:
//!   the secret lives in its own file (`identities/<name>.key`, or
//!   `grant.token` for Ring, `crate::ring::token`).
//! - A dedicated identity's two files, `identities/<name>.key` (the secret,
//!   wrapped with a passphrase when `login` was given `--passphrase-file`)
//!   and `identities/<name>.json` (its public details), read together by
//!   [`read_identity`] into a [`StoredIdentity`].
//!
//! Every file goes through [`crate::private_fs`]: directories 0700, files
//! 0600 written to a temp file then renamed, no links followed, loose or
//! oversized files refused. Everything here runs while the caller holds the
//! writers' lock, so two commands never write these files at once.

use std::path::Path;

use anyhow::{Context as _, bail};
use serde::{Deserialize, Serialize};
use sweepky_core::{DeviceId, Pubky, RecordError, SchemaVersion, UnknownFields};

use crate::Dirs;
use crate::identity::{
    IdentityMeta, IdentityName, IdentitySecret, MAX_IDENTITY_FILE_BYTES, MAX_IDENTITY_META_BYTES,
};
use crate::passphrase::{Passphrase, write_secret_file};
use crate::private_fs::{ensure_private_dir, read_private_file, write_private_file};

/// The most Sweepky reads of `login.json`: 64 KiB. The file is a few hundred
/// bytes; the rest is room for fields a newer Sweepky adds.
const MAX_LOGIN_FILE_BYTES: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// login.json

/// What kind of login `login.json` records: an open-string enum, so a
/// `login.json` a newer Sweepky wrote with a kind this build does not know
/// still parses, and the command that needs a session says what is wrong
/// instead of failing to read the file at all.
///
/// A `String` newtype, as for every open enum in the records (03, "Rust
/// conventions"); [`LoginKind::as_known`] is how code looks at it.
/// `transparent` makes serde read and write it as the bare string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct LoginKind(String);

/// The kinds of login this build knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KnownLoginKind {
    /// A dedicated identity, `login --identity <name>`.
    Identity,
    /// The pubky the user already has in Pubky Ring, signed in through a
    /// grant Ring approved: `login` without `--identity` (P2d).
    Ring,
}

impl KnownLoginKind {
    /// The string `login.json` holds for this kind.
    fn as_str(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Ring => "ring",
        }
    }
}

impl LoginKind {
    /// The kind, when this build knows it. The match is exact and
    /// case-sensitive.
    pub(crate) fn as_known(&self) -> Option<KnownLoginKind> {
        match self.0.as_str() {
            "identity" => Some(KnownLoginKind::Identity),
            "ring" => Some(KnownLoginKind::Ring),
            _ => None,
        }
    }
}

impl From<KnownLoginKind> for LoginKind {
    fn from(kind: KnownLoginKind) -> Self {
        Self(kind.as_str().to_owned())
    }
}

/// `login.json`: which login this install uses.
///
/// Holds public values only (a name, two public keys, a device id, when a
/// grant expires), so deriving `Debug` prints nothing secret.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
// The Rust fields are snake_case; the JSON keys camelCase, as in records.
#[serde(rename_all = "camelCase")]
pub(crate) struct LoginState {
    /// The format's version, 1.
    pub(crate) schema_version: SchemaVersion,
    /// What kind of login this is.
    pub(crate) kind: LoginKind,
    /// The identity's name, for a dedicated identity. `Option` with
    /// `default` and `skip_serializing_if`, because the Ring login has no
    /// name: a missing key reads as `None`, and `None` is not written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<IdentityName>,
    /// The pubky this install is logged in as, raw z-base32.
    pub(crate) pubky: Pubky,
    /// Its homeserver, raw z-base32.
    pub(crate) homeserver: Pubky,
    /// The id this install's device key is published under,
    /// `keys/<deviceId>.json`. The shared tail of `login` sets it once that
    /// write has gone through; until then it is `None`, which is not
    /// written, so a login whose key write was refused records none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) device_id: Option<DeviceId>,
    /// When the grant a Ring login holds expires, in seconds since the Unix
    /// epoch: the grant's own `exp`, which the homeserver reports with the
    /// session. A number, not RFC 3339 text, so a later run compares it
    /// with the clock without parsing a date; it is shown with
    /// `crate::ring::expiry_text`. Public, as the rest of the file is. A
    /// dedicated identity has no grant, so it has `None`, which is not
    /// written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) grant_expires_at: Option<u64>,
    /// Fields a newer Sweepky wrote, kept for the rewrite.
    #[serde(flatten)]
    pub(crate) extra: UnknownFields,
}

impl LoginState {
    /// The state of a login with the dedicated identity `name`, before its
    /// device key is recorded.
    pub(crate) fn identity(name: IdentityName, pubky: Pubky, homeserver: Pubky) -> Self {
        Self {
            schema_version: SchemaVersion::CURRENT,
            kind: KnownLoginKind::Identity.into(),
            name: Some(name),
            pubky,
            homeserver,
            device_id: None,
            grant_expires_at: None,
            extra: UnknownFields::new(),
        }
    }

    /// The state of a Pubky Ring login as `pubky` on `homeserver`, whose
    /// grant expires at `grant_expires_at` (Unix seconds), before its device
    /// key is recorded. The grant token itself is not here: it is a secret,
    /// and lives in `grant.token` (`crate::ring::token`).
    pub(crate) fn ring(pubky: Pubky, homeserver: Pubky, grant_expires_at: u64) -> Self {
        Self {
            schema_version: SchemaVersion::CURRENT,
            kind: KnownLoginKind::Ring.into(),
            name: None,
            pubky,
            homeserver,
            device_id: None,
            grant_expires_at: Some(grant_expires_at),
            extra: UnknownFields::new(),
        }
    }

    /// The file's bytes: pretty-printed JSON and a newline.
    fn to_json(&self) -> anyhow::Result<Vec<u8>> {
        let mut json = serde_json::to_vec_pretty(self).context("could not write login.json")?;
        json.push(b'\n');
        Ok(json)
    }

    /// Reads the file's bytes. A newer version or a key that is not one is
    /// an error. serde_json's own messages can quote the input, so they go
    /// through core's `RecordError`, which keeps only the kind of fault and
    /// where it is, as every record parse does.
    fn from_json(bytes: &[u8]) -> anyhow::Result<Self> {
        serde_json::from_slice(bytes)
            .map_err(RecordError::from)
            .context("login.json is not valid")
    }
}

/// Reads `login.json`, or `None` when this install has not logged in.
pub(crate) fn read_login_state(dirs: &Dirs) -> anyhow::Result<Option<LoginState>> {
    let path = dirs.login_file();
    let Some(bytes) = read_private_file(&path, MAX_LOGIN_FILE_BYTES)? else {
        return Ok(None);
    };
    // `&bytes` is a `&Zeroizing<Vec<u8>>`, read as a `&[u8]` through
    // `Deref`. Nothing here is secret; the buffer simply comes that way.
    LoginState::from_json(&bytes)
        .with_context(|| format!("could not read {}", path.display()))
        .map(Some)
}

/// Writes `login.json` (0600), creating the config directory (0700) if it is
/// not there yet.
pub(crate) fn write_login_state(dirs: &Dirs, state: &LoginState) -> anyhow::Result<()> {
    ensure_private_dir(dirs.config())?;
    write_private_file(&dirs.login_file(), &state.to_json()?)
}

// ---------------------------------------------------------------------------
// A dedicated identity's files.

/// What the config directory holds for one identity name.
///
/// No `Debug`: two of the variants hold an [`IdentitySecret`], which has
/// none, so the compiler could not derive one anyway.
pub(crate) enum StoredIdentity {
    /// Neither file: the name is free, and `login` creates a new identity.
    Missing,
    /// `<name>.key` without `<name>.json`. That is how P2c's second install
    /// gets the identity: by copying the key file alone. `login` rebuilds
    /// the details from the key and the identity's pkarr record.
    KeyOnly(IdentitySecret),
    /// Both files, checked to agree: the details name this name and the
    /// key's own pubky.
    Complete {
        /// The secret, from `<name>.key`.
        secret: IdentitySecret,
        /// The public details, from `<name>.json`.
        meta: IdentityMeta,
    },
}

/// Reads the identity `name`'s two files.
///
/// The key file is read only in Sweepky's own format
/// ([`IdentitySecret::from_file_bytes`]), so a Pubky recovery file, a raw
/// key or a recovery phrase someone dropped in as `<name>.key` is refused
/// with its one-line reason, never imported. A key file wrapped with a
/// passphrase is unwrapped with `passphrase` first
/// ([`IdentitySecret::from_stored`]), and without one is an error that says
/// how to give it. Refused too: details without a key (the secret is gone,
/// and a new key would be a different pubky), and details that name another
/// identity or another pubky than the key's.
pub(crate) fn read_identity(
    dirs: &Dirs,
    name: &IdentityName,
    passphrase: Option<&Passphrase>,
) -> anyhow::Result<StoredIdentity> {
    let key_path = dirs.identity_key_file(name);
    let meta_path = dirs.identity_file(name);
    let key_bytes = read_private_file(&key_path, MAX_IDENTITY_FILE_BYTES)?;
    let meta_bytes = read_private_file(&meta_path, MAX_IDENTITY_META_BYTES)?;
    let Some(key_bytes) = key_bytes else {
        if meta_bytes.is_some() {
            bail!(
                "{} is there but {} is not, so the identity's secret is gone; Sweepky will not \
                 make a new key under a name that names another pubky. Move {} away, or use \
                 another name",
                meta_path.display(),
                key_path.display(),
                meta_path.display()
            );
        }
        return Ok(StoredIdentity::Missing);
    };
    // `key_bytes` moves into `from_stored`, which unwraps it if it is
    // wrapped and wipes it when done either way.
    let secret = IdentitySecret::from_stored(&key_path, key_bytes, passphrase)
        .with_context(|| format!("could not read {}", key_path.display()))?;
    let Some(meta_bytes) = meta_bytes else {
        return Ok(StoredIdentity::KeyOnly(secret));
    };
    let meta = IdentityMeta::from_json(&meta_bytes)
        .with_context(|| format!("could not read {}", meta_path.display()))?;
    check_details_match(&meta_path, &meta, name, &secret)?;
    Ok(StoredIdentity::Complete { secret, meta })
}

/// Refuses details that do not belong to `name`'s key. They are only a
/// cache, so the fix is to delete them and let `login` rebuild them.
fn check_details_match(
    meta_path: &Path,
    meta: &IdentityMeta,
    name: &IdentityName,
    secret: &IdentitySecret,
) -> anyhow::Result<()> {
    // `Pubky`'s `==` compares the 32 key bytes. These are public keys, so a
    // plain, early-exit comparison leaks nothing.
    if &meta.name != name || meta.pubky != secret.pubky() {
        bail!(
            "{} does not match the identity's key file; it is only a cache, so delete it and run \
             login again to rebuild it",
            meta_path.display()
        );
    }
    Ok(())
}

/// Writes a new identity's two files: the secret first, then the details.
/// The secret's file is wrapped with `passphrase` when there is one; the
/// details are public and never wrapped.
///
/// In that order so a crash in between leaves a key without details, which
/// `login` picks up again ([`StoredIdentity::KeyOnly`]), and never details
/// without their key.
pub(crate) fn create_identity(
    dirs: &Dirs,
    secret: &IdentitySecret,
    meta: &IdentityMeta,
    passphrase: Option<&Passphrase>,
) -> anyhow::Result<()> {
    ensure_private_dir(&dirs.identities_dir())?;
    // `to_file_bytes` returns a `Zeroizing` buffer that wipes the secret's
    // hex when this statement ends and the temporary is dropped.
    write_secret_file(
        &dirs.identity_key_file(&meta.name),
        &secret.to_file_bytes(),
        passphrase,
    )?;
    write_identity_meta(dirs, meta)
}

/// Writes (or rewrites) an identity's details, `identities/<name>.json`.
pub(crate) fn write_identity_meta(dirs: &Dirs, meta: &IdentityMeta) -> anyhow::Result<()> {
    ensure_private_dir(&dirs.identities_dir())?;
    write_private_file(&dirs.identity_file(&meta.name), &meta.to_json()?)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::json;
    use sweepky_core::DeviceId;

    use super::{
        KnownLoginKind, LoginState, StoredIdentity, create_identity, read_identity,
        read_login_state, write_identity_meta, write_login_state,
    };
    use crate::Dirs;
    use crate::identity::{IdentityMeta, IdentityName, IdentitySecret, Refusal};
    use crate::test_support::{dirs_in, mode, private_temp, random_pubky};

    #[test]
    fn login_state_round_trips_and_keeps_unknown_fields() {
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        assert!(read_login_state(&dirs).expect("reads").is_none());

        let name: IdentityName = "throwaway".parse().expect("valid");
        let state = LoginState::identity(name, random_pubky(), random_pubky());
        write_login_state(&dirs, &state).expect("writes");
        assert_eq!(mode(&dirs.login_file()), 0o600);
        assert_eq!(mode(dirs.config()), 0o700);
        let read = read_login_state(&dirs).expect("reads").expect("present");
        assert_eq!(read, state);
        assert_eq!(read.kind.as_known(), Some(KnownLoginKind::Identity));

        // A field and a kind from a newer Sweepky: the file still reads, the
        // kind is not one this build knows, and the field survives a rewrite.
        let mut newer = serde_json::to_value(&state).expect("serializes");
        newer["kind"] = json!("hardware-key");
        newer["deviceLabel"] = json!("laptop");
        fs::write(dirs.login_file(), serde_json::to_vec(&newer).expect("json")).expect("write");
        let read = read_login_state(&dirs).expect("reads").expect("present");
        assert_eq!(read.kind.as_known(), None);
        write_login_state(&dirs, &read).expect("rewrites");
        let raw: serde_json::Value =
            serde_json::from_slice(&fs::read(dirs.login_file()).expect("read")).expect("json");
        assert_eq!(raw["deviceLabel"], json!("laptop"));
    }

    #[test]
    fn ring_login_state_round_trips_with_its_expiry_and_no_name() {
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        let (pubky, homeserver) = (random_pubky(), random_pubky());
        // 2028-10-19T00:00:00Z, two years after a login on 2026-10-20.
        let expires_at = 1_855_526_400;
        let mut state = LoginState::ring(pubky, homeserver, expires_at);
        write_login_state(&dirs, &state).expect("writes");
        assert_eq!(mode(&dirs.login_file()), 0o600);

        // On disk: kind `ring`, the expiry as a number of seconds, and no
        // `name` (a Ring login has none) and no `deviceId` yet.
        let raw = raw_login_json(&dirs);
        assert_eq!(raw["kind"], json!("ring"));
        assert_eq!(raw["grantExpiresAt"], json!(expires_at));
        assert_eq!(raw["pubky"], serde_json::to_value(pubky).expect("json"));
        assert_eq!(
            raw["homeserver"],
            serde_json::to_value(homeserver).expect("json")
        );
        assert!(raw.get("name").is_none(), "{raw}");
        assert!(raw.get("deviceId").is_none(), "{raw}");
        let read = read_login_state(&dirs).expect("reads").expect("present");
        assert_eq!(read, state);
        assert_eq!(read.kind.as_known(), Some(KnownLoginKind::Ring));

        // The shared tail sets the device id; it is written from then on.
        let device_id: DeviceId = "0035G87EK4XFE".parse().expect("valid");
        state.device_id = Some(device_id.clone());
        write_login_state(&dirs, &state).expect("rewrites");
        assert_eq!(raw_login_json(&dirs)["deviceId"], json!(device_id.as_str()));

        // A field from a newer Sweepky survives a rewrite of a Ring login.
        let mut newer = raw_login_json(&dirs);
        newer["grantLabel"] = json!("laptop");
        fs::write(dirs.login_file(), serde_json::to_vec(&newer).expect("json")).expect("write");
        let read = read_login_state(&dirs).expect("reads").expect("present");
        assert_eq!(read.grant_expires_at, Some(expires_at));
        write_login_state(&dirs, &read).expect("rewrites");
        assert_eq!(raw_login_json(&dirs)["grantLabel"], json!("laptop"));
    }

    #[test]
    fn identity_login_state_has_no_grant_expiry() {
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        let name: IdentityName = "throwaway".parse().expect("valid");
        let state = LoginState::identity(name, random_pubky(), random_pubky());
        write_login_state(&dirs, &state).expect("writes");
        let raw = raw_login_json(&dirs);
        assert!(raw.get("grantExpiresAt").is_none(), "{raw}");
        assert_eq!(state.grant_expires_at, None);
    }

    /// `login.json` as JSON, read straight from the disk.
    fn raw_login_json(dirs: &Dirs) -> serde_json::Value {
        serde_json::from_slice(&fs::read(dirs.login_file()).expect("read")).expect("json")
    }

    #[test]
    fn stored_identity_states() {
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        let name: IdentityName = "throwaway".parse().expect("valid");
        assert!(matches!(
            read_identity(&dirs, &name, None).expect("reads"),
            StoredIdentity::Missing
        ));

        // Both files, as `login` creates them: the key 0600 in a 0700
        // directory.
        let secret = IdentitySecret::generate();
        let pubky = secret.pubky();
        let meta = IdentityMeta::new(name.clone(), pubky, random_pubky(), false);
        create_identity(&dirs, &secret, &meta, None).expect("creates");
        assert_eq!(mode(&dirs.identity_key_file(&name)), 0o600);
        assert_eq!(mode(&dirs.identity_file(&name)), 0o600);
        assert_eq!(mode(&dirs.identities_dir()), 0o700);
        match read_identity(&dirs, &name, None).expect("reads") {
            StoredIdentity::Complete {
                secret: read,
                meta: read_meta,
            } => {
                assert_eq!(read.pubky(), pubky);
                assert_eq!(read_meta, meta);
            }
            _ => panic!("expected both files"),
        }

        // The key alone, as P2c copies it, is an identity whose details
        // `login` rebuilds.
        fs::remove_file(dirs.identity_file(&name)).expect("remove");
        match read_identity(&dirs, &name, None).expect("reads") {
            StoredIdentity::KeyOnly(read) => assert_eq!(read.pubky(), pubky),
            _ => panic!("expected the key alone"),
        }

        // Details for another pubky than the key's are refused.
        let other = IdentityMeta::new(name.clone(), random_pubky(), random_pubky(), true);
        write_identity_meta(&dirs, &other).expect("writes");
        assert!(read_identity(&dirs, &name, None).is_err());

        // Details without their key: the secret is gone, refused.
        fs::remove_file(dirs.identity_key_file(&name)).expect("remove");
        assert!(read_identity(&dirs, &name, None).is_err());
    }

    #[test]
    fn a_recovery_file_as_the_key_file_is_refused() {
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        let name: IdentityName = "throwaway".parse().expect("valid");
        let secret = IdentitySecret::generate();
        let meta = IdentityMeta::new(name.clone(), secret.pubky(), random_pubky(), true);
        create_identity(&dirs, &secret, &meta, None).expect("creates");

        // Someone drops a recovery file in place of the key file. Built here
        // from its fixed first line and some bytes; the classifier looks at
        // the first line alone.
        fs::write(
            dirs.identity_key_file(&name),
            b"pubky.org/recovery\nsynthetic encrypted bytes",
        )
        .expect("write");
        let err = read_identity(&dirs, &name, None)
            .err()
            .expect("a recovery file is refused");
        assert_eq!(
            err.downcast_ref::<Refusal>(),
            Some(&Refusal::RecoveryFile),
            "{err:#}"
        );
    }
}
