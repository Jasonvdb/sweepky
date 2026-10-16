//! This install's device key: the age identity that opens the sweeps
//! encrypted to this install, its public record `keys/<deviceId>.json`, and
//! [`KeyStore`], the seam that record is read and written through.
//!
//! - [`new_device_id`] names a new install's key: a [`RecordId`] made from
//!   the clock, 13 characters of upper-case Crockford base32, such as
//!   `0035G87EK4XFE`. That is always a valid [`DeviceId`], and it sorts by
//!   when the install was made, as every other Sweepky id does.
//! - [`device_key_record`] is the record `login` publishes:
//!   `{"schemaVersion":1,"alg":"age-x25519","recipient":"age1…",
//!   "label":"sweepky-cli","createdAt":"<RFC 3339>","revokedAt":null}`.
//! - [`create_device_key`] writes the secret to `device.key`, never over a
//!   key that is already there; [`read_device_key`] reads it back and
//!   [`remove_device_key`] deletes it.
//! - [`KeyStore`] reads and writes `keys/<deviceId>.json` records.
//!   [`SessionKeyStore`] is the real one, on a signed-in session and the
//!   public storage; the unit tests use a fake in memory
//!   (`test_support::FakeKeyStore`) that can be told to refuse a write.
//!
//! **Why the label is fixed.** `keys/` is world-readable, so a label such as
//! the machine's host name would tell everyone what the owner's machines are
//! called. Every install writes `sweepky-cli`, the client id.
//!
//! **The key file holds the secret and nothing else**: age's 74-byte
//! `AGE-SECRET-KEY-1…` string, no newline, 0600, written to a temp file and
//! renamed into place ([`crate::private_fs`]). [`DeviceIdentity`] has no
//! `Debug`, `Display` or `Serialize`, so it cannot be printed or logged; its
//! text exists only inside a [`SecretString`], which wipes itself, on its way
//! to and from that file.

use anyhow::{Context as _, bail};
use pubky::{PubkySession, PublicKey};
use sweepky_core::paths::{self, SweepkyPath};
use sweepky_core::{
    DeviceId, DeviceIdentity, DeviceKey, ExposeSecret, KnownKeyAlg, MAX_RECORD_BYTES, RecordId,
    RecordTime, SchemaVersion, SecretString, Timestamp, UnknownFields, Zeroizing,
};

use crate::Dirs;
use crate::clock;
use crate::private_fs::{
    ensure_private_dir, lstat, read_private_file, remove_private_file, write_private_file,
};
use crate::remote::{ListLimits, Listing, get_own, list_dir};

/// The `label` of every key this CLI publishes. Fixed, because `keys/` is
/// public and a host name there would leak (see the module docs).
const DEVICE_KEY_LABEL: &str = "sweepky-cli";

/// The most Sweepky reads of `device.key`: 4 KiB. The plain key is 74 bytes;
/// the rest is room for the passphrase-wrapped form a later step adds.
const MAX_DEVICE_KEY_FILE_BYTES: usize = 4096;

/// What `device.key` holds when it is not an age identity. Fixed text: the
/// file is a secret, so no message quotes any of it.
const NOT_A_DEVICE_KEY: &str = "is not a Sweepky device key: one age identity and nothing else";

/// A new device id, from the clock.
///
/// `Timestamp::now()` is microseconds since 1970, with its last byte a
/// random "clock id" that pubky-timestamp picks once per process, so two
/// installs that start in the same microsecond still differ, and it never
/// repeats within a process. It panics on a clock set before 1970, so this
/// function first asks `clock::now()`, which refuses such a clock with a
/// message instead. The check lives here rather than with each caller, so
/// that no caller can forget it.
pub(crate) fn new_device_id() -> anyhow::Result<DeviceId> {
    // Only the check is wanted; the time it reads is dropped.
    clock::now()?;
    let id = RecordId::from_timestamp(Timestamp::now());
    // 13 characters of `0-9` and `A-Z` always pass the device-id check, so
    // this cannot fail; the parse still runs the check, and its error is
    // returned rather than unwrapped, because nothing here may panic.
    id.to_string()
        .parse()
        .context("could not make a device id from the clock")
}

/// The `keys/<deviceId>.json` record for `identity`, made at `created_at`:
/// `alg` `age-x25519`, the identity's recipient, the fixed label, and
/// `revokedAt` `null`.
pub(crate) fn device_key_record(identity: &DeviceIdentity, created_at: RecordTime) -> DeviceKey {
    DeviceKey {
        schema_version: SchemaVersion::CURRENT,
        // `.into()` builds the open-string `KeyAlg` from the known value, so
        // the text is the one core matches on, `age-x25519`.
        alg: KnownKeyAlg::AgeX25519.into(),
        recipient: identity.recipient().to_string(),
        label: DEVICE_KEY_LABEL.to_owned(),
        created_at,
        revoked_at: None,
        extra: UnknownFields::new(),
    }
}

/// The record's bytes as they are published: compact JSON, `revokedAt`
/// written as `null` (core's `DeviceKey` never leaves it out).
pub(crate) fn device_key_bytes(record: &DeviceKey) -> anyhow::Result<Vec<u8>> {
    serde_json::to_vec(record).context("could not write the device key record")
}

/// Writes `identity` to `device.key` (0600, in the 0700 config directory),
/// unless something is already there.
///
/// It never replaces a key: an existing `device.key` may be the only key
/// that opens the sweeps encrypted to it, so it is refused and left alone.
/// The check and the write are two steps, which is safe because every
/// caller holds the writers' lock, so no other `sweepky` command writes the
/// config directory meanwhile.
pub(crate) fn create_device_key(dirs: &Dirs, identity: &DeviceIdentity) -> anyhow::Result<()> {
    let path = dirs.device_key_file();
    // `lstat` does not follow a link, so a link at the path, even one
    // pointing nowhere, counts as something there.
    if lstat(&path)?.is_some() {
        bail!(
            "{} already holds a device key that login.json does not record; Sweepky never \
             replaces a device key, because it may be the only key that opens the sweeps \
             encrypted to it. Move the file somewhere safe and run `sweepky login` again",
            path.display()
        );
    }
    ensure_private_dir(dirs.config())?;
    // `to_secret_string` hands out the identity's text in a `SecretString`,
    // which is wiped when it is dropped at the end of this function;
    // `expose_secret` lends it out for the one write, without a copy.
    let secret = identity.to_secret_string();
    write_private_file(&path, secret.expose_secret().as_bytes())
}

/// Reads this install's identity back from `device.key`, or `None` when
/// there is no such file.
// Only the tests read the key back so far. `expect` (rather than `allow`)
// warns once there is a caller, so whoever adds it deletes this line.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "login's reuse of an existing key and pull, later steps, are the first callers"
    )
)]
pub(crate) fn read_device_key(dirs: &Dirs) -> anyhow::Result<Option<DeviceIdentity>> {
    let path = dirs.device_key_file();
    let Some(bytes) = read_private_file(&path, MAX_DEVICE_KEY_FILE_BYTES)? else {
        return Ok(None);
    };
    // `from_utf8` borrows the bytes as a `&str`, copying nothing. Its error
    // is dropped for fixed text.
    let Ok(text) = std::str::from_utf8(&bytes) else {
        bail!("{} {NOT_A_DEVICE_KEY}", path.display());
    };
    // One copy, into a `SecretString`, which wipes it when dropped. The copy
    // is made at exactly the text's length, so turning it into the boxed
    // `str` a `SecretString` holds does not reallocate it and leave an
    // unwiped copy behind.
    let secret = SecretString::from(text);
    // core's `IdentityError` is fixed text and holds none of the input, so
    // it can go in the chain as it is.
    DeviceIdentity::from_secret(&secret)
        .map(Some)
        .with_context(|| format!("{} {NOT_A_DEVICE_KEY}", path.display()))
}

/// Deletes `device.key`. A missing file counts as success.
pub(crate) fn remove_device_key(dirs: &Dirs) -> anyhow::Result<()> {
    remove_private_file(&dirs.device_key_file())
}

/// The device ids found under an owner's `keys/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyIds {
    /// The ids, in the order the homeserver listed them.
    pub(crate) ids: Vec<DeviceId>,
    /// How many entries were not a `keys/<deviceId>.json` (another owner's,
    /// a name that is not a valid device id, anything else). A count only:
    /// the names are the homeserver's text.
    pub(crate) skipped: usize,
}

impl KeyIds {
    /// The device ids of a `keys/` listing.
    fn from_listing(listing: Listing) -> Self {
        let mut ids = Vec::new();
        let mut skipped = listing.skipped;
        for entry in listing.entries {
            match entry {
                SweepkyPath::Key(id) => ids.push(id),
                // A `list_dir` of `keys/` holds nothing else, but the type
                // allows it, so it is counted rather than assumed away.
                _ => skipped = skipped.saturating_add(1),
            }
        }
        Self { ids, skipped }
    }
}

/// Where `keys/<deviceId>.json` records are read and written: the seam
/// between the commands that manage device keys (`login` now; `keys` and
/// `logout` next) and the homeserver.
///
/// A trait so that those commands can be tested without a network: the unit
/// tests pass a fake that keeps records in memory, remembers every call and
/// can refuse a write with any status. [`SessionKeyStore`] is the real one.
///
/// The methods are `async fn`s, so each returns a future. A trait like this
/// cannot be used as `dyn KeyStore` (each implementation's futures are a
/// different type), so callers take `&impl KeyStore`, and the compiler makes
/// one copy of the caller per implementation: the real one in the binary,
/// the fake in the tests. `pub(crate)`, so the warning about `Send` bounds
/// on public async traits does not apply: nothing here moves these futures
/// to another thread.
pub(crate) trait KeyStore {
    /// The signed-in user's own `keys/<id>.json`, at most
    /// [`MAX_RECORD_BYTES`], or `None` when there is no such record.
    #[expect(
        dead_code,
        reason = "login's reuse of an existing key, a later P2a step, is the first caller"
    )]
    async fn get_own_key(&self, id: &DeviceId) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>>;

    /// Writes `record` as the signed-in user's `keys/<id>.json`.
    ///
    /// The SDK's own error comes back, so the caller decides what a refusal
    /// means: `login` turns 403 and 507 into its messages with
    /// [`crate::remote::write_error`]. Never print the error itself: its
    /// `Display` holds the server's text, or the request URL.
    async fn put_key(&self, id: &DeviceId, record: Vec<u8>) -> pubky::Result<()>;

    /// The device ids under `owner`'s `keys/`, from public storage.
    #[expect(dead_code, reason = "keys list, a later P2a step, is the first caller")]
    async fn list_key_ids(&self, owner: &PublicKey) -> anyhow::Result<KeyIds>;
}

/// The real [`KeyStore`]: the user's own records through a signed-in
/// session, and anyone's listing through the public storage.
///
/// It borrows both, which is what the `'a` says: the session and the client
/// must outlive the store, and the store cannot sign the session out or keep
/// it. Its owner, the command, signs out once the store is gone.
pub(crate) struct SessionKeyStore<'a> {
    session: &'a PubkySession,
    client: &'a pubky::Pubky,
}

impl<'a> SessionKeyStore<'a> {
    /// A store on `session`, listing through `client`.
    pub(crate) fn new(session: &'a PubkySession, client: &'a pubky::Pubky) -> Self {
        Self { session, client }
    }
}

impl KeyStore for SessionKeyStore<'_> {
    async fn get_own_key(&self, id: &DeviceId) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
        get_own(self.session, &paths::key(id), MAX_RECORD_BYTES).await
    }

    async fn put_key(&self, id: &DeviceId, record: Vec<u8>) -> pubky::Result<()> {
        // `map(drop)` throws the successful response away unread: a 2xx is
        // all that matters, and its body is not ours to trust.
        self.session
            .storage()
            .put(paths::key(id), record)
            .await
            .map(drop)
    }

    async fn list_key_ids(&self, owner: &PublicKey) -> anyhow::Result<KeyIds> {
        let listing = list_dir(self.client, owner, paths::KEYS_DIR, ListLimits::DEFAULT).await?;
        Ok(KeyIds::from_listing(listing))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::{Value, json};
    use sweepky_core::{DeviceId, DeviceIdentity, DeviceKey, RecordId, SecretString, Timestamp};

    use super::{
        create_device_key, device_key_bytes, device_key_record, new_device_id, read_device_key,
    };
    use crate::clock;
    use crate::test_support::{dirs_in, mode, private_temp};

    #[test]
    fn device_id_is_a_valid_device_id() {
        // A record id made from the clock renders as 13 characters of
        // upper-case Crockford base32, which the device-id check takes as
        // it is.
        let raw = RecordId::from_timestamp(Timestamp::now()).to_string();
        let device: DeviceId = raw.parse().expect("a valid device id");
        assert_eq!(device.as_str(), raw);
        assert_eq!(raw.len(), RecordId::LEN);

        // `new_device_id` is exactly that: its text reads back as a record id.
        let id = new_device_id().expect("an id");
        assert_eq!(id.as_str().len(), RecordId::LEN);
        id.as_str().parse::<RecordId>().expect("a record id");
        // Two in a row differ: pubky-timestamp never repeats within a process.
        assert_ne!(new_device_id().expect("an id"), id);
    }

    #[test]
    fn device_key_record_shape() {
        let identity = DeviceIdentity::generate();
        let created_at = clock::now().expect("a time");
        let record = device_key_record(&identity, created_at.clone());
        let bytes = device_key_bytes(&record).expect("serializes");

        // Exactly these fields: `revokedAt` is written as `null`, not left
        // out, and the label is the fixed one, never the machine's name.
        let value: Value = serde_json::from_slice(&bytes).expect("JSON");
        assert_eq!(
            value,
            json!({
                "schemaVersion": 1,
                "alg": "age-x25519",
                "recipient": identity.recipient().to_string(),
                "label": "sweepky-cli",
                "createdAt": created_at.as_str(),
                "revokedAt": null,
            })
        );
        // RFC 3339 in UTC to the second, `YYYY-MM-DDTHH:MM:SSZ`.
        let time = created_at.as_str();
        assert_eq!(time.len(), 20, "{time}");
        assert_eq!(time.get(10..11), Some("T"), "{time}");
        assert!(time.ends_with('Z'), "{time}");

        // It reads back through core's parser, and is a key a sweeper's CLI
        // would encrypt to: the recipient of this identity.
        let read = DeviceKey::from_json(&bytes).expect("parses");
        assert_eq!(read, record);
        assert_eq!(
            read.encryption_recipient().expect("usable"),
            identity.recipient()
        );
    }

    #[test]
    fn device_key_file_is_exactly_the_identity_string_0600() {
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        let identity = DeviceIdentity::generate();
        create_device_key(&dirs, &identity).expect("written");

        let path = dirs.device_key_file();
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(dirs.config()), 0o700);
        // The identity string and nothing else: 74 bytes, no newline.
        let bytes = fs::read(&path).expect("readable");
        assert_eq!(bytes.len(), 74);
        assert!(!bytes.contains(&b'\n'));
        let secret = SecretString::from(String::from_utf8(bytes).expect("UTF-8"));
        let read = DeviceIdentity::from_secret(&secret).expect("an identity");
        assert_eq!(read.recipient(), identity.recipient());
        // `read_device_key` reads it back the same way.
        let read = read_device_key(&dirs).expect("reads").expect("present");
        assert_eq!(read.recipient(), identity.recipient());

        // A second key is never written over the first, which may be the
        // only key that opens the sweeps encrypted to it.
        let other = DeviceIdentity::generate();
        let err = create_device_key(&dirs, &other).expect_err("refused");
        assert!(format!("{err:#}").contains("never replaces"), "{err:#}");
        let kept = read_device_key(&dirs).expect("reads").expect("present");
        assert_eq!(kept.recipient(), identity.recipient());
    }
}
