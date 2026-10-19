//! `owner-keys.json`: per bounty owner, the device keys this install last
//! encrypted a sweep to, so that `submit` notices when an owner's `keys/`
//! holds a key it did not hold then (02, "Who can read a sweep": a
//! sweeper's CLI pins each owner's key set on first use and warns, asking
//! before it continues, when a new key appears).
//!
//! ```json
//! {"schemaVersion": 1, "owners": {"<owner z32>": [
//!   {"deviceId": "<deviceId>", "recipient": "age1…"}, …]}}
//! ```
//!
//! Keyed by owner, as `installs.json` is, because a device id means
//! something only next to the owner whose `keys/` it is in, and each entry
//! holds the public age key the record held, not the id alone: someone who
//! can write the owner's `keys/` can rewrite a known id's record as easily
//! as add one. An owner's entry is exactly the set `submit` last accepted,
//! in device-id order, not every key it has ever seen: a key revoked or
//! removed since drops out of the pin, so one rewritten later counts as new
//! again.
//!
//! The fields a newer Sweepky adds are kept on rewrite: at the top, in
//! every other owner's entry, and in an entry of this owner's that is
//! pinned again. The file holds public values only (device ids and public
//! keys), but it is this install's record of which keys it trusted, so it
//! is handled as every config file is, through [`crate::private_fs`]: 0600
//! in the 0700 config directory, written to a temp file, renamed into place
//! and the directory synced, and read with a 64 KiB cap, a loose or linked
//! file refused.
//!
//! **Who writes it.** `submit` compares the owner's keys with the pin
//! outside the writers' lock, because that check may wait on a person.
//! The command then writes the pin inside the lock with
//! [`pin_owner_keys`], which reads the file again there and replaces this
//! owner's entry alone, so a concurrent `submit` to another owner keeps
//! its own.

use std::collections::BTreeMap;

use anyhow::{Context as _, bail};
use serde::{Deserialize, Serialize};
use sweepky_core::{AgeRecipient, DeviceId, Pubky, RecordError, SchemaVersion, UnknownFields};

use crate::Dirs;
use crate::private_fs::{ensure_private_dir, read_private_file, write_private_file};

/// The most Sweepky reads of `owner-keys.json`: 64 KiB, the cap of every
/// config file. Pretty-printed, a pinned key takes about 140 bytes and an
/// owner's entry about 70 more, so that is room for some three hundred
/// owners of one key each, or fourteen with the most keys `submit` takes
/// from one owner.
/// A pin that would take the file past it is refused rather than written,
/// so the file never holds what it cannot read back.
const MAX_PINS_FILE_BYTES: usize = 64 * 1024;

/// One of a bounty owner's keys, as `submit` reads it from their `keys/`:
/// the device id the record is published under and the key it holds.
///
/// Public values only (an [`AgeRecipient`] is a public key), so deriving
/// `Debug` prints nothing secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OwnerKey {
    /// The device id: the record is `keys/<deviceId>.json`.
    pub(crate) device_id: DeviceId,
    /// The key the record holds, as `DeviceKey::encryption_recipient` gave
    /// it.
    pub(crate) recipient: AgeRecipient,
}

/// `owner-keys.json`: per bounty owner, the keys pinned for them.
///
/// Public values only, so deriving `Debug` prints nothing secret.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
// The Rust fields are snake_case; the JSON keys camelCase, as in records.
#[serde(rename_all = "camelCase")]
pub(crate) struct PinList {
    /// The format's version, 1.
    schema_version: SchemaVersion,
    /// Each owner's pinned keys. A `BTreeMap` keeps the owners in one order
    /// (core's `Pubky` sorts by its key bytes), so the file is written the
    /// same way every time. `Pubky` is a JSON object key here: it is written
    /// as the raw z-base32 string and read from either spelling.
    owners: BTreeMap<Pubky, Vec<PinnedKey>>,
    /// Fields a newer Sweepky wrote, kept for the rewrite.
    #[serde(flatten)]
    extra: UnknownFields,
}

/// One pinned key: an [`OwnerKey`] as the file holds it.
///
/// A type of its own rather than an [`OwnerKey`] with one more field,
/// because two pinned keys are the same key when their device id and key
/// are ([`Self::matches`]), whatever fields a newer Sweepky wrote beside
/// them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PinnedKey {
    /// The device id the record was published under.
    pub(crate) device_id: DeviceId,
    /// The key it held. `AgeRecipient`'s own `Deserialize` runs its strict
    /// parse, so a file holding anything else is refused whole.
    pub(crate) recipient: AgeRecipient,
    /// Fields a newer Sweepky wrote in this entry, kept for the rewrite.
    #[serde(flatten)]
    extra: UnknownFields,
}

impl PinnedKey {
    /// The entry that pins `key`, with no other field.
    pub(crate) fn new(key: &OwnerKey) -> Self {
        Self {
            device_id: key.device_id.clone(),
            recipient: key.recipient.clone(),
            extra: UnknownFields::new(),
        }
    }

    /// Whether this entry pins `key`: the same device id holding the same
    /// key. Both are public values, so a plain, early-exit `==` is right:
    /// there is no secret whose timing could leak. `AgeRecipient`'s `==`
    /// compares the keys' strings, so a record that spells a key another
    /// way never passes for a pinned one.
    pub(crate) fn matches(&self, key: &OwnerKey) -> bool {
        self.device_id == key.device_id && self.recipient == key.recipient
    }
}

impl PinList {
    /// An empty list, as a config directory without the file has.
    fn new() -> Self {
        Self {
            schema_version: SchemaVersion::CURRENT,
            owners: BTreeMap::new(),
            extra: UnknownFields::new(),
        }
    }

    /// The keys pinned for `owner`, or `None` when none are: no `submit`
    /// to them yet. `owner` is found by its key bytes, never by how it is
    /// spelled.
    pub(crate) fn pinned(&self, owner: &Pubky) -> Option<&[PinnedKey]> {
        // `Vec::as_slice` borrows the entry as a slice, which is all a
        // reader needs, and copies nothing.
        self.owners.get(owner).map(Vec::as_slice)
    }

    /// Sets `owner`'s pin to `keys`. A key pinned already, the same device
    /// id holding the same key, keeps its entry as it is, with any fields a
    /// newer Sweepky wrote in it. Returns whether anything changed, so an
    /// unchanged pin is not written again.
    fn pin(&mut self, owner: Pubky, keys: &[OwnerKey]) -> bool {
        // `unwrap_or_default` gives the empty slice, `&[]`, for an owner
        // with no pin yet.
        let old = self.pinned(&owner).unwrap_or_default();
        // A linear search per key: an owner has at most a few dozen keys.
        // `cloned` copies the old entry out, so the new list owns its
        // entries and borrows nothing from `self`, which is changed below.
        let entries: Vec<PinnedKey> = keys
            .iter()
            .map(|key| {
                old.iter()
                    .find(|pin| pin.matches(key))
                    .cloned()
                    .unwrap_or_else(|| PinnedKey::new(key))
            })
            .collect();
        if self.pinned(&owner) == Some(entries.as_slice()) {
            return false;
        }
        self.owners.insert(owner, entries);
        true
    }

    /// The file's bytes: pretty-printed JSON and a newline.
    fn to_json(&self) -> anyhow::Result<Vec<u8>> {
        let mut json =
            serde_json::to_vec_pretty(self).context("could not write owner-keys.json")?;
        json.push(b'\n');
        Ok(json)
    }

    /// Reads the file's bytes. serde_json's messages go through core's
    /// `RecordError`, which keeps only the kind of fault and where it is,
    /// so no message quotes the file.
    fn from_json(bytes: &[u8]) -> anyhow::Result<Self> {
        serde_json::from_slice(bytes)
            .map_err(RecordError::from)
            .context("owner-keys.json is not valid")
    }
}

/// Reads `owner-keys.json`, or an empty list when there is no such file.
///
/// Through `private_fs`, as every config file: a link, anything but a
/// regular file, a file another user could read and one over
/// [`MAX_PINS_FILE_BYTES`] are refused before a byte is read.
pub(crate) fn read_pins(dirs: &Dirs) -> anyhow::Result<PinList> {
    let path = dirs.owner_keys_file();
    let Some(bytes) = read_private_file(&path, MAX_PINS_FILE_BYTES)? else {
        return Ok(PinList::new());
    };
    PinList::from_json(&bytes).with_context(|| format!("could not read {}", path.display()))
}

/// Pins `keys` for `owner`: reads the file again, replaces this owner's
/// entry alone, as [`PinList::pin`] does, and writes it back, 0600 in the
/// 0700 config directory, unless nothing changed. `submit` calls it inside
/// the writers' lock, so no other `sweepky` command writes the file
/// between the read and the write.
pub(crate) fn pin_owner_keys(dirs: &Dirs, owner: Pubky, keys: &[OwnerKey]) -> anyhow::Result<()> {
    let mut list = read_pins(dirs)?;
    if !list.pin(owner, keys) {
        return Ok(());
    }
    let bytes = list.to_json()?;
    if bytes.len() > MAX_PINS_FILE_BYTES {
        bail!(
            "{} would grow past the 64 KiB Sweepky reads from it, so the owner's keys were not \
             pinned; remove the entries of owners you no longer sweep for and try again",
            dirs.owner_keys_file().display()
        );
    }
    ensure_private_dir(dirs.config())?;
    write_private_file(&dirs.owner_keys_file(), &bytes)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use serde_json::{Map, Value, json};
    use sweepky_core::DeviceIdentity;

    use super::{MAX_PINS_FILE_BYTES, OwnerKey, PinnedKey, pin_owner_keys, read_pins};
    use crate::Dirs;
    use crate::private_fs::{ensure_private_dir, write_private_file};
    use crate::test_support::{FileSnapshot, chmod, dirs_in, mode, private_temp, random_pubky};

    /// An owner key under the device id `name`, with a fresh public age key
    /// made at run time.
    fn key(name: &str) -> OwnerKey {
        OwnerKey {
            device_id: name.parse().expect("a valid device id"),
            recipient: DeviceIdentity::generate().recipient(),
        }
    }

    /// An entry as the file holds it.
    fn entry(key: &OwnerKey) -> Value {
        json!({ "deviceId": key.device_id.as_str(), "recipient": key.recipient.to_string() })
    }

    /// The file as JSON.
    fn raw(path: &Path) -> Value {
        serde_json::from_slice(&fs::read(path).expect("readable")).expect("JSON")
    }

    /// Writes `bytes` as `owner-keys.json`, as a hand or a newer build could
    /// have, 0600 in the 0700 config directory, which the reader requires.
    fn write_by_hand(dirs: &Dirs, bytes: &[u8]) {
        ensure_private_dir(dirs.config()).expect("config dir");
        write_private_file(&dirs.owner_keys_file(), bytes).expect("write");
    }

    #[test]
    fn pins_are_0600_in_a_0700_config_dir_in_the_recorded_shape() {
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        let (owner, other) = (random_pubky(), random_pubky());
        let [a, b, c] = [key("laptop-a"), key("laptop-b"), key("desk")];
        // No file yet: no owner is pinned, and reading makes no file.
        assert!(read_pins(&dirs).expect("reads").pinned(&owner).is_none());
        assert_eq!(FileSnapshot::of(&dirs.owner_keys_file()), None);

        pin_owner_keys(&dirs, owner, &[a.clone(), b.clone()]).expect("pins");
        pin_owner_keys(&dirs, other, std::slice::from_ref(&c)).expect("pins");

        let path = dirs.owner_keys_file();
        assert_eq!(path, dirs.config().join("owner-keys.json"));
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(dirs.config()), 0o700);
        // `{schemaVersion, owners: {<z32>: [{deviceId, recipient}]}}`, the
        // owners keyed by their raw z-base32 key.
        let mut owners = Map::new();
        owners.insert(owner.to_string(), json!([entry(&a), entry(&b)]));
        owners.insert(other.to_string(), json!([entry(&c)]));
        assert_eq!(raw(&path), json!({ "schemaVersion": 1, "owners": owners }));

        let pins = read_pins(&dirs).expect("reads");
        let pinned = pins.pinned(&owner).expect("pinned");
        assert_eq!(pinned, [PinnedKey::new(&a), PinnedKey::new(&b)]);
        assert!(pinned[0].matches(&a) && !pinned[0].matches(&b));

        // Pinning the same set again changes nothing: the file is not even
        // written.
        let before = FileSnapshot::of(&path);
        pin_owner_keys(&dirs, owner, &[a, b]).expect("pins");
        assert_eq!(FileSnapshot::of(&path), before);
    }

    #[test]
    fn unknown_fields_survive_a_rewrite() {
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        let (owner, other) = (random_pubky(), random_pubky());
        let [a, b, c, d] = [key("a"), key("b"), key("c"), key("d")];
        let mut owners = Map::new();
        owners.insert(
            owner.to_string(),
            json!([
                { "deviceId": "a", "recipient": a.recipient.to_string(), "seenAt": "kept" },
                entry(&b),
            ]),
        );
        owners.insert(
            other.to_string(),
            json!([{ "deviceId": "d", "recipient": d.recipient.to_string(), "note": 1 }]),
        );
        let file = json!({ "schemaVersion": 1, "owners": owners, "addedLater": "kept" });
        write_by_hand(&dirs, file.to_string().as_bytes());

        // The owner's set is now `a` and `c`: `b` was revoked and `c` is new.
        pin_owner_keys(&dirs, owner, &[a.clone(), c.clone()]).expect("pins");

        let file = raw(&dirs.owner_keys_file());
        // The top-level field and the other owner's entry, field and all,
        // are as they were; `a`, pinned again, keeps its own field; `c` is
        // new and has none; `b` is gone.
        assert_eq!(file["addedLater"], "kept");
        assert_eq!(file["owners"][other.to_string()][0]["note"], 1);
        assert_eq!(
            file["owners"][owner.to_string()],
            json!([
                { "deviceId": "a", "recipient": a.recipient.to_string(), "seenAt": "kept" },
                entry(&c),
            ])
        );
    }

    #[test]
    fn a_loose_damaged_or_oversized_pins_file_is_refused() {
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        let owner = random_pubky();
        let a = key("a");
        pin_owner_keys(&dirs, owner, std::slice::from_ref(&a)).expect("pins");
        let path = dirs.owner_keys_file();

        // Loose, as every config file: refused, with the chmod that fixes it.
        chmod(&path, 0o644);
        let shown = format!("{:#}", read_pins(&dirs).expect_err("loose"));
        assert!(shown.contains("chmod 600"), "{shown}");
        chmod(&path, 0o600);

        // A recipient that fails the strict parse is a damaged file, refused
        // whole without quoting it.
        let upper = a.recipient.to_string().to_uppercase();
        let mut owners = Map::new();
        owners.insert(
            owner.to_string(),
            json!([{ "deviceId": "a", "recipient": upper }]),
        );
        let damaged = json!({ "schemaVersion": 1, "owners": owners });
        write_by_hand(&dirs, damaged.to_string().as_bytes());
        let shown = format!("{:#}", read_pins(&dirs).expect_err("damaged"));
        assert!(shown.contains("owner-keys.json is not valid"), "{shown}");
        assert!(!shown.contains(&upper), "{shown}");

        // Over the 64 KiB cap: refused before it is read.
        write_by_hand(&dirs, &vec![b' '; MAX_PINS_FILE_BYTES + 1]);
        let shown = format!("{:#}", read_pins(&dirs).expect_err("too large"));
        assert!(shown.contains("larger than"), "{shown}");

        // A pin that would take the file past the cap is refused, and the
        // file is left as it was, so it never holds what it cannot read
        // back.
        let filler = "x".repeat(MAX_PINS_FILE_BYTES - 200);
        let near_cap = json!({ "schemaVersion": 1, "owners": {}, "filler": filler });
        write_by_hand(&dirs, near_cap.to_string().as_bytes());
        let before = FileSnapshot::of(&path);
        let err = pin_owner_keys(&dirs, owner, &[a, key("b")]).expect_err("past the cap");
        assert!(format!("{err:#}").contains("64 KiB"), "{err:#}");
        assert_eq!(FileSnapshot::of(&path), before);
    }
}
