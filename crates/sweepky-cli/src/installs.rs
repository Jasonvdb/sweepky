//! `installs.json`: the device ids this owner's own installs created, so
//! that `keys list` and `pull` can tell this owner's keys under `keys/` from
//! one somebody else put there (02, "Who can read a sweep").
//!
//! ```json
//! {"schemaVersion": 1, "owners": {"<owner z32>": ["<deviceId>", …]}}
//! ```
//!
//! Keyed by owner, because a device id means something only next to the
//! owner whose `keys/` it is in. Each owner's ids are kept in the order they
//! were made. The fields a newer Sweepky adds are kept on rewrite. The file
//! holds public values only.
//!
//! **The list is local.** It knows the ids that installs sharing this
//! config directory made, not the ones another machine made. P2c's second
//! install of the same owner will therefore see the first install's key as
//! unknown, and alarm on it, until the two lists are joined.

use std::collections::BTreeMap;

use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use sweepky_core::{DeviceId, Pubky, RecordError, SchemaVersion, UnknownFields};

use crate::Dirs;
use crate::private_fs::{ensure_private_dir, read_private_file, write_private_file};

/// The most Sweepky reads of `installs.json`: 64 KiB, the cap of every
/// config file. An id takes about 20 bytes, so that is room for some three
/// thousand installs.
const MAX_INSTALLS_FILE_BYTES: usize = 64 * 1024;

/// `installs.json`: per owner, the device ids its installs here created.
///
/// Public values only, so deriving `Debug` prints nothing secret.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
// The Rust fields are snake_case; the JSON keys camelCase, as in records.
#[serde(rename_all = "camelCase")]
pub(crate) struct InstallList {
    /// The format's version, 1.
    schema_version: SchemaVersion,
    /// Each owner's device ids. A `BTreeMap` keeps the owners in one order
    /// (core's `Pubky` sorts by its key bytes), so the file is written the
    /// same way every time. `Pubky` is a JSON object key here: it is
    /// written as the raw z-base32 string and read from either spelling.
    owners: BTreeMap<Pubky, Vec<DeviceId>>,
    /// Fields a newer Sweepky wrote, kept for the rewrite.
    #[serde(flatten)]
    extra: UnknownFields,
}

impl InstallList {
    /// An empty list, as a config directory without the file has.
    fn new() -> Self {
        Self {
            schema_version: SchemaVersion::CURRENT,
            owners: BTreeMap::new(),
            extra: UnknownFields::new(),
        }
    }

    /// The ids `owner`'s installs created here, oldest first; empty when
    /// there are none.
    // `keys list` and `pull`, which compare `keys/` against it, are the
    // first callers outside the tests.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "keys list, a later P2a step, is the first caller")
    )]
    pub(crate) fn ids_of(&self, owner: &Pubky) -> &[DeviceId] {
        // `map_or` gives the empty slice for an owner with no entry, and
        // `Vec::as_slice` borrows the ids of one that has.
        self.owners.get(owner).map_or(&[], Vec::as_slice)
    }

    /// Adds `id` to `owner`'s ids, unless it is there already. Returns
    /// whether it added it, as `HashSet::insert` does.
    fn add(&mut self, owner: Pubky, id: &DeviceId) -> bool {
        // `entry(..).or_default()` finds the owner's list, or puts an empty
        // one in first, and hands back `&mut` to it either way.
        let ids = self.owners.entry(owner).or_default();
        if ids.contains(id) {
            return false;
        }
        ids.push(id.clone());
        true
    }

    /// Removes `id` from `owner`'s ids, and the owner with its last id.
    fn remove(&mut self, owner: &Pubky, id: &DeviceId) {
        if let Some(ids) = self.owners.get_mut(owner) {
            // `retain` keeps the ids for which the closure says `true`.
            ids.retain(|kept| kept != id);
            if ids.is_empty() {
                self.owners.remove(owner);
            }
        }
    }

    /// The file's bytes: pretty-printed JSON and a newline.
    fn to_json(&self) -> anyhow::Result<Vec<u8>> {
        let mut json = serde_json::to_vec_pretty(self).context("could not write installs.json")?;
        json.push(b'\n');
        Ok(json)
    }

    /// Reads the file's bytes. serde_json's messages go through core's
    /// `RecordError`, which keeps only the kind of fault and where it is.
    fn from_json(bytes: &[u8]) -> anyhow::Result<Self> {
        serde_json::from_slice(bytes)
            .map_err(RecordError::from)
            .context("installs.json is not valid")
    }
}

/// Reads `installs.json`, or an empty list when there is no such file.
pub(crate) fn read_installs(dirs: &Dirs) -> anyhow::Result<InstallList> {
    let path = dirs.installs_file();
    let Some(bytes) = read_private_file(&path, MAX_INSTALLS_FILE_BYTES)? else {
        return Ok(InstallList::new());
    };
    InstallList::from_json(&bytes).with_context(|| format!("could not read {}", path.display()))
}

/// Writes `list` as `installs.json` (0600), creating the config directory
/// (0700) if it is not there yet.
fn write_installs(dirs: &Dirs, list: &InstallList) -> anyhow::Result<()> {
    ensure_private_dir(dirs.config())?;
    write_private_file(&dirs.installs_file(), &list.to_json()?)
}

/// Records `id` as one of `owner`'s installs. Recording it again changes
/// nothing: the file is not even written, so a later login that finds its
/// id there leaves `installs.json` exactly as it was.
///
/// A read, a change and a write: callers hold the writers' lock, so no other
/// `sweepky` command changes the file in between.
pub(crate) fn record_install(dirs: &Dirs, owner: Pubky, id: &DeviceId) -> anyhow::Result<()> {
    let mut list = read_installs(dirs)?;
    if !list.add(owner, id) {
        return Ok(());
    }
    write_installs(dirs, &list)
}

/// Forgets `id` as one of `owner`'s installs, the owner going with its last
/// id. Forgetting an id that is not there changes nothing.
pub(crate) fn forget_install(dirs: &Dirs, owner: Pubky, id: &DeviceId) -> anyhow::Result<()> {
    let mut list = read_installs(dirs)?;
    list.remove(&owner, id);
    write_installs(dirs, &list)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::{Map, Value, json};
    use sweepky_core::DeviceId;

    use super::{forget_install, read_installs, record_install};
    use crate::test_support::{FileSnapshot, dirs_in, mode, private_temp, random_pubky};

    fn id(text: &str) -> DeviceId {
        text.parse().expect("a valid device id")
    }

    /// The file as JSON.
    fn raw(path: &std::path::Path) -> Value {
        serde_json::from_slice(&fs::read(path).expect("readable")).expect("JSON")
    }

    #[test]
    fn install_list_round_trips_per_owner_and_is_0600() {
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        let owner = random_pubky();
        let other = random_pubky();
        // No file yet: nobody's installs are known.
        assert!(
            read_installs(&dirs)
                .expect("reads")
                .ids_of(&owner)
                .is_empty()
        );

        record_install(&dirs, owner, &id("install-a")).expect("records");
        record_install(&dirs, owner, &id("install-b")).expect("records");
        record_install(&dirs, other, &id("install-c")).expect("records");
        // Recording an id again changes nothing, and does not even rewrite
        // the file.
        let before = FileSnapshot::of(&dirs.installs_file());
        record_install(&dirs, owner, &id("install-a")).expect("records");
        assert_eq!(FileSnapshot::of(&dirs.installs_file()), before);
        assert_eq!(mode(&dirs.installs_file()), 0o600);
        assert_eq!(mode(dirs.config()), 0o700);

        // Each owner's ids, in the order they were made.
        let list = read_installs(&dirs).expect("reads");
        assert_eq!(list.ids_of(&owner), [id("install-a"), id("install-b")]);
        assert_eq!(list.ids_of(&other), [id("install-c")]);
        // The recorded shape: owners keyed by their raw z-base32 key.
        let mut owners = Map::new();
        owners.insert(owner.to_string(), json!(["install-a", "install-b"]));
        owners.insert(other.to_string(), json!(["install-c"]));
        assert_eq!(
            raw(&dirs.installs_file()),
            json!({ "schemaVersion": 1, "owners": owners })
        );

        // Forgetting one id keeps the rest; an owner goes with its last id.
        forget_install(&dirs, owner, &id("install-a")).expect("forgets");
        forget_install(&dirs, other, &id("install-c")).expect("forgets");
        let list = read_installs(&dirs).expect("reads");
        assert_eq!(list.ids_of(&owner), [id("install-b")]);
        assert!(list.ids_of(&other).is_empty());
        let file = raw(&dirs.installs_file());
        assert_eq!(file["owners"].as_object().expect("a map").len(), 1);

        // A field a newer Sweepky wrote survives a rewrite.
        let mut newer = file;
        newer["addedLater"] = json!("kept");
        fs::write(dirs.installs_file(), newer.to_string()).expect("write");
        record_install(&dirs, other, &id("install-d")).expect("records");
        assert_eq!(raw(&dirs.installs_file())["addedLater"], "kept");
    }
}
