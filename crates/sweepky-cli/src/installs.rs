//! `installs.json`: the device keys this owner's own installs published, so
//! that `keys list` and `pull` can tell this owner's keys under `keys/` from
//! one somebody else put there, or rewrote (02, "Who can read a sweep").
//!
//! ```json
//! {"schemaVersion": 1, "owners": {"<owner z32>": [
//!   {"deviceId": "<deviceId>", "recipient": "age1…"}, …]}}
//! ```
//!
//! Keyed by owner, because a device id means something only next to the
//! owner whose `keys/` it is in. Each owner's installs are kept in the order
//! they were made, each with the public age key it published as
//! `keys/<deviceId>.json`: an id alone says a record is this owner's, but
//! not that it still holds the key that install published, and someone who
//! can write `keys/` can rewrite a known id's record as easily as add one.
//! The fields a newer Sweepky adds, at the top and in an entry, are kept on
//! rewrite. The file holds public values only.
//!
//! **An entry an earlier build wrote** is the device id alone, a JSON string
//! rather than an object. It reads as an install whose key is not recorded
//! (`recipient` `None`), which `keys list` reports as a record it cannot
//! check, rather than failing, and it is written back as an object without
//! `recipient`. The next `login` of that install fills its key in, once it
//! has checked the published record against `device.key`
//! ([`record_install_key`]).
//!
//! **The list is local.** It knows the ids that installs sharing this
//! config directory made, not the ones another machine made. P2c's second
//! install of the same owner will therefore see the first install's key as
//! unknown, and alarm on it, until the two lists are joined.
//!
//! [`unknown_key_ids`] is the comparison `login` and `keys list` make (and
//! P2c's `pull` will), and [`unknown_key_alarm`] the alarm they raise for
//! each id it finds; [`replaced_key_alarm`] is the alarm for a known id
//! whose record names another key.

use std::collections::BTreeMap;

use anyhow::{Context as _, bail};
use serde::{Deserialize, Serialize};
use sweepky_core::{AgeRecipient, DeviceId, Pubky, RecordError, SchemaVersion, UnknownFields};

use crate::Dirs;
use crate::private_fs::{ensure_private_dir, read_private_file, write_private_file};

/// The most Sweepky reads of `installs.json`: 64 KiB, the cap of every
/// config file. An entry with its key takes about 110 bytes, so that is
/// room for some five hundred installs.
const MAX_INSTALLS_FILE_BYTES: usize = 64 * 1024;

/// `installs.json`: per owner, the installs here that published a key.
///
/// Public values only, so deriving `Debug` prints nothing secret.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
// The Rust fields are snake_case; the JSON keys camelCase, as in records.
#[serde(rename_all = "camelCase")]
pub(crate) struct InstallList {
    /// The format's version, 1.
    schema_version: SchemaVersion,
    /// Each owner's installs. A `BTreeMap` keeps the owners in one order
    /// (core's `Pubky` sorts by its key bytes), so the file is written the
    /// same way every time. `Pubky` is a JSON object key here: it is
    /// written as the raw z-base32 string and read from either spelling.
    owners: BTreeMap<Pubky, Vec<Install>>,
    /// Fields a newer Sweepky wrote, kept for the rewrite.
    #[serde(flatten)]
    extra: UnknownFields,
}

/// One of an owner's installs here: the device id it published its key
/// under, and that key.
///
/// Public values only (an [`AgeRecipient`] is a public key), so deriving
/// `Debug` prints nothing secret.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
// `from = "InstallForm"` reads an entry as an `InstallForm`, which takes
// both shapes an entry has had, and converts it with the `From` impl below.
// Writing uses the fields here, so an entry is always written as an object.
#[serde(rename_all = "camelCase", from = "InstallForm")]
pub(crate) struct Install {
    /// The device id: the record is `keys/<deviceId>.json`.
    pub(crate) device_id: DeviceId,
    /// The public age key the install published there, or `None` for an
    /// entry an earlier build wrote with the id alone. Left out of the file
    /// when `None`, rather than written as `null`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recipient: Option<AgeRecipient>,
    /// Fields a newer Sweepky wrote in this entry, kept for the rewrite.
    #[serde(flatten)]
    extra: UnknownFields,
}

impl Install {
    /// The entry for `device_id`, with the key it published when that is
    /// known.
    pub(crate) fn new(device_id: DeviceId, recipient: Option<AgeRecipient>) -> Self {
        Self {
            device_id,
            recipient,
            extra: UnknownFields::new(),
        }
    }
}

/// The two shapes an entry of `installs.json` is read in.
///
/// `untagged` makes serde try each variant in turn and keep the first that
/// fits: a JSON string is an earlier build's entry, an object today's. A
/// value that fits neither, such as an object whose `recipient` fails
/// `AgeRecipient`'s strict parse, is an error, which core's `RecordError`
/// reduces to its kind and position like every other fault in the file.
#[derive(Deserialize)]
#[serde(untagged)]
enum InstallForm {
    /// The device id alone, as builds before keys were recorded wrote it.
    IdOnly(DeviceId),
    /// `{"deviceId": …, "recipient": …}` and any fields a newer Sweepky
    /// added.
    Entry(InstallEntry),
}

/// An entry in today's shape, as read.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InstallEntry {
    device_id: DeviceId,
    /// `AgeRecipient`'s own `Deserialize` runs its strict parse. A missing
    /// field or `null` is `None`.
    #[serde(default)]
    recipient: Option<AgeRecipient>,
    #[serde(flatten)]
    extra: UnknownFields,
}

/// What `#[serde(from = "InstallForm")]` calls once either shape is read.
impl From<InstallForm> for Install {
    fn from(form: InstallForm) -> Self {
        match form {
            InstallForm::IdOnly(device_id) => Self::new(device_id, None),
            InstallForm::Entry(InstallEntry {
                device_id,
                recipient,
                extra,
            }) => Self {
                device_id,
                recipient,
                extra,
            },
        }
    }
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

    /// The installs `owner` has here, oldest first; empty when there are
    /// none. `owner` is found by its key bytes (core's `Pubky` orders and
    /// compares by them), never by how it is spelled.
    pub(crate) fn installs_of(&self, owner: &Pubky) -> &[Install] {
        // `map_or` gives the empty slice for an owner with no entry, and
        // `Vec::as_slice` borrows the installs of one that has.
        self.owners.get(owner).map_or(&[], Vec::as_slice)
    }

    /// The device ids of [`Self::installs_of`], in the same order: what
    /// the tests compare. The commands use the entries themselves, keys
    /// and all.
    #[cfg(test)]
    pub(crate) fn ids_of(&self, owner: &Pubky) -> Vec<DeviceId> {
        // `map` borrows each entry's id and `clone` copies it out, so the
        // `Vec` this returns owns its ids and borrows nothing from `self`.
        self.installs_of(owner)
            .iter()
            .map(|install| install.device_id.clone())
            .collect()
    }

    /// Records `recipient` as the key `owner`'s install `id` published: a
    /// new entry, or the key filled into an entry an earlier build wrote
    /// with the id alone. Returns whether it changed anything, as
    /// `HashSet::insert` does: recording the same key again does not.
    ///
    /// An entry that records another key for `id` is refused and left as
    /// it is. Each id is made once, for one key, so another key there means
    /// the file was changed behind Sweepky's back, and the recorded key is
    /// what `keys list` checks the published record against.
    fn add(
        &mut self,
        owner: Pubky,
        id: &DeviceId,
        recipient: &AgeRecipient,
    ) -> anyhow::Result<bool> {
        // `entry(..).or_default()` finds the owner's list, or puts an empty
        // one in first, and hands back `&mut` to it either way.
        let installs = self.owners.entry(owner).or_default();
        // `iter_mut().find` hands back `&mut` to the entry for `id`, if
        // there is one, so its key can be filled in where it is.
        let Some(install) = installs.iter_mut().find(|install| install.device_id == *id) else {
            installs.push(Install::new(id.clone(), Some(recipient.clone())));
            return Ok(true);
        };
        match &install.recipient {
            // `==` on `AgeRecipient` compares the two keys; they are public,
            // so comparing them in variable time leaks nothing.
            Some(recorded) if recorded == recipient => Ok(false),
            Some(_) => bail!(
                "installs.json already records another key for keys/{id}.json, and Sweepky never \
                 replaces a recorded key: it is what `keys list` and `login` check that record \
                 against"
            ),
            None => {
                install.recipient = Some(recipient.clone());
                Ok(true)
            }
        }
    }

    /// Removes `id` from `owner`'s installs, and the owner with its last
    /// install.
    fn remove(&mut self, owner: &Pubky, id: &DeviceId) {
        if let Some(installs) = self.owners.get_mut(owner) {
            // `retain` keeps the entries for which the closure says `true`.
            installs.retain(|kept| kept.device_id != *id);
            if installs.is_empty() {
                self.owners.remove(owner);
            }
        }
    }

    /// Removes `owner` with all its installs. Returns whether it had an
    /// entry.
    fn remove_owner(&mut self, owner: &Pubky) -> bool {
        // `BTreeMap::remove` hands back the removed value, if there was one;
        // only whether there was is needed.
        self.owners.remove(owner).is_some()
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

/// The ids of `listed`, the entries of an owner's `keys/`, that are not in
/// `created`, the ids this owner's installs created: the ones to alarm on.
/// In the order they were listed, each once.
///
/// Ids compare as [`DeviceId`] values, exactly, so `Laptop` and `laptop` are
/// two ids, as they are two files on the homeserver. Both lists are public
/// ids, so a plain comparison is fine; nothing secret is matched here.
///
/// A plain function of two slices rather than a method on
/// [`InstallList`], so a caller can add an id the file does not hold yet,
/// such as `login.json`'s own device id.
pub(crate) fn unknown_key_ids(created: &[DeviceId], listed: &[DeviceId]) -> Vec<DeviceId> {
    let mut unknown: Vec<DeviceId> = Vec::new();
    for id in listed {
        // A linear search: an owner has a handful of installs, and a
        // listing is capped at 1000 entries.
        if !created.contains(id) && !unknown.contains(id) {
            unknown.push(id.clone());
        }
    }
    unknown
}

/// The alarm for `id`, a key under this owner's `keys/` that none of this
/// owner's installs here created, with what to do about it (02, "Who can
/// read a sweep"), as one line of a report, ending in its newline. Fixed
/// text and the id, which a [`DeviceId`] keeps to `A-Z`, `a-z`, `0-9`, `-`
/// and `_`, so it is safe to print as it is.
pub(crate) fn unknown_key_alarm(id: &DeviceId) -> String {
    format!(
        "alarm: keys/{id}.json is a device key that this owner's installs here did not create. \
         It may be a key an operator of the homeserver put there, or one written with a leaked \
         grant, and whoever holds its secret can read the sweeps encrypted to it. If you did not \
         publish it from another install, run `sweepky keys revoke {id}`; if a grant may have \
         leaked, also revoke it in Pubky Ring and log in again. (This install knows only the \
         installs that share its config directory, so a key you published from another machine \
         shows up here too.)\n"
    )
}

/// The alarm for `id`, a key under this owner's `keys/` that one of this
/// owner's installs here did create, whose unrevoked record no longer holds
/// the key that install published (02, "Who can read a sweep"), with what
/// to do about it, as one line of a report, ending in its newline. `own` is
/// whether that install is this one, which `login` refuses to go on with
/// in the same words. Fixed text and the id, as for [`unknown_key_alarm`].
pub(crate) fn replaced_key_alarm(id: &DeviceId, own: bool) -> String {
    if own {
        format!(
            "alarm: keys/{id}.json, this install's own device key record, does not hold this \
             install's key: someone other than this install wrote it, with this identity's \
             credentials or as an operator of its homeserver, and can read any sweep encrypted to \
             the key it holds. Run `sweepky logout` to revoke keys/{id}.json, and stop using this \
             identity if its key file may have leaked.\n"
        )
    } else {
        format!(
            "alarm: keys/{id}.json, the device key record of another of this owner's installs \
             here, does not hold the key that install published: someone other than that install \
             wrote it, with this identity's credentials or as an operator of its homeserver, and \
             can read any sweep encrypted to the key it holds. Run `sweepky keys revoke {id}`; if \
             a grant may have leaked, also revoke it in Pubky Ring and log in again.\n"
        )
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

/// Records that `owner`'s install `id` published `recipient` as
/// `keys/<id>.json`, as [`InstallList::add`] does: a new entry, or the key
/// filled into an earlier build's entry for `id`, and an error, with the
/// file left as it was, when the entry records another key. Recording the
/// same key again changes nothing: the file is not even written, so a later
/// login that finds its entry there leaves `installs.json` exactly as it
/// was.
///
/// A read, a change and a write: callers hold the writers' lock, so no other
/// `sweepky` command changes the file in between.
pub(crate) fn record_install_key(
    dirs: &Dirs,
    owner: Pubky,
    id: &DeviceId,
    recipient: &AgeRecipient,
) -> anyhow::Result<()> {
    let mut list = read_installs(dirs)?;
    if !list.add(owner, id, recipient)? {
        return Ok(());
    }
    write_installs(dirs, &list)
}

/// Records `id` alone as one of `owner`'s installs, with no key, as an
/// entry an earlier build wrote reads: the tests' way to set up an install
/// whose key is not recorded, or one whose key does not matter to them.
/// Recording it again changes nothing.
#[cfg(test)]
pub(crate) fn record_install(dirs: &Dirs, owner: Pubky, id: &DeviceId) -> anyhow::Result<()> {
    let mut list = read_installs(dirs)?;
    let installs = list.owners.entry(owner).or_default();
    if installs.iter().any(|install| install.device_id == *id) {
        return Ok(());
    }
    installs.push(Install::new(id.clone(), None));
    write_installs(dirs, &list)
}

/// Forgets `id` as one of `owner`'s installs, the owner going with its last
/// install. Forgetting an id that is not there changes nothing.
pub(crate) fn forget_install(dirs: &Dirs, owner: Pubky, id: &DeviceId) -> anyhow::Result<()> {
    let mut list = read_installs(dirs)?;
    list.remove(&owner, id);
    write_installs(dirs, &list)
}

/// Forgets every install of `owner` here: what `logout` does once it has
/// forgotten the identity, whose ids nothing here compares against any
/// more. Every other owner's entry, and every field a newer Sweepky wrote,
/// stays. With no entry for `owner` the file is not written, nor created.
pub(crate) fn forget_owner(dirs: &Dirs, owner: Pubky) -> anyhow::Result<()> {
    let mut list = read_installs(dirs)?;
    if !list.remove_owner(&owner) {
        return Ok(());
    }
    write_installs(dirs, &list)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::{Map, Value, json};
    use sweepky_core::{AgeRecipient, DeviceId, DeviceIdentity};

    use super::{
        Install, forget_install, forget_owner, read_installs, record_install, record_install_key,
    };
    use crate::Dirs;
    use crate::private_fs::{ensure_private_dir, write_private_file};
    use crate::test_support::{FileSnapshot, dirs_in, mode, private_temp, random_pubky};

    fn id(text: &str) -> DeviceId {
        text.parse().expect("a valid device id")
    }

    /// A fresh public age key, from an identity made at run time.
    fn recipient() -> AgeRecipient {
        DeviceIdentity::generate().recipient()
    }

    /// An entry as the file holds it: the device id and its key's `age1…`
    /// string.
    fn entry(name: &str, key: &AgeRecipient) -> Value {
        json!({ "deviceId": name, "recipient": key.to_string() })
    }

    /// The file as JSON.
    fn raw(path: &std::path::Path) -> Value {
        serde_json::from_slice(&fs::read(path).expect("readable")).expect("JSON")
    }

    /// Writes `file` as `installs.json`, as a hand or an earlier build
    /// could have, with the same primitives `write_installs` uses: 0600 in
    /// the 0700 config directory, which the reader requires.
    fn write_by_hand(dirs: &Dirs, file: &Value) {
        ensure_private_dir(dirs.config()).expect("config dir");
        write_private_file(&dirs.installs_file(), file.to_string().as_bytes()).expect("write");
    }

    #[test]
    fn install_list_round_trips_per_owner_and_is_0600() {
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        let owner = random_pubky();
        let other = random_pubky();
        let [key_a, key_b, key_c, key_d] = [recipient(), recipient(), recipient(), recipient()];
        // No file yet: nobody's installs are known.
        assert!(
            read_installs(&dirs)
                .expect("reads")
                .ids_of(&owner)
                .is_empty()
        );

        record_install_key(&dirs, owner, &id("install-a"), &key_a).expect("records");
        record_install_key(&dirs, owner, &id("install-b"), &key_b).expect("records");
        record_install_key(&dirs, other, &id("install-c"), &key_c).expect("records");
        // Recording an install's key again changes nothing, and does not
        // even rewrite the file.
        let before = FileSnapshot::of(&dirs.installs_file());
        record_install_key(&dirs, owner, &id("install-a"), &key_a).expect("records");
        assert_eq!(FileSnapshot::of(&dirs.installs_file()), before);
        assert_eq!(mode(&dirs.installs_file()), 0o600);
        assert_eq!(mode(dirs.config()), 0o700);

        // Each owner's installs, in the order they were made, each with
        // the key it published.
        let list = read_installs(&dirs).expect("reads");
        assert_eq!(list.ids_of(&owner), [id("install-a"), id("install-b")]);
        assert_eq!(
            list.installs_of(&owner),
            [
                Install::new(id("install-a"), Some(key_a.clone())),
                Install::new(id("install-b"), Some(key_b.clone())),
            ]
        );
        assert_eq!(list.ids_of(&other), [id("install-c")]);
        // The recorded shape: owners keyed by their raw z-base32 key, and
        // each entry the device id with its key's `age1…` string.
        let mut owners = Map::new();
        owners.insert(
            owner.to_string(),
            json!([entry("install-a", &key_a), entry("install-b", &key_b)]),
        );
        owners.insert(other.to_string(), json!([entry("install-c", &key_c)]));
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

        // A field a newer Sweepky wrote survives a rewrite, at the top and
        // in an entry.
        let mut newer = file;
        newer["addedLater"] = json!("kept");
        newer["owners"][owner.to_string()][0]["alsoLater"] = json!(1);
        fs::write(dirs.installs_file(), newer.to_string()).expect("write");
        record_install_key(&dirs, other, &id("install-d"), &key_d).expect("records");
        let file = raw(&dirs.installs_file());
        assert_eq!(file["addedLater"], "kept");
        assert_eq!(file["owners"][owner.to_string()][0]["alsoLater"], 1);
    }

    #[test]
    fn an_entry_without_its_key_reads_as_unknown_and_is_filled_in_once() {
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        let owner = random_pubky();
        // The shape a build before keys were recorded wrote: the ids alone.
        let mut owners = Map::new();
        owners.insert(owner.to_string(), json!(["install-a", "install-b"]));
        let old = json!({ "schemaVersion": 1, "owners": owners });
        write_by_hand(&dirs, &old);

        // It reads, rather than failing: the ids, with no key recorded.
        let list = read_installs(&dirs).expect("an earlier build's file reads");
        assert_eq!(list.ids_of(&owner), [id("install-a"), id("install-b")]);
        assert!(
            list.installs_of(&owner)
                .iter()
                .all(|install| install.recipient.is_none())
        );

        // Recording an install's key fills it into that entry, in place,
        // and the file is written in today's shape: the entry without a key
        // as an object without `recipient`.
        let key_b = recipient();
        record_install_key(&dirs, owner, &id("install-b"), &key_b).expect("records");
        let list = read_installs(&dirs).expect("reads");
        assert_eq!(
            list.installs_of(&owner),
            [
                Install::new(id("install-a"), None),
                Install::new(id("install-b"), Some(key_b.clone())),
            ]
        );
        assert_eq!(
            raw(&dirs.installs_file())["owners"][owner.to_string()],
            json!([
                { "deviceId": "install-a" },
                { "deviceId": "install-b", "recipient": key_b.to_string() },
            ])
        );

        // Another key for an install that has one is refused, naming the
        // record and neither key, and the file is left as it was.
        let before = FileSnapshot::of(&dirs.installs_file());
        let other = recipient();
        let err = record_install_key(&dirs, owner, &id("install-b"), &other)
            .expect_err("another key for the same install");
        let shown = format!("{err:#}");
        assert!(shown.contains("keys/install-b.json"), "{shown}");
        for key in [&key_b, &other] {
            assert!(!shown.contains(&key.to_string()), "{shown}");
        }
        assert_eq!(FileSnapshot::of(&dirs.installs_file()), before);

        // The tests' id-only helper writes an entry without a key too.
        record_install(&dirs, owner, &id("install-c")).expect("records");
        assert_eq!(
            read_installs(&dirs).expect("reads").installs_of(&owner)[2],
            Install::new(id("install-c"), None)
        );
    }

    #[test]
    fn a_recorded_key_that_is_not_a_strict_recipient_is_refused() {
        // installs.json is Sweepky's own file, so a key that fails the
        // strict parse is a damaged file, refused whole, and the message
        // quotes none of it.
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        let owner = random_pubky();
        let upper = recipient().to_string().to_uppercase();
        let mut owners = Map::new();
        owners.insert(
            owner.to_string(),
            json!([{ "deviceId": "install-a", "recipient": upper }]),
        );
        write_by_hand(&dirs, &json!({ "schemaVersion": 1, "owners": owners }));

        let err = read_installs(&dirs).expect_err("not a strict recipient");
        let shown = format!("{err:#}");
        assert!(shown.contains("installs.json is not valid"), "{shown}");
        assert!(!shown.contains(&upper), "{shown}");
    }

    #[test]
    fn forget_owner_drops_only_that_owners_ids() {
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        let owner = random_pubky();
        let other = random_pubky();
        // No file and no entry: nothing is written, not even an empty file.
        forget_owner(&dirs, owner).expect("forgets");
        assert_eq!(FileSnapshot::of(&dirs.installs_file()), None);

        record_install_key(&dirs, owner, &id("install-a"), &recipient()).expect("records");
        record_install_key(&dirs, owner, &id("install-b"), &recipient()).expect("records");
        record_install_key(&dirs, other, &id("install-c"), &recipient()).expect("records");
        let mut newer = raw(&dirs.installs_file());
        newer["addedLater"] = json!("kept");
        fs::write(dirs.installs_file(), newer.to_string()).expect("write");

        // Every id of `owner` goes; the other owner and the newer field stay.
        forget_owner(&dirs, owner).expect("forgets");
        let list = read_installs(&dirs).expect("reads");
        assert!(list.ids_of(&owner).is_empty());
        assert_eq!(list.ids_of(&other), [id("install-c")]);
        assert_eq!(raw(&dirs.installs_file())["addedLater"], "kept");
        // Forgetting it again finds no entry and leaves the file as it is.
        let before = FileSnapshot::of(&dirs.installs_file());
        forget_owner(&dirs, owner).expect("forgets");
        assert_eq!(FileSnapshot::of(&dirs.installs_file()), before);
    }
}
