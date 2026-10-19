//! The key half of `submit`: which of the bounty owner's keys a sweep is
//! encrypted to.
//!
//! Only the bounty's owner may read a sweep (00), so `submit` encrypts it
//! to the owner's published keys, the `keys/<deviceId>.json` records in the
//! owner's storage, and to this install's own. Those records are plain JSON
//! that anyone holding the owner's grant, or an active operator of their
//! homeserver, can add to or rewrite to read later sweeps (02, "Who can
//! read a sweep"). So [`accept_owner_keys`] takes them with care:
//!
//! 1. It lists the owner's `keys/` through `device::PublicKeys`, with no
//!    session, and refuses a listing of more than [`MAX_KEY_RECORDS`]
//!    records before it reads any. Each record is read capped at
//!    `MAX_RECORD_BYTES` and parsed by core's `DeviceKey::from_json`.
//! 2. It keeps the unrevoked records that `DeviceKey::encryption_recipient`
//!    accepts, the one way from a record to a key a sweep is encrypted to
//!    (`alg` exactly `age-x25519`, the recipient strictly canonical). A
//!    revoked record drops out quietly: the owner retired it. A record that
//!    is gone by the time it is read, does not parse, names another `alg`
//!    or holds a recipient that fails the strict parse is skipped, with a
//!    warning that names its device id and quotes none of it. A record that
//!    cannot be read at all, a failed request, stops the check instead, so
//!    a network fault never shrinks the pin (the key would then read as new
//!    when it came back) nor sends a sweep the owner cannot open there.
//! 3. It refuses an owner with no usable key, since nobody could read the
//!    sweep, and one with more than [`MAX_OWNER_KEYS`], which leaves room
//!    for this install's own key within core's `MAX_RECIPIENTS`.
//! 4. [`check_pin`], a pure function, compares that set with the one
//!    `owner-keys.json` pins for the owner ([`crate::pins`]). With no pin
//!    this is the first `submit` to them: it goes on, and pins the set,
//!    silently. With nothing new it goes on; a key revoked or removed since
//!    drops out of the pin without a word. A new key, a new device id or a
//!    known one whose record now holds another key, is warned of by its
//!    device id, and the person is asked whether to go on; under
//!    `--no-input` the warning is the error.
//!
//! [`AcceptedKeys`] is what goes on: the owner's keys to encrypt to, and
//! [`AcceptedKeys::write_pin`], which the command calls inside the
//! writers' lock. The check and the question run outside it, because a
//! question can wait on a person for as long as they like.
//!
//! **What is printed.** Device ids and fixed text only: a [`DeviceId`] is
//! `A-Z`, `a-z`, `0-9`, `-` and `_`, safe to print as it is. Never a
//! recipient, never a record's label or other text, and core's errors,
//! which name the kind of fault and never the input.

use std::collections::BTreeSet;

use anyhow::{Context as _, bail};
use pubky::PublicKey;
use sweepky_core::{AgeRecipient, DeviceId, DeviceKey, DeviceKeyError, MAX_RECIPIENTS, Pubky};

use crate::device::PublicKeys;
use crate::pins::{OwnerKey, PinnedKey, pin_owner_keys, read_pins};
use crate::prompt::{Prompting, confirm};
use crate::remote::public_key_of;
use crate::{Context, Dirs};

/// The most records `submit` reads from one owner's `keys/`: 128, P2b's
/// choice. Every install of the owner's publishes one and keeps it, revoked,
/// after `logout`, so this is room for many years of laptops; past it the
/// listing is refused before a record is read, so a `keys/` someone filled
/// costs one listing, not a thousand reads.
const MAX_KEY_RECORDS: usize = 128;

/// The most keys `submit` takes from one owner: one fewer than
/// `MAX_RECIPIENTS` (32), core's cap on a sweep's distinct recipients,
/// leaving room for this install's own key (02, "caps how many recipients
/// it will take from one owner"). Counted by record, before the encryptor
/// drops a key two records share, so the cap is never looser than core's.
const MAX_OWNER_KEYS: usize = MAX_RECIPIENTS - 1;

/// The question asked about new keys, after the warning that names them.
const NEW_KEYS_QUESTION: &str = "Encrypt this sweep to the new keys as well?";

/// What [`check_pin`] found, comparing the owner's keys with their pin.
#[derive(Debug, PartialEq, Eq)]
enum PinCheck {
    /// No pin for this owner: the first `submit` to them, which pins the
    /// keys without a word.
    FirstUse,
    /// The keys are exactly the pinned ones.
    Unchanged,
    /// Every key is pinned, and some pinned key is gone (revoked, removed
    /// or no longer usable): the pin shrinks to the keys, without a word.
    Shrunk,
    /// The device ids of the keys that are not pinned, in the order of the
    /// keys: a new device id, or a pinned one whose record now holds
    /// another key. The person is asked before the sweep is encrypted to
    /// them.
    NewKeys(Vec<DeviceId>),
}

/// Compares `current`, the owner's usable keys now, with `pinned`, the
/// keys `owner-keys.json` pins for them (`None` when it pins none).
///
/// A pure function of its two arguments, so every case is tested without
/// a file or a network. A key is pinned when an entry has its device id
/// *and* its key ([`PinnedKey::matches`]), so a known id rewritten to hold
/// another key is new. The searches are linear: an owner has at most
/// [`MAX_OWNER_KEYS`] keys, and a pin holds what was accepted last time.
fn check_pin(pinned: Option<&[PinnedKey]>, current: &[OwnerKey]) -> PinCheck {
    // `let … else`: bind the pin when there is one, or return.
    let Some(pinned) = pinned else {
        return PinCheck::FirstUse;
    };
    let new: Vec<DeviceId> = current
        .iter()
        .filter(|key| !pinned.iter().any(|pin| pin.matches(key)))
        .map(|key| key.device_id.clone())
        .collect();
    if !new.is_empty() {
        return PinCheck::NewKeys(new);
    }
    if pinned
        .iter()
        .any(|pin| !current.iter().any(|key| pin.matches(key)))
    {
        PinCheck::Shrunk
    } else {
        PinCheck::Unchanged
    }
}

/// The owner's keys `submit` encrypts to, once [`accept_owner_keys`] has
/// checked them, and whether their pin must be written.
///
/// The fields are private, so a caller cannot change the keys between the
/// check and the pin, nor skip the pin when it is due: it calls
/// [`Self::write_pin`] and that decides.
#[derive(Debug)]
pub(crate) struct AcceptedKeys {
    /// Whose keys these are.
    owner: Pubky,
    /// The keys, in device-id order.
    keys: Vec<OwnerKey>,
    /// Whether the pin differs from `keys`: first use, a shrunk set, or new
    /// keys the person accepted.
    repin: bool,
}

impl AcceptedKeys {
    /// The owner's keys to encrypt to, in device-id order: between 1 and
    /// [`MAX_OWNER_KEYS`] of them.
    pub(crate) fn keys(&self) -> &[OwnerKey] {
        &self.keys
    }

    /// Pins these keys for the owner when the pin differs from them, and
    /// does nothing otherwise. Call it inside the writers' lock:
    /// `pins::pin_owner_keys` reads the file again there and replaces this
    /// owner's entry alone.
    pub(crate) fn write_pin(&self, dirs: &Dirs) -> anyhow::Result<()> {
        if !self.repin {
            return Ok(());
        }
        pin_owner_keys(dirs, self.owner, &self.keys)
    }
}

/// Reads `owner`'s keys through `keys` and checks them against their pin,
/// as the module docs say: the warnings for skipped records, and for new
/// keys, go to standard error, and a question about new keys is asked
/// through `prompt::confirm` under `prompting`. Writes nothing.
///
/// `Ok(None)` when the person answered no to the question about new keys:
/// nothing is pinned, and the sweep must not be encrypted.
pub(crate) async fn accept_owner_keys(
    ctx: &Context,
    prompting: Prompting,
    keys: &impl PublicKeys,
    owner: Pubky,
) -> anyhow::Result<Option<AcceptedKeys>> {
    // The local file first, so a loose or damaged one stops the command
    // before anything is asked of the network.
    let pins = read_pins(&ctx.dirs)?;
    let found = read_owner_keys(keys, &public_key_of(&owner)?).await?;
    for warning in &found.warnings {
        ctx.stderr.line(warning)?;
    }
    refuse_key_count(found.usable.len())?;
    let repin = match check_pin(pins.pinned(&owner), &found.usable) {
        PinCheck::FirstUse | PinCheck::Shrunk => true,
        PinCheck::Unchanged => false,
        PinCheck::NewKeys(new) => {
            if !confirm_new_keys(ctx, prompting, &new)? {
                return Ok(None);
            }
            true
        }
    };
    Ok(Some(AcceptedKeys {
        owner,
        keys: found.usable,
        repin,
    }))
}

/// What reading the owner's `keys/` gave: the keys this build would
/// encrypt to, and a warning for each record it skipped.
struct FoundKeys {
    /// The usable keys, in device-id order.
    usable: Vec<OwnerKey>,
    /// One line per skipped record, naming its device id.
    warnings: Vec<String>,
}

/// Lists `owner`'s `keys/` and reads each record: steps 1 and 2 of the
/// module docs.
async fn read_owner_keys(keys: &impl PublicKeys, owner: &PublicKey) -> anyhow::Result<FoundKeys> {
    let mut found = FoundKeys {
        usable: Vec::new(),
        warnings: Vec::new(),
    };
    // The set of ids moves into the loop: each `id` is owned, so it moves
    // into its `OwnerKey` without a clone.
    for id in list_key_records(keys, owner).await? {
        match read_key_record(keys, owner, &id).await? {
            KeyRecord::Usable(recipient) => found.usable.push(OwnerKey {
                device_id: id,
                recipient,
            }),
            KeyRecord::Revoked => {}
            KeyRecord::Skipped(reason) => found.warnings.push(format!(
                "warning: keys/{id}.json of the bounty's owner is skipped, so this sweep is not \
                 encrypted to it: {reason}."
            )),
        }
    }
    Ok(found)
}

/// The device ids `owner`'s `keys/` lists, each once and in order, or an
/// error when there are more than [`MAX_KEY_RECORDS`], before any record
/// is read.
async fn list_key_records(
    keys: &impl PublicKeys,
    owner: &PublicKey,
) -> anyhow::Result<BTreeSet<DeviceId>> {
    let listed = keys
        .list_key_ids(owner)
        .await
        .context("could not list the keys/ of the bounty's owner")?;
    // A set drops an id a homeserver listed twice, so it is read and
    // counted once, and hands the ids back in order, whatever order the
    // homeserver listed them in.
    let ids: BTreeSet<DeviceId> = listed.ids.into_iter().collect();
    if ids.len() > MAX_KEY_RECORDS {
        bail!(
            "the keys/ of the bounty's owner lists {} device key records, more than the \
             {MAX_KEY_RECORDS} submit reads from one owner, so it read none of them and \
             encrypted nothing",
            ids.len()
        );
    }
    Ok(ids)
}

/// Reads `owner`'s `keys/<id>.json` and sorts it into a [`KeyRecord`]. A
/// failed request is the error that stops the whole check (module docs);
/// a record that is gone is skipped.
async fn read_key_record(
    keys: &impl PublicKeys,
    owner: &PublicKey,
    id: &DeviceId,
) -> anyhow::Result<KeyRecord> {
    let read = keys.get_key(owner, id).await.with_context(|| {
        format!(
            "could not read keys/{id}.json of the bounty's owner, so submit cannot tell which \
             keys to encrypt to; try again"
        )
    })?;
    Ok(match read {
        // `&bytes` lends the `Zeroizing<Vec<u8>>` out as the `&[u8]`
        // `classify_key_record` takes, through `Deref`, without a copy; the
        // buffer is wiped when it is dropped at the end of this arm.
        Some(bytes) => classify_key_record(&bytes),
        None => KeyRecord::Skipped("it was listed, but is gone now".to_owned()),
    })
}

/// What one listed `keys/<id>.json` is to `submit`.
enum KeyRecord {
    /// A key to encrypt to.
    Usable(AgeRecipient),
    /// Revoked: the owner retired it, so it drops out without a word.
    Revoked,
    /// Not a key this build can use, and why, in fixed text that quotes
    /// none of the record.
    Skipped(String),
}

/// Sorts a record's bytes into a [`KeyRecord`]: step 2 of the module docs.
/// Pure, and never fails: a record that is no use is a
/// [`KeyRecord::Skipped`], so one bad record never stops the others.
fn classify_key_record(bytes: &[u8]) -> KeyRecord {
    // core's capped parse refuses more than `MAX_RECORD_BYTES` before it
    // reads anything, and its `RecordError` names the kind of fault and
    // where it is, never the input.
    let record = match DeviceKey::from_json(bytes) {
        Ok(record) => record,
        Err(error) => {
            return KeyRecord::Skipped(format!(
                "it is not a device key record this build reads ({error})"
            ));
        }
    };
    // Before `encryption_recipient`, which checks `alg` first: a revoked
    // key of another kind is still only a retired key.
    if record.is_revoked() {
        return KeyRecord::Revoked;
    }
    match record.encryption_recipient() {
        Ok(recipient) => KeyRecord::Usable(recipient),
        // Cannot happen after the check above, but the match names it
        // rather than hide it in the arm below.
        Err(DeviceKeyError::Revoked) => KeyRecord::Revoked,
        // `anyhow::Error::new` wraps core's error so `{:#}` prints its whole
        // chain: for a bad recipient, the strict parse's own reason too.
        // Both are fixed text.
        Err(error) => KeyRecord::Skipped(format!("{:#}", anyhow::Error::new(error))),
    }
}

/// Refuses `count` usable keys when it is none or more than
/// [`MAX_OWNER_KEYS`]: step 3 of the module docs.
fn refuse_key_count(count: usize) -> anyhow::Result<()> {
    if count == 0 {
        bail!(
            "the bounty's owner has no key under keys/ that this build can encrypt to, so nobody \
             could read this sweep and submit sent nothing; the owner publishes a key when they \
             run `sweepky login`"
        );
    }
    if count > MAX_OWNER_KEYS {
        bail!(
            "the bounty's owner has {count} keys this build would encrypt to, more than the \
             {MAX_OWNER_KEYS} submit takes from one owner, so it encrypted nothing rather than \
             choose among them"
        );
    }
    Ok(())
}

/// Warns of `new`, the device ids of keys the pin does not hold, and asks
/// whether to encrypt to them as well: `true` for yes. Under
/// `--no-input` it asks nothing, and the warning is the error.
fn confirm_new_keys(ctx: &Context, prompting: Prompting, new: &[DeviceId]) -> anyhow::Result<bool> {
    let warning = new_keys_warning(new);
    match prompting {
        Prompting::Allowed => {
            ctx.stderr.line(&format!("warning: {warning}"))?;
            confirm(ctx, prompting, NEW_KEYS_QUESTION)
        }
        // `confirm` fails at once here, naming the flag and the question,
        // and reads nothing; `context` puts the warning in front of that,
        // so the error says which keys are new.
        Prompting::Forbidden => confirm(ctx, prompting, NEW_KEYS_QUESTION).context(warning),
    }
}

/// The warning about `new`, naming each by its record's path alone.
fn new_keys_warning(new: &[DeviceId]) -> String {
    let records: Vec<String> = new.iter().map(|id| format!("keys/{id}.json")).collect();
    format!(
        "the bounty's owner has keys this install has not encrypted a sweep to before, published \
         or rewritten since it last submitted to them: {}. Most often that is a new install of \
         theirs, but whoever holds a leaked grant of theirs, or runs their homeserver, could have \
         put a key there to read this sweep; if you can, check with the owner before you go on",
        records.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::path::PathBuf;

    use serde_json::{Value, json};
    use sweepky_core::{AgeRecipient, DeviceId, DeviceIdentity, MAX_RECORD_BYTES, Pubky};
    use tempfile::TempDir;

    use super::{
        AcceptedKeys, MAX_KEY_RECORDS, MAX_OWNER_KEYS, PinCheck, accept_owner_keys, check_pin,
    };
    use crate::Dirs;
    use crate::device::{device_key_bytes, device_key_record};
    use crate::pins::{OwnerKey, PinnedKey, read_pins};
    use crate::prompt::Prompting;
    use crate::remote::public_key_of;
    use crate::test_support::{
        FakeKeyStore, FileSnapshot, KeyStoreCall, PLANTED, dirs_in, offline_network, private_temp,
        random_pubky, test_context,
    };

    fn id(text: &str) -> DeviceId {
        text.parse().expect("a valid device id")
    }

    /// A fresh public age key, from an identity made at run time.
    fn new_key() -> AgeRecipient {
        DeviceIdentity::generate().recipient()
    }

    fn owner_key(name: &str, recipient: &AgeRecipient) -> OwnerKey {
        OwnerKey {
            device_id: id(name),
            recipient: recipient.clone(),
        }
    }

    /// A record as this CLI publishes one, for `recipient`, with the
    /// planted word as its label: no output may repeat it.
    fn record_of(recipient: &AgeRecipient) -> Value {
        let time = "2026-10-19T09:00:00Z".parse().expect("a time");
        let bytes = device_key_bytes(&device_key_record(recipient, time)).expect("JSON");
        let mut record: Value = serde_json::from_slice(&bytes).expect("JSON");
        record["label"] = json!(PLANTED);
        record
    }

    fn revoked(mut record: Value) -> Value {
        record["revokedAt"] = json!("2026-10-19T10:00:00Z");
        record
    }

    fn bytes(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).expect("JSON")
    }

    /// This install, the sweeper, with its config directory in a temp
    /// directory, and the bounty owner's `keys/` in a fake.
    struct Sweeper {
        home: TempDir,
        owner: Pubky,
        keys: FakeKeyStore,
    }

    impl Sweeper {
        fn new() -> Self {
            Self {
                home: private_temp(),
                owner: random_pubky(),
                keys: FakeKeyStore::default(),
            }
        }

        fn dirs(&self) -> Dirs {
            dirs_in(&self.home)
        }

        fn pins_file(&self) -> PathBuf {
            self.dirs().owner_keys_file()
        }

        /// Publishes a usable record of a fresh key as `keys/<name>.json`
        /// of the owner, and gives the key.
        fn publish(&self, name: &str) -> AgeRecipient {
            let key = new_key();
            self.set(name, &record_of(&key));
            key
        }

        /// Puts `record` in place as `keys/<name>.json` of the owner.
        fn set(&self, name: &str, record: &Value) {
            self.keys.set_record(&id(name), bytes(record));
        }

        /// What `submit`'s key check gives, answering `answer` if it asks,
        /// and what it wrote to standard error.
        async fn check(
            &self,
            prompting: Prompting,
            answer: &'static str,
        ) -> (anyhow::Result<Option<AcceptedKeys>>, String) {
            let (ctx, stderr) = test_context(offline_network(), &self.home, Cursor::new(answer));
            let accepted = accept_owner_keys(&ctx, prompting, &self.keys, self.owner).await;
            (accepted, stderr.text())
        }

        /// The check, accepted, with its pin written, as the command does
        /// under the writers' lock; and what it wrote to standard error.
        async fn submit(&self, answer: &'static str) -> (AcceptedKeys, String) {
            let (accepted, stderr) = self.check(Prompting::Allowed, answer).await;
            let accepted = accepted
                .unwrap_or_else(|err| panic!("refused: {err:#}"))
                .expect("accepted");
            accepted.write_pin(&self.dirs()).expect("pinned");
            (accepted, stderr)
        }

        /// The keys pinned for the owner, if any.
        fn pinned(&self) -> Option<Vec<OwnerKey>> {
            let pins = read_pins(&self.dirs()).expect("reads");
            let pinned = pins.pinned(&self.owner)?;
            Some(
                pinned
                    .iter()
                    .map(|pin| owner_key(pin.device_id.as_str(), &pin.recipient))
                    .collect(),
            )
        }
    }

    /// The owner keys `(name, key)` of `list`, in its order.
    fn owner_keys(list: &[(&str, &AgeRecipient)]) -> Vec<OwnerKey> {
        list.iter()
            .map(|&(name, key)| owner_key(name, key))
            .collect()
    }

    /// Fails the test if `text` shows any of `keys` or the planted label.
    fn assert_shows_no_key(text: &str, keys: &[&AgeRecipient]) {
        assert!(!text.contains(PLANTED), "{text}");
        for key in keys {
            assert!(!text.contains(&key.to_string()), "{text}");
        }
    }

    #[test]
    fn the_pin_check_compares_device_ids_and_keys() {
        let [a, b, c] = [
            owner_key("a", &new_key()),
            owner_key("b", &new_key()),
            owner_key("c", &new_key()),
        ];
        // `b` rewritten to hold another key.
        let b2 = owner_key("b", &new_key());
        // The pin of some keys, and the owner's keys now, from borrowed
        // keys: `cloned` copies each out, so the test keeps its own.
        let pin = |keys: &[&OwnerKey]| -> Vec<PinnedKey> {
            keys.iter().map(|key| PinnedKey::new(key)).collect()
        };
        let now = |keys: &[&OwnerKey]| -> Vec<OwnerKey> { keys.iter().copied().cloned().collect() };
        let ab = pin(&[&a, &b]);

        assert_eq!(check_pin(None, &now(&[&a])), PinCheck::FirstUse);
        assert_eq!(check_pin(Some(&ab), &now(&[&a, &b])), PinCheck::Unchanged);
        assert_eq!(check_pin(Some(&ab), &now(&[&a])), PinCheck::Shrunk);
        assert_eq!(
            check_pin(Some(&pin(&[&a])), &now(&[&a, &b])),
            PinCheck::NewKeys(vec![id("b")])
        );
        // A known device id that now holds another key is new.
        assert_eq!(
            check_pin(Some(&ab), &now(&[&a, &b2])),
            PinCheck::NewKeys(vec![id("b")])
        );
        // A new key and a dropped one: the new one is what matters.
        assert_eq!(
            check_pin(Some(&ab), &now(&[&a, &c])),
            PinCheck::NewKeys(vec![id("c")])
        );
        // An owner pinned to nothing (a file changed by hand): every key is
        // new.
        assert_eq!(
            check_pin(Some(&[]), &now(&[&a, &c])),
            PinCheck::NewKeys(vec![id("a"), id("c")])
        );
    }

    // P2b's Done-when, in its unit form: B's first `submit` pins A's key
    // set silently, and a key then added under A's `keys/` makes B's next
    // `submit` warn.
    #[tokio::test]
    async fn the_first_submit_pins_silently_and_a_key_added_later_warns() {
        let sweeper = Sweeper::new();
        let ka = sweeper.publish("laptop");
        let kb = sweeper.publish("desk");

        let (accepted, stderr) = sweeper.submit("").await;
        assert_eq!(stderr, "", "first use asks nothing and warns of nothing");
        let set = owner_keys(&[("desk", &kb), ("laptop", &ka)]);
        assert_eq!(accepted.keys(), set);
        assert_eq!(sweeper.pinned(), Some(set.clone()));

        // Nothing new: no word, and the pin is not even rewritten.
        let before = FileSnapshot::of(&sweeper.pins_file());
        let (accepted, stderr) = sweeper.submit("").await;
        assert_eq!(stderr, "");
        assert_eq!(accepted.keys(), set);
        assert_eq!(FileSnapshot::of(&sweeper.pins_file()), before);

        // A key added under the owner's keys/ warns, naming its device id
        // alone, and asks.
        let kc = sweeper.publish("intruder");
        let (accepted, stderr) = sweeper.check(Prompting::Allowed, "n\n").await;
        assert!(accepted.expect("an answer").is_none(), "no is no");
        assert!(stderr.starts_with("warning: "), "{stderr}");
        assert!(stderr.contains("keys/intruder.json"), "{stderr}");
        assert!(!stderr.contains("keys/laptop.json"), "{stderr}");
        assert!(stderr.ends_with("[y/N] "), "{stderr}");
        assert_shows_no_key(&stderr, &[&ka, &kb, &kc]);
        // No changes nothing.
        assert_eq!(FileSnapshot::of(&sweeper.pins_file()), before);

        // Under --no-input the warning is the error, and nothing is asked.
        let (refused, stderr) = sweeper.check(Prompting::Forbidden, "y\n").await;
        let shown = format!("{:#}", refused.expect_err("--no-input"));
        assert!(shown.contains("keys/intruder.json"), "{shown}");
        assert!(shown.contains("--no-input"), "{shown}");
        assert_shows_no_key(&shown, &[&ka, &kb, &kc]);
        assert_eq!(stderr, "");
        assert_eq!(FileSnapshot::of(&sweeper.pins_file()), before);

        // Yes pins the current set, so the next submit is quiet again.
        let (accepted, stderr) = sweeper.submit("y\n").await;
        assert!(stderr.contains("keys/intruder.json"), "{stderr}");
        let set = owner_keys(&[("desk", &kb), ("intruder", &kc), ("laptop", &ka)]);
        assert_eq!(accepted.keys(), set);
        assert_eq!(sweeper.pinned(), Some(set));
        let (_, stderr) = sweeper.submit("").await;
        assert_eq!(stderr, "");
    }

    #[tokio::test]
    async fn a_known_device_id_holding_another_key_counts_as_new() {
        let sweeper = Sweeper::new();
        let ka = sweeper.publish("laptop");
        sweeper.submit("").await;

        // Someone who can write keys/ rewrites the known id with their key.
        let intruder = sweeper.publish("laptop");
        let (accepted, stderr) = sweeper.check(Prompting::Allowed, "\n").await;
        assert!(accepted.expect("an answer").is_none());
        assert!(stderr.contains("keys/laptop.json"), "{stderr}");
        assert_shows_no_key(&stderr, &[&ka, &intruder]);
        assert_eq!(sweeper.pinned(), Some(owner_keys(&[("laptop", &ka)])));
    }

    #[tokio::test]
    async fn a_revoked_or_removed_key_drops_out_quietly_and_warns_again_when_rewritten() {
        let sweeper = Sweeper::new();
        let ka = sweeper.publish("a");
        let kb = sweeper.publish("b");
        sweeper.publish("c");
        sweeper.submit("").await;

        // `b` revoked and `c` removed: no warning, and the pin shrinks to
        // what is left.
        sweeper.set("b", &revoked(record_of(&kb)));
        sweeper.keys.remove_record(&id("c"));
        let (accepted, stderr) = sweeper.submit("").await;
        assert_eq!(stderr, "");
        assert_eq!(accepted.keys(), owner_keys(&[("a", &ka)]));
        assert_eq!(sweeper.pinned(), Some(owner_keys(&[("a", &ka)])));

        // The pin is what was accepted last time, not all ever seen: `b`
        // rewritten as unrevoked, even with its old key, warns again.
        sweeper.set("b", &record_of(&kb));
        let (accepted, stderr) = sweeper.check(Prompting::Allowed, "").await;
        assert!(accepted.expect("an answer").is_none());
        assert!(stderr.contains("keys/b.json"), "{stderr}");
    }

    #[tokio::test]
    async fn records_this_build_cannot_use_are_skipped_with_a_warning_naming_the_device_id() {
        let sweeper = Sweeper::new();
        let good = sweeper.publish("good");
        // Listed, but gone by the time it is read.
        sweeper.keys.list_without_record(&id("gone"));
        // Not a record at all, with the planted word in it.
        sweeper
            .keys
            .set_record(&id("garbage"), format!("{{\"{PLANTED}\"").into_bytes());
        // Another kind of key: an `alg` this build does not encrypt to.
        let other_alg_key = new_key();
        let mut other_alg = record_of(&other_alg_key);
        other_alg["alg"] = json!("AGE-X25519");
        sweeper.set("other-alg", &other_alg);
        // A recipient that fails the strict parse.
        let upper = new_key().to_string().to_uppercase();
        let mut bad_recipient = record_of(&new_key());
        bad_recipient["recipient"] = json!(upper);
        sweeper.set("bad-recipient", &bad_recipient);
        // Over the record cap.
        let mut too_large = record_of(&new_key());
        too_large["padding"] = json!("x".repeat(MAX_RECORD_BYTES));
        sweeper.set("too-large", &too_large);
        // Revoked, and of another alg as well: revoked comes first, quietly.
        sweeper.set("old", &revoked(other_alg.clone()));

        let (accepted, stderr) = sweeper.submit("").await;
        assert_eq!(accepted.keys(), owner_keys(&[("good", &good)]));
        // One warning per skipped record, each naming its device id.
        let warnings: Vec<&str> = stderr.lines().collect();
        assert_eq!(warnings.len(), 5, "{stderr}");
        for name in ["gone", "garbage", "other-alg", "bad-recipient", "too-large"] {
            let named = format!("keys/{name}.json");
            assert!(
                warnings
                    .iter()
                    .any(|line| line.starts_with("warning: ") && line.contains(&named)),
                "{name}: {stderr}"
            );
        }
        assert!(!stderr.contains("keys/old.json"), "{stderr}");
        assert!(!stderr.contains(&upper), "{stderr}");
        assert_shows_no_key(&stderr, &[&good, &other_alg_key]);
    }

    #[tokio::test]
    async fn a_record_that_cannot_be_read_stops_the_check() {
        let sweeper = Sweeper::new();
        sweeper.publish("good");
        sweeper.publish("flaky");
        sweeper.keys.fail_reads_of(&id("flaky"));

        let (refused, _) = sweeper.check(Prompting::Allowed, "").await;
        let shown = format!("{:#}", refused.expect_err("a failed read"));
        assert!(shown.contains("keys/flaky.json"), "{shown}");
        assert_eq!(sweeper.pinned(), None);
    }

    #[tokio::test]
    async fn an_owner_with_no_usable_key_is_refused() {
        let sweeper = Sweeper::new();
        // Nothing under keys/ at all.
        let (refused, _) = sweeper.check(Prompting::Allowed, "").await;
        let shown = format!("{:#}", refused.expect_err("no key"));
        assert!(shown.contains("no key"), "{shown}");

        // Only a revoked key and one this build cannot use.
        sweeper.set("revoked", &revoked(record_of(&new_key())));
        let mut other_alg = record_of(&new_key());
        other_alg["alg"] = json!("mlkem768x25519");
        sweeper.set("other-alg", &other_alg);
        let (refused, stderr) = sweeper.check(Prompting::Allowed, "").await;
        let shown = format!("{:#}", refused.expect_err("no usable key"));
        assert!(shown.contains("no key"), "{shown}");
        assert!(stderr.contains("keys/other-alg.json"), "{stderr}");
        assert_eq!(FileSnapshot::of(&sweeper.pins_file()), None);
    }

    #[tokio::test]
    async fn more_usable_keys_than_leave_room_for_this_install_is_refused() {
        // Room for this install's own key: MAX_RECIPIENTS − 1 owner keys.
        let sweeper = Sweeper::new();
        for n in 0..MAX_OWNER_KEYS {
            sweeper.publish(&format!("k{n}"));
        }
        let (accepted, _) = sweeper.check(Prompting::Allowed, "").await;
        let accepted = accepted.expect("at the cap").expect("accepted");
        assert_eq!(accepted.keys().len(), MAX_OWNER_KEYS);

        sweeper.publish("one-more");
        let (refused, _) = sweeper.check(Prompting::Allowed, "").await;
        let shown = format!("{:#}", refused.expect_err("past the cap"));
        assert!(shown.contains(&MAX_OWNER_KEYS.to_string()), "{shown}");
        assert_eq!(FileSnapshot::of(&sweeper.pins_file()), None);
    }

    #[tokio::test]
    async fn more_listed_records_than_the_read_cap_is_refused_before_any_is_read() {
        // Listed records, revoked ones too, at most the read cap.
        let sweeper = Sweeper::new();
        sweeper.publish("good");
        let old = bytes(&revoked(record_of(&new_key())));
        for n in 1..MAX_KEY_RECORDS {
            sweeper
                .keys
                .set_record(&id(&format!("old{n}")), old.clone());
        }
        let (accepted, _) = sweeper.check(Prompting::Allowed, "").await;
        let accepted = accepted.expect("at the cap").expect("accepted");
        assert_eq!(accepted.keys().len(), 1);

        // One more is refused, and only the listing was asked for.
        sweeper.keys.set_record(&id("one-more"), old);
        let before = sweeper.keys.calls().len();
        let (refused, _) = sweeper.check(Prompting::Allowed, "").await;
        let shown = format!("{:#}", refused.expect_err("past the read cap"));
        assert!(shown.contains(&MAX_KEY_RECORDS.to_string()), "{shown}");
        let owner = public_key_of(&sweeper.owner).expect("a key");
        assert_eq!(
            sweeper.keys.calls()[before..],
            [KeyStoreCall::ListKeyIds(owner)]
        );
    }
}
