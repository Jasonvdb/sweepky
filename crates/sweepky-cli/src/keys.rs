//! `sweepky keys list` and `sweepky keys revoke <deviceId>`: this
//! identity's published device keys, `keys/<deviceId>.json`, one per CLI
//! install (02, "Device keys").
//!
//! **`keys list`** reads public data only, so it needs no session and takes
//! no lock ([`list`]):
//!
//! 1. `login.json` names the pubky this install is logged in as, and
//!    `installs.json` the device ids this owner's installs here created,
//!    each with the key that install published.
//! 2. `keys/` is listed through public storage, paged and capped
//!    (`remote::list_dir`); a name that is not a `keys/<deviceId>.json` is
//!    skipped and counted, never fatal.
//! 3. Each listed record is read, capped at `MAX_RECORD_BYTES`, and parsed
//!    with core's `DeviceKey::from_json`. A record that is gone or does not
//!    parse is named by its device id with the reason, and not listed.
//! 4. Each unrevoked record goes through `DeviceKey::encryption_recipient`,
//!    the one way from a record to a key a sweep could be encrypted to. One
//!    that fails is marked unusable, with a warning naming its device id and
//!    never its recipient, which is the homeserver's text.
//! 5. An id that this owner's installs did not create raises the alarm of
//!    02 ("Who can read a sweep"), unless its record says it is revoked
//!    already, which is the fix the alarm asks for. So does an id they did
//!    create whose unrevoked record no longer holds the key that install
//!    published, as `installs.json` records it (`device::holds_key`, the
//!    comparison `login` makes of this install's own record): someone who
//!    can write `keys/` rewrote it. Only a record that holds this install's
//!    recorded key is shown as `this install; in use`. An entry an earlier
//!    build wrote records no key, so its record is shown as unverified,
//!    with a note, and raises no alarm.
//!
//! [`list_keys`] does steps 2 to 5 and returns a typed [`KeyListing`]; its
//! [`render`](KeyListing::render) is the text the binary prints, and every
//! string a record holds (`label`, `alg`, the times) goes through
//! `display::sanitize` on the way. [`key_alarms`] is the same steps with
//! only the alarms kept, which `login` runs after it has published or
//! reused this install's key.
//!
//! **`keys revoke <deviceId>`** ([`revoke`]) checks the id, then, under the
//! writers' lock with a session of its own that is always signed out
//! (`session::with_writer_session`), reads the signed-in user's own
//! `keys/<id>.json`, sets `revokedAt` to now unless it is set already, and
//! writes it back with every field it does not know kept ([`revoke_key`]).
//! Revoking this install's own key is allowed; the report then says to log
//! out. `logout` revokes this install's own key with the same
//! read-modify-write ([`revoke_if_published`]).

use std::collections::BTreeSet;

use anyhow::{Context as _, bail};
use pubky::PublicKey;
use sweepky_core::{AgeRecipient, DeviceId, DeviceKey, DeviceKeyError, KeyAlg, Pubky, RecordTime};

use crate::clock;
use crate::device::{
    KeyStore, PublicKeyReader, PublicKeys, SessionKeyStore, device_key_bytes, holds_key,
};
use crate::display::{MAX_LABEL_CHARS, sanitize};
use crate::installs::{
    Install, read_installs, replaced_key_alarm, unknown_key_alarm, unknown_key_ids,
};
use crate::remote::{pubky_of, public_key_of, write_error};
use crate::session::{NOT_LOGGED_IN, with_writer_session};
use crate::state::read_login_state;
use crate::{Context, Report};

// ---------------------------------------------------------------------------
// Reading one record.

/// What reading one listed `keys/<id>.json` gave.
enum RecordRead {
    /// The record, parsed.
    Parsed(DeviceKey),
    /// Not readable as a device key record, and why, in fixed text: gone
    /// (404) by the time it was read, a failed request, a body over the cap,
    /// or a parse error, none of which quotes the homeserver.
    Unreadable(String),
}

impl RecordRead {
    /// Whether an unknown key needs no alarm: its record says it is
    /// revoked, so sweepers no longer encrypt to it. Anything else, a key in
    /// use, a record that is gone or one that cannot be read, keeps the
    /// alarm, so a record that cannot be checked never passes for a settled
    /// one.
    fn settles_the_alarm(&self) -> bool {
        // `matches!` with a guard: the pattern binds `record`, and the
        // `if` must hold too.
        matches!(self, Self::Parsed(record) if record.is_revoked())
    }
}

/// Reads and parses `owner`'s `keys/<id>.json`.
///
/// Never an error: a record that cannot be read comes back as a
/// [`RecordRead`] too, so one bad record never stops a listing or an alarm.
async fn read_record(keys: &impl PublicKeys, owner: &PublicKey, id: &DeviceId) -> RecordRead {
    match keys.get_key(owner, id).await {
        // `&bytes` lends the `Zeroizing<Vec<u8>>` out as the `&[u8]`
        // `from_json` takes, through `Deref`, without a copy.
        Ok(Some(bytes)) => match DeviceKey::from_json(&bytes) {
            Ok(record) => RecordRead::Parsed(record),
            // core's `RecordError` names the kind of fault and where it is,
            // never the input.
            Err(error) => RecordRead::Unreadable(format!(
                "it is not a device key record this build reads ({error})"
            )),
        },
        // Listed, but deleted before it was read.
        Ok(None) => RecordRead::Unreadable("it was listed, but is gone now".to_owned()),
        // `remote`'s errors are fixed text and a status, never the server's
        // own words. `{:#}` prints the whole chain on one line.
        Err(error) => RecordRead::Unreadable(format!("{error:#}")),
    }
}

/// An alarm of 02 ("Who can read a sweep") about one `keys/<id>.json`:
/// someone who can write this owner's `keys/` may have given themselves a
/// key that sweeps are encrypted to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KeyAlarm {
    /// None of this owner's installs here created this id, and its record
    /// is not revoked, or could not be read to tell.
    Unknown(DeviceId),
    /// One of them did, but the record is unrevoked and no longer holds the
    /// key that install published: someone rewrote it.
    Replaced {
        /// The device id.
        id: DeviceId,
        /// Whether that install is this one, whose fix is `logout`.
        this_install: bool,
    },
}

impl KeyAlarm {
    /// The alarm as one line of a report, with what to do about it.
    pub(crate) fn line(&self) -> String {
        match self {
            Self::Unknown(id) => unknown_key_alarm(id),
            // `*this_install` copies the `bool` out of the borrowed alarm.
            Self::Replaced { id, this_install } => replaced_key_alarm(id, *this_install),
        }
    }
}

/// The alarms about `owner`'s `keys/`, from the same reads and checks as
/// `keys list` ([`list_keys`], with the listing dropped), so the two never
/// disagree: every listed record is read, an unknown id's to see whether it
/// is revoked and a known id's to compare it with the key `installs`
/// records for it. `installs` are this owner's installs here, from
/// `installs.json`, and `this_install` the id `login.json` records as this
/// install's.
///
/// `login` runs this once it has published or reused this install's key,
/// so that key is listed, known and recorded with its key; P2c's `pull` is
/// meant to run it too.
pub(crate) async fn key_alarms(
    keys: &impl PublicKeys,
    owner: &PublicKey,
    installs: &[Install],
    this_install: Option<&DeviceId>,
) -> anyhow::Result<Vec<KeyAlarm>> {
    Ok(list_keys(keys, owner, installs, this_install).await?.alarms)
}

// ---------------------------------------------------------------------------
// keys list

/// What `keys list` found under an owner's `keys/`.
///
/// Public values only, so deriving `Debug` prints nothing secret; the
/// homeserver's strings in it are printed through [`Self::render`], which
/// sanitises them, and never with `{:?}` outside the tests.
#[derive(Debug)]
struct KeyListing {
    /// Whose `keys/` this is.
    owner: Pubky,
    /// The records that parsed, in the order they were listed.
    keys: Vec<ListedKey>,
    /// The listed ids whose record was gone or did not parse.
    unreadable: Vec<UnreadableKey>,
    /// How many listing entries were not a `keys/<deviceId>.json`.
    skipped_names: usize,
    /// The alarms, in the order the ids were listed: unknown ids that are
    /// not revoked, and known ids whose record holds another key.
    alarms: Vec<KeyAlarm>,
}

/// One parsed `keys/<id>.json`, as `keys list` shows it.
#[derive(Debug)]
struct ListedKey {
    /// The device id, from the listing.
    id: DeviceId,
    /// The record's `label`: a stranger's text, sanitised when printed.
    label: String,
    /// The record's `alg`, exactly as the record has it: also a stranger's
    /// text.
    alg: KeyAlg,
    /// The record's `createdAt`.
    created_at: RecordTime,
    /// The record's `revokedAt`, `None` while the key is in use.
    revoked_at: Option<RecordTime>,
    /// Why this build cannot encrypt to this key, for an unrevoked key that
    /// fails `encryption_recipient`; `None` for a usable or a revoked key.
    unusable: Option<DeviceKeyError>,
    /// Whether this is the key `login.json` records as this install's.
    this_install: bool,
    /// Whether this owner's installs did not create it.
    unknown: bool,
    /// For an unrevoked key this owner's installs created, whether it
    /// still holds the key that install published.
    check: KeyCheck,
}

/// What comparing a record with the key its install published, as
/// `installs.json` records it, gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyCheck {
    /// Nothing to compare: the record is revoked, so it takes no further
    /// sweeps, or none of this owner's installs here created the id, which
    /// has an alarm of its own.
    Skipped,
    /// `installs.json` records no key for the id: an entry an earlier build
    /// wrote, or none at all for this install's own id.
    NotRecorded,
    /// The record holds the recorded key.
    Matches,
    /// The record holds another key, or none this build can encrypt to:
    /// someone other than that install wrote it.
    Replaced,
}

impl KeyCheck {
    /// The check of `record`, which `unknown` says this owner's installs
    /// did not create, against `recorded`, the key `installs.json` records
    /// for its id.
    fn of(record: &DeviceKey, unknown: bool, recorded: Option<&AgeRecipient>) -> Self {
        if unknown || record.is_revoked() {
            return Self::Skipped;
        }
        // `let … else`: bind the key when there is one, or return.
        let Some(expected) = recorded else {
            return Self::NotRecorded;
        };
        // `holds_key` is `login`'s comparison of this install's own record:
        // `encryption_recipient`, then the two keys as `AgeRecipient`
        // values. A record it cannot turn into a key does not hold the one
        // the install published either, since that one was usable.
        match holds_key(record, expected) {
            Ok(true) => Self::Matches,
            Ok(false) | Err(_) => Self::Replaced,
        }
    }
}

impl ListedKey {
    /// The entry for `record`, listed as `id`. `recorded` is the key
    /// `installs.json` records for `id`, if any.
    fn new(
        id: DeviceId,
        record: DeviceKey,
        this_install: Option<&DeviceId>,
        unknown: bool,
        recorded: Option<&AgeRecipient>,
    ) -> Self {
        // Only an unrevoked key is one a sweeper would encrypt to, so only
        // it is checked. `encryption_recipient` is the one way from a record
        // to a key (it checks `alg` and the recipient's strict form); the key
        // it returns is dropped at once by `.err()`, which keeps only why it
        // failed.
        let unusable = if record.is_revoked() {
            None
        } else {
            record.encryption_recipient().err()
        };
        // Before the record is taken apart below, which leaves its
        // recipient behind.
        let check = KeyCheck::of(&record, unknown, recorded);
        // Taking the record apart moves its strings into the entry rather
        // than copying them. `recipient` and the unknown fields are left
        // behind in `..` and dropped: nothing shows a recipient.
        let DeviceKey {
            alg,
            label,
            created_at,
            revoked_at,
            ..
        } = record;
        Self {
            // Compared before `id` moves into the struct below: a field
            // initialiser runs in the order it is written.
            this_install: this_install == Some(&id),
            id,
            label,
            alg,
            created_at,
            revoked_at,
            unusable,
            unknown,
            check,
        }
    }

    /// The entry's line: where the key comes from, whether it is in use,
    /// then the record's own fields, each sanitised.
    fn line(&self) -> String {
        format!(
            "  keys/{}.json: {}; {}; alg {}; label {}; created {}\n",
            self.id,
            self.origin(),
            self.status(),
            sanitize(self.alg.as_str(), MAX_LABEL_CHARS),
            sanitize(&self.label, MAX_LABEL_CHARS),
            sanitize(self.created_at.as_str(), RecordTime::MAX_LEN),
        )
    }

    /// Who made the key: this install, another install made here, or none
    /// of this owner's installs here.
    fn origin(&self) -> &'static str {
        if self.this_install {
            "this install"
        } else if self.unknown {
            "UNKNOWN: not created by this owner's installs here"
        } else {
            "another install made here"
        }
    }

    /// Whether the key is revoked (and when), replaced, one this build
    /// cannot encrypt to, unverified, or in use. "in use" for a key this
    /// owner's installs created means it holds the key that install
    /// published.
    fn status(&self) -> String {
        // A tuple `match` takes the first arm that fits, top to bottom, so
        // the order of the arms is the order of precedence.
        match (&self.revoked_at, self.check, self.unusable) {
            (Some(at), _, _) => format!("revoked {}", sanitize(at.as_str(), RecordTime::MAX_LEN)),
            (None, KeyCheck::Replaced, _) => {
                "REPLACED: it does not hold the key that install published".to_owned()
            }
            (None, _, Some(_)) => "unusable: this build cannot encrypt to it".to_owned(),
            (None, KeyCheck::NotRecorded, None) => {
                "unverified: installs.json does not record the key that install published"
                    .to_owned()
            }
            (None, KeyCheck::Skipped | KeyCheck::Matches, None) => "in use".to_owned(),
        }
    }

    /// The note for a key `installs.json` records no key for, or `None`.
    fn unverified_note(&self) -> Option<String> {
        if self.check != KeyCheck::NotRecorded {
            return None;
        }
        let fix = if self.this_install {
            " The next `sweepky login` records this install's key, once it has checked the \
             record against device.key."
        } else {
            ""
        };
        Some(format!(
            "note: installs.json does not record the key keys/{}.json was published with (an \
             earlier build wrote that entry, or it is missing), so keys list cannot tell whether \
             someone has rewritten it.{fix}\n",
            self.id
        ))
    }

    /// The alarm for a record that holds another key than its install
    /// published, or `None`.
    fn replaced_alarm(&self) -> Option<KeyAlarm> {
        // `bool::then` gives `Some` of the closure's value when the
        // condition holds, and `None` without calling it otherwise.
        (self.check == KeyCheck::Replaced).then(|| KeyAlarm::Replaced {
            id: self.id.clone(),
            this_install: self.this_install,
        })
    }

    /// The warning for a key this build cannot encrypt to, or `None` for a
    /// usable or a revoked key.
    fn unusable_warning(&self) -> Option<String> {
        // `?` on an `Option` returns `None` from the function when there is
        // no value. `anyhow::Error::new` wraps core's error so `{:#}` prints
        // its whole chain: for a bad recipient, the strict parse's own
        // reason too. Both are fixed text.
        let reason = anyhow::Error::new(self.unusable?);
        Some(format!(
            "warning: keys/{}.json holds a key this build cannot encrypt to ({reason:#}), so a \
             sweeper running this build skips it.\n",
            self.id
        ))
    }
}

/// A listed id whose record could not be shown.
#[derive(Debug)]
struct UnreadableKey {
    /// The device id, from the listing.
    id: DeviceId,
    /// Why, in fixed text.
    reason: String,
}

impl UnreadableKey {
    /// The warning that names the record and says why it is not listed.
    fn warning(&self) -> String {
        format!(
            "warning: keys/{}.json is not listed: {}.\n",
            self.id, self.reason
        )
    }
}

impl KeyListing {
    /// The text `keys list` prints: one line per key, then a warning per
    /// unusable or unreadable record, a note per record that cannot be
    /// checked against its install's key, the count of skipped names, and
    /// the alarms.
    ///
    /// Device ids and the owner's pubky are printed as they are: a
    /// [`DeviceId`] holds only `A-Z`, `a-z`, `0-9`, `-` and `_`, and a
    /// `Pubky` prints as z-base32. Everything else a record holds goes
    /// through `sanitize`.
    fn render(&self) -> String {
        let mut text = self.heading();
        for key in &self.keys {
            text.push_str(&key.line());
        }
        // `filter_map` keeps only the `Some`s: one warning per unusable key.
        for warning in self.keys.iter().filter_map(ListedKey::unusable_warning) {
            text.push_str(&warning);
        }
        for key in &self.unreadable {
            text.push_str(&key.warning());
        }
        for note in self.keys.iter().filter_map(ListedKey::unverified_note) {
            text.push_str(&note);
        }
        if let Some(note) = self.skipped_note() {
            text.push_str(&note);
        }
        for alarm in &self.alarms {
            text.push_str(&alarm.line());
        }
        text
    }

    /// The first line: whose `keys/` this is, or that it holds no key.
    fn heading(&self) -> String {
        if self.keys.is_empty() && self.unreadable.is_empty() {
            format!(
                "No device keys are published under keys/ of {}.\n",
                self.owner
            )
        } else {
            format!("Device keys under keys/ of {}:\n", self.owner)
        }
    }

    /// How many listing entries were skipped, or `None` when none were.
    fn skipped_note(&self) -> Option<String> {
        match self.skipped_names {
            0 => None,
            1 => Some(
                "1 entry under keys/ is not a keys/<deviceId>.json record and was skipped.\n"
                    .to_owned(),
            ),
            n => Some(format!(
                "{n} entries under keys/ are not keys/<deviceId>.json records and were skipped.\n"
            )),
        }
    }
}

/// The key `installs` records for `id`, or `None` when it records none:
/// no entry, or one an earlier build wrote with the id alone.
fn recorded_key<'a>(installs: &'a [Install], id: &DeviceId) -> Option<&'a AgeRecipient> {
    // The `'a` says the key is borrowed from `installs`, not from `id`.
    // `find` gives the first entry for `id`, and `and_then` its key, if any.
    installs
        .iter()
        .find(|install| install.device_id == *id)
        .and_then(|install| install.recipient.as_ref())
}

/// The ids this owner's installs created, as [`unknown_key_ids`] compares
/// the listing with: every id in `installs`, then `this_install`, the id
/// `login.json` records as this install's.
fn created_ids(installs: &[Install], this_install: Option<&DeviceId>) -> Vec<DeviceId> {
    // This install's own id counts as created even if installs.json lost
    // it (the next login puts it back), so it never reads as unknown.
    // `chain` adds the `Option`'s value, if any, after the installs' ids:
    // an `Option` is an iterator of zero or one items, and `cloned` turns
    // the borrowed ids into owned ones.
    installs
        .iter()
        .map(|install| &install.device_id)
        .chain(this_install)
        .cloned()
        .collect()
}

/// Lists `owner`'s `keys/` through `keys`: steps 2 to 5 of the module docs.
///
/// `installs` are this owner's installs here, from `installs.json`, each
/// with the key it published when that is recorded, and `this_install` the
/// id `login.json` records as this install's. Only the listing itself can
/// fail; one record that cannot be read is a warning in the listing.
async fn list_keys(
    keys: &impl PublicKeys,
    owner: &PublicKey,
    installs: &[Install],
    this_install: Option<&DeviceId>,
) -> anyhow::Result<KeyListing> {
    let listed = keys.list_key_ids(owner).await?;
    let unknown = unknown_key_ids(&created_ids(installs, this_install), &listed.ids);
    let mut listing = KeyListing {
        owner: pubky_of(owner),
        keys: Vec::new(),
        unreadable: Vec::new(),
        skipped_names: listed.skipped,
        alarms: Vec::new(),
    };
    // A homeserver could list one name twice; it is read and shown once.
    // `insert` returns `false` for a value the set holds already.
    let mut seen = BTreeSet::new();
    // `listed.ids` is moved into the loop: each `id` is owned, so it can
    // move into the entry without a clone.
    for id in listed.ids {
        if !seen.insert(id.clone()) {
            continue;
        }
        let is_unknown = unknown.contains(&id);
        let read = read_record(keys, owner, &id).await;
        if is_unknown && !read.settles_the_alarm() {
            listing.alarms.push(KeyAlarm::Unknown(id.clone()));
        }
        match read {
            RecordRead::Parsed(record) => {
                let recorded = recorded_key(installs, &id);
                let key = ListedKey::new(id, record, this_install, is_unknown, recorded);
                // `extend` with an `Option` adds its value, if any.
                listing.alarms.extend(key.replaced_alarm());
                listing.keys.push(key);
            }
            RecordRead::Unreadable(reason) => {
                listing.unreadable.push(UnreadableKey { id, reason });
            }
        }
    }
    Ok(listing)
}

/// Runs `keys list` for the identity this install is logged in as.
///
/// No session and no lock: it reads `login.json` and `installs.json`,
/// which every writer replaces whole with a rename, so a read never sees
/// half a file, and the rest is public storage.
pub(crate) async fn list(ctx: &Context) -> anyhow::Result<Report> {
    let Some(login) = read_login_state(&ctx.dirs)? else {
        bail!(NOT_LOGGED_IN);
    };
    let owner = public_key_of(&login.pubky)?;
    let installs = read_installs(&ctx.dirs)?;
    let reader = PublicKeyReader::new(ctx.network.pubky());
    let listing = list_keys(
        &reader,
        &owner,
        installs.installs_of(&login.pubky),
        login.device_id.as_ref(),
    )
    .await?;
    Ok(Report::new(listing.render()))
}

// ---------------------------------------------------------------------------
// keys revoke

/// What [`revoke_key`] and [`revoke_if_published`] did. `logout` reports
/// it too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Revocation {
    /// It set `revokedAt` to this time and wrote the record back.
    Revoked(RecordTime),
    /// The record was revoked already, at this time (the record's text),
    /// and was left as it is.
    AlreadyRevoked(RecordTime),
}

/// Revokes the signed-in user's own `keys/<id>.json` through `keys`, as
/// [`revoke_if_published`] does, for `keys revoke`: a missing record is an
/// error there, because the user named an id that has no record.
async fn revoke_key(
    keys: &impl KeyStore,
    id: &DeviceId,
    now: RecordTime,
) -> anyhow::Result<Revocation> {
    let Some(outcome) = revoke_if_published(keys, id, now).await? else {
        bail!(
            "keys/{id}.json does not exist, so there is nothing to revoke; `sweepky keys list` \
             shows this identity's device keys"
        );
    };
    Ok(outcome)
}

/// Revokes the signed-in user's own `keys/<id>.json` through `keys`:
/// reads it (capped at `MAX_RECORD_BYTES`, by the key store), sets
/// `revokedAt` to `now` unless it is set already, and writes it back.
/// `Ok(None)` when there is no such record, so nothing to revoke: `logout`
/// goes on then, and `keys revoke` ([`revoke_key`]) refuses.
///
/// Every other field stays as it was. core's `DeviceKey` keeps the fields
/// it does not know in a `#[serde(flatten)]` map, so a field a newer client
/// added is written back too, and the ones it knows are written back with
/// the values they were read with. A record that is already revoked is not
/// written at all, so revoking twice changes nothing and keeps the first
/// time. A record this build cannot parse is an error, and nothing is
/// written: it cannot be rewritten without losing what it holds.
pub(crate) async fn revoke_if_published(
    keys: &impl KeyStore,
    id: &DeviceId,
    now: RecordTime,
) -> anyhow::Result<Option<Revocation>> {
    let Some(bytes) = keys.get_own_key(id).await? else {
        return Ok(None);
    };
    let mut record = DeviceKey::from_json(&bytes).with_context(|| {
        format!(
            "keys/{id}.json is not a device key record this build reads, so Sweepky left it as \
             it is"
        )
    })?;
    if let Some(at) = &record.revoked_at {
        return Ok(Some(Revocation::AlreadyRevoked(at.clone())));
    }
    record.revoked_at = Some(now.clone());
    let bytes = device_key_bytes(&record)?;
    // `write_error` maps a 403 or a 507 to its own message and anything
    // else to fixed text and the status, never the server's words.
    keys.put_key(id, bytes)
        .await
        .map_err(|error| write_error(&error).context(format!("could not revoke keys/{id}.json")))?;
    Ok(Some(Revocation::Revoked(now)))
}

/// What `keys revoke` reports for `id`. `own` is whether `login.json`
/// records `id` as this install's own key.
fn revoke_report(id: &DeviceId, outcome: &Revocation, own: bool) -> String {
    let mut text = match outcome {
        Revocation::Revoked(at) => format!(
            "Revoked keys/{id}.json at {at}: sweeps uploaded from now on are not encrypted to \
             it. Sweeps already encrypted to it stay readable with its key; nothing is \
             re-encrypted.\n"
        ),
        // The time is the record's own text: checked printable ASCII by
        // core, and sanitised anyway, as every string from a record is.
        Revocation::AlreadyRevoked(at) => format!(
            "keys/{id}.json was revoked already, at {}, so keys revoke left it as it is.\n",
            sanitize(at.as_str(), RecordTime::MAX_LEN)
        ),
    };
    if own {
        text.push_str(
            "warning: that is this install's own device key, so sweeps are no longer encrypted \
             to this install. Run `sweepky logout` to finish retiring it: giving an install a \
             new device key is not part of this build.\n",
        );
    }
    text
}

/// Runs `keys revoke <deviceId>`.
///
/// `device_id` is read as text and checked here rather than by clap,
/// whose parse error would quote the value; core's check names only what
/// is wrong with it.
pub(crate) async fn revoke(ctx: &Context, device_id: &str) -> anyhow::Result<Report> {
    let id: DeviceId = device_id
        .parse()
        .context("keys revoke takes a device id, as `sweepky keys list` shows it")?;
    // The writers' lock, a fresh sign-in and a sign-out that is always
    // attempted, around the read and the write. The `async |signed|` closure
    // borrows `id` and `ctx` from this function; `signed` is lent to it for
    // the call only.
    with_writer_session(ctx, async |signed| {
        let keys = SessionKeyStore::new(signed.session(), ctx.network.pubky());
        let outcome = revoke_key(&keys, &id, clock::now()?).await?;
        let own = signed.login().device_id.as_ref() == Some(&id);
        Ok(Report::new(revoke_report(&id, &outcome, own)))
    })
    .await
}

#[cfg(test)]
mod tests {
    use pubky::{Keypair, PubkyResource, PublicKey};
    use serde_json::{Value, json};
    use sweepky_core::paths;
    use sweepky_core::{
        AgeRecipient, DeviceId, DeviceIdentity, DeviceKeyError, RecordTime, Zeroizing,
    };

    use super::{
        KeyAlarm, KeyCheck, KeyListing, Revocation, key_alarms, list_keys, revoke_key,
        revoke_report,
    };
    use crate::device::{KeyIds, PublicKeys, device_key_bytes, device_key_record};
    use crate::installs::Install;
    use crate::remote::{ListLimits, ListingError, ListingParser};
    use crate::test_support::{FakeKeyStore, KeyStoreCall};

    fn id(text: &str) -> DeviceId {
        text.parse().expect("a valid device id")
    }

    fn time(text: &str) -> RecordTime {
        text.parse().expect("a valid time")
    }

    /// A fresh owner: the public key a listing is asked for.
    fn owner() -> PublicKey {
        Keypair::random().public_key()
    }

    /// A fresh public age key, from an identity made at run time.
    fn new_key() -> AgeRecipient {
        DeviceIdentity::generate().recipient()
    }

    /// A record as this CLI publishes one, for `recipient`, as JSON.
    fn record_of(recipient: &AgeRecipient) -> Value {
        let bytes = device_key_bytes(&device_key_record(recipient, time("2026-10-16T09:41:07Z")))
            .expect("JSON");
        serde_json::from_slice(&bytes).expect("JSON")
    }

    /// A record as this CLI publishes one, for a fresh key, as JSON.
    fn record() -> Value {
        record_of(&new_key())
    }

    /// The `installs.json` entry of an install of this owner's here, with
    /// the key it published when that is recorded.
    fn install(id: &DeviceId, recipient: Option<&AgeRecipient>) -> Install {
        Install::new(id.clone(), recipient.cloned())
    }

    fn bytes(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).expect("JSON")
    }

    /// What `keys list` shows for `id`.
    fn entry<'a>(listing: &'a KeyListing, id: &DeviceId) -> &'a super::ListedKey {
        listing
            .keys
            .iter()
            .find(|key| &key.id == id)
            .expect("listed")
    }

    #[tokio::test]
    async fn unknown_ids_are_those_not_in_the_install_list() {
        let keys = FakeKeyStore::default();
        let own = id("own-install");
        let other = id("other");
        let own_key = new_key();
        keys.set_record(&own, bytes(&record_of(&own_key)));
        keys.set_record(&other, bytes(&record()));

        // installs.json knows `own`, with the key it published, and
        // login.json names it as this install's; nothing knows `other`.
        let installs = [install(&own, Some(&own_key))];
        let listing = list_keys(&keys, &owner(), &installs, Some(&own))
            .await
            .expect("lists");
        let mine = entry(&listing, &own);
        assert!(mine.this_install && !mine.unknown, "{mine:?}");
        assert_eq!(mine.check, KeyCheck::Matches);
        let theirs = entry(&listing, &other);
        assert!(!theirs.this_install && theirs.unknown, "{theirs:?}");
        // One alarm, for the unknown id, with what to do about it.
        assert_eq!(listing.alarms, [KeyAlarm::Unknown(other.clone())]);
        let text = listing.render();
        assert!(
            text.contains("keys/own-install.json: this install; in use"),
            "{text}"
        );
        assert!(text.contains("alarm: keys/other.json"), "{text}");
        assert!(text.contains("`sweepky keys revoke other`"), "{text}");
        assert!(!text.contains("alarm: keys/own-install.json"), "{text}");
    }

    #[tokio::test]
    async fn a_known_id_whose_record_names_another_key_alarms() {
        // Someone who can write keys/ (the owner's grant, or an operator)
        // rewrites the records of ids this owner's installs created, with
        // a valid, unrevoked key of their own, or with one this build cannot
        // encrypt to. Each is compared with the key installs.json records
        // for its id and raises the alarm; none is shown as in use.
        let keys = FakeKeyStore::default();
        let own = id("own-install");
        let sibling = id("sibling");
        let renamed = id("renamed-alg");
        let [own_key, sibling_key, renamed_key, intruder] =
            [new_key(), new_key(), new_key(), new_key()];
        keys.set_record(&own, bytes(&record_of(&intruder)));
        keys.set_record(&sibling, bytes(&record_of(&intruder)));
        // The key that install published, under an `alg` this build does
        // not encrypt to: no longer the record that install wrote.
        let mut other_alg = record_of(&renamed_key);
        other_alg["alg"] = json!("AGE-X25519");
        keys.set_record(&renamed, bytes(&other_alg));
        let installs = [
            install(&own, Some(&own_key)),
            install(&sibling, Some(&sibling_key)),
            install(&renamed, Some(&renamed_key)),
        ];

        let listing = list_keys(&keys, &owner(), &installs, Some(&own))
            .await
            .expect("lists");
        for known in [&own, &sibling, &renamed] {
            let shown = entry(&listing, known);
            assert!(!shown.unknown, "{shown:?}");
            assert_eq!(shown.check, KeyCheck::Replaced, "{shown:?}");
        }
        // One alarm each, in the order they were listed (the fake lists by
        // id), this install's own with `logout` as its fix.
        assert_eq!(
            listing.alarms,
            [
                KeyAlarm::Replaced {
                    id: own.clone(),
                    this_install: true
                },
                KeyAlarm::Replaced {
                    id: renamed.clone(),
                    this_install: false
                },
                KeyAlarm::Replaced {
                    id: sibling.clone(),
                    this_install: false
                },
            ]
        );
        let text = listing.render();
        assert!(!text.contains("in use"), "{text}");
        for part in [
            "keys/own-install.json: this install; REPLACED",
            "keys/sibling.json: another install made here; REPLACED",
            "alarm: keys/own-install.json, this install's own device key record, does not hold \
             this install's key",
            "`sweepky logout` to revoke keys/own-install.json",
            "alarm: keys/sibling.json, the device key record of another of this owner's installs",
            "`sweepky keys revoke sibling`",
            "`sweepky keys revoke renamed-alg`",
        ] {
            assert!(text.contains(part), "{part:?} missing from: {text}");
        }
        // Never a recipient: not the intruder's, nor the recorded ones.
        for key in [&own_key, &sibling_key, &renamed_key, &intruder] {
            assert!(!text.contains(&key.to_string()), "{text}");
        }

        // The check `login` runs (and P2c's `pull` will) raises the same
        // alarms from the same reads: every listed record, the known ones
        // too.
        let before = keys.calls().len();
        let alarms = key_alarms(&keys, &owner(), &installs, Some(&own))
            .await
            .expect("checks");
        assert_eq!(alarms, listing.alarms);
        let calls = keys.calls();
        for known in [&own, &sibling, &renamed] {
            assert!(
                calls[before..].contains(&KeyStoreCall::GetKey(known.clone())),
                "{calls:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_known_id_whose_record_holds_its_key_or_is_revoked_stays_quiet() {
        let keys = FakeKeyStore::default();
        let own = id("own-install");
        let sibling = id("sibling");
        let [own_key, sibling_key, intruder] = [new_key(), new_key(), new_key()];
        // This install's record holds the key it published.
        keys.set_record(&own, bytes(&record_of(&own_key)));
        // The sibling's was rewritten with another key, but is revoked: it
        // takes no further sweeps, so it is shown as revoked, not alarmed.
        let mut revoked = record_of(&intruder);
        revoked["revokedAt"] = json!("2026-10-16T10:00:00Z");
        keys.set_record(&sibling, bytes(&revoked));
        let installs = [
            install(&own, Some(&own_key)),
            install(&sibling, Some(&sibling_key)),
        ];

        let listing = list_keys(&keys, &owner(), &installs, Some(&own))
            .await
            .expect("lists");
        assert_eq!(entry(&listing, &own).check, KeyCheck::Matches);
        assert_eq!(entry(&listing, &sibling).check, KeyCheck::Skipped);
        assert!(listing.alarms.is_empty(), "{:?}", listing.alarms);
        let text = listing.render();
        assert!(
            text.contains("keys/own-install.json: this install; in use"),
            "{text}"
        );
        assert!(
            text.contains(
                "keys/sibling.json: another install made here; revoked 2026-10-16T10:00:00Z"
            ),
            "{text}"
        );
        assert!(!text.contains("alarm"), "{text}");
        let alarms = key_alarms(&keys, &owner(), &installs, Some(&own))
            .await
            .expect("checks");
        assert_eq!(alarms, []);
    }

    #[tokio::test]
    async fn a_known_id_without_a_recorded_key_is_unverified_not_an_alarm() {
        // An entry an earlier build wrote records the id alone, and an
        // installs.json that lost this install's entry records nothing:
        // there is no key to compare the record with, so keys list says so
        // rather than failing or showing the key as in use, and raises no
        // alarm.
        let keys = FakeKeyStore::default();
        let own = id("own-install");
        let earlier = id("earlier");
        keys.set_record(&own, bytes(&record()));
        keys.set_record(&earlier, bytes(&record()));
        for installs in [
            vec![install(&own, None), install(&earlier, None)],
            vec![install(&earlier, None)],
        ] {
            let listing = list_keys(&keys, &owner(), &installs, Some(&own))
                .await
                .expect("lists");
            for known in [&own, &earlier] {
                let shown = entry(&listing, known);
                assert!(!shown.unknown, "{shown:?}");
                assert_eq!(shown.check, KeyCheck::NotRecorded, "{shown:?}");
            }
            assert!(listing.alarms.is_empty(), "{:?}", listing.alarms);
            let text = listing.render();
            assert!(!text.contains("in use"), "{text}");
            assert!(!text.contains("alarm"), "{text}");
            for part in [
                "keys/own-install.json: this install; unverified",
                "keys/earlier.json: another install made here; unverified",
                "note: installs.json does not record the key keys/own-install.json was \
                 published with",
                "The next `sweepky login` records this install's key",
                "note: installs.json does not record the key keys/earlier.json",
            ] {
                assert!(text.contains(part), "{part:?} missing from: {text}");
            }
            // The login hint is for this install's key alone: one copy.
            assert_eq!(
                text.matches("The next `sweepky login`").count(),
                1,
                "{text}"
            );
        }
    }

    #[tokio::test]
    async fn unknown_key_that_is_revoked_raises_no_alarm() {
        // An unknown key that is revoked already is settled: it is still
        // marked unknown, but the alarm, whose fix is `keys revoke`, is not
        // raised again.
        let keys = FakeKeyStore::default();
        let other = id("other");
        let mut revoked = record();
        revoked["revokedAt"] = json!("2026-10-16T10:00:00Z");
        keys.set_record(&other, bytes(&revoked));

        let listing = list_keys(&keys, &owner(), &[], None).await.expect("lists");
        assert!(entry(&listing, &other).unknown);
        assert_eq!(entry(&listing, &other).check, KeyCheck::Skipped);
        assert!(listing.alarms.is_empty(), "{:?}", listing.alarms);
        assert!(!listing.render().contains("alarm"), "{}", listing.render());
    }

    #[tokio::test]
    async fn empty_keys_dir_raises_no_alarm() {
        let listing = list_keys(&FakeKeyStore::default(), &owner(), &[], None)
            .await
            .expect("lists");
        assert!(listing.keys.is_empty());
        assert!(listing.alarms.is_empty());
        assert!(!listing.render().contains("alarm"), "{}", listing.render());
    }

    /// A `keys/` listing the real parser read, with the records of `store`
    /// behind it: the fake's own listing skips nothing, so this one stands
    /// in for it.
    struct ParsedListing {
        ids: KeyIds,
        store: FakeKeyStore,
    }

    impl PublicKeys for ParsedListing {
        async fn list_key_ids(&self, _owner: &PublicKey) -> anyhow::Result<KeyIds> {
            Ok(self.ids.clone())
        }

        async fn get_key(
            &self,
            owner: &PublicKey,
            id: &DeviceId,
        ) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
            self.store.get_key(owner, id).await
        }
    }

    #[tokio::test]
    async fn invalid_key_names_are_skipped_not_fatal() {
        let owner = owner();
        let z32 = owner.z32();
        let dir = PubkyResource::new(owner.clone(), paths::KEYS_DIR).expect("a directory");
        // One valid entry, and five a stranger's homeserver could list that
        // are no `keys/<deviceId>.json`.
        let body = [
            format!("pubky://{z32}/pub/sweepky/keys/laptop.json"),
            // Not a device id: it starts with `-`.
            format!("pubky://{z32}/pub/sweepky/keys/-a.json"),
            // Not `.json`, or no extension at all.
            format!("pubky://{z32}/pub/sweepky/keys/laptop.txt"),
            format!("pubky://{z32}/pub/sweepky/keys/laptop"),
            // `..` in the transport form: the URL parser resolves it, so the
            // entry is `/pub/sweepky/x.json`, outside keys/.
            format!("https://_pubky.{z32}/storage/{z32}/pub/sweepky/keys/../x.json"),
            // `..` spelled with percent escapes is a plain name, inside a
            // subdirectory, and no device key either.
            format!("pubky://{z32}/pub/sweepky/keys/%2E%2E/x.json"),
        ]
        .join("\n");
        let mut parser = ListingParser::new(&dir, ListLimits::DEFAULT);
        assert!(matches!(parser.page(body.as_bytes()), Ok(None)), "one page");
        let ids = KeyIds::from_listing(parser.finish());
        assert_eq!(ids.ids, [id("laptop")]);
        assert_eq!(ids.skipped, 5);

        // `keys list` shows the one key and counts the rest.
        let store = FakeKeyStore::default();
        let laptop_key = new_key();
        store.set_record(&id("laptop"), bytes(&record_of(&laptop_key)));
        let installs = [install(&id("laptop"), Some(&laptop_key))];
        let listing = list_keys(&ParsedListing { ids, store }, &owner, &installs, None)
            .await
            .expect("skipped names are not fatal");
        assert_eq!(listing.keys.len(), 1);
        assert_eq!(listing.skipped_names, 5);
        let text = listing.render();
        assert!(text.contains("5 entries under keys/"), "{text}");
        assert!(
            !text.contains("x.json"),
            "a skipped name is not shown: {text}"
        );

        // A literal `..` in the `pubky://` form is no resource URL at all:
        // the SDK refuses the path, so the listing is refused whole, as for
        // any line that breaks the protocol. `keys list` then fails rather
        // than show a partial list.
        let dotdot = format!("pubky://{z32}/pub/sweepky/keys/../x.json");
        assert_eq!(
            ListingParser::new(&dir, ListLimits::DEFAULT)
                .page(dotdot.as_bytes())
                .err(),
            Some(ListingError::NotAResource)
        );
    }

    #[tokio::test]
    async fn listing_sanitises_label_and_alg() {
        let keys = FakeKeyStore::default();
        let mut hostile = record();
        // A colour escape, a right-to-left override and a zero-width space
        // in the label; an escape sequence in the alg.
        hostile["label"] = json!("\u{1b}[31mred\u{202e}txt.exe\u{200b}");
        hostile["alg"] = json!("age-x25519\u{1b}[0m");
        keys.set_record(&id("hostile"), bytes(&hostile));

        let text = list_keys(&keys, &owner(), &[install(&id("hostile"), None)], None)
            .await
            .expect("lists")
            .render();
        for raw in ['\u{1b}', '\u{202e}', '\u{200b}'] {
            assert!(!text.contains(raw), "{raw:?} printed raw: {text:?}");
        }
        for escaped in [
            r"\u{1b}[31mred",
            r"\u{202e}txt.exe\u{200b}",
            r"age-x25519\u{1b}[0m",
        ] {
            assert!(text.contains(escaped), "{escaped} missing: {text:?}");
        }
    }

    #[tokio::test]
    async fn unusable_key_is_flagged_by_device_id_without_recipient_text() {
        let keys = FakeKeyStore::default();
        let base = record();
        let recipient = base["recipient"].as_str().expect("a recipient").to_owned();
        // Another kind of key, as a newer client might publish.
        let mut new_alg = base.clone();
        new_alg["alg"] = json!("mlkem768x25519");
        keys.set_record(&id("new-alg"), bytes(&new_alg));
        // This build's kind, but not in the one spelling age accepts.
        let mut bad_recipient = base.clone();
        bad_recipient["recipient"] = json!(recipient.to_uppercase());
        keys.set_record(&id("bad-recipient"), bytes(&bad_recipient));
        // Revoked, and of another kind too: revoked is what counts.
        let mut revoked = new_alg.clone();
        revoked["revokedAt"] = json!("2026-10-16T10:00:00Z");
        keys.set_record(&id("revoked"), bytes(&revoked));
        keys.set_record(&id("fine"), bytes(&base));

        // Known ids whose key installs.json does not record, so the
        // unusable ones are flagged as unusable, not as replaced.
        let installs =
            ["new-alg", "bad-recipient", "revoked", "fine"].map(|name| install(&id(name), None));
        let listing = list_keys(&keys, &owner(), &installs, None)
            .await
            .expect("lists");
        assert_eq!(
            entry(&listing, &id("new-alg")).unusable,
            Some(DeviceKeyError::UnsupportedAlg)
        );
        assert!(matches!(
            entry(&listing, &id("bad-recipient")).unusable,
            Some(DeviceKeyError::Recipient(_))
        ));
        let shown_revoked = entry(&listing, &id("revoked"));
        assert_eq!(shown_revoked.revoked_at, Some(time("2026-10-16T10:00:00Z")));
        assert_eq!(shown_revoked.unusable, None);
        assert_eq!(entry(&listing, &id("fine")).unusable, None);

        let text = listing.render();
        // A warning per unusable key, naming it by its device id.
        assert!(text.contains("warning: keys/new-alg.json"), "{text}");
        assert!(text.contains("warning: keys/bad-recipient.json"), "{text}");
        assert!(!text.contains("warning: keys/revoked.json"), "{text}");
        assert!(!text.contains("warning: keys/fine.json"), "{text}");
        assert!(text.contains("revoked 2026-10-16T10:00:00Z"), "{text}");
        // Never the recipient's text, in either spelling.
        assert!(!text.contains(&recipient), "{text}");
        assert!(!text.contains(&recipient.to_uppercase()), "{text}");
    }

    /// The time `revoke_key` is handed as "now" in these tests.
    const NOW: &str = "2026-10-16T12:00:00Z";

    #[tokio::test]
    async fn revoke_sets_revoked_at_and_preserves_unknown_fields() {
        let keys = FakeKeyStore::default();
        let target = id("other-install");
        let mut original = record();
        original["addedLater"] = json!({ "nested": [1, "two", null] });
        keys.set_record(&target, bytes(&original));

        let outcome = revoke_key(&keys, &target, time(NOW))
            .await
            .expect("revokes");
        assert_eq!(outcome, Revocation::Revoked(time(NOW)));
        assert_eq!(
            keys.calls(),
            [
                KeyStoreCall::GetOwnKey(target.clone()),
                KeyStoreCall::PutKey(target.clone())
            ]
        );
        // The same record with `revokedAt` set, the newer field kept, and
        // nothing else changed.
        let written: Value =
            serde_json::from_slice(&keys.record(&target).expect("written")).expect("JSON");
        let mut expected = original;
        expected["revokedAt"] = json!(NOW);
        assert_eq!(written, expected);
    }

    #[test]
    fn revoke_report_of_own_key_says_to_log_out() {
        // Revoking this install's own key is allowed, and the report says
        // to log out; another install's says nothing of the kind.
        let target = id("this-install");
        let outcome = Revocation::Revoked(time(NOW));
        assert!(revoke_report(&target, &outcome, true).contains("`sweepky logout`"));
        assert!(!revoke_report(&target, &outcome, false).contains("logout"));
    }

    #[tokio::test]
    async fn revoke_keeps_an_existing_revoked_at() {
        let keys = FakeKeyStore::default();
        let target = id("old-install");
        let mut revoked = record();
        revoked["revokedAt"] = json!("2026-01-01T00:00:00Z");
        keys.set_record(&target, bytes(&revoked));

        let outcome = revoke_key(&keys, &target, time(NOW))
            .await
            .expect("idempotent");
        assert_eq!(
            outcome,
            Revocation::AlreadyRevoked(time("2026-01-01T00:00:00Z"))
        );
        // Read, and not written again.
        assert_eq!(keys.calls(), [KeyStoreCall::GetOwnKey(target.clone())]);
        assert_eq!(keys.record(&target), Some(bytes(&revoked)));
    }

    #[tokio::test]
    async fn revoke_of_a_missing_id_is_an_error() {
        let keys = FakeKeyStore::default();
        let err = revoke_key(&keys, &id("nobody"), time(NOW))
            .await
            .expect_err("nothing to revoke");
        let shown = format!("{err:#}");
        assert!(shown.contains("keys/nobody.json"), "{shown}");
        assert!(shown.contains("`sweepky keys list`"), "{shown}");
        assert_eq!(keys.calls(), [KeyStoreCall::GetOwnKey(id("nobody"))]);
    }

    #[tokio::test]
    async fn revoke_of_an_unreadable_record_writes_nothing() {
        // A record this build cannot read is left as it is, not rewritten.
        let keys = FakeKeyStore::default();
        let broken = b"{\"schemaVersion\":1,\"alg\":".to_vec();
        keys.set_record(&id("broken"), broken.clone());
        let err = revoke_key(&keys, &id("broken"), time(NOW))
            .await
            .expect_err("not a record");
        assert!(format!("{err:#}").contains("keys/broken.json"), "{err:#}");
        assert_eq!(keys.record(&id("broken")), Some(broken));
        assert!(!keys.calls().contains(&KeyStoreCall::PutKey(id("broken"))));
    }
}
