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
//!    (`remote::list_dir` with `ListLimits::DEFAULT`); a name that is not a
//!    `keys/<deviceId>.json` is skipped and counted, never fatal. A listing
//!    past those limits is refused whole.
//! 3. Each listed record is read, one after another, capped at
//!    `MAX_RECORD_BYTES`, and within [`KEY_RECORDS_BUDGET_BYTES`] for all of
//!    them together, then parsed with core's `DeviceKey::from_json`. A
//!    record that is gone, does not parse or cannot be read is named by its
//!    device id with the reason, and not listed.
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
//! reused this install's key, and `pull` on every run.
//!
//! **The check either finishes or fails, typed.** [`key_alarms`] gives the
//! alarms only once it has read every listed record within those bounds;
//! otherwise it fails with a [`KeyCheckError`]: the listing past its
//! limits, the records past the budget, the listing failing, or a record
//! under a known id that could not be read, which could hold any key. (A
//! record under an unknown id that could not be read is that id's alarm,
//! as 02 has it: only a revoked record settles it.) So a check that could
//! not finish never reads as "no alarms", and the caller has to say so:
//! `login` as a warning, `pull` as an alarm. `keys list` reads through the
//! same [`list_keys`], so the two never disagree; it fails in the same way
//! past the listing limits or the budget, and shows a record it could not
//! read as a warning beside the rest, which is what `login`'s warning
//! points at.
//!
//! **`keys revoke <deviceId>`** ([`revoke`]) checks the id, then, under the
//! writers' lock with a session of its own (`session::with_writer_session`:
//! an identity session is signed out afterwards, a Ring one only dropped),
//! reads the signed-in user's own
//! `keys/<id>.json`, sets `revokedAt` to now unless it is set already, and
//! writes it back with every field it does not know kept ([`revoke_key`]).
//! Revoking this install's own key is allowed; the report then says to log
//! out. `logout` revokes this install's own key with the same
//! read-modify-write ([`revoke_if_published`]).

use std::collections::BTreeSet;
use std::fmt;

use anyhow::{Context as _, bail};
use pubky::PublicKey;
use sweepky_core::{
    AgeRecipient, DeviceId, DeviceKey, DeviceKeyError, KeyAlg, MAX_RECORD_BYTES, Pubky, RecordTime,
};

use crate::clock;
use crate::device::{
    KeyStore, PublicKeyReader, PublicKeys, SessionKeyStore, device_key_bytes, holds_key,
};
use crate::display::{MAX_LABEL_CHARS, sanitize};
use crate::installs::{
    Install, read_installs, replaced_key_alarm, unknown_key_alarm, unknown_key_ids,
};
use crate::remote::{ListLimits, ListingError, pubky_of, public_key_of, write_error};
use crate::session::{NOT_LOGGED_IN, with_writer_session};
use crate::state::read_login_state;
use crate::{Context, Report};

// ---------------------------------------------------------------------------
// The bounds of one check of `keys/`, and how it fails.

/// The most bytes one check of `keys/` reads, all its records together: 8
/// MiB, P2c's choice.
///
/// A device key record is a few hundred bytes, and one holding a
/// post-quantum key would still be a few KiB, so a full listing of real
/// records takes a small part of it. `keys/` is the owner's own directory,
/// written by their installs or by whoever holds their grant or runs their
/// homeserver, so records anywhere near the budget are themselves a sign
/// that someone wrote there. Each record keeps its own cap,
/// `MAX_RECORD_BYTES` (1 MiB), which is the record format's.
const KEY_RECORDS_BUDGET_BYTES: usize = 8 * MIB;

/// One mebibyte.
const MIB: usize = 1024 * 1024;

/// What one check of `keys/` may still read, out of
/// [`KEY_RECORDS_BUDGET_BYTES`].
struct ReadBudget {
    left: usize,
}

impl ReadBudget {
    /// The whole budget, for a new check.
    fn new() -> Self {
        Self {
            left: KEY_RECORDS_BUDGET_BYTES,
        }
    }

    /// Lets the next read go ahead only while a record at the most a read
    /// returns, `MAX_RECORD_BYTES`, would still fit. So the reads together
    /// never pass the budget, however large each record turns out to be.
    fn check_room_for_a_record(&self) -> Result<(), KeyCheckError> {
        if self.left < MAX_RECORD_BYTES {
            return Err(KeyCheckError::OverBudget);
        }
        Ok(())
    }

    /// Takes `bytes` off what is left. `saturating_sub` stops at zero
    /// rather than wrapping round, so a reader that broke its cap leaves no
    /// room for another read instead of a huge amount.
    fn spend(&mut self, bytes: usize) {
        self.left = self.left.saturating_sub(bytes);
    }
}

/// Why a check of an owner's `keys/` could not finish: [`key_alarms`], and
/// the [`list_keys`] behind `keys list`, which reads with the same bounds.
///
/// It is not "no alarms", so a caller that gets one has to say that the
/// check failed: `login` prints it as a warning and `pull` as an alarm.
/// Its own text is fixed, with numbers and a device id at most (a
/// [`DeviceId`] holds only `A-Z`, `a-z`, `0-9`, `-` and `_`). A listing or
/// a read that failed keeps the reader's error as its cause, which for
/// [`PublicKeyReader`] is `remote`'s: fixed text and an HTTP status, never
/// the server's words or a record's.
#[derive(Debug)]
pub(crate) enum KeyCheckError {
    /// The listing has more entries than [`ListLimits::DEFAULT`] reads, so
    /// no record was read.
    TooManyKeys,
    /// What was read left less of [`KEY_RECORDS_BUDGET_BYTES`] than one more
    /// record may hold, so the check stopped before the rest.
    OverBudget,
    /// The listing failed otherwise: a request that failed, an answer other
    /// than 2xx or 404, a line that breaks the protocol.
    Listing(anyhow::Error),
    /// A record under a known id could not be read: a request that failed,
    /// or a body over `MAX_RECORD_BYTES`. It could hold any key, so the
    /// check cannot say whether it should alarm. Under an unknown id, a
    /// failed read is that id's alarm instead.
    Read {
        /// The record's device id.
        id: DeviceId,
        /// Why, from the reader.
        cause: anyhow::Error,
    },
}

impl KeyCheckError {
    /// A failed listing of `keys/`, sorted by why it failed.
    fn from_listing_error(error: anyhow::Error) -> Self {
        // `downcast_ref` finds a value of the named type in the error, under
        // the context `list_dir` wraps round it: here the parser's own
        // `ListingError`, the typed reason for a refused listing.
        match error.downcast_ref::<ListingError>() {
            Some(ListingError::TooManyEntries | ListingError::TooManyPages) => Self::TooManyKeys,
            _ => Self::Listing(error),
        }
    }
}

impl fmt::Display for KeyCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The cause is not written here: `source` below hands it on, and
        // `anyhow`'s `{:#}` prints it after this text.
        match self {
            Self::TooManyKeys => write!(
                f,
                "keys/ lists more than the {} entries one check reads, so none of its records \
                 was checked",
                ListLimits::DEFAULT.max_entries
            ),
            Self::OverBudget => write!(
                f,
                "the records under keys/ are more than one check reads: it reads up to {} MiB, \
                 and starts on a record only while {} MiB, the most one may hold, is left (a read \
                 that failed counts as that much), so it stopped before the rest; a device key \
                 record is a few hundred bytes",
                KEY_RECORDS_BUDGET_BYTES / MIB,
                MAX_RECORD_BYTES / MIB
            ),
            Self::Listing(_) => f.write_str("keys/ could not be listed"),
            Self::Read { id, .. } => write!(
                f,
                "keys/{id}.json could not be read, so the check cannot tell which key it holds"
            ),
        }
    }
}

/// Makes it an error type, so `?` turns it into an `anyhow::Error`, and
/// hands on the cause of a failed listing or read as its `source`, which is
/// how an error chain is linked.
impl std::error::Error for KeyCheckError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            // `as_ref` lends the `anyhow::Error` out as the plain
            // `dyn Error` it wraps.
            Self::Listing(cause) | Self::Read { cause, .. } => Some(cause.as_ref()),
            Self::TooManyKeys | Self::OverBudget => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Reading one record.

/// What reading one listed `keys/<id>.json` gave.
enum RecordRead {
    /// The record, parsed.
    Parsed(DeviceKey),
    /// Not readable as a device key record, and why.
    Unreadable(Unreadable),
}

/// Why a listed `keys/<id>.json` is not shown.
#[derive(Debug)]
enum Unreadable {
    /// It was read, but is no device key record this build reads: gone
    /// (404) by the time it was read, or a parse error, in fixed text that
    /// quotes none of it. No sweeper running this build encrypts to it
    /// either.
    NotARecord(String),
    /// The read failed: a request that failed, or a body over the cap. What
    /// the record holds is unknown, so a sweeper might still encrypt to it:
    /// `keys list` warns, and the check fails ([`KeyCheckError::Read`]).
    ReadFailed(anyhow::Error),
}

impl fmt::Display for Unreadable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotARecord(reason) => f.write_str(reason),
            // `remote`'s errors are fixed text and a status, never the
            // server's own words. `{:#}` prints the whole chain on one line.
            Self::ReadFailed(error) => write!(f, "{error:#}"),
        }
    }
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

/// Reads and parses `owner`'s `keys/<id>.json`, taking what it read off
/// `budget`.
///
/// Only the budget makes it an error ([`KeyCheckError::OverBudget`],
/// before anything is asked for): a record that cannot be read comes back
/// as a [`RecordRead`] too, so the caller decides what that means.
async fn read_record(
    keys: &impl PublicKeys,
    owner: &PublicKey,
    id: &DeviceId,
    budget: &mut ReadBudget,
) -> Result<RecordRead, KeyCheckError> {
    budget.check_room_for_a_record()?;
    let read = match keys.get_key(owner, id).await {
        Ok(Some(bytes)) => {
            budget.spend(bytes.len());
            // `&bytes` lends the `Zeroizing<Vec<u8>>` out as the `&[u8]`
            // `from_json` takes, through `Deref`, without a copy.
            match DeviceKey::from_json(&bytes) {
                Ok(record) => RecordRead::Parsed(record),
                // core's `RecordError` names the kind of fault and where it
                // is, never the input.
                Err(error) => RecordRead::Unreadable(Unreadable::NotARecord(format!(
                    "it is not a device key record this build reads ({error})"
                ))),
            }
        }
        // Listed, but deleted before it was read.
        Ok(None) => RecordRead::Unreadable(Unreadable::NotARecord(
            "it was listed, but is gone now".to_owned(),
        )),
        Err(error) => {
            // A failed read may have taken a whole record's worth before it
            // stopped (a body with no length is refused only at the chunk
            // that crosses the cap), so it counts as one. Otherwise a server
            // could make every read fail just past the cap and never touch
            // the budget.
            budget.spend(MAX_RECORD_BYTES);
            RecordRead::Unreadable(Unreadable::ReadFailed(error))
        }
    };
    Ok(read)
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
/// so that key is listed, known and recorded with its key; P2c's `pull`
/// runs it too.
///
/// The alarms come back only when every listed record was read; otherwise
/// the check fails with a [`KeyCheckError`] (see the module docs), and a
/// record under a known id that could not be read fails it too, though
/// `keys list` shows that one as a warning. A record under an unknown id
/// that could not be read is its alarm, as 02 has it: only a revoked
/// record settles that alarm, and a failed read shows none.
pub(crate) async fn key_alarms(
    keys: &impl PublicKeys,
    owner: &PublicKey,
    installs: &[Install],
    this_install: Option<&DeviceId>,
) -> Result<Vec<KeyAlarm>, KeyCheckError> {
    // Taking the listing apart moves these two fields out of it; `..`
    // drops the rest.
    let KeyListing {
        alarms, unreadable, ..
    } = list_keys(keys, owner, installs, this_install).await?;
    for key in unreadable {
        // A `let` chain: the pattern must match and the `&&` hold too. An
        // id with an `Unknown` alarm raised it already, whatever its record
        // holds, so its failed read leaves nothing undecided.
        if let Unreadable::ReadFailed(cause) = key.why
            && !alarms.contains(&KeyAlarm::Unknown(key.id.clone()))
        {
            return Err(KeyCheckError::Read { id: key.id, cause });
        }
    }
    Ok(alarms)
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
    /// The listed ids whose record was gone, did not parse or could not be
    /// read.
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
    /// Why.
    why: Unreadable,
}

impl UnreadableKey {
    /// The warning that names the record and says why it is not listed.
    fn warning(&self) -> String {
        format!(
            "warning: keys/{}.json is not listed: {}.\n",
            self.id, self.why
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
/// id `login.json` records as this install's.
///
/// It fails, with a [`KeyCheckError`], when the listing fails or is past
/// [`ListLimits::DEFAULT`], and when the records pass
/// [`KEY_RECORDS_BUDGET_BYTES`]. One record that cannot be read is a
/// warning in the listing, which [`key_alarms`] turns into a failure.
async fn list_keys(
    keys: &impl PublicKeys,
    owner: &PublicKey,
    installs: &[Install],
    this_install: Option<&DeviceId>,
) -> Result<KeyListing, KeyCheckError> {
    let listed = keys
        .list_key_ids(owner)
        .await
        .map_err(KeyCheckError::from_listing_error)?;
    // `PublicKeyReader` lists with `ListLimits::DEFAULT`, which refuses a
    // longer listing already. Counting again here holds any `PublicKeys`
    // to the same bound, and comes before anything that grows with the
    // listing, such as the search for unknown ids.
    if listed.ids.len().saturating_add(listed.skipped) > ListLimits::DEFAULT.max_entries {
        return Err(KeyCheckError::TooManyKeys);
    }
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
    let mut budget = ReadBudget::new();
    // `listed.ids` is moved into the loop: each `id` is owned, so it can
    // move into the entry without a clone.
    for id in listed.ids {
        if !seen.insert(id.clone()) {
            continue;
        }
        let is_unknown = unknown.contains(&id);
        // One read at a time, each awaited before the next is sent: the
        // budget is checked before every one.
        let read = read_record(keys, owner, &id, &mut budget).await?;
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
            RecordRead::Unreadable(why) => {
                listing.unreadable.push(UnreadableKey { id, why });
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
    // The writers' lock and a fresh session around the read and the write;
    // afterwards an identity session is signed out, a Ring one only dropped. The `async |signed|` closure
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
        AgeRecipient, DeviceId, DeviceIdentity, DeviceKeyError, MAX_RECORD_BYTES, RecordTime,
        Zeroizing,
    };

    use super::{
        KEY_RECORDS_BUDGET_BYTES, KeyAlarm, KeyCheck, KeyCheckError, KeyListing, Revocation,
        key_alarms, list_keys, revoke_key, revoke_report,
    };
    use crate::device::{KeyIds, PublicKeys, device_key_bytes, device_key_record};
    use crate::installs::Install;
    use crate::remote::{ListLimits, ListingError, ListingParser};
    use crate::test_support::{FAKE_READ_FAILURE, FAKE_SERVER_TEXT, FakeKeyStore, KeyStoreCall};

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

        // The check `login` and `pull` run raises the same
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

    /// A failure of the check as a caller prints it: its own text, then
    /// each cause after it, as `anyhow`'s `{:#}` prints a chain.
    fn shown(failure: KeyCheckError) -> String {
        format!("{:#}", anyhow::Error::new(failure))
    }

    /// Asserts that `text`, a failure as a caller prints it, quotes none of
    /// `quoted` (records' labels and keys, listing lines) and none of the
    /// fake homeserver's own words.
    fn assert_quotes_none(text: &str, quoted: &[&str]) {
        for part in quoted.iter().chain(&[FAKE_SERVER_TEXT]) {
            assert!(!text.contains(part), "{part:?} quoted in: {text}");
        }
    }

    /// A record as this CLI publishes one, for `recipient`, under `label`,
    /// padded with trailing spaces (which JSON allows) to exactly `len`
    /// bytes.
    fn padded_record(recipient: &AgeRecipient, label: &str, len: usize) -> Vec<u8> {
        let mut value = record_of(recipient);
        value["label"] = json!(label);
        let mut padded = bytes(&value);
        padded.resize(len, b' ');
        padded
    }

    #[tokio::test]
    async fn records_past_the_budget_fail_the_check_after_reading_no_more_than_it() {
        // A device key record is a few hundred bytes, so records at the
        // per-record cap, one more than the budget holds, are someone
        // filling keys/. Each carries a label and a key the failure must
        // not quote.
        const LABEL: &str = "synthetic-label-text";
        let keys = FakeKeyStore::default();
        let owner = owner();
        let recipient = new_key();
        let fit = KEY_RECORDS_BUDGET_BYTES / MAX_RECORD_BYTES;
        let ids: Vec<DeviceId> = (0..=fit).map(|n| id(&format!("filler-{n}"))).collect();
        for filler in &ids {
            keys.set_record(filler, padded_record(&recipient, LABEL, MAX_RECORD_BYTES));
        }

        let failure = key_alarms(&keys, &owner, &[], None)
            .await
            .expect_err("over the budget");
        assert!(matches!(failure, KeyCheckError::OverBudget), "{failure:?}");
        // No more than the budget was read: the records asked for add up
        // to at most it, and the last one, which would pass it, was never
        // asked for.
        let calls = keys.calls();
        let read: usize = calls
            .iter()
            .filter_map(|call| match call {
                KeyStoreCall::GetKey(asked) => keys.record(asked).map(|bytes| bytes.len()),
                _ => None,
            })
            .sum();
        assert!(read <= KEY_RECORDS_BUDGET_BYTES, "{read} bytes read");
        let last = ids.last().expect("ids");
        assert!(
            !calls.contains(&KeyStoreCall::GetKey(last.clone())),
            "{calls:?}"
        );
        // Fixed text, which quotes no record.
        let text = shown(failure);
        assert_eq!(
            text,
            "the records under keys/ are more than one check reads: it reads up to 8 MiB, and \
             starts on a record only while 1 MiB, the most one may hold, is left (a read that \
             failed counts as that much), so it stopped before the rest; a device key record is \
             a few hundred bytes"
        );
        assert_quotes_none(&text, &[LABEL, &recipient.to_string()]);

        // `keys list` reads with the same bounds, and fails the same way.
        let listed = list_keys(&keys, &owner, &[], None)
            .await
            .expect_err("the same bounds");
        assert!(matches!(listed, KeyCheckError::OverBudget), "{listed:?}");

        // One record fewer is the budget exactly, which is not past it:
        // every record is read and checked.
        keys.remove_record(last);
        let alarms = key_alarms(&keys, &owner, &[], None)
            .await
            .expect("within the budget");
        assert_eq!(alarms.len(), fit);
    }

    /// A `keys/` whose listing is refused with this error, which
    /// `list_key_ids` hands on in the context `remote::list_dir` adds to
    /// it, as `PublicKeyReader` does.
    struct RefusedListing(ListingError);

    impl PublicKeys for RefusedListing {
        async fn list_key_ids(&self, owner: &PublicKey) -> anyhow::Result<KeyIds> {
            Err(anyhow::Error::new(self.0).context(format!(
                "could not list {} of {}",
                paths::KEYS_DIR,
                owner.z32()
            )))
        }

        async fn get_key(
            &self,
            _owner: &PublicKey,
            _id: &DeviceId,
        ) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
            anyhow::bail!("a refused listing names no record to read")
        }
    }

    /// What the real parser refuses a `keys/` listing with one entry past
    /// [`ListLimits::DEFAULT`], read in full pages as `list_dir` reads it.
    fn refusal_past_the_default(owner: &PublicKey) -> ListingError {
        let dir = PubkyResource::new(owner.clone(), paths::KEYS_DIR).expect("a directory");
        let mut parser = ListingParser::new(&dir, ListLimits::DEFAULT);
        let z32 = owner.z32();
        let page_size = usize::from(ListLimits::DEFAULT.page_size);
        // The bound only stops a parser that never refuses from looping.
        for page in 0..=ListLimits::DEFAULT.max_pages {
            let lines: String = (page * page_size..(page + 1) * page_size)
                .map(|n| format!("pubky://{z32}/pub/sweepky/keys/k{n}.json\n"))
                .collect();
            if let Err(refusal) = parser.page(lines.as_bytes()) {
                return refusal;
            }
        }
        panic!("the parser read more than ListLimits::DEFAULT allows");
    }

    #[tokio::test]
    async fn a_listing_past_the_default_limits_is_a_typed_failure_not_alarms() {
        let limit = ListLimits::DEFAULT.max_entries;
        let owner = owner();
        // Ids none of this owner's installs created, listed with no record
        // behind them: on its own, each is an alarm.
        let keys = FakeKeyStore::default();
        for n in 0..limit {
            keys.list_without_record(&id(&format!("k{n}")));
        }
        let alarms = key_alarms(&keys, &owner, &[], None)
            .await
            .expect("at the limit, the check runs");
        assert_eq!(alarms.len(), limit);

        // One past it is a failure, before any record is read, rather than
        // a thousand alarms; `keys list` refuses it the same way.
        keys.list_without_record(&id("one-more"));
        let before = keys.calls().len();
        let failure = key_alarms(&keys, &owner, &[], None)
            .await
            .expect_err("past the limit");
        assert!(matches!(failure, KeyCheckError::TooManyKeys), "{failure:?}");
        assert_eq!(
            keys.calls()[before..],
            [KeyStoreCall::ListKeyIds(owner.clone())]
        );
        let listed = list_keys(&keys, &owner, &[], None)
            .await
            .expect_err("the same bounds");
        assert!(matches!(listed, KeyCheckError::TooManyKeys), "{listed:?}");
        let text = shown(failure);
        assert_eq!(
            text,
            "keys/ lists more than the 1000 entries one check reads, so none of its records was \
             checked"
        );
        assert_quotes_none(&text, &["k1000", "one-more"]);

        // The real listing refuses the entry past the limit itself, and
        // that refusal, as `list_dir` hands it on, is the same failure.
        let refusal = refusal_past_the_default(&owner);
        assert_eq!(refusal, ListingError::TooManyEntries);
        let failure = key_alarms(&RefusedListing(refusal), &owner, &[], None)
            .await
            .expect_err("refused");
        assert!(matches!(failure, KeyCheckError::TooManyKeys), "{failure:?}");
        assert_quotes_none(&shown(failure), &["pubky://", "k1000"]);

        // Any other refusal of the listing is a failure too, with
        // `remote`'s fixed reason as its cause.
        let failure = key_alarms(&RefusedListing(ListingError::NotUtf8), &owner, &[], None)
            .await
            .expect_err("refused");
        assert!(matches!(failure, KeyCheckError::Listing(_)), "{failure:?}");
        assert_eq!(
            shown(failure),
            format!(
                "keys/ could not be listed: could not list /pub/sweepky/keys/ of {}: a line of the \
                 listing is not UTF-8",
                owner.z32()
            )
        );
    }

    #[tokio::test]
    async fn a_record_that_cannot_be_read_fails_the_check() {
        // A known id whose read fails: no alarm could say whether its
        // record still holds that install's key, so the check fails rather
        // than come back with none. `keys list`, from the same reads, shows
        // the rest with a warning, as P2a had it.
        let keys = FakeKeyStore::default();
        let owner = owner();
        let own = id("own-install");
        let sibling = id("sibling");
        let [own_key, sibling_key] = [new_key(), new_key()];
        keys.set_record(&own, bytes(&record_of(&own_key)));
        keys.set_record(&sibling, bytes(&record_of(&sibling_key)));
        keys.fail_reads_of(&sibling);
        let installs = [
            install(&own, Some(&own_key)),
            install(&sibling, Some(&sibling_key)),
        ];

        let failure = key_alarms(&keys, &owner, &installs, Some(&own))
            .await
            .expect_err("a read failed");
        assert!(
            matches!(&failure, KeyCheckError::Read { id, .. } if *id == sibling),
            "{failure:?}"
        );
        // The device id and `remote`'s fixed words for the failed request,
        // and no record.
        let text = shown(failure);
        assert_eq!(
            text,
            format!(
                "keys/sibling.json could not be read, so the check cannot tell which key it \
                 holds: {FAKE_READ_FAILURE}"
            )
        );
        assert_quotes_none(&text, &[&own_key.to_string(), &sibling_key.to_string()]);

        let listing = list_keys(&keys, &owner, &installs, Some(&own))
            .await
            .expect("keys list lists the rest");
        assert!(listing.alarms.is_empty(), "{:?}", listing.alarms);
        let rendered = listing.render();
        for part in [
            "keys/own-install.json: this install; in use",
            "warning: keys/sibling.json is not listed",
        ] {
            assert!(rendered.contains(part), "{part:?} missing from: {rendered}");
        }
    }

    #[tokio::test]
    async fn a_record_under_an_unknown_id_that_cannot_be_read_still_alarms() {
        // 02: "a record under an unknown id that it cannot read still
        // alarms". Only a revoked record settles that alarm, and a failed
        // read shows none, so the check finishes with the alarm rather than
        // failing, and `login` raises it rather than a warning.
        let keys = FakeKeyStore::default();
        let owner = owner();
        let own = id("own-install");
        let own_key = new_key();
        keys.set_record(&own, bytes(&record_of(&own_key)));
        let stranger = id("stranger");
        let mut revoked = record_of(&new_key());
        revoked["revokedAt"] = json!(NOW);
        keys.set_record(&stranger, bytes(&revoked));
        keys.fail_reads_of(&stranger);
        let installs = [install(&own, Some(&own_key))];

        let alarms = key_alarms(&keys, &owner, &installs, Some(&own))
            .await
            .expect("the unknown id's alarm settles the check");
        assert_eq!(alarms, [KeyAlarm::Unknown(stranger.clone())]);
        let listing = list_keys(&keys, &owner, &installs, Some(&own))
            .await
            .expect("keys list lists it");
        assert_eq!(listing.alarms, alarms);
        assert!(
            listing
                .render()
                .contains("warning: keys/stranger.json is not listed"),
            "{}",
            listing.render()
        );
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
