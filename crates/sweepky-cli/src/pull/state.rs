//! The local state `pull` keeps between runs, in two files of the data
//! directory, each holding one entry per owner:
//!
//! - `feed-cursors.json`, an owner's [`FeedCursors`]: for each watched
//!   homeserver, the event id its `/events/` feed has been read up to (01,
//!   "Open bounties": `pull` advances a cursor only after the whole batch
//!   is processed and persists it per homeserver, [`FeedCursors::advance`]).
//! - `poll-state.json`, an owner's [`PollState`]: what the roster polling
//!   learnt (01, "Circle"). For each member, the newest record id seen in
//!   their `bounties/` and `sweeps/` ([`Watermarks`]), where the next
//!   newest-first listing stops, and the last of their done bounties, open
//!   bounties and running sweeps read again, where the next turn through
//!   each kind starts; a summary of each bounty and
//!   sweep read ([`BountySummary`], [`SweepSummary`]), with the `ETag` its
//!   last answer gave, so a record that can still change is read again
//!   with `If-None-Match`; the `ETag` of each of the owner's own
//!   `discovered.json`; the strangers' sweeps accepted for each of the
//!   owner's bounties; and the sweeps whose deletion was confirmed.
//!
//! ```json
//! {"schemaVersion":1,"owners":{"<owner z32>":{"cursors":{"<homeserver z32>":"<event id>"}}}}
//! {"schemaVersion":1,"owners":{"<owner z32>":{
//!   "watermarks":{"<member z32>":{"bounties":"<id>","sweeps":"<id>","rereadDoneAfter":"<id>",
//!     "rereadOpenAfter":"<id>","rereadRunningAfter":"<id>"}},
//!   "bounties":{"pubky://<owner>/pub/sweepky/bounties/<id>.json":
//!     {"status":"open","open":true,"credits":[],"etag":"<tag>"}},
//!   "sweeps":{"pubky://<sweeper>/pub/sweepky/sweeps/<id>.json":
//!     {"bounty":"pubky://…","targets":["t1"],"status":"running","etag":null,"pulled":false}},
//!   "discoveredEtags":{"<bounty id>":"<tag>"},
//!   "acceptedSweeps":{"<bounty id>":["pubky://<sweeper>/pub/sweepky/sweeps/<id>.json"]},
//!   "deletedSweeps":["pubky://<sweeper>/pub/sweepky/sweeps/<id>.json"]}}}
//! ```
//!
//! **Per owner**, because one `SWEEPKY_HOME` can see several logins over
//! time, and a cursor or a watermark means something only for the owner
//! whose bounties were pulled. Every key is compared by its bytes, never
//! by its spelling (core's `Pubky`, `BountyRef` and `SweepRef`).
//!
//! The rules, as for every file of Sweepky's own ([`crate::private_fs`]):
//!
//! - **Owner-only.** Each file is 0600 in the 0700 data directory, written
//!   whole to a new temp file, synced, renamed into place and its
//!   directory synced; never `chmod`ed afterwards, never through a link.
//! - **Bounded.** A read refuses a link, a loose file and one over its cap
//!   ([`MAX_FEED_CURSORS_BYTES`], [`MAX_POLL_STATE_BYTES`]) before a byte is
//!   read, and a write that would pass the cap is refused, leaving the file
//!   as it was, so the file never holds what it cannot read back.
//! - **No secret.** Public keys, record and event ids, URLs, statuses,
//!   target ids and `ETag`s only. An `ETag` is a server's text: it is
//!   checked when it is read back as when it first came, sent back, and
//!   never printed.
//! - **Errors quote nothing.** serde_json's messages go through core's
//!   `RecordError`, which keeps only the kind of fault and where it is.
//! - **Fields a newer Sweepky adds are kept** on a rewrite: at the top, in
//!   each owner's entry, and in each watermark and summary.
//!
//! **Writing.** `write` reads the file again and replaces this owner's
//! entry alone, so another owner's stays as the file has it now. That is
//! a read, a change and a write, and nothing here locks: every writer of
//! either file holds the pull lock (`crate::lock::PullLock`) around its
//! reads and writes, so no other write comes in between.
//!
//! - **`pull`** reads both files as it starts and writes them back after
//!   each step, so it holds the pull lock from its first read to its last
//!   write: two pulls of one install run one after the other, and neither
//!   writes back a state that lacks the other's steps.
//! - **`post --open`** lowers `feed-cursors.json`'s cursors for a new open
//!   bounty under the pull lock too. It takes the pull lock before the
//!   writers' lock, the order `pull` takes them in (`pull` takes the
//!   writers' lock inside the pull lock for its one public write), so
//!   neither command holds one while it waits for the other. It waits
//!   while a `pull` runs, so a cursor it lowers is never written over by a
//!   `pull` that read the file before ([`FeedCursors::advance`]).
//! - **`logout`** reads and writes neither file.
//!
//! **What the poll state holds came from other people's records.** A
//! status is an open string, and credits and targets are lists, so a
//! summary is as long as its record makes it. `pull` bounds what a record
//! may carry into a summary and how many records the roster poll reads a
//! run (`pull::roster`), and how many strangers' sweeps the feed watcher
//! keeps in all, under half of the cap (`pull::feed`). So no stranger alone
//! can fill the file, but the roster's records are bounded per run only,
//! and a roster key can fill it over many runs. The cap keeps the file
//! finite and is the backstop: a write that would pass it is refused with
//! [`WouldPassCap`], which the feed watcher takes as no room for what it
//! read, and every other caller as an error.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::PathBuf;

use anyhow::Context as _;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sweepky_core::{
    Bounty, BountyRef, BountyStatus, EventCursor, Pubky, RecordError, RecordId, SchemaVersion,
    Sweep, SweepRef, SweepStatus, TargetId, UnknownFields,
};

use crate::Dirs;
use crate::private_fs::{ensure_private_dir, read_private_file, write_private_file};
use crate::remote::ETag;

/// The most Sweepky reads, or writes, of `feed-cursors.json`: 64 KiB, the
/// cap of its other small local files. In compact JSON a cursor takes at
/// most 78 bytes and an owner's entry 71 more, so that is room for some
/// 400 owners watching one homeserver each, or one owner watching some 800.
const MAX_FEED_CURSORS_BYTES: usize = 64 * 1024;

/// The most Sweepky reads, or writes, of `poll-state.json`: 4 MiB. In
/// compact JSON, with a 46-byte tag as the 0.16.2 homeserver gives, a
/// sweep summary of one target takes about 320 bytes and a bounty summary
/// about 200 plus 55 per credit, so that is room for some 15,000 summaries.
const MAX_POLL_STATE_BYTES: usize = 4 * 1024 * 1024;

/// One owner's feed cursors: for each watched homeserver, by its public
/// key, the event id of its `/events/` feed read up to. The next read of
/// that feed starts after it.
///
/// Public values only, so deriving `Debug` prints nothing secret.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
// `default`: a field missing from the file reads as its default, here an
// empty map, so an entry a newer Sweepky shaped otherwise still reads.
#[serde(default)]
pub(crate) struct FeedCursors {
    /// The cursor per homeserver. A `BTreeMap` keeps its keys in one order,
    /// so the file is written the same way every time.
    cursors: BTreeMap<Pubky, EventCursor>,
    /// Fields a newer Sweepky wrote in this owner's entry, kept for the
    /// rewrite.
    #[serde(flatten)]
    extra: UnknownFields,
}

impl FeedCursors {
    /// `owner`'s cursors in `feed-cursors.json`, or none when the file or
    /// the owner's entry is not there.
    pub(crate) fn read(dirs: &Dirs, owner: Pubky) -> anyhow::Result<Self> {
        read_entry(dirs, owner)
    }

    /// Writes these as `owner`'s cursors, leaving every other owner's as
    /// the file has them.
    pub(crate) fn write(&self, dirs: &Dirs, owner: Pubky) -> anyhow::Result<()> {
        write_entry(dirs, owner, self)
    }

    /// Removes `owner`'s cursors from the file, leaving every other
    /// owner's. With no entry for `owner` the file is not written, nor
    /// created.
    pub(crate) fn drop_owner(dirs: &Dirs, owner: Pubky) -> anyhow::Result<()> {
        let mut file = read_file::<Self>(dirs)?;
        // `BTreeMap::remove` hands back the removed entry, if there was
        // one; only whether there was is needed.
        if file.owners.remove(&owner).is_none() {
            return Ok(());
        }
        write_file(dirs, &file)
    }

    /// The cursor kept for `homeserver`, if any.
    pub(crate) fn get(&self, homeserver: &Pubky) -> Option<EventCursor> {
        // `copied` turns the `Option<&EventCursor>` the map lends into an
        // `Option<EventCursor>`: the cursor is `Copy`, a plain `u64`.
        self.cursors.get(homeserver).copied()
    }

    /// Sets `homeserver`'s cursor to `cursor`, replacing the one it had.
    pub(crate) fn set(&mut self, homeserver: Pubky, cursor: EventCursor) {
        self.cursors.insert(homeserver, cursor);
    }

    /// Moves `owner`'s cursor for `homeserver` in the file from `from` on to
    /// `to`, as `pull` does once a batch of that feed is processed, and says
    /// whether it did: only while the file still holds `from` there, the
    /// cursor this run started the batch from. Checking that `to` is past
    /// `from` is the caller's (`pull::feed`).
    ///
    /// The caller holds the pull lock, as every writer of the file does,
    /// `post --open` included when it lowers a cursor for a new bounty, so
    /// nothing else writes the file between the batch's read of `from` and
    /// this write: the pull lock is what makes the compare and the write one
    /// step. The compare stays as a second line of defence: a cursor moved
    /// by an earlier batch of the same run, written out of order, is left as
    /// the file has it.
    pub(crate) fn advance(
        dirs: &Dirs,
        owner: Pubky,
        homeserver: Pubky,
        from: EventCursor,
        to: EventCursor,
    ) -> anyhow::Result<bool> {
        let mut stored = Self::read(dirs, owner)?;
        if stored.get(&homeserver) != Some(from) {
            return Ok(false);
        }
        stored.set(homeserver, to);
        stored.write(dirs, owner)?;
        Ok(true)
    }

    /// Lowers `homeserver`'s cursor to `cursor`: keeps the cursor there when
    /// it is at or below `cursor`, and stores `cursor` otherwise, or when
    /// there is none. For a bounty whose starting cursor is behind the one
    /// kept, so that the feed is read again from where that bounty began.
    pub(crate) fn lower_to(&mut self, homeserver: Pubky, cursor: EventCursor) {
        // The entry API looks the key up once: `and_modify` changes the
        // value in place when the key is there, `or_insert` adds one when
        // it is not. `*kept` reaches through the `&mut` to the cursor
        // itself, and `min` keeps the smaller of the two event ids.
        self.cursors
            .entry(homeserver)
            .and_modify(|kept| *kept = (*kept).min(cursor))
            .or_insert(cursor);
    }

    /// Lowers each cursor kept here to the one `cursors` gives its
    /// homeserver, when that one is lower, and says whether any was. A
    /// homeserver with no cursor here gets none: unlike [`lower_to`], this
    /// only ever moves a cursor back. The feed watcher lowers this install's
    /// cursors with it to those of an open bounty's `discovered.json`
    /// (`pull::feed`).
    ///
    /// [`lower_to`]: Self::lower_to
    pub(crate) fn lower_kept_to(&mut self, cursors: &BTreeMap<Pubky, EventCursor>) -> bool {
        let mut lowered = false;
        for (homeserver, &cursor) in cursors {
            // `get_mut` lends the kept cursor itself, so `*kept = …` changes
            // it in place. The `if let … && …` (a let chain) runs the block
            // only when one is kept and the new one is lower.
            if let Some(kept) = self.cursors.get_mut(homeserver)
                && cursor < *kept
            {
                *kept = cursor;
                lowered = true;
            }
        }
        lowered
    }
}

/// One owner's roster poll state: the module docs' `poll-state.json`
/// entry.
///
/// The fields are `pub(crate)` because the state is plain data that `pull`
/// reads and changes as it goes; only `extra`, which must come back as it
/// was read, is private.
///
/// Public values only, and an [`ETag`]'s `Debug` gives its length alone,
/// so deriving `Debug` prints nothing secret and no server's text.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(crate) struct PollState {
    /// Per roster member, where the next newest-first listing of each of
    /// their directories stops.
    pub(crate) watermarks: BTreeMap<Pubky, Watermarks>,
    /// Every bounty read, by its record's URL.
    pub(crate) bounties: BTreeMap<BountyRef, BountySummary>,
    /// Every sweep read, by its record's URL.
    pub(crate) sweeps: BTreeMap<SweepRef, SweepSummary>,
    /// The tag of each of the owner's own `bounties/<id>.discovered.json`,
    /// by the bounty's id, so it is read again only when it changed.
    pub(crate) discovered_etags: BTreeMap<RecordId, ETag>,
    /// The strangers' sweeps accepted for each of the owner's bounties, by
    /// the bounty's id: what `discovered.json` lists, or is to list.
    pub(crate) accepted_sweeps: BTreeMap<RecordId, BTreeSet<SweepRef>>,
    /// The sweeps whose deletion was confirmed against the sweeper's own
    /// storage, not taken from the feed's word (a `DEL` event is as
    /// unverified as a `PUT`).
    pub(crate) deleted_sweeps: BTreeSet<SweepRef>,
    /// Fields a newer Sweepky wrote in this owner's entry, kept for the
    /// rewrite.
    #[serde(flatten)]
    extra: UnknownFields,
}

impl PollState {
    /// `owner`'s poll state in `poll-state.json`, or an empty one when the
    /// file or the owner's entry is not there.
    pub(crate) fn read(dirs: &Dirs, owner: Pubky) -> anyhow::Result<Self> {
        read_entry(dirs, owner)
    }

    /// Writes this as `owner`'s poll state, leaving every other owner's as
    /// the file has it.
    pub(crate) fn write(&self, dirs: &Dirs, owner: Pubky) -> anyhow::Result<()> {
        write_entry(dirs, owner, self)
    }
}

#[cfg(test)]
impl PollState {
    /// Writes this as `owner`'s poll state, then pads the file with a field
    /// at the top, as a newer Sweepky could have written one, until it is
    /// `room` bytes short of its cap: a file this state still fits, and a
    /// little more does not. For the tests of the callers that must cope
    /// with a full file.
    pub(crate) fn write_with_room(&self, dirs: &Dirs, owner: Pubky, room: usize) {
        self.write(dirs, owner).expect("written");
        let path = dirs.poll_state_file();
        let written = std::fs::read(&path).expect("readable");
        let mut file: serde_json::Value = serde_json::from_slice(&written).expect("JSON");
        // In compact JSON the field adds `"filler":"",` to its own bytes.
        let filler = MAX_POLL_STATE_BYTES - room - written.len() - r#""filler":"","#.len();
        file["filler"] = serde_json::Value::String("x".repeat(filler));
        let mut bytes = serde_json::to_vec(&file).expect("JSON");
        bytes.push(b'\n');
        assert_eq!(bytes.len(), MAX_POLL_STATE_BYTES - room);
        write_private_file(&path, &bytes).expect("written");
    }
}

/// Where the roster poll stands in one member's storage: the newest record
/// id seen in each of their directories with record ids, `bounties/` and
/// `sweeps/` (`keys/` files are named by device id, which no listing stops
/// at), and the last of their done bounties, open bounties and running
/// sweeps read again. Each `None` until there is one.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct Watermarks {
    /// The newest id seen in `bounties/`.
    pub(crate) bounties: Option<RecordId>,
    /// The newest id seen in `sweeps/`.
    pub(crate) sweeps: Option<RecordId>,
    /// The id of the member's done bounty read again last: the next run's
    /// turn through their done bounties starts after it (`pull::roster`).
    // Left out of the file while `None`, so a file written before this
    // field is written back as it was.
    #[serde(rename = "rereadDoneAfter", skip_serializing_if = "Option::is_none")]
    pub(crate) reread_done_after: Option<RecordId>,
    /// The id of the member's open bounty read again last: when they have
    /// more than a run reads again, the next run's turn through them starts
    /// after it (`pull::roster`). Left out while `None`, as above.
    #[serde(rename = "rereadOpenAfter", skip_serializing_if = "Option::is_none")]
    pub(crate) reread_open_after: Option<RecordId>,
    /// The same for the member's `running` sweeps of the owner's bounties.
    #[serde(rename = "rereadRunningAfter", skip_serializing_if = "Option::is_none")]
    pub(crate) reread_running_after: Option<RecordId>,
    /// Fields a newer Sweepky wrote here, kept for the rewrite.
    #[serde(flatten)]
    extra: UnknownFields,
}

/// What `pull` keeps of a bounty record between runs: whether it can still
/// change and so is worth reading again (`status`), whether it takes
/// strangers' sweeps (`open`), whom it credits, for the trust labels, and
/// the tag to send back.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct BountySummary {
    /// The record's `status`, an open string, as written.
    pub(crate) status: BountyStatus,
    /// The record's `open`.
    pub(crate) open: bool,
    /// The record's `credits`, as written: [`sweepky_core::trust_labels`]
    /// applies its own filters.
    pub(crate) credits: Vec<Pubky>,
    /// The tag the record's last answer gave, if a usable one.
    pub(crate) etag: Option<ETag>,
    /// Fields a newer Sweepky wrote here, kept for the rewrite.
    #[serde(flatten)]
    extra: UnknownFields,
}

impl BountySummary {
    /// The summary of `bounty`, whose answer gave `etag`.
    pub(crate) fn new(bounty: &Bounty, etag: Option<ETag>) -> Self {
        // `&Bounty`: the record is only borrowed, so `clone` and `to_vec`
        // copy out what the summary owns.
        Self {
            status: bounty.status().clone(),
            open: bounty.open,
            credits: bounty.credits().to_vec(),
            etag,
            extra: UnknownFields::new(),
        }
    }

    /// Brings this summary up to date with `bounty`, read again with the
    /// new tag `etag`, keeping the fields a newer Sweepky wrote here.
    pub(crate) fn update(&mut self, bounty: &Bounty, etag: Option<ETag>) {
        // `..Self::new(..)` fills in every field not named before it, so a
        // field added to the summary later is filled in here too.
        // `mem::take` moves the map out and leaves an empty one in its
        // place, so nothing is copied.
        *self = Self {
            extra: std::mem::take(&mut self.extra),
            ..Self::new(bounty, etag)
        };
    }
}

/// What `pull` keeps of a sweep record between runs: what it sweeps
/// (`bounty`, `targets`), whether it can still change (`status`), the tag
/// to send back, and whether its package has been pulled, or refused for
/// good.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct SweepSummary {
    /// The bounty the record names.
    pub(crate) bounty: BountyRef,
    /// The record's `targets`.
    pub(crate) targets: Vec<TargetId>,
    /// The record's `status`, an open string, as written.
    pub(crate) status: SweepStatus,
    /// The tag the record's last answer gave, if a usable one.
    pub(crate) etag: Option<ETag>,
    /// Whether its package has been decrypted into the data directory.
    pub(crate) pulled: bool,
    /// Whether `pull` read its package and refused it for a reason a later
    /// run would meet again, such as a package not encrypted to this
    /// install's key (`pull::open`), so it is not read again.
    // `default`: a file written before this field reads as `false`.
    // `skip_serializing_if` leaves it out while `false`, so such a file is
    // written back as it was. `Not::not` is `!` as a function, which serde
    // calls with `&self.refused`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) refused: bool,
    /// Fields a newer Sweepky wrote here, kept for the rewrite.
    #[serde(flatten)]
    extra: UnknownFields,
}

impl SweepSummary {
    /// The summary of `sweep`, whose answer gave `etag`, not pulled yet.
    pub(crate) fn new(sweep: &Sweep, etag: Option<ETag>) -> Self {
        Self {
            bounty: sweep.bounty,
            targets: sweep.targets.clone(),
            status: sweep.status.clone(),
            etag,
            pulled: false,
            refused: false,
            extra: UnknownFields::new(),
        }
    }

    /// Brings this summary up to date with `sweep`, read again with the new
    /// tag `etag`, keeping whether its package was pulled or refused and
    /// the fields a newer Sweepky wrote here.
    pub(crate) fn update(&mut self, sweep: &Sweep, etag: Option<ETag>) {
        *self = Self {
            pulled: self.pulled,
            refused: self.refused,
            extra: std::mem::take(&mut self.extra),
            ..Self::new(sweep, etag)
        };
    }
}

/// What both files share: `{schemaVersion, owners: {<owner z32>: <E>}}`,
/// with `E` the type of one owner's entry.
///
/// Generic, so that the reading, the cap and the rewrite are written once
/// for the two files. serde's derive adds the bounds itself: the
/// `Serialize` it writes needs `E: Serialize`, the `Deserialize` needs `E`
/// to be `Deserialize` too.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OwnerFile<E> {
    /// The format's version, 1.
    schema_version: SchemaVersion,
    /// Each owner's entry. `Pubky` is a JSON object key here: written as
    /// the raw z-base32 string, read from either spelling.
    owners: BTreeMap<Pubky, E>,
    /// Fields a newer Sweepky wrote at the top, kept for the rewrite.
    #[serde(flatten)]
    extra: UnknownFields,
}

/// One owner's entry of one of the two files, which ties each entry type
/// to its file and that file's cap, so neither can be read as the other.
///
/// The supertraits (after the `:`) are what every function below needs of
/// an entry: `Clone` to put a copy in the file, `Default` for an owner with
/// no entry yet, and serde's two traits. `DeserializeOwned` is
/// `Deserialize` for any input lifetime: the entry owns its strings rather
/// than borrowing from the file's bytes, which are wiped after the read.
trait OwnerEntry: Clone + Default + Serialize + DeserializeOwned {
    /// The most bytes of the file read, or written.
    const MAX_BYTES: usize;

    /// The file's path.
    fn path(dirs: &Dirs) -> PathBuf;
}

impl OwnerEntry for FeedCursors {
    const MAX_BYTES: usize = MAX_FEED_CURSORS_BYTES;

    fn path(dirs: &Dirs) -> PathBuf {
        dirs.feed_cursors_file()
    }
}

impl OwnerEntry for PollState {
    const MAX_BYTES: usize = MAX_POLL_STATE_BYTES;

    fn path(dirs: &Dirs) -> PathBuf {
        dirs.poll_state_file()
    }
}

/// A write refused because the file would pass its cap, which leaves the
/// file as it was. A type of its own, not a message alone, so that a caller
/// that can go on without the write tells it apart from a file that could
/// not be written at all: `pull::feed` then drops what it added and reads
/// no more (`downcast_ref::<WouldPassCap>()`).
///
/// A path and a number, so deriving `Debug` prints nothing secret.
#[derive(Debug)]
pub(crate) struct WouldPassCap {
    /// The file not written.
    path: PathBuf,
    /// Its cap, in bytes.
    cap: usize,
}

impl fmt::Display for WouldPassCap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} would grow past the {} bytes Sweepky reads from it, so it was not written",
            self.path.display(),
            self.cap
        )
    }
}

// An empty impl: `Error`'s methods all have defaults. Implementing it (with
// `Display` and `Debug` above) is what lets an `anyhow::Error` hold one.
impl std::error::Error for WouldPassCap {}

/// Reads `E`'s file whole, or an empty one when there is no file.
///
/// Through `private_fs`: a link, anything but a regular file, a file
/// another user could read and one over `E::MAX_BYTES` are refused before
/// a byte is read.
fn read_file<E: OwnerEntry>(dirs: &Dirs) -> anyhow::Result<OwnerFile<E>> {
    let path = E::path(dirs);
    let Some(bytes) = read_private_file(&path, E::MAX_BYTES)? else {
        return Ok(OwnerFile {
            schema_version: SchemaVersion::CURRENT,
            owners: BTreeMap::new(),
            extra: UnknownFields::new(),
        });
    };
    // `RecordError::from` keeps only the kind of fault and where it is, so
    // the message quotes nothing of the file.
    serde_json::from_slice(&bytes)
        .map_err(RecordError::from)
        .with_context(|| format!("{} is not valid", path.display()))
}

/// Writes `file` as `E`'s file: compact JSON and a newline, 0600 in the
/// 0700 data directory, made if it is missing. Refused, with the file left
/// as it was, when it would pass `E::MAX_BYTES`: [`WouldPassCap`].
fn write_file<E: OwnerEntry>(dirs: &Dirs, file: &OwnerFile<E>) -> anyhow::Result<()> {
    let path = E::path(dirs);
    let mut bytes =
        serde_json::to_vec(file).with_context(|| format!("could not write {}", path.display()))?;
    bytes.push(b'\n');
    if bytes.len() > E::MAX_BYTES {
        // `into` wraps the typed error in an `anyhow::Error`, which keeps it
        // for a caller's `downcast_ref`.
        return Err(WouldPassCap {
            path,
            cap: E::MAX_BYTES,
        }
        .into());
    }
    ensure_private_dir(dirs.data())?;
    write_private_file(&path, &bytes)
}

/// `owner`'s entry in `E`'s file, or an empty one.
fn read_entry<E: OwnerEntry>(dirs: &Dirs, owner: Pubky) -> anyhow::Result<E> {
    // `remove` moves the entry out of the map, which is dropped anyway, so
    // nothing is copied.
    Ok(read_file::<E>(dirs)?
        .owners
        .remove(&owner)
        .unwrap_or_default())
}

/// Replaces `owner`'s entry in `E`'s file with `entry`: reads the file
/// again, so every other owner's entry and the top-level fields stay as
/// the file has them now, and writes it back.
fn write_entry<E: OwnerEntry>(dirs: &Dirs, owner: Pubky, entry: &E) -> anyhow::Result<()> {
    let mut file = read_file::<E>(dirs)?;
    // The map owns its entries, so it takes a copy; the caller keeps
    // `entry` to go on with.
    file.owners.insert(owner, entry.clone());
    write_file(dirs, &file)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use serde_json::{Value, json};
    use sweepky_core::{Bounty, BountyRef, EventCursor, Pubky, Sweep, SweepRef};
    use tokio::sync::oneshot;
    use tokio::time::sleep;

    use super::{
        BountySummary, FeedCursors, OwnerEntry, PollState, SweepSummary, WouldPassCap, read_entry,
        write_entry,
    };
    use crate::Dirs;
    use crate::lock::PullLock;
    use crate::private_fs::{ensure_private_dir, write_private_file};
    use crate::remote::ETag;
    use crate::test_support::{
        FileSnapshot, PLANTED, bounty_json, chmod, dirs_in, json_bytes, mode, private_temp,
        random_pubky, record_id, repo_target_json, sweep_json,
    };

    /// The cursor at event `id`.
    fn cursor(id: u64) -> EventCursor {
        EventCursor::new(id)
    }

    /// An entity tag, as a homeserver's `ETag` header could give it.
    fn tag(text: &str) -> ETag {
        ETag::parse(text.as_bytes()).expect("a usable tag")
    }

    /// The file at `path` as JSON.
    fn raw(path: &Path) -> Value {
        serde_json::from_slice(&fs::read(path).expect("readable")).expect("JSON")
    }

    /// Writes `bytes` at `path` as a hand or a newer build could have, 0600
    /// in the 0700 data directory, which the reader requires.
    fn write_by_hand(dirs: &Dirs, path: &Path, bytes: &[u8]) {
        ensure_private_dir(dirs.data()).expect("data dir");
        write_private_file(path, bytes).expect("write");
    }

    /// The error text of reading `owner`'s entry of `E`'s file, which must
    /// be refused. Generic, so one test runs for both files: `E` picks the
    /// file, its cap and the type its entries are read as.
    fn read_error<E: OwnerEntry>(dirs: &Dirs, owner: Pubky) -> String {
        // `let ... else` rather than `expect_err`, which would need `E:
        // Debug` to print an entry read by mistake.
        let Err(error) = read_entry::<E>(dirs, owner) else {
            panic!("{} was read, not refused", E::path(dirs).display());
        };
        format!("{error:#}")
    }

    /// Checks that `E`'s file is refused, in fixed text that quotes none of
    /// it, when it is over its cap, malformed, loose or a link.
    fn refuses_bad_files<E: OwnerEntry>(dirs: &Dirs, planted_file: &Path) {
        let (path, owner) = (E::path(dirs), random_pubky());

        // Over the cap: refused before it is read.
        write_by_hand(dirs, &path, &vec![b' '; E::MAX_BYTES + 1]);
        let shown = read_error::<E>(dirs, owner);
        assert!(shown.contains("larger than"), "{shown}");

        // Not JSON, or JSON of the wrong shape: refused in fixed text.
        for damaged in [
            PLANTED.as_bytes().to_vec(),
            json_bytes(&json!({ "schemaVersion": 1, "owners": PLANTED })),
            json_bytes(&json!({ "schemaVersion": 1, "owners": { PLANTED: {} } })),
        ] {
            write_by_hand(dirs, &path, &damaged);
            let shown = read_error::<E>(dirs, owner);
            assert!(shown.contains("is not valid"), "{shown}");
            assert!(!shown.contains(PLANTED), "{shown}");
        }

        // Loose, with any group or other bit: refused, with the chmod that
        // fixes it, as every private file.
        let empty = json!({ "schemaVersion": 1, "owners": {} });
        write_by_hand(dirs, &path, &json_bytes(&empty));
        for loose in [0o640, 0o604, 0o620] {
            chmod(&path, loose);
            let shown = read_error::<E>(dirs, owner);
            assert!(shown.contains("chmod 600"), "{shown}");
        }

        // A link, even to a private file: refused, never followed.
        fs::remove_file(&path).expect("remove");
        symlink(planted_file, &path).expect("symlink");
        let shown = read_error::<E>(dirs, owner);
        assert!(shown.contains("symbolic link"), "{shown}");
        assert!(!shown.contains(PLANTED), "{shown}");
    }

    /// Checks that writing `entry` into `E`'s file, already near its cap,
    /// is refused and leaves the file as it was.
    fn refuses_a_write_past_the_cap<E: OwnerEntry>(dirs: &Dirs, entry: &E) {
        let path = E::path(dirs);
        let near_cap = json!({
            "schemaVersion": 1,
            "owners": {},
            "filler": "x".repeat(E::MAX_BYTES - 200),
        });
        write_by_hand(dirs, &path, &json_bytes(&near_cap));
        let before = FileSnapshot::of(&path);

        let err = write_entry(dirs, random_pubky(), entry).expect_err("past the cap");
        // A type of its own, so a caller that can go on without the write
        // tells it apart from a file that could not be written at all.
        assert!(err.downcast_ref::<WouldPassCap>().is_some(), "{err:#}");
        let shown = format!("{err:#}");
        assert!(shown.contains(&E::MAX_BYTES.to_string()), "{shown}");
        assert_eq!(FileSnapshot::of(&path), before);
    }

    #[test]
    fn feed_cursors_round_trip_per_owner_and_homeserver_0600_in_a_0700_data_dir() {
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        let (owner, other) = (random_pubky(), random_pubky());
        let (home, watched) = (random_pubky(), random_pubky());
        // No file yet: no cursor, and reading makes no file.
        let none = FeedCursors::read(&dirs, owner).expect("reads");
        assert_eq!(none.get(&home), None);
        assert_eq!(FileSnapshot::of(&dirs.feed_cursors_file()), None);

        let mut mine = FeedCursors::default();
        mine.set(home, cursor(41));
        mine.set(watched, cursor(7));
        mine.write(&dirs, owner).expect("written");
        let mut theirs = FeedCursors::default();
        theirs.set(home, cursor(3));
        theirs.write(&dirs, other).expect("written");

        let path = dirs.feed_cursors_file();
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(dirs.data()), 0o700);
        // Owners and homeservers keyed by their raw z-base32 key, each
        // cursor the event id as a string, as `discovered.json` holds one.
        assert_eq!(
            raw(&path),
            json!({
                "schemaVersion": 1,
                "owners": {
                    owner.to_string(): {
                        "cursors": { home.to_string(): "41", watched.to_string(): "7" },
                    },
                    other.to_string(): { "cursors": { home.to_string(): "3" } },
                },
            })
        );

        // A fresh reader, as the next run is, reads back what was written:
        // the unit form of the cursor surviving a restart.
        assert_eq!(FeedCursors::read(&dirs, owner).expect("reads"), mine);
        let read = FeedCursors::read(&dirs, other).expect("reads");
        assert_eq!(read.get(&home), Some(cursor(3)));
        assert_eq!(read.get(&watched), None);

        // Keys compare by their bytes: a file that spells the owner and the
        // homeserver `pubky<z32>`, as the SDK prints a key, reads the same.
        let spelled = json!({
            "schemaVersion": 1,
            "owners": { format!("pubky{owner}"): { "cursors": { format!("pubky{home}"): "41" } } },
        });
        write_by_hand(&dirs, &path, &json_bytes(&spelled));
        let read = FeedCursors::read(&dirs, owner).expect("reads");
        assert_eq!(read.get(&home), Some(cursor(41)));
    }

    #[test]
    fn lower_to_keeps_the_lower_cursor() {
        let (home, watched) = (random_pubky(), random_pubky());
        let mut cursors = FeedCursors::default();
        // None yet: the new one is stored.
        cursors.lower_to(home, cursor(50));
        assert_eq!(cursors.get(&home), Some(cursor(50)));
        // The kept one is higher: the new one is stored.
        cursors.lower_to(home, cursor(20));
        assert_eq!(cursors.get(&home), Some(cursor(20)));
        // The kept one is lower: it stays.
        cursors.lower_to(home, cursor(90));
        assert_eq!(cursors.get(&home), Some(cursor(20)));
        // `set`, after a batch, stores what it is given; another homeserver
        // is untouched either way.
        cursors.set(home, cursor(90));
        cursors.lower_to(watched, cursor(5));
        assert_eq!(cursors.get(&home), Some(cursor(90)));
        assert_eq!(cursors.get(&watched), Some(cursor(5)));
    }

    #[test]
    fn lower_kept_to_lowers_only_the_cursors_kept_and_says_whether_it_did() {
        let (home, watched, unwatched) = (random_pubky(), random_pubky(), random_pubky());
        let mut cursors = FeedCursors::default();
        cursors.set(home, cursor(100));
        cursors.set(watched, cursor(40));
        let given = BTreeMap::from([
            // Lower: lowered.
            (home, cursor(30)),
            // Higher: kept.
            (watched, cursor(90)),
            // No cursor kept for it: none added.
            (unwatched, cursor(1)),
        ]);
        assert!(cursors.lower_kept_to(&given));
        assert_eq!(cursors.get(&home), Some(cursor(30)));
        assert_eq!(cursors.get(&watched), Some(cursor(40)));
        assert_eq!(cursors.get(&unwatched), None);
        // Nothing lower left: nothing changes, and it says so.
        let before = cursors.clone();
        assert!(!cursors.lower_kept_to(&given));
        assert_eq!(cursors, before);
    }

    // Every writer of feed-cursors.json holds the pull lock (module docs), so
    // a `post --open` that lowers a cursor while a `pull` runs cannot come
    // between the pull's read of a batch's cursor and its `advance`: it waits
    // for the pull to let go, then lowers the cursor the pull left, and the
    // lowered one is what the file keeps. Come in between, the lowering would
    // be written over with the batch's cursor, and the new bounty's events
    // before it skipped for good. Two opens of the lock in one process
    // exclude each other as two processes do, and all three futures run in
    // this one task (`tokio::join!`).
    #[tokio::test]
    async fn a_lowering_while_a_pull_runs_waits_for_its_advance_and_survives_it() {
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        let (owner, home) = (random_pubky(), random_pubky());
        let mut start = FeedCursors::default();
        start.set(home, cursor(5));
        start.write(&dirs, owner).expect("written");
        let mut pull = PullLock::open(&dirs).expect("opened");
        let mut post = PullLock::open(&dirs).expect("opened");
        let (read, has_read) = oneshot::channel::<()>();
        let (finish, may_finish) = oneshot::channel::<()>();
        let waited = AtomicBool::new(false);

        let pulling = pull.hold(
            || {},
            async || {
                // The batch's cursor, read as `pull::feed` reads it before
                // it asks for the page.
                let from = FeedCursors::read(&dirs, owner)?.get(&home);
                read.send(()).expect("the lowering listens");
                may_finish.await.expect("the test lets the batch finish");
                let moved =
                    FeedCursors::advance(&dirs, owner, home, from.expect("stored"), cursor(100))?;
                assert!(moved, "the cursor moved while the pull held the lock");
                Ok(())
            },
        );
        let lowering = async {
            has_read.await.expect("the pull read its cursor");
            post.hold(
                || waited.store(true, Ordering::SeqCst),
                async || {
                    // As `post --open` stores a new bounty's starting
                    // cursor, 3, behind the one kept.
                    let mut stored = FeedCursors::read(&dirs, owner)?;
                    stored.lower_to(home, cursor(3));
                    stored.write(&dirs, owner)
                },
            )
            .await
        };
        let watching = async {
            sleep(Duration::from_millis(300)).await;
            assert!(waited.load(Ordering::SeqCst), "the lowering did not wait");
            let stored = FeedCursors::read(&dirs, owner).expect("reads");
            assert_eq!(stored.get(&home), Some(cursor(5)), "lowered meanwhile");
            finish.send(()).expect("the pull waits");
        };
        let (pulled, lowered, ()) = tokio::join!(pulling, lowering, watching);
        pulled.expect("advanced");
        lowered.expect("lowered");

        let stored = FeedCursors::read(&dirs, owner).expect("reads");
        assert_eq!(stored.get(&home), Some(cursor(3)));
    }

    #[test]
    fn advance_moves_a_stored_cursor_only_from_the_one_the_caller_read() {
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        let path = dirs.feed_cursors_file();
        let (owner, other, home) = (random_pubky(), random_pubky(), random_pubky());
        // No cursor stored: nothing to move on from, and no file is made.
        let moved = FeedCursors::advance(&dirs, owner, home, cursor(5), cursor(9));
        assert!(!moved.expect("reads"));
        assert_eq!(FileSnapshot::of(&path), None);

        let mut mine = FeedCursors::default();
        mine.set(home, cursor(5));
        mine.write(&dirs, owner).expect("written");
        let mut theirs = FeedCursors::default();
        theirs.set(home, cursor(3));
        theirs.write(&dirs, other).expect("written");

        // From the cursor stored: moved, and another owner's is untouched.
        let moved = FeedCursors::advance(&dirs, owner, home, cursor(5), cursor(9));
        assert!(moved.expect("written"));
        let read = FeedCursors::read(&dirs, owner).expect("reads");
        assert_eq!(read.get(&home), Some(cursor(9)));
        assert_eq!(FeedCursors::read(&dirs, other).expect("reads"), theirs);

        // From one the file no longer holds, as when another writer moved
        // it meanwhile: left as the file has it.
        let before = FileSnapshot::of(&path);
        let moved = FeedCursors::advance(&dirs, owner, home, cursor(5), cursor(12));
        assert!(!moved.expect("reads"));
        assert_eq!(FileSnapshot::of(&path), before);
    }

    #[test]
    fn drop_owner_removes_one_owner_s_cursors_and_no_other() {
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        let path = dirs.feed_cursors_file();
        let (owner, other, home) = (random_pubky(), random_pubky(), random_pubky());
        // Dropping an owner with no cursors writes nothing, not even a new
        // file.
        FeedCursors::drop_owner(&dirs, owner).expect("nothing to drop");
        assert_eq!(FileSnapshot::of(&path), None);

        let mut mine = FeedCursors::default();
        mine.set(home, cursor(9));
        mine.write(&dirs, owner).expect("written");
        let mut theirs = FeedCursors::default();
        theirs.set(home, cursor(3));
        theirs.write(&dirs, other).expect("written");
        let before = raw(&path)["owners"][other.to_string()].clone();

        FeedCursors::drop_owner(&dirs, owner).expect("dropped");
        let file = raw(&path);
        assert_eq!(file["owners"].get(owner.to_string()), None);
        assert_eq!(file["owners"][other.to_string()], before);
        assert_eq!(
            FeedCursors::read(&dirs, owner).expect("reads"),
            FeedCursors::default()
        );
        assert_eq!(FeedCursors::read(&dirs, other).expect("reads"), theirs);
    }

    #[test]
    fn unknown_fields_survive_a_rewrite() {
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        let (owner, other, home) = (random_pubky(), random_pubky(), random_pubky());

        // The feed cursors: at the top, in this owner's entry and in
        // another owner's.
        let file = json!({
            "schemaVersion": 1,
            "owners": {
                owner.to_string(): { "cursors": { home.to_string(): "5" }, "seenAt": "kept" },
                other.to_string(): { "cursors": {}, "note": 1 },
            },
            "addedLater": "kept",
        });
        write_by_hand(&dirs, &dirs.feed_cursors_file(), &json_bytes(&file));
        let mut mine = FeedCursors::read(&dirs, owner).expect("reads");
        mine.set(home, cursor(6));
        mine.write(&dirs, owner).expect("written");
        let file = raw(&dirs.feed_cursors_file());
        assert_eq!(file["addedLater"], "kept");
        assert_eq!(
            file["owners"][owner.to_string()],
            json!({ "cursors": { home.to_string(): "6" }, "seenAt": "kept" })
        );
        assert_eq!(
            file["owners"][other.to_string()],
            json!({ "cursors": {}, "note": 1 })
        );

        // The poll state: at the top, in the owner's entry, and in each
        // watermark and summary.
        let member = random_pubky();
        let bounty = BountyRef {
            owner: member,
            id: record_id(10),
        };
        let sweep = SweepRef {
            sweeper: random_pubky(),
            id: record_id(12),
        };
        let entry = json!({
            "watermarks": {
                member.to_string(): {
                    "bounties": record_id(10).to_string(),
                    "sweeps": null,
                    "keysToo": "kept",
                },
            },
            "bounties": {
                bounty.to_string(): {
                    "status": "open", "open": true, "credits": [], "etag": null, "seen": "kept",
                },
            },
            "sweeps": {
                sweep.to_string(): {
                    "bounty": bounty.to_string(),
                    "targets": ["t1"],
                    "status": "running",
                    "etag": "\"s-1\"",
                    "pulled": false,
                    "progress": "kept",
                },
            },
            "discoveredEtags": {},
            "acceptedSweeps": {},
            "deletedSweeps": [],
            "laterList": [1],
        });
        let file = json!({
            "schemaVersion": 1,
            "owners": { owner.to_string(): entry },
            "addedLater": "kept",
        });
        write_by_hand(&dirs, &dirs.poll_state_file(), &json_bytes(&file));
        let mut state = PollState::read(&dirs, owner).expect("reads");
        state.sweeps.get_mut(&sweep).expect("summarised").pulled = true;
        state.write(&dirs, owner).expect("written");

        let mut expected = file;
        expected["owners"][owner.to_string()]["sweeps"][sweep.to_string()]["pulled"] = json!(true);
        assert_eq!(raw(&dirs.poll_state_file()), expected);
    }

    #[test]
    fn an_update_takes_the_record_s_fields_and_keeps_pulled_refused_and_unknown_fields() {
        let bounty = BountyRef {
            owner: random_pubky(),
            id: record_id(10),
        };
        let sweeper = random_pubky();
        // Summaries as a newer Sweepky could have written them.
        let mut bounty_summary: BountySummary = serde_json::from_value(json!({
            "status": "open", "open": true, "credits": [], "etag": "\"b-1\"", "seen": "kept",
        }))
        .expect("a summary");
        let mut sweep_summary: SweepSummary = serde_json::from_value(json!({
            "bounty": bounty.to_string(), "targets": ["t1"], "status": "running",
            "etag": "\"s-1\"", "pulled": false, "refused": true, "progress": "kept",
        }))
        .expect("a summary");

        let mut done = bounty_json(json!([repo_target_json("t1")]));
        done["status"] = json!("done");
        done["credits"] = json!([sweeper.to_string()]);
        let done = Bounty::from_json(&json_bytes(&done)).expect("a bounty");
        bounty_summary.update(&done, Some(tag("\"b-2\"")));
        assert_eq!(
            serde_json::to_value(&bounty_summary).expect("JSON"),
            json!({
                "status": "done", "open": false, "credits": [sweeper.to_string()],
                "etag": "\"b-2\"", "seen": "kept",
            })
        );

        let finished = sweep_json(bounty, &["t1", "t2"], "done");
        let finished = Sweep::from_json(&json_bytes(&finished)).expect("a sweep");
        sweep_summary.update(&finished, None);
        assert_eq!(
            serde_json::to_value(&sweep_summary).expect("JSON"),
            json!({
                "bounty": bounty.to_string(), "targets": ["t1", "t2"], "status": "done",
                "etag": null, "pulled": false, "refused": true, "progress": "kept",
            })
        );
        // A new summary is not refused, and leaves the field out, as a file
        // written before it had none.
        let fresh = serde_json::to_value(SweepSummary::new(&finished, None)).expect("JSON");
        assert_eq!(fresh.get("refused"), None);
        assert_eq!(fresh["pulled"], json!(false));
    }

    #[test]
    fn an_oversized_linked_loose_or_malformed_file_is_refused_without_quoting_it() {
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        let planted_file = temp.path().join("planted.json");
        write_private_file(&planted_file, PLANTED.as_bytes()).expect("write");
        refuses_bad_files::<FeedCursors>(&dirs, &planted_file);
        refuses_bad_files::<PollState>(&dirs, &planted_file);

        // A tag in the poll state that is not one Sweepky would send back
        // makes the file damaged, and is not quoted either.
        let owner = random_pubky();
        let sweep = SweepRef {
            sweeper: random_pubky(),
            id: record_id(12),
        };
        let bounty = BountyRef {
            owner,
            id: record_id(10),
        };
        let bad_tag = json!({
            "schemaVersion": 1,
            "owners": { owner.to_string(): { "sweeps": { sweep.to_string(): {
                "bounty": bounty.to_string(),
                "targets": [],
                "status": "running",
                "etag": format!("\"{PLANTED} with spaces\""),
                "pulled": false,
            } } } },
        });
        fs::remove_file(dirs.poll_state_file()).expect("remove the link");
        write_by_hand(&dirs, &dirs.poll_state_file(), &json_bytes(&bad_tag));
        let shown = read_error::<PollState>(&dirs, owner);
        assert!(shown.contains("is not valid"), "{shown}");
        assert!(!shown.contains(PLANTED), "{shown}");
    }

    #[test]
    fn a_write_past_the_cap_is_refused_and_leaves_the_file_as_it_was() {
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        let mut cursors = FeedCursors::default();
        let mut state = PollState::default();
        for n in 0..8 {
            cursors.set(random_pubky(), cursor(n));
            state.deleted_sweeps.insert(SweepRef {
                sweeper: random_pubky(),
                id: record_id(n),
            });
        }
        refuses_a_write_past_the_cap(&dirs, &cursors);
        refuses_a_write_past_the_cap(&dirs, &state);
    }

    #[test]
    fn the_poll_state_round_trips_and_one_owner_s_entry_is_replaced_alone() {
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        let (owner, other) = (random_pubky(), random_pubky());
        let (member, sweeper) = (random_pubky(), random_pubky());
        let bounty = BountyRef {
            owner: member,
            id: record_id(10),
        };
        let own_bounty = record_id(11);
        let sweep = SweepRef {
            sweeper,
            id: record_id(12),
        };
        let deleted = SweepRef {
            sweeper,
            id: record_id(13),
        };
        let mut done = bounty_json(json!([repo_target_json("t1")]));
        done["status"] = json!("done");
        done["open"] = json!(true);
        done["credits"] = json!([sweeper.to_string()]);
        done["doneAt"] = json!("2026-10-19T10:00:00Z");
        let record = Bounty::from_json(&json_bytes(&done)).expect("a bounty");
        let swept = sweep_json(bounty, &["t1"], "running");
        let swept = Sweep::from_json(&json_bytes(&swept)).expect("a sweep");

        let mut state = PollState::default();
        let marks = state.watermarks.entry(member).or_default();
        marks.bounties = Some(record_id(10));
        marks.sweeps = Some(record_id(12));
        marks.reread_done_after = Some(record_id(10));
        marks.reread_open_after = Some(record_id(8));
        marks.reread_running_after = Some(record_id(12));
        state
            .bounties
            .insert(bounty, BountySummary::new(&record, Some(tag("\"b-1\""))));
        let mut summary = SweepSummary::new(&swept, Some(tag("\"s-1\"")));
        assert!(!summary.pulled, "a new summary is not pulled yet");
        summary.pulled = true;
        state.sweeps.insert(sweep, summary);
        state.discovered_etags.insert(own_bounty, tag("\"d-1\""));
        state
            .accepted_sweeps
            .entry(own_bounty)
            .or_default()
            .insert(sweep);
        state.deleted_sweeps.insert(deleted);
        state.write(&dirs, owner).expect("written");

        let path = dirs.poll_state_file();
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(dirs.data()), 0o700);
        assert_eq!(
            raw(&path),
            json!({
                "schemaVersion": 1,
                "owners": { owner.to_string(): {
                    "watermarks": { member.to_string(): {
                        "bounties": record_id(10).to_string(),
                        "sweeps": record_id(12).to_string(),
                        "rereadDoneAfter": record_id(10).to_string(),
                        "rereadOpenAfter": record_id(8).to_string(),
                        "rereadRunningAfter": record_id(12).to_string(),
                    } },
                    "bounties": { bounty.to_string(): {
                        "status": "done",
                        "open": true,
                        "credits": [sweeper.to_string()],
                        "etag": "\"b-1\"",
                    } },
                    "sweeps": { sweep.to_string(): {
                        "bounty": bounty.to_string(),
                        "targets": ["t1"],
                        "status": "running",
                        "etag": "\"s-1\"",
                        "pulled": true,
                    } },
                    "discoveredEtags": { own_bounty.to_string(): "\"d-1\"" },
                    "acceptedSweeps": { own_bounty.to_string(): [sweep.to_string()] },
                    "deletedSweeps": [deleted.to_string()],
                } },
            })
        );
        // A fresh reader reads back what was written.
        assert_eq!(PollState::read(&dirs, owner).expect("reads"), state);

        // Another owner's entry, then this owner's replaced: the other one
        // is as it was.
        let mut theirs = PollState::default();
        theirs.deleted_sweeps.insert(sweep);
        theirs.write(&dirs, other).expect("written");
        let before = raw(&path)["owners"][other.to_string()].clone();
        PollState::default().write(&dirs, owner).expect("replaced");
        assert_eq!(
            PollState::read(&dirs, owner).expect("reads"),
            PollState::default()
        );
        assert_eq!(raw(&path)["owners"][other.to_string()], before);
        assert_eq!(PollState::read(&dirs, other).expect("reads"), theirs);
    }
}
