//! `pull`'s one public write: `bounties/<id>.discovered.json` of each of
//! the owner's bounties open to strangers (`open: true`, status `open`),
//! the strangers' sweeps the owner found and where the feeds stand (01,
//! "Records" and "Open bounties"). The board reads this file and never a
//! feed; a second install of the owner learns from it what the first
//! found.
//!
//! [`publish_discovered`] runs after the feed watcher (`pull::feed`), from
//! the poll state it brought up to date and what it found this run.
//!
//! **What a file becomes.** The file as it is, with three changes, and
//! everything else kept, its unknown fields and its version included:
//!
//! - every sweep this install accepted for the bounty and the file does
//!   not list is appended, oldest first (a sweep id is its record's
//!   creation time). Every one, not only this run's, so a sweep whose write
//!   was refused before is listed by the next write;
//! - every sweep whose deletion this run confirmed, by a 404 at its
//!   sweeper's own storage (`pull::feed`), is dropped. A sweep the feed
//!   said was deleted but whose record still answers stays listed;
//! - this install's current cursor of each feed the run read, from the
//!   local `feed-cursors.json`, replaces the file's cursor for that
//!   homeserver. The file's cursor for any other homeserver, one whose
//!   head this run could not find or another install of the owner watches,
//!   is kept.
//!
//! **Written only when its sweeps change, or when there is none.** A file
//! whose sweeps the changes leave as they are is not written, however far
//! the cursors moved: this write is itself an event on the owner's
//! homeserver, after the cursor `pull` just stored, so a rule that also
//! wrote for a cursor would write on every run, and on production every
//! `pull` would make a public write under the lock. The file's cursors may
//! therefore lag behind the local ones. That is safe: the local file is
//! what this install reads on from, and an install with no local cursor
//! starts from the file's lower one and reads some events twice, which
//! accepts nothing twice. An open bounty with no file, as after a
//! `discovered.json` PUT `post --open` saw refused, gets one, with a
//! warning.
//!
//! **In this order.** For each open bounty, the file is read with no
//! session through `PublicRecords`, and the changes made to it in memory.
//! Those due a write are checked against [`MAX_RECORD_BYTES`]: one past
//! it is not written, with an alarm, and every other file is. A sweep's
//! URL takes about 100 bytes, so that is some 10,000 sweeps of one bounty,
//! which only a flood of strangers' sweeps reaches. Only then, and only
//! when a file is due, are the writers' lock taken and a fresh session
//! opened, once for every file ([`WriteUnderLock`]): with `login.json`
//! seen to name the owner still, each file is read back through the
//! session, the changes made again to what it holds now, its size checked
//! again, and it is PUT unless its sweeps are already as they would be.
//! The session is signed out and the lock let go whatever happened. So
//! the lock covers the sign-in, the read-back, the PUT and the sign-out
//! alone, no local file is read or written under it, and a file another
//! install wrote meanwhile loses nothing it lists but what this run
//! confirmed gone.
//!
//! **Two installs of one owner.** The sweeps are a union, as 01 has it for
//! the bounty, less this run's confirmed deletions; the cursors are last
//! writer wins, homeserver by homeserver. A deletion only drops a sweep in
//! the run that confirmed it, never later: an install that missed the
//! `DEL` (its read of that sweeper failed at the time) still has the sweep
//! as accepted and lists it again, and if the other install dropped it on
//! every write, the two would rewrite the file on every `pull`, each
//! undoing the other.
//!
//! **Public values only.** The file holds sweep URLs and cursors, the
//! typed fields can hold nothing else, and its unknown fields are the
//! owner's own file's. Every warning and alarm is fixed text with paths,
//! keys and numbers; a refused write is `write_error`'s fixed text and the
//! status, never the server's words. Only a failure of the local files is
//! an error; every other fault is a warning, so `pull` carries on.
//!
//! **Known limits.** A deletion whose write was refused, or that another
//! install lists again, stays listed: this install does not confirm it
//! again. An install that has not seen it confirms it gone when it reads
//! the file, and drops it; the board finds its record gone meanwhile. A
//! file past the cap raises its alarm on every run, and grows no more
//! while the bounty is open. A file that cannot be read, or does not
//! parse, is not rewritten: it may be a newer Sweepky's.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use anyhow::{Context as _, bail};
use sweepky_core::paths;
use sweepky_core::{
    Discovered, EventCursor, MAX_RECORD_BYTES, Pubky, RecordId, SchemaVersion, SweepRef,
    UnknownFields, Zeroizing,
};

use super::feed::{FeedWatch, open_to_strangers};
use super::state::{FeedCursors, PollState};
use crate::own_storage::{OwnStorage, SessionStorage};
use crate::records::{PublicRecords, not_a_record};
use crate::remote::write_error;
use crate::session::with_writer_session;
use crate::{Context, Dirs};

/// What `pull` says when `login.json`, read again under the lock, names
/// another pubky than the owner `pull` read for: the files are that
/// owner's, so nothing is written for another.
const LOGIN_CHANGED: &str = "this install's login changed while pull ran, so it wrote no \
                             discovered.json; run pull again";

/// What [`publish_discovered`] did, for the rest of `pull`.
///
/// Ids and fixed text only, so deriving `Debug` prints no one's text.
#[derive(Debug, Default)]
pub(crate) struct Published {
    /// The open bounties whose `discovered.json` was written, by id, in the
    /// order written.
    pub(crate) written: Vec<RecordId>,
    /// One line for each fault skipped, in fixed text that names paths,
    /// keys and numbers, never a file's or a server's words.
    pub(crate) warnings: Vec<String>,
    /// One line, starting `alarm: `, for each file not written because it
    /// would pass `MAX_RECORD_BYTES`.
    pub(crate) alarms: Vec<String>,
}

impl Published {
    /// Adds a warning.
    // `fmt::Arguments` is what `format_args!` builds: the pieces of a
    // message, borrowed, written into the one `String` kept here.
    fn warn(&mut self, warning: fmt::Arguments<'_>) {
        self.warnings.push(warning.to_string());
    }

    /// Adds the alarm for the file at `path`, not written because it would
    /// be `len` bytes, past [`MAX_RECORD_BYTES`].
    fn too_long(&mut self, path: &str, len: usize) {
        self.alarms.push(format!(
            "alarm: {path} would be {len} bytes, more than the {MAX_RECORD_BYTES} a record may \
             have, so pull did not write it: so many sweeps of one bounty may be a flood of \
             strangers' sweeps. What this install accepted and pulled is kept here."
        ));
    }
}

/// What a run's write changes in the open bounties' files (the module
/// docs' three changes), worked out before the lock and made again, under
/// it, to each file read back.
///
/// Public values only, so deriving `Debug` prints nothing secret.
#[derive(Debug)]
pub(crate) struct Changes {
    /// The owner whose files these are.
    owner: Pubky,
    /// For each of the owner's bounties open to strangers, the strangers'
    /// sweeps this install accepted for it, oldest first. Its keys are the
    /// bounties whose file is looked at.
    accepted: BTreeMap<RecordId, Vec<SweepRef>>,
    /// The sweeps whose deletion this run confirmed.
    deleted: BTreeSet<SweepRef>,
    /// This install's current cursor of each feed the run read.
    cursors: BTreeMap<Pubky, EventCursor>,
}

impl Changes {
    /// The changes for `owner`'s open bounties in `state`, from what the
    /// watch found this run (`found`) and the local `feed-cursors.json` in
    /// `dirs`.
    fn of(dirs: &Dirs, owner: Pubky, state: &PollState, found: &FeedWatch) -> anyhow::Result<Self> {
        let accepted = open_to_strangers(state, owner)
            .into_iter()
            .map(|bounty| (bounty, accepted_in_upload_order(state, bounty)))
            .collect();
        let local = FeedCursors::read(dirs, owner)?;
        // Inside a closure that gives an `Option`, `?` on an `Option` gives
        // `None` at once, which `filter_map` leaves out: a homeserver whose
        // cursor is no longer in the file (another writer dropped it).
        let cursors = found
            .starts
            .keys()
            .filter_map(|&homeserver| Some((homeserver, local.get(&homeserver)?)))
            .collect();
        Ok(Self {
            owner,
            accepted,
            deleted: found.deleted.iter().map(|gone| gone.sweep).collect(),
            cursors,
        })
    }

    /// Bounty `id`'s file with these changes made, from `current`, the file
    /// as read (`None` when there is none), or `None` when there is one and
    /// its sweeps would stay as they are.
    ///
    /// `current` by value: the file read is changed in place and handed
    /// back, so a long list of sweeps is never copied.
    fn apply(&self, id: RecordId, current: Option<Discovered>) -> Option<Discovered> {
        let missing = current.is_none();
        let mut next = current.unwrap_or_else(|| Discovered {
            schema_version: SchemaVersion::CURRENT,
            sweeps: Vec::new(),
            cursors: BTreeMap::new(),
            extra: UnknownFields::new(),
        });
        let listed = next.sweeps.len();
        next.sweeps.retain(|sweep| !self.deleted.contains(sweep));
        let kept = next.sweeps.len();
        // A set of what is listed, so each sweep accepted is looked up in
        // it rather than in the whole list: a flood of strangers' sweeps
        // makes the list long. Appended after the deletions, so a sweep
        // deleted and written again within one run is listed.
        let known: BTreeSet<SweepRef> = next.sweeps.iter().copied().collect();
        // As in `of`: nothing for a bounty not in the map. `extend` copies
        // each `&SweepRef` it is given into the list.
        let accepted = self.accepted.get(&id).into_iter().flatten();
        next.sweeps
            .extend(accepted.filter(|sweep| !known.contains(sweep)));
        // Nothing dropped and nothing added: a cursor alone is no reason to
        // write (see the module docs).
        let unchanged = kept == listed && next.sweeps.len() == kept;
        if !missing && unchanged {
            return None;
        }
        // `extend` with the pairs a `&BTreeMap` lends copies each key and
        // value in, replacing the cursor a homeserver had.
        next.cursors.extend(&self.cursors);
        Some(next)
    }

    /// What bounty `id`'s file comes to, from `current` as read (`None`
    /// when there is none): [`apply`](Self::apply)'s result as the bytes to
    /// PUT, checked against the cap.
    fn to_write(&self, id: RecordId, current: Option<Discovered>) -> anyhow::Result<ToWrite> {
        let Some(next) = self.apply(id, current) else {
            return Ok(ToWrite::Unchanged);
        };
        let bytes = serde_json::to_vec(&next)
            .with_context(|| format!("could not write {}", paths::discovered(id)))?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Ok(ToWrite::TooLong(bytes.len()));
        }
        Ok(ToWrite::Bytes(bytes))
    }
}

/// What one file comes to once the changes are made to it as read.
enum ToWrite {
    /// Its sweeps would stay as they are: nothing to write.
    Unchanged,
    /// The bytes to PUT: compact JSON within [`MAX_RECORD_BYTES`]. Public
    /// values only, so a plain `Vec`, not a wiped buffer.
    Bytes(Vec<u8>),
    /// It would be this many bytes, past [`MAX_RECORD_BYTES`], which core's
    /// `from_json` would refuse for the board and every install alike: not
    /// written.
    TooLong(usize),
}

/// The strangers' sweeps the poll state says this install accepted for
/// `bounty`, in upload order, which is id order: the set orders them by
/// sweeper.
fn accepted_in_upload_order(state: &PollState, bounty: RecordId) -> Vec<SweepRef> {
    // `into_iter().flatten()` on the `Option` the map lends yields nothing
    // for a bounty with no sweep accepted, and each sweep of one that has;
    // `copied` copies each out, as a `SweepRef` is `Copy`.
    let mut sweeps: Vec<SweepRef> = state
        .accepted_sweeps
        .get(&bounty)
        .into_iter()
        .flatten()
        .copied()
        .collect();
    sweeps.sort_by_key(|sweep| (sweep.id, sweep.sweeper));
    sweeps
}

/// The writers' lock and a fresh session, around the writes of the files
/// due ([`write_due`]).
///
/// A trait so that the write can be tested without a homeserver, as
/// `submit`'s `FinishSweep` is: the tests implement it with a fake storage
/// that counts the sessions it opens. Its method is an `async fn`, so
/// callers take `&impl WriteUnderLock`.
pub(crate) trait WriteUnderLock {
    /// Writes each of `due`'s files with `changes`, as [`write_due`] does,
    /// under the writers' lock with a fresh session, signed out afterwards
    /// whatever happened.
    async fn write(
        &self,
        due: &[RecordId],
        changes: &Changes,
        published: &mut Published,
    ) -> anyhow::Result<()>;
}

/// The real [`WriteUnderLock`]: `session::with_writer_session`, which
/// takes the lock, signs in afresh, runs the writes, then signs out and lets
/// the lock go, also when they fail.
pub(crate) struct LockedSession<'a> {
    ctx: &'a Context,
    /// The owner `pull` read for, whom the session must be.
    owner: Pubky,
}

impl<'a> LockedSession<'a> {
    /// The lock and a session of `ctx`'s login, which must be `owner`'s.
    pub(crate) fn new(ctx: &'a Context, owner: Pubky) -> Self {
        Self { ctx, owner }
    }
}

impl WriteUnderLock for LockedSession<'_> {
    async fn write(
        &self,
        due: &[RecordId],
        changes: &Changes,
        published: &mut Published,
    ) -> anyhow::Result<()> {
        // `async move` moves the references into the body, `published`'s
        // `&mut` among them. The body only borrows the session, so
        // `with_writer_session` signs it out whatever the body returns.
        with_writer_session(self.ctx, async move |signed| {
            // `login.json` is read again under the lock: a `login` as
            // another identity since would write these files into that
            // identity's storage.
            if signed.login().pubky != self.owner {
                bail!(LOGIN_CHANGED);
            }
            write_due(&SessionStorage::new(signed), due, changes, published).await
        })
        .await
    }
}

/// Writes the `discovered.json` of `owner`'s bounties open to strangers in
/// `state`, with what the watch `found` this run and the local cursors in
/// `dirs`: see the module docs. `records` reads the files with no session;
/// `writer` writes those due under the lock.
///
/// Only a failure of the local files is an error. A file that cannot be
/// read, a failed lock, sign-in or read-back and a refused PUT are warnings
/// in [`Published`], and a file too long an alarm.
pub(crate) async fn publish_discovered(
    records: &impl PublicRecords,
    writer: &impl WriteUnderLock,
    dirs: &Dirs,
    owner: Pubky,
    state: &PollState,
    found: &FeedWatch,
) -> anyhow::Result<Published> {
    let changes = Changes::of(dirs, owner, state, found)?;
    let mut published = Published::default();
    let mut due = Vec::new();
    // `keys` lends each id; `&bounty` copies it out (`RecordId` is `Copy`).
    for &bounty in changes.accepted.keys() {
        if is_due(records, &changes, bounty, &mut published).await? {
            due.push(bounty);
        }
    }
    if due.is_empty() {
        return Ok(published);
    }
    if let Err(error) = writer.write(&due, &changes, &mut published).await {
        published.warn(format_args!(
            "pull could not write the discovered.json of your open bounties this time: {error:#}"
        ));
    }
    Ok(published)
}

/// Whether bounty `bounty`'s file, read now with no session, is due a
/// write that fits a record ([`Changes::to_write`]). A file that is missing
/// is due, with a warning; one that cannot be read or does not parse is
/// not, with a warning, and one too long is not, with an alarm.
async fn is_due(
    records: &impl PublicRecords,
    changes: &Changes,
    bounty: RecordId,
    published: &mut Published,
) -> anyhow::Result<bool> {
    let path = paths::discovered(bounty);
    let owner = changes.owner;
    let read = records
        .get_record(owner, &path)
        .await
        .and_then(|found| parse(found, &path, owner));
    let current = match read {
        Ok(current) => current,
        Err(error) => {
            published.warn(format_args!(
                "pull did not update {path} this time, as it could not read it: {error:#}"
            ));
            return Ok(false);
        }
    };
    let missing = current.is_none();
    match changes.to_write(bounty, current)? {
        ToWrite::Unchanged => Ok(false),
        ToWrite::TooLong(len) => {
            published.too_long(&path, len);
            Ok(false)
        }
        ToWrite::Bytes(_) => {
            if missing {
                published.warn(format_args!(
                    "{path} of {owner} was missing, so pull writes it from this install's feed \
                     cursors and the strangers' sweeps it accepted"
                ));
            }
            Ok(true)
        }
    }
}

/// Under the lock, through `storage`, the session's own: reads each of
/// `due`'s files back, makes `changes` to what it holds now, and PUTs it
/// unless its sweeps are already as they would be or it would pass the
/// cap. The first read or PUT that fails ends the writes with its error.
async fn write_due(
    storage: &impl OwnStorage,
    due: &[RecordId],
    changes: &Changes,
    published: &mut Published,
) -> anyhow::Result<()> {
    for &bounty in due {
        let path = paths::discovered(bounty);
        let current = parse(storage.get_own(&path).await?, &path, changes.owner)?;
        let bytes = match changes.to_write(bounty, current)? {
            ToWrite::Bytes(bytes) => bytes,
            ToWrite::Unchanged => continue,
            ToWrite::TooLong(len) => {
                published.too_long(&path, len);
                continue;
            }
        };
        // A refusal is mapped by `write_error`: 403 and 507 to their
        // messages, anything else to fixed text and the status. The SDK's
        // error itself holds the server's text, so it is never printed.
        storage
            .put(&path, bytes)
            .await
            .map_err(|error| write_error(&error).context(format!("could not write {path}")))?;
        published.written.push(bounty);
    }
    Ok(())
}

/// A [`WriteUnderLock`] in place of the writers' lock and a session, for
/// this module's tests and the command's (`pub(super)`: the `pull` module
/// and its other children may use it): it counts the sessions it opened and
/// closed, and writes through its `FakeOwnStorage` what the real one writes
/// through the session's. `cfg(test)`, so it never reaches the binary.
#[cfg(test)]
#[derive(Default)]
pub(super) struct FakeSession {
    pub(super) storage: crate::test_support::FakeOwnStorage,
    // `Cell` lets a method that takes `&self`, as the trait's does, change a
    // `Copy` value; a single-threaded test needs no `Mutex`.
    opened: std::cell::Cell<usize>,
    closed: std::cell::Cell<usize>,
}

#[cfg(test)]
impl FakeSession {
    /// The sessions opened and closed so far.
    pub(super) fn sessions(&self) -> (usize, usize) {
        (self.opened.get(), self.closed.get())
    }
}

#[cfg(test)]
impl WriteUnderLock for FakeSession {
    async fn write(
        &self,
        due: &[RecordId],
        changes: &Changes,
        published: &mut Published,
    ) -> anyhow::Result<()> {
        self.opened.set(self.opened.get() + 1);
        let result = write_due(&self.storage, due, changes, published).await;
        self.closed.set(self.closed.get() + 1);
        result
    }
}

/// `found`, the bytes at `path` of `owner`'s storage, as a discovered-sweeps
/// file, or `None` when there is none. Core's `from_json` refuses more than
/// `MAX_RECORD_BYTES` and a newer `schemaVersion` before it parses, and its
/// error quotes nothing of the file.
fn parse(
    found: Option<Zeroizing<Vec<u8>>>,
    path: &str,
    owner: Pubky,
) -> anyhow::Result<Option<Discovered>> {
    // `map` parses only a `Some`; `transpose` turns the
    // `Option<Result<..>>` into the `Result<Option<..>>` returned.
    found
        .map(|bytes| Discovered::from_json(&bytes))
        .transpose()
        .with_context(|| not_a_record("discovered-sweeps", path, owner))
}

#[cfg(test)]
mod tests {
    use std::io;

    use pubky::StatusCode;
    use pubky_testnet::EphemeralTestnet;
    use serde_json::{Map, Value, json};
    use sweepky_core::paths;
    use sweepky_core::{
        Bounty, BountyRef, Discovered, EventCursor, MAX_RECORD_BYTES, Pubky, RecordId, SweepRef,
    };
    use tempfile::TempDir;

    use super::{
        FakeSession, LOGIN_CHANGED, LockedSession, Published, WriteUnderLock, publish_discovered,
    };
    use crate::own_storage::OwnStorage;
    use crate::pull::feed::{BountySweep, FeedWatch, Start, StartSource};
    use crate::pull::state::{BountySummary, FeedCursors, PollState};
    use crate::records::{PublicRecordReader, PublicRecords};
    use crate::remote::QUOTA_FULL;
    use crate::state::read_login_state;
    use crate::test_support::{
        FakePublicRecords, FileSnapshot, PLANTED, bounty_json, dirs_in, json_bytes, private_temp,
        random_pubky, record_id, repo_target_json, test_context,
    };
    use crate::{Dirs, Network};

    /// One run of `pull` for one owner, after its feed watch: the data
    /// directory, the homeserver whose feed the run read, the poll state and
    /// what the watch found.
    struct Run {
        // Held so the directory lives as long as the run; never read.
        _temp: TempDir,
        dirs: Dirs,
        owner: Pubky,
        home: Pubky,
        state: PollState,
        found: FeedWatch,
    }

    impl Run {
        /// A run that read `home`'s feed and left this install's cursor
        /// there at `cursor`, with no bounty yet.
        fn new(cursor: u64) -> Self {
            let temp = private_temp();
            let (owner, home) = (random_pubky(), random_pubky());
            Self::in_dirs(temp, owner, home, cursor)
        }

        /// As [`new`](Self::new), for `owner`, in `temp`.
        fn in_dirs(temp: TempDir, owner: Pubky, home: Pubky, cursor: u64) -> Self {
            let dirs = dirs_in(&temp);
            let mut cursors = FeedCursors::default();
            cursors.set(home, EventCursor::new(cursor));
            cursors.write(&dirs, owner).expect("written");
            let mut found = FeedWatch::default();
            // Where the feed was read from: below where it stands now.
            let start = Start {
                cursor: EventCursor::new(0),
                source: StartSource::Local,
            };
            found.starts.insert(home, start);
            Self {
                _temp: temp,
                dirs,
                owner,
                home,
                state: PollState::default(),
                found,
            }
        }

        /// Adds the owner's bounty `n` to the poll state, `open` to
        /// strangers or not, with `status`, and gives its id.
        fn with_bounty(&mut self, n: u64, open: bool, status: &str) -> RecordId {
            let mut record = bounty_json(json!([repo_target_json("t1")]));
            record["open"] = json!(open);
            record["status"] = json!(status);
            if status == "done" {
                record["doneAt"] = json!("2026-10-19T10:00:00Z");
            }
            let bounty = Bounty::from_json(&json_bytes(&record)).expect("a bounty");
            let id = record_id(n);
            let owner = self.owner;
            self.state
                .bounties
                .insert(BountyRef { owner, id }, BountySummary::new(&bounty, None));
            id
        }

        /// Records `sweep` as accepted for bounty `id`, as the watcher
        /// does: in this run when `now`, else in an earlier one.
        fn accept(&mut self, id: RecordId, sweep: SweepRef, now: bool) {
            self.state
                .accepted_sweeps
                .entry(id)
                .or_default()
                .insert(sweep);
            if now {
                self.found.accepted.push(BountySweep { bounty: id, sweep });
            }
        }

        /// Records that this run confirmed `sweep` of bounty `id` gone, as
        /// the watcher does once its sweeper's storage answers 404.
        fn delete(&mut self, id: RecordId, sweep: SweepRef) {
            if let Some(accepted) = self.state.accepted_sweeps.get_mut(&id) {
                accepted.remove(&sweep);
            }
            self.state.deleted_sweeps.insert(sweep);
            self.found.deleted.push(BountySweep { bounty: id, sweep });
        }

        /// The write, as `pull` makes it after the watch.
        async fn publish(
            &self,
            records: &impl PublicRecords,
            writer: &impl WriteUnderLock,
        ) -> Published {
            publish_discovered(
                records,
                writer,
                &self.dirs,
                self.owner,
                &self.state,
                &self.found,
            )
            .await
            .expect("the local files read")
        }
    }

    /// Sweep `n` of a new stranger.
    fn stranger_sweep(n: u64) -> SweepRef {
        SweepRef {
            sweeper: random_pubky(),
            id: record_id(n),
        }
    }

    /// A `discovered.json` listing `sweeps`, with `cursors`.
    fn discovered_json(sweeps: &[SweepRef], cursors: &[(Pubky, u64)]) -> Value {
        let cursors: Map<String, Value> = cursors
            .iter()
            .map(|(homeserver, cursor)| (homeserver.to_string(), json!(cursor.to_string())))
            .collect();
        let sweeps: Vec<String> = sweeps.iter().map(ToString::to_string).collect();
        json!({ "schemaVersion": 1, "sweeps": sweeps, "cursors": cursors })
    }

    /// The owner's public storage and a session's both holding `file` as
    /// bounty `id`'s `discovered.json`: what `pull` reads before the lock
    /// and reads back under it.
    fn holding(owner: Pubky, id: RecordId, file: &Value) -> (FakePublicRecords, FakeSession) {
        let path = paths::discovered(id);
        let records = FakePublicRecords::default().with_record(owner, &path, file);
        let session = FakeSession::default();
        session.storage.insert(&path, json_bytes(file));
        (records, session)
    }

    /// Bounty `id`'s file as `session` wrote it, after checking that core
    /// reads it back.
    async fn written(session: &FakeSession, id: RecordId) -> Value {
        let bytes = session
            .storage
            .get_own(&paths::discovered(id))
            .await
            .expect("reads")
            .expect("written");
        Discovered::from_json(&bytes).expect("core reads it");
        serde_json::from_slice(&bytes).expect("JSON")
    }

    #[tokio::test]
    async fn a_moved_cursor_alone_takes_no_lock_opens_no_session_and_puts_nothing() {
        // The file lists every sweep accepted; only the cursor moved on,
        // from 100 to 500.
        let mut run = Run::new(500);
        let id = run.with_bounty(10, true, "open");
        let listed = stranger_sweep(20);
        run.accept(id, listed, false);
        let file = discovered_json(&[listed], &[(run.home, 100)]);
        let (records, session) = holding(run.owner, id, &file);

        let published = run.publish(&records, &session).await;

        assert_eq!(session.sessions(), (0, 0), "no lock and no session");
        assert!(session.storage.puts().is_empty());
        assert!(published.written.is_empty());
        assert!(published.warnings.is_empty(), "{:?}", published.warnings);
        assert!(published.alarms.is_empty(), "{:?}", published.alarms);
    }

    #[tokio::test]
    async fn a_stranger_s_sweep_accepted_now_is_appended_in_one_put_with_the_local_cursors() {
        // The unit form of 06's "appended to `discovered.json`".
        let mut run = Run::new(300);
        let id = run.with_bounty(10, true, "open");
        let (listed, found) = (stranger_sweep(20), stranger_sweep(30));
        run.accept(id, listed, false);
        run.accept(id, found, true);
        let mut file = discovered_json(&[listed], &[(run.home, 100)]);
        file["newerField"] = json!({ "kept": [1, 2] });
        let (records, session) = holding(run.owner, id, &file);

        let published = run.publish(&records, &session).await;

        assert_eq!(session.storage.puts(), [paths::discovered(id)]);
        assert_eq!(session.sessions(), (1, 1));
        assert_eq!(published.written, [id]);
        let mut expected = discovered_json(&[listed, found], &[(run.home, 300)]);
        expected["newerField"] = json!({ "kept": [1, 2] });
        assert_eq!(written(&session, id).await, expected);
    }

    #[tokio::test]
    async fn a_del_not_confirmed_leaves_the_sweep_listed_and_puts_nothing() {
        // The feed's `DEL` came, but the sweeper's storage still answers for
        // the record, so the watcher confirmed nothing: nothing changed.
        let mut run = Run::new(300);
        let id = run.with_bounty(10, true, "open");
        let [said_gone, kept] = [20, 30].map(stranger_sweep);
        run.accept(id, said_gone, false);
        run.accept(id, kept, false);
        let file = discovered_json(&[said_gone, kept], &[(run.home, 100)]);
        let (records, session) = holding(run.owner, id, &file);

        let published = run.publish(&records, &session).await;

        assert_eq!(session.sessions(), (0, 0));
        assert!(session.storage.puts().is_empty());
        assert!(published.written.is_empty());
    }

    #[tokio::test]
    async fn a_del_confirmed_by_a_404_drops_the_sweep_in_one_put() {
        let mut run = Run::new(300);
        let id = run.with_bounty(10, true, "open");
        let [gone, kept] = [20, 30].map(stranger_sweep);
        run.accept(id, gone, false);
        run.accept(id, kept, false);
        run.delete(id, gone);
        let file = discovered_json(&[gone, kept], &[(run.home, 100)]);
        let (records, session) = holding(run.owner, id, &file);

        let published = run.publish(&records, &session).await;

        assert_eq!(session.storage.puts(), [paths::discovered(id)]);
        assert_eq!(published.written, [id]);
        assert_eq!(
            written(&session, id).await,
            discovered_json(&[kept], &[(run.home, 300)])
        );
    }

    #[tokio::test]
    async fn a_deletion_confirmed_in_an_earlier_run_drops_nothing_now() {
        // An earlier run confirmed `gone` deleted, and another install that
        // missed its `DEL` has listed it again since: this run's watch
        // confirmed nothing, so the file stays as it is.
        let mut run = Run::new(300);
        let id = run.with_bounty(10, true, "open");
        let [gone, kept] = [20, 30].map(stranger_sweep);
        run.accept(id, kept, false);
        run.state.deleted_sweeps.insert(gone);
        let file = discovered_json(&[gone, kept], &[(run.home, 100)]);
        let (records, session) = holding(run.owner, id, &file);

        let published = run.publish(&records, &session).await;

        assert_eq!(session.sessions(), (0, 0));
        assert!(session.storage.puts().is_empty());
        assert!(published.written.is_empty());
    }

    #[tokio::test]
    async fn the_file_read_back_under_the_lock_keeps_another_install_s_sweeps_and_not_the_deleted()
    {
        let mut run = Run::new(300);
        let id = run.with_bounty(10, true, "open");
        let [listed, found, gone, theirs] = [20, 30, 40, 50].map(stranger_sweep);
        let elsewhere = random_pubky();
        run.accept(id, listed, false);
        run.accept(id, found, true);
        run.accept(id, gone, false);
        run.delete(id, gone);
        let path = paths::discovered(id);
        // Read before the lock...
        let before = discovered_json(&[listed], &[(run.home, 100)]);
        let records = FakePublicRecords::default().with_record(run.owner, &path, &before);
        // ...and back under it, once another install of the owner wrote it:
        // a sweep this one does not know, the deleted one listed again, and
        // that install's cursors, one on a homeserver this run did not read.
        let session = FakeSession::default();
        let theirs_now =
            discovered_json(&[listed, gone, theirs], &[(run.home, 900), (elsewhere, 7)]);
        session.storage.insert(&path, json_bytes(&theirs_now));

        let published = run.publish(&records, &session).await;

        assert_eq!(published.written, [id]);
        // Theirs kept, the deleted one dropped, this install's appended; this
        // install's cursor wins where it has one, and theirs stays where it
        // has none.
        assert_eq!(
            written(&session, id).await,
            discovered_json(&[listed, theirs, found], &[(run.home, 300), (elsewhere, 7)])
        );
    }

    #[tokio::test]
    async fn a_result_over_the_record_cap_is_refused_before_the_lock_with_an_alarm() {
        let mut run = Run::new(300);
        let id = run.with_bounty(10, true, "open");
        let found = stranger_sweep(20);
        run.accept(id, found, true);
        // A file whose unknown field, kept on the rewrite, leaves the
        // result `over` bytes past the cap. JSON's length does not depend on
        // the order of an object's keys, so the result's is measured with an
        // empty `pad`.
        let mut result = discovered_json(&[found], &[(run.home, 300)]);
        result["pad"] = json!("");
        let base = serde_json::to_vec(&result).expect("JSON").len();
        let padded = |over: usize| {
            let mut file = discovered_json(&[], &[(run.home, 100)]);
            file["pad"] = json!("x".repeat(MAX_RECORD_BYTES + over - base));
            file
        };
        let local = || {
            (
                FileSnapshot::of(&run.dirs.poll_state_file()),
                FileSnapshot::of(&run.dirs.feed_cursors_file()),
            )
        };
        let before = local();

        let (records, session) = holding(run.owner, id, &padded(1));
        let published = run.publish(&records, &session).await;

        assert_eq!(session.sessions(), (0, 0), "no lock and no session");
        assert!(session.storage.puts().is_empty());
        assert!(published.written.is_empty());
        let [alarm] = published.alarms.as_slice() else {
            panic!("one alarm: {:?}", published.alarms);
        };
        assert!(alarm.starts_with("alarm: "), "{alarm}");
        assert!(alarm.contains(&paths::discovered(id)), "{alarm}");
        assert!(!alarm.contains("xxx"), "it quotes the file: {alarm}");
        assert_eq!(local(), before, "the local state is kept");

        // At the cap exactly, the file is written.
        let (records, session) = holding(run.owner, id, &padded(0));
        let published = run.publish(&records, &session).await;
        assert!(published.alarms.is_empty(), "{:?}", published.alarms);
        assert_eq!(published.written, [id]);
        let bytes = session
            .storage
            .get_own(&paths::discovered(id))
            .await
            .expect("reads")
            .expect("written");
        assert_eq!(bytes.len(), MAX_RECORD_BYTES);
        Discovered::from_json(&bytes).expect("core reads a file at the cap");
    }

    #[tokio::test]
    async fn an_open_bounty_with_no_discovered_json_gets_one_and_a_closed_or_done_one_never() {
        let mut run = Run::new(400);
        let first = run.with_bounty(10, true, "open");
        let second = run.with_bounty(11, true, "open");
        let closed = run.with_bounty(12, false, "open");
        let done = run.with_bounty(13, true, "done");
        let found = stranger_sweep(20);
        run.accept(first, found, false);
        run.accept(closed, stranger_sweep(21), false);
        run.accept(done, stranger_sweep(22), false);
        let records = FakePublicRecords::default();
        let session = FakeSession::default();

        let published = run.publish(&records, &session).await;

        // Both open ones, in one session, from the cursors pull starts from
        // next; neither of the others is read or written.
        let (first_path, second_path) = (paths::discovered(first), paths::discovered(second));
        assert_eq!(
            session.storage.puts(),
            [first_path.as_str(), second_path.as_str()]
        );
        assert_eq!(session.sessions(), (1, 1));
        assert_eq!(published.written, [first, second]);
        assert_eq!(
            written(&session, first).await,
            discovered_json(&[found], &[(run.home, 400)])
        );
        assert_eq!(
            written(&session, second).await,
            discovered_json(&[], &[(run.home, 400)])
        );
        let asked: Vec<String> = records.asked().into_iter().map(|(_, path)| path).collect();
        assert_eq!(asked, [first_path.as_str(), second_path.as_str()]);
        // One warning for each, naming its file.
        let [one, two] = published.warnings.as_slice() else {
            panic!("two warnings: {:?}", published.warnings);
        };
        assert!(one.contains(&first_path), "{one}");
        assert!(two.contains(&second_path), "{two}");
    }

    #[tokio::test]
    async fn a_refused_put_is_write_error_s_fixed_text_and_the_session_is_closed() {
        let mut run = Run::new(300);
        let id = run.with_bounty(10, true, "open");
        run.accept(id, stranger_sweep(20), true);
        let path = paths::discovered(id);
        let (records, session) = holding(run.owner, id, &discovered_json(&[], &[(run.home, 1)]));
        session
            .storage
            .refuse(&path, StatusCode::INSUFFICIENT_STORAGE, PLANTED);

        let published = run.publish(&records, &session).await;

        assert_eq!(session.storage.puts(), [path.as_str()]);
        assert_eq!(session.sessions(), (1, 1), "closed on the error too");
        assert!(published.written.is_empty());
        let [warning] = published.warnings.as_slice() else {
            panic!("one warning: {:?}", published.warnings);
        };
        assert!(warning.contains(QUOTA_FULL), "{warning}");
        assert!(warning.contains(&path), "{warning}");
        assert!(!warning.contains(PLANTED), "{warning}");
    }

    #[tokio::test]
    async fn a_sweep_a_refused_write_left_out_is_listed_by_the_next_write() {
        let mut run = Run::new(300);
        let id = run.with_bounty(10, true, "open");
        let found = stranger_sweep(20);
        run.accept(id, found, true);
        let path = paths::discovered(id);
        let (records, session) = holding(run.owner, id, &discovered_json(&[], &[(run.home, 1)]));
        session
            .storage
            .refuse(&path, StatusCode::INSUFFICIENT_STORAGE, PLANTED);
        let published = run.publish(&records, &session).await;
        assert!(published.written.is_empty());

        // The next run accepts nothing new: the sweep is in the poll state's
        // `acceptedSweeps` alone.
        run.found.accepted.clear();
        session.storage.stop_failing();
        let published = run.publish(&records, &session).await;

        assert_eq!(published.written, [id]);
        assert_eq!(
            written(&session, id).await,
            discovered_json(&[found], &[(run.home, 300)])
        );
    }

    #[tokio::test]
    async fn the_first_failed_put_ends_the_run_s_writes() {
        let mut run = Run::new(300);
        let first = run.with_bounty(10, true, "open");
        let second = run.with_bounty(11, true, "open");
        run.accept(first, stranger_sweep(20), true);
        run.accept(second, stranger_sweep(21), true);
        let file = discovered_json(&[], &[(run.home, 1)]);
        let (first_path, second_path) = (paths::discovered(first), paths::discovered(second));
        let records = FakePublicRecords::default()
            .with_record(run.owner, &first_path, &file)
            .with_record(run.owner, &second_path, &file);
        let session = FakeSession::default();
        session.storage.insert(&first_path, json_bytes(&file));
        session.storage.insert(&second_path, json_bytes(&file));
        session.storage.fail_transport(&first_path);

        let published = run.publish(&records, &session).await;

        assert_eq!(session.storage.puts(), [first_path.as_str()]);
        assert_eq!(session.sessions(), (1, 1), "closed on the error too");
        assert!(published.written.is_empty());
        let [warning] = published.warnings.as_slice() else {
            panic!("one warning: {:?}", published.warnings);
        };
        assert!(warning.contains(&first_path), "{warning}");
    }

    #[tokio::test]
    async fn a_file_this_build_cannot_read_is_not_rewritten_and_not_quoted() {
        let mut run = Run::new(300);
        let id = run.with_bounty(10, true, "open");
        run.accept(id, stranger_sweep(20), true);
        // A newer Sweepky's file, and one whose list holds no sweep's URL.
        let newer = json!({ "schemaVersion": 2, "sweeps": [PLANTED], "cursors": {} });
        let broken = json!({ "schemaVersion": 1, "sweeps": [PLANTED], "cursors": {} });
        for file in [newer, broken] {
            let (records, session) = holding(run.owner, id, &file);

            let published = run.publish(&records, &session).await;

            assert_eq!(session.sessions(), (0, 0), "no lock and no session");
            assert!(session.storage.puts().is_empty());
            assert!(published.written.is_empty());
            let [warning] = published.warnings.as_slice() else {
                panic!("one warning: {:?}", published.warnings);
            };
            assert!(warning.contains(&paths::discovered(id)), "{warning}");
            assert!(!warning.contains(PLANTED), "{warning}");
        }
    }

    #[tokio::test]
    #[pubky_testnet::test]
    async fn the_real_write_takes_a_fresh_session_of_the_owner_s_login_and_lets_the_lock_go() {
        let testnet = EphemeralTestnet::builder()
            .with_http_relay()
            .build()
            .await
            .expect("testnet starts");
        let temp = private_temp();
        let (ctx, stderr) = test_context(
            Network::injected(
                testnet.sdk().expect("client"),
                format!("{}inbox", testnet.http_relay().local_url()),
                testnet.homeserver_app().public_key(),
            ),
            &temp,
            io::empty(),
        );
        crate::login::login(&ctx, Some("discovered-test"), None, None)
            .await
            .expect("login");
        let login = read_login_state(&ctx.dirs)
            .expect("reads")
            .expect("logged in");
        let mut run = Run::in_dirs(temp, login.pubky, login.homeserver, 300);
        let id = run.with_bounty(10, true, "open");
        let found = stranger_sweep(20);
        run.accept(id, found, true);
        let records = PublicRecordReader::new(ctx.network.pubky());
        let after_login = stderr.text().len();

        // Under the lock, a login that is not the owner pull read writes
        // nothing; its session is signed out and the lock let go all the
        // same, so the next write neither waits nor warns.
        let published = run
            .publish(&records, &LockedSession::new(&ctx, random_pubky()))
            .await;
        assert!(published.written.is_empty());
        assert!(
            published
                .warnings
                .iter()
                .any(|warning| warning.contains(LOGIN_CHANGED)),
            "{:?}",
            published.warnings
        );

        let published = run
            .publish(&records, &LockedSession::new(&ctx, login.pubky))
            .await;
        assert_eq!(published.written, [id]);
        assert_eq!(stderr.text().get(after_login..), Some(""));
        // As anyone reads it.
        let bytes = records
            .get_record(login.pubky, &paths::discovered(id))
            .await
            .expect("reads")
            .expect("written");
        let discovered = Discovered::from_json(&bytes).expect("core reads it");
        assert_eq!(discovered.sweeps, [found]);
        assert_eq!(
            discovered.cursors.get(&login.homeserver),
            Some(&EventCursor::new(300))
        );
    }
}
