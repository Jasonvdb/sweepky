//! `pull`'s roster polling (01, "Circle"): the owner's circle read; each of
//! its keys' `bounties/` and `sweeps/` listed newest first, down to what the
//! poll state has seen; the new records read; the records that can still
//! change read again only if they changed; and the poll state brought up
//! to date.
//!
//! [`poll_roster`] reads public records alone, through `PublicRecords`,
//! with no session and no lock, in this order:
//!
//! 1. **The roster.** The `circle.json` in the owner's own storage, which
//!    counts only when it names the owner as its admin: anyone can put any
//!    file in their own storage, so a roster counts only in its admin's (as
//!    for `run`'s pick). With no circle the roster is the owner alone; one
//!    that names another admin, or that cannot be read, is a warning and the
//!    owner alone too. Both fall on the side of less trust: nobody is
//!    labelled `circle` who should not be, and fewer keys are polled. Of the
//!    roster, the first [`MAX_MEMBERS`] keys are polled, the admin first and
//!    then each member once, by key bytes; the roster [`RosterPoll`] hands
//!    back holds those keys alone, so the later steps of the run agree on
//!    who is in it.
//! 2. **Each key**, once its homeserver resolves ([`Homeservers`], once a
//!    run): a key whose pkarr record names no homeserver, or whose lookup
//!    fails, is skipped with one warning that names it. Then:
//!    - *Again, if changed.* The key's records in the poll state that can
//!      still change (01), each read with the `ETag` its last answer gave
//!      as `If-None-Match`: its open bounties (status `open`) and its
//!      `running` sweeps of the owner's bounties, the newest of each first,
//!      and its done bounties, whose credits the owner may revise, in turn,
//!      at most [`MAX_DONE_REREADS_PER_MEMBER`] a run from the one after
//!      where the last run's turn stopped, going round, so each is read
//!      again within a bounded number of runs. At most
//!      [`MAX_REREADS_PER_MEMBER`] in all, shared by [`reread_shares`] so
//!      that no kind starves another, with a warning when open bounties or
//!      running sweeps are left. A 304 leaves its summary as it was, a 404
//!      drops it, and a new answer updates it, keeping whether its package
//!      was pulled.
//!    - *What is new.* `bounties/`, then `sweeps/`, listed newest first
//!      down to the key's watermark there (`PublicRecords::list_newest_first`;
//!      a 404 is an empty directory, never an unreachable key). The records
//!      listed that the poll state does not hold yet are read oldest first,
//!      at most [`MAX_NEW_BOUNTIES_PER_MEMBER`] and
//!      [`MAX_NEW_SWEEPS_PER_MEMBER`] a run, and the watermark moves up to
//!      each one as it is read. So whatever a cut or a failure leaves
//!      unread stays above the watermark and is listed again next run, and
//!      nothing is read twice: one that was read is at or below it.
//! 3. **What the run found**, from the poll state, so a record unchanged
//!    since an earlier run counts as much as one read now: the owner's own
//!    bounties, the roster's sweeps of them, and every bounty of the roster
//!    as a `CreditedBounty`, each once.
//!
//! **What is kept.** A bounty's summary and a sweep's of one of the owner's
//! bounties. A sweep of another owner's bounty is read once, as it is new,
//! and nothing of it is kept: the watermark that passes it is what remembers
//! it, so no later listing names it and nothing reads it again. Circle
//! members sweep each other's bounties all the time, so keeping those would
//! grow the poll state with every run. A record that parses but would carry
//! more into its summary than Sweepky writes (a status over
//! [`MAX_STATUS_BYTES`], more than [`MAX_CREDITS`] credits, more than
//! `MAX_TARGETS` targets) is skipped like one that does not parse.
//!
//! **Faults skip, they do not stop**, and each is a warning:
//!
//! - A record over the cap, or one that does not parse or carries too
//!   much: skipped, and the watermark passes it. One read again that no
//!   longer parses keeps the summary it had: a newer Sweepky's may parse
//!   once this build is updated.
//! - A read that fails (a listing refused, a status, a network error) ends
//!   that key's poll for the run: its reads all go to one homeserver, which
//!   would likely fail the rest too, each perhaps after a long wait. The key
//!   is looked up again, once, so that the rest of the run uses what its
//!   pkarr record says now. The watermark has not passed what was not read,
//!   so the next run reads it.
//!
//! **Errors and warnings quote no record.** They name a key, a path core
//! built, a count, and `remote`'s and core's fixed text. Nothing here prints
//! a title, a status or a label, so nothing here needs the sanitiser.

use std::iter;

use anyhow::{Context as _, bail};
use sweepky_core::paths::{self, SweepkyPath};
use sweepky_core::{
    Bounty, BountyRef, Circle, CreditedBounty, KnownBountyStatus, KnownSweepStatus, Pubky,
    RecordId, SchemaVersion, Sweep, SweepRef, UnknownFields,
};

use super::resolve::{Homeservers, ResolveHomeserver, Unreachable};
use super::state::{BountySummary, PollState, SweepSummary, Watermarks};
use crate::post::draft::MAX_TARGETS;
use crate::records::{PublicRecords, not_a_record};
use crate::remote::{BodyTooLarge, Conditional, ETag, Listing};

/// The most keys of the roster polled, its admin first: 01's "a circle of
/// under ~30" (05 moves to event streams past that), as for `run`'s pick.
pub(crate) const MAX_MEMBERS: usize = 32;

/// The most new bounty records read of one key in a run: the oldest of
/// those listed, so the rest come next run.
pub(crate) const MAX_NEW_BOUNTIES_PER_MEMBER: usize = 16;

/// The most new sweep records read of one key in a run. Twice the
/// bounties: a sweep takes an hour, a bounty is posted far more rarely.
pub(crate) const MAX_NEW_SWEEPS_PER_MEMBER: usize = 32;

/// The most records of one key read again in a run, if changed, of every
/// kind together: its open bounties, its `running` sweeps and its done
/// bounties, each kind with its share ([`reread_shares`]).
pub(crate) const MAX_REREADS_PER_MEMBER: usize = 32;

/// The most done bounties of one key read again in a run, in turn. A done
/// bounty changes only when its owner revises the credits (01), so a few a
/// run, going round, bring each one up to date within a bounded number of
/// runs however many there are, for a request each that is mostly a 304.
pub(crate) const MAX_DONE_REREADS_PER_MEMBER: usize = 8;

// Checked when the crate compiles: the done bounties' number leaves room in
// the budget for the other two kinds, so `reread_shares` cannot underflow.
const _: () = assert!(MAX_DONE_REREADS_PER_MEMBER < MAX_REREADS_PER_MEMBER);

/// The longest status a summary keeps, in bytes. Every status Sweepky
/// writes is a short word (`running` is the longest, at 7), and one a newer
/// Sweepky adds will be too; a longer one would only fill the poll state.
pub(crate) const MAX_STATUS_BYTES: usize = 32;

/// The most credits, as written, a bounty's summary keeps. `done` credits
/// each sweeper who helped once; 128 is far past any bounty's honest list,
/// and keeps one summary of credits under 8 KiB.
pub(crate) const MAX_CREDITS: usize = 128;

/// What the owner's circle names in place of a roster that is not one.
const ANOTHER_ADMIN: &str = "the circle.json in your storage names another admin, so it is not \
                             your roster: pull reads your own records alone this time";

/// What [`poll_roster`] found, for the rest of `pull`.
///
/// No `Debug`: the roster's name and labels are text whoever wrote the
/// circle chose, and a `{:?}` would print it unsanitised.
pub(crate) struct RosterPoll {
    /// The roster this run: the owner's circle cut to the keys polled, or
    /// the owner alone. Trust labels and the feed read it, so a key cut
    /// from the circle counts as outside it everywhere this run.
    pub(crate) roster: Circle,
    /// Every bounty of the owner's that the poll state holds, oldest first;
    /// its summary is there.
    pub(crate) own_bounties: Vec<BountyRef>,
    /// Every sweep by a key of the roster, of one of those bounties, that
    /// the poll state holds, in key order; its summary is there.
    pub(crate) sweeps: Vec<SweepRef>,
    /// Every bounty of the roster that the poll state holds, each once,
    /// whatever its status, as `sweepky_core::trust_labels` takes them.
    pub(crate) credited: Vec<CreditedBounty>,
    /// One line for each fault skipped, in fixed text that names keys and
    /// paths, never a record's content.
    pub(crate) warnings: Vec<String>,
}

/// Polls the roster of `owner` through `records`, with each key's
/// homeserver from `homeservers`, and brings `state` up to date: see the
/// module docs. Every fault is a warning in the [`RosterPoll`]; none stops
/// the poll. Writing `state` back is the caller's.
pub(crate) async fn poll_roster<R: PublicRecords, H: ResolveHomeserver>(
    records: &R,
    homeservers: &mut Homeservers<'_, H>,
    owner: Pubky,
    state: &mut PollState,
) -> RosterPoll {
    let mut poller = Poller {
        records,
        homeservers,
        owner,
        state,
        warnings: Vec::new(),
    };
    let roster = poller.roster().await;
    // `once` gives the admin alone; `chain` goes on with every member. The
    // keys are copied out, so the roster is not borrowed while they are
    // polled.
    let keys: Vec<Pubky> = iter::once(roster.admin)
        .chain(roster.members.iter().map(|member| member.pubky))
        .collect();
    for key in keys {
        poller.poll_key(key).await;
    }
    poller.found(roster)
}

/// The roster of `owner` alone: no circle, or none that counts.
fn alone(owner: Pubky) -> Circle {
    Circle {
        schema_version: SchemaVersion::CURRENT,
        name: String::new(),
        admin: owner,
        members: Vec::new(),
        extra: UnknownFields::new(),
    }
}

/// `circle` with each member once, none the admin, and at most
/// [`MAX_MEMBERS`] keys with the admin; and whether it listed more.
// It takes the circle by value and hands it back changed: the members are
// moved, not copied, from the list read into the list kept.
fn bounded(mut circle: Circle) -> (Circle, bool) {
    let listed = std::mem::take(&mut circle.members);
    for member in listed {
        // `Pubky`'s `==` compares the 32 key bytes, never a spelling. A
        // linear search, over at most `MAX_MEMBERS` keys.
        let seen = member.pubky == circle.admin
            || circle.members.iter().any(|kept| kept.pubky == member.pubky);
        if seen {
            continue;
        }
        // The admin is one of the `MAX_MEMBERS` keys.
        if circle.members.len() + 1 >= MAX_MEMBERS {
            return (circle, true);
        }
        circle.members.push(member);
    }
    (circle, false)
}

/// Why the poll of one key ended before its last read. `pub(super)`, like
/// [`Fetched`], [`Polled`] and [`fetch`], so that the feed watcher
/// (`pull::feed`) reads strangers' sweep records the same way.
pub(super) enum Stop {
    /// Its homeserver did not resolve.
    Unreachable(Unreachable),
    /// A read failed: `remote`'s fixed text, which names the path and the
    /// key.
    ReadFailed(anyhow::Error),
}

/// One of the two directories polled, with record ids in its file names.
#[derive(Clone, Copy)]
enum Directory {
    Bounties,
    Sweeps,
}

impl Directory {
    /// Its path, as core builds it.
    fn path(self) -> &'static str {
        match self {
            Self::Bounties => paths::BOUNTIES_DIR,
            Self::Sweeps => paths::SWEEPS_DIR,
        }
    }

    /// The most new records read of it, of one key in a run.
    fn max_new(self) -> usize {
        match self {
            Self::Bounties => MAX_NEW_BOUNTIES_PER_MEMBER,
            Self::Sweeps => MAX_NEW_SWEEPS_PER_MEMBER,
        }
    }

    /// The id of the record `entry` is, or `None` for any other file, such
    /// as an open bounty's `.discovered.json` or a sweep's `.age`.
    fn record_id(self, entry: &SweepkyPath) -> Option<RecordId> {
        // An or-pattern binds `id` in both alternatives; `*id` copies the
        // id out of the borrowed entry.
        match (self, entry) {
            (Self::Bounties, SweepkyPath::Bounty(id))
            | (Self::Sweeps, SweepkyPath::SweepRecord(id)) => Some(*id),
            _ => None,
        }
    }

    /// Its watermark among `marks`.
    fn watermark(self, marks: &Watermarks) -> Option<RecordId> {
        match self {
            Self::Bounties => marks.bounties,
            Self::Sweeps => marks.sweeps,
        }
    }

    /// Its watermark among `marks`, to move up.
    // One reference in, one out: the compiler ties the field lent out to
    // `marks`, so it cannot outlive the borrow of the watermarks.
    fn watermark_mut(self, marks: &mut Watermarks) -> &mut Option<RecordId> {
        match self {
            Self::Bounties => &mut marks.bounties,
            Self::Sweeps => &mut marks.sweeps,
        }
    }
}

/// One key's records in the poll state that can still change, by kind, to
/// read again.
struct Rereads {
    /// Its open bounties, newest first.
    open: Vec<BountyRef>,
    /// Its `running` sweeps of the owner's bounties, newest first.
    running: Vec<SweepRef>,
    /// Its done bounties, whose credits the owner may revise (01), oldest
    /// first.
    done: Vec<BountyRef>,
}

impl Rereads {
    /// What of these this run reads, each kind within its share of the
    /// budget ([`reread_shares`]): the newest open bounties and running
    /// sweeps, and the done bounties next in turn after `after`, in the
    /// order they are read. And how many open bounties and running sweeps
    /// are left for a later run; the done bounties left wait for their turn.
    // It takes `self` by value and hands back the lists cut: nothing is
    // copied, and the uncut lists cannot be used by mistake afterwards.
    fn this_run(mut self, after: Option<RecordId>) -> (Self, usize) {
        let shares = reread_shares(self.open.len(), self.running.len(), self.done.len());
        let left = (self.open.len() - shares.open) + (self.running.len() - shares.running);
        self.open.truncate(shares.open);
        self.running.truncate(shares.running);
        self.done = next_turn(&self.done, after, shares.done);
        (self, left)
    }
}

/// What one read of a record gave.
pub(super) enum Fetched<T> {
    /// The record as it is now, with the tag its answer gave.
    Record { record: T, etag: Option<ETag> },
    /// A 304: unchanged since the tag sent.
    Unchanged,
    /// A 404: there is no such record, or no longer.
    Absent,
    /// Not a record this build keeps: over the cap, not one of its kind, or
    /// carrying more than a summary keeps. Why, in fixed text that names the
    /// path and the key.
    Unreadable(anyhow::Error),
}

/// A record the roster reads and keeps a summary of: a bounty or a sweep.
///
/// A trait so that one [`fetch`] serves both: each kind says what it is
/// called, where it is, and how it is parsed. It is this crate's own trait,
/// so it may be implemented for core's types. `Sized` is needed to return
/// `Self` by value.
pub(super) trait Polled: Sized {
    /// Its name in a message.
    const KIND: &'static str;

    /// The path of record `id` in its writer's storage.
    fn path(id: RecordId) -> String;

    /// Parses the record and refuses one whose summary would carry more
    /// than Sweepky writes. Core's `from_json` refuses more than
    /// `MAX_RECORD_BYTES` before it parses anything, and its error quotes
    /// nothing.
    fn parse(bytes: &[u8]) -> anyhow::Result<Self>;
}

impl Polled for Bounty {
    const KIND: &'static str = "bounty";

    fn path(id: RecordId) -> String {
        paths::bounty(id)
    }

    fn parse(bytes: &[u8]) -> anyhow::Result<Self> {
        let bounty = Self::from_json(bytes)?;
        if bounty.status().as_str().len() > MAX_STATUS_BYTES {
            bail!("its status is longer than the {MAX_STATUS_BYTES} bytes pull keeps");
        }
        if bounty.credits().len() > MAX_CREDITS {
            bail!("it lists more than the {MAX_CREDITS} credits pull keeps");
        }
        Ok(bounty)
    }
}

impl Polled for Sweep {
    const KIND: &'static str = "sweep";

    fn path(id: RecordId) -> String {
        paths::sweep_record(id)
    }

    fn parse(bytes: &[u8]) -> anyhow::Result<Self> {
        let sweep = Self::from_json(bytes)?;
        if sweep.status.as_str().len() > MAX_STATUS_BYTES {
            bail!("its status is longer than the {MAX_STATUS_BYTES} bytes pull keeps");
        }
        if sweep.targets.len() > MAX_TARGETS {
            bail!("it names more than the {MAX_TARGETS} targets one run sweeps");
        }
        Ok(sweep)
    }
}

/// Reads record `id` of `owner`'s storage, a `T`, sending `etag` as
/// `If-None-Match` when there is one, and parses a new answer.
pub(super) async fn fetch<T: Polled>(
    records: &impl PublicRecords,
    owner: Pubky,
    id: RecordId,
    etag: Option<&ETag>,
) -> Result<Fetched<T>, Stop> {
    let path = T::path(id);
    let answer = match records.get_record_if_changed(owner, &path, etag).await {
        Ok(answer) => answer,
        // A body over the cap is the record's fault, not the homeserver's:
        // skipped like one that does not parse, rather than ending the key's
        // poll at the same record every run. `downcast_ref` finds the typed
        // error under the context `remote` added to it.
        Err(error) if error.downcast_ref::<BodyTooLarge>().is_some() => {
            return Ok(Fetched::Unreadable(error));
        }
        Err(error) => return Err(Stop::ReadFailed(error)),
    };
    Ok(match answer {
        Conditional::NotModified => Fetched::Unchanged,
        Conditional::Absent => Fetched::Absent,
        Conditional::Changed { body, etag } => {
            match T::parse(&body).with_context(|| not_a_record(T::KIND, &path, owner)) {
                Ok(record) => Fetched::Record { record, etag },
                Err(error) => Fetched::Unreadable(error),
            }
        }
    })
}

/// What the roster poll reads through, and what it has found so far.
///
/// Generic over the two seams, `R` and `H`, as a function taking
/// `&impl PublicRecords` is. Two lifetimes: `'p` is how long the poll
/// borrows the reader, the cache and the state, and `'h` how long the cache
/// borrows its resolver. With one for both, `&'p mut Homeservers<'p, H>`
/// would lend the cache for as long as the resolver lives, which the caller
/// could not use again afterwards.
struct Poller<'p, 'h, R, H> {
    records: &'p R,
    homeservers: &'p mut Homeservers<'h, H>,
    owner: Pubky,
    state: &'p mut PollState,
    warnings: Vec<String>,
}

impl<R: PublicRecords, H: ResolveHomeserver> Poller<'_, '_, R, H> {
    /// The roster this run: see the module docs.
    async fn roster(&mut self) -> Circle {
        let circle = match self.records.get_circle(self.owner).await {
            // A match guard (`if` after the pattern): this arm applies only
            // to the owner's own roster.
            Ok(Some(circle)) if circle.admin == self.owner => circle,
            Ok(Some(_)) => {
                self.warnings.push(ANOTHER_ADMIN.to_owned());
                return alone(self.owner);
            }
            Ok(None) => return alone(self.owner),
            Err(error) => {
                self.warnings.push(format!(
                    "your circle.json could not be read, so pull reads your own records alone \
                     this time: {error:#}"
                ));
                return alone(self.owner);
            }
        };
        let (roster, cut) = bounded(circle);
        if cut {
            self.warnings.push(format!(
                "your circle lists more than {MAX_MEMBERS} keys; pull polls the first \
                 {MAX_MEMBERS}, you first, and counts the rest as outside it this time"
            ));
        }
        roster
    }

    /// Polls `key`, with a warning when it stops early.
    async fn poll_key(&mut self, key: Pubky) {
        // `let ... else`: go on with the reason it stopped, or return when
        // the poll ran to its end.
        let Err(stop) = self.poll_until_stopped(key).await else {
            return;
        };
        let warning = match stop {
            Stop::Unreachable(why) => format!("pull skipped roster key {key}: {why}"),
            Stop::ReadFailed(error) => {
                let now = match self.homeservers.after_failed_read(key).await {
                    Ok(_) => String::new(),
                    Err(why) => format!("; looked up again, {why}"),
                };
                format!("pull reads no more of roster key {key} this time: {error:#}{now}")
            }
        };
        self.warnings.push(warning);
    }

    /// Polls `key` until its last read, or until it cannot go on.
    async fn poll_until_stopped(&mut self, key: Pubky) -> Result<(), Stop> {
        // The homeserver found is not used here: every read below resolves
        // the key again inside the SDK. The lookup is the gate.
        self.homeservers
            .resolve(key)
            .await
            .map_err(Stop::Unreachable)?;
        self.reread(key).await?;
        self.read_new(key, Directory::Bounties).await?;
        self.read_new(key, Directory::Sweeps).await
    }

    /// Reads `key`'s records that can still change again, each only if it
    /// changed since its tag: those [`Rereads::this_run`] picks, with a
    /// warning when open bounties or running sweeps are left. The done
    /// bounties' turn starts after the one the last run read last.
    async fn reread(&mut self, key: Pubky) -> Result<(), Stop> {
        let after = self
            .state
            .watermarks
            .get(&key)
            .and_then(|marks| marks.reread_done_after);
        let (this_run, left) = self.can_change(key).this_run(after);
        if left > 0 {
            self.warnings.push(format!(
                "pull reads the newest open bounties and running sweeps of roster key {key} \
                 again this time and leaves {left} for a later run"
            ));
        }
        for bounty in this_run.open {
            self.reread_bounty(bounty).await?;
        }
        for sweep in this_run.running {
            self.reread_sweep(sweep).await?;
        }
        for bounty in this_run.done {
            self.reread_bounty(bounty).await?;
            // Moved as each is read, so one a failed read leaves unread
            // comes first next run.
            let marks = self.state.watermarks.entry(key).or_default();
            marks.reread_done_after = Some(bounty.id);
        }
        Ok(())
    }

    /// Reads `bounty` again, if it changed since its tag.
    async fn reread_bounty(&mut self, bounty: BountyRef) -> Result<(), Stop> {
        // A copy of the tag, so the state is not borrowed while the read
        // below changes it.
        let etag = self
            .state
            .bounties
            .get(&bounty)
            .and_then(|s| s.etag.clone());
        let fetched = fetch(self.records, bounty.owner, bounty.id, etag.as_ref()).await?;
        self.keep_bounty(bounty, fetched);
        Ok(())
    }

    /// Reads `sweep` again, if it changed since its tag.
    async fn reread_sweep(&mut self, sweep: SweepRef) -> Result<(), Stop> {
        let etag = self.state.sweeps.get(&sweep).and_then(|s| s.etag.clone());
        let fetched = fetch(self.records, sweep.sweeper, sweep.id, etag.as_ref()).await?;
        self.keep_sweep(sweep, fetched);
        Ok(())
    }

    /// `key`'s records in the poll state that can still change: its open
    /// and its done bounties, and its `running` sweeps of the owner's
    /// bounties.
    fn can_change(&self, key: Pubky) -> Rereads {
        // `rev` walks a map from its last key down, so `key`'s sweeps come
        // newest first (see `bounties_of` for why).
        let running = self
            .state
            .sweeps
            .iter()
            .rev()
            .filter(|(sweep, summary)| {
                sweep.sweeper == key
                    && summary.bounty.owner == self.owner
                    && summary.status.as_known() == Some(KnownSweepStatus::Running)
            })
            .map(|(&sweep, _)| sweep)
            .collect();
        Rereads {
            open: self
                .bounties_of(key, KnownBountyStatus::Open)
                .rev()
                .collect(),
            running,
            done: self.bounties_of(key, KnownBountyStatus::Done).collect(),
        }
    }

    /// `key`'s bounties in the poll state whose status is `status`, oldest
    /// first: a ref orders by its key, then its id, and an id is its
    /// record's creation time.
    // `impl DoubleEndedIterator`: an iterator whose type the caller need not
    // name, which can be walked from its end too (`rev`). It borrows the
    // state, so it cannot outlive `&self`. `move` copies `key` and `status`
    // into the closure, which outlives this call.
    fn bounties_of(
        &self,
        key: Pubky,
        status: KnownBountyStatus,
    ) -> impl DoubleEndedIterator<Item = BountyRef> {
        self.state
            .bounties
            .iter()
            .filter(move |(bounty, summary)| {
                bounty.owner == key && summary.status.as_known() == Some(status)
            })
            .map(|(&bounty, _)| bounty)
    }

    /// Reads the records `dir` of `key` lists above its watermark that the
    /// poll state does not hold, oldest first and within the bounds, moving
    /// the watermark up to each as it goes.
    async fn read_new(&mut self, key: Pubky, dir: Directory) -> Result<(), Stop> {
        let seen = self
            .state
            .watermarks
            .get(&key)
            .and_then(|marks| dir.watermark(marks));
        let listing = self
            .records
            .list_newest_first(key, dir.path(), seen)
            .await
            .map_err(Stop::ReadFailed)?;
        let mut new = new_record_ids(&listing, dir);
        let max = dir.max_new();
        if new.len() > max {
            self.warnings.push(format!(
                "{} of roster key {key} lists {} new records; pull reads the oldest {max} this \
                 time and the rest next time",
                dir.path(),
                new.len()
            ));
            new.truncate(max);
        }
        for id in new {
            self.read_new_record(key, dir, id).await?;
            // Read, or skipped for good: the watermark passes it.
            self.pass_watermark(key, dir, id);
        }
        Ok(())
    }

    /// Moves `key`'s watermark in `dir` up to `id`, never down.
    fn pass_watermark(&mut self, key: Pubky, dir: Directory, id: RecordId) {
        let mark = dir.watermark_mut(self.state.watermarks.entry(key).or_default());
        // `None` is below every `Some`, so `max` sets a first watermark too.
        *mark = (*mark).max(Some(id));
    }

    /// Reads record `id` of `key`'s `dir`, unless the poll state holds it
    /// already (from an earlier roster, or from the feed): such a record is
    /// read again only if it can still change, by [`reread`](Self::reread).
    async fn read_new_record(
        &mut self,
        key: Pubky,
        dir: Directory,
        id: RecordId,
    ) -> Result<(), Stop> {
        match dir {
            Directory::Bounties => {
                let bounty = BountyRef { owner: key, id };
                if !self.state.bounties.contains_key(&bounty) {
                    let fetched = fetch(self.records, key, id, None).await?;
                    self.keep_bounty(bounty, fetched);
                }
            }
            Directory::Sweeps => {
                let sweep = SweepRef { sweeper: key, id };
                if !self.state.sweeps.contains_key(&sweep) {
                    let fetched = fetch(self.records, key, id, None).await?;
                    self.keep_sweep(sweep, fetched);
                }
            }
        }
        Ok(())
    }

    /// Brings `bounty`'s summary in line with what its read gave.
    fn keep_bounty(&mut self, bounty: BountyRef, fetched: Fetched<Bounty>) {
        match fetched {
            Fetched::Record { record, etag } => match self.state.bounties.get_mut(&bounty) {
                Some(summary) => summary.update(&record, etag),
                None => {
                    self.state
                        .bounties
                        .insert(bounty, BountySummary::new(&record, etag));
                }
            },
            Fetched::Unchanged => {}
            Fetched::Absent => {
                self.state.bounties.remove(&bounty);
            }
            // Any summary it had stays as it was.
            Fetched::Unreadable(error) => self.skipped(&error),
        }
    }

    /// Brings `sweep`'s summary in line with what its read gave. Only a
    /// sweep of one of the owner's bounties is kept.
    fn keep_sweep(&mut self, sweep: SweepRef, fetched: Fetched<Sweep>) {
        match fetched {
            Fetched::Record { record, etag } if record.bounty.owner == self.owner => {
                match self.state.sweeps.get_mut(&sweep) {
                    Some(summary) => summary.update(&record, etag),
                    None => {
                        self.state
                            .sweeps
                            .insert(sweep, SweepSummary::new(&record, etag));
                    }
                }
            }
            // Of another owner's bounty, or gone: nothing of it is kept (the
            // module docs say why), and a summary it had is dropped.
            Fetched::Record { .. } | Fetched::Absent => {
                self.state.sweeps.remove(&sweep);
            }
            Fetched::Unchanged => {}
            Fetched::Unreadable(error) => self.skipped(&error),
        }
    }

    /// Warns of a record skipped: `error` names its path and key.
    fn skipped(&mut self, error: &anyhow::Error) {
        self.warnings
            .push(format!("pull skipped a record: {error:#}"));
    }

    /// What the run found, from the poll state as it is now.
    // It takes `self` by value, the poll being over: the warnings are moved
    // into the result, not copied.
    fn found(self, roster: Circle) -> RosterPoll {
        // `&*` turns the poll's `&mut PollState` into a shared borrow, all
        // that reading needs.
        let state = &*self.state;
        // The fields are filled in the order written, so `roster` is moved
        // in only after the two lines that borrow it.
        RosterPoll {
            own_bounties: own_bounties(state, self.owner),
            sweeps: roster_sweeps(state, &roster, self.owner),
            credited: credited_bounties(state, &roster),
            roster,
            warnings: self.warnings,
        }
    }
}

/// The ids of the records `listing` names in `dir`, oldest first and each
/// once, whatever order the server listed them in: the watermark moves up as
/// each is read, so what a run leaves unread stays above it.
fn new_record_ids(listing: &Listing, dir: Directory) -> Vec<RecordId> {
    let mut ids: Vec<RecordId> = listing
        .entries
        .iter()
        .filter_map(|entry| dir.record_id(entry))
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// How many records of each kind of [`Rereads`] one key reads again in a
/// run.
// `Debug` and `PartialEq` for the tests: counts only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Shares {
    open: usize,
    running: usize,
    done: usize,
}

/// Splits [`MAX_REREADS_PER_MEMBER`] between one key's `open` bounties,
/// `running` sweeps and `done` bounties waiting to be read again, so that no
/// kind starves another. The done bounties take at most
/// [`MAX_DONE_REREADS_PER_MEMBER`], as they seldom change; the open bounties
/// and the running sweeps take half each of the rest, at least 12, and a
/// kind with fewer than its half leaves what it does not use to the other.
/// The shares never add up to more than the budget.
fn reread_shares(open: usize, running: usize, done: usize) -> Shares {
    let done = done.min(MAX_DONE_REREADS_PER_MEMBER);
    let room = MAX_REREADS_PER_MEMBER - done;
    // The running sweeps are owed half the room, or all of theirs if fewer,
    // and the open bounties take the rest, or all of theirs if fewer; then
    // the running sweeps take whatever the open bounties left.
    let open = open.min(room - running.min(room / 2));
    let running = running.min(room - open);
    Shares {
        open,
        running,
        done,
    }
}

/// Up to `n` of `bounties`, which are in id order: the first after `after`
/// and on from there, going round to the start, so a turn that stopped at
/// `after` goes on where it stopped. Each at most once.
fn next_turn(bounties: &[BountyRef], after: Option<RecordId>, n: usize) -> Vec<BountyRef> {
    // `partition_point` finds by binary search where the ids past `after`
    // begin, as the slice is in id order. `None` is below every `Some`, so
    // with no `after` that is the start.
    let start = bounties.partition_point(|bounty| Some(bounty.id) <= after);
    // `split_at` lends the two halves: the second, then the first, go round
    // once, so `take` never gives one twice.
    let (before, from) = bounties.split_at(start);
    from.iter().chain(before).take(n).copied().collect()
}

/// The owner's bounties `state` holds, oldest first.
fn own_bounties(state: &PollState, owner: Pubky) -> Vec<BountyRef> {
    state
        .bounties
        .keys()
        .filter(|bounty| bounty.owner == owner)
        .copied()
        .collect()
}

/// The sweeps `state` holds by a key of `roster`, of a bounty of the
/// owner's that `state` holds.
fn roster_sweeps(state: &PollState, roster: &Circle, owner: Pubky) -> Vec<SweepRef> {
    state
        .sweeps
        .iter()
        .filter(|(sweep, summary)| {
            roster.is_in_roster(sweep.sweeper)
                && summary.bounty.owner == owner
                && state.bounties.contains_key(&summary.bounty)
        })
        .map(|(&sweep, _)| sweep)
        .collect()
}

/// Every bounty of `roster` that `state` holds, as `trust_labels` takes it.
///
/// A map holds each key once, so each bounty is in the list once:
/// `trust_labels` counts every entry it is given and cannot tell two copies
/// of one record apart (P1a).
fn credited_bounties(state: &PollState, roster: &Circle) -> Vec<CreditedBounty> {
    state
        .bounties
        .iter()
        .filter(|(bounty, _)| roster.is_in_roster(bounty.owner))
        .map(|(bounty, summary)| CreditedBounty {
            owner: bounty.owner,
            status: summary.status.clone(),
            credits: summary.credits.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use sweepky_core::paths;
    use sweepky_core::{
        Bounty, BountyRef, KnownSweepStatus, MAX_RECORD_BYTES, Pubky, Sweep, SweepRef, TrustLabel,
        trust_labels,
    };

    use super::{
        MAX_CREDITS, MAX_DONE_REREADS_PER_MEMBER, MAX_MEMBERS, MAX_NEW_BOUNTIES_PER_MEMBER,
        MAX_REREADS_PER_MEMBER, MAX_STATUS_BYTES, RosterPoll, Shares, next_turn, poll_roster,
        reread_shares,
    };
    use crate::post::draft::MAX_TARGETS;
    use crate::pull::resolve::Homeservers;
    use crate::pull::state::{BountySummary, PollState, SweepSummary};
    use crate::test_support::{
        FakeHomeservers, FakeLookup, FakePublicRecords, PLANTED, bounty_json, circle_json, dirs_in,
        json_bytes, private_temp, random_pubky, record_id, repo_target_json, sweep_json,
    };

    /// Bounty `n` of `owner`.
    fn bounty(owner: Pubky, n: u64) -> BountyRef {
        BountyRef {
            owner,
            id: record_id(n),
        }
    }

    /// Sweep `n` of `sweeper`.
    fn sweep(sweeper: Pubky, n: u64) -> SweepRef {
        SweepRef {
            sweeper,
            id: record_id(n),
        }
    }

    /// A bounty record of one target with `status`, crediting `credits`.
    fn bounty_with(status: &str, credits: &[Pubky]) -> Value {
        let mut record = bounty_json(json!([repo_target_json("t1")]));
        record["status"] = json!(status);
        record["credits"] = json!(credits.iter().map(ToString::to_string).collect::<Vec<_>>());
        if status == "done" {
            record["doneAt"] = json!("2026-10-19T10:00:00Z");
        }
        record
    }

    /// The summary an earlier run kept of bounty `record`, with no tag.
    fn bounty_summary(record: &Value) -> BountySummary {
        let bounty = Bounty::from_json(&json_bytes(record)).expect("a bounty");
        BountySummary::new(&bounty, None)
    }

    /// The summary an earlier run kept of sweep `record`, with no tag.
    fn sweep_summary(record: &Value) -> SweepSummary {
        let sweep = Sweep::from_json(&json_bytes(record)).expect("a sweep");
        SweepSummary::new(&sweep, None)
    }

    /// `n` as a record's timestamp, for [`record_id`].
    fn nth(n: usize) -> u64 {
        u64::try_from(n).expect("small")
    }

    /// One run's roster poll: a fresh cache of homeservers, as each run
    /// starts with.
    async fn poll(
        records: &FakePublicRecords,
        resolver: &FakeHomeservers,
        owner: Pubky,
        state: &mut PollState,
    ) -> RosterPoll {
        let mut homeservers = Homeservers::new(resolver);
        poll_roster(records, &mut homeservers, owner, state).await
    }

    /// Checks that no warning repeats a stranger's text or could drive a
    /// terminal.
    fn assert_quotes_nothing(warnings: &[String]) {
        for warning in warnings {
            assert!(!warning.contains(PLANTED), "{warning}");
            assert!(!warning.chars().any(char::is_control), "{warning:?}");
        }
    }

    #[tokio::test]
    async fn a_second_poll_lists_down_to_the_watermarks_and_rereads_only_what_can_change() {
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        let (owner, member, credited) = (random_pubky(), random_pubky(), random_pubky());
        let (open, done, theirs) = (bounty(owner, 10), bounty(owner, 11), bounty(member, 20));
        let (vanishing, running, finished) =
            (sweep(member, 29), sweep(member, 30), sweep(member, 31));
        let records = FakePublicRecords::default()
            // `circle create` lists the admin among the members too.
            .with_record(
                owner,
                paths::circle(),
                &circle_json(owner, &[owner, member]),
            )
            .with_record(owner, &paths::bounty(open.id), &bounty_with("open", &[]))
            .with_record(
                owner,
                &paths::bounty(done.id),
                &bounty_with("done", &[member]),
            )
            .with_record(
                member,
                &paths::bounty(theirs.id),
                &bounty_with("done", &[credited]),
            )
            .with_record(
                member,
                &paths::sweep_record(vanishing.id),
                &sweep_json(open, &["t1"], "running"),
            )
            .with_record(
                member,
                &paths::sweep_record(running.id),
                &sweep_json(open, &["t1"], "running"),
            )
            .with_record(
                member,
                &paths::sweep_record(finished.id),
                &sweep_json(done, &["t1"], "done"),
            )
            .with_file(
                member,
                &paths::sweep_package(finished.id),
                b"sealed".to_vec(),
            );
        let resolver = FakeHomeservers::default();

        // The first run reads every record listed, once, with no tag to send.
        let mut state = PollState::default();
        let first = poll(&records, &resolver, owner, &mut state).await;
        assert!(first.warnings.is_empty(), "{:?}", first.warnings);
        assert_eq!(first.own_bounties, [open, done]);
        assert_eq!(first.sweeps, [vanishing, running, finished]);
        assert_eq!(first.credited.len(), 3);
        assert_eq!(
            records.asked(),
            [
                (owner, paths::circle().to_owned()),
                (owner, paths::BOUNTIES_DIR.to_owned()),
                (owner, paths::bounty(open.id)),
                (owner, paths::bounty(done.id)),
                (owner, paths::SWEEPS_DIR.to_owned()),
                (member, paths::BOUNTIES_DIR.to_owned()),
                (member, paths::bounty(theirs.id)),
                (member, paths::SWEEPS_DIR.to_owned()),
                (member, paths::sweep_record(vanishing.id)),
                (member, paths::sweep_record(running.id)),
                (member, paths::sweep_record(finished.id)),
            ]
        );
        let sent = records.conditional_asked();
        assert!(sent.iter().all(|(_, _, tag)| tag.is_none()), "{sent:?}");
        assert_eq!(state.watermarks[&owner].bounties, Some(done.id));
        assert_eq!(state.watermarks[&owner].sweeps, None);
        assert_eq!(state.watermarks[&member].bounties, Some(theirs.id));
        assert_eq!(state.watermarks[&member].sweeps, Some(finished.id));

        // The next run reads the state back from its file.
        state.write(&dirs, owner).expect("written");
        let mut state = PollState::read(&dirs, owner).expect("read back");
        let open_before = state.bounties[&open].clone();
        let open_tag = open_before.etag.clone().expect("a tag");
        let (done_before, theirs_before) = (
            state.bounties[&done].clone(),
            state.bounties[&theirs].clone(),
        );
        let done_tag = done_before.etag.clone().expect("a tag");
        let theirs_tag = theirs_before.etag.clone().expect("a tag");
        let vanishing_tag = state.sweeps[&vanishing].etag.clone().expect("a tag");
        let running_tag = state.sweeps[&running].etag.clone().expect("a tag");

        // Meanwhile: one running sweep is deleted and the other is done, and
        // a bounty and a sweep of it are new.
        let (newer, new_sweep) = (bounty(owner, 12), sweep(member, 32));
        let records = records
            .without_file(member, &paths::sweep_record(vanishing.id))
            .with_record(
                member,
                &paths::sweep_record(running.id),
                &sweep_json(open, &["t1"], "done"),
            )
            .with_record(owner, &paths::bounty(newer.id), &bounty_with("open", &[]))
            .with_record(
                member,
                &paths::sweep_record(new_sweep.id),
                &sweep_json(newer, &["t1"], "running"),
            );
        let (asked_before, sent_before) =
            (records.asked().len(), records.conditional_asked().len());
        let second = poll(&records, &resolver, owner, &mut state).await;
        assert!(second.warnings.is_empty(), "{:?}", second.warnings);

        // Each listing stops at its watermark, so only the new records are
        // read, and of the rest only those that can still change are read
        // again, each with the tag its last answer gave: the open bounty and
        // the running sweeps, newest first, then the done bounties, whose
        // credits may be revised.
        assert_eq!(
            records.asked().split_off(asked_before),
            [
                (owner, paths::circle().to_owned()),
                (owner, paths::bounty(open.id)),
                (owner, paths::bounty(done.id)),
                (owner, paths::BOUNTIES_DIR.to_owned()),
                (owner, paths::bounty(newer.id)),
                (owner, paths::SWEEPS_DIR.to_owned()),
                (member, paths::sweep_record(running.id)),
                (member, paths::sweep_record(vanishing.id)),
                (member, paths::bounty(theirs.id)),
                (member, paths::BOUNTIES_DIR.to_owned()),
                (member, paths::SWEEPS_DIR.to_owned()),
                (member, paths::sweep_record(new_sweep.id)),
            ]
        );
        assert_eq!(
            records.conditional_asked().split_off(sent_before),
            [
                (owner, paths::bounty(open.id), Some(open_tag)),
                (owner, paths::bounty(done.id), Some(done_tag)),
                (owner, paths::bounty(newer.id), None),
                (
                    member,
                    paths::sweep_record(running.id),
                    Some(running_tag.clone())
                ),
                (
                    member,
                    paths::sweep_record(vanishing.id),
                    Some(vanishing_tag)
                ),
                (member, paths::bounty(theirs.id), Some(theirs_tag)),
                (member, paths::sweep_record(new_sweep.id), None),
            ]
        );
        // The 304s left the summaries of the open bounty and the done ones
        // as they were; the 404 dropped the deleted sweep's; the done
        // sweep's is new, with its new tag, and not pulled yet.
        assert_eq!(state.bounties[&open], open_before);
        assert_eq!(state.bounties[&done], done_before);
        assert_eq!(state.bounties[&theirs], theirs_before);
        assert!(!state.sweeps.contains_key(&vanishing));
        let now_done = &state.sweeps[&running];
        assert_eq!(now_done.status.as_known(), Some(KnownSweepStatus::Done));
        assert_ne!(now_done.etag, Some(running_tag));
        assert!(!now_done.pulled);
        assert_eq!(state.watermarks[&owner].bounties, Some(newer.id));
        assert_eq!(state.watermarks[&member].sweeps, Some(new_sweep.id));
        assert_eq!(second.own_bounties, [open, done, newer]);
        assert_eq!(second.sweeps, [running, finished, new_sweep]);
        // One lookup per key per run.
        assert_eq!(resolver.asked(), [owner, member, owner, member]);
    }

    #[tokio::test]
    async fn a_404_listing_is_an_empty_directory_not_an_unreachable_key() {
        let (owner, empty) = (random_pubky(), random_pubky());
        // `empty` has no file at all: both listings answer as a 404 does.
        let records = FakePublicRecords::default().with_record(
            owner,
            paths::circle(),
            &circle_json(owner, &[empty]),
        );
        let resolver = FakeHomeservers::default();
        let mut state = PollState::default();
        let found = poll(&records, &resolver, owner, &mut state).await;

        assert!(found.warnings.is_empty(), "{:?}", found.warnings);
        assert!(found.roster.is_in_roster(empty));
        let asked = records.asked();
        assert!(asked.contains(&(empty, paths::BOUNTIES_DIR.to_owned())));
        assert!(asked.contains(&(empty, paths::SWEEPS_DIR.to_owned())));
        assert_eq!(resolver.times_asked(empty), 1);
        // Nothing seen, so nothing to stop at next time.
        assert!(!state.watermarks.contains_key(&empty));
    }

    #[tokio::test]
    async fn a_key_with_no_homeserver_is_skipped_with_one_warning_and_the_rest_are_polled() {
        let (owner, gone, member) = (random_pubky(), random_pubky(), random_pubky());
        let records = FakePublicRecords::default()
            .with_record(owner, paths::circle(), &circle_json(owner, &[gone, member]))
            .with_record(
                gone,
                &paths::bounty(record_id(1)),
                &bounty_with("open", &[]),
            )
            .with_record(
                member,
                &paths::bounty(record_id(2)),
                &bounty_with("open", &[]),
            );
        let resolver = FakeHomeservers::default().with_answers(gone, &[FakeLookup::NoRecord]);
        let mut state = PollState::default();
        let found = poll(&records, &resolver, owner, &mut state).await;

        assert_eq!(found.warnings.len(), 1, "{:?}", found.warnings);
        assert!(found.warnings[0].contains(&gone.to_string()));
        assert!(found.warnings[0].contains("no homeserver"));
        // Nothing of its storage is asked for; everyone else is polled.
        let asked = records.asked();
        assert!(asked.iter().all(|(key, _)| *key != gone), "{asked:?}");
        assert!(asked.contains(&(member, paths::bounty(record_id(2)))));
        assert!(asked.contains(&(owner, paths::SWEEPS_DIR.to_owned())));
        for key in [owner, gone, member] {
            assert_eq!(resolver.times_asked(key), 1);
        }
        // Still in the roster: unreachable is not untrusted.
        assert!(found.roster.is_in_roster(gone));
    }

    #[tokio::test]
    async fn a_circle_naming_another_admin_is_not_a_roster() {
        let (owner, admin, member) = (random_pubky(), random_pubky(), random_pubky());
        let mine = bounty(owner, 1);
        // A file in the owner's storage that names someone else as the
        // admin of a circle the owner and `member` are in.
        let records = FakePublicRecords::default()
            .with_record(
                owner,
                paths::circle(),
                &circle_json(admin, &[owner, member]),
            )
            .with_record(owner, &paths::bounty(mine.id), &bounty_with("open", &[]))
            .with_record(
                member,
                &paths::bounty(record_id(2)),
                &bounty_with("done", &[]),
            );
        let resolver = FakeHomeservers::default();
        let found = poll(&records, &resolver, owner, &mut PollState::default()).await;

        assert_eq!(found.warnings.len(), 1, "{:?}", found.warnings);
        assert!(found.warnings[0].contains("another admin"));
        assert_eq!(found.roster.admin, owner);
        assert!(found.roster.members.is_empty());
        assert!(!found.roster.is_in_roster(member));
        assert_eq!(resolver.asked(), [owner]);
        assert!(records.asked().iter().all(|(key, _)| *key == owner));
        assert_eq!(found.own_bounties, [mine]);
        assert_eq!(found.credited.len(), 1);
    }

    #[tokio::test]
    async fn no_circle_is_a_roster_of_the_owner_alone() {
        let owner = random_pubky();
        let mine = bounty(owner, 1);
        let records = FakePublicRecords::default().with_record(
            owner,
            &paths::bounty(mine.id),
            &bounty_with("open", &[]),
        );
        let resolver = FakeHomeservers::default();
        let found = poll(&records, &resolver, owner, &mut PollState::default()).await;

        assert!(found.warnings.is_empty(), "{:?}", found.warnings);
        assert_eq!(found.roster.admin, owner);
        assert!(found.roster.members.is_empty());
        assert_eq!(resolver.asked(), [owner]);
        assert_eq!(found.own_bounties, [mine]);
    }

    #[tokio::test]
    async fn a_sweep_of_another_owner_s_bounty_is_remembered_and_never_read_again() {
        let (owner, member, stranger) = (random_pubky(), random_pubky(), random_pubky());
        let elsewhere = sweep(member, 5);
        let records = FakePublicRecords::default()
            .with_record(owner, paths::circle(), &circle_json(owner, &[member]))
            .with_record(
                member,
                &paths::sweep_record(elsewhere.id),
                &sweep_json(bounty(stranger, 1), &["t1"], "running"),
            );
        let resolver = FakeHomeservers::default();
        let mut state = PollState::default();
        let path = (member, paths::sweep_record(elsewhere.id));

        let first = poll(&records, &resolver, owner, &mut state).await;
        assert!(first.sweeps.is_empty());
        assert_eq!(
            records
                .asked()
                .iter()
                .filter(|&asked| *asked == path)
                .count(),
            1
        );
        // Remembered by the watermark, which has passed it, so no listing
        // names it again. Not kept as a summary: nothing here reads it
        // again, running or not.
        assert_eq!(state.watermarks[&member].sweeps, Some(elsewhere.id));
        assert!(!state.sweeps.contains_key(&elsewhere));

        for _ in 0..2 {
            let again = poll(&records, &resolver, owner, &mut state).await;
            assert!(again.sweeps.is_empty());
        }
        assert_eq!(
            records
                .asked()
                .iter()
                .filter(|&asked| *asked == path)
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn each_roster_bounty_is_credited_once_however_many_polls() {
        let (owner, member, sweeper) = (random_pubky(), random_pubky(), random_pubky());
        let records = FakePublicRecords::default()
            .with_record(owner, paths::circle(), &circle_json(owner, &[member]))
            .with_record(
                owner,
                &paths::bounty(record_id(1)),
                &bounty_with("done", &[sweeper]),
            )
            .with_record(
                owner,
                &paths::bounty(record_id(2)),
                &bounty_with("open", &[]),
            )
            .with_record(
                member,
                &paths::bounty(record_id(3)),
                &bounty_with("done", &[sweeper, sweeper]),
            );
        let resolver = FakeHomeservers::default();
        let mut state = PollState::default();

        for _ in 0..3 {
            let found = poll(&records, &resolver, owner, &mut state).await;
            let mut owners: Vec<Pubky> = found.credited.iter().map(|b| b.owner).collect();
            owners.sort_unstable();
            let mut expected = vec![owner, owner, member];
            expected.sort_unstable();
            assert_eq!(owners, expected);
            // So the trust label counts each done bounty once: two bounties,
            // of two owners, however many polls ran.
            let trust = trust_labels(&found.roster, &found.credited).get(sweeper);
            assert_eq!(trust.label, TrustLabel::Known);
            assert_eq!((trust.tally.bounties, trust.tally.owners), (2, 2));
        }
    }

    /// How many of `warnings` hold `text`.
    fn count_holding(warnings: &[String], text: &str) -> usize {
        warnings
            .iter()
            .filter(|warning| warning.contains(text))
            .count()
    }

    #[tokio::test]
    async fn keys_past_max_members_are_cut_with_a_warning() {
        let owner = random_pubky();
        let members: Vec<Pubky> = (0..MAX_MEMBERS + 2).map(|_| random_pubky()).collect();
        // The circle's own text is a stranger's too, and printed nowhere.
        let mut circle = circle_json(owner, &members);
        circle["name"] = json!(format!("{PLANTED}\u{1b}[2J"));
        circle["members"][0]["label"] = json!(PLANTED);
        let records = FakePublicRecords::default().with_record(owner, paths::circle(), &circle);
        let resolver = FakeHomeservers::default();
        let found = poll(&records, &resolver, owner, &mut PollState::default()).await;

        assert_quotes_nothing(&found.warnings);
        let first = format!("first {MAX_MEMBERS}");
        assert_eq!(
            count_holding(&found.warnings, &first),
            1,
            "{:?}",
            found.warnings
        );
        // The roster holds the first keys alone, the admin first, and only
        // they are looked up and read.
        assert_eq!(resolver.asked().len(), MAX_MEMBERS);
        assert_eq!(1 + found.roster.members.len(), MAX_MEMBERS);
        let cut = members[MAX_MEMBERS - 1];
        assert!(!found.roster.is_in_roster(cut));
        assert!(records.asked().iter().all(|(key, _)| *key != cut));
    }

    #[tokio::test]
    async fn new_records_past_the_per_run_bound_wait_for_the_next_run() {
        let owner = random_pubky();
        let newest = u64::try_from(MAX_NEW_BOUNTIES_PER_MEMBER).expect("small") + 2;
        let mut records = FakePublicRecords::default();
        for n in 1..=newest {
            records = records.with_record(
                owner,
                &paths::bounty(record_id(n)),
                &bounty_with("open", &[]),
            );
        }
        let resolver = FakeHomeservers::default();
        let mut state = PollState::default();

        // The oldest are read, and the watermark stops at the last of them.
        let first = poll(&records, &resolver, owner, &mut state).await;
        let oldest = format!("oldest {MAX_NEW_BOUNTIES_PER_MEMBER}");
        assert_eq!(
            count_holding(&first.warnings, &oldest),
            1,
            "{:?}",
            first.warnings
        );
        assert_eq!(first.own_bounties.len(), MAX_NEW_BOUNTIES_PER_MEMBER);
        assert_eq!(
            state.watermarks[&owner].bounties,
            Some(record_id(newest - 2))
        );

        // The rest come next run.
        let second = poll(&records, &resolver, owner, &mut state).await;
        assert!(second.warnings.is_empty(), "{:?}", second.warnings);
        assert_eq!(second.own_bounties.len(), MAX_NEW_BOUNTIES_PER_MEMBER + 2);
        assert_eq!(state.watermarks[&owner].bounties, Some(record_id(newest)));
    }

    #[tokio::test]
    async fn a_record_no_summary_keeps_is_skipped_once_with_a_warning_that_quotes_none_of_it() {
        let owner = random_pubky();
        // Each with the planted word where a careless message would quote it.
        let mut long_status = bounty_with("open", &[]);
        long_status["status"] = json!(format!("{PLANTED}{}", "x".repeat(MAX_STATUS_BYTES)));
        let too_many_credits = bounty_with("done", &vec![random_pubky(); MAX_CREDITS + 1]);
        let mut over_cap = json_bytes(&bounty_with(PLANTED, &[]));
        over_cap.resize(MAX_RECORD_BYTES + 1, b' ');
        let not_json = format!("{{\"title\": \"{PLANTED}").into_bytes();
        let mut too_many_targets = sweep_json(bounty(owner, 1), &["t1"], "running");
        too_many_targets["targets"] = json!(
            (0..=MAX_TARGETS)
                .map(|n| format!("t{n}"))
                .collect::<Vec<_>>()
        );
        let records = FakePublicRecords::default()
            .with_record(owner, &paths::bounty(record_id(1)), &long_status)
            .with_record(owner, &paths::bounty(record_id(2)), &too_many_credits)
            .with_file(owner, &paths::bounty(record_id(3)), over_cap)
            .with_file(owner, &paths::bounty(record_id(4)), not_json)
            .with_record(owner, &paths::sweep_record(record_id(5)), &too_many_targets);
        let resolver = FakeHomeservers::default();
        let mut state = PollState::default();

        let first = poll(&records, &resolver, owner, &mut state).await;
        assert_quotes_nothing(&first.warnings);
        assert_eq!(count_holding(&first.warnings, "pull skipped a record"), 5);
        assert!(state.bounties.is_empty());
        assert!(state.sweeps.is_empty());
        // The watermarks pass them, so they are not read again.
        assert_eq!(state.watermarks[&owner].bounties, Some(record_id(4)));
        assert_eq!(state.watermarks[&owner].sweeps, Some(record_id(5)));
        let second = poll(&records, &resolver, owner, &mut state).await;
        assert!(second.warnings.is_empty(), "{:?}", second.warnings);
        let reads = records
            .asked()
            .iter()
            .filter(|(_, path)| !path.ends_with('/'))
            .count();
        // The circle twice, and each record once.
        assert_eq!(reads, 2 + 5);
    }

    #[tokio::test]
    async fn a_failed_read_looks_the_key_up_once_more_and_ends_its_poll_for_the_run() {
        let (owner, moved, flaky, member) = (
            random_pubky(),
            random_pubky(),
            random_pubky(),
            random_pubky(),
        );
        let records = FakePublicRecords::default()
            .with_record(
                owner,
                paths::circle(),
                &circle_json(owner, &[moved, flaky, member]),
            )
            .with_broken_listing(moved, paths::BOUNTIES_DIR)
            .with_broken_listing(flaky, paths::BOUNTIES_DIR)
            .with_broken_listing(flaky, paths::SWEEPS_DIR);
        // `moved`'s record names no homeserver by the time it is looked up
        // again.
        let resolver = FakeHomeservers::default().with_answers(
            moved,
            &[FakeLookup::At(random_pubky()), FakeLookup::NoRecord],
        );
        let found = poll(&records, &resolver, owner, &mut PollState::default()).await;

        assert_eq!(found.warnings.len(), 2, "{:?}", found.warnings);
        let about = |key: Pubky| {
            found
                .warnings
                .iter()
                .find(|warning| warning.contains(&key.to_string()))
                .cloned()
                .expect("a warning")
        };
        assert!(about(moved).contains("more entries than were asked for"));
        assert!(about(moved).contains("no homeserver"));
        assert!(!about(flaky).contains("no homeserver"));
        // Looked up once more after the failure, and no more; nothing more
        // of either is read this run.
        assert_eq!(resolver.times_asked(moved), 2);
        assert_eq!(resolver.times_asked(flaky), 2);
        let asked = records.asked();
        for key in [moved, flaky] {
            assert!(!asked.contains(&(key, paths::SWEEPS_DIR.to_owned())));
        }
        // Everyone else is polled as before.
        assert_eq!(resolver.times_asked(member), 1);
        assert!(asked.contains(&(member, paths::SWEEPS_DIR.to_owned())));
    }

    #[tokio::test]
    async fn a_done_bounty_whose_credits_are_revised_is_read_again_and_the_label_follows() {
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        let (owner, member, sweeper) = (random_pubky(), random_pubky(), random_pubky());
        let theirs = bounty(member, 1);
        let path = paths::bounty(theirs.id);
        let records = FakePublicRecords::default()
            .with_record(owner, paths::circle(), &circle_json(owner, &[member]))
            .with_record(member, &path, &bounty_with("done", &[]));
        let resolver = FakeHomeservers::default();
        let mut state = PollState::default();
        let first = poll(&records, &resolver, owner, &mut state).await;
        let trust = trust_labels(&first.roster, &first.credited).get(sweeper);
        assert_eq!(trust.label, TrustLabel::Unknown);

        // The member runs `done` again on the bounty, crediting `sweeper`
        // now (01: the owner may revise the credits of a done bounty).
        let records = records.with_record(member, &path, &bounty_with("done", &[sweeper]));
        let tag = state.bounties[&theirs].etag.clone().expect("a tag");
        state.write(&dirs, owner).expect("written");
        let mut state = PollState::read(&dirs, owner).expect("read back");
        let sent_before = records.conditional_asked().len();
        let second = poll(&records, &resolver, owner, &mut state).await;

        // Read again with its tag, and the new credits are in its summary,
        // so the label follows them.
        assert!(second.warnings.is_empty(), "{:?}", second.warnings);
        assert_eq!(
            records.conditional_asked().split_off(sent_before),
            [(member, path.clone(), Some(tag))]
        );
        assert_eq!(state.bounties[&theirs].credits, [sweeper]);
        let trust = trust_labels(&second.roster, &second.credited).get(sweeper);
        assert_eq!(trust.label, TrustLabel::Known);
        assert_eq!((trust.tally.bounties, trust.tally.owners), (1, 1));

        // Unchanged since: read again with the new tag, a 304, and the
        // summary stays as it was.
        let before = state.bounties[&theirs].clone();
        let sent_before = records.conditional_asked().len();
        let third = poll(&records, &resolver, owner, &mut state).await;
        assert!(third.warnings.is_empty(), "{:?}", third.warnings);
        assert_eq!(
            records.conditional_asked().split_off(sent_before),
            [(member, path, before.etag.clone())]
        );
        assert_eq!(state.bounties[&theirs], before);
    }

    #[tokio::test]
    async fn done_bounties_past_the_per_run_number_are_read_again_in_turn_going_round() {
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        let owner = random_pubky();
        // Fewer than a run reads as new, so the first run reads them all.
        let count = MAX_DONE_REREADS_PER_MEMBER + 4;
        assert!(count <= MAX_NEW_BOUNTIES_PER_MEMBER);
        let mut records = FakePublicRecords::default();
        for n in 1..=nth(count) {
            records = records.with_record(
                owner,
                &paths::bounty(record_id(n)),
                &bounty_with("done", &[]),
            );
        }
        let resolver = FakeHomeservers::default();
        let mut state = PollState::default();
        let first = poll(&records, &resolver, owner, &mut state).await;
        assert_eq!(first.own_bounties.len(), count);

        // Each later run reads the next of them again, oldest first, from
        // the one after where the last run stopped, going round to the
        // oldest: the record ids 1 to `count`, over and over, cut into
        // turns. The poll state, written and read back between runs, keeps
        // where the turn stopped.
        let mut in_turn = (1..=nth(count)).cycle();
        for _ in 0..3 {
            state.write(&dirs, owner).expect("written");
            let mut read_back = PollState::read(&dirs, owner).expect("read back");
            let before = read_back.bounties.clone();
            let sent_before = records.conditional_asked().len();
            let found = poll(&records, &resolver, owner, &mut read_back).await;
            assert!(found.warnings.is_empty(), "{:?}", found.warnings);

            // `by_ref` borrows the iterator, so the next turn goes on from
            // where this one stopped.
            let expected: Vec<_> = in_turn
                .by_ref()
                .take(MAX_DONE_REREADS_PER_MEMBER)
                .map(|n| (owner, paths::bounty(record_id(n))))
                .collect();
            let sent = records.conditional_asked().split_off(sent_before);
            assert!(sent.iter().all(|(_, _, tag)| tag.is_some()), "{sent:?}");
            let read: Vec<_> = sent.into_iter().map(|(key, path, _)| (key, path)).collect();
            assert_eq!(read, expected);
            // Every answer was a 304.
            assert_eq!(read_back.bounties, before);
            state = read_back;
        }
    }

    #[test]
    fn a_turn_goes_on_after_where_the_last_stopped_even_once_that_bounty_is_gone() {
        let owner = random_pubky();
        let done = [bounty(owner, 2), bounty(owner, 4), bounty(owner, 6)];
        // No turn yet: from the oldest.
        assert_eq!(next_turn(&done, None, 2), done[..2]);
        // After bounty 3, which is gone: from bounty 4, going round.
        assert_eq!(
            next_turn(&done, Some(record_id(3)), 3),
            [done[1], done[2], done[0]]
        );
        // After the newest, or past it: round to the oldest.
        assert_eq!(next_turn(&done, Some(record_id(9)), 1), [done[0]]);
        // Never one twice, however many are asked for.
        assert_eq!(next_turn(&done, Some(record_id(4)), 9).len(), done.len());
    }

    #[test]
    fn the_shares_of_the_rereads_stay_in_the_budget_and_starve_no_kind() {
        let half = (MAX_REREADS_PER_MEMBER - MAX_DONE_REREADS_PER_MEMBER) / 2;
        let most = MAX_REREADS_PER_MEMBER + 8;
        for open in 0..=most {
            for running in 0..=most {
                for done in 0..=most {
                    let shares = reread_shares(open, running, done);
                    let Shares {
                        open: open_read,
                        running: running_read,
                        done: done_read,
                    } = shares;
                    // Within what waits, the done bounties' own number, and
                    // the budget.
                    assert!(open_read <= open && running_read <= running && done_read <= done);
                    assert!(done_read <= MAX_DONE_REREADS_PER_MEMBER);
                    assert!(open_read + running_read + done_read <= MAX_REREADS_PER_MEMBER);
                    // The done bounties' number always fits, and what the
                    // open bounties and the running sweeps leave flows to
                    // the other, so a kind is cut only when the budget is
                    // spent, and never below half of the room the done
                    // bounties leave.
                    assert_eq!(done_read, done.min(MAX_DONE_REREADS_PER_MEMBER));
                    let all_read = open_read == open && running_read == running;
                    assert!(
                        all_read || open_read + running_read + done_read == MAX_REREADS_PER_MEMBER,
                        "{shares:?} of {open}, {running}, {done}"
                    );
                    assert!(open_read >= open.min(half), "{shares:?}");
                    assert!(running_read >= running.min(half), "{shares:?}");
                }
            }
        }
        // All three kinds past their shares: 12, 12 and 8 of 32.
        assert_eq!(
            reread_shares(most, most, most),
            Shares {
                open: half,
                running: half,
                done: MAX_DONE_REREADS_PER_MEMBER,
            }
        );
    }

    /// A poll state as earlier runs left it for `owner`, whose circle has
    /// `member`, with each of `bounties` and `sweeps` summarised, and the
    /// listings' watermarks past them all, so a run reads nothing as new.
    fn polled_before(
        owner: Pubky,
        member: Pubky,
        bounties: &[(BountyRef, Value)],
        sweeps: &[(SweepRef, Value)],
    ) -> (FakePublicRecords, PollState) {
        let mut records = FakePublicRecords::default().with_record(
            owner,
            paths::circle(),
            &circle_json(owner, &[member]),
        );
        let mut state = PollState::default();
        for (bounty, record) in bounties {
            records = records.with_record(bounty.owner, &paths::bounty(bounty.id), record);
            state.bounties.insert(*bounty, bounty_summary(record));
            let marks = state.watermarks.entry(bounty.owner).or_default();
            marks.bounties = marks.bounties.max(Some(bounty.id));
        }
        for (sweep, record) in sweeps {
            records = records.with_record(sweep.sweeper, &paths::sweep_record(sweep.id), record);
            state.sweeps.insert(*sweep, sweep_summary(record));
            let marks = state.watermarks.entry(sweep.sweeper).or_default();
            marks.sweeps = marks.sweeps.max(Some(sweep.id));
        }
        (records, state)
    }

    /// The paths of `key`'s storage that were read again, if changed, of
    /// those `records` was asked: bounties, then sweeps.
    fn reread_of(records: &FakePublicRecords, key: Pubky) -> (Vec<String>, Vec<String>) {
        records
            .conditional_asked()
            .into_iter()
            .filter(|(owner, _, _)| *owner == key)
            .map(|(_, path, _)| path)
            .partition(|path| path.starts_with(paths::BOUNTIES_DIR))
    }

    #[tokio::test]
    async fn open_bounties_past_the_whole_budget_leave_the_running_sweeps_their_share() {
        let (owner, member) = (random_pubky(), random_pubky());
        let mine = bounty(owner, 1);
        let (open_count, running_count) = (MAX_REREADS_PER_MEMBER + 4, 5);
        let mut bounties = vec![(mine, bounty_with("open", &[]))];
        bounties
            .extend((1..=nth(open_count)).map(|n| (bounty(member, n), bounty_with("open", &[]))));
        let sweeps: Vec<_> = (1..=nth(running_count))
            .map(|n| (sweep(member, 100 + n), sweep_json(mine, &["t1"], "running")))
            .collect();
        let (records, mut state) = polled_before(owner, member, &bounties, &sweeps);
        let resolver = FakeHomeservers::default();
        let found = poll(&records, &resolver, owner, &mut state).await;

        // Every running sweep is read again, and the open bounties take the
        // rest of the budget, the newest first.
        let (bounties_read, sweeps_read) = reread_of(&records, member);
        let mut every_sweep: Vec<String> = sweeps
            .iter()
            .map(|(sweep, _)| paths::sweep_record(sweep.id))
            .collect();
        every_sweep.reverse();
        assert_eq!(sweeps_read, every_sweep);
        let open_read = MAX_REREADS_PER_MEMBER - running_count;
        let newest: Vec<String> = (1..=nth(open_count))
            .rev()
            .take(open_read)
            .map(|n| paths::bounty(record_id(n)))
            .collect();
        assert_eq!(bounties_read, newest);
        // One warning, that counts what is left for a later run.
        assert_eq!(found.warnings.len(), 1, "{:?}", found.warnings);
        let left = open_count - open_read;
        assert!(found.warnings[0].contains(&member.to_string()));
        let leaves = format!("leaves {left} for a later run");
        assert!(found.warnings[0].contains(&leaves), "{}", found.warnings[0]);
    }

    #[tokio::test]
    async fn a_key_with_only_running_sweeps_reads_them_with_the_whole_budget() {
        let (owner, member) = (random_pubky(), random_pubky());
        let mine = bounty(owner, 1);
        let running_count = MAX_REREADS_PER_MEMBER + 3;
        let sweeps: Vec<_> = (1..=nth(running_count))
            .map(|n| (sweep(member, 100 + n), sweep_json(mine, &["t1"], "running")))
            .collect();
        let (records, mut state) =
            polled_before(owner, member, &[(mine, bounty_with("open", &[]))], &sweeps);
        let resolver = FakeHomeservers::default();
        let found = poll(&records, &resolver, owner, &mut state).await;

        let (bounties_read, sweeps_read) = reread_of(&records, member);
        assert!(bounties_read.is_empty(), "{bounties_read:?}");
        let newest: Vec<String> = sweeps
            .iter()
            .rev()
            .take(MAX_REREADS_PER_MEMBER)
            .map(|(sweep, _)| paths::sweep_record(sweep.id))
            .collect();
        assert_eq!(sweeps_read, newest);
        assert_eq!(found.warnings.len(), 1, "{:?}", found.warnings);
        let leaves = "leaves 3 for a later run";
        assert!(found.warnings[0].contains(leaves), "{}", found.warnings[0]);
    }
}
