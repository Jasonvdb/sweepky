//! `pull`'s open-bounty feed watcher (01, "Open bounties"): how the owner
//! finds strangers' sweeps of their open bounties, through each watched
//! homeserver's public `/events/` feed and through the sweeps each open
//! bounty's `discovered.json` already lists.
//!
//! [`watch_open_bounties`] runs after the roster poll, whose poll state says
//! which of the owner's bounties are **open to strangers**: `open: true`
//! with status `open`. A stranger's sweep of any other bounty, closed or
//! done, is not added. With none open, it sends no feed request, reads no
//! `discovered.json`, and drops the owner's local feed cursors: no sweep
//! could be accepted, so nothing is missed, and a later `post --open`
//! stores new ones. Otherwise, in this order:
//!
//! 1. **What each open bounty's `discovered.json` lists.** Read from the
//!    owner's own storage with the tag of its last answer as
//!    `If-None-Match`, so an unchanged file costs a 304. A new answer gives
//!    the cursors it holds, and the sweeps it lists that this install has
//!    neither accepted nor seen deleted are confirmed one by one, as a
//!    feed's are (below), at most [`MAX_LISTED_SWEEPS_PER_RUN`] a run. A
//!    listed sweep whose record is gone is a confirmed deletion. This is how
//!    a second install of the owner sees what the first discovered: its own
//!    cursor may start past those events. The tag is kept only once every
//!    sweep the file lists is settled, so a file with sweeps still to
//!    confirm is read whole again next run. Then the poll state is written.
//! 2. **Where each watched homeserver's feed starts** ([`Start`]): at the
//!    local cursor; else at the lowest cursor the open bounties'
//!    `discovered.json` give it; else at its head, found by
//!    `events::find_head`, with a warning. A start that did not come from
//!    the local file is stored there at once, so the next run starts from
//!    it even if this one reads no page of that feed. There is one cursor
//!    per owner and homeserver, not per bounty: a sweep record names its
//!    bounty, so reading from the lowest start serves every open bounty on
//!    that homeserver, and no sweep can name a bounty from before it
//!    existed.
//! 3. **Each feed, a batch at a time**: a page of up to [`FEED_PAGE_SIZE`]
//!    events, at most [`MAX_FEED_PAGES_PER_RUN`] pages a run. A page with
//!    more events than asked for is refused by the events seam; one with no
//!    cursor, or whose cursor is not past the one asked for, stops that
//!    feed with a warning. Of a page, the sweep records alone, each once
//!    with its last operation (core's `FeedPage::sweep_records`: dedupe by
//!    URL), of sweepers outside the roster (the roster poll reads the
//!    roster's). A `PUT` is a record to read from the sweeper's own storage,
//!    a `DEL` the question whether a sweep accepted is gone. Then the poll
//!    state is written, and then the cursor moved on to the page's
//!    ([`FeedCursors::advance`]).
//!
//! **The feed is a hint.** Every sweep accepted, from a feed or from a
//! `discovered.json`, is the record read from its sweeper's own storage,
//! through `PublicRecords`, once its homeserver resolves through the run's
//! [`Homeservers`] (which on production puts the host policy in front):
//! never the feed's host's word, which can be any bytes for a path. A sweep
//! is accepted when that record names one of the owner's bounties open to
//! strangers. A `DEL` drops a sweep only once its sweeper's storage answers
//! 404 for it; a `DEL` of a sweep this install never accepted is not looked
//! into.
//!
//! **Bounded.** A page's body is capped at core's `MAX_FEED_BODY_BYTES` and
//! holds at most [`FEED_PAGE_SIZE`] events, a run reads a finite number of
//! pages and listed sweeps, and every record read is capped at
//! `MAX_RECORD_BYTES`, with the roster poll's limits on what a summary may
//! carry.
//!
//! **What it keeps of strangers is capped too**, because the feed is
//! anyone's to write to and only a confirmed deletion takes a sweep out of
//! the poll state: at most [`MAX_ACCEPTED_PER_BOUNTY`] sweeps accepted for
//! one bounty and [`MAX_STRANGERS_SWEEPS_KEPT`] kept in all, deletions
//! included. Past them a new stranger's sweep is left out, with a warning
//! that names the bounty, and the feed reads on: the sweeps already
//! accepted still come up to date, and once no open bounty has room, a new
//! sweep is not even read. Should the poll state's file still have no room
//! for a step's changes (the roster's records fill the rest of it), the
//! step is dropped: the state goes back to what it was before it, the
//! cursor stays, nothing more is read this run, and a warning says so. So
//! nothing the watcher adds can make a later write of the poll state fail.
//!
//! **Faults skip, they do not stall.** A sweeper whose homeserver does not
//! resolve, or a read of whose storage fails, is read no more this run, with
//! one warning; a record that does not parse is skipped with one. The
//! cursor still moves on: a stranger can make their own reads fail, and
//! that must not stop the owner's feed. Such a sweep is seen again at the
//! next event of its record, or through a `discovered.json` listing.
//!
//! **Errors and warnings quote nothing** of a feed or a record: fixed text,
//! numbers, keys, and the URLs and paths core built, with `remote`'s and
//! core's fixed text as causes. So nothing printed needs the sanitiser.
//! Only a failure of the local files is an error; every other fault is a
//! warning in the [`FeedWatch`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use anyhow::Context as _;
use sweepky_core::paths;
use sweepky_core::{
    BountyRef, Circle, Discovered, EventCursor, FeedOp, FeedPage, KnownBountyStatus, Pubky,
    RecordId, Sweep, SweepRef,
};

use super::resolve::{Homeservers, ResolveHomeserver};
use super::roster::{Fetched, Stop, fetch};
use super::state::{FeedCursors, PollState, SweepSummary, WouldPassCap};
use crate::Dirs;
use crate::events::{EventsFeed, find_head};
use crate::records::{PublicRecords, not_a_record};
use crate::remote::{Conditional, ETag, MAX_PAGE_SIZE};

/// The events asked for a page: 1000, the most a homeserver sends (01:
/// `limit` caps at 1000 silently, so a reader loops while a page is full).
pub(crate) const FEED_PAGE_SIZE: u16 = MAX_PAGE_SIZE;

/// The most pages of one homeserver's feed read in a run: 10, production's
/// `/events/` burst (06), so a run's pages need not wait on its rate. At
/// 1000 events a page that is 10,000 events a run; a feed further ahead is
/// read on in the next.
pub(crate) const MAX_FEED_PAGES_PER_RUN: usize = 10;

/// The most sweeps listed in the open bounties' `discovered.json`, and new
/// to this install, confirmed in a run: 256, each one read of a stranger's
/// record. A fresh install of a busy owner reads the rest over the next
/// runs.
pub(crate) const MAX_LISTED_SWEEPS_PER_RUN: usize = 256;

/// The most strangers' sweeps the poll state keeps accepted for one of the
/// owner's bounties: 256, as many as a run confirms from the open bounties'
/// `discovered.json`, so a second install takes in a full bounty's list in
/// one run. The feed is anyone's to write to and nothing but a confirmed
/// deletion takes a sweep out of the poll state, so without a cap a flood
/// of sweeps under throwaway keys would grow it until its write failed.
pub(crate) const MAX_ACCEPTED_PER_BOUNTY: usize = 256;

/// The most strangers' sweeps the poll state keeps in all, accepted for any
/// of the owner's bounties, open or not, or confirmed deleted: 1024. One
/// accepted takes at most about 1.6 KiB of the file (a summary of 32
/// targets with its tag, and its URL in `acceptedSweeps`), so the feed
/// fills under half of the 4 MiB cap and leaves the rest to the roster.
/// Deletions count, as a flood could otherwise cycle sweeps through
/// acceptance and deletion and grow the file by a URL each time.
pub(crate) const MAX_STRANGERS_SWEEPS_KEPT: usize = 1024;

/// Why a feed stops when its page holds events, or malformed lines, but no
/// cursor to go on from.
const NO_CURSOR: &str = "the homeserver sent a page with no cursor to go on from, which breaks \
                         the protocol";

/// Why a feed stops when its page's cursor is not past the one asked for:
/// read on from it, the run would ask for the same events again.
const CURSOR_NOT_FORWARD: &str = "the homeserver's cursor did not move past the one asked for, \
                                  which breaks the protocol";

/// Why a feed stops when its cursor in the local file is no longer the one
/// this run read from.
const CURSOR_MOVED: &str = "its cursor in feed-cursors.json changed while pull read it, as \
                            another pull or a post --open changes it; pull goes on from there \
                            next time";

/// What the watcher says when the poll state's file has no room for what a
/// step of it read: the step is dropped, and nothing more is read.
const POLL_STATE_FULL: &str = "poll-state.json has no room for the strangers' sweeps pull just \
                               read for your open bounties, so it keeps none of them, leaves the \
                               events feeds' cursors where they were and reads no more of them \
                               this time; the sweeps it already holds are opened as usual";

/// Where a feed's start came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartSource {
    /// The local `feed-cursors.json`: where this install read up to.
    Local,
    /// The lowest cursor the open bounties' `discovered.json` give it, as a
    /// second install of the owner first finds it.
    Discovered,
    /// The head of the feed, searched for now, as no cursor was known: a
    /// sweep written there before now is seen only if a `discovered.json`
    /// lists it.
    HeadSearch,
}

/// Where a feed was read from this run, and why there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Start {
    /// The cursor the first page was asked after.
    pub(crate) cursor: EventCursor,
    /// Where it came from.
    pub(crate) source: StartSource,
}

/// A stranger's sweep of one of the owner's bounties, as
/// `bounties/<id>.discovered.json` lists it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BountySweep {
    /// The owner's bounty, by its id.
    pub(crate) bounty: RecordId,
    /// The stranger's sweep record.
    pub(crate) sweep: SweepRef,
}

/// What [`watch_open_bounties`] found, for the rest of `pull`: what the
/// public `discovered.json` write is to add and drop.
///
/// Keys, ids and `pull`'s own fixed text only, so deriving `Debug` prints
/// no stranger's text.
#[derive(Debug, Default)]
pub(crate) struct FeedWatch {
    /// Each watched homeserver whose feed was read, and where from. One
    /// whose head could not be found is not here, and a warning says so.
    pub(crate) starts: BTreeMap<Pubky, Start>,
    /// The strangers' sweeps accepted this run, in the order accepted, each
    /// once. The poll state's `acceptedSweeps` holds them too.
    pub(crate) accepted: Vec<BountySweep>,
    /// The sweeps whose deletion was confirmed this run: accepted before, or
    /// listed in a `discovered.json`, and gone from their sweeper's storage.
    /// The poll state's `deletedSweeps` holds them too.
    pub(crate) deleted: Vec<BountySweep>,
    /// One line for each fault skipped, in fixed text that names keys,
    /// URLs and paths, never a feed's or a record's content.
    pub(crate) warnings: Vec<String>,
}

/// What the watcher reads through: the events seam, anyone's public records,
/// the run's cache of homeservers, and the pace of a head search
/// (`events::SEARCH_PACE` for a real homeserver, zero in the tests).
///
/// A struct rather than four more arguments. Two lifetimes, as for the
/// roster poll: `'a` is how long the watcher borrows the readers and the
/// cache, `'h` how long the cache borrows its resolver.
pub(crate) struct FeedReaders<'a, 'h, F, R, H> {
    pub(crate) feed: &'a F,
    pub(crate) records: &'a R,
    pub(crate) homeservers: &'a mut Homeservers<'h, H>,
    pub(crate) pace: Duration,
}

/// Watches the feeds of `watch_list` for strangers' sweeps of `owner`'s
/// open bounties, and confirms the sweeps their `discovered.json` list,
/// outside `roster`, bringing `state` up to date: see the module docs.
///
/// The cursors in `dirs` move on after each batch, with `state` written
/// first, so a sweep accepted is in the poll state's file before the
/// cursor moves past its event: a run stopped between the two reads the
/// page again next time, and accepts nothing twice. A step whose changes
/// the file has no room for is dropped, its cursor kept, with a warning,
/// and nothing more is read. Writing `state` once more at the end, for
/// what came after the last batch, is the caller's. Only a failure to
/// read or write those local files is an error.
pub(crate) async fn watch_open_bounties<F, R, H>(
    readers: FeedReaders<'_, '_, F, R, H>,
    dirs: &Dirs,
    owner: Pubky,
    roster: &Circle,
    watch_list: &[Pubky],
    state: &mut PollState,
) -> anyhow::Result<FeedWatch>
where
    F: EventsFeed,
    R: PublicRecords,
    H: ResolveHomeserver,
{
    let open = open_to_strangers(state, owner);
    // A tag is kept for an open bounty's file alone: no other is read, and
    // should a bounty open again, its file's cursors are wanted whole.
    state.discovered_etags.retain(|id, _| open.contains(id));
    if open.is_empty() {
        FeedCursors::drop_owner(dirs, owner)?;
        return Ok(FeedWatch::default());
    }
    // Taking the struct apart moves each borrow out of it, one field each.
    let FeedReaders {
        feed,
        records,
        homeservers,
        pace,
    } = readers;
    let mut watcher = Watcher {
        feed,
        records,
        homeservers,
        dirs,
        owner,
        roster,
        state,
        open,
        given_up: BTreeSet::new(),
        bounties_full: BTreeSet::new(),
        poll_state_full: false,
        found: FeedWatch::default(),
    };
    let listed = watcher.read_discovered().await?;
    // With no room for what the listings added, a feed's would have none
    // either, so no feed is read.
    if watcher.poll_state_full {
        return Ok(watcher.found);
    }
    let starts = watcher.starts(watch_list, &listed, pace).await?;
    for (&homeserver, start) in &starts {
        watcher.read_feed(homeserver, start.cursor).await?;
    }
    watcher.found.starts = starts;
    Ok(watcher.found)
}

/// The ids of `owner`'s bounties in `state` that are open to strangers:
/// `open: true`, with status `open`. `pull::discovered` writes the
/// `discovered.json` of these alone.
pub(super) fn open_to_strangers(state: &PollState, owner: Pubky) -> BTreeSet<RecordId> {
    state
        .bounties
        .iter()
        .filter(|(bounty, summary)| {
            bounty.owner == owner
                && summary.open
                && summary.status.as_known() == Some(KnownBountyStatus::Open)
        })
        .map(|(bounty, _)| bounty.id)
        .collect()
}

/// The cursor `page` goes on from, asked for the events after `asked`, or
/// why the feed stops there: core's `FeedPage::cursor` is the homeserver's
/// word, so whether it moved forward is checked here.
fn next_cursor(page: &FeedPage, asked: EventCursor) -> Result<EventCursor, &'static str> {
    match page.cursor() {
        None => Err(NO_CURSOR),
        // A match guard (`if` after the pattern): this arm takes a cursor at
        // or below the one asked for, which would ask for the same events
        // again.
        Some(next) if next <= asked => Err(CURSOR_NOT_FORWARD),
        Some(next) => Ok(next),
    }
}

/// How one batch of a feed ended.
enum Batch {
    /// Processed and stored: the feed goes on from `next`, and `full` says
    /// whether the page was full, so that more may follow at once.
    Read { next: EventCursor, full: bool },
    /// Nothing more of this feed this run: caught up, or stopped with a
    /// warning.
    Stop,
}

/// How confirming the sweeps one `discovered.json` lists ended.
enum Listed {
    /// Every sweep it lists is settled: accepted now or before, not one to
    /// accept, unreadable, or confirmed gone.
    Settled,
    /// Some are to confirm again next run: their sweeper could not be read.
    Unsettled,
    /// The run's budget ran out before the list did.
    OutOfBudget,
}

/// What the watcher reads through, and what it has found so far.
///
/// Generic over the three seams, as the roster's `Poller` is over its two;
/// `'w` is how long it borrows them, the state and the roster, and `'h`
/// how long the cache borrows its resolver.
struct Watcher<'w, 'h, F, R, H> {
    feed: &'w F,
    records: &'w R,
    homeservers: &'w mut Homeservers<'h, H>,
    dirs: &'w Dirs,
    owner: Pubky,
    roster: &'w Circle,
    state: &'w mut PollState,
    /// The owner's bounties open to strangers this run, by id.
    open: BTreeSet<RecordId>,
    /// The sweepers read no more this run: unreachable, or a read failed.
    given_up: BTreeSet<Pubky>,
    /// The open bounties found with no room for another stranger's sweep
    /// this run, each named in one warning.
    bounties_full: BTreeSet<RecordId>,
    /// Whether the poll state's file had no room for a step's changes: the
    /// step was dropped, and nothing more is read this run.
    poll_state_full: bool,
    /// What the run found so far.
    found: FeedWatch,
}

/// What the watcher held before a step that changes the poll state, to go
/// back to when the file has no room for the step's changes.
struct Before {
    /// The whole poll state.
    state: PollState,
    /// How many sweeps the run had accepted.
    accepted: usize,
    /// How many deletions the run had confirmed.
    deleted: usize,
}

impl<F: EventsFeed, R: PublicRecords, H: ResolveHomeserver> Watcher<'_, '_, F, R, H> {
    /// Reads each open bounty's `discovered.json`, confirms the sweeps it
    /// lists that are new to this install, stores the poll state, and gives
    /// the lowest cursor the files give each homeserver, in memory only.
    async fn read_discovered(&mut self) -> anyhow::Result<FeedCursors> {
        let before = self.before_step();
        let mut lowest = FeedCursors::default();
        let mut budget = MAX_LISTED_SWEEPS_PER_RUN;
        let mut cut = false;
        // A copy of the ids, so that `self` is not borrowed by the loop
        // while its body changes the state.
        let open: Vec<RecordId> = self.open.iter().copied().collect();
        for id in open {
            let Some((discovered, etag)) = self.read_one_discovered(id).await else {
                continue;
            };
            // Iterating a `&BTreeMap` lends each key and value; `&homeserver`
            // and `&cursor` copy them out, as both are `Copy`.
            for (&homeserver, &cursor) in &discovered.cursors {
                lowest.lower_to(homeserver, cursor);
            }
            let listed = self
                .confirm_listed(id, &discovered.sweeps, &mut budget)
                .await;
            cut |= matches!(listed, Listed::OutOfBudget);
            match (listed, etag) {
                (Listed::Settled, Some(etag)) => {
                    self.state.discovered_etags.insert(id, etag);
                }
                // Read whole again next run, so the rest is confirmed then.
                _ => {
                    self.state.discovered_etags.remove(&id);
                }
            }
        }
        if cut {
            self.warn(format_args!(
                "your open bounties' discovered.json list more than \
                 {MAX_LISTED_SWEEPS_PER_RUN} sweeps new to this install; pull confirms that \
                 many this time and the rest next time"
            ));
        }
        // Stored before any feed is read, as a batch is, so that a feed's
        // batch dropped for want of room goes back to a state that fits.
        self.keep_step(before)?;
        Ok(lowest)
    }

    /// Bounty `id`'s `discovered.json` with the tag its answer gave, when
    /// it changed since the tag kept; `None` when it did not, when there is
    /// none, or when it could not be read, with a warning.
    async fn read_one_discovered(&mut self, id: RecordId) -> Option<(Discovered, Option<ETag>)> {
        let path = paths::discovered(id);
        let etag = self.state.discovered_etags.get(&id).cloned();
        let answer = self
            .records
            .get_record_if_changed(self.owner, &path, etag.as_ref())
            .await;
        let (body, etag) = match answer {
            Ok(Conditional::Changed { body, etag }) => (body, etag),
            // Unchanged since its sweeps were settled and its cursors used.
            Ok(Conditional::NotModified) => return None,
            // None yet, as after a refused write: the discovered.json write
            // makes one.
            Ok(Conditional::Absent) => {
                self.state.discovered_etags.remove(&id);
                return None;
            }
            Err(error) => {
                self.warn(format_args!(
                    "pull could not read the discovered sweeps of one of your bounties this \
                     time: {error:#}"
                ));
                return None;
            }
        };
        // Core's `from_json` refuses more than `MAX_RECORD_BYTES` before it
        // parses anything, and its error quotes nothing of the file.
        match Discovered::from_json(&body)
            .with_context(|| not_a_record("discovered-sweeps", &path, self.owner))
        {
            Ok(discovered) => Some((discovered, etag)),
            Err(error) => {
                self.state.discovered_etags.remove(&id);
                self.warn(format_args!("pull skipped a record: {error:#}"));
                None
            }
        }
    }

    /// Confirms each of `sweeps`, listed in bounty `id`'s
    /// `discovered.json`, that is by a sweeper outside the roster and new to
    /// this install, at most `budget` of them, which it counts down.
    async fn confirm_listed(
        &mut self,
        id: RecordId,
        sweeps: &[SweepRef],
        budget: &mut usize,
    ) -> Listed {
        let mut listed = Listed::Settled;
        for &sweep in sweeps {
            if self.roster.is_in_roster(sweep.sweeper) || self.seen(sweep) {
                continue;
            }
            // `checked_sub` gives `None` rather than wrapping below zero.
            let Some(left) = budget.checked_sub(1) else {
                return Listed::OutOfBudget;
            };
            *budget = left;
            match self.refetch(sweep).await {
                Some(Fetched::Record { record, etag }) => self.accept(sweep, &record, etag),
                Some(Fetched::Absent) => self.record_deletion(id, sweep),
                Some(Fetched::Unreadable(error)) => self.skipped(&error),
                // No tag is sent for a sweep this install has not accepted,
                // so no 304 can come.
                Some(Fetched::Unchanged) => {}
                None => listed = Listed::Unsettled,
            }
        }
        listed
    }

    /// Where each feed of `watch_list` starts: see the module docs. A start
    /// that did not come from the local file is stored there before any page
    /// is read. A head search waits `pace` between its requests.
    async fn starts(
        &mut self,
        watch_list: &[Pubky],
        listed: &FeedCursors,
        pace: Duration,
    ) -> anyhow::Result<BTreeMap<Pubky, Start>> {
        let local = FeedCursors::read(self.dirs, self.owner)?;
        let mut starts = BTreeMap::new();
        for &homeserver in watch_list {
            if let Some(start) = self.start_of(homeserver, &local, listed, pace).await {
                starts.insert(homeserver, start);
            }
        }
        self.store_new_starts(&starts)?;
        Ok(starts)
    }

    /// Where `homeserver`'s feed starts: at its cursor in `local`, else in
    /// `listed`, else at its head, searched for now with a warning. `None`,
    /// with a warning, when the search fails.
    async fn start_of(
        &mut self,
        homeserver: Pubky,
        local: &FeedCursors,
        listed: &FeedCursors,
        pace: Duration,
    ) -> Option<Start> {
        // Guard clauses, in order of precedence: the local file wins.
        if let Some(cursor) = local.get(&homeserver) {
            let source = StartSource::Local;
            return Some(Start { cursor, source });
        }
        if let Some(cursor) = listed.get(&homeserver) {
            let source = StartSource::Discovered;
            return Some(Start { cursor, source });
        }
        match find_head(self.feed, homeserver, pace).await {
            Ok(cursor) => {
                self.warn(format_args!(
                    "no starting cursor is known for the events feed of {homeserver}, so pull \
                     starts at its head, event {cursor}: a stranger's sweep written there \
                     before now is seen only if an open bounty's discovered.json lists it"
                ));
                Some(Start {
                    cursor,
                    source: StartSource::HeadSearch,
                })
            }
            Err(error) => {
                self.warn(format_args!(
                    "pull skipped the events feed of {homeserver} this time: no starting \
                     cursor is known for it, and {error:#}"
                ));
                None
            }
        }
    }

    /// Stores each of `starts` that did not come from the local file, so the
    /// next run starts there too: a `discovered.json` read once with its tag
    /// is not read for its cursors again, and a head searched once is not
    /// searched again. Each is lowered into the file, never raising a cursor
    /// another writer stored meanwhile.
    fn store_new_starts(&self, starts: &BTreeMap<Pubky, Start>) -> anyhow::Result<()> {
        if starts
            .values()
            .all(|start| start.source == StartSource::Local)
        {
            return Ok(());
        }
        let mut stored = FeedCursors::read(self.dirs, self.owner)?;
        for (&homeserver, start) in starts {
            if start.source != StartSource::Local {
                stored.lower_to(homeserver, start.cursor);
            }
        }
        stored
            .write(self.dirs, self.owner)
            .context("could not store where the events feeds start")
    }

    /// Reads `homeserver`'s feed from `cursor`, a batch at a time, at most
    /// [`MAX_FEED_PAGES_PER_RUN`] of them, while each page is full.
    async fn read_feed(
        &mut self,
        homeserver: Pubky,
        mut cursor: EventCursor,
    ) -> anyhow::Result<()> {
        // Once a step was dropped for want of room, no feed is read on.
        if self.poll_state_full {
            return Ok(());
        }
        for _ in 0..MAX_FEED_PAGES_PER_RUN {
            match self.batch(homeserver, cursor).await? {
                Batch::Read { next, full: true } => cursor = next,
                Batch::Read { full: false, .. } | Batch::Stop => return Ok(()),
            }
        }
        self.warn(format_args!(
            "the events feed of {homeserver} has more than {MAX_FEED_PAGES_PER_RUN} pages of new \
             events; pull reads the rest next time"
        ));
        Ok(())
    }

    /// Reads, processes and stores the page of `homeserver`'s feed after
    /// `cursor`: see the module docs.
    async fn batch(&mut self, homeserver: Pubky, cursor: EventCursor) -> anyhow::Result<Batch> {
        let page = match self.feed.page(homeserver, cursor, FEED_PAGE_SIZE).await {
            Ok(page) => page,
            // A page with more events than asked for among them: the seam
            // refuses it, in fixed text.
            Err(error) => return Ok(self.stop_feed(homeserver, format_args!("{error:#}"))),
        };
        if page.is_caught_up() {
            return Ok(Batch::Stop);
        }
        let next = match next_cursor(&page, cursor) {
            Ok(next) => next,
            Err(why) => return Ok(self.stop_feed(homeserver, why)),
        };
        let before = self.before_step();
        self.act_on(&page).await;
        // The poll state first, then the cursor: see `watch_open_bounties`.
        // A batch dropped for want of room leaves the cursor where it was.
        if !self.keep_step(before)? {
            return Ok(Batch::Stop);
        }
        if !FeedCursors::advance(self.dirs, self.owner, homeserver, cursor, next)? {
            return Ok(self.stop_feed(homeserver, CURSOR_MOVED));
        }
        // A line this build does not read is still a line the homeserver
        // counted against the limit, so a page is full by its lines.
        let lines = page.events().len().saturating_add(page.malformed());
        Ok(Batch::Read {
            next,
            full: lines >= usize::from(FEED_PAGE_SIZE),
        })
    }

    /// Acts on each sweep record `page` names, by a sweeper outside the
    /// roster, by its last operation there.
    async fn act_on(&mut self, page: &FeedPage) {
        // `sweep_records` owns what it gives (two `Copy` values a pair), so
        // the loop does not borrow the page while `self` changes.
        for (op, sweep) in page.sweep_records() {
            if self.roster.is_in_roster(sweep.sweeper) {
                continue;
            }
            match op {
                FeedOp::Put => self.on_put(sweep).await,
                FeedOp::Del => self.on_del(sweep).await,
            }
        }
    }

    /// Stops `homeserver`'s feed for the run, with a warning that says why.
    // `impl fmt::Display` takes the fixed texts above and `format_args!`
    // alike, so no `String` is built before the warning's own.
    fn stop_feed(&mut self, homeserver: Pubky, why: impl fmt::Display) -> Batch {
        self.warn(format_args!(
            "pull reads no more of the events feed of {homeserver} this time: {why}"
        ));
        Batch::Stop
    }

    /// A `PUT` of `sweep`'s record: reads it, and accepts it when it is one.
    async fn on_put(&mut self, sweep: SweepRef) {
        // A sweep new to this install could be accepted only into room, so
        // once no open bounty has any, it is not even read: a flood's later
        // pages cost no reads of its keys' storage.
        if self.accepted_for(sweep).is_none() && self.no_open_bounty_has_room() {
            return;
        }
        match self.refetch(sweep).await {
            Some(Fetched::Record { record, etag }) => self.accept(sweep, &record, etag),
            Some(Fetched::Unreadable(error)) => self.skipped(&error),
            // A 304, unchanged since it was accepted; a 404, gone since,
            // whose `DEL` comes later; or skipped with a warning.
            Some(Fetched::Unchanged | Fetched::Absent) | None => {}
        }
    }

    /// A `DEL` of `sweep`'s record: drops the sweep only if this install
    /// accepted it and its sweeper's storage now answers 404 for it.
    async fn on_del(&mut self, sweep: SweepRef) {
        let Some(bounty) = self.accepted_for(sweep) else {
            return;
        };
        // Anything but a 404 says the record is still there, and the `DEL`
        // is not taken.
        if let Some(Fetched::Absent) = self.refetch(sweep).await {
            self.record_deletion(bounty, sweep);
        }
    }

    /// Reads `sweep`'s record from its sweeper's own storage, once their
    /// homeserver resolves, with the tag of its last answer when this
    /// install accepted it. `None` when the sweeper is read no more this
    /// run, with one warning the first time.
    async fn refetch(&mut self, sweep: SweepRef) -> Option<Fetched<Sweep>> {
        let sweeper = sweep.sweeper;
        if self.given_up.contains(&sweeper) {
            return None;
        }
        // The lookup is the gate: a key with no homeserver, or one the host
        // policy refuses, is not read at all. The homeserver itself is not
        // used: the read resolves the key again inside the SDK.
        if let Err(why) = self.homeservers.resolve(sweeper).await {
            self.give_up(sweeper, format_args!("{why}"));
            return None;
        }
        // A copy of the tag, so the state is not borrowed during the read.
        let etag = self
            .accepted_for(sweep)
            .and_then(|_| self.state.sweeps.get(&sweep))
            .and_then(|summary| summary.etag.clone());
        match fetch::<Sweep>(self.records, sweeper, sweep.id, etag.as_ref()).await {
            Ok(fetched) => Some(fetched),
            Err(Stop::ReadFailed(error)) => {
                // Looked up again, as the roster poll does, so the rest of
                // the run uses what the key's record says now.
                let again = match self.homeservers.after_failed_read(sweeper).await {
                    Ok(_) => String::new(),
                    Err(why) => format!("; looked up again, {why}"),
                };
                self.give_up(sweeper, format_args!("{error:#}{again}"));
                None
            }
            // `fetch` gives no other, but should it, the sweeper is skipped.
            Err(Stop::Unreachable(why)) => {
                self.give_up(sweeper, format_args!("{why}"));
                None
            }
        }
    }

    /// Takes `record`, just read as `sweep`'s: accepts the sweep when the
    /// record names one of the owner's bounties open to strangers, and
    /// brings the summary of a sweep accepted before up to date, whatever its
    /// bounty's status now. A sweep of any other bounty leaves nothing.
    fn accept(&mut self, sweep: SweepRef, record: &Sweep, etag: Option<ETag>) {
        let bounty = record.bounty;
        if bounty.owner != self.owner {
            return;
        }
        let before = self
            .state
            .accepted_sweeps
            .get(&bounty.id)
            .is_some_and(|accepted| accepted.contains(&sweep));
        if !before && !self.open.contains(&bounty.id) {
            return;
        }
        if !before && !self.has_room_for(bounty.id) {
            self.leave_out(bounty.id);
            return;
        }
        match self.state.sweeps.get_mut(&sweep) {
            Some(summary) => summary.update(record, etag),
            None => {
                self.state
                    .sweeps
                    .insert(sweep, SweepSummary::new(record, etag));
            }
        }
        if !before {
            self.state
                .accepted_sweeps
                .entry(bounty.id)
                .or_default()
                .insert(sweep);
            // Deleted once, and written again since.
            self.state.deleted_sweeps.remove(&sweep);
            self.found.accepted.push(BountySweep {
                bounty: bounty.id,
                sweep,
            });
        }
    }

    /// Whether the poll state has room for one more stranger's sweep of
    /// bounty `id`: [`MAX_ACCEPTED_PER_BOUNTY`] for the bounty, and
    /// [`MAX_STRANGERS_SWEEPS_KEPT`] in all, deletions included.
    fn has_room_for(&self, id: RecordId) -> bool {
        // `map_or` gives 0 for a bounty with no sweep accepted yet; the
        // function `BTreeSet::len` counts each set, as `|set| set.len()`
        // would.
        let of_bounty = self.state.accepted_sweeps.get(&id).map_or(0, BTreeSet::len);
        of_bounty < MAX_ACCEPTED_PER_BOUNTY
            && self.strangers_sweeps_kept() < MAX_STRANGERS_SWEEPS_KEPT
    }

    /// How many strangers' sweeps the poll state keeps: accepted for any of
    /// the owner's bounties, or confirmed deleted.
    fn strangers_sweeps_kept(&self) -> usize {
        let accepted: usize = self.state.accepted_sweeps.values().map(BTreeSet::len).sum();
        accepted.saturating_add(self.state.deleted_sweeps.len())
    }

    /// Whether every open bounty was found with no room this run, so that
    /// no new stranger's sweep could be accepted.
    fn no_open_bounty_has_room(&self) -> bool {
        // Every bounty `leave_out` names is open, so this is the two sets
        // being equal.
        self.open.is_subset(&self.bounties_full)
    }

    /// Leaves a new stranger's sweep of bounty `id` out for want of room,
    /// with one warning a bounty a run, which names the bounty.
    fn leave_out(&mut self, id: RecordId) {
        // `insert` says whether `id` was new to the set: the first sweep of
        // this bounty left out this run.
        if self.bounties_full.insert(id) {
            let bounty = BountyRef {
                owner: self.owner,
                id,
            };
            self.warn(format_args!(
                "pull leaves out new strangers' sweeps of your bounty {bounty} this time: it \
                 keeps at most {MAX_ACCEPTED_PER_BOUNTY} accepted for one bounty and \
                 {MAX_STRANGERS_SWEEPS_KEPT} strangers' sweeps in all, deleted ones included, \
                 and has no room for more"
            ));
        }
    }

    /// What the watcher holds now, before a step that changes the poll
    /// state. A copy of the whole state: each step already reads, parses
    /// and rewrites the whole file, so the copy costs less than its write.
    fn before_step(&self) -> Before {
        Before {
            state: self.state.clone(),
            accepted: self.found.accepted.len(),
            deleted: self.found.deleted.len(),
        }
    }

    /// Writes the poll state with the changes of the step that began at
    /// `before`, and says whether they are kept. When the file has no room
    /// for them ([`WouldPassCap`], which leaves the file as it was), the
    /// state and what the run found go back to `before`, so a later write
    /// of the state has the room it had, and nothing more is read this run,
    /// with a warning. A file that could not be written at all is an error.
    fn keep_step(&mut self, before: Before) -> anyhow::Result<bool> {
        match self.state.write(self.dirs, self.owner) {
            Ok(()) => return Ok(true),
            // `downcast_ref` finds `state`'s typed refusal under any context
            // added to it: the file is as it was, and the run can go on.
            Err(error) if error.downcast_ref::<WouldPassCap>().is_some() => {}
            Err(error) => return Err(error),
        }
        // `*` writes through the `&mut` into the caller's state itself.
        *self.state = before.state;
        // `truncate` drops what the step pushed and keeps what came before.
        self.found.accepted.truncate(before.accepted);
        self.found.deleted.truncate(before.deleted);
        self.poll_state_full = true;
        self.warn(format_args!("{POLL_STATE_FULL}"));
        Ok(false)
    }

    /// Records that `sweep`, of bounty `bounty`, is gone from its sweeper's
    /// storage: no longer accepted, no summary, and deleted.
    fn record_deletion(&mut self, bounty: RecordId, sweep: SweepRef) {
        if let Some(accepted) = self.state.accepted_sweeps.get_mut(&bounty) {
            accepted.remove(&sweep);
        }
        self.state.sweeps.remove(&sweep);
        self.state.deleted_sweeps.insert(sweep);
        self.found.deleted.push(BountySweep { bounty, sweep });
    }

    /// The bounty `sweep` was accepted for, if this install accepted it.
    fn accepted_for(&self, sweep: SweepRef) -> Option<RecordId> {
        self.state
            .accepted_sweeps
            .iter()
            .find(|(_, accepted)| accepted.contains(&sweep))
            .map(|(&bounty, _)| bounty)
    }

    /// Whether this install accepted `sweep`, or confirmed it gone.
    fn seen(&self, sweep: SweepRef) -> bool {
        self.state.deleted_sweeps.contains(&sweep) || self.accepted_for(sweep).is_some()
    }

    /// Reads `sweeper`'s storage no more this run, with a warning that says
    /// why.
    fn give_up(&mut self, sweeper: Pubky, why: fmt::Arguments<'_>) {
        self.given_up.insert(sweeper);
        self.warn(format_args!(
            "pull reads no more sweeps of {sweeper} this time: {why}"
        ));
    }

    /// Warns of a record skipped: `error` names its path and key.
    fn skipped(&mut self, error: &anyhow::Error) {
        self.warn(format_args!("pull skipped a record: {error:#}"));
    }

    /// Adds a warning.
    // `fmt::Arguments` is what `format_args!` builds: the pieces of a
    // message, borrowed, written into the one `String` kept here.
    fn warn(&mut self, warning: fmt::Arguments<'_>) {
        self.found.warnings.push(warning.to_string());
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::time::Duration;

    use serde_json::{Map, Value, json};
    use sweepky_core::paths;
    use sweepky_core::{
        Bounty, BountyRef, Circle, EventCursor, KnownSweepStatus, Pubky, Sweep, SweepRef,
    };
    use tempfile::TempDir;

    use super::{
        BountySweep, CURSOR_NOT_FORWARD, FeedReaders, FeedWatch, MAX_ACCEPTED_PER_BOUNTY,
        MAX_FEED_PAGES_PER_RUN, MAX_STRANGERS_SWEEPS_KEPT, NO_CURSOR, POLL_STATE_FULL, Start,
        StartSource, watch_open_bounties,
    };
    use crate::Dirs;
    use crate::pull::resolve::Homeservers;
    use crate::pull::state::{BountySummary, FeedCursors, PollState, SweepSummary};
    use crate::remote::ETag;
    use crate::test_support::{
        FakeEventsFeed, FakeHomeservers, FakeLookup, FakePublicRecords, PLANTED, bounty_json,
        circle_json, dirs_in, events_page, feed_page, json_bytes, private_temp, random_pubky,
        record_id, repo_target_json, sweep_json,
    };

    /// One owner's install: its data directory, its roster, and the
    /// homeservers it watches, one unless a test says otherwise.
    struct Install {
        // Held so the directory lives as long as the install; never read.
        _temp: TempDir,
        dirs: Dirs,
        owner: Pubky,
        roster: Circle,
        /// The homeserver watched first.
        home: Pubky,
        watch_list: Vec<Pubky>,
    }

    impl Install {
        /// A fresh install of a new owner, with no circle, watching one
        /// homeserver.
        fn new() -> Self {
            let temp = private_temp();
            let dirs = dirs_in(&temp);
            let (owner, home) = (random_pubky(), random_pubky());
            Self {
                _temp: temp,
                dirs,
                owner,
                roster: circle(owner, &[]),
                home,
                watch_list: vec![home],
            }
        }

        /// The same install, its circle listing `members` too.
        fn with_members(mut self, members: &[Pubky]) -> Self {
            self.roster = circle(self.owner, members);
            self
        }

        /// Stores `cursor` as this owner's local cursor on `homeserver`.
        fn store_cursor(&self, homeserver: Pubky, cursor: u64) {
            let mut cursors = FeedCursors::read(&self.dirs, self.owner).expect("reads");
            cursors.set(homeserver, EventCursor::new(cursor));
            cursors.write(&self.dirs, self.owner).expect("written");
        }

        /// This owner's local cursor on `homeserver`, as a fresh reader
        /// finds it.
        fn stored_cursor(&self, homeserver: Pubky) -> Option<u64> {
            FeedCursors::read(&self.dirs, self.owner)
                .expect("reads")
                .get(&homeserver)
                .map(EventCursor::id)
        }

        /// One run of the watcher, as `pull` runs it: a fresh cache of
        /// homeservers, and no pause in a head search.
        async fn watch(
            &self,
            feed: &FakeEventsFeed,
            records: &FakePublicRecords,
            resolver: &FakeHomeservers,
            state: &mut PollState,
        ) -> FeedWatch {
            let mut homeservers = Homeservers::new(resolver);
            let readers = FeedReaders {
                feed,
                records,
                homeservers: &mut homeservers,
                pace: Duration::ZERO,
            };
            watch_open_bounties(
                readers,
                &self.dirs,
                self.owner,
                &self.roster,
                &self.watch_list,
                state,
            )
            .await
            .expect("watched")
        }
    }

    /// The circle `admin` keeps, listing `members`.
    fn circle(admin: Pubky, members: &[Pubky]) -> Circle {
        Circle::from_json(&json_bytes(&circle_json(admin, members))).expect("a circle")
    }

    /// Bounty `n` of `owner`.
    fn bounty(owner: Pubky, n: u64) -> BountyRef {
        BountyRef {
            owner,
            id: record_id(n),
        }
    }

    /// Sweep `n` of a new stranger.
    fn stranger_sweep(n: u64) -> SweepRef {
        SweepRef {
            sweeper: random_pubky(),
            id: record_id(n),
        }
    }

    /// A bounty record of one target, open to strangers or not, with
    /// `status`.
    fn bounty_record(open: bool, status: &str) -> Value {
        let mut record = bounty_json(json!([repo_target_json("t1")]));
        record["open"] = json!(open);
        record["status"] = json!(status);
        if status == "done" {
            record["doneAt"] = json!("2026-10-19T10:00:00Z");
        }
        record
    }

    /// The poll state of a roster poll that read `bounties`, each with its
    /// record.
    fn state_of(bounties: &[(BountyRef, Value)]) -> PollState {
        let mut state = PollState::default();
        for (bounty, record) in bounties {
            let record = Bounty::from_json(&json_bytes(record)).expect("a bounty");
            state
                .bounties
                .insert(*bounty, BountySummary::new(&record, None));
        }
        state
    }

    /// The poll state of one bounty, `open`, open to strangers.
    fn one_open(open: BountyRef) -> PollState {
        state_of(&[(open, bounty_record(true, "open"))])
    }

    /// The feed line of a write of `sweep`'s record.
    fn put(sweep: SweepRef) -> String {
        format!("PUT {}", sweep.url())
    }

    /// The feed line of a deletion of `sweep`'s record.
    fn del(sweep: SweepRef) -> String {
        format!("DEL {}", sweep.url())
    }

    /// `records` holding `sweep`'s record too: of `bounty`, with `status`.
    fn with_sweep(
        records: FakePublicRecords,
        sweep: SweepRef,
        bounty: BountyRef,
        status: &str,
    ) -> FakePublicRecords {
        records.with_record(
            sweep.sweeper,
            &paths::sweep_record(sweep.id),
            &sweep_json(bounty, &["t1"], status),
        )
    }

    /// An open bounty's `discovered.json`, listing `sweeps`, with
    /// `cursors`.
    fn discovered_json(sweeps: &[SweepRef], cursors: &[(Pubky, u64)]) -> Value {
        let cursors: Map<String, Value> = cursors
            .iter()
            .map(|(homeserver, cursor)| (homeserver.to_string(), json!(cursor.to_string())))
            .collect();
        let sweeps: Vec<String> = sweeps.iter().map(ToString::to_string).collect();
        json!({ "schemaVersion": 1, "sweeps": sweeps, "cursors": cursors })
    }

    /// How many times `sweep`'s record was read so far.
    fn reads_of(records: &FakePublicRecords, sweep: SweepRef) -> usize {
        let record = (sweep.sweeper, paths::sweep_record(sweep.id));
        records
            .asked()
            .iter()
            .filter(|&asked| *asked == record)
            .count()
    }

    /// `sweep` of `bounty`, as the watch reports it.
    fn of(bounty: BountyRef, sweep: SweepRef) -> BountySweep {
        BountySweep {
            bounty: bounty.id,
            sweep,
        }
    }

    /// The start at `cursor`, from `source`.
    fn start(cursor: u64, source: StartSource) -> Start {
        Start {
            cursor: EventCursor::new(cursor),
            source,
        }
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
    async fn a_stranger_s_sweep_found_through_the_feed_is_accepted_once() {
        // The unit form of 06's "C found through `/events/`".
        let install = Install::new();
        let open = bounty(install.owner, 10);
        let found = stranger_sweep(20);
        install.store_cursor(install.home, 0);
        // Its running PUT, its package's PUT and its done PUT, on one page.
        let feed = FakeEventsFeed::of_events(vec![
            (1, put(found)),
            (2, format!("PUT {}", found.package_url())),
            (3, put(found)),
        ]);
        let records = with_sweep(FakePublicRecords::default(), found, open, "done");
        let resolver = FakeHomeservers::default();
        let mut state = one_open(open);

        let watch = install.watch(&feed, &records, &resolver, &mut state).await;
        assert!(watch.warnings.is_empty(), "{:?}", watch.warnings);
        assert_eq!(watch.accepted, [of(open, found)]);
        assert!(watch.deleted.is_empty());
        // The open bounty's discovered.json, from the owner's storage, then
        // the sweep's record, once: never its package.
        assert_eq!(
            records.asked(),
            [
                (install.owner, paths::discovered(open.id)),
                (found.sweeper, paths::sweep_record(found.id)),
            ]
        );
        assert_eq!(state.accepted_sweeps[&open.id], BTreeSet::from([found]));
        let summary = &state.sweeps[&found];
        assert_eq!(summary.status.as_known(), Some(KnownSweepStatus::Done));
        assert!(!summary.pulled);
        assert_eq!(install.stored_cursor(install.home), Some(3));
    }

    #[tokio::test]
    async fn each_record_is_read_from_its_sweeper_s_own_storage_once_its_homeserver_resolves() {
        let install = Install::new();
        let open = bounty(install.owner, 10);
        let (reachable, unreachable) = (stranger_sweep(20), stranger_sweep(21));
        install.store_cursor(install.home, 0);
        // The feed holds lines and no record bytes.
        let feed = FakeEventsFeed::of_events(vec![(1, put(reachable)), (2, put(unreachable))]);
        let records = with_sweep(FakePublicRecords::default(), reachable, open, "running");
        let records = with_sweep(records, unreachable, open, "running");
        let resolver =
            FakeHomeservers::default().with_answers(unreachable.sweeper, &[FakeLookup::NoRecord]);
        let mut state = one_open(open);

        let watch = install.watch(&feed, &records, &resolver, &mut state).await;
        assert_eq!(watch.accepted, [of(open, reachable)]);
        // Only the watched homeserver is asked for events; each sweeper is
        // looked up, and only one whose homeserver resolves is read, from
        // its own storage.
        assert_eq!(feed.homeservers_asked(), BTreeSet::from([install.home]));
        assert_eq!(resolver.asked(), [reachable.sweeper, unreachable.sweeper]);
        assert_eq!(
            records.asked(),
            [
                (install.owner, paths::discovered(open.id)),
                (reachable.sweeper, paths::sweep_record(reachable.id)),
            ]
        );
        assert_eq!(watch.warnings.len(), 1, "{:?}", watch.warnings);
        assert!(watch.warnings[0].contains(&unreachable.sweeper.to_string()));
        assert!(watch.warnings[0].contains("no homeserver"));
    }

    #[tokio::test]
    async fn the_roster_s_sweeps_and_those_of_bounties_not_open_or_unreadable_are_not_accepted() {
        let member = random_pubky();
        let install = Install::new().with_members(&[member]);
        let owner = install.owner;
        let (open, closed, done) = (bounty(owner, 10), bounty(owner, 11), bounty(owner, 12));
        let theirs = bounty(random_pubky(), 13);
        let in_circle = SweepRef {
            sweeper: member,
            id: record_id(20),
        };
        let (of_theirs, of_closed, of_done) =
            (stranger_sweep(21), stranger_sweep(22), stranger_sweep(23));
        let (unreadable, accepted) = (stranger_sweep(24), stranger_sweep(25));
        let records = FakePublicRecords::default().with_file(
            unreadable.sweeper,
            &paths::sweep_record(unreadable.id),
            format!("{{\"schemaVersion\": 1, \"bounty\": \"{PLANTED}\"}}").into_bytes(),
        );
        let records = with_sweep(records, in_circle, open, "running");
        let records = with_sweep(records, of_theirs, theirs, "running");
        let records = with_sweep(records, of_closed, closed, "running");
        let records = with_sweep(records, of_done, done, "running");
        let records = with_sweep(records, accepted, open, "running");
        install.store_cursor(install.home, 0);
        let feed = FakeEventsFeed::of_events(
            [
                in_circle, of_theirs, of_closed, of_done, unreadable, accepted,
            ]
            .into_iter()
            .zip(1..)
            .map(|(sweep, id)| (id, put(sweep)))
            .collect(),
        );
        let resolver = FakeHomeservers::default();
        // The roster poll's summaries: open to strangers, closed to them
        // (`open: false`), and done.
        let mut state = state_of(&[
            (open, bounty_record(true, "open")),
            (closed, bounty_record(false, "open")),
            (done, bounty_record(true, "done")),
        ]);

        let watch = install.watch(&feed, &records, &resolver, &mut state).await;
        assert_eq!(watch.accepted, [of(open, accepted)]);
        // The circle's sweep is the roster poll's: it is not even read here.
        assert_eq!(reads_of(&records, in_circle), 0);
        // Nothing of the rest is kept.
        assert_eq!(state.accepted_sweeps.len(), 1);
        assert_eq!(state.sweeps.keys().copied().collect::<Vec<_>>(), [accepted]);
        // The record that does not parse is a warning that names it and
        // quotes none of it.
        assert_eq!(watch.warnings.len(), 1, "{:?}", watch.warnings);
        assert!(watch.warnings[0].contains(&unreadable.sweeper.to_string()));
        assert_quotes_nothing(&watch.warnings);
    }

    #[tokio::test]
    async fn a_del_drops_a_sweep_only_once_its_record_is_gone() {
        let install = Install::new();
        let open = bounty(install.owner, 10);
        let (kept, gone, unknown) = (stranger_sweep(20), stranger_sweep(21), stranger_sweep(22));
        install.store_cursor(install.home, 0);
        let records = with_sweep(FakePublicRecords::default(), kept, open, "done");
        let records = with_sweep(records, gone, open, "done");
        let resolver = FakeHomeservers::default();
        let mut state = one_open(open);
        let first = FakeEventsFeed::of_events(vec![(1, put(kept)), (2, put(gone))]);
        let watch = install.watch(&first, &records, &resolver, &mut state).await;
        assert_eq!(watch.accepted, [of(open, kept), of(open, gone)]);

        // Then `gone` is deleted, and the feed says so of all three: of
        // `kept` falsely, and of `unknown`, which this install never
        // accepted.
        let records = records.without_file(gone.sweeper, &paths::sweep_record(gone.id));
        let asked_before = records.asked().len();
        let second = FakeEventsFeed::of_events(vec![
            (1, put(kept)),
            (2, put(gone)),
            (3, del(kept)),
            (4, del(gone)),
            (5, del(unknown)),
        ]);
        let watch = install
            .watch(&second, &records, &resolver, &mut state)
            .await;
        assert!(watch.warnings.is_empty(), "{:?}", watch.warnings);
        assert!(watch.accepted.is_empty());
        assert_eq!(watch.deleted, [of(open, gone)]);
        assert_eq!(state.accepted_sweeps[&open.id], BTreeSet::from([kept]));
        assert_eq!(state.deleted_sweeps, BTreeSet::from([gone]));
        assert!(state.sweeps.contains_key(&kept));
        assert!(!state.sweeps.contains_key(&gone));
        // After the bounty's discovered.json, each DEL of a sweep accepted is
        // checked against its sweeper's own storage; a DEL of any other is
        // not looked into.
        assert_eq!(
            records.asked().split_off(asked_before),
            [
                (install.owner, paths::discovered(open.id)),
                (kept.sweeper, paths::sweep_record(kept.id)),
                (gone.sweeper, paths::sweep_record(gone.id)),
            ]
        );
    }

    #[tokio::test]
    async fn a_page_with_more_events_than_asked_for_is_refused_and_asked_for_again_next_run() {
        let install = Install::new();
        install.store_cursor(install.home, 7);
        // A homeserver that sends one event more than it is asked for.
        let ids: Vec<u64> = (8..=1008).collect();
        let feed = FakeEventsFeed::answering(move |cursor, limit| {
            Ok(feed_page(&ids, cursor, limit.saturating_add(1)))
        });
        let (records, resolver) = (FakePublicRecords::default(), FakeHomeservers::default());
        let mut state = one_open(bounty(install.owner, 10));

        for run in 1..=2 {
            let watch = install.watch(&feed, &records, &resolver, &mut state).await;
            assert_eq!(watch.warnings.len(), 1, "{:?}", watch.warnings);
            assert!(
                watch.warnings[0].contains("more events than were asked for"),
                "{}",
                watch.warnings[0]
            );
            assert_eq!(install.stored_cursor(install.home), Some(7));
            assert_eq!(feed.asked().len(), run);
        }
        // Each run asked for the same page, once.
        assert_eq!(feed.asked(), [(EventCursor::new(7), 1000); 2]);
    }

    #[tokio::test]
    async fn a_page_whose_cursor_does_not_move_forward_stops_that_feed_for_the_run() {
        let install = Install::new();
        let open = bounty(install.owner, 10);
        let stranger = stranger_sweep(20);
        let records = with_sweep(FakePublicRecords::default(), stranger, open, "done");
        let resolver = FakeHomeservers::default();
        let line = put(stranger);
        // Asked for the events after 7: a cursor at it, one below it, and
        // events with no cursor at all.
        let pages = [
            (format!("{line}\ncursor: 7"), CURSOR_NOT_FORWARD),
            (format!("{line}\ncursor: 3"), CURSOR_NOT_FORWARD),
            (line.clone(), NO_CURSOR),
        ];
        for (body, why) in pages {
            install.store_cursor(install.home, 7);
            let feed = FakeEventsFeed::answering(move |_, _| Ok(body.clone().into_bytes()));
            let mut state = one_open(open);
            let watch = install.watch(&feed, &records, &resolver, &mut state).await;
            assert_eq!(watch.warnings.len(), 1, "{:?}", watch.warnings);
            assert!(watch.warnings[0].ends_with(why), "{}", watch.warnings[0]);
            assert!(watch.warnings[0].contains(&install.home.to_string()));
            // Nothing on the page is acted on, its cursor is not kept, and
            // it is not asked for again this run.
            assert!(watch.accepted.is_empty());
            assert_eq!(install.stored_cursor(install.home), Some(7));
            assert_eq!(feed.asked(), [(EventCursor::new(7), 1000)]);
        }
        assert_eq!(reads_of(&records, stranger), 0);
    }

    #[tokio::test]
    async fn the_cursor_is_kept_after_each_batch_and_a_restart_resumes_there() {
        // The unit form of 06's "the events cursor survives a restart".
        let install = Install::new();
        let (owner, home) = (install.owner, install.home);
        let open = bounty(owner, 10);
        let stranger = stranger_sweep(20);
        install.store_cursor(home, 0);
        // Three pages: the stranger's running PUT on the first, its done PUT
        // on the third, and another app's files around them.
        let other = random_pubky();
        let events: Vec<(u64, String)> = (1..=2600)
            .map(|id| match id {
                10 | 2500 => (id, put(stranger)),
                _ => (id, format!("PUT pubky://{other}/pub/example.app/{id}.json")),
            })
            .collect();
        // The first run's homeserver fails at the third page. At each
        // request it checks that the batch before was stored first: the
        // cursor asked for is the one the file holds, and the stranger
        // accepted on the first page is in the poll state's file.
        let (dirs, first_events) = (install.dirs.clone(), events.clone());
        let first = FakeEventsFeed::answering(move |cursor, limit| {
            let stored = FeedCursors::read(&dirs, owner).expect("reads").get(&home);
            assert_eq!(stored, Some(cursor));
            let accepted = PollState::read(&dirs, owner)
                .expect("reads")
                .accepted_sweeps;
            assert_eq!(accepted.contains_key(&open.id), cursor.id() > 0);
            if cursor.id() >= 2000 {
                anyhow::bail!("the homeserver answered 503 Service Unavailable");
            }
            Ok(events_page(&first_events, cursor, limit))
        });
        let records = with_sweep(FakePublicRecords::default(), stranger, open, "running");
        let resolver = FakeHomeservers::default();
        let mut state = one_open(open);
        let watch = install.watch(&first, &records, &resolver, &mut state).await;
        assert_eq!(watch.accepted, [of(open, stranger)]);
        assert_eq!(watch.warnings.len(), 1, "{:?}", watch.warnings);
        let asked: Vec<u64> = first
            .asked()
            .iter()
            .map(|(cursor, _)| cursor.id())
            .collect();
        assert_eq!(asked, [0, 1000, 2000]);
        assert_eq!(install.stored_cursor(home), Some(2000));

        // A restart: the state read back from its file, a fresh cache and an
        // honest homeserver; the stranger's sweep is done now.
        let mut state = PollState::read(&install.dirs, owner).expect("reads");
        let records = with_sweep(records, stranger, open, "done");
        let second = FakeEventsFeed::of_events(events);
        let watch = install
            .watch(&second, &records, &resolver, &mut state)
            .await;
        assert!(watch.warnings.is_empty(), "{:?}", watch.warnings);
        assert_eq!(watch.starts[&home], start(2000, StartSource::Local));
        assert_eq!(second.asked(), [(EventCursor::new(2000), 1000)]);
        // Its done PUT brings the sweep accepted before up to date, and does
        // not accept it again.
        assert!(watch.accepted.is_empty());
        let summary = &state.sweeps[&stranger];
        assert_eq!(summary.status.as_known(), Some(KnownSweepStatus::Done));
        assert_eq!(install.stored_cursor(home), Some(2600));
    }

    #[tokio::test]
    async fn each_feed_starts_at_its_local_cursor_else_the_lowest_listed_else_its_head() {
        let mut install = Install::new();
        let owner = install.owner;
        let (local, listed, unknown) = (install.home, random_pubky(), random_pubky());
        install.watch_list = vec![local, listed, unknown];
        install.store_cursor(local, 100);
        let (first, second) = (bounty(owner, 10), bounty(owner, 11));
        let records = FakePublicRecords::default()
            .with_record(
                owner,
                &paths::discovered(first.id),
                &discovered_json(&[], &[(listed, 30), (local, 5)]),
            )
            .with_record(
                owner,
                &paths::discovered(second.id),
                &discovered_json(&[], &[(listed, 20)]),
            );
        // Every homeserver's feed holds the events 10, 25 and 40, so its
        // head is 40.
        let feed = FakeEventsFeed::of_ids(&[10, 25, 40]);
        let resolver = FakeHomeservers::default();
        let mut state = state_of(&[
            (first, bounty_record(true, "open")),
            (second, bounty_record(true, "open")),
        ]);

        let watch = install.watch(&feed, &records, &resolver, &mut state).await;
        assert_eq!(
            watch.starts,
            BTreeMap::from([
                (local, start(100, StartSource::Local)),
                (listed, start(20, StartSource::Discovered)),
                (unknown, start(40, StartSource::HeadSearch)),
            ])
        );
        // The head search is the one warning, and names its homeserver.
        assert_eq!(watch.warnings.len(), 1, "{:?}", watch.warnings);
        assert!(watch.warnings[0].contains(&unknown.to_string()));
        // Each start is stored, and the listed one read on to the head.
        assert_eq!(install.stored_cursor(local), Some(100));
        assert_eq!(install.stored_cursor(listed), Some(40));
        assert_eq!(install.stored_cursor(unknown), Some(40));

        // So the next run starts from the local file everywhere, and
        // searches nothing.
        let watch = install.watch(&feed, &records, &resolver, &mut state).await;
        assert!(watch.warnings.is_empty(), "{:?}", watch.warnings);
        assert!(
            watch
                .starts
                .values()
                .all(|start| start.source == StartSource::Local)
        );
    }

    #[tokio::test]
    async fn with_no_bounty_open_to_strangers_no_feed_is_read_and_the_owner_s_cursors_go() {
        let install = Install::new();
        let owner = install.owner;
        let (closed, done) = (bounty(owner, 10), bounty(owner, 11));
        // Another owner's open bounty, which the roster poll read, does not
        // count.
        let theirs = bounty(random_pubky(), 12);
        install.store_cursor(install.home, 5);
        let other_owner = random_pubky();
        let mut other_cursors = FeedCursors::default();
        other_cursors.set(install.home, EventCursor::new(3));
        other_cursors
            .write(&install.dirs, other_owner)
            .expect("written");
        let feed = FakeEventsFeed::of_ids(&[1]);
        let (records, resolver) = (FakePublicRecords::default(), FakeHomeservers::default());
        let mut state = state_of(&[
            (closed, bounty_record(false, "open")),
            (done, bounty_record(true, "done")),
            (theirs, bounty_record(true, "open")),
        ]);
        let tag = ETag::parse(b"\"d-1\"").expect("a tag");
        state.discovered_etags.insert(done.id, tag);

        let watch = install.watch(&feed, &records, &resolver, &mut state).await;
        assert!(feed.asked().is_empty());
        assert!(records.asked().is_empty());
        assert!(watch.starts.is_empty());
        assert!(watch.accepted.is_empty());
        assert!(watch.warnings.is_empty(), "{:?}", watch.warnings);
        assert_eq!(
            FeedCursors::read(&install.dirs, owner).expect("reads"),
            FeedCursors::default()
        );
        assert_eq!(
            FeedCursors::read(&install.dirs, other_owner).expect("reads"),
            other_cursors
        );
        assert!(state.discovered_etags.is_empty());
    }

    #[tokio::test]
    async fn a_sweep_a_discovered_json_lists_is_confirmed_and_accepted_once() {
        // A second install of the owner (06's "the second install of A"),
        // on a fresh home: the done sweep the first install found reaches
        // it through the bounty's discovered.json, and the feed's later PUT
        // of it does not accept it again.
        let install = Install::new();
        let owner = install.owner;
        let open = bounty(owner, 10);
        let (listed, gone) = (stranger_sweep(20), stranger_sweep(21));
        let discovered = paths::discovered(open.id);
        let records = with_sweep(FakePublicRecords::default(), listed, open, "done").with_record(
            owner,
            &discovered,
            &discovered_json(&[listed, gone], &[(install.home, 0)]),
        );
        let feed = FakeEventsFeed::of_events(vec![(1, put(listed))]);
        let resolver = FakeHomeservers::default();
        let mut state = one_open(open);

        let watch = install.watch(&feed, &records, &resolver, &mut state).await;
        assert!(watch.warnings.is_empty(), "{:?}", watch.warnings);
        assert_eq!(watch.starts[&install.home].source, StartSource::Discovered);
        assert_eq!(watch.accepted, [of(open, listed)]);
        // The listed sweep whose record is gone is not accepted: its deletion
        // is confirmed instead.
        assert_eq!(watch.deleted, [of(open, gone)]);
        assert!(state.deleted_sweeps.contains(&gone));
        // Each is read from its sweeper's own storage, after its lookup.
        assert_eq!(reads_of(&records, gone), 1);
        assert!(resolver.asked().contains(&listed.sweeper));
        assert!(resolver.asked().contains(&gone.sweeper));

        // The next run sends the file's tag, and an unchanged file has
        // nothing new to confirm.
        let tag = state.discovered_etags.get(&open.id).cloned();
        assert!(tag.is_some(), "kept once every listed sweep is settled");
        let asked_before = records.asked().len();
        let watch = install.watch(&feed, &records, &resolver, &mut state).await;
        assert!(watch.accepted.is_empty());
        assert!(watch.deleted.is_empty());
        assert_eq!(
            records.asked().split_off(asked_before),
            [(owner, discovered.clone())]
        );
        assert_eq!(
            records.conditional_asked().last(),
            Some(&(owner, discovered, tag))
        );
    }

    #[tokio::test]
    async fn a_run_reads_at_most_its_pages_and_leaves_the_rest_for_the_next() {
        let install = Install::new();
        install.store_cursor(install.home, 0);
        let pages = u64::try_from(MAX_FEED_PAGES_PER_RUN).expect("a few");
        let (full, last) = (pages * 1000, pages * 1000 + 5);
        let ids: Vec<u64> = (1..=last).collect();
        let feed = FakeEventsFeed::of_ids(&ids);
        let (records, resolver) = (FakePublicRecords::default(), FakeHomeservers::default());
        let mut state = one_open(bounty(install.owner, 10));

        let watch = install.watch(&feed, &records, &resolver, &mut state).await;
        assert_eq!(feed.asked().len(), MAX_FEED_PAGES_PER_RUN);
        assert_eq!(install.stored_cursor(install.home), Some(full));
        // The last page read was full: the rest is for the next run, which
        // a warning says.
        assert_eq!(watch.warnings.len(), 1, "{:?}", watch.warnings);
        assert!(watch.warnings[0].contains(&install.home.to_string()));

        let watch = install.watch(&feed, &records, &resolver, &mut state).await;
        assert!(watch.warnings.is_empty(), "{:?}", watch.warnings);
        assert_eq!(
            feed.asked().split_off(MAX_FEED_PAGES_PER_RUN),
            [(EventCursor::new(full), 1000)]
        );
        assert_eq!(install.stored_cursor(install.home), Some(last));
    }

    /// `records` holding a running sweep of `bounty` for each of `sweeps`.
    fn with_running(
        records: FakePublicRecords,
        sweeps: &[SweepRef],
        bounty: BountyRef,
    ) -> FakePublicRecords {
        // `fold` threads the fake through each sweep, as a chain of
        // `with_sweep` calls would.
        sweeps.iter().fold(records, |records, &sweep| {
            with_sweep(records, sweep, bounty, "running")
        })
    }

    /// A feed of a `PUT` of each of `sweeps`, at events 1, 2 and on.
    fn feed_of_puts(sweeps: &[SweepRef]) -> FakeEventsFeed {
        // `(1..).zip(..)` numbers the lines from 1, as the events' ids.
        FakeEventsFeed::of_events((1..).zip(sweeps.iter().map(|&sweep| put(sweep))).collect())
    }

    #[tokio::test]
    async fn past_a_bounty_s_cap_its_new_strangers_sweeps_are_left_out_and_the_feed_reads_on() {
        let install = Install::new();
        let open = bounty(install.owner, 10);
        install.store_cursor(install.home, 0);
        // A stranger's sweep an earlier run accepted while it was running;
        // it is done now.
        let earlier = stranger_sweep(5);
        let running =
            Sweep::from_json(&json_bytes(&sweep_json(open, &["t1"], "running"))).expect("a sweep");
        let mut state = one_open(open);
        state
            .sweeps
            .insert(earlier, SweepSummary::new(&running, None));
        state
            .accepted_sweeps
            .insert(open.id, BTreeSet::from([earlier]));
        // A flood of sweeps under throwaway keys, more than the bounty has
        // room for, then the earlier sweep's done PUT.
        let flood: Vec<SweepRef> = (100..)
            .take(MAX_ACCEPTED_PER_BOUNTY + 3)
            .map(stranger_sweep)
            .collect();
        let records = with_sweep(FakePublicRecords::default(), earlier, open, "done");
        let records = with_running(records, &flood, open);
        let mut sweeps = flood.clone();
        sweeps.push(earlier);
        let feed = feed_of_puts(&sweeps);
        let last = u64::try_from(sweeps.len()).expect("a few");
        let resolver = FakeHomeservers::default();

        let watch = install.watch(&feed, &records, &resolver, &mut state).await;
        // Room for all but one of the flood: the earlier sweep holds a place.
        let room = MAX_ACCEPTED_PER_BOUNTY - 1;
        assert_eq!(watch.accepted.len(), room);
        assert_eq!(
            state.accepted_sweeps[&open.id].len(),
            MAX_ACCEPTED_PER_BOUNTY
        );
        assert!(!state.sweeps.contains_key(&flood[room]));
        // The first sweep with no room was read and left out; once no open
        // bounty had room, the rest were not even read.
        assert_eq!(reads_of(&records, flood[room]), 1);
        for &sweep in &flood[room + 1..] {
            assert_eq!(reads_of(&records, sweep), 0);
        }
        // The feed read on: the earlier sweep is up to date, and the cursor
        // is past the page.
        let summary = &state.sweeps[&earlier];
        assert_eq!(summary.status.as_known(), Some(KnownSweepStatus::Done));
        assert_eq!(install.stored_cursor(install.home), Some(last));
        // One warning, which names the bounty and the caps, and quotes no
        // stranger.
        assert_eq!(watch.warnings.len(), 1, "{:?}", watch.warnings);
        for part in [
            open.to_string(),
            MAX_ACCEPTED_PER_BOUNTY.to_string(),
            MAX_STRANGERS_SWEEPS_KEPT.to_string(),
        ] {
            assert!(watch.warnings[0].contains(&part), "{}", watch.warnings[0]);
        }
        assert_quotes_nothing(&watch.warnings);
        // What was kept is in the poll state's file.
        assert_eq!(
            PollState::read(&install.dirs, install.owner).expect("reads"),
            state
        );
    }

    #[tokio::test]
    async fn deletions_count_against_the_cap_on_strangers_sweeps_kept_in_all() {
        let install = Install::new();
        let owner = install.owner;
        let (first, second) = (bounty(owner, 10), bounty(owner, 11));
        install.store_cursor(install.home, 0);
        let mut state = state_of(&[
            (first, bounty_record(true, "open")),
            (second, bounty_record(true, "open")),
        ]);
        // Deletions earlier runs confirmed: all but two of the strangers'
        // sweeps pull keeps in all.
        let gone = random_pubky();
        state.deleted_sweeps = (0..)
            .take(MAX_STRANGERS_SWEEPS_KEPT - 2)
            .map(|n| SweepRef {
                sweeper: gone,
                id: record_id(n),
            })
            .collect();
        // Two sweeps of each bounty, one of each, then one of each again.
        let of_first = [stranger_sweep(100), stranger_sweep(102)];
        let of_second = [stranger_sweep(101), stranger_sweep(103)];
        let records = with_running(FakePublicRecords::default(), &of_first, first);
        let records = with_running(records, &of_second, second);
        let feed = feed_of_puts(&[of_first[0], of_second[0], of_first[1], of_second[1]]);
        let resolver = FakeHomeservers::default();

        let watch = install.watch(&feed, &records, &resolver, &mut state).await;
        assert_eq!(
            watch.accepted,
            [of(first, of_first[0]), of(second, of_second[0])]
        );
        // Each bounty's first sweep left out is a warning that names it.
        assert_eq!(watch.warnings.len(), 2, "{:?}", watch.warnings);
        assert!(watch.warnings[0].contains(&first.to_string()));
        assert!(watch.warnings[1].contains(&second.to_string()));
    }

    #[tokio::test]
    async fn a_page_the_poll_state_has_no_room_for_is_dropped_and_asked_for_again_next_run() {
        let mut install = Install::new();
        let owner = install.owner;
        // Two watched homeservers with the same feed: once the poll state
        // has no room, the second is not read.
        install.watch_list.push(random_pubky());
        for &homeserver in &install.watch_list {
            install.store_cursor(homeserver, 0);
        }
        let open = bounty(owner, 10);
        let flood: Vec<SweepRef> = (100..110).map(stranger_sweep).collect();
        let records = with_running(FakePublicRecords::default(), &flood, open);
        let feed = feed_of_puts(&flood);
        let resolver = FakeHomeservers::default();
        // A poll state with room for less than one sweep more.
        let mut state = one_open(open);
        state.write_with_room(&install.dirs, owner, 300);
        let before = state.clone();

        for run in 1..=2 {
            let watch = install.watch(&feed, &records, &resolver, &mut state).await;
            assert_eq!(watch.warnings, [POLL_STATE_FULL]);
            assert!(watch.accepted.is_empty());
            // The state is as it was, in memory and in its file, and so is
            // every cursor.
            assert_eq!(state, before);
            assert_eq!(
                PollState::read(&install.dirs, owner).expect("reads"),
                before
            );
            for &homeserver in &install.watch_list {
                assert_eq!(install.stored_cursor(homeserver), Some(0));
            }
            // One page a run, of one homeserver: no feed is read on.
            assert_eq!(feed.asked().len(), run);
        }
        assert_eq!(feed.homeservers_asked().len(), 1);
    }
}
