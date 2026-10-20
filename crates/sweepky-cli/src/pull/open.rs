//! Opening the sweeps `pull` found (02, "Who can read a sweep"): each
//! sweep's package fetched from its sweeper's own storage, decrypted with
//! this install's device key, checked against its record and the bounty it
//! is pulled for, split into its files and handed to `pull::store`.
//!
//! [`open_sweeps`] runs after the roster poll and the feed watcher, whose
//! poll state says what is waiting: a sweep of one of the owner's bounties
//! the roster poll has read, whose record says `done`, not stored and not
//! refused yet, by a key of the roster or accepted for that bounty from the
//! feed. A `running` sweep waits for a later pull, an `aborted` one has
//! nothing to open (P2b), and a stranger's sweep of a bounty closed to
//! strangers was never accepted.
//!
//! **Each sweep, one at a time**, once its sweeper's homeserver resolves
//! through the run's [`Homeservers`] (the host policy on production), and
//! always from that sweeper's own storage, never a feed's host:
//!
//! 1. Its record, read again, so that `open_package` is given the record
//!    itself rather than the poll state's summary of it. It must still say
//!    `done`, name the bounty being pulled, and name only targets that
//!    bounty has, of a kind this build reads. Checked before the package is
//!    fetched, so a record that fails costs no download.
//! 2. Its `.age`, at most `MAX_CIPHERTEXT_BYTES` (`PublicRecords::
//!    get_package`, through `remote::get_unredirected`), checked again
//!    before core sees it.
//! 3. `open_package` with this install's key, the path the record and the
//!    package were fetched from, and the record: decryption, the package's
//!    parse and core's binding (the sweeper is the path's owner, the bounty
//!    and targets the record's).
//! 4. What core's binding leaves to the caller: each target's commit in
//!    `targetShas` is the one the bounty pins for review
//!    (`KnownTarget::reviewed_commit`: a pull request's head, any other
//!    target's `rev`), as `submit` records it.
//! 5. The compact copy of the findings, then `into_files`, then the
//!    store's path check, then `store_sweep`: a circle member's sweep among
//!    the trusted, anyone else's in `untrusted/`.
//!
//! **A fair order, within caps per run.** Of a bounty's waiting sweeps, the
//! circle's go first, then everyone else's; within each, sweepers take
//! turns ([`fair_order`]). At most [`MAX_OPENS_PER_SWEEPER`] of one
//! sweeper's are opened a run, and at most [`MAX_OPENS_PER_BOUNTY`] of a
//! bounty's; what is left waits for the next run, with a warning. The share
//! per sweeper keeps one key's flood from crowding out everyone else, and
//! the circle's turn first keeps a flood of throwaway keys from delaying
//! the circle. The caps also bound the memory a run takes, since a package
//! may be 32 MiB.
//!
//! **Settled, or tried again.** A sweep stored is marked `pulled`. One
//! refused for a reason a later run would meet again is marked `refused`
//! and never fetched again, so a broken or hostile sweep costs one
//! download, not one a run, and cannot hold its sweeper's share or the
//! bounty's run after run: a record that is gone, no longer reads, no
//! longer says `done`, or names another bounty or other targets; a package
//! that is missing, too large, not encrypted to this install's key, not
//! bound to its record or the bounty's pins; files the store refuses. That
//! is for good: a later build that would read such a sweep does not try it
//! again. A sweeper who cannot be reached, or whose read fails, is read no
//! more this run, with one warning, and their sweeps wait for the next; so
//! does a sweep the store failed to write.
//!
//! **Secrets and sealed content.** This install's key is read by the
//! command, once and before any network read (`pull::ThisInstall`), and
//! lent to [`open_sweeps`], which only ever lends it on to `open_package`;
//! the command drops it as soon as the run's opens are done. Nothing
//! decrypted is printed or logged: a package is consumed by its
//! split and its files by the store. Warnings name keys, URLs and paths
//! core built, numbers, and core's and `remote`'s fixed text, never a byte
//! of a record or a package.
//!
//! **Known limit.** The manifest has no sweep id (01), so a sweeper's own
//! package uploaded again under another of their sweep records, of the same
//! bounty and targets, binds there too, and is stored twice.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use anyhow::anyhow;
use sweepky_core::{
    BindingError, Bounty, BountyRef, Circle, DecryptError, DeviceIdentity, GitSha,
    KnownSweepStatus, MAX_CIPHERTEXT_BYTES, OpenError, PackageFiles, Pubky, RecordError, Sweep,
    SweepPackage, SweepRef, TargetId, Zeroizing, open_package,
};

use super::resolve::{Homeservers, ResolveHomeserver};
use super::roster::{Fetched, Stop, fetch};
use super::state::{PollState, SweepSummary};
use super::store::{CompactFindings, Placement, Stored, check_paths, store_sweep};
use crate::Dirs;
use crate::records::PublicRecords;
use crate::remote::BodyTooLarge;

/// The most sweeps of one bounty opened in a run. A package may be 32 MiB
/// and decrypting and parsing one takes several times that, so a run's work
/// is bounded; the rest are opened next run.
pub(crate) const MAX_OPENS_PER_BOUNTY: usize = 16;

/// The most sweeps of one sweeper opened for one bounty in a run: a
/// quarter of [`MAX_OPENS_PER_BOUNTY`], so one key's flood leaves room for
/// at least three other sweepers.
pub(crate) const MAX_OPENS_PER_SWEEPER: usize = 4;

/// What [`open_sweeps`] did, for the rest of `pull`.
///
/// Keys, URLs, the paths `pull::store` gives and fixed text only, so
/// deriving `Debug` prints nothing of a package.
#[derive(Debug, Default)]
pub(crate) struct Opened {
    /// The sweeps stored this run, in the order opened.
    pub(crate) stored: Vec<OpenedSweep>,
    /// One line for each sweep skipped, sweeper read no more and bounty cut
    /// short, in fixed text that names keys and URLs, never a record's or a
    /// package's content.
    pub(crate) warnings: Vec<String>,
}

/// One sweep [`open_sweeps`] stored: which, of which bounty, and where.
#[derive(Debug)]
pub(crate) struct OpenedSweep {
    /// The owner's bounty it was pulled for.
    pub(crate) bounty: BountyRef,
    /// The sweep record it belongs to.
    pub(crate) sweep: SweepRef,
    /// Where it is stored now: written this run, or found there already.
    pub(crate) stored: Stored,
}

/// Opens the sweeps `owner`'s poll state `state` says are waiting with
/// `identity`, this install's key, reading through `records` once each
/// sweeper's homeserver resolves through `homeservers`, and stores them in
/// `dirs`' data directory: see the module docs. Marks each one stored as
/// `pulled` and each one refused for good as `refused` in `state`; writing
/// `state` back is the caller's.
///
/// Every fault of a sweep, a sweeper or a bounty is a warning in the
/// [`Opened`], so nothing here is an error.
// `identity` is borrowed (`&`), never owned: the caller read it and decides
// when it is dropped, which wipes it.
pub(crate) async fn open_sweeps<R: PublicRecords, H: ResolveHomeserver>(
    records: &R,
    homeservers: &mut Homeservers<'_, H>,
    dirs: &Dirs,
    identity: &DeviceIdentity,
    owner: Pubky,
    roster: &Circle,
    state: &mut PollState,
) -> Opened {
    let waiting = waiting_sweeps(state, owner, roster);
    let mut opener = Opener {
        records,
        homeservers,
        dirs,
        identity,
        roster,
        state,
        given_up: BTreeSet::new(),
        found: Opened::default(),
    };
    for (bounty, sweeps) in waiting {
        opener.open_bounty(bounty, sweeps).await;
    }
    opener.found
}

/// The sweeps waiting to be opened, by the owner's bounty they are of: see
/// the module docs.
fn waiting_sweeps(
    state: &PollState,
    owner: Pubky,
    roster: &Circle,
) -> BTreeMap<BountyRef, Vec<SweepRef>> {
    let mut waiting: BTreeMap<BountyRef, Vec<SweepRef>> = BTreeMap::new();
    // `&sweep` in the pattern copies the `SweepRef` key out of the map's
    // `&SweepRef`: it is `Copy`.
    for (&sweep, summary) in &state.sweeps {
        let bounty = summary.bounty;
        // One of the owner's bounties the roster poll has read, so its
        // record can be read for the revisions it pins.
        let ours = bounty.owner == owner && state.bounties.contains_key(&bounty);
        let admitted = roster.is_in_roster(sweep.sweeper)
            || state
                .accepted_sweeps
                .get(&bounty.id)
                .is_some_and(|accepted| accepted.contains(&sweep));
        if ours && admitted && is_waiting(summary) {
            waiting.entry(bounty).or_default().push(sweep);
        }
    }
    waiting
}

/// Whether the sweep `summary` describes has a package to open: its record
/// says `done`, and it was neither stored nor refused yet.
fn is_waiting(summary: &SweepSummary) -> bool {
    summary.status.as_known() == Some(KnownSweepStatus::Done) && !summary.pulled && !summary.refused
}

/// The order in which a bounty's `waiting` sweeps are opened this run, each
/// sweeper's cut to [`MAX_OPENS_PER_SWEEPER`]: the circle's first, then the
/// rest, each group in turns (see [`in_turns`]).
fn fair_order(waiting: Vec<SweepRef>, roster: &Circle) -> Vec<SweepRef> {
    // `partition` splits the list in one pass: the sweeps for which the
    // closure is true, then the others.
    let (circle, others): (Vec<SweepRef>, Vec<SweepRef>) = waiting
        .into_iter()
        .partition(|sweep| roster.is_in_roster(sweep.sweeper));
    let mut order = in_turns(circle);
    order.extend(in_turns(others));
    order
}

/// `sweeps` in turns by sweeper: every sweeper's oldest first, then every
/// sweeper's second, and so on up to [`MAX_OPENS_PER_SWEEPER`] turns, each
/// turn in upload order. A sweep id is its record's creation time, so
/// upload order is id order.
fn in_turns(mut sweeps: Vec<SweepRef>) -> Vec<SweepRef> {
    sweeps.sort_by_key(|sweep| (sweep.id, sweep.sweeper));
    let mut per_sweeper: BTreeMap<Pubky, usize> = BTreeMap::new();
    let mut turns: Vec<(usize, SweepRef)> = Vec::new();
    for sweep in sweeps {
        // How many of this sweeper's came before: this one's turn.
        let count = per_sweeper.entry(sweep.sweeper).or_insert(0);
        if *count < MAX_OPENS_PER_SWEEPER {
            turns.push((*count, sweep));
        }
        *count += 1;
    }
    // `sort_by_key` is stable: sweeps of the same turn keep their upload
    // order.
    turns.sort_by_key(|&(turn, _)| turn);
    turns.into_iter().map(|(_, sweep)| sweep).collect()
}

/// The commit each target of a bounty pins for review, by target id: a pull
/// request's head, any other target's `rev` (`KnownTarget::reviewed_commit`,
/// as `submit` writes `targetShas`). A target of a kind this build does not
/// read, or with a field that fails its check, has none, so no sweep of it
/// binds.
// The ids are borrowed from the bounty record, which outlives the map; the
// commits are cloned, because `known()` builds a new view of the target
// each time and the commit it lends out lives only as long as that view.
type Pins<'b> = BTreeMap<&'b TargetId, GitSha>;

/// [`Pins`] of `bounty`.
fn pins_of(bounty: &Bounty) -> Pins<'_> {
    bounty
        .targets
        .iter()
        .filter_map(|target| {
            // `ok()` turns the `Result` into an `Option`, dropping the
            // error; the first `?` then leaves out a target that fails its
            // check, and the second one of a kind this build does not know.
            let known = target.known().ok()??;
            Some((target.id(), known.reviewed_commit().clone()))
        })
        .collect()
}

/// Why a sweep is refused for good: a fault of its record or its package
/// that every later run would meet again. Each is fixed text, with core's
/// fixed text after it where core said why.
enum Refusal {
    /// Its record is gone from its sweeper's storage.
    RecordGone,
    /// Its record no longer reads: over the cap, or not a sweep record this
    /// build reads (the roster poll's fixed text, naming path and key).
    RecordUnreadable(anyhow::Error),
    /// Its record no longer says `done`.
    NotDone,
    /// Its record names another bounty than the one it is pulled for.
    OtherBounty,
    /// Its record names no target, or one the bounty does not have or pins
    /// nothing for.
    OtherTargets,
    /// Its record says `done`, but no `.age` is there.
    NoPackage,
    /// Its `.age` is over [`MAX_CIPHERTEXT_BYTES`].
    TooLarge,
    /// No stanza of its `.age` opens with this install's key.
    NotForThisKey,
    /// Its `.age` did not decrypt otherwise: core's reason.
    NotDecrypted(DecryptError),
    /// It decrypted, but not to a sweep package this build reads.
    NotAPackage(RecordError),
    /// Its manifest does not belong to its record or the path it came from.
    NotBound(BindingError),
    /// Its manifest's `targetShas` are not the commits the bounty pins.
    OtherRevisions,
    /// Its files cannot be stored: the compact copy, the split or the
    /// store's path check refused them, in their own fixed text.
    NotStorable(anyhow::Error),
}

/// The words of the refusal of a sweep sealed to other keys only, as 02's
/// "Fixed at upload" has it: a key published later opens later sweeps only.
const NOT_FOR_THIS_KEY: &str = "not encrypted to this install's key (sealed before this install's \
                                key was published, or to another install)";

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RecordGone => f.write_str("its sweep record is gone"),
            Self::RecordUnreadable(why) => write!(f, "its sweep record no longer reads: {why:#}"),
            Self::NotDone => f.write_str("its sweep record no longer says done"),
            Self::OtherBounty => {
                f.write_str("its sweep record names another bounty than the one being pulled")
            }
            Self::OtherTargets => f.write_str(
                "its sweep record names a target this bounty does not have, no target at all, or \
                 one of a kind this build does not read",
            ),
            Self::NoPackage => f.write_str(
                "its sweep record says done, but its sweeper's storage holds no package",
            ),
            Self::TooLarge => write!(
                f,
                "its package is larger than the {MAX_CIPHERTEXT_BYTES} bytes any sweep package \
                 encrypts to, so it was not decrypted"
            ),
            Self::NotForThisKey => f.write_str(NOT_FOR_THIS_KEY),
            Self::NotDecrypted(why) => write!(f, "its package could not be decrypted: {why}"),
            Self::NotAPackage(why) => write!(
                f,
                "its package decrypted, but not to a sweep package this build reads: {why}"
            ),
            Self::NotBound(why) => write!(f, "{why}"),
            Self::OtherRevisions => {
                f.write_str("its package was swept at other revisions than the bounty pins")
            }
            Self::NotStorable(why) => write!(f, "its files cannot be stored: {why:#}"),
        }
    }
}

/// Core's reason a package did not open, as a [`Refusal`]. A `match` with
/// no `_` arm, so a variant core adds later is a compile error here until
/// someone decides what it means.
fn refusal_of(error: OpenError) -> Refusal {
    match error {
        OpenError::Decrypt(DecryptError::NoMatchingKey) => Refusal::NotForThisKey,
        OpenError::Decrypt(why) => Refusal::NotDecrypted(why),
        OpenError::Record(why) => Refusal::NotAPackage(why),
        OpenError::Binding(why) => Refusal::NotBound(why),
    }
}

/// Why one sweep was not stored this run.
enum Skip {
    /// Refused for good: marked `refused`, never fetched again.
    ForGood(Refusal),
    /// Not this run: the store failed to write it. It waits for the next.
    ThisTime(anyhow::Error),
    /// Its sweeper is read no more this run, and a warning says why. It
    /// waits for the next.
    GaveUp,
}

// `?` on a `Result<_, Refusal>` in a function that returns `Result<_, Skip>`
// converts the error through this `From`.
impl From<Refusal> for Skip {
    fn from(why: Refusal) -> Self {
        Self::ForGood(why)
    }
}

/// What the opener reads through, and what it has found so far.
///
/// Two lifetimes, as for the roster poll's `Poller`: `'o` is how long it
/// borrows the reader, the cache, the key, the roster and the state, and
/// `'h` how long the cache borrows its resolver.
struct Opener<'o, 'h, R, H> {
    records: &'o R,
    homeservers: &'o mut Homeservers<'h, H>,
    dirs: &'o Dirs,
    /// This install's key, only ever lent to `open_package`.
    identity: &'o DeviceIdentity,
    roster: &'o Circle,
    state: &'o mut PollState,
    /// The sweepers read no more this run: unreachable, or a read failed.
    given_up: BTreeSet<Pubky>,
    found: Opened,
}

impl<R: PublicRecords, H: ResolveHomeserver> Opener<'_, '_, R, H> {
    /// Opens `waiting`, sweeps of the owner's `bounty`, in [`fair_order`]
    /// and within the caps, with a warning when some are left.
    async fn open_bounty(&mut self, bounty: BountyRef, waiting: Vec<SweepRef>) {
        let Some(record) = self.bounty_record(bounty).await else {
            return;
        };
        let pins = pins_of(&record);
        let count = waiting.len();
        let (mut tried, mut passed_over) = (0, 0);
        for sweep in fair_order(waiting, self.roster) {
            if tried == MAX_OPENS_PER_BOUNTY {
                break;
            }
            // A sweeper read no more this run takes no turn.
            if !self.resolve_or_give_up(sweep.sweeper).await {
                passed_over += 1;
                continue;
            }
            tried += 1;
            let result = self.open_one(bounty, &pins, sweep).await;
            self.settle(bounty, sweep, result);
        }
        // Never below zero, as the order holds at most `count` sweeps;
        // `saturating_sub` says so without a panic to reason about.
        let left = count.saturating_sub(tried + passed_over);
        if left > 0 {
            self.warn(format_args!(
                "{left} sweeps of {bounty} wait for the next pull: pull opens at most \
                 {MAX_OPENS_PER_BOUNTY} of a bounty's sweeps a run, and at most \
                 {MAX_OPENS_PER_SWEEPER} of one sweeper's"
            ));
        }
    }

    /// The owner's bounty record `bounty`, read from their own storage for
    /// the revisions it pins, or `None`, with a warning, when it cannot be
    /// read this run.
    async fn bounty_record(&mut self, bounty: BountyRef) -> Option<Bounty> {
        let why = match self.homeservers.resolve(bounty.owner).await {
            Err(why) => why.to_string(),
            Ok(_) => match self.records.get_bounty(bounty).await {
                Ok(Some(record)) => return Some(record),
                Ok(None) => "its record is gone from your storage".to_owned(),
                Err(error) => format!("{error:#}"),
            },
        };
        self.warn(format_args!(
            "pull opens no sweep of {bounty} this time: {why}"
        ));
        None
    }

    /// Whether `sweeper`'s storage is read this run: not given up already,
    /// and their homeserver resolves. One that does not resolve is given up
    /// here, with its warning.
    async fn resolve_or_give_up(&mut self, sweeper: Pubky) -> bool {
        if self.given_up.contains(&sweeper) {
            return false;
        }
        // The lookup is the gate: a key with no homeserver, or one the host
        // policy refuses, is not read at all. The homeserver itself is not
        // used: each read resolves the key again inside the SDK.
        match self.homeservers.resolve(sweeper).await {
            Ok(_) => true,
            Err(why) => {
                self.give_up(sweeper, format_args!("{why}"));
                false
            }
        }
    }

    /// Opens `sweep` of `bounty`, whose targets pin `pins`, and stores it:
    /// the module docs' five steps.
    async fn open_one(
        &mut self,
        bounty: BountyRef,
        pins: &Pins<'_>,
        sweep: SweepRef,
    ) -> Result<Stored, Skip> {
        let record = self.read_record(sweep).await?;
        check_record(&record, bounty, pins)?;
        let ciphertext = self.read_package(sweep).await?;
        // `sweep` is the path both were just fetched from, never a URL from
        // the feed, the record or the package: the binding is only as good
        // as that path.
        let package =
            open_package(&ciphertext, self.identity, &sweep, &record).map_err(refusal_of)?;
        // Public bytes, but up to 32 MiB: dropped before the split, not
        // after the store.
        drop(ciphertext);
        check_revisions(&package, pins)?;
        let (findings, files) = split(package)?;
        let placement = if self.roster.is_in_roster(sweep.sweeper) {
            Placement::Trusted
        } else {
            Placement::Untrusted
        };
        store_sweep(self.dirs, bounty, sweep, placement, findings, files).map_err(Skip::ThisTime)
    }

    /// `sweep`'s record, read again from its sweeper's storage with no tag,
    /// so a body always comes back, within the roster poll's limits.
    async fn read_record(&mut self, sweep: SweepRef) -> Result<Sweep, Skip> {
        match fetch::<Sweep>(self.records, sweep.sweeper, sweep.id, None).await {
            Ok(Fetched::Record { record, .. }) => Ok(record),
            Ok(Fetched::Absent) => Err(Refusal::RecordGone.into()),
            Ok(Fetched::Unreadable(why)) => Err(Refusal::RecordUnreadable(why).into()),
            // `remote` refuses a 304 to a read that sent no tag, so this is
            // a failed read too.
            Ok(Fetched::Unchanged) => Err(self
                .give_up_after_failed_read(
                    sweep.sweeper,
                    anyhow!("the homeserver answered 304 unasked"),
                )
                .await),
            Err(Stop::ReadFailed(error)) => {
                Err(self.give_up_after_failed_read(sweep.sweeper, error).await)
            }
            // `fetch` gives no other, but should it, the sweeper is skipped.
            Err(Stop::Unreachable(why)) => {
                self.give_up(sweep.sweeper, format_args!("{why}"));
                Err(Skip::GaveUp)
            }
        }
    }

    /// `sweep`'s `.age` from its sweeper's storage, at most
    /// [`MAX_CIPHERTEXT_BYTES`].
    async fn read_package(&mut self, sweep: SweepRef) -> Result<Zeroizing<Vec<u8>>, Skip> {
        match self.records.get_package(sweep).await {
            // The real reader refuses a longer body before it is buffered;
            // checked again here, so that whatever reader is behind the
            // seam, nothing longer reaches core.
            Ok(Some(ciphertext)) if ciphertext.len() > MAX_CIPHERTEXT_BYTES => {
                Err(Refusal::TooLarge.into())
            }
            Ok(Some(ciphertext)) => Ok(ciphertext),
            Ok(None) => Err(Refusal::NoPackage.into()),
            // `downcast_ref` finds the typed error under the context
            // `remote` added to it.
            Err(error) if error.downcast_ref::<BodyTooLarge>().is_some() => {
                Err(Refusal::TooLarge.into())
            }
            Err(error) => Err(self.give_up_after_failed_read(sweep.sweeper, error).await),
        }
    }

    /// Settles what opening `sweep` of `bounty` gave: stored is `pulled`,
    /// refused for good is `refused`, each with its line in the
    /// [`Opened`].
    fn settle(&mut self, bounty: BountyRef, sweep: SweepRef, result: Result<Stored, Skip>) {
        match result {
            Ok(stored) => {
                if let Some(summary) = self.state.sweeps.get_mut(&sweep) {
                    summary.pulled = true;
                }
                self.found.stored.push(OpenedSweep {
                    bounty,
                    sweep,
                    stored,
                });
            }
            Err(Skip::ForGood(why)) => {
                if let Some(summary) = self.state.sweeps.get_mut(&sweep) {
                    summary.refused = true;
                }
                self.warn(format_args!("pull skipped {sweep} for good: {why}"));
            }
            Err(Skip::ThisTime(error)) => {
                self.warn(format_args!("pull skipped {sweep} this time: {error:#}"));
            }
            Err(Skip::GaveUp) => {}
        }
    }

    /// Reads `sweeper`'s storage no more this run after a read of it failed
    /// with `error`, looking the key up again, as the roster poll does, so
    /// the rest of the run uses what its record says now.
    async fn give_up_after_failed_read(&mut self, sweeper: Pubky, error: anyhow::Error) -> Skip {
        let again = match self.homeservers.after_failed_read(sweeper).await {
            Ok(_) => String::new(),
            Err(why) => format!("; looked up again, {why}"),
        };
        self.give_up(sweeper, format_args!("{error:#}{again}"));
        Skip::GaveUp
    }

    /// Reads `sweeper`'s storage no more this run, with a warning that says
    /// why.
    fn give_up(&mut self, sweeper: Pubky, why: fmt::Arguments<'_>) {
        self.given_up.insert(sweeper);
        self.warn(format_args!(
            "pull reads no more sweeps of {sweeper} this time: {why}"
        ));
    }

    /// Adds a warning.
    // `fmt::Arguments` is what `format_args!` builds: the pieces of a
    // message, borrowed, written into the one `String` kept here.
    fn warn(&mut self, warning: fmt::Arguments<'_>) {
        self.found.warnings.push(warning.to_string());
    }
}

/// Refuses `record`, just read for a sweep of `bounty`, unless it says
/// `done`, names `bounty`, and names at least one target, each one `pins`
/// has: what core's binding leaves to the caller about the record.
fn check_record(record: &Sweep, bounty: BountyRef, pins: &Pins<'_>) -> Result<(), Refusal> {
    if record.status.as_known() != Some(KnownSweepStatus::Done) {
        return Err(Refusal::NotDone);
    }
    // `BountyRef`'s `==` compares the owner's key bytes and the id.
    if record.bounty != bounty {
        return Err(Refusal::OtherBounty);
    }
    if record.targets.is_empty() || !record.targets.iter().all(|id| pins.contains_key(id)) {
        return Err(Refusal::OtherTargets);
    }
    Ok(())
}

/// Refuses `package` unless each commit its manifest's `targetShas` gives
/// is the one `pins` has for that target. `open_package` has checked that
/// those are exactly its record's targets, which [`check_record`] found
/// among `pins`.
// Commits are public (the bounty pins them), so plain `==` is right: a
// constant-time comparison is for secrets.
fn check_revisions(package: &SweepPackage, pins: &Pins<'_>) -> Result<(), Refusal> {
    let pinned = package
        .manifest
        .target_shas
        .iter()
        .all(|(id, commit)| pins.get(id) == Some(commit));
    if pinned {
        Ok(())
    } else {
        Err(Refusal::OtherRevisions)
    }
}

/// `package` split into what the store writes: the compact copy of its
/// findings, taken first since `into_files` consumes them, and its files,
/// once the store's path check passes them. Consumes the package, so
/// nothing of it outlives the split but the two buffers handed back.
fn split(package: SweepPackage) -> Result<(CompactFindings, PackageFiles), Refusal> {
    let findings = CompactFindings::of(&package.findings).map_err(Refusal::NotStorable)?;
    // `PackageError::FindingsFileTooLarge` among the rest: a warning for
    // this sweep, never a failed pull. `anyhow::Error::from` keeps core's
    // fixed text.
    let files = package
        .into_files()
        .map_err(|error| Refusal::NotStorable(anyhow::Error::from(error)))?;
    check_paths(&files).map_err(Refusal::NotStorable)?;
    Ok((findings, files))
}

#[cfg(test)]
mod tests {
    use std::mem;

    use serde_json::{Value, json};
    use sweepky_core::paths;
    use sweepky_core::{
        Bounty, BountyRef, Circle, DeviceIdentity, MAX_CIPHERTEXT_BYTES, MAX_FINDINGS_FILE_BYTES,
        Pubky, Sweep, SweepPackage, SweepRef, seal_package,
    };
    use tempfile::TempDir;

    use super::{MAX_OPENS_PER_BOUNTY, MAX_OPENS_PER_SWEEPER, Opened, fair_order, open_sweeps};
    use crate::Dirs;
    use crate::pull::resolve::Homeservers;
    use crate::pull::state::{BountySummary, PollState, SweepSummary};
    use crate::pull::store::{Placement, Stored};
    use crate::test_support::{
        FAKE_HOMESERVER, FakeHomeservers, FakeLookup, FakePublicRecords, PLANTED, SYNTHETIC_HEAD,
        SYNTHETIC_SHA, bounty_json, circle_json, dirs_in, done_record, json_bytes, package_json,
        pr_target_json, private_temp, random_pubky, record_id, repo_target_json, stored_findings,
        sweep_json,
    };

    /// What the warning about a sweep sealed to other keys only says.
    const NOT_FOR_THIS_KEY: &str = "not encrypted to this install's key (sealed before this \
                                    install's key was published, or to another install)";

    /// One owner's install, with its device key, one bounty of the owner's,
    /// everyone's public storage in memory, and the poll state the roster
    /// poll and the feed watcher would have left.
    struct Fixture {
        // Kept so the directory lives as long as the fixture.
        _home: TempDir,
        dirs: Dirs,
        owner: Pubky,
        /// This install's key, as the command lends it to the opens.
        key: DeviceIdentity,
        bounty: BountyRef,
        /// The roster's members besides the owner, its admin.
        members: Vec<Pubky>,
        records: FakePublicRecords,
        resolver: FakeHomeservers,
        state: PollState,
    }

    impl Fixture {
        /// A bounty of `targets`, and a fresh device key.
        fn new(targets: Value) -> Self {
            let home = private_temp();
            let dirs = dirs_in(&home);
            let owner = random_pubky();
            let key = DeviceIdentity::generate();
            let bounty = BountyRef {
                owner,
                id: record_id(1),
            };
            let record = bounty_json(targets);
            let records =
                FakePublicRecords::default().with_record(owner, &paths::bounty(bounty.id), &record);
            // The roster poll's summary of the bounty, as it keeps one of
            // each bounty of the owner's it read.
            let mut state = PollState::default();
            let parsed = Bounty::from_json(&json_bytes(&record)).expect("a bounty");
            state
                .bounties
                .insert(bounty, BountySummary::new(&parsed, None));
            Self {
                _home: home,
                dirs,
                owner,
                key,
                bounty,
                members: Vec::new(),
                records,
                resolver: FakeHomeservers::default(),
                state,
            }
        }

        /// A package of `sweeper`'s of `bounty`, swept at `shas` (target id
        /// to commit), with [`PLANTED`] in its finding and its attachment.
        fn package(&self, sweeper: Pubky, bounty: BountyRef, shas: Value) -> SweepPackage {
            SweepPackage::from_json(&json_bytes(&package_json(sweeper, bounty, shas)))
                .expect("a package")
        }

        /// `package` sealed as `submit` seals one: to this install's key and
        /// to the sweeper's own.
        fn sealed(&self, package: &SweepPackage) -> Vec<u8> {
            let sweeper_key = DeviceIdentity::generate();
            seal_package(package, &[self.key.recipient(), sweeper_key.recipient()]).expect("sealed")
        }

        /// Puts `record` at `sweep`'s path in its sweeper's storage, and
        /// `package`, when there is one, beside it as its `.age`.
        fn publish(&mut self, sweep: SweepRef, record: &Value, package: Option<Vec<u8>>) {
            // `mem::take` moves the fake out, leaving an empty one, so the
            // builder methods, which take it by value, can be chained on it.
            let records = mem::take(&mut self.records).with_record(
                sweep.sweeper,
                &paths::sweep_record(sweep.id),
                record,
            );
            self.records = match package {
                Some(bytes) => {
                    records.with_file(sweep.sweeper, &paths::sweep_package(sweep.id), bytes)
                }
                None => records,
            };
        }

        /// Summarises `record` as `sweep`'s in the poll state, as the roster
        /// poll or the feed watcher would have; a stranger's as accepted.
        fn summarise(&mut self, sweep: SweepRef, record: &Value) {
            let parsed = Sweep::from_json(&json_bytes(record)).expect("a sweep");
            self.state
                .sweeps
                .insert(sweep, SweepSummary::new(&parsed, None));
            if !self.roster().is_in_roster(sweep.sweeper) {
                self.state
                    .accepted_sweeps
                    .entry(parsed.bounty.id)
                    .or_default()
                    .insert(sweep);
            }
        }

        /// `sweeper`'s done sweep `n` of the bounty, of target `t1` at
        /// [`SYNTHETIC_SHA`], sealed for this install, published and
        /// summarised: what the usual sweep looks like to `pull`.
        fn submit(&mut self, sweeper: Pubky, n: u64) -> SweepRef {
            let sweep = sweep_of(sweeper, n);
            let package = self.package(sweeper, self.bounty, json!({ "t1": SYNTHETIC_SHA }));
            let record = done_record(self.bounty, &["t1"]);
            self.publish(sweep, &record, Some(self.sealed(&package)));
            self.summarise(sweep, &record);
            sweep
        }

        /// The roster: the owner and [`members`](Self::members).
        fn roster(&self) -> Circle {
            let record = circle_json(self.owner, &self.members);
            Circle::from_json(&json_bytes(&record)).expect("a circle")
        }

        /// One run's opens, with a fresh cache of homeservers, as each run
        /// starts with.
        async fn open(&mut self) -> Opened {
            let roster = self.roster();
            let mut homeservers = Homeservers::new(&self.resolver);
            open_sweeps(
                &self.records,
                &mut homeservers,
                &self.dirs,
                &self.key,
                self.owner,
                &roster,
                &mut self.state,
            )
            .await
        }

        /// Where `sweep` of the bounty is stored, or `None` when it is not.
        fn stored(&self, sweep: SweepRef) -> Option<Placement> {
            stored_findings(&self.dirs, self.bounty, sweep)
                .expect("readable")
                .map(|(placement, _)| placement)
        }

        /// Whether `pull` asked for `sweep`'s package.
        fn package_asked(&self, sweep: SweepRef) -> bool {
            self.records
                .asked()
                .contains(&(sweep.sweeper, paths::sweep_package(sweep.id)))
        }
    }

    /// `sweeper`'s sweep with record id `n`: ids order as `n` does.
    fn sweep_of(sweeper: Pubky, n: u64) -> SweepRef {
        SweepRef {
            sweeper,
            id: record_id(n),
        }
    }

    /// The sweeps `opened` stored, in the order stored.
    fn stored_sweeps(opened: &Opened) -> Vec<SweepRef> {
        opened.stored.iter().map(|done| done.sweep).collect()
    }

    /// The one warning that names `sweep`.
    fn warning_about(opened: &Opened, sweep: SweepRef) -> &str {
        let url = sweep.to_string();
        let found: Vec<&String> = opened
            .warnings
            .iter()
            .filter(|warning| warning.contains(&url))
            .collect();
        assert_eq!(found.len(), 1, "{:?}", opened.warnings);
        found[0]
    }

    /// Checks that nothing `open_sweeps` hands back, printed, holds a
    /// finding or could drive a terminal.
    fn assert_prints_no_finding(opened: &Opened) {
        let printed = format!("{opened:?}");
        assert!(!printed.contains(PLANTED), "{printed}");
        for warning in &opened.warnings {
            assert!(!warning.contains(PLANTED), "{warning}");
            assert!(!warning.chars().any(char::is_control), "{warning:?}");
        }
    }

    #[tokio::test]
    async fn a_package_sealed_now_opens_binds_and_is_stored_and_nothing_printed_holds_a_finding() {
        let mut fx = Fixture::new(json!([repo_target_json("t1")]));
        let (member, stranger) = (random_pubky(), random_pubky());
        fx.members.push(member);
        let trusted = fx.submit(member, 10);
        let untrusted = fx.submit(stranger, 11);

        let opened = fx.open().await;
        assert!(opened.warnings.is_empty(), "{:?}", opened.warnings);
        assert_prints_no_finding(&opened);
        // Both written, the circle's first, the stranger's apart.
        let sweeps = stored_sweeps(&opened);
        assert_eq!(sweeps, [trusted, untrusted]);
        assert!(
            opened
                .stored
                .iter()
                .all(|done| done.bounty == fx.bounty && matches!(done.stored, Stored::Written(_)))
        );
        let (placement, findings) = stored_findings(&fx.dirs, fx.bounty, trusted)
            .expect("readable")
            .expect("stored");
        assert_eq!(placement, Placement::Trusted);
        assert_eq!(findings.findings[0].title, PLANTED);
        assert_eq!(fx.stored(untrusted), Some(Placement::Untrusted));
        // Each read from its sweeper's own storage.
        assert!(fx.package_asked(trusted) && fx.package_asked(untrusted));
        assert!(fx.state.sweeps[&trusted].pulled && fx.state.sweeps[&untrusted].pulled);

        // Pulled, so the next run opens neither again.
        let asked = fx.records.asked().len();
        let again = fx.open().await;
        assert!(again.stored.is_empty() && again.warnings.is_empty());
        assert_eq!(fx.records.asked().len(), asked);
    }

    #[tokio::test]
    async fn a_package_sealed_to_another_key_only_is_not_encrypted_to_this_install_s_key() {
        // The unit form of 06's "a device key published after a sweep
        // cannot decrypt it": the sweep was sealed to the keys the owner
        // had then, and this install's is not among them.
        let mut fx = Fixture::new(json!([repo_target_json("t1")]));
        let sweeper = random_pubky();
        fx.members.push(sweeper);
        let sweep = sweep_of(sweeper, 10);
        let package = fx.package(sweeper, fx.bounty, json!({ "t1": SYNTHETIC_SHA }));
        let earlier_key = DeviceIdentity::generate();
        let sealed = seal_package(&package, &[earlier_key.recipient()]).expect("sealed");
        let record = done_record(fx.bounty, &["t1"]);
        fx.publish(sweep, &record, Some(sealed));
        fx.summarise(sweep, &record);

        let opened = fx.open().await;
        assert!(opened.stored.is_empty());
        let warning = warning_about(&opened, sweep);
        assert!(warning.contains(NOT_FOR_THIS_KEY), "{warning}");
        assert_prints_no_finding(&opened);
        assert_eq!(fx.stored(sweep), None);
        // Refused for good: every later run would meet the same package.
        let summary = &fx.state.sweeps[&sweep];
        assert!(summary.refused && !summary.pulled);
        let asked = fx.records.asked().len();
        let again = fx.open().await;
        assert!(again.warnings.is_empty(), "{:?}", again.warnings);
        assert_eq!(fx.records.asked().len(), asked);
    }

    #[tokio::test]
    async fn what_binding_leaves_to_pull_is_checked_and_a_refused_sweep_stores_nothing() {
        // t1 a repo at SYNTHETIC_SHA, t2 a pull request whose reviewed
        // commit is its head, SYNTHETIC_HEAD, not its base, SYNTHETIC_SHA.
        let mut fx = Fixture::new(json!([repo_target_json("t1"), pr_target_json("t2")]));
        let other_bounty = BountyRef {
            owner: fx.owner,
            id: record_id(2),
        };
        let pinned = json!({ "t1": SYNTHETIC_SHA, "t2": SYNTHETIC_HEAD });
        let sweepers: Vec<Pubky> = (0..5).map(|_| random_pubky()).collect();
        fx.members.extend(&sweepers);
        let sweep = |i: usize| sweep_of(sweepers[i], 10 + i as u64);
        let (bound, elsewhere, off_target, unpinned, copied) =
            (sweep(0), sweep(1), sweep(2), sweep(3), sweep(4));
        let both = done_record(fx.bounty, &["t1", "t2"]);

        // Bound: swept at the pins, a pull request at its head.
        let bound_package = fx.sealed(&fx.package(bound.sweeper, fx.bounty, pinned.clone()));
        fx.publish(bound, &both, Some(bound_package.clone()));
        fx.summarise(bound, &both);
        // The record names another bounty of the owner's than the one its
        // summary was pulled for, and the package agrees with the record.
        let other = done_record(other_bounty, &["t1", "t2"]);
        let package = fx.package(elsewhere.sweeper, other_bounty, pinned.clone());
        fx.publish(elsewhere, &other, Some(fx.sealed(&package)));
        fx.summarise(elsewhere, &both);
        // A target the bounty does not have.
        let t9 = done_record(fx.bounty, &["t9"]);
        let package = fx.package(
            off_target.sweeper,
            fx.bounty,
            json!({ "t9": SYNTHETIC_SHA }),
        );
        fx.publish(off_target, &t9, Some(fx.sealed(&package)));
        fx.summarise(off_target, &t9);
        // The pull request swept at its base.
        let base = json!({ "t1": SYNTHETIC_SHA, "t2": SYNTHETIC_SHA });
        let package = fx.package(unpinned.sweeper, fx.bounty, base);
        fx.publish(unpinned, &both, Some(fx.sealed(&package)));
        fx.summarise(unpinned, &both);
        // The bound package copied under another sweeper's own record: the
        // path it is fetched from names that sweeper, the manifest the first.
        fx.publish(copied, &both, Some(bound_package));
        fx.summarise(copied, &both);

        let opened = fx.open().await;
        assert_prints_no_finding(&opened);
        let stored = stored_sweeps(&opened);
        assert_eq!(stored, [bound]);
        assert_eq!(fx.stored(bound), Some(Placement::Trusted));
        for (refused, reason) in [
            (elsewhere, "names another bounty than the one being pulled"),
            (off_target, "names a target this bounty does not have"),
            (unpinned, "swept at other revisions than the bounty pins"),
            (
                copied,
                "names another sweeper than the one whose storage it came from",
            ),
        ] {
            let warning = warning_about(&opened, refused);
            assert!(warning.contains(reason), "{warning}");
            assert_eq!(fx.stored(refused), None, "{reason}");
            assert!(fx.state.sweeps[&refused].refused, "{reason}");
        }
        // The record's own faults are found before its package is read.
        assert!(!fx.package_asked(elsewhere) && !fx.package_asked(off_target));
    }

    #[tokio::test]
    async fn a_package_over_the_cap_is_refused_before_it_is_opened_and_a_missing_one_warns() {
        let mut fx = Fixture::new(json!([repo_target_json("t1")]));
        let (big, missing) = (random_pubky(), random_pubky());
        fx.members.extend([big, missing]);
        let record = done_record(fx.bounty, &["t1"]);
        let big_sweep = sweep_of(big, 10);
        fx.publish(big_sweep, &record, Some(vec![0; MAX_CIPHERTEXT_BYTES + 1]));
        fx.summarise(big_sweep, &record);
        let missing_sweep = sweep_of(missing, 11);
        fx.publish(missing_sweep, &record, None);
        fx.summarise(missing_sweep, &record);

        let opened = fx.open().await;
        assert!(opened.stored.is_empty());
        // The cap's own reason, not one of decryption's.
        let warning = warning_about(&opened, big_sweep);
        assert!(
            warning.contains(&format!("larger than the {MAX_CIPHERTEXT_BYTES} bytes")),
            "{warning}"
        );
        assert!(!warning.contains("decrypted:"), "{warning}");
        let warning = warning_about(&opened, missing_sweep);
        assert!(warning.contains("holds no package"), "{warning}");
        for sweep in [big_sweep, missing_sweep] {
            assert_eq!(fx.stored(sweep), None);
            assert!(fx.state.sweeps[&sweep].refused);
        }
    }

    #[tokio::test]
    async fn findings_too_large_to_write_out_are_a_warning_for_that_sweep_alone() {
        let mut fx = Fixture::new(json!([repo_target_json("t1")]));
        let (deep, plain) = (random_pubky(), random_pubky());
        fx.members.extend([deep, plain]);
        // A zero 100 arrays down takes 2 bytes compact and over 200
        // pretty-printed, so these findings fit a package but come to over
        // twice the cap as findings.json (core's own test of `into_files`).
        const DEPTH: usize = 100;
        let mut nested = Value::Array(vec![Value::from(0); MAX_FINDINGS_FILE_BYTES / DEPTH]);
        for _ in 0..DEPTH {
            nested = Value::Array(vec![nested]);
        }
        let mut value = package_json(deep, fx.bounty, json!({ "t1": SYNTHETIC_SHA }));
        value["findings"]["findings"][0]["extra"] = json!({ "deep": nested });
        let package = SweepPackage::from_json(&json_bytes(&value)).expect("a package");
        let deep_sweep = sweep_of(deep, 10);
        let record = done_record(fx.bounty, &["t1"]);
        fx.publish(deep_sweep, &record, Some(fx.sealed(&package)));
        fx.summarise(deep_sweep, &record);
        let plain_sweep = fx.submit(plain, 11);

        // The pull goes on: the other sweep is stored.
        let opened = fx.open().await;
        let warning = warning_about(&opened, deep_sweep);
        assert!(warning.contains("128 MiB"), "{warning}");
        assert_eq!(fx.stored(deep_sweep), None);
        assert!(fx.state.sweeps[&deep_sweep].refused);
        assert_eq!(fx.stored(plain_sweep), Some(Placement::Trusted));
    }

    #[tokio::test]
    async fn a_stranger_s_sweep_with_an_agent_instruction_file_is_refused_for_good() {
        // A file the owner's agent would load as instructions once it read
        // `untrusted/`: the store refuses the path, and every later run
        // would refuse it again.
        let mut fx = Fixture::new(json!([repo_target_json("t1")]));
        let stranger = random_pubky();
        let sweep = sweep_of(stranger, 10);
        let mut value = package_json(stranger, fx.bounty, json!({ "t1": SYNTHETIC_SHA }));
        value["attachments"]["audit/CLAUDE.md"] = json!(PLANTED);
        let package = SweepPackage::from_json(&json_bytes(&value)).expect("a package");
        let record = done_record(fx.bounty, &["t1"]);
        fx.publish(sweep, &record, Some(fx.sealed(&package)));
        fx.summarise(sweep, &record);

        let opened = fx.open().await;
        let warning = warning_about(&opened, sweep);
        assert!(warning.contains("load as their instructions"), "{warning}");
        assert!(!warning.contains("CLAUDE"), "{warning}");
        assert_prints_no_finding(&opened);
        assert_eq!(fx.stored(sweep), None);
        let summary = &fx.state.sweeps[&sweep];
        assert!(summary.refused && !summary.pulled);
        let asked = fx.records.asked().len();
        let again = fx.open().await;
        assert!(again.warnings.is_empty(), "{:?}", again.warnings);
        assert_eq!(fx.records.asked().len(), asked);
    }

    #[tokio::test]
    async fn the_cap_per_bounty_stops_a_run_with_a_warning_and_the_rest_open_next_run() {
        let mut fx = Fixture::new(json!([repo_target_json("t1")]));
        // Five members with their share each: one more turn than the cap
        // per bounty leaves room for.
        let members: Vec<Pubky> = (0..5).map(|_| random_pubky()).collect();
        fx.members.extend(&members);
        let mut sweeps = Vec::new();
        for (i, member) in members.iter().enumerate() {
            for j in 0..MAX_OPENS_PER_SWEEPER {
                sweeps.push(fx.submit(*member, (100 + 10 * i + j) as u64));
            }
        }
        let waiting = sweeps.len() - MAX_OPENS_PER_BOUNTY;

        let first = fx.open().await;
        assert_eq!(first.stored.len(), MAX_OPENS_PER_BOUNTY);
        assert_eq!(first.warnings.len(), 1, "{:?}", first.warnings);
        let warning = &first.warnings[0];
        assert!(
            warning.contains(&format!("{waiting} sweeps of {} wait", fx.bounty)),
            "{warning}"
        );
        let second = fx.open().await;
        assert!(second.warnings.is_empty(), "{:?}", second.warnings);
        assert_eq!(second.stored.len(), waiting);
        // Between the two, every sweep once.
        let mut opened: Vec<SweepRef> = first
            .stored
            .iter()
            .chain(&second.stored)
            .map(|done| done.sweep)
            .collect();
        opened.sort();
        sweeps.sort();
        assert_eq!(opened, sweeps);
        assert!(sweeps.iter().all(|sweep| fx.state.sweeps[sweep].pulled));
    }

    #[tokio::test]
    async fn a_stranger_s_fifty_sweeps_leave_room_for_every_other_sweeper() {
        let mut fx = Fixture::new(json!([repo_target_json("t1")]));
        let (flooder, stranger, member) = (random_pubky(), random_pubky(), random_pubky());
        fx.members.push(member);
        // The flood is older than the other two sweeps.
        let flood: Vec<SweepRef> = (0..50).map(|n| fx.submit(flooder, 100 + n)).collect();
        let lone = fx.submit(stranger, 500);
        let circle = fx.submit(member, 600);

        let opened = fx.open().await;
        let stored = stored_sweeps(&opened);
        // The circle first, then the strangers in turn: the flooder's
        // oldest, the other stranger's, then the rest of the flooder's share.
        let mut expected = vec![circle, flood[0], lone];
        expected.extend(&flood[1..MAX_OPENS_PER_SWEEPER]);
        assert_eq!(stored, expected);
        assert_eq!(fx.stored(lone), Some(Placement::Untrusted));
        let left = flood.len() - MAX_OPENS_PER_SWEEPER;
        assert!(
            opened.warnings[0].contains(&format!("{left} sweeps of")),
            "{:?}",
            opened.warnings
        );
    }

    #[test]
    fn the_circle_goes_first_and_strangers_take_turns_within_their_share() {
        let circle_key = random_pubky();
        let (flooder, second, third) = (random_pubky(), random_pubky(), random_pubky());
        let roster_json = circle_json(random_pubky(), &[circle_key]);
        let roster = Circle::from_json(&json_bytes(&roster_json)).expect("a circle");
        let mut waiting: Vec<SweepRef> = (1..=50).map(|n| sweep_of(flooder, n)).collect();
        waiting.extend([sweep_of(second, 60), sweep_of(third, 70)]);
        // The circle's sweeps are the newest, and its member has more than
        // a share.
        waiting.extend((80..90).map(|n| sweep_of(circle_key, n)));

        let order = fair_order(waiting, &roster);
        let mut expected: Vec<SweepRef> = (80..84).map(|n| sweep_of(circle_key, n)).collect();
        expected.extend([
            sweep_of(flooder, 1),
            sweep_of(second, 60),
            sweep_of(third, 70),
            sweep_of(flooder, 2),
            sweep_of(flooder, 3),
            sweep_of(flooder, 4),
        ]);
        assert_eq!(order, expected);
    }

    #[tokio::test]
    async fn only_done_sweeps_are_opened() {
        let mut fx = Fixture::new(json!([repo_target_json("t1")]));
        let member = random_pubky();
        fx.members.push(member);
        let mut sweeps = Vec::new();
        for (n, status) in [(10, "running"), (11, "aborted")] {
            let sweep = sweep_of(member, n);
            let record = sweep_json(fx.bounty, &["t1"], status);
            fx.publish(sweep, &record, None);
            fx.summarise(sweep, &record);
            sweeps.push(sweep);
        }

        let opened = fx.open().await;
        assert!(opened.stored.is_empty() && opened.warnings.is_empty());
        assert!(fx.records.asked().is_empty(), "{:?}", fx.records.asked());
        for sweep in sweeps {
            let summary = &fx.state.sweeps[&sweep];
            assert!(!summary.pulled && !summary.refused);
        }
    }

    #[tokio::test]
    async fn a_sweeper_who_cannot_be_reached_is_skipped_this_run_and_opened_the_next() {
        let mut fx = Fixture::new(json!([repo_target_json("t1")]));
        let (away, member) = (random_pubky(), random_pubky());
        fx.members.extend([away, member]);
        let late = fx.submit(away, 10);
        let kept = fx.submit(member, 11);
        fx.resolver = FakeHomeservers::default().with_answers(
            away,
            &[FakeLookup::NoRecord, FakeLookup::At(FAKE_HOMESERVER)],
        );

        let first = fx.open().await;
        let stored = stored_sweeps(&first);
        assert_eq!(stored, [kept]);
        assert_eq!(first.warnings.len(), 1, "{:?}", first.warnings);
        assert!(first.warnings[0].contains(&away.to_string()));
        // Not read, so not refused: the next run tries again.
        assert!(!fx.package_asked(late));
        assert!(!fx.state.sweeps[&late].refused);

        let second = fx.open().await;
        let stored = stored_sweeps(&second);
        assert_eq!(stored, [late]);
    }
}
