//! Which target `run` sweeps when it is given no bounty URL (03's `run`
//! row: "picks a target from the circle's open bounties with the fewest
//! sweeps"): of the targets open to the sweeper in the bounties of a
//! circle's members, the one their own sweep records name least.
//!
//! [`pick_target`] reads public records alone, through `PublicRecords`,
//! with no session, in this order:
//!
//! 1. **The circle.** The one `--circle <admin>` names, else this install's
//!    own: the `circle.json` in the sweeper's own storage. It must name the
//!    key whose storage holds it as its admin (anyone can put any file in
//!    their own storage, so a roster counts only in its admin's), and list
//!    the sweeper. With neither a `--circle` nor a circle of one's own,
//!    `run` says to give a bounty's URL or `--circle`.
//! 2. **The open targets.** For each of the first [`MAX_MEMBERS`] keys of
//!    its roster, the admin first and then the members, each once by key
//!    bytes: the newest [`MAX_BOUNTIES_PER_MEMBER`] bounty records that
//!    key's `bounties/` lists. A bounty is open to the sweeper when `run`
//!    would accept it with its URL, by the same `select::accept`: status
//!    `open`, and open to anyone, or closed and in a roster that lists the
//!    sweeper (its owner's own `circle.json`, or under `--circle` the circle
//!    named). Each of its targets that `run --target` would take, by the
//!    same `select::choose_targets`, is open to the sweeper: a target of an
//!    unknown kind, a malformed one and one the source's policy refuses are
//!    not, nor any target of a bounty whose ids collide when case is
//!    ignored or that has more than `MAX_TARGETS`, which `post` never
//!    writes.
//! 3. **The counts**, when any target is open: for each of the same keys,
//!    the newest [`MAX_SWEEPS_PER_MEMBER`] sweep records its `sweeps/`
//!    lists. A `running` or `done` record adds one to each open target it
//!    names, by its bounty and id. An `aborted` one swept nothing, so it
//!    counts for nothing, as do one of a status this build does not know,
//!    one naming another bounty, and one naming more targets than one run
//!    takes (`MAX_TARGETS`), which no `run` wrote. A stranger's never
//!    counts: only the roster's `sweeps/` are read.
//! 4. **The pick.** The open target with the fewest. A tie goes to the
//!    older bounty, the one with the lower id (a record id is its creation
//!    time), then to the target earlier in that bounty's own order, then to
//!    the owner with the lower key, so the pick never depends on the order
//!    in which the records were read.
//!
//! **Bounds**, P2b's choice, since 01 sets none: 32 keys, 01's "a circle of
//! under ~30" (05 moves to event streams past that), 16 bounty records and
//! 32 sweep records of each, the newest by id. So picking reads at most 32
//! `circle.json`s (the one picked from, then each owner's own, once each),
//! 32 × 16 bounty records and 32 × 32 sweep records, each capped at
//! `MAX_RECORD_BYTES` before it is parsed, and two listings of each key,
//! each within `ListLimits::DEFAULT` (`records.rs`). The newest come from
//! the whole listing, sorted by id, so a listing in any order, as a hostile
//! server may send, gives the same records. Limit: `remote::list_dir`
//! lists oldest first and refuses a listing past 1000 entries whole, so a
//! key whose `sweeps/` holds more than 500 sweeps (a record and a package
//! each) has its sweeps skipped with a warning; reverse paging, which 01
//! asks `pull` for, would lift it.
//!
//! **Faults skip, they do not stop.** A listing that cannot be read or
//! breaks the protocol (`list_dir` refuses it whole) skips that key's
//! bounties or sweeps, with a warning that names the key and the reason.
//! Records that cannot be read or parsed are skipped, with one warning per
//! key and kind that counts them and gives the first reason. An owner's
//! `circle.json` that cannot be read skips their closed bounties, with a
//! warning. Every reason is fixed text, and a warning names nothing else
//! but a key and a path, which this build checked: a roster's keys are
//! public keys, and the one `--circle` named has proved to be one by
//! holding the circle that names it. Only the circle picked from is needed.
//!
//! **The pick is advisory.** `run` then checks the picked bounty and target
//! exactly as it would with the bounty's URL and `--target`, reading the
//! bounty again, so what it sweeps is decided by the same code on fresh
//! records, and a bounty closed in between is refused there. No stranger's
//! text is printed here: the pick names the bounty by its URL and the
//! target by its id, both checked values, and `run`'s summary that follows
//! shows the title and focus through the sanitiser.

use std::cmp::Reverse;
use std::collections::HashMap;
use std::iter;

use anyhow::bail;
use sweepky_core::{
    Bounty, BountyRef, Circle, KnownSweepStatus, Pubky, RecordId, Sweep, SweepRef, TargetId,
};

use super::RunRequest;
use super::select;
use crate::post::draft::MAX_TARGETS;
use crate::records::PublicRecords;
use crate::targets::TargetResolver;

/// The most keys of the roster picking reads, its admin first.
pub(crate) const MAX_MEMBERS: usize = 32;

/// The most bounty records picking reads of one key: the newest.
pub(crate) const MAX_BOUNTIES_PER_MEMBER: usize = 16;

/// The most sweep records picking reads of one key: the newest.
pub(crate) const MAX_SWEEPS_PER_MEMBER: usize = 32;

/// What `run` stops with when no target in the circle is open to the
/// sweeper.
pub(crate) const NOTHING_OPEN: &str = "there is no open bounty to pick: none of the circle's \
                                       members has an open bounty you may run with a target this \
                                       build can sweep; give a bounty's URL to run one";

/// What [`pick_target`] found: the target it picked, if any, and a line for
/// each fault it skipped.
#[derive(Debug)]
pub(crate) struct Pick {
    /// The target to sweep, or `None` when nothing in the circle is open to
    /// the sweeper ([`NOTHING_OPEN`]).
    pub(crate) choice: Option<Choice>,
    /// One line for each listing or `circle.json` that could not be read,
    /// one for each key with records that could not be, and one when the
    /// roster was cut at [`MAX_MEMBERS`].
    pub(crate) warnings: Vec<String>,
}

/// The target picked, and how it compared.
#[derive(Debug)]
pub(crate) struct Choice {
    /// Its bounty.
    pub(crate) bounty: BountyRef,
    /// Its id in that bounty, which `run` then sweeps as `--target`.
    pub(crate) target: TargetId,
    /// How many of the circle's sweep records name it.
    pub(crate) sweeps: usize,
    /// How many open targets it was picked from.
    pub(crate) considered: usize,
}

impl Pick {
    /// What `run` shows before it checks the pick: each warning, then the
    /// pick. Every value in it is a checked one.
    pub(crate) fn summary(&self) -> String {
        let mut text: String = self
            .warnings
            .iter()
            .map(|warning| format!("warning: {warning}\n"))
            .collect();
        if let Some(choice) = &self.choice {
            text.push_str(&format!(
                "Picked target {} of the bounty {}, the least swept of the {} open targets read in \
                 the circle (sweep records naming it: {}).\n",
                choice.target, choice.bounty, choice.considered, choice.sweeps
            ));
        }
        text
    }
}

/// Picks the target `sweeper` sweeps with no bounty URL, from the circle
/// `circle` (`--circle`) names, else the sweeper's own: see the module docs
/// for the rules and the bounds. Fails only when there is no such circle to
/// pick from; every other fault is a warning in the [`Pick`].
pub(crate) async fn pick_target(
    records: &impl PublicRecords,
    source: &impl TargetResolver,
    sweeper: Pubky,
    circle: Option<Pubky>,
) -> anyhow::Result<Pick> {
    let roster = picking_circle(records, sweeper, circle).await?;
    let (members, cut) = roster_members(&roster);
    let mut picker = Picker {
        records,
        source,
        sweeper,
        flag: circle,
        // The circle picked from is the first one known, so it is never read
        // again: under `--circle` it decides every bounty, and in the
        // sweeper's own circle it decides the sweeper's own closed bounties.
        circles: HashMap::from([(roster.admin, Some(roster))]),
        open: HashMap::new(),
        warnings: Vec::new(),
    };
    if cut {
        picker.warnings.push(format!(
            "the circle lists more than {MAX_MEMBERS} keys; picking reads the first {MAX_MEMBERS}, \
             its admin first"
        ));
    }
    for &member in &members {
        picker.read_open_targets(member).await;
    }
    // With no target open, no count can matter, so no sweep is read.
    if !picker.open.is_empty() {
        for &member in &members {
            picker.count_sweeps(member).await;
        }
    }
    Ok(Pick {
        choice: least_swept(&picker.open),
        warnings: picker.warnings,
    })
}

/// The circle to pick from: the one the key `flag` (`--circle`) names
/// keeps, else the sweeper's own. Refused when there is none, when it names
/// another admin, and when it does not list the sweeper. No refusal names
/// the key `--circle` was given.
async fn picking_circle(
    records: &impl PublicRecords,
    sweeper: Pubky,
    flag: Option<Pubky>,
) -> anyhow::Result<Circle> {
    let holder = flag.unwrap_or(sweeper);
    let Some(circle) = records.get_circle(holder).await? else {
        if flag.is_some() {
            bail!(
                "the key --circle names keeps no circle.json, so run has no circle to pick from; \
                 give a bounty's URL, or another --circle"
            );
        }
        bail!(
            "you keep no circle of your own (no circle.json in your storage) to pick a bounty \
             from: give a bounty's URL, or --circle <admin> to pick from the circle that key keeps"
        );
    };
    // `Pubky`'s `==` compares the 32 key bytes, never a spelling.
    if circle.admin != holder {
        let whose = match flag {
            Some(_) => "the storage of the key --circle names",
            None => "your storage",
        };
        bail!(
            "the circle.json in {whose} names another admin, so it is not that key's roster to \
             pick from"
        );
    }
    // Only a `--circle` can fail this: the sweeper is the admin of their
    // own circle.
    if !circle.is_in_roster(sweeper) {
        bail!("you are not in the circle --circle names, so run picks nothing from it");
    }
    Ok(circle)
}

/// The keys of `roster` picking reads, in its order: the admin, then each
/// member, once each, at most [`MAX_MEMBERS`]; and whether it lists more.
fn roster_members(roster: &Circle) -> (Vec<Pubky>, bool) {
    let mut members: Vec<Pubky> = Vec::with_capacity(MAX_MEMBERS);
    // `once` gives the admin alone; `chain` goes on with every member.
    let roster_order = iter::once(roster.admin).chain(roster.members.iter().map(|m| m.pubky));
    for pubky in roster_order {
        // A linear search, over at most `MAX_MEMBERS` keys.
        if members.contains(&pubky) {
            continue;
        }
        if members.len() == MAX_MEMBERS {
            return (members, true);
        }
        members.push(pubky);
    }
    (members, false)
}

/// The targets open to the sweeper, by bounty, each bounty's in its own
/// order.
type OpenTargets = HashMap<BountyRef, Vec<OpenTarget>>;

/// One target open to the sweeper, and how many of the circle's sweep
/// records name it.
struct OpenTarget {
    id: TargetId,
    sweeps: usize,
}

/// The two kinds of record picking lists and reads of each key.
#[derive(Clone, Copy)]
enum RecordKind {
    Bounty,
    Sweep,
}

impl RecordKind {
    /// The most of this kind picking reads of one key.
    fn max_per_member(self) -> usize {
        match self {
            Self::Bounty => MAX_BOUNTIES_PER_MEMBER,
            Self::Sweep => MAX_SWEEPS_PER_MEMBER,
        }
    }

    /// Its name in a warning.
    fn name(self) -> &'static str {
        match self {
            Self::Bounty => "bounty",
            Self::Sweep => "sweep",
        }
    }
}

/// What picking reads through, and what it has found so far.
///
/// Generic over the two seams, `R` and `S`, as a function taking
/// `&impl PublicRecords` is: `impl Trait` in an argument is shorthand for
/// such a type parameter, which a struct has to spell out. The bounds are
/// on the `impl` block below, where the methods need them.
struct Picker<'a, R, S> {
    records: &'a R,
    source: &'a S,
    sweeper: Pubky,
    /// `--circle <admin>`, which `run` checks every bounty against.
    flag: Option<Pubky>,
    /// Each `circle.json` read so far, or `None` where there was none or it
    /// could not be read, by the key whose storage holds it.
    circles: HashMap<Pubky, Option<Circle>>,
    open: OpenTargets,
    warnings: Vec<String>,
}

impl<R: PublicRecords, S: TargetResolver> Picker<'_, R, S> {
    /// Adds the targets of `member`'s newest bounties that are open to the
    /// sweeper.
    async fn read_open_targets(&mut self, member: Pubky) {
        // A copy of the reference, so the closure below borrows this local
        // and not `self`, which `read_newest` borrows mutably.
        let records = self.records;
        let bounties = self
            .read_newest(member, RecordKind::Bounty, async |id| {
                records.get_bounty(BountyRef { owner: member, id }).await
            })
            .await;
        for (id, bounty) in bounties {
            let bounty_ref = BountyRef { owner: member, id };
            if !self.accepts(bounty_ref, &bounty).await {
                continue;
            }
            let targets = open_targets_in(&bounty, self.source);
            if !targets.is_empty() {
                self.open.insert(bounty_ref, targets);
            }
        }
    }

    /// Whether `run` would accept `bounty` with its URL, by
    /// `select::accept` and the circle that decides, if any.
    async fn accepts(&mut self, bounty_ref: BountyRef, bounty: &Bounty) -> bool {
        let request = RunRequest {
            bounty: bounty_ref,
            sweeper: self.sweeper,
            circle: self.flag,
            target: None,
        };
        let circle = match select::circle_to_read(&request, bounty) {
            Some(holder) => self.circle_of(holder).await,
            None => None,
        };
        select::accept(&request, bounty, circle).is_ok()
    }

    /// The `circle.json` `holder`'s storage holds, read the first time it
    /// is asked for and kept: `None` when there is none, or when it could
    /// not be read, which is a warning.
    async fn circle_of(&mut self, holder: Pubky) -> Option<&Circle> {
        // Not `entry(..).or_insert_with(..)`: the read is `async`, and that
        // closure cannot wait for it.
        if !self.circles.contains_key(&holder) {
            let circle = match self.records.get_circle(holder).await {
                Ok(circle) => circle,
                Err(error) => {
                    self.warnings.push(format!(
                        "the circle.json of circle member {holder} could not be read, so picking \
                         skips their closed bounties: {error:#}"
                    ));
                    None
                }
            };
            self.circles.insert(holder, circle);
        }
        // `get` gives an `Option<&Option<Circle>>`; `and_then(Option::as_ref)`
        // turns it into the `Option<&Circle>` the caller wants.
        self.circles.get(&holder).and_then(Option::as_ref)
    }

    /// Adds `member`'s newest sweep records to the counts of the open
    /// targets they name.
    async fn count_sweeps(&mut self, member: Pubky) {
        let records = self.records;
        let sweeps = self
            .read_newest(member, RecordKind::Sweep, async |id| {
                records
                    .get_sweep(SweepRef {
                        sweeper: member,
                        id,
                    })
                    .await
            })
            .await;
        for (_, sweep) in sweeps {
            count_sweep(&mut self.open, &sweep);
        }
    }

    /// The newest records of `kind` that `member`'s directory lists
    /// ([`newest_listed`](Self::newest_listed)), each read through `read`,
    /// with one warning for those that could not be, which counts them and
    /// gives the first reason. A record listed but gone by the time it is
    /// read is skipped quietly.
    // `impl AsyncFn(RecordId) -> ..` takes an async closure that may be
    // called more than once: one helper for both kinds, each passing its
    // own read. `T` is the record type that read gives.
    async fn read_newest<T>(
        &mut self,
        member: Pubky,
        kind: RecordKind,
        read: impl AsyncFn(RecordId) -> anyhow::Result<Option<T>>,
    ) -> Vec<(RecordId, T)> {
        let ids = self.newest_listed(member, kind).await;
        let mut found = Vec::with_capacity(ids.len());
        let mut unread: usize = 0;
        let mut first_fault = None;
        for id in ids {
            match read(id).await {
                Ok(Some(record)) => found.push((id, record)),
                Ok(None) => {}
                Err(error) => {
                    unread = unread.saturating_add(1);
                    // Keeps the first error; a later one is dropped.
                    first_fault.get_or_insert(error);
                }
            }
        }
        if let Some(error) = first_fault {
            self.warnings.push(format!(
                "{unread} of the {} records of circle member {member} could not be read, so \
                 picking skips them; the first: {error:#}",
                kind.name()
            ));
        }
        found
    }

    /// The ids of the newest records of `kind` that `member`'s directory
    /// lists, at most [`RecordKind::max_per_member`], or none, with a
    /// warning, when the listing could not be read.
    async fn newest_listed(&mut self, member: Pubky, kind: RecordKind) -> Vec<RecordId> {
        let listed = match kind {
            RecordKind::Bounty => self.records.list_bounties(member).await,
            RecordKind::Sweep => self.records.list_sweeps(member).await,
        };
        match listed {
            Ok(ids) => newest(ids, kind.max_per_member()),
            Err(error) => {
                self.warnings.push(format!(
                    "the {} records of circle member {member} could not be listed, so picking \
                     skips them: {error:#}",
                    kind.name()
                ));
                Vec::new()
            }
        }
    }
}

/// The `max` newest of `ids`, newest first. A record id is its creation
/// time, so the newest are the highest; sorting first means the order the
/// server listed them in does not matter, and an id listed twice is read
/// once.
fn newest(mut ids: Vec<RecordId>, max: usize) -> Vec<RecordId> {
    // `Reverse` flips the comparison, so the sort puts the highest first.
    ids.sort_unstable_by_key(|&id| Reverse(id));
    ids.dedup();
    ids.truncate(max);
    ids
}

/// The targets of `bounty`, in its order, that `run --target` would take:
/// none when it has more than `MAX_TARGETS`, which `post` never writes and
/// which would make the checks below walk a stranger's thousands of
/// targets once for each.
fn open_targets_in(bounty: &Bounty, source: &impl TargetResolver) -> Vec<OpenTarget> {
    if bounty.targets.len() > MAX_TARGETS {
        return Vec::new();
    }
    bounty
        .targets
        .iter()
        .filter(|target| select::choose_targets(bounty, Some(target.id().as_str()), source).is_ok())
        .map(|target| OpenTarget {
            id: target.id().clone(),
            sweeps: 0,
        })
        .collect()
}

/// Adds one to each open target `sweep` names, when it is `running` or
/// `done` and names no more targets than one run takes.
fn count_sweep(open: &mut OpenTargets, sweep: &Sweep) {
    let swept = matches!(
        sweep.status.as_known(),
        Some(KnownSweepStatus::Running | KnownSweepStatus::Done)
    );
    // The cap keeps `contains` below to at most 32 × 32 comparisons.
    if !swept || sweep.targets.len() > MAX_TARGETS {
        return;
    }
    let Some(targets) = open.get_mut(&sweep.bounty) else {
        return;
    };
    // `contains` counts the sweep once for a target, however often it
    // names it.
    for target in targets
        .iter_mut()
        .filter(|target| sweep.targets.contains(&target.id))
    {
        target.sweeps = target.sweeps.saturating_add(1);
    }
}

/// The open target with the fewest sweeps, ties broken as the module docs
/// say, or `None` when there is none.
fn least_swept(open: &OpenTargets) -> Option<Choice> {
    let considered = open.values().map(Vec::len).sum();
    open.iter()
        // `move` copies `bounty`, a reference, into the inner closure, which
        // outlives this outer one's call.
        .flat_map(|(bounty, targets)| {
            targets
                .iter()
                .enumerate()
                .map(move |(position, target)| (bounty, position, target))
        })
        // A tuple compares field by field: fewest sweeps, then the older
        // bounty, the earlier target, and the lower owner key. No two
        // targets have all four equal, so the order a `HashMap` iterates in
        // never decides.
        .min_by_key(|&(bounty, position, target)| {
            (target.sweeps, bounty.id, position, bounty.owner)
        })
        .map(|(bounty, _, target)| Choice {
            bounty: *bounty,
            target: target.id.clone(),
            sweeps: target.sweeps,
            considered,
        })
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use sweepky_core::paths;
    use sweepky_core::{BountyRef, Pubky};

    use super::{
        Choice, MAX_BOUNTIES_PER_MEMBER, MAX_MEMBERS, MAX_SWEEPS_PER_MEMBER, NOTHING_OPEN, Pick,
        pick_target,
    };
    use crate::targets::TargetSource;
    use crate::test_support::{
        FakePublicRecords, PLANTED, bounty_json, circle_json, random_pubky, record_id,
        repo_target_json, sweep_json,
    };

    /// Bounty `n` of `owner`: its record id is timestamp `n`, so a smaller
    /// `n` is an older bounty.
    fn bounty_ref(owner: Pubky, n: u64) -> BountyRef {
        BountyRef {
            owner,
            id: record_id(n),
        }
    }

    /// A bounty record of repo targets with these ids, status open, open to
    /// anyone or closed.
    fn bounty(targets: &[&str], open: bool) -> Value {
        let targets: Vec<Value> = targets.iter().map(|id| repo_target_json(id)).collect();
        let mut value = bounty_json(json!(targets));
        value["open"] = json!(open);
        value
    }

    /// The fake with `admin`'s `circle.json` listing `members`.
    fn circle(records: FakePublicRecords, admin: Pubky, members: &[Pubky]) -> FakePublicRecords {
        records.with_record(admin, paths::circle(), &circle_json(admin, members))
    }

    /// The fake with `value` as bounty `bounty`.
    fn with_bounty(
        records: FakePublicRecords,
        bounty: BountyRef,
        value: &Value,
    ) -> FakePublicRecords {
        records.with_record(bounty.owner, &paths::bounty(bounty.id), value)
    }

    /// The fake with sweep record `n` of `sweeper`, of `targets` of `bounty`.
    fn with_sweep(
        records: FakePublicRecords,
        sweeper: Pubky,
        n: u64,
        bounty: BountyRef,
        targets: &[&str],
        status: &str,
    ) -> FakePublicRecords {
        records.with_record(
            sweeper,
            &paths::sweep_record(record_id(n)),
            &sweep_json(bounty, targets, status),
        )
    }

    /// What `pick_target` picks from the sweeper's own circle, with the
    /// real source's policy.
    async fn pick(records: &FakePublicRecords, sweeper: Pubky, circle: Option<Pubky>) -> Pick {
        pick_target(records, &TargetSource::Real, sweeper, circle)
            .await
            .unwrap_or_else(|error| panic!("{error:#}"))
    }

    /// The bounty and target id `pick` chose.
    fn chosen(pick: &Pick) -> (BountyRef, &str, usize) {
        let Some(Choice {
            bounty,
            target,
            sweeps,
            ..
        }) = &pick.choice
        else {
            panic!("nothing picked: {:?}", pick.warnings);
        };
        (*bounty, target.as_str(), *sweeps)
    }

    /// Every record of `owner` read under `dir`, in order: the listings
    /// (which end with `/`) left out.
    fn records_read(records: &FakePublicRecords, owner: Pubky, dir: &str) -> Vec<String> {
        records
            .asked()
            .into_iter()
            .filter(|(asked, path)| *asked == owner && path.starts_with(dir) && path != dir)
            .map(|(_, path)| path)
            .collect()
    }

    /// The owners whose `dir` was listed, in order.
    fn listed(records: &FakePublicRecords, dir: &str) -> Vec<Pubky> {
        records
            .asked()
            .into_iter()
            .filter(|(_, path)| path == dir)
            .map(|(owner, _)| owner)
            .collect()
    }

    #[tokio::test]
    async fn the_target_the_circle_s_sweep_records_name_least_is_picked() {
        let (sweeper, a, b, stranger) = (
            random_pubky(),
            random_pubky(),
            random_pubky(),
            random_pubky(),
        );
        // A's bounty is open to anyone; B's is closed, and B's own circle
        // lists the sweeper.
        let a_bounty = bounty_ref(a, 10);
        let b_bounty = bounty_ref(b, 20);
        let mut records = circle(FakePublicRecords::default(), sweeper, &[sweeper, a, b]);
        records = circle(records, b, &[b, sweeper]);
        records = with_bounty(records, a_bounty, &bounty(&["t1", "t2"], true));
        records = with_bounty(records, b_bounty, &bounty(&["t1"], false));
        // A's t1 twice, by A and by the sweeper itself; A's t2 once.
        records = with_sweep(records, a, 30, a_bounty, &["t1"], "running");
        records = with_sweep(records, sweeper, 31, a_bounty, &["t1", "t2"], "done");
        // Each of these would lift B's t1 to a tie with A's t2, which the
        // older bounty, A's, would then win, so none may count: an aborted
        // sweep, one of a status this build does not know, one of another
        // of B's bounties naming t1, and a stranger's.
        records = with_sweep(records, b, 32, b_bounty, &["t1"], "aborted");
        records = with_sweep(records, b, 33, b_bounty, &["t1"], PLANTED);
        records = with_sweep(records, a, 34, bounty_ref(b, 99), &["t1"], "done");
        records = with_sweep(records, stranger, 35, b_bounty, &["t1"], "done");
        // A stranger's open bounty, never swept: outside the roster, so it
        // is never read.
        records = with_bounty(records, bounty_ref(stranger, 1), &bounty(&["t1"], true));

        let pick = pick(&records, sweeper, None).await;

        assert_eq!(chosen(&pick), (b_bounty, "t1", 0));
        assert_eq!(pick.choice.as_ref().expect("picked").considered, 3);
        assert!(pick.warnings.is_empty(), "{:?}", pick.warnings);
        assert!(
            records.asked().iter().all(|(owner, _)| *owner != stranger),
            "{:?}",
            records.asked()
        );
    }

    #[tokio::test]
    async fn a_tie_goes_to_the_older_bounty_then_to_its_first_target() {
        let (sweeper, a, b) = (random_pubky(), random_pubky(), random_pubky());
        // A is read first, but B's bounty is the older; its targets are in
        // the order t2, t1.
        let newer = bounty_ref(a, 20);
        let older = bounty_ref(b, 10);
        let mut records = circle(FakePublicRecords::default(), sweeper, &[a, b]);
        records = with_bounty(records, newer, &bounty(&["t1"], true));
        records = with_bounty(records, older, &bounty(&["t2", "t1"], true));

        // Nobody has swept anything: the older bounty's first target.
        assert_eq!(
            chosen(&pick(&records, sweeper, None).await),
            (older, "t2", 0)
        );

        // Its t2 swept once: t1 of each bounty ties at none, and the older
        // bounty's wins.
        records = with_sweep(records, a, 30, older, &["t2"], "done");
        assert_eq!(
            chosen(&pick(&records, sweeper, None).await),
            (older, "t1", 0)
        );
    }

    #[tokio::test]
    async fn done_closed_unknown_and_malformed_bounties_are_skipped() {
        let (sweeper, a, other) = (random_pubky(), random_pubky(), random_pubky());
        // A's own circle does not list the sweeper.
        let mut records = circle(FakePublicRecords::default(), sweeper, &[a]);
        records = circle(records, a, &[a, other]);
        let mut done = bounty(&["t1"], true);
        done["status"] = json!("done");
        let mut unknown_status = bounty(&["t1"], true);
        unknown_status["status"] = json!(PLANTED);
        let mut no_usable_target = bounty(&[], true);
        no_usable_target["targets"] = json!([
            { "id": "t1", "kind": format!("crate-{PLANTED}"), "name": PLANTED },
            { "id": "t2", "kind": "repo", "repo": "github.com/org/name", "rev": PLANTED },
        ]);
        records = with_bounty(records, bounty_ref(a, 1), &done);
        records = with_bounty(records, bounty_ref(a, 2), &bounty(&["t1"], false));
        records = with_bounty(records, bounty_ref(a, 3), &no_usable_target);
        records = with_bounty(records, bounty_ref(a, 4), &unknown_status);
        records = records.with_file(
            a,
            &paths::bounty(record_id(5)),
            format!("{PLANTED} is not JSON").into_bytes(),
        );
        // The one bounty left, swept twice already.
        let swept = bounty_ref(a, 6);
        records = with_bounty(records, swept, &bounty(&["t1"], true));
        records = with_sweep(records, a, 30, swept, &["t1"], "done");
        records = with_sweep(records, a, 31, swept, &["t1"], "running");

        let pick = pick(&records, sweeper, None).await;

        assert_eq!(chosen(&pick), (swept, "t1", 2));
        assert_eq!(pick.choice.as_ref().expect("picked").considered, 1);
        // The record that is not a bounty is the one fault, said once,
        // naming its owner and quoting none of it.
        assert_eq!(pick.warnings.len(), 1, "{:?}", pick.warnings);
        let warning = &pick.warnings[0];
        assert!(warning.contains("1 of the bounty records"), "{warning}");
        assert!(warning.contains(&a.to_string()), "{warning}");
        assert!(!warning.contains(PLANTED), "{warning}");
    }

    #[tokio::test]
    async fn reading_stops_at_the_member_bounty_and_sweep_bounds() {
        let sweeper = random_pubky();
        // The admin, then more members than are read.
        let members: Vec<Pubky> = (0..MAX_MEMBERS + 1).map(|_| random_pubky()).collect();
        let first = members[0];
        let mut records = circle(FakePublicRecords::default(), sweeper, &members);
        // More bounties of one t1 each than are read, oldest first: 1, 2, …
        let bounty_count = MAX_BOUNTIES_PER_MEMBER + 2;
        for n in 1..=bounty_count {
            let n = u64::try_from(n).expect("small");
            records = with_bounty(records, bounty_ref(first, n), &bounty(&["t1"], true));
        }
        // More sweeps than are read. The two oldest name the oldest bounty
        // that is read, 3, and the rest the newest, so 3 is picked only if
        // the two oldest sweeps were not read; and 1 or 2 would be, being
        // older and unswept, had they been read.
        let oldest_read = bounty_ref(first, 3);
        let newest = bounty_ref(first, u64::try_from(bounty_count).expect("small"));
        for n in 0..MAX_SWEEPS_PER_MEMBER + 2 {
            let target = if n < 2 { oldest_read } else { newest };
            let n = 1000 + u64::try_from(n).expect("small");
            records = with_sweep(records, first, n, target, &["t1"], "done");
        }

        let pick = pick(&records, sweeper, None).await;

        assert_eq!(chosen(&pick), (oldest_read, "t1", 0));
        // The first members of the roster, the admin first, and no more.
        let mut roster = vec![sweeper];
        roster.extend(&members[..MAX_MEMBERS - 1]);
        assert_eq!(listed(&records, paths::BOUNTIES_DIR), roster);
        assert_eq!(listed(&records, paths::SWEEPS_DIR), roster);
        // The newest records of each kind, each read once.
        let bounties_read = records_read(&records, first, paths::BOUNTIES_DIR);
        assert_eq!(
            bounties_read.len(),
            MAX_BOUNTIES_PER_MEMBER,
            "{bounties_read:?}"
        );
        assert!(!bounties_read.contains(&paths::bounty(record_id(1))));
        assert!(!bounties_read.contains(&paths::bounty(record_id(2))));
        let sweeps_read = records_read(&records, first, paths::SWEEPS_DIR);
        assert_eq!(sweeps_read.len(), MAX_SWEEPS_PER_MEMBER, "{sweeps_read:?}");
        assert!(!sweeps_read.contains(&paths::sweep_record(record_id(1000))));
        assert!(!sweeps_read.contains(&paths::sweep_record(record_id(1001))));
        // Cutting the roster is said.
        assert!(
            pick.warnings
                .iter()
                .any(|warning| warning.contains(&format!("the first {MAX_MEMBERS}"))),
            "{:?}",
            pick.warnings
        );
    }

    #[tokio::test]
    async fn a_listing_that_breaks_the_protocol_skips_that_member_with_a_warning() {
        let (sweeper, a, b) = (random_pubky(), random_pubky(), random_pubky());
        let mut records = circle(FakePublicRecords::default(), sweeper, &[a, b]);
        // A's bounty is the older, so it would be picked if A's listing
        // were read.
        records = with_bounty(records, bounty_ref(a, 1), &bounty(&["t1"], true));
        records = records.with_broken_listing(a, paths::BOUNTIES_DIR);
        // B's sweep of its own bounty would count if B's listing were read.
        let b_bounty = bounty_ref(b, 2);
        records = with_bounty(records, b_bounty, &bounty(&["t1"], true));
        records = with_sweep(records, b, 30, b_bounty, &["t1"], "done");
        records = records.with_broken_listing(b, paths::SWEEPS_DIR);

        let pick = pick(&records, sweeper, None).await;

        assert_eq!(chosen(&pick), (b_bounty, "t1", 0));
        assert_eq!(pick.warnings.len(), 2, "{:?}", pick.warnings);
        for (warning, member, kind) in [
            (&pick.warnings[0], a, "bounty"),
            (&pick.warnings[1], b, "sweep"),
        ] {
            assert!(
                warning.contains(&format!("the {kind} records")),
                "{warning}"
            );
            assert!(warning.contains(&member.to_string()), "{warning}");
            assert!(warning.contains("could not be listed"), "{warning}");
            assert!(
                warning.contains("more entries than were asked for"),
                "{warning}"
            );
        }
        // The warnings come first in what run shows.
        let summary = pick.summary();
        assert!(summary.starts_with("warning: "), "{summary}");
        assert!(
            summary.contains(&format!("target t1 of the bounty {b_bounty}")),
            "{summary}"
        );
    }

    #[tokio::test]
    async fn with_nothing_open_nothing_is_picked_and_no_sweep_is_read() {
        let (sweeper, a) = (random_pubky(), random_pubky());
        let mut records = circle(FakePublicRecords::default(), sweeper, &[a]);
        let mut done = bounty(&["t1"], true);
        done["status"] = json!("done");
        records = with_bounty(records, bounty_ref(a, 1), &done);
        records = with_sweep(records, a, 30, bounty_ref(a, 1), &["t1"], "done");

        let pick = pick(&records, sweeper, None).await;

        assert!(pick.choice.is_none(), "{:?}", pick.choice);
        assert!(pick.warnings.is_empty(), "{:?}", pick.warnings);
        assert_eq!(listed(&records, paths::SWEEPS_DIR), Vec::<Pubky>::new());
        assert!(NOTHING_OPEN.contains("no open bounty"), "{NOTHING_OPEN}");
        assert!(NOTHING_OPEN.contains("bounty's URL"), "{NOTHING_OPEN}");
    }

    #[tokio::test]
    async fn the_circle_flag_s_circle_is_picked_from_instead() {
        let (sweeper, admin, a, b) = (
            random_pubky(),
            random_pubky(),
            random_pubky(),
            random_pubky(),
        );
        // The sweeper's own circle lists B, the one --circle names lists A.
        let mut records = circle(FakePublicRecords::default(), sweeper, &[b]);
        records = circle(records, admin, &[admin, sweeper, a]);
        let a_bounty = bounty_ref(a, 2);
        records = with_bounty(records, bounty_ref(b, 1), &bounty(&["t1"], true));
        // Closed, and A keeps no circle: under --circle, the circle it names
        // decides, as it does for a URL.
        records = with_bounty(records, a_bounty, &bounty(&["t1"], false));

        let pick = pick(&records, sweeper, Some(admin)).await;

        assert_eq!(chosen(&pick), (a_bounty, "t1", 0));
        assert_eq!(listed(&records, paths::BOUNTIES_DIR), [admin, sweeper, a]);
        assert!(
            records.asked().iter().all(|(owner, _)| *owner != b),
            "{:?}",
            records.asked()
        );
    }

    #[tokio::test]
    async fn without_a_circle_to_pick_from_run_asks_for_a_url_or_the_circle_flag() {
        let (sweeper, admin, other) = (random_pubky(), random_pubky(), random_pubky());
        let refusal = async |records: &FakePublicRecords, flag: Option<Pubky>| {
            let err = pick_target(records, &TargetSource::Real, sweeper, flag)
                .await
                .expect_err("refused");
            format!("{err:#}")
        };

        // No --circle and no circle of one's own.
        let message = refusal(&FakePublicRecords::default(), None).await;
        assert!(message.contains("bounty's URL"), "{message}");
        assert!(message.contains("--circle"), "{message}");

        // --circle names a key that keeps no circle, keeps another's, or
        // keeps one that does not list the sweeper. No refusal names it.
        for (records, expected) in [
            (FakePublicRecords::default(), "no circle.json"),
            (
                FakePublicRecords::default().with_record(
                    admin,
                    paths::circle(),
                    &circle_json(other, &[sweeper]),
                ),
                "another admin",
            ),
            (
                circle(FakePublicRecords::default(), admin, &[other]),
                "you are not in",
            ),
        ] {
            let message = refusal(&records, Some(admin)).await;
            assert!(message.contains(expected), "{message}");
            assert!(message.contains("--circle"), "{message}");
            assert!(!message.contains(&admin.to_string()), "{message}");
        }
    }
}
