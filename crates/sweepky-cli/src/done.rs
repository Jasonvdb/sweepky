//! `done <bounty> [--credit <pubky>]… [--no-credit <pubky>]…`: the owner
//! marks their bounty done and credits every sweeper whose sweep helped
//! (00, "The loop", step 6; 01, "The bounty post"). It is the only command
//! that rewrites a bounty, and its one write is that bounty.
//!
//! [`done`] runs these steps, in this order:
//!
//! 1. **The arguments, with no file or network read.** The URL must be a
//!    bounty record's (`run::parse_bounty_url`, which refuses a sweep's URL
//!    and a pasted key in fixed text), and every `--credit` and
//!    `--no-credit` a pubky (`circle::parse_pubky`: core's parse, then the
//!    SDK's Ed25519 check). A `--credit` naming the bounty's owner, the key
//!    in its URL, compared by key bytes so either spelling is caught, is
//!    refused with [`OWN_CREDIT`]. So are one key in both flags and more
//!    `--credit` keys than a record carries.
//! 2. **The proposal**, from what the last `pull` left on this install:
//!    `login.json` must name the bounty's owner; then the bounty's
//!    `groups.json` (`pull::triage`), read within its cap once its
//!    directory's owner check names the owner, and the poll state. Every
//!    sweeper with a sweep that is a member of a group, and whose record
//!    last said `done`, is proposed, in upload order, each once, never the
//!    owner: core's `propose_credits` rule, read from the file (below).
//! 3. **The flags applied**, and what each proposed sweeper reported shown
//!    on standard error: their trust label as of that `pull`, how many
//!    findings in how many groups, and each group's place (file, line and
//!    scope, sanitised) with how many sweepers reported it. Never a
//!    finding's text, so a stranger's title never reaches the agent here.
//! 4. **The question**, `prompt::confirm`, unless the flags settle every
//!    name ([`Decision::of`]). A no writes nothing; `--no-input` fails
//!    naming the question.
//! 5. **The rewrite**, under the writers' lock with a fresh session (an
//!    identity session signed out afterwards, a Ring one only dropped):
//!    `login.json` still the owner's, the bounty read
//!    back through the session, core's `Bounty::mark_done` with
//!    `clock::now()` (which refuses the owner again), the record checked
//!    against `MAX_RECORD_BYTES`, then PUT. The lock covers the sign-in
//!    or restore, the read-back, the PUT and the sign-out alone; the question is
//!    asked before it, so no person's answer ever holds it.
//!
//! **"Unless flags settle it"** (P2c's reading): no question only when a
//! flag was given, nothing says the proposal may be missing a sweeper, and
//! every proposed sweeper is named by `--credit` or `--no-credit`. Then no
//! name in the list comes from the proposal alone. A lone `--credit X`
//! never credits the rest of the proposal unasked.
//!
//! **Why `groups.json` and not core's `propose_credits`.** That function
//! takes the `FindingGroups` that `group_findings` builds from every
//! sweep's findings. `pull` already built them, within its caps, and wrote
//! their sweeps and members to `groups.json`; reading the members back
//! gives the same proposal (a sweep is in a group exactly when it has a
//! finding) without reading findings again. Its labels and places are
//! `pull`'s, as of that run: shown, never trusted for anything.
//!
//! **Last writer wins, deliberately** (01). A bounty already done is
//! marked done again with the new credits; two installs of one owner
//! rewriting at once leave whichever wrote last.

use std::collections::BTreeSet;

use anyhow::{Context as _, anyhow, bail};
use serde::Deserialize;
use sweepky_core::paths;
use sweepky_core::{
    Bounty, BountyRef, CreditTally, KnownBountyStatus, KnownSweepStatus, MAX_RECORD_BYTES, Pubky,
    RecordTime, SchemaVersion, SweepRef, Trust, TrustLabel,
};

use crate::circle::parse_pubky;
use crate::display::{MAX_LABEL_CHARS, sanitize};
use crate::own_storage::{OwnStorage, SessionStorage};
use crate::private_fs::read_private_file;
use crate::prompt::{Prompting, confirm};
use crate::pull::roster::MAX_CREDITS;
use crate::pull::state::PollState;
use crate::pull::store::stored_bounty_dir;
use crate::pull::triage::{GROUPS_FILE, MAX_TRIAGE_FILE_BYTES};
use crate::pull::{counted, label_text};
use crate::records::not_a_record;
use crate::remote::write_error;
use crate::run::{logged_in_sweeper, parse_bounty_url};
use crate::session::with_writer_session;
use crate::{Context, Dirs, Report, clock};

/// What `done` refuses a `--credit` naming the bounty's owner with: one
/// line, before any file or network read.
const OWN_CREDIT: &str =
    "--credit names the bounty's owner, who is never credited on their own bounty";

/// What `done` refuses one key named by both flags with.
const BOTH_FLAGS: &str =
    "one pubky is named by both --credit and --no-credit; name each sweeper in one of them";

/// What `done` refuses another owner's bounty with. It quotes no key: the
/// URL's and the login's are both the user's to see already.
const OTHER_OWNER: &str = "that bounty is not this install's to mark: done marks only the \
                           bounties of the pubky this install is logged in as";

/// What `done` says when `login.json`, read again under the lock, names
/// another pubky than the bounty's owner.
const LOGIN_CHANGED: &str = "this install was logged in as another identity while done ran, so \
                             the bounty was not marked done; run done again";

/// What `done` says when it writes nothing: in its report when the owner
/// does not say yes, and in front of the error under `--no-input`.
const NOT_MARKED: &str = "the bounty was not marked done";

/// The warning for a bounty with no `groups.json` on this install.
const NO_GROUPS: &str = "this install has no groups for this bounty (`sweepky pull` writes them \
                         once it has stored a sweep of it), so the proposal may be missing \
                         sweepers";

/// The most groups the preview lists for one proposed sweeper; it counts
/// the rest. A stranger's sweep can hold thousands of findings.
const MAX_GROUPS_SHOWN: usize = 16;

/// The most characters of an anchor's file the preview shows.
const MAX_ANCHOR_FILE_CHARS: usize = 256;

/// The most characters of an anchor's scope the preview shows.
const MAX_ANCHOR_SCOPE_CHARS: usize = 128;

/// Runs `sweepky done <bounty> [--credit <pubky>]… [--no-credit <pubky>]…`,
/// the arguments as typed: see the module docs for the order and why.
/// `prompting` is the global `--no-input`.
pub(crate) async fn done(
    ctx: &Context,
    prompting: Prompting,
    bounty: &str,
    credit: &[String],
    no_credit: &[String],
) -> anyhow::Result<Report> {
    // Step 1, before anything is read: a refusal here has touched nothing.
    let request = DoneRequest::parse(bounty, credit, no_credit)?;
    done_with(ctx, prompting, &request, &LockedSession { ctx }).await
}

/// What `done` was asked, every value checked, and no file read yet.
#[derive(Debug)]
struct DoneRequest {
    /// The bounty to mark done; its owner is the key in its URL.
    bounty: BountyRef,
    /// `--credit`, each key once, in the order first given.
    credit: Vec<Pubky>,
    /// `--no-credit`.
    no_credit: BTreeSet<Pubky>,
}

impl DoneRequest {
    /// Checks the arguments as typed (step 1). Every refusal is fixed text
    /// that quotes nothing typed.
    fn parse(bounty: &str, credit: &[String], no_credit: &[String]) -> anyhow::Result<Self> {
        let bounty = parse_bounty_url(bounty, "done")?;
        let credit = parse_credits(credit, bounty.owner)?;
        // `collect` into a `Result` stops at the first `Err` and hands it
        // back, so `?` refuses the first value that is not a pubky.
        let no_credit = no_credit
            .iter()
            .map(|text| parse_pubky(text, "done --no-credit"))
            .collect::<anyhow::Result<BTreeSet<Pubky>>>()?;
        if credit.iter().any(|pubky| no_credit.contains(pubky)) {
            bail!(BOTH_FLAGS);
        }
        Ok(Self {
            bounty,
            credit,
            no_credit,
        })
    }

    /// Whether a flag names `pubky`.
    fn names(&self, pubky: Pubky) -> bool {
        self.credit.contains(&pubky) || self.no_credit.contains(&pubky)
    }
}

/// The `--credit` keys, each once in the order first given, refused with
/// [`OWN_CREDIT`] at the first that is `owner`, and as a whole when there
/// are more than a record carries: every one of them is in the list `done`
/// writes.
fn parse_credits(credit: &[String], owner: Pubky) -> anyhow::Result<Vec<Pubky>> {
    let mut credited = Vec::new();
    let mut seen = BTreeSet::new();
    for text in credit {
        let pubky = parse_pubky(text, "done --credit")?;
        // `Pubky`'s `==` compares the 32 key bytes, so `pubky<z32>` and raw
        // z32 are one key. Both are public keys, so a comparison that is not
        // constant-time leaks nothing.
        if pubky == owner {
            bail!(OWN_CREDIT);
        }
        // `insert` is `false` for a key seen already: kept once.
        if seen.insert(pubky) {
            credited.push(pubky);
        }
    }
    if credited.len() > MAX_CREDITS {
        bail!(too_many(credited.len()));
    }
    Ok(credited)
}

/// The refusal of a list of `count` credits.
fn too_many(count: usize) -> String {
    format!(
        "done writes at most {MAX_CREDITS} credits, the most pull reads from a bounty, and \
         these would be {count}; drop some with --no-credit"
    )
}

/// [`done`] from step 2 on, with `writer` for step 5: the real lock and
/// session in the command, a fake in the tests.
async fn done_with(
    ctx: &Context,
    prompting: Prompting,
    request: &DoneRequest,
    writer: &impl MarkUnderLock,
) -> anyhow::Result<Report> {
    require_own_bounty(&ctx.dirs, request.bounty)?;
    let proposal = Proposal::read(&ctx.dirs, request.bounty)?;
    let decision = Decision::of(&proposal, request)?;
    ctx.stderr
        .write_flushed(&preview(request.bounty, &proposal, &decision))?;
    if !decision.settled {
        let question = format!(
            "Mark this bounty done, crediting {}, where anyone can read it?",
            counted(decision.credits.len(), "sweeper")
        );
        // `context` puts the words in front of `--no-input`'s error, so
        // both ways of not saying yes say that nothing was written.
        if !confirm(ctx, prompting, &question).context(NOT_MARKED)? {
            return Ok(Report::new(format!("Not confirmed, so {NOT_MARKED}.\n")));
        }
    }
    let credits: Vec<Pubky> = decision.credits.iter().map(|credit| credit.pubky).collect();
    let marked = writer
        .mark(request.bounty, &credits)
        .await
        .context("could not mark the bounty done")?;
    Ok(report(request.bounty, &marked))
}

/// Checks that this install is logged in as `bounty`'s owner: only their
/// own session can write it, and only their install holds its groups.
fn require_own_bounty(dirs: &Dirs, bounty: BountyRef) -> anyhow::Result<()> {
    // `run`'s helper: the pubky `login.json` names, or `NOT_LOGGED_IN`.
    if logged_in_sweeper(dirs)? != bounty.owner {
        bail!(OTHER_OWNER);
    }
    Ok(())
}

/// `groups.json` as `done` reads it: what `pull::triage` writes, less what
/// `done` does not use (each sweep's `trusted`, each group's `reportedBy`,
/// each member's `index`), which serde skips. A local file, but its places
/// are what sweepers' agents wrote, strangers' among them: no `Debug` on
/// this or the shapes below, and every string goes through the sanitiser
/// before it is shown.
// Owned `String`s rather than borrowed `&str`s: a JSON string with an
// escape in it cannot be borrowed from the input, and the file's bytes are
// in a buffer that is wiped and dropped once this is parsed.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GroupsFile {
    // Read only so that its check runs: `SchemaVersion` refuses a newer
    // one as it is read. The leading `_` tells the compiler it is never
    // used otherwise.
    #[serde(rename = "schemaVersion")]
    _schema_version: SchemaVersion,
    /// The bounty the file is of.
    bounty: BountyRef,
    /// The sweeps grouped, in upload order, each with its sweeper's label.
    sweeps: Vec<GroupedSweep>,
    /// The groups, each with its members.
    groups: Vec<Group>,
    /// The sweeps `pull` left out of the groups (its caps).
    left_out: Vec<SweepRef>,
}

/// A `groups.json` sweep: the sweep and its sweeper's trust as `pull`
/// labelled it, the label as written.
#[derive(Deserialize)]
struct GroupedSweep {
    sweep: SweepRef,
    label: String,
    bounties: u64,
    owners: u64,
}

/// A `groups.json` group.
#[derive(Deserialize)]
struct Group {
    members: Vec<Member>,
}

/// A `groups.json` member: a finding of `sweep`, grouped by `anchor`.
#[derive(Deserialize)]
struct Member {
    sweep: SweepRef,
    anchor: Option<Anchor>,
}

/// The place a member was grouped by, as its agent wrote it.
#[derive(Deserialize)]
struct Anchor {
    file: String,
    line: Option<u64>,
    scope: Option<String>,
}

/// What `done` proposes for a bounty, and why the proposal may be missing
/// sweepers. Keys, counts and sanitised text alone.
// No `Debug` here or on the two below: a place is part of a finding, and
// sealed content is shown on purpose, in the preview, never by a `{:?}`.
struct Proposal {
    /// One line for each reason the proposal may be missing a sweeper.
    /// While there is any, `done` asks whatever the flags say.
    warnings: Vec<String>,
    /// The sweepers proposed, in upload order, with what each reported.
    proposed: Vec<Reporter>,
    /// The sweepers in the groups, the owner aside, none of whose grouped
    /// sweeps last said `done`, in upload order.
    not_done: Vec<Pubky>,
    /// Whether the owner's own sweeps are in the groups.
    owner_grouped: bool,
}

/// A proposed sweeper and what the preview shows of them.
struct Reporter {
    sweeper: Pubky,
    /// Their trust label as `pull` gave it, in its words, sanitised.
    label: String,
    /// How many findings of their done sweeps are in the groups.
    findings: usize,
    /// How many groups those findings are in.
    groups: usize,
    /// The first [`MAX_GROUPS_SHOWN`] of those groups, in the file's order.
    shown: Vec<ReportedGroup>,
}

/// One group a proposed sweeper reported, as the preview shows it.
struct ReportedGroup {
    /// The place their finding was grouped by, sanitised.
    place: String,
    /// How many sweepers reported the group, the owner included.
    reporters: usize,
}

impl Proposal {
    /// The proposal for `bounty` from what the last `pull` left in `dirs`:
    /// its `groups.json` and the poll state (step 2).
    fn read(dirs: &Dirs, bounty: BountyRef) -> anyhow::Result<Self> {
        let state = PollState::read(dirs, bounty.owner)?;
        let mut warnings: Vec<String> = unpulled_warning(&state, bounty).into_iter().collect();
        let Some(groups) = read_groups(dirs, bounty)? else {
            warnings.push(NO_GROUPS.to_owned());
            return Ok(Self {
                warnings,
                proposed: Vec::new(),
                not_done: Vec::new(),
                owner_grouped: false,
            });
        };
        if !groups.left_out.is_empty() {
            warnings.push(format!(
                "the last pull left {} of this bounty out of its groups, which it caps, so the \
                 proposal may be missing their sweepers",
                counted(groups.left_out.len(), "sweep")
            ));
        }
        Ok(Self::of_groups(&groups, &state, bounty.owner, warnings))
    }

    /// The proposal `groups` and `state` give for `owner`'s bounty.
    fn of_groups(
        groups: &GroupsFile,
        state: &PollState,
        owner: Pubky,
        warnings: Vec<String>,
    ) -> Self {
        let grouped = groups.sweeps_with_findings();
        // A sweep counts when its record last said `done` (P2b: aborted
        // sweeps are left out; P2c: so is anything else). A sweep the poll
        // state no longer holds was confirmed deleted. A set of at most
        // the grouped sweeps, so each member below is one lookup in it.
        let done: BTreeSet<SweepRef> = grouped
            .iter()
            .map(|entry| entry.sweep)
            .filter(|sweep| last_said_done(state, sweep))
            .collect();
        let mut proposed: Vec<Reporter> = Vec::new();
        let mut not_done: Vec<Pubky> = Vec::new();
        // Two passes over the upload order, the order core proposes in: a
        // sweeper is proposed for any done sweep of theirs, so whether one
        // was left out is known only once every sweep has been seen.
        // A closure that makes a fresh iterator each time it is called:
        // one pass uses an iterator up.
        let others = || grouped.iter().filter(|entry| entry.sweep.sweeper != owner);
        for entry in others().filter(|entry| done.contains(&entry.sweep)) {
            if !proposed
                .iter()
                .any(|reporter| reporter.sweeper == entry.sweep.sweeper)
            {
                proposed.push(Reporter::new(entry));
            }
        }
        for entry in others() {
            let sweeper = entry.sweep.sweeper;
            if !proposed.iter().any(|reporter| reporter.sweeper == sweeper)
                && !not_done.contains(&sweeper)
            {
                not_done.push(sweeper);
            }
        }
        tally(&mut proposed, groups, &done);
        Self {
            warnings,
            proposed,
            not_done,
            owner_grouped: grouped.iter().any(|entry| entry.sweep.sweeper == owner),
        }
    }
}

impl GroupsFile {
    /// The sweeps with a finding in a group, in upload order: the sweeps
    /// core's `propose_credits` proposes from.
    fn sweeps_with_findings(&self) -> Vec<&GroupedSweep> {
        let members: BTreeSet<SweepRef> = self
            .groups
            .iter()
            .flat_map(|group| group.members.iter().map(|member| member.sweep))
            .collect();
        self.sweeps
            .iter()
            .filter(|entry| members.contains(&entry.sweep))
            .collect()
    }
}

impl Group {
    /// How many sweepers reported the group, the owner included.
    fn reporters(&self) -> usize {
        self.members
            .iter()
            .map(|member| member.sweep.sweeper)
            .collect::<BTreeSet<Pubky>>()
            .len()
    }
}

impl Reporter {
    /// The sweeper of `entry`, with nothing counted yet.
    fn new(entry: &GroupedSweep) -> Self {
        Self {
            sweeper: entry.sweep.sweeper,
            label: shown_label(entry),
            findings: 0,
            groups: 0,
            shown: Vec::new(),
        }
    }

    /// Counts `group`, which `member`, a finding of theirs, is in, and
    /// keeps its place while fewer than [`MAX_GROUPS_SHOWN`] are kept.
    fn add_group(&mut self, group: &Group, member: &Member) {
        self.groups += 1;
        // Placed and counted only for the groups shown: a stranger's sweep
        // can hold thousands.
        if self.shown.len() < MAX_GROUPS_SHOWN {
            self.shown.push(ReportedGroup {
                place: shown_place(member.anchor.as_ref()),
                reporters: group.reporters(),
            });
        }
    }
}

/// Whether `sweep`'s record last said `done`, as the poll state has it.
fn last_said_done(state: &PollState, sweep: &SweepRef) -> bool {
    state
        .sweeps
        .get(sweep)
        .and_then(|summary| summary.status.as_known())
        == Some(KnownSweepStatus::Done)
}

/// Counts, for each of `proposed`, the findings of their `done` sweeps in
/// `groups` and the groups those findings are in.
fn tally(proposed: &mut [Reporter], groups: &GroupsFile, done: &BTreeSet<SweepRef>) {
    for group in &groups.groups {
        // The sweepers counted in this group already: a sweeper with two
        // findings in one group reported it once.
        let mut counted_here = BTreeSet::new();
        for member in group
            .members
            .iter()
            .filter(|member| done.contains(&member.sweep))
        {
            let sweeper = member.sweep.sweeper;
            // `iter_mut` lends each reporter mutably, and `find` stops at
            // the sweeper's. The owner is never among them, nor anyone else
            // not proposed. At most 64 sweeps are grouped, so this search
            // is short.
            let Some(reporter) = proposed
                .iter_mut()
                .find(|reporter| reporter.sweeper == sweeper)
            else {
                continue;
            };
            reporter.findings += 1;
            if counted_here.insert(sweeper) {
                reporter.add_group(group, member);
            }
        }
    }
}

/// The warning for `bounty`'s done sweeps the poll state says are neither
/// pulled nor refused for good, which no group holds yet, or `None`.
fn unpulled_warning(state: &PollState, bounty: BountyRef) -> Option<String> {
    let count = state
        .sweeps
        .values()
        .filter(|summary| {
            summary.bounty == bounty
                && summary.status.as_known() == Some(KnownSweepStatus::Done)
                && !summary.pulled
                && !summary.refused
        })
        .count();
    // `then` gives `Some` of the closure's value only when the `bool` is
    // `true`.
    (count > 0).then(|| {
        format!(
            "{} of this bounty {} not pulled yet, so the proposal may be missing their \
             sweepers; run `sweepky pull` first",
            counted(count, "done sweep"),
            if count == 1 { "is" } else { "are" }
        )
    })
}

/// `bounty`'s `groups.json` in `dirs`, or `None` when there is none. Its
/// directory is checked first (`pull::store`): a link there, or another
/// owner's directory, is an error. The file is read within `pull`'s cap
/// for it, and its parse error quotes nothing of it.
fn read_groups(dirs: &Dirs, bounty: BountyRef) -> anyhow::Result<Option<GroupsFile>> {
    let Some(dir) = stored_bounty_dir(dirs, bounty)? else {
        return Ok(None);
    };
    let path = dir.join(GROUPS_FILE);
    let Some(bytes) = read_private_file(&path, MAX_TRIAGE_FILE_BYTES)? else {
        return Ok(None);
    };
    // serde_json's own message can quote a value it read, a stranger's
    // place among them, so only its line and column are kept.
    let groups: GroupsFile = serde_json::from_slice(&bytes).map_err(|error| {
        anyhow!(
            "{} is not a groups file this build reads (line {}, column {}); run `sweepky pull` \
             to write it again",
            path.display(),
            error.line(),
            error.column()
        )
    })?;
    if groups.bounty != bounty {
        bail!(
            "{} is the groups file of another bounty; run `sweepky pull` to write it again",
            path.display()
        );
    }
    Ok(Some(groups))
}

/// The label `pull` gave a sweep's sweeper, in `pull`'s report's words. A
/// label read back is never trusted for anything: `done` only shows it.
fn shown_label(entry: &GroupedSweep) -> String {
    // The words core's `TrustLabel` is written as, read back.
    let label = match entry.label.as_str() {
        "circle" => TrustLabel::Circle,
        "known" => TrustLabel::Known,
        "unknown" => TrustLabel::Unknown,
        other => {
            return format!(
                "a label this build does not know, {}",
                sanitize(other, MAX_LABEL_CHARS)
            );
        }
    };
    label_text(Trust {
        label,
        tally: CreditTally {
            bounties: entry.bounties,
            owners: entry.owners,
        },
    })
}

/// A member's place as the preview shows it: `file:line in scope`, each
/// part sanitised, or that it has none.
fn shown_place(anchor: Option<&Anchor>) -> String {
    let Some(anchor) = anchor else {
        return "no place in the code".to_owned();
    };
    let mut place = sanitize(&anchor.file, MAX_ANCHOR_FILE_CHARS);
    if let Some(line) = anchor.line {
        place.push_str(&format!(":{line}"));
    }
    if let Some(scope) = &anchor.scope {
        place.push_str(&format!(" in {}", sanitize(scope, MAX_ANCHOR_SCOPE_CHARS)));
    }
    place
}

/// The credits `done` is to write, and whether it must ask first.
#[derive(Debug)]
struct Decision {
    /// The credits, in order: the proposal's left after `--no-credit`, in
    /// upload order, then `--credit`'s others, in the order given.
    credits: Vec<Credit>,
    /// The proposed sweepers `--no-credit` dropped.
    dropped: Vec<Pubky>,
    /// Whether the flags settle every name, so `done` does not ask.
    settled: bool,
}

/// One credit to write, and where it came from.
#[derive(Debug)]
struct Credit {
    pubky: Pubky,
    proposed: bool,
    flagged: bool,
}

impl Decision {
    /// The flags of `request` applied to `proposal` (step 3), and whether
    /// they settle every name ([`flags_settle`]). More credits than a
    /// record carries are refused.
    fn of(proposal: &Proposal, request: &DoneRequest) -> anyhow::Result<Self> {
        let mut credits = Vec::new();
        let mut dropped = Vec::new();
        for reporter in &proposal.proposed {
            let pubky = reporter.sweeper;
            if request.no_credit.contains(&pubky) {
                dropped.push(pubky);
            } else {
                credits.push(Credit {
                    pubky,
                    proposed: true,
                    flagged: request.credit.contains(&pubky),
                });
            }
        }
        for &pubky in &request.credit {
            if !credits.iter().any(|credit| credit.pubky == pubky) {
                credits.push(Credit {
                    pubky,
                    proposed: false,
                    flagged: true,
                });
            }
        }
        if credits.len() > MAX_CREDITS {
            bail!(too_many(credits.len()));
        }
        Ok(Self {
            credits,
            dropped,
            settled: flags_settle(proposal, request),
        })
    }
}

/// Whether the flags of `request` settle every name of `proposal`, so
/// `done` need not ask: a flag was given, nothing says the proposal may be
/// missing a sweeper, and a flag names every proposed sweeper. Then no name
/// in the list comes from the proposal alone: it is the proposal less
/// `--no-credit`'s, so `--credit`'s, plus `--credit`'s others.
fn flags_settle(proposal: &Proposal, request: &DoneRequest) -> bool {
    let any_flag = !request.credit.is_empty() || !request.no_credit.is_empty();
    any_flag
        && proposal.warnings.is_empty()
        && proposal
            .proposed
            .iter()
            .all(|reporter| request.names(reporter.sweeper))
}

/// What `done` shows before it asks (step 3): the warnings, the bounty,
/// what each proposed sweeper reported, who is left out and why, and the
/// credits to write, each with where it came from. Keys and the URL are
/// core-built; labels and places went through the sanitiser.
fn preview(bounty: BountyRef, proposal: &Proposal, decision: &Decision) -> String {
    let mut text: String = proposal
        .warnings
        .iter()
        .map(|warning| format!("warning: {warning}\n"))
        .collect();
    text.push_str(&format!("The bounty to mark done: {bounty}\n"));
    if proposal.proposed.is_empty() {
        text.push_str("Proposed: nobody, from this install's groups as of its last pull.\n");
    } else {
        text.push_str(
            "Proposed from this install's groups, as of its last pull: each sweeper with a done \
             sweep in a group, never you.\n",
        );
        for reporter in &proposal.proposed {
            push_reporter(&mut text, reporter);
        }
    }
    if !proposal.not_done.is_empty() {
        text.push_str("Not proposed, as none of their grouped sweeps is done:\n");
        for sweeper in &proposal.not_done {
            text.push_str(&format!("  {sweeper}\n"));
        }
    }
    if proposal.owner_grouped {
        text.push_str(
            "Your own sweeps are in the groups too; you are never credited on your own bounty.\n",
        );
    }
    push_decision(&mut text, decision);
    text
}

/// The preview's lines for `decision`: each credit with where it came
/// from, the proposed sweepers dropped, and whether `done` asks.
fn push_decision(text: &mut String, decision: &Decision) {
    text.push_str(&format!("Credits to write ({}):\n", decision.credits.len()));
    if decision.credits.is_empty() {
        text.push_str("  nobody\n");
    }
    for credit in &decision.credits {
        let from = match (credit.proposed, credit.flagged) {
            (true, true) => "proposed, --credit",
            (true, false) => "proposed",
            (false, _) => "--credit",
        };
        text.push_str(&format!("  {} ({from})\n", credit.pubky));
    }
    if !decision.dropped.is_empty() {
        text.push_str("Not credited (--no-credit):\n");
        for sweeper in &decision.dropped {
            text.push_str(&format!("  {sweeper}\n"));
        }
    }
    if decision.settled {
        text.push_str("The flags name every proposed sweeper, so done does not ask.\n");
    }
}

/// The preview's lines for `reporter`.
fn push_reporter(text: &mut String, reporter: &Reporter) {
    text.push_str(&format!(
        "  {}: {}; {} in {}\n",
        reporter.sweeper,
        reporter.label,
        counted(reporter.findings, "finding"),
        counted(reporter.groups, "group")
    ));
    for group in &reporter.shown {
        text.push_str(&format!(
            "    {}, reported by {}\n",
            group.place,
            counted(group.reporters, "sweeper")
        ));
    }
    // Never below zero: `shown` holds at most `groups` entries.
    let more = reporter.groups.saturating_sub(reporter.shown.len());
    if more > 0 {
        text.push_str(&format!("    and {}\n", counted(more, "more group")));
    }
}

/// What `done` reports once the bounty is written.
fn report(bounty: BountyRef, marked: &Marked) -> Report {
    let mut text = format!(
        "Marked the bounty done, crediting {}:\n{bounty}\n",
        counted(marked.credits.len(), "sweeper")
    );
    for credit in &marked.credits {
        text.push_str(&format!("  {credit}\n"));
    }
    if marked.was_done {
        text.push_str(
            "It was done already: these credits replace the ones it had, as the last write \
             wins.\n",
        );
    }
    Report::new(text)
}

/// What the rewrite did: whether the bounty was done already, and the
/// credits written. Public keys alone, so `Debug` prints nothing secret.
#[derive(Debug)]
struct Marked {
    was_done: bool,
    credits: Vec<Pubky>,
}

/// The writers' lock and a fresh session, around [`rewrite`] (step 5).
///
/// A trait so that the command can be tested without a homeserver, as
/// `pull::discovered::WriteUnderLock` is. Its method is an `async fn`, so
/// callers take `&impl MarkUnderLock`.
trait MarkUnderLock {
    /// Marks `bounty` done crediting `credits`, as [`rewrite`] does, at
    /// the time now, under the lock with a fresh session, ended afterwards
    /// whatever happened (an identity's signed out, a Ring one dropped).
    async fn mark(&self, bounty: BountyRef, credits: &[Pubky]) -> anyhow::Result<Marked>;
}

/// The real [`MarkUnderLock`]: `session::with_writer_session`, which takes
/// the lock, signs in or restores afresh, runs the rewrite, then ends the
/// session (signs an identity's out, drops a Ring one) and lets the lock
/// go, also when it fails.
struct LockedSession<'a> {
    ctx: &'a Context,
}

impl MarkUnderLock for LockedSession<'_> {
    async fn mark(&self, bounty: BountyRef, credits: &[Pubky]) -> anyhow::Result<Marked> {
        // The body only borrows the session, so `with_writer_session` ends
        // it whatever the body returns.
        with_writer_session(self.ctx, async move |signed| {
            // `login.json` is read again under the lock: a `login` as
            // another identity since would write into that one's storage.
            if signed.login().pubky != bounty.owner {
                bail!(LOGIN_CHANGED);
            }
            rewrite(&SessionStorage::new(signed), bounty, credits, clock::now()?).await
        })
        .await
    }
}

/// Through `storage`, the owner's own: reads `bounty` back, marks it done
/// crediting `credits` at `done_at` with core's `Bounty::mark_done`, which
/// keeps every other field, unknown ones included, and refuses the owner,
/// and PUTs it unless it would pass `MAX_RECORD_BYTES`.
async fn rewrite(
    storage: &impl OwnStorage,
    bounty: BountyRef,
    credits: &[Pubky],
    done_at: RecordTime,
) -> anyhow::Result<Marked> {
    let path = paths::bounty(bounty.id);
    let Some(bytes) = storage.get_own(&path).await? else {
        bail!("{bounty} is not on your homeserver, so it was not marked done");
    };
    let current =
        Bounty::from_json(&bytes).with_context(|| not_a_record("bounty", &path, bounty.owner))?;
    let was_done = current.status().as_known() == Some(KnownBountyStatus::Done);
    // `?` turns core's `MarkDoneError` into an `anyhow::Error`, through the
    // `std::error::Error` that `thiserror` derived for it; its text is
    // fixed.
    let done = current.mark_done(bounty.owner, credits.iter().copied(), done_at)?;
    let record = serde_json::to_vec(&done).context("could not write the bounty record")?;
    if record.len() > MAX_RECORD_BYTES {
        bail!(
            "the bounty marked done would be {} bytes, over the {MAX_RECORD_BYTES} bytes Sweepky \
             reads a record up to, so it was not written; credit fewer sweepers",
            record.len()
        );
    }
    // A refusal is mapped by `write_error`: 403 and 507 to their messages,
    // anything else to fixed text and the status, never the server's words.
    storage
        .put(&path, record)
        .await
        .map_err(|error| write_error(&error).context(format!("could not write {path}")))?;
    Ok(Marked {
        was_done,
        credits: done.credits().to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io::Cursor;

    use pubky::{Keypair, StatusCode};
    use serde_json::{Value, json};
    use sweepky_core::paths;
    use sweepky_core::{
        Bounty, BountyRef, Circle, Findings, KnownBountyStatus, KnownSweepStatus, MAX_RECORD_BYTES,
        Manifest, Pubky, RecordTime, Sweep, SweepPackage, SweepRef, parse_audit_findings,
    };
    use tempfile::TempDir;

    use super::{
        BOTH_FLAGS, DoneRequest, LockedSession, MarkUnderLock, Marked, NO_GROUPS, NOT_MARKED,
        OTHER_OWNER, OWN_CREDIT, done_with, rewrite,
    };
    use crate::identity::{IdentityName, Refusal};
    use crate::own_storage::OwnStorage;
    use crate::prompt::Prompting;
    use crate::pull::roster::{MAX_CREDITS, RosterPoll};
    use crate::pull::state::{PollState, SweepSummary};
    use crate::pull::store::{CompactFindings, Placement, store_sweep};
    use crate::pull::triage::triage_bounties;
    use crate::remote::{QUOTA_FULL, WRITE_FORBIDDEN};
    use crate::session::NOT_LOGGED_IN;
    use crate::state::{LoginState, write_login_state};
    use crate::test_support::{
        FAKE_HOMESERVER, FAKE_SERVER_TEXT, FakeOwnStorage, PLANTED, SYNTHETIC_SHA, SharedBuffer,
        bounty_json, circle_json, json_bytes, offline_network, private_temp, random_pubky,
        record_id, repo_target_json, sweep_json, test_context,
    };
    use crate::{Context, Report, clock};

    /// `fixtures/cloudflare/findings.json`: B's findings, in Cloudflare's
    /// format, as `submit` converts them.
    const CLOUDFLARE_FINDINGS: &[u8] = include_bytes!("../../../fixtures/cloudflare/findings.json");
    /// `fixtures/common/findings.json`: C's findings, in the common format.
    /// Its first finding shares B's place in `src/auth/session.rs`.
    const COMMON_FINDINGS: &[u8] = include_bytes!("../../../fixtures/common/findings.json");
    /// The title of C's first finding: finding text, which `done` never
    /// shows.
    const C_TITLE: &str = "A session still counts as valid during its expiry second";

    /// The place B, C and the owner all reported, as the preview shows it.
    const SHARED_PLACE: &str = "src/auth/session.rs:88 in fn is_expired";

    fn b_findings() -> Findings {
        let playbook = "cloudflare/security-audit@c1c8a8c".parse().expect("a name");
        parse_audit_findings(CLOUDFLARE_FINDINGS, &playbook)
            .expect("converted")
            .0
    }

    fn c_findings() -> Findings {
        Findings::from_json(COMMON_FINDINGS).expect("findings")
    }

    /// One finding at `file` and `scope` on line 88, a sink, with
    /// [`PLANTED`] as its title and description.
    fn one_finding(file: &str, scope: &str) -> Findings {
        let document = json!({
            "schemaVersion": 1,
            "playbook": "careful-review",
            "findings": [{
                "id": "one",
                "title": PLANTED,
                "status": "needs_validation",
                "locations": [{ "file": file, "line": 88, "kind": "sink", "scope": scope }],
                "description": PLANTED,
            }],
        });
        Findings::from_json(&json_bytes(&document)).expect("findings")
    }

    /// A [`MarkUnderLock`] in place of the writers' lock and a session: it
    /// counts the sessions it opened, and rewrites through its
    /// `FakeOwnStorage` what the real one rewrites through the session's.
    #[derive(Default)]
    struct FakeLock {
        storage: FakeOwnStorage,
        // `Cell`: the trait's `&self` method changes a count, which a
        // single-threaded test can do without a `Mutex`.
        sessions: Cell<usize>,
    }

    impl MarkUnderLock for FakeLock {
        async fn mark(&self, bounty: BountyRef, credits: &[Pubky]) -> anyhow::Result<Marked> {
            self.sessions.set(self.sessions.get() + 1);
            rewrite(&self.storage, bounty, credits, clock::now()?).await
        }
    }

    /// An owner's install, logged in, with one bounty on their homeserver
    /// behind a [`FakeLock`], and whatever `pull` stored and grouped of it.
    struct Owner {
        // Kept so the directory lives as long as the fixture.
        _home: TempDir,
        ctx: Context,
        stderr: SharedBuffer,
        owner: Pubky,
        bounty: BountyRef,
        /// A circle member and a stranger.
        b: Pubky,
        c: Pubky,
        state: PollState,
        lock: FakeLock,
    }

    impl Owner {
        /// The owner's install, whose standard input holds `answer`, with
        /// a circle of the owner and B and no sweep stored yet.
        fn new(answer: &'static [u8]) -> Self {
            let home = private_temp();
            let (ctx, stderr) = test_context(offline_network(), &home, Cursor::new(answer));
            let owner = random_pubky();
            let name: IdentityName = "owner".parse().expect("a name");
            write_login_state(
                &ctx.dirs,
                &LoginState::identity(name, owner, FAKE_HOMESERVER),
            )
            .expect("written");
            let bounty = BountyRef {
                owner,
                id: record_id(1),
            };
            let lock = FakeLock::default();
            lock.storage.insert(
                &paths::bounty(bounty.id),
                json_bytes(&bounty_json(json!([repo_target_json("t1")]))),
            );
            Self {
                _home: home,
                ctx,
                stderr,
                owner,
                bounty,
                b: random_pubky(),
                c: random_pubky(),
                state: PollState::default(),
                lock,
            }
        }

        /// The owner's install with what `pull` leaves once it stored and
        /// grouped three done sweeps: the owner's own, B's and C's, which
        /// all report one place.
        fn with_three_sweeps(answer: &'static [u8]) -> Self {
            let mut fx = Self::new(answer);
            fx.store(
                fx.owner,
                10,
                one_finding("src/auth/session.rs", "fn is_expired"),
            );
            fx.store(fx.b, 11, b_findings());
            fx.store(fx.c, 12, c_findings());
            fx.triage();
            fx
        }

        /// Stores `findings` as `sweeper`'s done sweep `n` of the bounty, as
        /// `pull::open` does, and summarises it as pulled.
        fn store(&mut self, sweeper: Pubky, n: u64, findings: Findings) -> SweepRef {
            let sweep = SweepRef {
                sweeper,
                id: record_id(n),
            };
            let manifest: Manifest = serde_json::from_value(json!({
                "sweeper": sweeper.to_string(),
                "bounty": self.bounty.to_string(),
                "targets": ["t1"],
                "targetShas": { "t1": SYNTHETIC_SHA },
                "playbook": "careful-review",
                "startedAt": "2026-10-19T09:00:00Z",
                "finishedAt": "2026-10-19T10:00:00Z",
            }))
            .expect("a manifest");
            let package = SweepPackage::new(manifest, findings);
            let compact = CompactFindings::of(&package.findings).expect("compact");
            let files = package.into_files().expect("split");
            let placement = if sweeper == self.owner || sweeper == self.b {
                Placement::Trusted
            } else {
                Placement::Untrusted
            };
            store_sweep(
                &self.ctx.dirs,
                self.bounty,
                sweep,
                placement,
                compact,
                files,
            )
            .expect("stored");
            let mut record = sweep_json(self.bounty, &["t1"], "done");
            record["finishedAt"] = json!("2026-10-19T10:00:00Z");
            let parsed = Sweep::from_json(&json_bytes(&record)).expect("a sweep");
            let mut summary = SweepSummary::new(&parsed, None);
            summary.pulled = true;
            self.state.sweeps.insert(sweep, summary);
            sweep
        }

        /// What the triage at the end of a `pull` writes, `groups.json`
        /// among it, with the circle of the owner and B, and the poll state
        /// as that `pull` leaves it.
        fn triage(&self) {
            let roster =
                Circle::from_json(&json_bytes(&circle_json(self.owner, &[self.owner, self.b])))
                    .expect("a circle");
            let poll = RosterPoll {
                roster,
                own_bounties: vec![self.bounty],
                sweeps: Vec::new(),
                credited: Vec::new(),
                warnings: Vec::new(),
            };
            triage_bounties(&self.ctx.dirs, &poll, &self.state).expect("triaged");
            self.save_state();
        }

        fn save_state(&self) {
            self.state
                .write(&self.ctx.dirs, self.owner)
                .expect("written");
        }

        /// `done <bounty> --credit … --no-credit …`, the flags given as
        /// these keys, with the fake lock.
        async fn done(
            &self,
            prompting: Prompting,
            credit: &[Pubky],
            no_credit: &[Pubky],
        ) -> anyhow::Result<Report> {
            let text = |keys: &[Pubky]| keys.iter().map(ToString::to_string).collect::<Vec<_>>();
            let request =
                DoneRequest::parse(&self.bounty.to_string(), &text(credit), &text(no_credit))?;
            done_with(&self.ctx, prompting, &request, &self.lock).await
        }

        /// The bounty as the owner's homeserver holds it now.
        async fn record(&self) -> Bounty {
            let bytes = self
                .lock
                .storage
                .get_own(&paths::bounty(self.bounty.id))
                .await
                .expect("reads")
                .expect("there");
            Bounty::from_json(&bytes).expect("a bounty")
        }

        /// How many questions standard error shows.
        fn questions(&self) -> usize {
            self.stderr.text().matches("[y/N]").count()
        }
    }

    /// `message` names none of `texts`.
    fn assert_unquoted(message: &str, texts: &[&str]) {
        for text in texts {
            assert!(!message.contains(text), "{message} quotes {text}");
        }
    }

    #[tokio::test]
    async fn credit_naming_the_owner_is_refused_in_one_line_before_any_file_is_read() {
        // No login: had done read login.json, it would have failed with
        // NOT_LOGGED_IN instead.
        let home = private_temp();
        let (ctx, stderr) = test_context(offline_network(), &home, Cursor::new(&b"y\n"[..]));
        let owner = random_pubky();
        let id = record_id(1);
        let raw = owner.to_string();
        let prefixed = format!("pubky{owner}");
        // The URL and the flag in either spelling: compared by key bytes.
        for (in_url, in_flag) in [(&raw, &prefixed), (&prefixed, &raw), (&raw, &raw)] {
            let url = format!("pubky://{in_url}/pub/sweepky/bounties/{id}.json");
            let others = [random_pubky().to_string()];
            let flags = [others[0].clone(), in_flag.clone()];

            let error = super::done(&ctx, Prompting::Allowed, &url, &flags, &[])
                .await
                .expect_err("refused");

            assert_eq!(format!("{error:#}"), OWN_CREDIT, "{in_url} {in_flag}");
        }
        assert!(!OWN_CREDIT.contains('\n'));
        assert_eq!(stderr.text(), "");
        assert!(!ctx.dirs.credential_lock_file().exists());
    }

    #[tokio::test]
    async fn another_owners_bounty_a_sweep_url_a_pasted_key_or_a_bad_flag_is_refused_unquoted() {
        let fx = Owner::new(b"y\n");
        let other = random_pubky();
        let id = record_id(1);
        let secret = Keypair::random().secret();
        // A test may hold a secret in a plain array; spelt as a pasted key
        // would be, in z-base32.
        let z32_secret = Pubky::from_bytes(secret).to_string();
        let others_bounty = format!("pubky://{other}/pub/sweepky/bounties/{id}.json");
        let sweep_url = format!("pubky://{}/pub/sweepky/sweeps/{id}.json", fx.owner);

        let error = super::done(&fx.ctx, Prompting::Allowed, &others_bounty, &[], &[])
            .await
            .expect_err("refused");
        assert_eq!(format!("{error:#}"), OTHER_OWNER);

        let error = super::done(&fx.ctx, Prompting::Allowed, &sweep_url, &[], &[])
            .await
            .expect_err("refused");
        let message = format!("{error:#}");
        assert!(message.contains("a sweep record's URL"), "{message}");
        assert!(message.contains("done takes a bounty's URL"), "{message}");
        assert_unquoted(&message, &[&sweep_url, &fx.owner.to_string()]);

        let error = super::done(&fx.ctx, Prompting::Allowed, &z32_secret, &[], &[])
            .await
            .expect_err("refused");
        assert_eq!(error.downcast_ref::<Refusal>(), Some(&Refusal::RawKey));
        assert_unquoted(&format!("{error:#}"), &[&z32_secret]);

        let url = fx.bounty.to_string();
        for (credit, no_credit) in [
            (vec![PLANTED.to_owned()], vec![]),
            (vec![], vec![PLANTED.to_owned()]),
        ] {
            let error = super::done(&fx.ctx, Prompting::Allowed, &url, &credit, &no_credit)
                .await
                .expect_err("refused");
            let message = format!("{error:#}");
            assert!(message.contains("takes a pubky"), "{message}");
            assert_unquoted(&message, &[PLANTED]);
        }
        // Nothing asked, nothing locked.
        assert_eq!(fx.stderr.text(), "");
        assert!(!fx.ctx.dirs.credential_lock_file().exists());
    }

    #[tokio::test]
    async fn one_key_in_both_flags_or_more_credits_than_a_record_carries_is_refused() {
        let fx = Owner::new(b"y\n");
        let url = fx.bounty.to_string();
        let b = fx.b.to_string();
        let error = super::done(
            &fx.ctx,
            Prompting::Allowed,
            &url,
            // `from_ref` lends `b` as a one-item slice, with no copy.
            std::slice::from_ref(&b),
            &[format!("pubky{b}")],
        )
        .await
        .expect_err("refused");
        assert_eq!(format!("{error:#}"), BOTH_FLAGS);

        let many: Vec<String> = (0..=MAX_CREDITS)
            .map(|_| random_pubky().to_string())
            .collect();
        let error = super::done(&fx.ctx, Prompting::Allowed, &url, &many, &[])
            .await
            .expect_err("refused");
        let message = format!("{error:#}");
        assert!(
            message.contains(&format!("at most {MAX_CREDITS}")),
            "{message}"
        );
        assert_eq!(fx.stderr.text(), "");
    }

    #[tokio::test]
    async fn the_proposal_is_b_and_c_never_the_owner_each_with_its_label_and_places() {
        let fx = Owner::with_three_sweeps(b"n\n");

        let report = fx
            .done(Prompting::Allowed, &[], &[])
            .await
            .expect("a no is not an error");

        assert!(report.text().contains(NOT_MARKED), "{}", report.text());
        let shown = fx.stderr.text();
        let (owner, b, c) = (fx.owner.to_string(), fx.b.to_string(), fx.c.to_string());
        // B is `circle`, C, a stranger, `unknown`. B's three findings are
        // three groups, C's two are two, and the place all three reported
        // is one group with three reporters.
        for line in [
            format!("  {b}: circle; 3 findings in 3 groups\n"),
            format!("  {c}: unknown; 2 findings in 2 groups\n"),
            format!("    {SHARED_PLACE}, reported by 3 sweepers\n"),
            "    src/http.rs:12 in fn header, reported by 1 sweeper\n".to_owned(),
            format!("Credits to write (2):\n  {b} (proposed)\n  {c} (proposed)\n"),
        ] {
            assert!(shown.contains(&line), "{line:?} not in {shown}");
        }
        // B before C: upload order.
        assert!(shown.find(&format!("  {b}:")) < shown.find(&format!("  {c}:")));
        // The owner's own sweep is grouped, and the owner is never proposed.
        assert!(!shown.contains(&format!("  {owner}")), "{shown}");
        // Places and counts, never a finding's text.
        assert_unquoted(&shown, &[PLANTED, C_TITLE]);
        assert!(
            shown.ends_with(
                "Mark this bounty done, crediting 2 sweepers, where anyone can read it? [y/N] "
            ),
            "{shown}"
        );
        // A no writes nothing and opens no session.
        assert_eq!(fx.lock.sessions.get(), 0);
        assert!(fx.lock.storage.puts().is_empty());
    }

    #[tokio::test]
    async fn a_sweep_whose_last_known_status_is_not_done_is_not_proposed() {
        let mut fx = Owner::with_three_sweeps(b"n\n");
        // C's record says running again since it was stored and grouped.
        let c_sweep = SweepRef {
            sweeper: fx.c,
            id: record_id(12),
        };
        fx.state
            .sweeps
            .get_mut(&c_sweep)
            .expect("summarised")
            .status = KnownSweepStatus::Running.into();
        fx.save_state();

        fx.done(Prompting::Allowed, &[], &[]).await.expect("a no");

        let shown = fx.stderr.text();
        let (b, c) = (fx.b.to_string(), fx.c.to_string());
        assert!(
            shown.contains(&format!("Credits to write (1):\n  {b} (proposed)\n")),
            "{shown}"
        );
        assert!(!shown.contains(&format!("  {c}:")), "{shown}");
        assert!(
            shown.contains(&format!(
                "as none of their grouped sweeps is done:\n  {c}\n"
            )),
            "{shown}"
        );
    }

    #[tokio::test]
    async fn every_place_a_stranger_wrote_is_sanitised() {
        let mut fx = Owner::new(b"n\n");
        let d = random_pubky();
        fx.store(
            d,
            10,
            one_finding("src/\u{1b}[2Jevil.rs", "fn \u{202e}gnp.exe"),
        );
        fx.triage();

        fx.done(Prompting::Allowed, &[], &[]).await.expect("a no");

        let shown = fx.stderr.text();
        for raw in ['\u{1b}', '\u{202e}'] {
            assert!(
                !shown.contains(raw),
                "{raw:?} reached the terminal: {shown:?}"
            );
        }
        assert!(
            shown.contains(
                "    src/\\u{1b}[2Jevil.rs:88 in fn \\u{202e}gnp.exe, reported by 1 sweeper\n"
            ),
            "{shown}"
        );
    }

    #[tokio::test]
    async fn no_credit_drops_a_proposed_name_credit_adds_one_and_the_rest_is_asked_once() {
        // --no-credit C --credit D: B still comes from the proposal alone,
        // so done asks, once; a yes writes B and D.
        let fx = Owner::with_three_sweeps(b"y\n");
        let d = random_pubky();

        fx.done(Prompting::Allowed, &[d], &[fx.c])
            .await
            .expect("marked");

        assert_eq!(fx.questions(), 1);
        let shown = fx.stderr.text();
        let decided = format!(
            "Credits to write (2):\n  {} (proposed)\n  {d} (--credit)\n\
             Not credited (--no-credit):\n  {}\n",
            fx.b, fx.c
        );
        assert!(shown.contains(&decided), "{shown}");
        assert_eq!(fx.record().await.credits(), [fx.b, d]);
        assert_eq!(fx.lock.sessions.get(), 1);
    }

    #[tokio::test]
    async fn flags_that_name_every_proposed_sweeper_need_no_question_even_under_no_input() {
        let fx = Owner::with_three_sweeps(b"");

        let report = fx
            .done(Prompting::Forbidden, &[fx.b], &[fx.c])
            .await
            .expect("marked");

        assert_eq!(fx.questions(), 0);
        let shown = fx.stderr.text();
        assert!(shown.contains("so done does not ask"), "{shown}");
        assert_eq!(fx.record().await.credits(), [fx.b]);
        let written = format!("crediting 1 sweeper:\n{}\n  {}\n", fx.bounty, fx.b);
        assert!(report.text().contains(&written), "{}", report.text());
    }

    #[tokio::test]
    async fn a_lone_credit_leaves_the_rest_to_the_question_which_no_input_refuses() {
        // C comes from the proposal alone, so done would ask; under
        // --no-input it fails naming the question, and writes nothing.
        let fx = Owner::with_three_sweeps(b"y\n");

        let error = fx
            .done(Prompting::Forbidden, &[fx.b], &[])
            .await
            .expect_err("no question under --no-input");

        let message = format!("{error:#}");
        assert!(message.contains("--no-input"), "{message}");
        assert!(
            message.contains("Mark this bounty done, crediting 2 sweepers"),
            "{message}"
        );
        assert!(message.contains(NOT_MARKED), "{message}");
        assert_eq!(fx.lock.sessions.get(), 0);
        assert!(fx.lock.storage.puts().is_empty());
    }

    #[tokio::test]
    async fn with_no_groups_a_warning_says_the_proposal_may_miss_sweepers_and_the_question_follows()
    {
        // Nothing stored for the bounty on this install, and a flag that
        // would settle every name of an empty proposal.
        let fx = Owner::new(b"n\n");
        fx.done(Prompting::Allowed, &[fx.b], &[])
            .await
            .expect("a no");

        let shown = fx.stderr.text();
        assert!(
            shown.starts_with(&format!("warning: {NO_GROUPS}\n")),
            "{shown}"
        );
        assert_eq!(fx.questions(), 1);
        assert!(
            shown.ends_with(
                "Mark this bounty done, crediting 1 sweeper, where anyone can read it? [y/N] "
            ),
            "{shown}"
        );
        assert!(fx.lock.storage.puts().is_empty());
    }

    #[tokio::test]
    async fn the_question_comes_before_the_writers_lock() {
        // The real lock and session: a no takes neither.
        let fx = Owner::with_three_sweeps(b"n\n");
        let request = DoneRequest::parse(&fx.bounty.to_string(), &[], &[]).expect("checked");
        let report = done_with(
            &fx.ctx,
            Prompting::Allowed,
            &request,
            &LockedSession { ctx: &fx.ctx },
        )
        .await
        .expect("a no");
        assert!(report.text().contains(NOT_MARKED));
        assert!(!fx.ctx.dirs.credential_lock_file().exists());
    }

    #[tokio::test]
    async fn not_logged_in_is_said_before_anything_is_asked() {
        let home = private_temp();
        let (ctx, stderr) = test_context(offline_network(), &home, Cursor::new(&b"y\n"[..]));
        let url = format!(
            "pubky://{}/pub/sweepky/bounties/{}.json",
            random_pubky(),
            record_id(1)
        );
        let error = super::done(&ctx, Prompting::Allowed, &url, &[], &[])
            .await
            .expect_err("not logged in");
        assert_eq!(format!("{error:#}"), NOT_LOGGED_IN);
        assert_eq!(stderr.text(), "");
    }

    // ----- The rewrite under the lock -----

    fn time(text: &str) -> RecordTime {
        text.parse().expect("a time")
    }

    /// A bounty a newer client posted: a field this build does not know at
    /// the top, one inside `playbook`, a reward object and a target of a
    /// kind it does not know.
    fn newer_bounty() -> Value {
        let mut record = bounty_json(json!([
            repo_target_json("t1"),
            { "id": "t2", "kind": "crate", "name": "serde", "version": "1.0.229" },
        ]));
        record["addedLater"] = json!({ "nested": [1, "two", null] });
        record["playbook"]["profile"] = json!("standard");
        record["reward"] = json!({ "kind": "sats", "capSats": 250_000 });
        record
    }

    /// A storage holding `record` as `bounty`'s.
    fn storage_with(bounty: BountyRef, record: &Value) -> FakeOwnStorage {
        let storage = FakeOwnStorage::default();
        storage.insert(&paths::bounty(bounty.id), json_bytes(record));
        storage
    }

    fn a_bounty() -> BountyRef {
        BountyRef {
            owner: random_pubky(),
            id: record_id(1),
        }
    }

    async fn stored(storage: &FakeOwnStorage, bounty: BountyRef) -> Value {
        let bytes = storage
            .get_own(&paths::bounty(bounty.id))
            .await
            .expect("reads")
            .expect("there");
        serde_json::from_slice(&bytes).expect("JSON")
    }

    #[tokio::test]
    async fn the_rewrite_sets_done_done_at_and_credits_and_keeps_every_field_it_does_not_know() {
        let bounty = a_bounty();
        let input = newer_bounty();
        let storage = storage_with(bounty, &input);
        let (b, c) = (random_pubky(), random_pubky());

        let marked = rewrite(&storage, bounty, &[b, c], time("2026-10-19T12:00:00Z"))
            .await
            .expect("marked");

        assert!(!marked.was_done);
        assert_eq!(marked.credits, [b, c]);
        let mut expected = input;
        expected["status"] = json!("done");
        expected["credits"] = json!([b.to_string(), c.to_string()]);
        expected["doneAt"] = json!("2026-10-19T12:00:00Z");
        assert_eq!(stored(&storage, bounty).await, expected);
        assert_eq!(storage.puts(), [paths::bounty(bounty.id)]);
    }

    #[tokio::test]
    async fn done_again_replaces_the_credits_the_last_write_winning() {
        let bounty = a_bounty();
        let storage = storage_with(bounty, &newer_bounty());
        let (b, c, d) = (random_pubky(), random_pubky(), random_pubky());

        rewrite(&storage, bounty, &[b, c], time("2026-10-19T12:00:00Z"))
            .await
            .expect("marked");
        let again = rewrite(&storage, bounty, &[d], time("2026-10-20T12:00:00Z"))
            .await
            .expect("marked again");

        assert!(again.was_done);
        let done =
            Bounty::from_json(&json_bytes(&stored(&storage, bounty).await)).expect("a bounty");
        assert_eq!(done.status().as_known(), Some(KnownBountyStatus::Done));
        assert_eq!(done.credits(), [d]);
        assert_eq!(done.done_at(), Some(&time("2026-10-20T12:00:00Z")));
    }

    #[tokio::test]
    async fn a_refused_put_gives_write_errors_fixed_text_never_the_servers() {
        let bounty = a_bounty();
        let path = paths::bounty(bounty.id);
        for (status, fixed) in [
            (StatusCode::FORBIDDEN, WRITE_FORBIDDEN),
            (StatusCode::INSUFFICIENT_STORAGE, QUOTA_FULL),
        ] {
            let storage = FakeOwnStorage::refusing(&path, status, FAKE_SERVER_TEXT);
            storage.insert(&path, json_bytes(&newer_bounty()));

            let error = rewrite(
                &storage,
                bounty,
                &[random_pubky()],
                time("2026-10-19T12:00:00Z"),
            )
            .await
            .expect_err("refused");

            let message = format!("{error:#}");
            assert!(message.contains(fixed), "{message}");
            assert_unquoted(&message, &[FAKE_SERVER_TEXT]);
        }
    }

    #[tokio::test]
    async fn a_rewrite_past_the_record_cap_is_refused_before_the_put() {
        // A bounty 64 bytes under the cap: two credits and a doneAt take it
        // over.
        let bounty = a_bounty();
        let mut record = newer_bounty();
        // Each `b` added to the brief adds one byte to the record.
        let short = MAX_RECORD_BYTES - 64 - json_bytes(&record).len();
        let brief = format!(
            "{}{}",
            record["brief"].as_str().expect("a brief"),
            "b".repeat(short)
        );
        record["brief"] = json!(brief);
        assert_eq!(json_bytes(&record).len(), MAX_RECORD_BYTES - 64);
        let storage = storage_with(bounty, &record);

        let error = rewrite(
            &storage,
            bounty,
            &[random_pubky(), random_pubky()],
            time("2026-10-19T12:00:00Z"),
        )
        .await
        .expect_err("over the cap");

        let message = format!("{error:#}");
        assert!(
            message.contains(&format!("over the {MAX_RECORD_BYTES} bytes")),
            "{message}"
        );
        assert!(storage.puts().is_empty());
    }

    #[tokio::test]
    async fn the_owner_is_refused_again_by_core_at_the_rewrite() {
        let bounty = a_bounty();
        let storage = storage_with(bounty, &newer_bounty());
        let error = rewrite(
            &storage,
            bounty,
            &[bounty.owner],
            time("2026-10-19T12:00:00Z"),
        )
        .await
        .expect_err("refused");
        assert!(
            format!("{error:#}").contains("cannot be credited"),
            "{error:#}"
        );
        assert!(storage.puts().is_empty());
    }
}
