//! `pull`'s local triage of each of the owner's bounties: every stored
//! sweep's sweeper given its trust label, the sweeps' findings grouped by
//! the place in the code they point at, and two files written in the
//! bounty's directory, both 0600:
//!
//! | File | What |
//! |---|---|
//! | `<bounty id>/groups.json` | attribution: the sweeps grouped, each with its sweeper's label, every group with its `reportedBy`, its members and their anchors, and the sweeps left out |
//! | `<bounty id>/merged.json` | content: the merged report, the findings of trusted sweeps only |
//!
//! [`triage_bounties`] runs after `pull::open` has stored what it opened.
//!
//! **Trust** (01, "Records (v1)"; 00's trust model). The labels come from
//! core's `trust_labels`, given the run's roster and every roster bounty as
//! the roster poll hands them on: each once, from the poll state's map, so
//! a credit is never counted twice, and core leaves out a credit naming the
//! bounty's own owner. A sweep is trusted only when its sweeper is `circle`.
//! A `known` or `unknown` sweeper is outside the circle: their sweep groups
//! and is attributed like anyone's, but its content stays in `untrusted/`
//! and never enters `merged.json` (01, "Attribution and content are two
//! different steps"; 02, "Untrusted reports are data"). The label is this
//! run's, not where `pull::store` put the sweep when it was opened.
//!
//! **Which sweeps.** Every sweep of the bounty the poll state says is
//! stored (`pulled`), except one whose record now says `aborted` (P2b). At
//! most [`MAX_GROUPED_SWEEPS`] of them, and at most
//! [`MAX_GROUPED_FINDINGS_BYTES`] of compact findings among them, are read:
//! the circle's first, then everyone else's, each oldest first, so a flood
//! of strangers' sweeps cannot push the circle's out of the merged report.
//! A sweep past the count, or whose compact copy is longer than what is
//! left of the bytes, is left out, with a warning and in `groups.json`'s
//! `leftOut`; a smaller one after it may still fit. Each copy's length is
//! checked before it is read (`store::read_stored_findings`). Those read are
//! grouped by core's `group_findings` in upload order, which is sweep-id
//! order: an id is its record's creation time, and `finishedAt` is opaque
//! text.
//!
//! **The files.** Compact JSON, written by `store::compact_json` into a
//! wiped buffer of exactly their length, at most [`MAX_TRIAGE_FILE_BYTES`],
//! then through `private_fs::write_private_file`, as `pull`'s state files
//! are: 0600 from the start, a temp file renamed into place, a link at the
//! name refused, and only once the bounty's directory is seen to be a real
//! one whose owner check names the owner. The same sweeps, labels and
//! findings give the same bytes. Both files are rewritten every run, so a
//! sweeper who leaves the circle takes their content out of `merged.json`
//! at the next pull. A bounty with no directory yet (nothing stored) gets
//! neither.
//!
//! - `groups.json` is `{schemaVersion: 1, bounty, sweeps: [{sweep, label,
//!   bounties, owners, trusted}], groups: [{reportedBy: [<z32>], members:
//!   [{sweep, index, anchor: {file, line?, scope?} | null}]}], leftOut:
//!   [<sweep URL>]}`. A member is finding `index` of its sweep's
//!   `findings.json`; its anchor is the location it was grouped by, its
//!   first sink or else its first location, as core picks it.
//! - `merged.json` is `{schemaVersion: 1, bounty, groups: [{reportedBy,
//!   findings: [{sweep, index, finding}]}]}`: core's merged report, each
//!   group with a trusted member and its findings from trusted sweeps
//!   alone. Its `reportedBy` is the whole group's, strangers included:
//!   attribution counts every sweep, and a key is no content.
//!
//! **Sealed content.** Findings and anchors are what sweepers' agents
//! wrote: they are written into these owner-only files and never printed
//! here (`done` shows the anchors, sanitised, as places).
//! Nothing here derives `Debug` over a finding, and every warning names
//! keys, core-built URLs, paths and numbers alone. An untrusted sweep's
//! anchors are a stranger's text, so `groups.json` is data to the owner's
//! agent, as `untrusted/` is (02): shown, never followed.
//!
//! **Known limits.** Every bounty of the owner's with a directory is
//! triaged every run, each within the caps above, so a run's local work
//! grows with the number of bounties. A write that fails leaves the file the
//! last run wrote.

use std::path::Path;

use anyhow::bail;
use serde::Serialize;
use sweepky_core::{
    BountyRef, Finding, FindingGroup, FindingGroups, Findings, KnownLocationKind, KnownSweepStatus,
    Location, LocationKind, MergedGroup, Pubky, SchemaVersion, SweepFindings, SweepRef, Trust,
    TrustLabel, TrustTable, group_findings, trust_labels,
};

use super::roster::RosterPoll;
use super::state::PollState;
use super::store::{StoredCopy, compact_json, read_stored_findings, stored_bounty_dir};
use crate::Dirs;
use crate::private_fs::write_private_file;

/// The most sweeps of one bounty grouped in a run. Grouping holds every
/// sweep's findings at once, so this bounds the memory it takes.
pub(crate) const MAX_GROUPED_SWEEPS: usize = 64;

/// The most bytes of compact findings grouped for one bounty in a run:
/// 64 MiB. A count alone bounds nothing, since one sweep's copy may be
/// 32 MiB and parsing JSON takes up to about 20 times its size (P1b).
pub(crate) const MAX_GROUPED_FINDINGS_BYTES: usize = 64 * 1024 * 1024;

/// The most bytes `groups.json` or `merged.json` may be: 256 MiB, four times
/// [`MAX_GROUPED_FINDINGS_BYTES`]. Either file holds, per grouped finding,
/// at most its anchor or its content, as compact as in its copy, plus about
/// 210 bytes: a sweep URL, an index, one reporter's key (a group lists each
/// reporter once, and each finding adds at most one) and the JSON around
/// them. A finding's compact JSON is about 100 bytes at the least, so a file
/// the budget lets through stays under about 3.2 times it, and `done` can
/// read either back with this cap.
pub(crate) const MAX_TRIAGE_FILE_BYTES: usize = 4 * MAX_GROUPED_FINDINGS_BYTES;

/// The attribution file, in a bounty's directory.
pub(crate) const GROUPS_FILE: &str = "groups.json";

/// The merged report, in a bounty's directory.
pub(crate) const MERGED_FILE: &str = "merged.json";

/// What [`triage_bounties`] did, for the rest of `pull`.
///
/// Keys, URLs, labels and fixed text only, so deriving `Debug` prints
/// nothing of a finding.
#[derive(Debug, Default)]
pub(crate) struct Triaged {
    /// Each bounty triaged, in the roster poll's order.
    pub(crate) bounties: Vec<BountyTriage>,
    /// One line for each sweep left out, in fixed text that names keys,
    /// URLs and numbers, never a finding.
    pub(crate) warnings: Vec<String>,
}

/// One bounty's triage: its sweeps grouped, each with its label.
#[derive(Debug)]
pub(crate) struct BountyTriage {
    /// The owner's bounty.
    pub(crate) bounty: BountyRef,
    /// The sweeps grouped, in upload order.
    pub(crate) sweeps: Vec<LabelledSweep>,
}

/// A sweep grouped, with its sweeper's trust and whether its content
/// enters `merged.json`: `groups.json`'s `sweeps` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct LabelledSweep {
    /// The sweep.
    pub(crate) sweep: SweepRef,
    /// Its sweeper's label and tally.
    // `flatten` writes `Trust`'s `label`, `bounties` and `owners` beside
    // `sweep` rather than under a key of their own.
    #[serde(flatten)]
    pub(crate) trust: Trust,
    /// Whether its sweeper is `circle`.
    pub(crate) trusted: bool,
}

/// How much one bounty's triage reads. The run's are the constants above;
/// a test passes smaller ones, so it can reach them with a few sweeps.
#[derive(Clone, Copy)]
struct Caps {
    /// The most sweeps grouped.
    sweeps: usize,
    /// The most bytes of compact findings among them.
    bytes: usize,
}

impl Caps {
    /// A run's caps, the constants above.
    const RUN: Self = Self {
        sweeps: MAX_GROUPED_SWEEPS,
        bytes: MAX_GROUPED_FINDINGS_BYTES,
    };
}

/// Triages each of the owner's bounties the roster poll `poll` found,
/// reading what `pull::store` stored and what the poll state `state` says
/// of it: see the module docs. Writes `groups.json` and `merged.json` in
/// each bounty's directory that exists.
///
/// A sweep that cannot be read is left out with a warning. The errors are
/// the local files': a bounty directory that is a link or another owner's,
/// and a write that fails.
pub(crate) fn triage_bounties(
    dirs: &Dirs,
    poll: &RosterPoll,
    state: &PollState,
) -> anyhow::Result<Triaged> {
    triage_within(dirs, poll, state, Caps::RUN)
}

/// [`triage_bounties`] within `caps`.
fn triage_within(
    dirs: &Dirs,
    poll: &RosterPoll,
    state: &PollState,
    caps: Caps,
) -> anyhow::Result<Triaged> {
    // Once a run: each roster bounty is in `credited` once (the roster
    // poll's own rule), which is what makes `trust_labels` count it once.
    let labels = trust_labels(&poll.roster, &poll.credited);
    let mut triager = Triager {
        dirs,
        state,
        labels: &labels,
        caps,
        warnings: Vec::new(),
    };
    let mut bounties = Vec::new();
    // `&bounty` in the pattern copies each `BountyRef` out of the list: it
    // is `Copy`.
    for &bounty in &poll.own_bounties {
        if let Some(triaged) = triager.triage_bounty(bounty)? {
            bounties.push(triaged);
        }
    }
    Ok(Triaged {
        bounties,
        warnings: triager.warnings,
    })
}

/// The groups of the owner's `bounty` again, as [`triage_bounties`] made
/// them for `merged.json` this run, for `pull --findings` to print; `None`
/// when nothing of it is stored. `labels` is the run's table, the one the
/// triage labelled with.
///
/// The same stored copies, read again within the same caps and in the same
/// order, give the same groups, so one bounty's findings are held at a
/// time rather than every bounty's for the whole run. Whatever warnings
/// the reads give, the triage said already; they are dropped here.
pub(crate) fn regroup(
    dirs: &Dirs,
    state: &PollState,
    labels: &TrustTable,
    bounty: BountyRef,
) -> anyhow::Result<Option<FindingGroups>> {
    // Checked first, as the triage does: a link, or another owner's bounty
    // with the same id, is an error before anything is read.
    if stored_bounty_dir(dirs, bounty)?.is_none() {
        return Ok(None);
    }
    let mut triager = Triager {
        dirs,
        state,
        labels,
        caps: Caps::RUN,
        warnings: Vec::new(),
    };
    let (grouped, _left_out) = triager.group(bounty);
    Ok(Some(grouped))
}

/// What one run's triage reads, and the warnings it has so far.
///
/// One lifetime for every borrow: they all come from [`triage_within`]'s
/// arguments, or its locals, and live as long as its call.
struct Triager<'t> {
    dirs: &'t Dirs,
    state: &'t PollState,
    labels: &'t TrustTable,
    caps: Caps,
    warnings: Vec<String>,
}

impl Triager<'_> {
    /// Triages `bounty`, or `None` when nothing of it is stored yet.
    fn triage_bounty(&mut self, bounty: BountyRef) -> anyhow::Result<Option<BountyTriage>> {
        // Checked before anything is read or written: a link, or another
        // owner's bounty with the same id, is an error.
        let Some(dir) = stored_bounty_dir(self.dirs, bounty)? else {
            return Ok(None);
        };
        let (grouped, left_out) = self.group(bounty);
        let labelled: Vec<LabelledSweep> = grouped
            .sweeps()
            .iter()
            .map(|sweep| self.labelled(sweep.sweep))
            .collect();
        write_file(
            &dir,
            GROUPS_FILE,
            &groups_file(bounty, &grouped, &labelled, &left_out),
        )?;
        write_file(&dir, MERGED_FILE, &merged_file(bounty, &grouped))?;
        Ok(Some(BountyTriage {
            bounty,
            sweeps: labelled,
        }))
    }

    /// The stored sweeps of `bounty` read within the caps and grouped, with
    /// the sweeps left out.
    fn group(&mut self, bounty: BountyRef) -> (FindingGroups, Vec<SweepRef>) {
        let (sweeps, left_out) = self.read_within_caps(bounty, self.candidates(bounty));
        // `group_findings` takes the sweeps by value and hands them back
        // inside the groups, so nothing is copied.
        (group_findings(sweeps), left_out)
    }

    /// `sweep` with its sweeper's trust.
    fn labelled(&self, sweep: SweepRef) -> LabelledSweep {
        // `Trust` is `Copy`, so `get` hands back a copy, not a borrow.
        let trust = self.labels.get(sweep.sweeper);
        LabelledSweep {
            sweep,
            trust,
            trusted: trust.label == TrustLabel::Circle,
        }
    }

    /// The sweeps of `bounty` the poll state says are stored, but for the
    /// aborted, in the order they are read: the circle's first, then the
    /// rest, each oldest first.
    fn candidates(&self, bounty: BountyRef) -> Vec<LabelledSweep> {
        let mut candidates: Vec<LabelledSweep> = self
            .state
            .sweeps
            .iter()
            .filter(|(_, summary)| {
                summary.bounty == bounty
                    && summary.pulled
                    && summary.status.as_known() != Some(KnownSweepStatus::Aborted)
            })
            .map(|(&sweep, _)| self.labelled(sweep))
            .collect();
        // `false` sorts before `true`, so `!trusted` puts the circle first.
        // A sweep id is its record's creation time; two sweepers' sweeps
        // with one id are ordered by key, so the order is the same each run.
        candidates.sort_by_key(|candidate| {
            (
                !candidate.trusted,
                candidate.sweep.id,
                candidate.sweep.sweeper,
            )
        });
        candidates
    }

    /// The findings of `candidates`, sweeps of `bounty`, read in their order
    /// within the caps and handed back in upload order, with the sweeps
    /// left out.
    fn read_within_caps(
        &mut self,
        bounty: BountyRef,
        candidates: Vec<LabelledSweep>,
    ) -> (Vec<SweepFindings>, Vec<SweepRef>) {
        let mut read: Vec<SweepFindings> = Vec::new();
        let mut left_out: Vec<SweepRef> = Vec::new();
        let mut bytes_left = self.caps.bytes;
        let mut past_count = 0;
        // The pattern takes each candidate apart, keeping the two fields
        // used here; `..` skips the rest.
        for LabelledSweep { sweep, trusted, .. } in candidates {
            if read.len() == self.caps.sweeps {
                left_out.push(sweep);
                past_count += 1;
                continue;
            }
            let Some((findings, len)) = self.read_one(bounty, sweep, bytes_left) else {
                left_out.push(sweep);
                continue;
            };
            // Never below zero: the copy was read within `bytes_left`.
            // `saturating_sub` says so without a panic to reason about.
            bytes_left = bytes_left.saturating_sub(len);
            read.push(SweepFindings {
                sweep,
                trusted,
                findings,
            });
        }
        // Those past the count, in one line rather than one each.
        if past_count > 0 {
            self.warnings.push(format!(
                "pull left {past_count} sweeps of {bounty} out of its groups this time: it \
                 groups at most {} of a bounty's sweeps",
                self.caps.sweeps
            ));
        }
        read.sort_by_key(|sweep| (sweep.sweep.id, sweep.sweep.sweeper));
        (read, left_out)
    }

    /// The findings of `sweep` of `bounty` and their copy's length, if the
    /// copy is at most `bytes_left` long and reads; else `None`, with a
    /// warning that says why.
    fn read_one(
        &mut self,
        bounty: BountyRef,
        sweep: SweepRef,
        bytes_left: usize,
    ) -> Option<(Findings, usize)> {
        let why = match read_stored_findings(self.dirs, bounty, sweep, bytes_left) {
            Ok(Some(StoredCopy::Read { findings, len, .. })) => return Some((findings, len)),
            Ok(Some(StoredCopy::OverCap { len })) => format!(
                "its findings are {len} bytes, more than the {bytes_left} left of the {} bytes \
                 of findings pull groups of a bounty",
                self.caps.bytes
            ),
            Ok(None) => "it is marked pulled, but no copy of its findings is stored".to_owned(),
            Err(error) => format!("{error:#}"),
        };
        self.warnings.push(format!(
            "pull left {sweep} out of the groups of {bounty} this time: {why}"
        ));
        None
    }
}

/// `groups.json`'s shape, borrowing what it writes from the groups.
// No `Debug` on this or the shapes below: they hold findings, anchors and
// agent-written text, which are only ever serialized into the owner's file.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupsFile<'g> {
    schema_version: SchemaVersion,
    bounty: BountyRef,
    sweeps: &'g [LabelledSweep],
    groups: Vec<GroupEntry<'g>>,
    left_out: &'g [SweepRef],
}

/// A `groups.json` group.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupEntry<'g> {
    reported_by: &'g [Pubky],
    members: Vec<MemberEntry<'g>>,
}

/// A `groups.json` member: finding `index` of `sweep`, and where it points.
#[derive(Serialize)]
struct MemberEntry<'g> {
    sweep: SweepRef,
    index: usize,
    anchor: Option<AnchorEntry<'g>>,
}

/// The file, line and scope of the location a finding was grouped by, as
/// its agent wrote them.
#[derive(Serialize)]
struct AnchorEntry<'g> {
    file: &'g str,
    #[serde(skip_serializing_if = "Option::is_none")]
    line: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<&'g str>,
}

/// `merged.json`'s shape.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MergedFile<'g> {
    schema_version: SchemaVersion,
    bounty: BountyRef,
    groups: Vec<MergedEntry<'g>>,
}

/// A `merged.json` group.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MergedEntry<'g> {
    reported_by: &'g [Pubky],
    findings: Vec<MergedFindingEntry<'g>>,
}

/// A `merged.json` finding: finding `index` of the trusted sweep `sweep`,
/// whole, as its sweep holds it.
#[derive(Serialize)]
struct MergedFindingEntry<'g> {
    sweep: SweepRef,
    index: usize,
    finding: &'g Finding,
}

/// `groups.json` of `bounty`: the sweeps `grouped` holds, labelled as
/// `labelled` (in the same order), its groups, and the sweeps `left_out`.
// The `'g` ties the shape to `grouped`, `labelled` and `left_out`, which it
// borrows from instead of copying: none of them may be dropped while it is
// alive, and the compiler checks that.
fn groups_file<'g>(
    bounty: BountyRef,
    grouped: &'g FindingGroups,
    labelled: &'g [LabelledSweep],
    left_out: &'g [SweepRef],
) -> GroupsFile<'g> {
    GroupsFile {
        schema_version: SchemaVersion::CURRENT,
        bounty,
        sweeps: labelled,
        groups: grouped
            .groups()
            .iter()
            .map(|group| group_entry(grouped, group))
            .collect(),
        left_out,
    }
}

/// `group` of `grouped` as `groups.json` writes it.
fn group_entry<'g>(grouped: &'g FindingGroups, group: &'g FindingGroup) -> GroupEntry<'g> {
    GroupEntry {
        reported_by: group.reported_by(),
        // A member `group_findings` made always points at a finding; the
        // lookups give `None` rather than panic, and `filter_map` skips one.
        members: group
            .members()
            .iter()
            .filter_map(|&member| {
                let sweep = grouped.sweeps().get(member.sweep)?;
                let finding = grouped.finding(member)?;
                Some(MemberEntry {
                    sweep: sweep.sweep,
                    index: member.finding,
                    anchor: anchor_of(finding),
                })
            })
            .collect(),
    }
}

/// The location `finding` was grouped by: its first location whose `kind`
/// is exactly `sink`, or else its first location (core's rule on
/// `group_findings`, whose own anchor type is private to it); `None` when it
/// has none. Written as the agent wrote it, before core's trimming.
fn anchor_of(finding: &Finding) -> Option<AnchorEntry<'_>> {
    let location = finding
        .locations
        .iter()
        .find(|location| is_sink(location))
        .or_else(|| finding.locations.first())?;
    Some(AnchorEntry {
        file: &location.file,
        line: location.line,
        // `as_deref` turns the `&Option<String>` into an `Option<&str>`.
        scope: location.scope.as_deref(),
    })
}

/// Whether `location`'s `kind` is exactly `sink`, as core reads it.
fn is_sink(location: &Location) -> bool {
    location.kind.as_ref().and_then(LocationKind::as_known) == Some(KnownLocationKind::Sink)
}

/// `merged.json` of `bounty`: `grouped`'s merged report, trusted content
/// only.
fn merged_file(bounty: BountyRef, grouped: &FindingGroups) -> MergedFile<'_> {
    MergedFile {
        schema_version: SchemaVersion::CURRENT,
        bounty,
        groups: grouped
            .merged()
            .iter()
            .map(|group| merged_entry(grouped, group))
            .collect(),
    }
}

/// `group`, one of `grouped`'s merged groups, as `merged.json` writes it.
// `group` is borrowed for this call alone (its lifetime is left unnamed),
// while the entry keeps only `'g` borrows of what `grouped` holds. So the
// entry may outlive `group`, which lives only until `merged_file`'s
// `collect` is done.
fn merged_entry<'g>(grouped: &'g FindingGroups, group: &MergedGroup<'g>) -> MergedEntry<'g> {
    MergedEntry {
        reported_by: group.reported_by(),
        findings: group
            .findings()
            .iter()
            .filter_map(|merged| {
                // `merged()` holds trusted sweeps' findings alone; checked
                // again here, where they are written, so this file never
                // takes a stranger's content whatever the groups say.
                let sweep = grouped
                    .sweeps()
                    .get(merged.member.sweep)
                    .filter(|sweep| sweep.trusted)?;
                Some(MergedFindingEntry {
                    sweep: sweep.sweep,
                    index: merged.member.finding,
                    finding: merged.finding,
                })
            })
            .collect(),
    }
}

/// Writes `value` as compact JSON to `name` in the bounty directory `dir`,
/// 0600, at most [`MAX_TRIAGE_FILE_BYTES`].
fn write_file<T: Serialize>(dir: &Path, name: &str, value: &T) -> anyhow::Result<()> {
    let path = dir.join(name);
    // The bytes are in a `Zeroizing` buffer, wiped when it goes out of scope
    // at the end of this function, once they are written.
    let Some(json) = compact_json(value, MAX_TRIAGE_FILE_BYTES)? else {
        bail!(
            "{} would be more than the {MAX_TRIAGE_FILE_BYTES} bytes pull writes of it, so it \
             was not written",
            path.display()
        );
    };
    write_private_file(&path, &json)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use serde_json::{Value, json};
    use sweepky_core::paths;
    use sweepky_core::{
        BountyRef, Circle, Findings, KnownSweepStatus, Manifest, Pubky, Sweep, SweepPackage,
        SweepRef, TrustLabel, parse_audit_findings,
    };
    use tempfile::TempDir;

    use super::{
        Caps, GROUPS_FILE, MAX_TRIAGE_FILE_BYTES, MERGED_FILE, Triaged, triage_bounties,
        triage_within,
    };
    use crate::Dirs;
    use crate::private_fs::read_private_file;
    use crate::pull::resolve::Homeservers;
    use crate::pull::roster::{RosterPoll, poll_roster};
    use crate::pull::state::{PollState, SweepSummary};
    use crate::pull::store::{CompactFindings, Placement, store_sweep};
    use crate::test_support::{
        FakeHomeservers, FakePublicRecords, PLANTED, SYNTHETIC_SHA, bounty_json, circle_json,
        dirs_in, json_bytes, mode, private_temp, random_pubky, record_id, repo_target_json,
        sweep_json,
    };

    /// `fixtures/cloudflare/findings.json`: B's findings, in Cloudflare's
    /// format.
    const CLOUDFLARE_FINDINGS: &[u8] =
        include_bytes!("../../../../fixtures/cloudflare/findings.json");
    /// `fixtures/common/findings.json`: C's findings, in the common format.
    const COMMON_FINDINGS: &[u8] = include_bytes!("../../../../fixtures/common/findings.json");

    /// A, the owner and the roster's admin; B, a circle member; C, the
    /// stranger S3: the names `fixtures/README.md` gives them.
    const A: &str = "ybymzxgk1zd3a7dm3i15gcuq7ewqkbimft6r1n8oc9o6uay8mqfo";
    const B: &str = "btyoe954e99wb6sp7csdipt9ki8ca3iyus1tfi3171zqdixb5csy";
    const C: &str = "qwujy4epafpmfei7bxn8fccfm1shzqp516sbenxi7qr6gua4n77o";

    /// The shared location's ids: Cloudflare's record and the common one.
    const B_EXPIRY: &str = "auth-expiry-inclusive";
    const C_EXPIRY: &str = "session-expiry-off-by-one";
    /// The id both fixtures use, at unrelated sinks.
    const SHARED_ID: &str = "auth-token-compare-timing";

    fn pubky(text: &str) -> Pubky {
        text.parse().expect("a pubky")
    }

    /// B's findings: the Cloudflare fixture, converted as `submit` converts
    /// it.
    fn b_findings() -> Findings {
        let playbook = "cloudflare/security-audit@c1c8a8c".parse().expect("a name");
        parse_audit_findings(CLOUDFLARE_FINDINGS, &playbook)
            .expect("converted")
            .0
    }

    /// C's findings: the common fixture, as written.
    fn c_findings() -> Findings {
        Findings::from_json(COMMON_FINDINGS).expect("findings")
    }

    /// One short finding, with [`PLANTED`] in its title and its anchor's
    /// scope: the smallest copy the tests store.
    fn planted_findings() -> Findings {
        let document = json!({
            "schemaVersion": 1,
            "playbook": "careful-review",
            "findings": [{
                "id": "p",
                "title": PLANTED,
                "status": "needs_validation",
                "locations": [{ "file": "src/p.rs", "line": 1, "scope": PLANTED }],
                "description": "",
            }],
        });
        Findings::from_json(&json_bytes(&document)).expect("findings")
    }

    /// Where the finding with id `id` is in `findings`: the one with it.
    fn index_of(findings: &Findings, id: &str) -> usize {
        let mut found = findings
            .findings
            .iter()
            .enumerate()
            .filter(|(_, finding)| finding.id == id);
        let (index, _) = found.next().expect("a finding with the id");
        assert!(found.next().is_none(), "two findings with id {id}");
        index
    }

    /// A's install: its data directory, its bounty, its roster and the poll
    /// state `pull::open` would have left once it stored each sweep.
    struct Fixture {
        // Kept so the directory lives as long as the fixture.
        _home: TempDir,
        dirs: Dirs,
        bounty: BountyRef,
        /// The roster: A's circle of A and B.
        roster: Circle,
        state: PollState,
    }

    impl Fixture {
        fn new() -> Self {
            let home = private_temp();
            let dirs = dirs_in(&home);
            let bounty = BountyRef {
                owner: pubky(A),
                id: record_id(1),
            };
            let roster =
                Circle::from_json(&json_bytes(&circle_json(pubky(A), &[pubky(A), pubky(B)])))
                    .expect("a circle");
            Self {
                _home: home,
                dirs,
                bounty,
                roster,
                state: PollState::default(),
            }
        }

        /// Stores `findings` as `sweeper`'s done sweep `n` of the bounty, as
        /// `pull::open` does once it opened it: the circle's among the
        /// trusted, anyone else's in `untrusted/`, and summarised as pulled.
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
            let placement = if self.roster.is_in_roster(sweeper) {
                Placement::Trusted
            } else {
                Placement::Untrusted
            };
            store_sweep(&self.dirs, self.bounty, sweep, placement, compact, files).expect("stored");
            let mut record = sweep_json(self.bounty, &["t1"], "done");
            record["finishedAt"] = json!("2026-10-19T10:00:00Z");
            let parsed = Sweep::from_json(&json_bytes(&record)).expect("a sweep");
            let mut summary = SweepSummary::new(&parsed, None);
            summary.pulled = true;
            self.state.sweeps.insert(sweep, summary);
            sweep
        }

        /// What the roster poll hands on: the roster, the owner's bounty,
        /// and no credits.
        fn poll(&self) -> RosterPoll {
            RosterPoll {
                roster: self.roster.clone(),
                own_bounties: vec![self.bounty],
                sweeps: Vec::new(),
                credited: Vec::new(),
                warnings: Vec::new(),
            }
        }

        /// One run's triage, with the run's caps.
        fn triage(&self) -> Triaged {
            triage_bounties(&self.dirs, &self.poll(), &self.state).expect("triaged")
        }

        /// One run's triage, within `caps`.
        fn triage_within(&self, caps: Caps) -> Triaged {
            triage_within(&self.dirs, &self.poll(), &self.state, caps).expect("triaged")
        }

        /// The path of `name` in the bounty's directory.
        fn path(&self, name: &str) -> PathBuf {
            self.dirs.pulled_bounty_dir(&self.bounty.id).join(name)
        }

        /// `name`'s bytes, read back as every private file is, within the
        /// triage files' cap.
        fn bytes(&self, name: &str) -> Vec<u8> {
            read_private_file(&self.path(name), MAX_TRIAGE_FILE_BYTES)
                .expect("readable")
                .expect("written")
                .to_vec()
        }

        /// `name`, read back and parsed.
        fn json(&self, name: &str) -> Value {
            serde_json::from_slice(&self.bytes(name)).expect("JSON")
        }
    }

    /// The member entry `groups.json` writes for finding `index` of `sweep`,
    /// anchored at `file`, `line` and `scope`.
    fn member(sweep: SweepRef, index: usize, file: &str, line: u64, scope: &str) -> Value {
        json!({
            "sweep": sweep.to_string(),
            "index": index,
            "anchor": { "file": file, "line": line, "scope": scope },
        })
    }

    /// The one group of `file` (`groups.json` or `merged.json`) whose
    /// entries under `key` hold finding `index` of `sweep`.
    fn group_holding<'v>(file: &'v Value, key: &str, sweep: SweepRef, index: usize) -> &'v Value {
        let url = json!(sweep.to_string());
        let mut holding = file["groups"]
            .as_array()
            .expect("groups")
            .iter()
            .filter(|group| {
                group[key]
                    .as_array()
                    .expect("entries")
                    .iter()
                    .any(|entry| entry["sweep"] == url && entry["index"] == json!(index))
            });
        let group = holding.next().expect("a group holding it");
        assert!(holding.next().is_none(), "two groups hold it");
        group
    }

    /// The `groups.json` entry of `sweep`.
    fn sweep_entry(
        sweep: SweepRef,
        label: &str,
        bounties: u64,
        owners: u64,
        trusted: bool,
    ) -> Value {
        json!({
            "sweep": sweep.to_string(),
            "label": label,
            "bounties": bounties,
            "owners": owners,
            "trusted": trusted,
        })
    }

    /// The sweeps `groups.json` lists, in its order.
    fn listed_sweeps(groups: &Value) -> Vec<String> {
        groups["sweeps"]
            .as_array()
            .expect("sweeps")
            .iter()
            .map(|entry| entry["sweep"].as_str().expect("a URL").to_owned())
            .collect()
    }

    #[test]
    fn cloudflare_and_common_format_sweeps_group_the_shared_location_and_keep_the_shared_id_pair_apart()
     {
        let mut fx = Fixture::new();
        // B's sweep first, so B is first in upload order.
        let b = fx.store(pubky(B), 10, b_findings());
        let c = fx.store(pubky(C), 11, c_findings());

        fx.triage();
        let groups = fx.json(GROUPS_FILE);

        // The shared location is one group of B's finding and C's, both
        // anchored at its sink, reported by B and C in upload order.
        let (b_expiry, c_expiry) = (
            index_of(&b_findings(), B_EXPIRY),
            index_of(&c_findings(), C_EXPIRY),
        );
        let shared = group_holding(&groups, "members", b, b_expiry);
        let session = "src/auth/session.rs";
        assert_eq!(
            shared["members"],
            json!([
                member(b, b_expiry, session, 88, "fn is_expired"),
                member(c, c_expiry, session, 88, "fn is_expired"),
            ])
        );
        assert_eq!(shared["reportedBy"], json!([B, C]));

        // The shared-id pair stays two groups, each its sweeper's alone.
        let (b_timing, c_timing) = (
            index_of(&b_findings(), SHARED_ID),
            index_of(&c_findings(), SHARED_ID),
        );
        let b_group = group_holding(&groups, "members", b, b_timing);
        let c_group = group_holding(&groups, "members", c, c_timing);
        assert_eq!(
            b_group["members"],
            json!([member(b, b_timing, session, 120, "fn validate")])
        );
        assert_eq!(b_group["reportedBy"], json!([B]));
        assert_eq!(
            c_group["members"],
            json!([member(c, c_timing, "src/http.rs", 12, "fn header")])
        );
        assert_eq!(c_group["reportedBy"], json!([C]));

        // Every other finding is a group of its own: B's three and C's two
        // findings make four groups.
        assert_eq!(groups["groups"].as_array().expect("groups").len(), 4);
    }

    #[test]
    fn only_the_circle_s_content_enters_merged_json_and_strangers_are_still_attributed() {
        // A's circle is A and B: B is `circle` and trusted, C, a stranger,
        // `unknown` and untrusted.
        let mut fx = Fixture::new();
        let b = fx.store(pubky(B), 10, b_findings());
        let c = fx.store(pubky(C), 11, c_findings());

        let triaged = fx.triage();
        let groups = fx.json(GROUPS_FILE);
        let merged = fx.json(MERGED_FILE);

        assert_eq!(
            groups["sweeps"],
            json!([
                sweep_entry(b, "circle", 0, 0, true),
                sweep_entry(c, "unknown", 0, 0, false),
            ])
        );
        assert_eq!(triaged.bounties.len(), 1);
        assert_eq!(triaged.bounties[0].bounty, fx.bounty);
        let labels: Vec<(SweepRef, TrustLabel, bool)> = triaged.bounties[0]
            .sweeps
            .iter()
            .map(|labelled| (labelled.sweep, labelled.trust.label, labelled.trusted))
            .collect();
        assert_eq!(
            labels,
            [
                (b, TrustLabel::Circle, true),
                (c, TrustLabel::Unknown, false)
            ]
        );

        // Every finding merged is B's, exactly as B's sweep holds it, and
        // every one of B's findings is there.
        let b_all = b_findings();
        let mut merged_b = Vec::new();
        for group in merged["groups"].as_array().expect("groups") {
            for entry in group["findings"].as_array().expect("findings") {
                assert_eq!(entry["sweep"], json!(b.to_string()));
                let index =
                    usize::try_from(entry["index"].as_u64().expect("an index")).expect("fits");
                let expected = serde_json::to_value(&b_all.findings[index]).expect("JSON");
                assert_eq!(entry["finding"], expected);
                merged_b.push(index);
            }
        }
        merged_b.sort_unstable();
        assert_eq!(merged_b, (0..b_all.findings.len()).collect::<Vec<_>>());

        // Nothing of C's sweep is in merged.json: not its URL, and no title,
        // description or fix of C's.
        let merged_bytes = String::from_utf8(fx.bytes(MERGED_FILE)).expect("UTF-8");
        assert!(!merged_bytes.contains(&c.to_string()));
        for finding in &c_findings().findings {
            for text in [
                Some(&finding.title),
                Some(&finding.description),
                finding.fix.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                let written = serde_json::to_string(text).expect("JSON");
                assert!(!merged_bytes.contains(&written), "{written}");
            }
        }

        // Attribution still counts C: groups.json lists C among the shared
        // group's reporters, and so does the merged group, whose content is
        // B's alone.
        let b_expiry = index_of(&b_all, B_EXPIRY);
        let shared = group_holding(&groups, "members", b, b_expiry);
        assert_eq!(shared["reportedBy"], json!([B, C]));
        let merged_shared = group_holding(&merged, "findings", b, b_expiry);
        assert_eq!(merged_shared["reportedBy"], json!([B, C]));
        assert_eq!(
            merged_shared["findings"]
                .as_array()
                .expect("findings")
                .len(),
            1
        );
        // C's half of the shared-id pair, which only C reported, has no
        // group in merged.json.
        let c_timing = index_of(&c_findings(), SHARED_ID);
        assert_eq!(
            group_holding(&groups, "members", c, c_timing)["reportedBy"],
            json!([C])
        );
        assert_eq!(
            merged["groups"].as_array().expect("groups").len(),
            groups["groups"].as_array().expect("groups").len() - 1
        );
    }

    /// A's bounty record, done, crediting `credits`.
    fn done_bounty(credits: &[&str]) -> Value {
        let mut record = bounty_json(json!([repo_target_json("t1")]));
        record["status"] = json!("done");
        record["credits"] = json!(credits);
        record["doneAt"] = json!("2026-10-19T12:00:00Z");
        record
    }

    #[tokio::test]
    async fn after_a_s_bounty_is_done_crediting_b_and_c_c_is_known_and_a_self_credit_adds_nothing()
    {
        let mut fx = Fixture::new();
        // A's storage, as the roster poll reads it: A's circle of A and B,
        // and A's bounty, done, crediting B, C and A itself.
        let records = FakePublicRecords::default()
            .with_record(
                pubky(A),
                paths::circle(),
                &circle_json(pubky(A), &[pubky(A), pubky(B)]),
            )
            .with_record(
                pubky(A),
                &paths::bounty(fx.bounty.id),
                &done_bounty(&[B, C, A]),
            );
        let resolver = FakeHomeservers::default();
        // Two runs: the bounty is in the poll state from the first, and
        // still counts once.
        let mut poll = None;
        for _ in 0..2 {
            let mut homeservers = Homeservers::new(&resolver);
            poll = Some(poll_roster(&records, &mut homeservers, pubky(A), &mut fx.state).await);
        }
        let poll = poll.expect("polled");
        assert!(poll.warnings.is_empty(), "{:?}", poll.warnings);
        // A swept its own bounty too.
        let a = fx.store(pubky(A), 10, planted_findings());
        let b = fx.store(pubky(B), 11, b_findings());
        let c = fx.store(pubky(C), 12, c_findings());

        triage_bounties(&fx.dirs, &poll, &fx.state).expect("triaged");
        let groups = fx.json(GROUPS_FILE);

        // C is `known`, credited on one bounty by one owner, and still
        // outside the circle, so untrusted. B's credit shows in B's tally.
        // A's credit to itself adds nothing.
        assert_eq!(
            groups["sweeps"],
            json!([
                sweep_entry(a, "circle", 0, 0, true),
                sweep_entry(b, "circle", 1, 1, true),
                sweep_entry(c, "known", 1, 1, false),
            ])
        );
    }

    #[test]
    fn an_aborted_sweep_is_left_out() {
        let mut fx = Fixture::new();
        let b = fx.store(pubky(B), 10, b_findings());
        let c = fx.store(pubky(C), 11, c_findings());
        // C's record was rewritten `aborted` after it was stored.
        fx.state.sweeps.get_mut(&c).expect("summarised").status = KnownSweepStatus::Aborted.into();

        let triaged = fx.triage();
        let groups = fx.json(GROUPS_FILE);

        assert_eq!(listed_sweeps(&groups), [b.to_string()]);
        assert_eq!(groups["leftOut"], json!([]));
        assert!(triaged.warnings.is_empty(), "{:?}", triaged.warnings);
        // B's three findings alone, each a group of its own.
        assert_eq!(groups["groups"].as_array().expect("groups").len(), 3);
    }

    /// Checks that nothing triage hands back, printed, holds a finding.
    fn assert_prints_no_finding(triaged: &Triaged) {
        let printed = format!("{triaged:?}");
        assert!(!printed.contains(PLANTED), "{printed}");
        for warning in &triaged.warnings {
            assert!(!warning.contains(PLANTED), "{warning}");
        }
    }

    #[test]
    fn sweeps_past_the_count_cap_are_left_out_with_a_warning_the_circle_s_first() {
        let mut fx = Fixture::new();
        let stranger = fx.store(pubky(C), 10, c_findings());
        let member = fx.store(pubky(B), 11, b_findings());
        let later = fx.store(random_pubky(), 12, planted_findings());

        let triaged = fx.triage_within(Caps {
            sweeps: 2,
            bytes: usize::MAX,
        });
        let groups = fx.json(GROUPS_FILE);

        // The circle's sweep is taken first, then the strangers' oldest
        // first, and the two grouped are listed in upload order.
        assert_eq!(
            listed_sweeps(&groups),
            [stranger.to_string(), member.to_string()]
        );
        assert_eq!(groups["leftOut"], json!([later.to_string()]));
        assert_eq!(triaged.warnings.len(), 1, "{:?}", triaged.warnings);
        assert!(
            triaged.warnings[0].contains("at most 2"),
            "{:?}",
            triaged.warnings
        );
        assert_prints_no_finding(&triaged);
    }

    #[test]
    fn a_sweep_past_the_byte_budget_is_left_out_with_a_warning_and_a_smaller_one_still_fits() {
        let mut fx = Fixture::new();
        let stranger = fx.store(pubky(C), 10, c_findings());
        let member = fx.store(pubky(B), 11, b_findings());
        let small = fx.store(random_pubky(), 12, planted_findings());
        // The compact copy is serde_json's compact form: room for B's and
        // the small one, not C's.
        let len = |findings: &Findings| serde_json::to_vec(findings).expect("JSON").len();
        let budget = len(&b_findings()) + len(&planted_findings());
        assert!(len(&c_findings()) > len(&planted_findings()));

        let triaged = fx.triage_within(Caps {
            sweeps: 64,
            bytes: budget,
        });
        let groups = fx.json(GROUPS_FILE);

        assert_eq!(
            listed_sweeps(&groups),
            [member.to_string(), small.to_string()]
        );
        assert_eq!(groups["leftOut"], json!([stranger.to_string()]));
        assert_eq!(triaged.warnings.len(), 1, "{:?}", triaged.warnings);
        let warning = &triaged.warnings[0];
        assert!(warning.contains(&stranger.to_string()), "{warning}");
        assert!(warning.contains(&budget.to_string()), "{warning}");
        assert_prints_no_finding(&triaged);
    }

    #[test]
    fn the_files_are_owner_only_the_same_every_run_and_read_back_within_their_caps() {
        let mut fx = Fixture::new();
        fx.store(pubky(B), 10, b_findings());
        fx.store(pubky(C), 11, c_findings());

        fx.triage();
        let first = (fx.bytes(GROUPS_FILE), fx.bytes(MERGED_FILE));
        fx.triage();
        let second = (fx.bytes(GROUPS_FILE), fx.bytes(MERGED_FILE));

        assert_eq!(first, second);
        for name in [GROUPS_FILE, MERGED_FILE] {
            assert_eq!(mode(&fx.path(name)), 0o600, "{name}");
            // `bytes` read it within its cap; it parses back.
            let _ = fx.json(name);
        }
    }

    #[test]
    fn a_bounty_directory_of_another_owner_gets_no_triage_files() {
        let mut fx = Fixture::new();
        fx.store(pubky(B), 10, b_findings());
        // Another owner's bounty with the same id, on the same data
        // directory, whose poll state says B's sweep is stored for it.
        let other = BountyRef {
            owner: random_pubky(),
            id: fx.bounty.id,
        };
        let mut poll = fx.poll();
        poll.own_bounties = vec![other];
        for summary in fx.state.sweeps.values_mut() {
            summary.bounty = other;
        }

        let error = triage_bounties(&fx.dirs, &poll, &fx.state).expect_err("refused");

        assert!(format!("{error:#}").contains("another owner"), "{error:#}");
        assert!(!fx.path(GROUPS_FILE).exists() && !fx.path(MERGED_FILE).exists());
    }
}
