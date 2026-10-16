//! Finding groups: the findings of several sweeps, grouped by the place in the
//! code they point at, with every sweeper who reported each group; the merged
//! report's content, from trusted sweeps only; and the credits `done`
//! proposes.
//!
//! The rules are on [`group_findings`], [`FindingGroups::merged`] and
//! [`FindingGroups::propose_credits`], because this module is private and
//! only the re-exported items appear in the crate's docs. The `matching`
//! module finds each finding's anchor and joins the findings that match, into
//! the sets of `disjoint_sets`; this one turns those sets into groups.

use std::collections::{HashMap, HashSet};

use crate::findings::{Finding, Findings};
use crate::pubky::Pubky;
use crate::url::SweepRef;

mod disjoint_sets;
mod matching;

use disjoint_sets::DisjointSets;
use matching::{Anchor, join_by_id, join_by_location};

/// How many lines apart two anchors in one file may be and still group, when
/// the scope cannot decide: lines `l` and `m` match when `|l - m|` is at most
/// this.
///
/// Small on purpose. Two playbooks rarely agree on the exact line of one bug,
/// but a wide window would chain the findings of a busy file into one group.
/// Grouping is a heuristic the owner confirms or splits either way.
pub const LINE_WINDOW: u64 = 5;

/// One decrypted sweep, as [`group_findings`] takes it: which sweep it is,
/// whether its content may enter the merged report, and its findings.
// `Debug` is derived: `SweepRef` and `bool` are public data, and `Findings`'
// own `Debug` is the redacted one that prints counts only, so no derived
// `Debug` here or on the types that hold this one prints a string an agent
// wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepFindings {
    /// The sweep, from the path its record and package were fetched from.
    /// Its `sweeper` is who gets the attribution: [`Manifest::check_binding`]
    /// has already tied it to the manifest inside the package.
    ///
    /// [`Manifest::check_binding`]: crate::Manifest::check_binding
    pub sweep: SweepRef,
    /// Whether the sweep's content may enter the owner's merged report
    /// (01, "Attribution and content are two different steps"). Only
    /// [`FindingGroups::merged`] reads it, to leave an untrusted sweep's
    /// findings out. Grouping, `reported_by` and
    /// [`FindingGroups::propose_credits`] do not: an untrusted sweep groups,
    /// and is attributed, like any other.
    pub trusted: bool,
    /// The sweep's findings, exactly as decrypted.
    pub findings: Findings,
}

/// Where a grouped finding is: the index of its sweep in
/// [`FindingGroups::sweeps`], and of the finding in that sweep's
/// `findings.findings`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupMember {
    /// The sweep's index, in upload order.
    pub sweep: usize,
    /// The finding's index within its sweep.
    pub finding: usize,
}

/// One group: findings from one or more sweeps that point at the same place.
// The fields are private, so a group can only come from `group_findings`,
// and its members always point into the sweeps beside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingGroup {
    reported_by: Vec<Pubky>,
    members: Vec<GroupMember>,
}

impl FindingGroup {
    /// Every sweeper who reported a finding in this group, each once, in
    /// upload order (by the first of their sweeps with a finding here): 01's
    /// `reportedBy`. A sweeper with two sweeps, or two findings in the group,
    /// appears once. Trusted or not, every sweep counts.
    pub fn reported_by(&self) -> &[Pubky] {
        &self.reported_by
    }

    /// The group's findings, at least one, in upload order: by sweep, then
    /// by their order in the sweep.
    pub fn members(&self) -> &[GroupMember] {
        &self.members
    }
}

/// The sweeps given to [`group_findings`], unchanged, and the groups their
/// findings form.
///
/// Every finding of every sweep is a member of exactly one group, so nothing
/// is dropped: a finding nothing else matches is a group of its own. The
/// groups come in the order of their first member, which makes the result the
/// same on every run for the same input.
///
/// [`merged`](Self::merged) gives the merged report's content, from trusted
/// sweeps only, and [`propose_credits`](Self::propose_credits) the credits
/// `sweepky done` proposes, from every sweep.
///
/// **Local only.** Groups say which sweepers reported the same place, which
/// is sealed content: nothing here goes into a public record. That is why
/// this type has no `Serialize`; the CLI's local triage files (P2c) get a
/// shape of their own. Its `Debug` prints the sweeps through the redacted
/// `Debug` of [`Findings`], so it shows the sweep references, the trusted
/// flags, the reporters and the member indices, but no string an agent wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingGroups {
    sweeps: Vec<SweepFindings>,
    groups: Vec<FindingGroup>,
}

impl FindingGroups {
    /// The sweeps, exactly as they were passed in, in upload order. Every
    /// raw record is here, under its sweep.
    pub fn sweeps(&self) -> &[SweepFindings] {
        &self.sweeps
    }

    /// The groups, in the order of their first member.
    pub fn groups(&self) -> &[FindingGroup] {
        &self.groups
    }

    /// The finding `member` points at, or `None` when it points at none. A
    /// member taken from [`groups`](Self::groups) always points at one;
    /// `None` is for one built by hand.
    // `get` returns an `Option` where `[i]` would panic on a bad index, and
    // `and_then` chains the second lookup onto the first.
    pub fn finding(&self, member: GroupMember) -> Option<&Finding> {
        self.sweeps
            .get(member.sweep)
            .and_then(|sweep| sweep.findings.findings.get(member.finding))
    }

    /// The groups of the owner's merged report: each group's findings from
    /// trusted sweeps only, in the order of [`groups`](Self::groups), with
    /// every group that no trusted sweep reported left out. That is 01's
    /// "Attribution and content are two different steps" and 02's
    /// "Untrusted reports are data": a stranger's findings never enter the
    /// merged report.
    ///
    /// Only the content is filtered. A merged group's
    /// [`reported_by`](MergedGroup::reported_by) is the whole group's,
    /// untrusted sweepers included, because attribution counts every sweep.
    /// An untrusted sweep's findings are still under its sweep in
    /// [`sweeps`](Self::sweeps), where `pull` (P2c) finds what it writes to
    /// `untrusted/` for the owner's agent to summarise without applying.
    ///
    /// Grouping reads no trusted flag, so an untrusted finding can still have
    /// joined two trusted ones into one group (single linkage, see
    /// [`group_findings`]); the owner confirms or splits the groups.
    // `'_` in the return type is the borrow of `self`: the merged groups
    // point into this `FindingGroups`, so they cannot outlive it, and
    // building them copies no finding.
    pub fn merged(&self) -> Vec<MergedGroup<'_>> {
        self.groups
            .iter()
            .filter_map(|group| self.merged_group(group))
            .collect()
    }

    /// `group` with its findings from trusted sweeps only and all its
    /// reporters, or `None` when no trusted sweep reported it: such a group
    /// has no content to merge.
    // One named lifetime for both borrows: the result points at `group`'s
    // reporters and at findings inside `self`, so it may live only as long
    // as both. Elision alone would tie the result to `self` and refuse
    // `&group.reported_by`, a borrow the compiler cannot see is as long.
    fn merged_group<'a>(&'a self, group: &'a FindingGroup) -> Option<MergedGroup<'a>> {
        let findings: Vec<MergedFinding<'a>> = group
            .members
            .iter()
            .filter_map(|&member| self.trusted_finding(member))
            .collect();
        if findings.is_empty() {
            return None;
        }
        Some(MergedGroup {
            reported_by: &group.reported_by,
            findings,
        })
    }

    /// The finding `member` points at, with the member, when its sweep is
    /// trusted; `None` for an untrusted sweep's finding.
    // The `?` on an `Option` returns `None` early, as on a `Result` it
    // returns the error. Members built by `group_findings` always point at a
    // finding, so the lookups give `None` only for an untrusted sweep, but a
    // lookup still never panics.
    fn trusted_finding(&self, member: GroupMember) -> Option<MergedFinding<'_>> {
        let sweep = self.sweeps.get(member.sweep)?;
        if !sweep.trusted {
            return None;
        }
        let finding = sweep.findings.findings.get(member.finding)?;
        Some(MergedFinding { member, finding })
    }

    /// The credits `sweepky done` proposes: every sweeper other than `owner`
    /// who contributed to at least one group, each once, in upload order (by
    /// the first of their sweeps with a finding, as in
    /// [`reported_by`](FindingGroup::reported_by)).
    ///
    /// - **Every sweep counts.** Trusted or not, and whatever their findings'
    ///   `status`, so a stranger who reported the same place as a circle
    ///   member is proposed with them (01), and so are two sweepers who
    ///   found the same issue.
    /// - **Never the owner.** An owner may sweep their own bounty, and their
    ///   findings group like anyone's, but 01's no-self-credit rule keeps
    ///   them out of the proposal. Sweepers are compared by their key bytes
    ///   ([`Pubky`]'s `==`), so `owner` is left out whichever of its two
    ///   spellings it was parsed from.
    /// - **Empty when nobody else helped.** A sweep with no findings is in no
    ///   group, so it proposes no one, and a bounty that only its owner
    ///   reported on gets an empty list, which
    ///   [`Bounty::mark_done`](crate::Bounty::mark_done) accepts.
    ///
    /// It is a proposal: the owner trims it, and `mark_done` refuses the
    /// owner whatever list it is given.
    pub fn propose_credits(&self, owner: Pubky) -> Vec<Pubky> {
        // A set beside the list, so each sweeper is added once without
        // searching the list each time.
        let mut proposed_already: HashSet<Pubky> = HashSet::new();
        let mut proposed: Vec<Pubky> = Vec::new();
        for sweep in &self.sweeps {
            // Every finding is in exactly one group (see `group_findings`),
            // so a sweep contributed to a group exactly when it has a
            // finding. Walking the sweeps rather than the groups keeps the
            // upload order: the groups come in the order of their first
            // member, which can put a later sweeper first.
            if sweep.findings.findings.is_empty() {
                continue;
            }
            let sweeper = sweep.sweep.sweeper;
            // `&&` stops at the first `false`, so `insert`, which records
            // the sweeper, runs only for someone other than the owner.
            if sweeper != owner && proposed_already.insert(sweeper) {
                proposed.push(sweeper);
            }
        }
        proposed
    }
}

/// One group of the owner's merged report, from [`FindingGroups::merged`]:
/// every sweeper who reported the group, and its findings from trusted sweeps
/// only, at least one.
// The fields are private, so a merged group can only come from `merged`,
// which is what filters its findings.
//
// The `'a` is the borrow of the `FindingGroups` this came from: a merged
// group points at the reporters and findings held there instead of copying
// them, and the compiler refuses any use of it once they are gone.
//
// `Debug` is derived: `Pubky` and `GroupMember` are public data, and each
// `&Finding` prints through the redacted `Debug` of `Finding`, counts only, so
// no derived `Debug` here prints a string an agent wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergedGroup<'a> {
    reported_by: &'a [Pubky],
    findings: Vec<MergedFinding<'a>>,
}

impl<'a> MergedGroup<'a> {
    /// Every sweeper who reported the group, trusted or not, each once, in
    /// upload order: the whole group's
    /// [`reported_by`](FindingGroup::reported_by). Attribution counts every
    /// sweep; only the findings below are filtered.
    // Returns `&'a`, the borrow of the `FindingGroups`, rather than a borrow
    // of this merged group, so the list may outlive the `MergedGroup`.
    pub fn reported_by(&self) -> &'a [Pubky] {
        self.reported_by
    }

    /// The group's findings from trusted sweeps, at least one, in upload
    /// order: by sweep, then by their order in the sweep.
    pub fn findings(&self) -> &[MergedFinding<'a>] {
        &self.findings
    }
}

/// A finding in the merged report, and where it is.
// `Copy`, since it is an index pair and a shared reference, both of which
// copy for free; the finding itself is never copied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MergedFinding<'a> {
    /// Where the finding is in [`FindingGroups::sweeps`]. Its sweep is
    /// trusted.
    pub member: GroupMember,
    /// The finding, exactly as decrypted.
    pub finding: &'a Finding,
}

/// Groups the findings of several sweeps by the place in the code they point
/// at (01, "The sweep package"). Pass the sweeps in upload order.
///
/// Finding ids are local to the sweep that wrote them, so two sweeps may name
/// one bug differently and different bugs alike. Grouping therefore goes by
/// location, and an equal id is only a hint for when location says nothing:
///
/// - **Anchor.** A finding's anchor is its first location whose `kind` is
///   exactly `sink`, or else its first location. A finding with no locations
///   has no anchor. Only the anchor is compared: two findings that share an
///   entrypoint but not a sink are two problems.
/// - **Normalising.** Files are compared exactly after one leading `./` is
///   stripped, and scopes exactly after leading and trailing ASCII whitespace
///   is trimmed; a scope that trims to nothing counts as no scope. Nothing
///   else is folded: not case, not other separators, not Unicode.
/// - **Matching.** Two anchors in different files never match. In one file,
///   when both give a scope, they match exactly when the scopes are equal,
///   however far apart their lines. Otherwise, when both give a line, they
///   match when the lines are at most [`LINE_WINDOW`] apart.
/// - **Equal ids.** When location cannot decide either way (a finding has no
///   anchor, or two anchors are in one file and give neither two scopes nor
///   two lines), findings whose ids are equal, exactly and not empty, match.
///   An equal id never matches a pair that location keeps apart.
/// - **Single linkage.** A group is everything connected by matches, so if
///   `a` matches `b` and `b` matches `c`, all three are one group even when
///   `a` and `c` do not match. A sink with a scope can join an unscoped line
///   above it and one below it, and a finding with no locations matches
///   every finding with its id, so it puts them all in one group, even ones
///   location keeps apart from each other. Grouping is a heuristic the owner
///   confirms or splits.
///
/// A finding's `status` is not read, so a `rejected` finding groups like any
/// other, and neither is the sweep's `trusted` flag. A group's
/// [`reported_by`](FindingGroup::reported_by) lists each sweeper once, in
/// upload order, trusted or not: attribution counts every sweep. The flag
/// decides only what [`FindingGroups::merged`] gives.
///
/// The strings compared are agent-written and untrusted. They are only
/// compared, never parsed, run or used as a path. The work is near-linear in
/// the number of findings (the findings are sorted into buckets by file and
/// by id rather than compared pair by pair), and nothing here panics, whatever
/// the input.
// The sweeps are taken by value, `Vec<SweepFindings>` rather than a slice,
// so the result can own them and hand them back unchanged: the caller needs
// the raw records beside the groups, and owning them means `FindingGroups`
// needs no lifetime parameter tying it to the caller's copy.
pub fn group_findings(sweeps: Vec<SweepFindings>) -> FindingGroups {
    // `entries` borrows the strings inside `sweeps`, and the groups built
    // from it hold only copies (`Pubky` and `GroupMember` are `Copy`). The
    // borrow ends at its last use, so `sweeps` can be moved into the result
    // below; the compiler checks that no reference into it is left.
    let entries = entries_in_upload_order(&sweeps);
    let mut sets = DisjointSets::new(entries.len());
    join_by_location(&entries, &mut sets);
    join_by_id(&entries, &mut sets);
    let groups = collect_groups(&entries, &mut sets);
    FindingGroups { sweeps, groups }
}

/// What grouping reads from one finding.
// The `'a` says each `&str` points into the `SweepFindings` the entry was
// made from, so an entry cannot outlive the sweeps it borrows.
struct Entry<'a> {
    member: GroupMember,
    sweeper: Pubky,
    id: &'a str,
    anchor: Option<Anchor<'a>>,
}

/// One entry per finding, in upload order: by sweep, then by finding.
fn entries_in_upload_order(sweeps: &[SweepFindings]) -> Vec<Entry<'_>> {
    // `enumerate` gives each item its index, so no index is ever looked up.
    // `flat_map` flattens each sweep's findings into one list, and `move`
    // copies `sweep_index` and the sweeper into the inner closure, which
    // outlives the outer closure's call.
    sweeps
        .iter()
        .enumerate()
        .flat_map(|(sweep_index, sweep)| {
            let sweeper = sweep.sweep.sweeper;
            sweep
                .findings
                .findings
                .iter()
                .enumerate()
                .map(move |(finding_index, finding)| Entry {
                    member: GroupMember {
                        sweep: sweep_index,
                        finding: finding_index,
                    },
                    sweeper,
                    id: &finding.id,
                    anchor: Anchor::of(finding),
                })
        })
        .collect()
}

/// The groups the joined sets form, in the order of their first member, each
/// with its members and reporters in upload order.
fn collect_groups(entries: &[Entry<'_>], sets: &mut DisjointSets) -> Vec<FindingGroup> {
    let mut group_of_root: HashMap<usize, usize> = HashMap::new();
    // Which sweepers each group already lists, so a sweeper is added once
    // without searching the list each time.
    let mut listed: HashSet<(usize, Pubky)> = HashSet::new();
    let mut groups: Vec<FindingGroup> = Vec::new();
    // Entries are in upload order, so walking them in order puts each group's
    // members in upload order, and the groups in the order of their first.
    for (index, entry) in entries.iter().enumerate() {
        let root = sets.find(index);
        let next = groups.len();
        let group_index = *group_of_root.entry(root).or_insert(next);
        if group_index == next {
            groups.push(FindingGroup {
                reported_by: Vec::new(),
                members: Vec::new(),
            });
        }
        // `get_mut` hands back `None` instead of panicking, though the group
        // was pushed just above if it was missing.
        if let Some(group) = groups.get_mut(group_index) {
            group.members.push(entry.member);
            // `insert` is true only the first time this pair is seen.
            if listed.insert((group_index, entry.sweeper)) {
                group.reported_by.push(entry.sweeper);
            }
        }
    }
    groups
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{FindingGroups, GroupMember, LINE_WINDOW, SweepFindings, group_findings};
    use crate::findings::test_support::{FIXTURE, playbook};
    use crate::findings::{Findings, parse_audit_findings};
    use crate::pubky::Pubky;
    use crate::url::SweepRef;

    /// The owner A, sweepers B and C of P2c's end-to-end test (the admin A,
    /// roster member B and the stranger S3 in fixtures/trust-labels.json),
    /// and roster member D.
    const A: &str = "ybymzxgk1zd3a7dm3i15gcuq7ewqkbimft6r1n8oc9o6uay8mqfo";
    const B: &str = "btyoe954e99wb6sp7csdipt9ki8ca3iyus1tfi3171zqdixb5csy";
    const C: &str = "qwujy4epafpmfei7bxn8fccfm1shzqp516sbenxi7qr6gua4n77o";
    const D: &str = "5ymaqd61szab6j1qmry9jfo6ft81echtzscdbfs9sq8p3temcyco";
    /// Sweep ids from fixtures/trust-labels.json.
    const ID1: &str = "0035G87EK4XFE";
    const ID2: &str = "0035JREYBXX7T";
    const ID3: &str = "0035M2DX3Q44W";

    fn pubky(text: &str) -> Pubky {
        text.parse().unwrap()
    }

    fn sweep_ref(sweeper: &str, id: &str) -> SweepRef {
        format!("pubky://{sweeper}/pub/sweepky/sweeps/{id}.json")
            .parse()
            .unwrap()
    }

    /// A location with each of `line`, `kind` and `scope` left out when
    /// `None`.
    fn location(file: &str, line: Option<u64>, kind: Option<&str>, scope: Option<&str>) -> Value {
        let mut location = json!({ "file": file });
        if let Some(line) = line {
            location["line"] = json!(line);
        }
        if let Some(kind) = kind {
            location["kind"] = json!(kind);
        }
        if let Some(scope) = scope {
            location["scope"] = json!(scope);
        }
        location
    }

    /// A sink at `file`, `line` and `scope`.
    fn sink(file: &str, line: u64, scope: &str) -> Value {
        location(file, Some(line), Some("sink"), Some(scope))
    }

    /// A sink at `file` with no scope.
    fn sink_at_line(file: &str, line: u64) -> Value {
        location(file, Some(line), Some("sink"), None)
    }

    /// A `needs_validation` finding with the id and locations given.
    fn finding(id: &str, locations: Vec<Value>) -> Value {
        json!({
            "id": id,
            "title": "A synthetic finding",
            "severity": null,
            "confidence": null,
            "status": "needs_validation",
            "locations": locations,
            "description": "Synthetic.",
        })
    }

    /// A common-format document holding `list`, read through the real parse.
    fn findings(list: Vec<Value>) -> Findings {
        let document = json!({
            "schemaVersion": 1,
            "playbook": "careful-review",
            "findings": list,
        });
        Findings::from_json(document.to_string().as_bytes()).unwrap()
    }

    /// A trusted sweep `id` by `sweeper` holding `list`.
    fn sweep(sweeper: &str, id: &str, list: Vec<Value>) -> SweepFindings {
        SweepFindings {
            sweep: sweep_ref(sweeper, id),
            trusted: true,
            findings: findings(list),
        }
    }

    /// Each group's members as `(sweep, finding)` pairs, in the result's
    /// order.
    fn member_sets(groups: &FindingGroups) -> Vec<Vec<(usize, usize)>> {
        groups
            .groups()
            .iter()
            .map(|group| {
                group
                    .members()
                    .iter()
                    .map(|member| (member.sweep, member.finding))
                    .collect()
            })
            .collect()
    }

    /// Each group's reporters, in the result's order.
    fn reporter_lists(groups: &FindingGroups) -> Vec<&[Pubky]> {
        groups
            .groups()
            .iter()
            .map(|group| group.reported_by())
            .collect()
    }

    /// The groups of one sweep's findings, as `member_sets` gives them.
    fn groups_of(list: Vec<Value>) -> Vec<Vec<(usize, usize)>> {
        member_sets(&group_findings(vec![sweep(B, ID1, list)]))
    }

    #[test]
    fn findings_at_one_file_and_scope_group_whatever_their_ids() {
        // DW1's shared location: two sweeps' sinks in one file and scope,
        // under different ids and at lines further apart than LINE_WINDOW, so
        // the scope decides, not the lines. The file compares after a leading
        // `./` is stripped, and the scope after ASCII whitespace is trimmed.
        let groups = group_findings(vec![
            sweep(
                B,
                ID1,
                vec![finding(
                    "auth-expiry-inclusive",
                    vec![sink("src/auth/session.rs", 88, "fn is_expired")],
                )],
            ),
            sweep(
                C,
                ID2,
                vec![finding(
                    "session-expiry-off-by-one",
                    vec![sink(
                        "./src/auth/session.rs",
                        88 + LINE_WINDOW + 40,
                        " fn is_expired\t",
                    )],
                )],
            ),
        ]);
        assert_eq!(member_sets(&groups), vec![vec![(0, 0), (1, 0)]]);
        let group = groups.groups().first().unwrap();
        assert_eq!(group.reported_by(), [pubky(B), pubky(C)]);
    }

    #[test]
    fn the_sink_anchors_a_finding_not_its_entrypoint() {
        // P1a's Cloudflare fixture: `auth-expiry-inclusive` and
        // `auth-token-compare-timing` share only their entrypoint,
        // `src/auth/handler.rs` line 18 in `fn handle_request`. Their sinks
        // are in one file but in different scopes, so they stay apart.
        let (cloudflare, _) = parse_audit_findings(FIXTURE.as_bytes(), &playbook()).unwrap();
        let position = |id: &str| {
            cloudflare
                .findings
                .iter()
                .position(|finding| finding.id == id)
                .unwrap()
        };
        let expiry = position("auth-expiry-inclusive");
        let timing = position("auth-token-compare-timing");
        for index in [expiry, timing] {
            let entrypoint = cloudflare.findings[index].locations.first().unwrap();
            assert_eq!(entrypoint.file, "src/auth/handler.rs");
            assert_eq!(entrypoint.line, Some(18));
            assert_eq!(entrypoint.kind.as_ref().unwrap().as_str(), "entrypoint");
        }
        let groups = group_findings(vec![SweepFindings {
            sweep: sweep_ref(B, ID1),
            trusted: true,
            findings: cloudflare,
        }]);
        // All three records stay alone, the two above among them.
        assert_eq!(
            member_sets(&groups),
            vec![vec![(0, 0)], vec![(0, 1)], vec![(0, 2)]]
        );
    }

    #[test]
    fn a_finding_without_a_sink_is_anchored_at_its_first_location() {
        // Whatever that location's kind: the first finding here groups with
        // the second at `src/a.rs` `fn first`, and not with the third at its
        // second location's `src/b.rs` `fn second`.
        assert_eq!(
            groups_of(vec![
                finding(
                    "no-sink",
                    vec![
                        location("src/a.rs", Some(10), Some("propagation"), Some("fn first")),
                        location("src/b.rs", Some(20), Some("entrypoint"), Some("fn second")),
                    ],
                ),
                finding("a", vec![sink("src/a.rs", 300, "fn first")]),
                finding("b", vec![sink("src/b.rs", 20, "fn second")]),
            ]),
            vec![vec![(0, 0), (0, 1)], vec![(0, 2)]]
        );
    }

    #[test]
    fn without_a_scope_nearby_lines_group_and_distant_lines_do_not() {
        // In one file with no scope, lines up to LINE_WINDOW apart group.
        assert_eq!(
            groups_of(vec![
                finding("a", vec![sink_at_line("src/a.rs", 100)]),
                finding("b", vec![sink_at_line("src/a.rs", 100 + LINE_WINDOW)]),
            ]),
            vec![vec![(0, 0), (0, 1)]]
        );
        // One line more and they split.
        assert_eq!(
            groups_of(vec![
                finding("a", vec![sink_at_line("src/a.rs", 100)]),
                finding("b", vec![sink_at_line("src/a.rs", 100 + LINE_WINDOW + 1)]),
            ]),
            vec![vec![(0, 0)], vec![(0, 1)]]
        );
    }

    #[test]
    fn different_scopes_split_even_at_close_lines() {
        assert_eq!(
            groups_of(vec![
                finding("a", vec![sink("src/a.rs", 100, "fn a")]),
                finding("b", vec![sink("src/a.rs", 101, "fn b")]),
            ]),
            vec![vec![(0, 0)], vec![(0, 1)]]
        );
    }

    #[test]
    fn a_scoped_sink_links_the_unscoped_lines_on_both_sides_of_it() {
        // When only one of two gives a scope, the lines decide. Grouping is
        // single linkage, so a scoped sink joins the unscoped ones on both
        // sides of it, which are themselves too far apart to group.
        assert_eq!(
            groups_of(vec![
                finding("below", vec![sink_at_line("src/a.rs", 100)]),
                finding("scoped", vec![sink("src/a.rs", 100 + LINE_WINDOW, "fn a")]),
                finding(
                    "above",
                    vec![sink_at_line("src/a.rs", 100 + 2 * LINE_WINDOW)]
                ),
                finding(
                    "far",
                    vec![sink_at_line("src/a.rs", 100 + 3 * LINE_WINDOW + 1)]
                ),
            ]),
            vec![vec![(0, 0), (0, 1), (0, 2)], vec![(0, 3)]]
        );
    }

    #[test]
    fn equal_ids_never_join_findings_at_unrelated_locations() {
        // DW1's shared-id pair: one id at sinks in different files.
        let groups = group_findings(vec![
            sweep(
                B,
                ID1,
                vec![finding(
                    "auth-token-compare-timing",
                    vec![sink("src/auth/session.rs", 120, "fn validate")],
                )],
            ),
            sweep(
                C,
                ID2,
                vec![finding(
                    "auth-token-compare-timing",
                    vec![sink("src/http.rs", 12, "fn header")],
                )],
            ),
        ]);
        assert_eq!(member_sets(&groups), vec![vec![(0, 0)], vec![(1, 0)]]);
        assert_eq!(reporter_lists(&groups), [[pubky(B)], [pubky(C)]]);

        // One id in one file, in different scopes, at close lines.
        assert_eq!(
            groups_of(vec![
                finding("same", vec![sink("src/a.rs", 10, "fn a")]),
                finding("same", vec![sink("src/a.rs", 11, "fn b")]),
            ]),
            vec![vec![(0, 0)], vec![(0, 1)]]
        );
        // One id in one file with no scopes, at distant lines.
        assert_eq!(
            groups_of(vec![
                finding("same", vec![sink_at_line("src/a.rs", 10)]),
                finding("same", vec![sink_at_line("src/a.rs", 10 + LINE_WINDOW + 1)]),
            ]),
            vec![vec![(0, 0)], vec![(0, 1)]]
        );
    }

    #[test]
    fn equal_ids_join_findings_whose_locations_cannot_decide() {
        // No locations at all: an equal id joins, another id stays alone.
        assert_eq!(
            groups_of(vec![
                finding("x", vec![]),
                finding("y", vec![]),
                finding("x", vec![]),
            ]),
            vec![vec![(0, 0), (0, 2)], vec![(0, 1)]]
        );
        // One file, with neither a scope nor a line.
        let bare = || location("src/a.rs", None, Some("sink"), None);
        assert_eq!(
            groups_of(vec![
                finding("x", vec![bare()]),
                finding("y", vec![bare()]),
                finding("x", vec![bare()]),
            ]),
            vec![vec![(0, 0), (0, 2)], vec![(0, 1)]]
        );
        // A finding with no locations cannot be told apart from one that has
        // them, so an equal id joins the two.
        assert_eq!(
            groups_of(vec![
                finding("x", vec![sink("src/a.rs", 10, "fn a")]),
                finding("x", vec![]),
                finding("y", vec![sink("src/a.rs", 10, "fn other")]),
            ]),
            vec![vec![(0, 0), (0, 1)], vec![(0, 2)]]
        );
        // A scope without a line beside a line without a scope: the scope
        // needs both to give one and the lines need both lines, so location
        // cannot decide, and an equal id joins them.
        assert_eq!(
            groups_of(vec![
                finding(
                    "x",
                    vec![location("src/a.rs", None, Some("sink"), Some("fn a"))]
                ),
                finding("x", vec![sink_at_line("src/a.rs", 10)]),
                finding("y", vec![sink_at_line("src/a.rs", 900)]),
            ]),
            vec![vec![(0, 0), (0, 1)], vec![(0, 2)]]
        );
        // An empty id gives no hint, so findings without locations and with
        // empty ids stay alone.
        assert_eq!(
            groups_of(vec![finding("", vec![]), finding("", vec![])]),
            vec![vec![(0, 0)], vec![(0, 1)]]
        );
    }

    #[test]
    fn reported_by_lists_each_sweeper_once_in_upload_order() {
        let shared = || finding("f", vec![sink("src/a.rs", 10, "fn a")]);
        // C uploads twice, B once in between and with two findings in the
        // group. B's sweep is untrusted, which changes nothing here:
        // attribution counts every sweep.
        let mut untrusted = sweep(B, ID2, vec![shared(), shared()]);
        untrusted.trusted = false;
        let groups = group_findings(vec![
            sweep(C, ID1, vec![shared()]),
            untrusted,
            sweep(C, ID3, vec![shared()]),
            sweep(D, ID1, vec![]),
        ]);
        assert_eq!(
            member_sets(&groups),
            vec![vec![(0, 0), (1, 0), (1, 1), (2, 0)]]
        );
        assert_eq!(groups.groups()[0].reported_by(), [pubky(C), pubky(B)]);

        // The order is the order the sweeps were passed in.
        let groups = group_findings(vec![
            sweep(D, ID1, vec![shared()]),
            sweep(B, ID2, vec![shared()]),
            sweep(C, ID3, vec![shared()]),
        ]);
        assert_eq!(
            groups.groups()[0].reported_by(),
            [pubky(D), pubky(B), pubky(C)]
        );
    }

    /// Three sweeps with shared and lone findings, a `rejected` one among
    /// them, and an empty sweep.
    fn mixed_sweeps() -> Vec<SweepFindings> {
        let mut rejected = finding("r", vec![sink("src/a.rs", 10, "fn a")]);
        rejected["status"] = json!("rejected");
        vec![
            sweep(
                B,
                ID1,
                vec![
                    finding("x", vec![sink("src/b.rs", 5, "fn b")]),
                    finding("y", vec![sink("src/a.rs", 99, "fn a")]),
                    finding("z", vec![]),
                ],
            ),
            sweep(C, ID2, vec![]),
            sweep(
                D,
                ID3,
                vec![
                    rejected,
                    finding("z", vec![]),
                    finding("w", vec![sink_at_line("src/c.rs", 1)]),
                ],
            ),
        ]
    }

    #[test]
    fn groups_come_in_the_order_of_their_first_member() {
        // Members come in input order. Status is ignored, so the rejected
        // finding groups with `y` at `fn a`.
        assert_eq!(
            member_sets(&group_findings(mixed_sweeps())),
            vec![
                vec![(0, 0)],
                vec![(0, 1), (2, 0)],
                vec![(0, 2), (2, 1)],
                vec![(2, 2)],
            ]
        );
    }

    #[test]
    fn every_raw_record_is_kept() {
        let input = mixed_sweeps();
        let groups = group_findings(input.clone());
        // Every (sweep, finding) pair is in exactly one group.
        let mut all: Vec<(usize, usize)> = member_sets(&groups).concat();
        all.sort_unstable();
        let expected: Vec<(usize, usize)> = input
            .iter()
            .enumerate()
            .flat_map(|(s, sweep)| (0..sweep.findings.findings.len()).map(move |f| (s, f)))
            .collect();
        assert_eq!(all, expected);
        // The sweeps come back unchanged, and every member reads its own
        // finding back.
        assert_eq!(groups.sweeps(), input.as_slice());
        for group in groups.groups() {
            for &member in group.members() {
                assert_eq!(
                    groups.finding(member),
                    Some(&input[member.sweep].findings.findings[member.finding])
                );
            }
        }
    }

    #[test]
    fn the_same_input_groups_the_same_way_every_time() {
        assert_eq!(
            group_findings(mixed_sweeps()),
            group_findings(mixed_sweeps())
        );
    }

    #[test]
    fn grouping_never_panics_on_odd_agent_input() {
        // Empty strings everywhere, a kind this build does not know (so the
        // first location anchors), lines at 0 and u64::MAX, and unicode
        // scopes, one of them padded with a no-break space, which is not
        // ASCII whitespace and stays.
        let odd = vec![
            finding("", vec![location("", Some(0), Some(""), Some(""))]),
            finding("", vec![location("", Some(u64::MAX), Some("SINK"), None)]),
            finding("e", vec![location("src/é.rs", Some(u64::MAX), None, None)]),
            finding(
                "e",
                vec![location(
                    "src/é.rs",
                    Some(u64::MAX - LINE_WINDOW),
                    None,
                    None,
                )],
            ),
            finding("u", vec![sink("src/é.rs", 1, "fn 名前 \u{202e}")]),
            finding("u", vec![sink("src/é.rs", 2, "\u{a0}fn 名前 \u{202e}")]),
            finding("u", vec![sink("src/é.rs", 3, "\tfn 名前 \u{202e} ")]),
        ];
        assert_eq!(
            groups_of(odd),
            vec![
                vec![(0, 0)],
                vec![(0, 1)],
                vec![(0, 2), (0, 3)],
                vec![(0, 4), (0, 6)],
                vec![(0, 5)],
            ]
        );
    }

    #[test]
    fn no_findings_make_no_groups() {
        // No sweeps, and sweeps with no findings, which are still kept.
        assert!(group_findings(vec![]).groups().is_empty());
        let empty = group_findings(vec![sweep(B, ID1, vec![]), sweep(C, ID2, vec![])]);
        assert!(empty.groups().is_empty());
        assert_eq!(empty.sweeps().len(), 2);
    }

    #[test]
    fn a_member_that_points_nowhere_reads_as_none() {
        let groups = group_findings(vec![sweep(B, ID1, vec![finding("x", vec![])])]);
        assert!(
            groups
                .finding(GroupMember {
                    sweep: usize::MAX,
                    finding: 0
                })
                .is_none()
        );
        assert!(
            groups
                .finding(GroupMember {
                    sweep: 0,
                    finding: 1
                })
                .is_none()
        );
    }

    #[test]
    fn thousands_of_findings_group_without_comparing_every_pair() {
        // On one line of one file they are one group; with no locations and
        // distinct ids, each is its own; with no locations and one id, they
        // are one.
        let many = 5_000;
        let one_line = (0..many)
            .map(|i| finding(&format!("f{i}"), vec![sink_at_line("src/a.rs", 7)]))
            .collect();
        assert_eq!(groups_of(one_line).len(), 1);
        let distinct = (0..many)
            .map(|i| finding(&format!("f{i}"), vec![]))
            .collect();
        assert_eq!(groups_of(distinct).len(), many);
        let one_id = (0..many).map(|_| finding("same", vec![])).collect();
        assert_eq!(groups_of(one_id).len(), 1);
    }

    #[test]
    fn debug_prints_no_finding_content() {
        // FindingGroups' Debug goes through the redacted Debug of Findings,
        // so no id, file, scope or title an agent wrote shows.
        let groups = group_findings(vec![sweep(
            B,
            ID1,
            vec![finding(
                "secret-id",
                vec![sink("src/secret.rs", 4242, "fn secret")],
            )],
        )]);
        // The merged output's Debug goes through the same redacted Debug of
        // each `Finding` it holds.
        for printed in [format!("{groups:?}"), format!("{:?}", groups.merged())] {
            for content in ["secret", "4242", "A synthetic finding", "Synthetic."] {
                assert!(!printed.contains(content), "{content} printed");
            }
        }
    }

    #[test]
    fn a_bounty_nobody_else_helped_with_proposes_no_one() {
        // Only the owner A reported anything: B's sweep has no findings, so
        // B contributed to no group.
        let owner_only = group_findings(vec![
            sweep(B, ID1, vec![]),
            sweep(
                A,
                ID2,
                vec![finding("f", vec![sink("src/a.rs", 10, "fn a")])],
            ),
        ]);
        assert_eq!(owner_only.groups().len(), 1);
        assert!(owner_only.propose_credits(pubky(A)).is_empty());
        // No sweep has findings, or there are no sweeps at all.
        let empty = group_findings(vec![sweep(B, ID1, vec![]), sweep(C, ID2, vec![])]);
        assert!(empty.propose_credits(pubky(A)).is_empty());
        assert!(group_findings(vec![]).propose_credits(pubky(A)).is_empty());
    }

    #[test]
    fn propose_credits_lists_each_contributor_once_in_upload_order() {
        // B and D report `x`, and C and B report `y`. The groups come in the
        // order of their first member, so their reporters read B, D, C; the
        // credits come in upload order, by each sweeper's first sweep with a
        // finding, so C's empty first sweep does not put C first. C's second
        // sweep is untrusted, and C is proposed all the same.
        let x = || finding("x", vec![sink("src/a.rs", 10, "fn x")]);
        let y = || finding("y", vec![sink("src/b.rs", 10, "fn y")]);
        let mut untrusted = sweep(C, ID3, vec![y()]);
        untrusted.trusted = false;
        let groups = group_findings(vec![
            sweep(C, ID1, vec![]),
            sweep(B, ID2, vec![x()]),
            untrusted,
            sweep(D, ID1, vec![x()]),
            sweep(B, ID3, vec![y()]),
        ]);
        assert_eq!(
            reporter_lists(&groups),
            [[pubky(B), pubky(D)], [pubky(C), pubky(B)]]
        );
        assert_eq!(
            groups.propose_credits(pubky(A)),
            [pubky(B), pubky(C), pubky(D)]
        );
    }

    /// A finding's anchor as the reference rule below reads it: the file,
    /// the scope and the line, normalised the way grouping compares them.
    struct ReferenceAnchor {
        file: String,
        scope: Option<String>,
        line: Option<u64>,
    }

    /// The anchor of a finding written as JSON: its first sink, else its
    /// first location.
    fn reference_anchor(finding: &Value) -> Option<ReferenceAnchor> {
        let locations = finding["locations"].as_array().unwrap();
        let anchor = locations
            .iter()
            .find(|location| location["kind"] == "sink")
            .or(locations.first())?;
        let file = anchor["file"].as_str().unwrap();
        Some(ReferenceAnchor {
            file: file.strip_prefix("./").unwrap_or(file).to_owned(),
            scope: anchor["scope"]
                .as_str()
                .map(|scope| scope.trim_ascii().to_owned())
                .filter(|scope| !scope.is_empty()),
            line: anchor["line"].as_u64(),
        })
    }

    /// The pairwise rule the bucketed grouping implements: `Some(true)` when
    /// two anchors match, `Some(false)` when location keeps them apart, and
    /// `None` when location cannot decide either way.
    fn reference_match(a: Option<&ReferenceAnchor>, b: Option<&ReferenceAnchor>) -> Option<bool> {
        let (a, b) = (a?, b?);
        if a.file != b.file {
            return Some(false);
        }
        if let (Some(scope_a), Some(scope_b)) = (&a.scope, &b.scope) {
            return Some(scope_a == scope_b);
        }
        match (a.line, b.line) {
            (Some(line_a), Some(line_b)) => Some(line_a.abs_diff(line_b) <= LINE_WINDOW),
            _ => None,
        }
    }

    /// The groups of `list` built the slow way: single linkage over every
    /// pair, by the pairwise rule, with equal non-empty ids joining the pairs
    /// it cannot decide. Every finding takes the smallest label among those
    /// it joins until nothing changes, so each ends up holding the first
    /// index of its group.
    fn reference_groups(list: &[Value]) -> Vec<Vec<(usize, usize)>> {
        let anchors: Vec<Option<ReferenceAnchor>> = list.iter().map(reference_anchor).collect();
        let len = list.len();
        let mut label: Vec<usize> = (0..len).collect();
        loop {
            let mut changed = false;
            for i in 0..len {
                for j in 0..len {
                    let joined = match reference_match(anchors[i].as_ref(), anchors[j].as_ref()) {
                        Some(matched) => matched,
                        None => list[i]["id"] != "" && list[i]["id"] == list[j]["id"],
                    };
                    if joined && label[j] < label[i] {
                        label[i] = label[j];
                        changed = true;
                    }
                }
            }
            if !changed {
                break;
            }
        }
        // Groups in the order of their first member, as the result has them.
        let mut groups: Vec<Vec<(usize, usize)>> = Vec::new();
        let mut firsts: Vec<usize> = Vec::new();
        for (i, &first) in label.iter().enumerate() {
            match firsts.iter().position(|&seen| seen == first) {
                Some(group) => groups[group].push((0, i)),
                None => {
                    firsts.push(first);
                    groups.push(vec![(0, i)]);
                }
            }
        }
        groups
    }

    #[test]
    fn bucketed_grouping_matches_the_pairwise_rule() {
        // The real code buckets by file and by id to stay near-linear. This
        // checks it against `reference_groups` on many small, sparse,
        // deterministic pseudo-random lists: small enough that most findings
        // are not joined through some other path, so a pair the buckets
        // missed shows up as a split group.
        let mut state: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = |bound: usize| -> usize {
            // xorshift64: deterministic, and enough to mix the cases.
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % bound as u64) as usize
        };
        let files = ["src/a.rs", "./src/a.rs", "src/b.rs"];
        let scopes = [None, Some("fn a"), Some(" fn a"), Some("fn b"), Some(" ")];
        let ids = ["x", "y", "z", ""];
        let kinds = [None, Some("sink"), Some("entrypoint")];
        let (mut shared, mut lone) = (0, 0);
        for _ in 0..500 {
            let mut list: Vec<Value> = Vec::new();
            for _ in 0..2 + next(8) {
                let mut locations = Vec::new();
                for _ in 0..next(3) {
                    let line = match next(3) {
                        0 => None,
                        _ => Some(next(30) as u64),
                    };
                    locations.push(location(
                        files[next(files.len())],
                        line,
                        kinds[next(kinds.len())],
                        scopes[next(scopes.len())],
                    ));
                }
                list.push(finding(ids[next(ids.len())], locations));
            }
            let expected = reference_groups(&list);
            shared += expected.iter().filter(|group| group.len() > 1).count();
            lone += expected.iter().filter(|group| group.len() == 1).count();
            assert_eq!(groups_of(list), expected);
        }
        // The mix has both shared and lone findings, so the check means
        // something.
        assert!(shared > 100 && lone > 100, "{shared} shared, {lone} lone");
    }
}
