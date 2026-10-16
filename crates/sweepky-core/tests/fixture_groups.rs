//! P1b's grouping Done-when, on the findings of the two synthetic run
//! directories under `fixtures/`: the shared location is one group with both
//! reporters, the shared-id pair stays apart, `propose_credits` names both
//! sweepers and never the owner, and an untrusted sweep is attributed but not
//! merged.
//!
//! - B, a circle member, submitted `fixtures/cloudflare/findings.json`, in
//!   Cloudflare's format, converted here the way `submit` converts it.
//! - C, the stranger S3, submitted `fixtures/common/findings.json`, in the
//!   common format.
//! - A, the bounty's owner, also swept their own bounty. A's sweep is built
//!   in code: one finding at the shared location, under an id of its own.
//!
//! The pubkys are A, B and S3 (C here) from `fixtures/trust-labels.json`, and
//! B's and C's sweep ids are the ones `run_dir_round_trip.rs` uses.
//! `fixtures/README.md` says what the fixtures hold. The fixtures are compiled
//! in with `include_bytes!`, so this test opens no file when it runs, and it
//! goes through the public API alone, as P2c's `pull` and `done` will.

use serde_json::json;
use sweepky_core::{
    FindingGroup, FindingGroups, Findings, GroupMember, MergedGroup, Pubky, SweepFindings,
    SweepRef, group_findings, parse_audit_findings,
};

/// `fixtures/cloudflare/findings.json`, B's findings in Cloudflare's format.
const CLOUDFLARE_FINDINGS: &[u8] = include_bytes!("../../../fixtures/cloudflare/findings.json");
/// `fixtures/common/findings.json`, C's findings in the common format.
const COMMON_FINDINGS: &[u8] = include_bytes!("../../../fixtures/common/findings.json");

/// A, the bounty's owner: the roster's admin in `fixtures/trust-labels.json`.
const A: &str = "ybymzxgk1zd3a7dm3i15gcuq7ewqkbimft6r1n8oc9o6uay8mqfo";
/// B, a circle member, who submitted the Cloudflare-shaped run directory.
const B: &str = "btyoe954e99wb6sp7csdipt9ki8ca3iyus1tfi3171zqdixb5csy";
/// C, the stranger S3, who submitted the common-format run directory.
const C: &str = "qwujy4epafpmfei7bxn8fccfm1shzqp516sbenxi7qr6gua4n77o";

/// The sweeps' indices in upload order, as every test here passes them: B,
/// then C, then (where present) A.
const B_SWEEP: usize = 0;
const C_SWEEP: usize = 1;
const A_SWEEP: usize = 2;

/// The shared location's ids: Cloudflare's record, the common fixture's
/// finding, and the one A's own sweep gives it.
const B_EXPIRY: &str = "auth-expiry-inclusive";
const C_EXPIRY: &str = "session-expiry-off-by-one";
const A_EXPIRY: &str = "expiry-second-still-valid";
/// The id both fixtures use, at unrelated sinks.
const SHARED_ID: &str = "auth-token-compare-timing";

fn pubky(text: &str) -> Pubky {
    text.parse().unwrap()
}

fn sweep_ref(sweeper: &str, sweep_id: &str) -> SweepRef {
    format!("pubky://{sweeper}/pub/sweepky/sweeps/{sweep_id}.json")
        .parse()
        .unwrap()
}

/// B's sweep, trusted: the Cloudflare fixture converted under its playbook,
/// as `SweepPackage::build` converts it.
fn b_sweep() -> SweepFindings {
    let playbook = "cloudflare/security-audit@c1c8a8c".parse().unwrap();
    let (findings, _) = parse_audit_findings(CLOUDFLARE_FINDINGS, &playbook).unwrap();
    SweepFindings {
        sweep: sweep_ref(B, "0035VDF0PFF72"),
        trusted: true,
        findings,
    }
}

/// C's sweep, trusted: the common fixture as written.
fn c_sweep() -> SweepFindings {
    SweepFindings {
        sweep: sweep_ref(C, "0035VE9TZVPAA"),
        trusted: true,
        findings: Findings::from_json(COMMON_FINDINGS).unwrap(),
    }
}

/// A's own sweep of A's bounty, trusted: one finding whose only location is
/// the shared sink, `src/auth/session.rs` line 88 in `fn is_expired`.
fn a_sweep() -> SweepFindings {
    let document = json!({
        "schemaVersion": 1,
        "playbook": "careful-review",
        "findings": [{
            "id": A_EXPIRY,
            "title": "Expiry check lets the last second through",
            "severity": null,
            "confidence": null,
            "status": "needs_validation",
            "locations": [{
                "file": "src/auth/session.rs",
                "line": 88,
                "kind": "sink",
                "scope": "fn is_expired",
            }],
            "description": "Synthetic.",
        }],
    });
    SweepFindings {
        sweep: sweep_ref(A, "0035VFB2N4G8R"),
        trusted: true,
        findings: Findings::from_json(document.to_string().as_bytes()).unwrap(),
    }
}

/// Where the finding with id `id` is in sweep `sweep`: the one finding there
/// with that id.
fn member(groups: &FindingGroups, sweep: usize, id: &str) -> GroupMember {
    let findings = &groups.sweeps()[sweep].findings.findings;
    let mut positions = findings
        .iter()
        .enumerate()
        .filter(|(_, finding)| finding.id == id)
        .map(|(position, _)| position);
    let finding = positions.next().unwrap();
    assert!(positions.next().is_none(), "two findings with id {id}");
    GroupMember { sweep, finding }
}

/// The one group `member` is in.
fn group_of(groups: &FindingGroups, member: GroupMember) -> &FindingGroup {
    let mut holding = groups
        .groups()
        .iter()
        .filter(|group| group.members().contains(&member));
    let group = holding.next().unwrap();
    assert!(holding.next().is_none(), "{member:?} is in two groups");
    group
}

/// The merged group that holds `member`'s content, if any does.
// Two lifetimes: `'m` is the borrow of the `merged` list, which the result
// points into, and `'g` is the borrow of the `FindingGroups` each merged
// group points into. Naming both lets the result keep each one as it was.
fn merged_holding<'m, 'g>(
    merged: &'m [MergedGroup<'g>],
    member: GroupMember,
) -> Option<&'m MergedGroup<'g>> {
    merged.iter().find(|group| {
        group
            .findings()
            .iter()
            .any(|merged_finding| merged_finding.member == member)
    })
}

/// Each merged finding of `group` as its member and its id, in order.
// The ids borrow from the `FindingGroups` (`'g`), not from `group`, so the
// list stays usable after `group` is gone.
fn merged_members<'g>(group: &MergedGroup<'g>) -> Vec<(GroupMember, &'g str)> {
    group
        .findings()
        .iter()
        .map(|merged_finding| (merged_finding.member, merged_finding.finding.id.as_str()))
        .collect()
}

#[test]
fn fixture_sweeps_group_the_shared_location_with_both_reporters() {
    let groups = group_findings(vec![b_sweep(), c_sweep()]);
    let b_expiry = member(&groups, B_SWEEP, B_EXPIRY);
    let c_expiry = member(&groups, C_SWEEP, C_EXPIRY);
    // One group holds both, and nothing else.
    let shared = group_of(&groups, b_expiry);
    assert_eq!(shared.members(), [b_expiry, c_expiry]);
    assert_eq!(shared.reported_by(), [pubky(B), pubky(C)]);
    // Every other finding is alone: B's three, C's two, one group shared.
    assert_eq!(groups.groups().len(), 4);
}

#[test]
fn fixture_shared_id_pair_stays_apart() {
    let groups = group_findings(vec![b_sweep(), c_sweep()]);
    let b_timing = member(&groups, B_SWEEP, SHARED_ID);
    let c_timing = member(&groups, C_SWEEP, SHARED_ID);
    // Two groups, each holding its own finding and reporter alone.
    let b_group = group_of(&groups, b_timing);
    let c_group = group_of(&groups, c_timing);
    assert_eq!(b_group.members(), [b_timing]);
    assert_eq!(b_group.reported_by(), [pubky(B)]);
    assert_eq!(c_group.members(), [c_timing]);
    assert_eq!(c_group.reported_by(), [pubky(C)]);
}

#[test]
fn propose_credits_returns_both_and_leaves_out_the_owner() {
    // The owner A swept their own bounty and found the shared location too,
    // so A is among that group's reporters, last, in upload order.
    let groups = group_findings(vec![b_sweep(), c_sweep(), a_sweep()]);
    let b_expiry = member(&groups, B_SWEEP, B_EXPIRY);
    let c_expiry = member(&groups, C_SWEEP, C_EXPIRY);
    let a_expiry = member(&groups, A_SWEEP, A_EXPIRY);
    let shared = group_of(&groups, b_expiry);
    assert_eq!(shared.members(), [b_expiry, c_expiry, a_expiry]);
    assert_eq!(shared.reported_by(), [pubky(B), pubky(C), pubky(A)]);
    // B and C, in upload order, and never A.
    assert_eq!(groups.propose_credits(pubky(A)), [pubky(B), pubky(C)]);
    // The owner is compared by key bytes, so the SDK's `pubky<z32>`
    // spelling of A is left out just the same.
    let owner_as_sdk_prints_it = pubky(&format!("pubky{A}"));
    assert_eq!(
        groups.propose_credits(owner_as_sdk_prints_it),
        [pubky(B), pubky(C)]
    );
}

#[test]
fn propose_credits_is_the_same_when_the_owner_reported_nothing() {
    // Without A's sweep, A is in no group, and the proposal is still B and C.
    let without_owner = group_findings(vec![b_sweep(), c_sweep()]);
    assert!(
        without_owner
            .groups()
            .iter()
            .all(|group| !group.reported_by().contains(&pubky(A)))
    );
    assert_eq!(
        without_owner.propose_credits(pubky(A)),
        [pubky(B), pubky(C)]
    );
}

#[test]
fn an_untrusted_sweep_is_attributed_but_not_merged() {
    let mut untrusted_c = c_sweep();
    untrusted_c.trusted = false;
    let groups = group_findings(vec![b_sweep(), untrusted_c, a_sweep()]);
    let b_expiry = member(&groups, B_SWEEP, B_EXPIRY);
    let c_expiry = member(&groups, C_SWEEP, C_EXPIRY);
    let a_expiry = member(&groups, A_SWEEP, A_EXPIRY);
    let c_timing = member(&groups, C_SWEEP, SHARED_ID);

    // Attribution counts C either way: C is among the shared group's
    // reporters and in the proposed credits.
    let shared = group_of(&groups, b_expiry);
    assert_eq!(shared.members(), [b_expiry, c_expiry, a_expiry]);
    assert_eq!(shared.reported_by(), [pubky(B), pubky(C), pubky(A)]);
    assert_eq!(groups.propose_credits(pubky(A)), [pubky(B), pubky(C)]);

    let merged = groups.merged();
    // The shared group's merged content is B's finding and A's, in upload
    // order, and none of C's. Its reporters still include C.
    let merged_shared = merged_holding(&merged, b_expiry).unwrap();
    assert_eq!(
        merged_members(merged_shared),
        [(b_expiry, B_EXPIRY), (a_expiry, A_EXPIRY)]
    );
    assert_eq!(merged_shared.reported_by(), [pubky(B), pubky(C), pubky(A)]);
    // Nothing anywhere in the merged output comes from C's sweep.
    for group in &merged {
        for merged_finding in group.findings() {
            assert_ne!(merged_finding.member.sweep, C_SWEEP);
            assert_ne!(merged_finding.finding.id, C_EXPIRY);
        }
    }
    // C's half of the shared-id pair, which only C reported, is a group in
    // `groups()` but missing from `merged()`. Every other group, which has a
    // trusted member, is merged.
    assert_eq!(group_of(&groups, c_timing).reported_by(), [pubky(C)]);
    assert!(merged_holding(&merged, c_timing).is_none());
    assert_eq!(merged.len(), groups.groups().len() - 1);
}

#[test]
fn a_trusted_sweep_is_merged() {
    // The flag is what decides: the same three sweeps, with C trusted, merge
    // C's content too, and every group.
    let all_trusted = group_findings(vec![b_sweep(), c_sweep(), a_sweep()]);
    let b_expiry = member(&all_trusted, B_SWEEP, B_EXPIRY);
    let c_expiry = member(&all_trusted, C_SWEEP, C_EXPIRY);
    let a_expiry = member(&all_trusted, A_SWEEP, A_EXPIRY);
    let c_timing = member(&all_trusted, C_SWEEP, SHARED_ID);
    let merged = all_trusted.merged();
    assert_eq!(
        merged_members(merged_holding(&merged, b_expiry).unwrap()),
        [
            (b_expiry, B_EXPIRY),
            (c_expiry, C_EXPIRY),
            (a_expiry, A_EXPIRY)
        ]
    );
    assert!(merged_holding(&merged, c_timing).is_some());
    assert_eq!(merged.len(), all_trusted.groups().len());
}
