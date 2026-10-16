//! [`Manifest`], the part of a sweep package that says what it covers, and
//! [`Manifest::check_binding`], which ties a decrypted package to the sweep
//! record it was fetched with.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::sweep::Sweep;
use crate::names::{GitSha, Playbook, TargetId};
use crate::pubky::Pubky;
use crate::schema::UnknownFields;
use crate::time::RecordTime;
use crate::url::{BountyRef, SweepRef};

/// Why a decrypted package's [`Manifest`] does not belong to the sweep
/// record it was fetched with ([`Manifest::check_binding`]).
///
/// The variants hold no data: not a key, an id, a target or any other value
/// from the package or the record, so an error can go into a log line or a
/// terminal as it is. Which variant it is says which check failed, and the
/// caller already holds the values it compared.
// `Copy` is fine for a fieldless enum: it is one small number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BindingError {
    /// The manifest names a sweeper other than the owner of the path the
    /// record and the package were fetched from: a package copied under
    /// someone else's storage, or one that claims to be someone else's.
    #[error("the package names another sweeper than the one whose storage it came from")]
    SweeperMismatch,
    /// The manifest names another bounty than the sweep record does.
    #[error("the package names another bounty than its sweep record")]
    BountyMismatch,
    /// The manifest's targets, the record's targets and the manifest's
    /// `targetShas` keys are not one and the same set, or a target appears
    /// twice in either list.
    #[error("the package's targets are not its sweep record's, or one is listed twice")]
    TargetsMismatch,
}

/// A sweep package's `manifest`: `{sweeper, bounty, targets, targetShas,
/// playbook, startedAt, finishedAt}` (01, "The sweep package").
///
/// It travels inside the encrypted package, so only the bounty's owner and
/// the sweeper read it. It echoes who swept which bounty's targets at which
/// commits, so a package copied under another sweeper's or another bounty's
/// record does not check out there: [`check_binding`](Self::check_binding)
/// compares it with the sweep record and the record's path. Each reference
/// is typed and checked as it is read: a key, a bounty record's URL, target
/// ids, full git SHAs and a playbook in 01's pattern.
///
/// **No `schemaVersion` of its own, and no `from_json`.** A manifest is never
/// a file by itself: 01 puts `schemaVersion` on the package envelope around
/// it, and P1b parses that envelope, with its size cap and version check,
/// manifest included. The manifest is not one of 01's six record kinds.
///
/// If one target id appears twice as a key of `targetShas`, the later entry
/// wins; `submit` never writes that.
///
/// **`Debug` counts the unknown fields.** It prints every typed field, which
/// says no more than the public records already do (the sweep record and its
/// path, and the revs the bounty pins), but of [`extra`](Self::extra) only how
/// many fields it has: those are whatever a newer client sealed into the
/// package, so they may be as private as the findings beside them.
// `Debug` is not derived, because the derived one would print `extra` in
// full; the hand-written impl is below.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    /// The sweeper, whose homeserver holds the sweep record and package.
    pub sweeper: Pubky,
    /// The bounty swept.
    pub bounty: BountyRef,
    /// The bounty's targets the sweep covers.
    pub targets: Vec<TargetId>,
    /// The commit each target was swept at, by target id.
    // A `BTreeMap` iterates in key order, so writing a manifest twice gives
    // the same JSON. Its keys are `TargetId`s, so each JSON object key goes
    // through the same check as any other target id.
    pub target_shas: BTreeMap<TargetId, GitSha>,
    /// The playbook the sweep followed. A label, as on [`Sweep`].
    pub playbook: Playbook,
    /// When the sweep started.
    pub started_at: RecordTime,
    /// When it finished. Always present: `submit` builds the manifest after
    /// the sweep has ended.
    pub finished_at: RecordTime,
    /// The fields of the manifest this build does not know, kept for a
    /// rewrite.
    #[serde(flatten)]
    pub extra: UnknownFields,
}

impl Manifest {
    /// Checks that this manifest, decrypted from a sweep's package, belongs
    /// to the sweep record `sweep` and the path `sweep_ref` both were
    /// fetched from (02, "Authorship without signatures"). In this order:
    ///
    /// 1. [`sweeper`](Self::sweeper) is the path's owner,
    ///    [`SweepRef::sweeper`], compared by key, so either spelling of a key
    ///    is the same sweeper. Otherwise [`BindingError::SweeperMismatch`]:
    ///    a package copied under another sweeper's storage does not check
    ///    out there, and nor does one that names someone else.
    /// 2. [`bounty`](Self::bounty) is the record's
    ///    [`bounty`](Sweep::bounty), owner and id. Otherwise
    ///    [`BindingError::BountyMismatch`].
    /// 3. [`targets`](Self::targets), the record's
    ///    [`targets`](Sweep::targets) and the keys of
    ///    [`target_shas`](Self::target_shas) are one set: the same ids,
    ///    compared exactly (case included), in any order, and no id twice in
    ///    either list. Otherwise [`BindingError::TargetsMismatch`].
    ///
    /// The playbook and the times are not compared: `submit --playbook`
    /// (P2b) may name another playbook than `run` wrote in the record, and
    /// the times are the CLI's.
    ///
    /// `sweep_ref` must say where the caller fetched the record and the
    /// package from: the sweeper's own storage, as the caller resolved it
    /// ([`SweepRef::url`] and [`SweepRef::package_url`]). Never take it from
    /// the feed, the record or the package: the check is only as good as
    /// that path.
    ///
    /// What this does not check is the caller's (P2c): that the record's
    /// bounty is the one being pulled, that its targets are that bounty's,
    /// and that `targetShas` are the revisions the bounty pins, which needs
    /// the bounty record. The manifest has no sweep id (01), so a package
    /// uploaded again under another of the same sweeper's records, of the
    /// same bounty and targets, binds there too.
    ///
    /// # Errors
    ///
    /// The first check that fails, as a [`BindingError`], which holds no
    /// data.
    // Every value compared here is public (a key, a bounty URL, target ids
    // that the public records carry too), so plain `==` is right: a
    // constant-time comparison is for secrets, and none is involved.
    pub fn check_binding(&self, sweep_ref: &SweepRef, sweep: &Sweep) -> Result<(), BindingError> {
        // `Pubky`'s `==` compares the 32 key bytes, never the string.
        if self.sweeper != sweep_ref.sweeper {
            return Err(BindingError::SweeperMismatch);
        }
        // `BountyRef`'s `==` compares the owner's key bytes and the id.
        if self.bounty != sweep.bounty {
            return Err(BindingError::BountyMismatch);
        }
        let manifest_targets = self.checked_target_set()?;
        // `unique_set` gives `None` for a record that lists a target twice,
        // and `None` never equals `Some`, so that is a mismatch too.
        if unique_set(&sweep.targets) != Some(manifest_targets) {
            return Err(BindingError::TargetsMismatch);
        }
        Ok(())
    }

    /// The manifest's targets as a set, when none appears twice and they are
    /// exactly the keys of `targetShas`; otherwise
    /// [`BindingError::TargetsMismatch`].
    ///
    /// The part of [`check_binding`](Self::check_binding) that needs no
    /// record. Sealing runs it too (`seal_package`), so a sweeper's CLI
    /// never seals a package that no record could bind.
    // The set holds `&TargetId`s borrowed from `self.targets`, so no id is
    // copied. The elided lifetime ties them to `&self`: the borrow checker
    // will not let the set outlive the manifest it points into.
    pub(crate) fn checked_target_set(&self) -> Result<BTreeSet<&TargetId>, BindingError> {
        let targets = unique_set(&self.targets).ok_or(BindingError::TargetsMismatch)?;
        // A `BTreeMap`'s keys and a `BTreeSet` both iterate in `TargetId`
        // order, so the two are the same set exactly when the two sequences
        // are equal, item by item. `copied()` turns the set's `&&TargetId`
        // items into `&TargetId`s, the type the map's keys come as.
        if !self.target_shas.keys().eq(targets.iter().copied()) {
            return Err(BindingError::TargetsMismatch);
        }
        Ok(targets)
    }
}

/// `targets` as a set, or `None` when an id appears twice.
// A sorted set rather than a hash set: its cost is bounded (each insert is
// O(log n)) whatever ids a stranger picks, and it needs no random seed.
fn unique_set(targets: &[TargetId]) -> Option<BTreeSet<&TargetId>> {
    let mut set = BTreeSet::new();
    for target in targets {
        // `insert` returns `false` when the id was already in the set.
        if !set.insert(target) {
            return None;
        }
    }
    Some(set)
}

/// Prints the typed fields as a derived `Debug` would and, in place of
/// `extra`, `extra_fields`: how many fields it holds, never what they hold.
impl fmt::Debug for Manifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Naming every field, with no `..`, makes a field added later a
        // compile error here until someone decides whether it may print.
        let Self {
            sweeper,
            bounty,
            targets,
            target_shas,
            playbook,
            started_at,
            finished_at,
            extra,
        } = self;
        // Every field is accounted for, `extra` by its count, so the output
        // ends with `}` (`finish`), not with the `..` that would say a field
        // was left out.
        f.debug_struct("Manifest")
            .field("sweeper", sweeper)
            .field("bounty", bounty)
            .field("targets", targets)
            .field("target_shas", target_shas)
            .field("playbook", playbook)
            .field("started_at", started_at)
            .field("finished_at", finished_at)
            .field("extra_fields", &extra.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{BindingError, Manifest};
    use crate::names::{GitSha, TargetId};
    use crate::pubky::Pubky;
    use crate::records::Sweep;
    use crate::url::SweepRef;

    /// Sweeper S1 and owner A from `fixtures/trust-labels.json`.
    const SWEEPER: &str = "a8fyof86uespzzjc3hiryromqy6hgw1gem5htj76jn6sto4jokhy";
    const OWNER: &str = "ybymzxgk1zd3a7dm3i15gcuq7ewqkbimft6r1n8oc9o6uay8mqfo";
    /// One of A's bounty ids.
    const BOUNTY_ID: &str = "0035G87EK4XFE";
    const REV1: &str = "4444444444444444444444444444444444444444";
    const REV2: &str = "5555555555555555555555555555555555555555";
    /// Another sweeper: C from `fixtures/trust-labels.json`.
    const OTHER_SWEEPER: &str = "3rus98p3q6naiqxckzo676jeewj1whf6ai8911mxacshks18eq3y";
    /// Another bounty id, used here under A as owner.
    const OTHER_BOUNTY_ID: &str = "0035HHKN24QMC";
    /// The sweep's id, the `<id>` in `sweeps/<id>.json` and `sweeps/<id>.age`.
    const SWEEP_ID: &str = "0035M2DX3Q44W";

    fn manifest_json() -> Value {
        json!({
            "sweeper": SWEEPER,
            "bounty": format!("pubky://{OWNER}/pub/sweepky/bounties/{BOUNTY_ID}.json"),
            "targets": ["t1", "t2"],
            "targetShas": { "t1": REV1, "t2": REV2 },
            "playbook": "cloudflare/security-audit@c1c8a8c",
            "startedAt": "2026-10-16T08:00:00Z",
            "finishedAt": "2026-10-16T09:10:00Z",
        })
    }

    fn parse(input: &Value) -> Result<Manifest, serde_json::Error> {
        serde_json::from_value(input.clone())
    }

    fn bounty_url(owner: &str, id: &str) -> String {
        format!("pubky://{owner}/pub/sweepky/bounties/{id}.json")
    }

    /// The path a record and its package were fetched from: `sweeper`'s
    /// `sweeps/<SWEEP_ID>.json`.
    fn path_of(sweeper: &str) -> SweepRef {
        format!("pubky://{sweeper}/pub/sweepky/sweeps/{SWEEP_ID}.json")
            .parse()
            .unwrap()
    }

    /// The sweep record `manifest_json` belongs to: the same bounty and
    /// targets, the targets in another order, and a playbook and times that
    /// differ from the manifest's.
    fn record_json() -> Value {
        json!({
            "schemaVersion": 1,
            "bounty": bounty_url(OWNER, BOUNTY_ID),
            "targets": ["t2", "t1"],
            "playbook": "my-own-review",
            "status": "done",
            "startedAt": "2026-10-16T07:59:00Z",
            "finishedAt": "2026-10-16T09:11:00Z",
        })
    }

    /// Checks the manifest `manifest` against the record `record`, as fetched
    /// from `path_owner`'s storage.
    fn check(manifest: &Value, path_owner: &str, record: &Value) -> Result<(), BindingError> {
        let record = Sweep::from_json(record.to_string().as_bytes()).unwrap();
        parse(manifest)
            .unwrap()
            .check_binding(&path_of(path_owner), &record)
    }

    #[test]
    fn a_manifest_round_trips_with_an_unknown_field() {
        let mut input = manifest_json();
        input["addedLater"] = json!({ "by": "a newer client" });
        let manifest = parse(&input).unwrap();
        assert_eq!(manifest.sweeper, SWEEPER.parse::<Pubky>().unwrap());
        assert_eq!(manifest.targets.len(), 2);
        let t2: TargetId = "t2".parse().unwrap();
        assert_eq!(
            manifest.target_shas.get(&t2),
            Some(&REV2.parse::<GitSha>().unwrap())
        );
        assert_eq!(manifest.extra.len(), 1);
        assert_eq!(serde_json::to_value(&manifest).unwrap(), input);
    }

    #[test]
    fn a_manifest_with_a_bad_reference_is_rejected() {
        let sweep_url = format!("pubky://{OWNER}/pub/sweepky/sweeps/{BOUNTY_ID}.json");
        let cases = [
            ("sweeper", json!("not-a-pubky")),
            ("bounty", json!(sweep_url)),
            ("targets", json!(["../t1"])),
            // A target id as a key, a full git SHA as a value.
            ("targetShas", json!({ "../t1": REV1 })),
            ("targetShas", json!({ "t1": "c1c8a8c" })),
            ("playbook", json!("security audit")),
        ];
        for (field, value) in cases {
            let mut input = manifest_json();
            input[field] = value;
            assert!(parse(&input).is_err(), "{input}");
        }
    }

    #[test]
    fn manifest_debug_counts_extra_fields() {
        // `extra` holds whatever a newer client sealed into the package, so
        // `{:?}` shows how many fields it has and nothing of them. The typed
        // fields echo the public records and print as usual.
        const MARKER: &str = "MARKER-7f3a";
        let mut input = manifest_json();
        input[format!("{MARKER}-key")] = json!("plain value");
        input["addedLater"] = json!({ "by": format!("{MARKER}-value") });
        let manifest = parse(&input).unwrap();
        assert_eq!(manifest.extra.len(), 2);

        let typed_values = [
            SWEEPER,
            OWNER,
            BOUNTY_ID,
            "\"t1\"",
            "\"t2\"",
            REV1,
            REV2,
            "cloudflare/security-audit@c1c8a8c",
            "2026-10-16T08:00:00Z",
            "2026-10-16T09:10:00Z",
        ];
        for debug in [format!("{manifest:?}"), format!("{manifest:#?}")] {
            assert!(debug.starts_with("Manifest {"), "{debug}");
            for hidden in [MARKER, "plain value", "addedLater"] {
                assert!(!debug.contains(hidden), "{hidden} in {debug}");
            }
            assert!(debug.contains("extra_fields: 2"), "{debug}");
            for value in typed_values {
                assert!(debug.contains(value), "{value} not in {debug}");
            }
        }
    }

    #[test]
    fn binding_accepts_the_matching_record() {
        // Targets compare as sets, so the record may list them in another
        // order. The playbook and the times are not compared: `submit
        // --playbook` may name another playbook than `run` wrote.
        assert_eq!(check(&manifest_json(), SWEEPER, &record_json()), Ok(()));

        // The path's owner compares by key, so the SDK's `pubky<z32>`
        // spelling of the same sweeper passes too.
        let prefixed = format!("pubky{SWEEPER}");
        assert_eq!(check(&manifest_json(), &prefixed, &record_json()), Ok(()));
    }

    #[test]
    fn binding_rejects_a_package_under_another_sweepers_path() {
        // DW1, wrong path. The sweeper's package, uploaded under someone
        // else's storage beside a record of the same bounty and targets,
        // does not check out there: 02's authorship rule. The bounty's own
        // owner is someone else too.
        for path_owner in [OTHER_SWEEPER, OWNER] {
            assert_eq!(
                check(&manifest_json(), path_owner, &record_json()),
                Err(BindingError::SweeperMismatch),
                "{path_owner}"
            );
        }
    }

    #[test]
    fn binding_rejects_a_manifest_naming_another_sweeper() {
        // DW1, wrong sweeper: the path and the record untouched, the
        // manifest inside names someone else.
        let mut manifest = manifest_json();
        manifest["sweeper"] = json!(OTHER_SWEEPER);
        assert_eq!(
            check(&manifest, SWEEPER, &record_json()),
            Err(BindingError::SweeperMismatch)
        );

        // The sweeper is checked first, so a manifest wrong about
        // everything is refused for its sweeper.
        manifest["bounty"] = json!(bounty_url(OWNER, OTHER_BOUNTY_ID));
        manifest["targets"] = json!(["t9"]);
        manifest["targetShas"] = json!({ "t9": REV1 });
        assert_eq!(
            check(&manifest, SWEEPER, &record_json()),
            Err(BindingError::SweeperMismatch)
        );
    }

    #[test]
    fn binding_rejects_another_bounty() {
        // A record of another bounty: another id of the same owner, or the
        // same id under another owner.
        for bounty in [
            bounty_url(OWNER, OTHER_BOUNTY_ID),
            bounty_url(OTHER_SWEEPER, BOUNTY_ID),
        ] {
            let mut record = record_json();
            record["bounty"] = json!(bounty);
            assert_eq!(
                check(&manifest_json(), SWEEPER, &record),
                Err(BindingError::BountyMismatch),
                "{record}"
            );
        }
    }

    #[test]
    fn binding_rejects_other_targets() {
        // A record with other targets: fewer, more, others, none, one in
        // another case (ids compare exactly), or a repeated one.
        for targets in [
            json!(["t1"]),
            json!(["t1", "t2", "t3"]),
            json!(["t1", "t3"]),
            json!([]),
            json!(["t1", "T2"]),
            json!(["t1", "t2", "t2"]),
        ] {
            let mut record = record_json();
            record["targets"] = targets;
            assert_eq!(
                check(&manifest_json(), SWEEPER, &record),
                Err(BindingError::TargetsMismatch),
                "{record}"
            );
        }

        // A target repeated in the manifest, even when the record repeats it
        // too: neither list may hold a duplicate.
        let mut repeated = manifest_json();
        repeated["targets"] = json!(["t1", "t2", "t1"]);
        let mut repeated_record = record_json();
        repeated_record["targets"] = json!(["t1", "t2", "t1"]);
        for record in [record_json(), repeated_record] {
            assert_eq!(
                check(&repeated, SWEEPER, &record),
                Err(BindingError::TargetsMismatch),
                "{record}"
            );
        }

        // `targetShas` keys that differ from `targets`: one missing, one
        // extra, with `targets` itself matching the record.
        for shas in [
            json!({ "t1": REV1 }),
            json!({ "t1": REV1, "t2": REV2, "t3": REV1 }),
        ] {
            let mut manifest = manifest_json();
            manifest["targetShas"] = shas;
            assert_eq!(
                check(&manifest, SWEEPER, &record_json()),
                Err(BindingError::TargetsMismatch),
                "{manifest}"
            );
        }
    }

    #[test]
    fn binding_errors_carry_no_content() {
        // Fixed variants, with no field to hold a value from the package or
        // the record. The `match` has no `_ =>` arm, so a variant added
        // later stops this test compiling until someone lists it here, in
        // the match and in `errors`.
        let errors = [
            BindingError::SweeperMismatch,
            BindingError::BountyMismatch,
            BindingError::TargetsMismatch,
        ];
        for error in errors {
            match error {
                BindingError::SweeperMismatch
                | BindingError::BountyMismatch
                | BindingError::TargetsMismatch => {}
            }
        }
        let content = [
            SWEEPER,
            OTHER_SWEEPER,
            OWNER,
            BOUNTY_ID,
            OTHER_BOUNTY_ID,
            SWEEP_ID,
            REV1,
            REV2,
            "\"t1\"",
            "cloudflare/security-audit",
            "my-own-review",
            "2026-10-16",
        ];
        for error in errors {
            for printed in [
                error.to_string(),
                format!("{error:?}"),
                format!("{error:#?}"),
            ] {
                for value in content {
                    assert!(!printed.contains(value), "{value} in {printed}");
                }
            }
        }
    }
}
