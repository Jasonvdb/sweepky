//! [`Manifest`], the part of a sweep package that says what it covers.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::names::{GitSha, Playbook, TargetId};
use crate::pubky::Pubky;
use crate::schema::UnknownFields;
use crate::time::RecordTime;
use crate::url::BountyRef;

/// A sweep package's `manifest`: `{sweeper, bounty, targets, targetShas,
/// playbook, startedAt, finishedAt}` (01, "The sweep package").
///
/// It travels inside the encrypted package, so only the bounty's owner and
/// the sweeper read it. It echoes who swept which bounty's targets at which
/// commits, so a package copied under another sweeper's or another bounty's
/// record does not check out there: P1b's manifest binding compares it with
/// the sweep record and the record's path. This type only reads and writes
/// it, with each reference typed and checked: a key, a bounty record's URL,
/// target ids, full git SHAs and a playbook in 01's pattern.
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
    /// The playbook the sweep followed. A label, as on [`Sweep`](crate::Sweep).
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

    use super::Manifest;
    use crate::names::{GitSha, TargetId};
    use crate::pubky::Pubky;

    /// Sweeper S1 and owner A from `fixtures/trust-labels.json`.
    const SWEEPER: &str = "a8fyof86uespzzjc3hiryromqy6hgw1gem5htj76jn6sto4jokhy";
    const OWNER: &str = "ybymzxgk1zd3a7dm3i15gcuq7ewqkbimft6r1n8oc9o6uay8mqfo";
    /// One of A's bounty ids.
    const BOUNTY_ID: &str = "0035G87EK4XFE";
    const REV1: &str = "4444444444444444444444444444444444444444";
    const REV2: &str = "5555555555555555555555555555555555555555";

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
}
