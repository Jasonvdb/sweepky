//! [`Sweep`], a sweep record in `sweeps/<id>.json`, and [`SweepStatus`],
//! its `status`.

use serde::{Deserialize, Serialize};

use crate::error::RecordError;
use crate::names::{Playbook, Sha256Hex, TargetId};
use crate::open_enum::open_enum;
use crate::schema::{MAX_RECORD_BYTES, SchemaVersion, UnknownFields, parse_record};
use crate::time::RecordTime;
use crate::url::BountyRef;

open_enum! {
    /// A sweep's `status`.
    ///
    /// Open, so a status a newer client adds parses and is written back
    /// unchanged instead of failing the record.
    pub struct SweepStatus;

    /// The sweep statuses this build knows.
    pub enum KnownSweepStatus {
        /// `run` has started the sweep; `submit` has not finished it.
        Running = "running",
        /// `submit` uploaded the package.
        Done = "done",
        /// The sweep stopped without a package.
        Aborted = "aborted",
    }
}

/// A sweep record, at `/pub/sweepky/sweeps/<id>.json` on the sweeper's own
/// homeserver: `{schemaVersion, bounty, targets, playbook, status, startedAt,
/// finishedAt?, sha256?}`.
///
/// `run` writes it as `running`; `submit` uploads the encrypted package beside
/// it (`sweeps/<id>.age`) and flips it to `done`, or to `aborted`.
///
/// **Public.** It says who swept which bounty, when, with which playbook, and
/// how it ended. The typed fields hold nothing from the sweep's findings (no
/// severity, count or finding title); those are only inside the package,
/// which only the owner and the sweeper can open. `extra` only carries back
/// what the record already held.
///
/// The references are typed and checked when read: `bounty` must be a bounty
/// record's URL, each of `targets` a valid target id and `playbook` must
/// match 01's pattern, or the record is rejected whole. Whether they match
/// anything (the bounty exists and has those targets, the record sits under
/// the sweeper named in the package) is checked later, against the bounty
/// and the package's manifest (P1b).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Sweep {
    /// The record's `schemaVersion`.
    pub schema_version: SchemaVersion,
    /// The bounty swept.
    pub bounty: BountyRef,
    /// The bounty's targets the sweep covers: an array, because one run can
    /// cover a primary target plus companions.
    pub targets: Vec<TargetId>,
    /// The playbook the sweep followed. A label: print or compare it, never
    /// use it as a path or a command argument (see [`Playbook`]).
    pub playbook: Playbook,
    /// How far the sweep got.
    pub status: SweepStatus,
    /// When the sweep started.
    pub started_at: RecordTime,
    /// When it finished, once it has.
    // Left out when `None` rather than written as `null`: 01 marks the field
    // optional (`finishedAt?`), and a running sweep has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<RecordTime>,
    /// The SHA-256 digest 01 gives a finished sweep record (`sha256?`), as
    /// written. Left out when `None`. This type only carries it; 01 does not
    /// say what it is a digest of.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<Sha256Hex>,
    /// The top-level fields this build does not know, kept for a rewrite.
    #[serde(flatten)]
    pub extra: UnknownFields,
}

impl Sweep {
    /// Parses a `sweeps/<id>.json` record fetched from a homeserver.
    ///
    /// Refuses input over [`MAX_RECORD_BYTES`] with
    /// [`RecordError::TooLarge`] and a newer `schemaVersion` with
    /// [`RecordError::UnsupportedVersion`], before reading the rest; anything
    /// malformed, including a URL that is not a bounty record's, a bad target
    /// id or a playbook outside 01's pattern, is a [`RecordError::Json`]. An
    /// unknown `status` is not malformed.
    pub fn from_json(input: &[u8]) -> Result<Self, RecordError> {
        parse_record(input, MAX_RECORD_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{KnownSweepStatus, Sweep};
    use crate::error::{JsonCategory, RecordError};
    use crate::url::BountyRef;

    /// Owner A from `fixtures/trust-labels.json` and one of A's bounty ids.
    const OWNER: &str = "ybymzxgk1zd3a7dm3i15gcuq7ewqkbimft6r1n8oc9o6uay8mqfo";
    const BOUNTY_ID: &str = "0035G87EK4XFE";
    const STARTED_AT: &str = "2026-10-16T08:00:00Z";
    const FINISHED_AT: &str = "2026-10-16T09:10:00Z";

    fn bounty_url() -> String {
        format!("pubky://{OWNER}/pub/sweepky/bounties/{BOUNTY_ID}.json")
    }

    /// A sweep record as `run` writes it, before the sweep finishes.
    fn running() -> Value {
        json!({
            "schemaVersion": 1,
            "bounty": bounty_url(),
            "targets": ["t1", "t2"],
            "playbook": "cloudflare/security-audit@c1c8a8c",
            "status": "running",
            "startedAt": STARTED_AT,
        })
    }

    /// The same record as `submit` leaves it.
    fn done() -> Value {
        let mut input = running();
        input["status"] = json!("done");
        input["finishedAt"] = json!(FINISHED_AT);
        input["sha256"] = json!("ab".repeat(32));
        input
    }

    fn parse(input: &Value) -> Result<Sweep, RecordError> {
        Sweep::from_json(input.to_string().as_bytes())
    }

    #[test]
    fn a_running_record_parses_with_no_finish_fields() {
        let sweep = parse(&running()).unwrap();
        assert_eq!(sweep.status.as_known(), Some(KnownSweepStatus::Running));
        assert_eq!(sweep.finished_at, None);
        assert_eq!(sweep.sha256, None);
        let expected = BountyRef {
            owner: OWNER.parse().unwrap(),
            id: BOUNTY_ID.parse().unwrap(),
        };
        assert_eq!(sweep.bounty, expected);
        assert_eq!(sweep.targets.len(), 2);
    }

    #[test]
    fn a_done_record_parses_with_its_finish_fields() {
        let sweep = parse(&done()).unwrap();
        assert_eq!(sweep.status.as_known(), Some(KnownSweepStatus::Done));
        assert!(sweep.finished_at.is_some());
        assert!(sweep.sha256.is_some());
    }

    #[test]
    fn both_record_shapes_round_trip_with_an_unknown_field() {
        for mut input in [running(), done()] {
            input["addedLater"] = json!({ "by": "a newer client" });
            let sweep = parse(&input).unwrap();
            assert_eq!(sweep.extra.len(), 1);
            // `finishedAt` and `sha256` are left out when `None`, not written
            // as `null`, so the running record comes back without them.
            assert_eq!(serde_json::to_value(&sweep).unwrap(), input);
        }
    }

    #[test]
    fn status_is_an_open_label() {
        let mut aborted = running();
        aborted["status"] = json!("aborted");
        let sweep = parse(&aborted).unwrap();
        assert_eq!(sweep.status.as_known(), Some(KnownSweepStatus::Aborted));

        let mut paused = running();
        paused["status"] = json!("paused");
        let sweep = parse(&paused).unwrap();
        assert_eq!(sweep.status.as_known(), None);
        assert_eq!(sweep.status.as_str(), "paused");
        assert_eq!(serde_json::to_value(&sweep).unwrap(), paused);
    }

    #[test]
    fn a_bad_playbook_bounty_url_or_target_id_is_rejected() {
        // One bad value per field shows the record reads it through its
        // checked type. Each type's own tests (names.rs, url.rs) cover the
        // rest of its cases.
        let sweep_url = format!("pubky://{OWNER}/pub/sweepky/sweeps/{BOUNTY_ID}.json");
        let cases = [
            ("playbook", json!("security audit")),
            // A sweep's URL, not a bounty record's.
            ("bounty", json!(sweep_url)),
            // One bad entry fails the whole list.
            ("targets", json!(["t1", "../t2"])),
        ];
        for (field, value) in cases {
            let mut input = running();
            input[field] = value;
            assert!(
                matches!(
                    parse(&input),
                    Err(RecordError::Json {
                        category: JsonCategory::Data,
                        ..
                    })
                ),
                "{input}"
            );
        }
    }

    #[test]
    fn a_newer_version_is_refused() {
        let mut input = running();
        input["schemaVersion"] = json!(2);
        assert_eq!(
            parse(&input).unwrap_err(),
            RecordError::UnsupportedVersion {
                found: 2,
                supported: 1
            }
        );
    }
}
