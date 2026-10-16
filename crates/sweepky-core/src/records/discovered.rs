//! [`Discovered`], an open bounty's discovered-sweeps file.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::RecordError;
use crate::ids::EventCursor;
use crate::pubky::Pubky;
use crate::schema::{MAX_RECORD_BYTES, SchemaVersion, UnknownFields, parse_record};
use crate::url::SweepRef;

/// An open bounty's discovered-sweeps file,
/// `/pub/sweepky/bounties/<id>.discovered.json`: `{schemaVersion, sweeps,
/// cursors}`.
///
/// The owner's CLI writes it: `post --open` with the starting cursor of each
/// watched homeserver and no sweeps, then `pull`, which appends the strangers'
/// sweeps it accepts from the events feeds and moves the cursors on. The
/// board reads it to show those sweeps, and never reads a feed itself.
///
/// The file is public, so it holds sweep URLs and feed positions and nothing
/// else: the typed fields cannot hold anything from a sweep's findings, and
/// `extra` only carries back what the file already had
/// (`docs/plan/01-records-and-discovery.md`, "Records").
///
/// In JSON, `sweeps` is a list of sweep record URLs and `cursors` an object
/// from a homeserver's key, in raw z-base32, to an event id as a decimal
/// string. Reading takes either spelling of a key. If one homeserver appears
/// twice under `cursors` (once in each spelling, say), the later entry wins;
/// the CLI never writes that.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Discovered {
    /// The record's `schemaVersion`.
    pub schema_version: SchemaVersion,
    /// The sweeps found so far, in the order they were added. Use
    /// [`add_sweep`](Self::add_sweep) to append without duplicates.
    pub sweeps: Vec<SweepRef>,
    /// Each watched homeserver's position in its `/events/` feed: the last
    /// event read.
    // A `BTreeMap` rather than a `HashMap`: it iterates in key order (here the
    // key bytes), so writing the file twice gives the same bytes, and a
    // rewrite does not reshuffle the object. A `HashMap`'s order changes from
    // run to run.
    pub cursors: BTreeMap<Pubky, EventCursor>,
    /// The top-level fields this build does not know, kept for a rewrite.
    #[serde(flatten)]
    pub extra: UnknownFields,
}

impl Discovered {
    /// Parses a `bounties/<id>.discovered.json` record fetched from a
    /// homeserver.
    ///
    /// Refuses input over [`MAX_RECORD_BYTES`] with
    /// [`RecordError::TooLarge`] and a newer `schemaVersion` with
    /// [`RecordError::UnsupportedVersion`], before reading the rest; anything
    /// malformed, including a URL that is not a sweep record's, is a
    /// [`RecordError::Json`].
    pub fn from_json(input: &[u8]) -> Result<Self, RecordError> {
        parse_record(input, MAX_RECORD_BYTES)
    }

    /// Appends `sweep` unless it is already listed, and says whether it did.
    ///
    /// Two refs are the same sweep when the sweeper's key bytes and the id
    /// are equal ([`SweepRef`]'s `==`), so a URL respelled with the SDK's
    /// `pubky` prefix is still a duplicate.
    // It returns whether it appended, as `HashSet::insert` does, so the
    // caller learns whether the sweep was new without a second scan.
    // `SweepRef` is `Copy` (40 bytes), so it is taken by value and pushed
    // without a clone. `contains` scans the list: fine for the few sweeps one
    // bounty draws.
    pub fn add_sweep(&mut self, sweep: SweepRef) -> bool {
        if self.sweeps.contains(&sweep) {
            return false;
        }
        self.sweeps.push(sweep);
        true
    }

    /// Sets `homeserver`'s cursor to `cursor`, replacing the one it had.
    ///
    /// It does not check that the cursor moves forward; `pull` advances a
    /// cursor only once it has processed the whole batch before it.
    pub fn set_cursor(&mut self, homeserver: Pubky, cursor: EventCursor) {
        // `insert` replaces the value of a key already present. It returns
        // the old value, which this method has no use for.
        self.cursors.insert(homeserver, cursor);
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::Discovered;
    use crate::error::RecordError;
    use crate::ids::EventCursor;
    use crate::pubky::Pubky;
    use crate::url::SweepRef;

    /// The committed fixture, in canonical form.
    const FIXTURE: &str = include_str!("../../../../fixtures/discovered.json");

    /// The first homeserver in the fixture's `cursors`.
    const HOMESERVER: &str = "1nepshaq7wqc3ddb7361kz1mf6yum4k6qgtpyuy8zt1n5pzpue9o";

    fn fixture_json() -> Value {
        serde_json::from_str(FIXTURE).unwrap()
    }

    fn fixture_record() -> Discovered {
        // Parsed from the file's own bytes, as a homeserver would serve them.
        Discovered::from_json(FIXTURE.as_bytes()).unwrap()
    }

    fn parse(input: &Value) -> Result<Discovered, RecordError> {
        Discovered::from_json(input.to_string().as_bytes())
    }

    #[test]
    fn the_fixture_round_trips() {
        let discovered = fixture_record();
        assert_eq!(discovered.sweeps.len(), 2);
        assert_eq!(discovered.cursors.len(), 2);
        assert!(discovered.extra.is_empty());
        assert_eq!(serde_json::to_value(&discovered).unwrap(), fixture_json());
    }

    #[test]
    fn unknown_fields_survive_a_round_trip() {
        // Added here rather than in the file, so the file stays canonical.
        let mut input = fixture_json();
        input["addedLater"] = json!({ "by": "a newer client" });

        let discovered = parse(&input).unwrap();
        assert_eq!(discovered.extra.len(), 1);
        assert_eq!(serde_json::to_value(&discovered).unwrap(), input);
    }

    #[test]
    fn add_sweep_refuses_a_sweep_already_listed() {
        let mut discovered = fixture_record();
        let first = discovered.sweeps[0];
        let second = discovered.sweeps[1];

        // The first sweep again, with the sweeper in the SDK's spelling.
        let respelled: SweepRef = format!(
            "pubky://pubky{}/pub/sweepky/sweeps/{}.json",
            first.sweeper, first.id
        )
        .parse()
        .unwrap();
        assert!(!discovered.add_sweep(respelled));
        assert_eq!(discovered.sweeps, [first, second]);

        // A sweep matches only on both the sweeper and the id.
        let same_sweeper = SweepRef {
            sweeper: first.sweeper,
            id: second.id,
        };
        let same_id = SweepRef {
            sweeper: second.sweeper,
            id: first.id,
        };
        assert!(discovered.add_sweep(same_sweeper));
        assert!(discovered.add_sweep(same_id));
        assert!(!discovered.add_sweep(same_sweeper));
        assert_eq!(discovered.sweeps, [first, second, same_sweeper, same_id]);
    }

    #[test]
    fn set_cursor_replaces_and_writes_a_decimal_string_keyed_by_raw_z32() {
        let mut discovered = fixture_record();
        // The homeserver in the SDK's spelling: still the same map key.
        let homeserver: Pubky = format!("pubky{HOMESERVER}").parse().unwrap();
        discovered.set_cursor(homeserver, EventCursor::new(900_001));
        assert_eq!(discovered.cursors.len(), 2);
        assert_eq!(
            discovered.cursors.get(&homeserver),
            Some(&EventCursor::new(900_001))
        );

        let mut expected = fixture_json();
        expected["cursors"][HOMESERVER] = json!("900001");
        assert_eq!(serde_json::to_value(&discovered).unwrap(), expected);
    }
}
