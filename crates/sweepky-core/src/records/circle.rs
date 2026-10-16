//! [`Circle`], the roster in `circle.json`.

use serde::{Deserialize, Serialize};

use crate::error::RecordError;
use crate::pubky::Pubky;
use crate::schema::{MAX_RECORD_BYTES, SchemaVersion, UnknownFields, parse_record};

/// The roster an admin keeps at `/pub/sweepky/circle.json`: the default trust
/// set and the default discovery set.
///
/// In JSON, `{schemaVersion, name, admin, members: [{pubky, label?}]}`, with
/// every pubky written in raw z-base32. Reading takes a pubky in either
/// spelling, and a member whose `pubky` is not a valid key makes the whole
/// record an error.
///
/// Who is in the roster is [`is_in_roster`](Self::is_in_roster)'s rule: the
/// `admin` and every entry in `members`.
// `PartialEq` lets a test compare whole records. `Eq` marks that equality as
// total, which every field's is: `UnknownFields` is a `serde_json::Map`, and
// a serde_json number is never NaN, so it is `Eq` too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Circle {
    /// The record's `schemaVersion`.
    pub schema_version: SchemaVersion,
    /// The circle's name, as the admin wrote it. Untrusted text.
    pub name: String,
    /// The admin, whose homeserver holds this file and who alone can rewrite
    /// it. The admin is in the roster whether or not `members` lists them.
    pub admin: Pubky,
    /// The members, in the order the admin listed them.
    pub members: Vec<CircleMember>,
    /// The top-level fields this build does not know, kept for a rewrite.
    #[serde(flatten)]
    pub extra: UnknownFields,
}

/// One entry of a [`Circle`]'s `members`: `{pubky, label?}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CircleMember {
    /// The member's key.
    pub pubky: Pubky,
    /// A short name the admin gave the member, if any. Untrusted text.
    // `skip_serializing_if` leaves `None` out when writing, rather than
    // writing `null`, so a member written without a label comes back without
    // one. `default` reads a missing `label` as `None`; serde does that for an
    // `Option` anyway, and the two attributes are the usual pair.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// The fields of this member this build does not know, kept for a
    /// rewrite.
    #[serde(flatten)]
    pub extra: UnknownFields,
}

impl Circle {
    /// Parses a `circle.json` record fetched from a homeserver.
    ///
    /// Refuses input over [`MAX_RECORD_BYTES`] with
    /// [`RecordError::TooLarge`] and a newer `schemaVersion` with
    /// [`RecordError::UnsupportedVersion`], before reading the rest; anything
    /// malformed, including a bad member key, is a [`RecordError::Json`].
    pub fn from_json(input: &[u8]) -> Result<Self, RecordError> {
        parse_record(input, MAX_RECORD_BYTES)
    }

    /// Whether `pubky` is in the roster: the `admin`, or an entry in
    /// `members`.
    ///
    /// 01 calls the whole `circle.json` record the roster, so the admin is in
    /// it whether or not `members` lists them too: an admin missing from
    /// `members` is still labelled `circle`, and their done bounties count as
    /// a trusted owner's. `fixtures/README.md` states the same rule for the
    /// board's TypeScript trust badge, so the CLI and the board agree.
    ///
    /// Compares key bytes, so the spelling a key was written in does not
    /// matter. The comparison is not constant-time and need not be: these are
    /// public keys from a public file.
    // `Pubky` is `Copy` (32 bytes), so it is taken by value, as the rest of
    // this crate does: the caller keeps theirs, and there is no reference to
    // manage.
    pub fn is_in_roster(&self, pubky: Pubky) -> bool {
        // `||` stops at the first `true`, so the admin's own key skips the
        // scan of `members`. `iter().any(..)` also stops at the first match;
        // a linear scan is right for a roster of a few dozen members.
        self.admin == pubky || self.members.iter().any(|member| member.pubky == pubky)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::Circle;
    use crate::error::{JsonCategory, RecordError};
    use crate::pubky::Pubky;
    use crate::schema::MAX_RECORD_BYTES;

    /// The trust-label fixture. Its `roster` is a full `circle.json` record.
    const TRUST_LABELS: &str = include_str!("../../../../fixtures/trust-labels.json");

    /// Members A and B, and X, an owner outside the fixture's roster, from
    /// trust-labels.json.
    const A: &str = "ybymzxgk1zd3a7dm3i15gcuq7ewqkbimft6r1n8oc9o6uay8mqfo";
    const B: &str = "btyoe954e99wb6sp7csdipt9ki8ca3iyus1tfi3171zqdixb5csy";
    const X: &str = "z5quft985i4g55uz4ccsxn9r8qnmmk48kmmn6byyyoacu4u37rny";

    fn roster() -> Value {
        let fixture: Value = serde_json::from_str(TRUST_LABELS).unwrap();
        fixture["roster"].clone()
    }

    fn parse(input: &Value) -> Result<Circle, RecordError> {
        Circle::from_json(input.to_string().as_bytes())
    }

    fn pubky(text: &str) -> Pubky {
        text.parse().unwrap()
    }

    #[test]
    fn the_fixture_roster_round_trips_with_unknown_fields() {
        let mut input = roster();
        input["addedLater"] = json!({ "nested": [1, "two", null] });
        input["members"][1]["since"] = json!("2026-08-01");
        // A member without a label: written back without one, not as null.
        input["members"][2].as_object_mut().unwrap().remove("label");

        let circle = parse(&input).unwrap();
        assert_eq!(circle.extra.len(), 1);
        assert_eq!(circle.members[1].extra.len(), 1);
        assert_eq!(circle.members[2].label, None);
        assert_eq!(serde_json::to_value(&circle).unwrap(), input);
    }

    #[test]
    fn the_roster_is_the_admin_and_the_members_compared_by_key_bytes() {
        // X is the admin and is not listed in `members`.
        let input = json!({
            "schemaVersion": 1,
            "name": "Admin not listed",
            "admin": format!("pubky{X}"),
            "members": [{ "pubky": format!("pubky{A}") }, { "pubky": B, "label": "B" }],
        });
        let circle = parse(&input).unwrap();
        // Written as pubky<z32>, compared as key bytes.
        assert!(circle.is_in_roster(pubky(A)));
        assert!(circle.is_in_roster(pubky(B)));
        // The admin is in the roster without a `members` entry.
        assert_eq!(circle.admin, pubky(X));
        assert!(circle.is_in_roster(pubky(X)));
        // A key that is neither the admin nor listed is not.
        assert!(!circle.is_in_roster(Pubky::from_bytes([7; 32])));
        // And the keys are written back in the raw form.
        let output = serde_json::to_value(&circle).unwrap();
        assert_eq!(output["admin"], X);
        assert_eq!(output["members"][0]["pubky"], A);
    }

    #[test]
    fn a_bad_member_pubky_is_an_error() {
        for bad in [json!("not-a-pubky"), json!(A.to_uppercase()), json!(7)] {
            let mut input = roster();
            input["members"][1]["pubky"] = bad.clone();
            assert!(
                matches!(
                    parse(&input),
                    Err(RecordError::Json {
                        category: JsonCategory::Data,
                        ..
                    })
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_newer_version_is_refused() {
        let mut input = roster();
        input["schemaVersion"] = json!(2);
        assert_eq!(
            parse(&input).unwrap_err(),
            RecordError::UnsupportedVersion {
                found: 2,
                supported: 1
            }
        );
    }

    #[test]
    fn an_input_over_the_cap_is_refused() {
        // A valid roster padded with JSON whitespace to one byte over the cap.
        let mut bytes = roster().to_string().into_bytes();
        bytes.resize(MAX_RECORD_BYTES + 1, b' ');
        assert_eq!(
            Circle::from_json(&bytes).unwrap_err(),
            RecordError::TooLarge {
                limit: MAX_RECORD_BYTES,
                len: MAX_RECORD_BYTES + 1
            }
        );
    }
}
