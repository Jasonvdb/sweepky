//! [`Bounty`], a bounty post in `bounties/<id>.json`, and
//! [`Bounty::mark_done`], the rewrite `sweepky done` makes.

use std::collections::HashSet;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::error::RecordError;
use crate::open_enum::open_enum;
use crate::pubky::Pubky;
use crate::schema::{MAX_RECORD_BYTES, SchemaVersion, UnknownFields, parse_record};
use crate::target::Target;
use crate::time::RecordTime;

open_enum! {
    /// A bounty's `focus`: what it is looking for.
    ///
    /// An open label (01): `security` is the first use case, `bugs` and
    /// `perf` the others this build names, and any other string is just as
    /// valid. A focus this build does not name parses, is written back
    /// unchanged, and has no `as_known()`.
    pub struct Focus;

    /// The focus labels this build names.
    pub enum KnownFocus {
        /// A security review, the first use case.
        Security = "security",
        /// General bugs.
        Bugs = "bugs",
        /// Performance.
        Perf = "perf",
    }
}

open_enum! {
    /// A bounty's `status`.
    ///
    /// Open, so a status a newer client adds parses and is written back
    /// unchanged instead of failing the bounty.
    pub struct BountyStatus;

    /// The bounty statuses this build knows.
    pub enum KnownBountyStatus {
        /// Taking sweeps.
        Open = "open",
        /// Resolved by its owner, with `credits` and `doneAt` set.
        Done = "done",
    }
}

/// A bounty post, at `/pub/sweepky/bounties/<id>.json`: a fixed envelope that
/// tools act on, with a freeform brief inside (01, "The bounty post").
///
/// In JSON, `{schemaVersion, title, focus, brief, playbook: {suggested?,
/// required}, targets, open, reward, status, credits, createdAt, doneAt}`.
/// `open` reads as `false` and `credits` as empty when missing; `reward` and
/// `doneAt` read as `null` when missing and are always written, `null`
/// included.
///
/// **Public.** Anyone can read `/pub/`, so the typed fields hold the owner's
/// own words and choices (title, brief, targets, the reserved reward) and
/// nothing from any sweep's findings: no severity, no count, no finding
/// title. `credits` says only who helped. `extra` only carries back what the
/// record already held.
///
/// **Targets** are read in two steps (see [`Target`]): reading the bounty
/// checks each target's `id` and `kind` and keeps the rest as written, so a
/// target of an unknown kind round-trips and is skipped rather than failing
/// the bounty. The ids must be distinct: a sweep names targets by id, so a
/// bounty with two targets of one id is rejected whole. Ids that differ only
/// in case (`t1`, `T1`) are distinct here; code that makes a directory per
/// target must refuse them itself ([`TargetId`](crate::TargetId)).
///
/// **The done state** (`status`, `credits`, `doneAt`) is private. A `Bounty`
/// gets it from the record it was read from, from [`new`](Self::new) (open,
/// nobody credited), or from [`mark_done`](Self::mark_done), which refuses to
/// credit the owner. So any credits list this crate writes either is the one
/// the record already had or passed that check.
///
/// The text fields (`title`, `brief`, `playbook.suggested`) hold whatever the
/// owner wrote, and the owner may be a stranger: code that prints one to a
/// terminal treats it as untrusted text.
// `PartialEq` and `Eq` let tests compare whole records; every field's
// equality is total (a serde_json number is never NaN), as on `Circle`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bounty {
    /// The record's `schemaVersion`.
    pub schema_version: SchemaVersion,
    /// A one-line title. Public, and confirmed by the human before `post`
    /// writes it. Untrusted text.
    pub title: String,
    /// What the bounty is looking for.
    pub focus: Focus,
    /// Markdown for humans and agents: what to look for, context, scope, how
    /// to report. Public. Untrusted text.
    pub brief: String,
    /// The playbook the owner suggests, if any.
    pub playbook: BountyPlaybook,
    /// The pinned targets, each with an id distinct from the others'.
    // `deserialize_with` makes serde call `unique_targets` to read this field
    // instead of `Vec<Target>`'s own `Deserialize`. Writing is unchanged.
    #[serde(deserialize_with = "unique_targets")]
    pub targets: Vec<Target>,
    /// Whether sweeps from outside the circle are accepted (labelled
    /// untrusted). `false` when missing.
    #[serde(default)]
    pub open: bool,
    /// Reserved for a sats reward (`docs/plan/05-extensions.md`): `null` in
    /// v1. Kept as raw JSON, so a newer client's reward object survives a
    /// rewrite. It is the owner's offer, never anything from a sweep's
    /// findings.
    // `Option<Value>` rather than `Value`: JSON `null` and a missing key both
    // read as `None`, and `None` is written as `null`, so a v1 record always
    // carries `"reward": null`, the shape 01 shows.
    #[serde(default)]
    pub reward: Option<Value>,
    // `status`, `credits` and `done_at` are private (no `pub`): see "The
    // done state" above. serde's derive reads and writes private fields like
    // any other, and the getters below give read access.
    status: BountyStatus,
    #[serde(default)]
    credits: Vec<Pubky>,
    /// When the bounty was posted.
    pub created_at: RecordTime,
    #[serde(default)]
    done_at: Option<RecordTime>,
    /// The top-level fields this build does not know, kept for a rewrite.
    #[serde(flatten)]
    pub extra: UnknownFields,
}

/// A bounty's `playbook`: `{suggested?, required}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BountyPlaybook {
    /// The playbook the owner suggests, or `None` for no suggestion: an open
    /// string naming a skill, a URL or a procedure.
    ///
    /// Not checked against 01's playbook pattern, which is for the playbook a
    /// sweep record declares: a suggestion may be a URL. So it is untrusted
    /// text: show it, compare it, never use it as a path or a command
    /// argument.
    // Left out when `None`, like a circle member's `label`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggested: Option<String>,
    /// Whether the playbook is required: always `false` in v1, where a
    /// playbook is suggested and never required (00). Kept as written.
    pub required: bool,
    /// The fields of `playbook` this build does not know, kept for a rewrite.
    #[serde(flatten)]
    pub extra: UnknownFields,
}

/// Why [`Bounty::mark_done`] refused to rewrite a bounty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MarkDoneError {
    /// `credits` names the bounty's owner, who is never credited on their own
    /// bounty (01, "No self-credit").
    #[error("the bounty's owner cannot be credited on their own bounty")]
    OwnerCredited,
}

impl Bounty {
    /// A new bounty as `post` writes it: `status` `open`, nobody credited,
    /// `doneAt` and `reward` `null`, no unknown fields, and `open` `false`.
    ///
    /// For an open bounty, set [`open`](Self::open) afterwards. Give each
    /// target its own id: reading refuses a bounty whose ids repeat, so a
    /// record built with a repeat could not be read back.
    pub fn new(
        title: String,
        focus: Focus,
        brief: String,
        playbook: BountyPlaybook,
        targets: Vec<Target>,
        created_at: RecordTime,
    ) -> Self {
        Self {
            schema_version: SchemaVersion::CURRENT,
            title,
            focus,
            brief,
            playbook,
            targets,
            open: false,
            reward: None,
            status: KnownBountyStatus::Open.into(),
            credits: Vec::new(),
            created_at,
            done_at: None,
            extra: UnknownFields::new(),
        }
    }

    /// Parses a `bounties/<id>.json` record fetched from a homeserver.
    ///
    /// Refuses input over [`MAX_RECORD_BYTES`] with
    /// [`RecordError::TooLarge`] and a newer `schemaVersion` with
    /// [`RecordError::UnsupportedVersion`], before reading the rest; anything
    /// malformed, including a bad target id, two targets sharing an id or a
    /// credit that is not a valid key, is a [`RecordError::Json`]. An unknown
    /// `focus`, `status` or target kind is not malformed.
    pub fn from_json(input: &[u8]) -> Result<Self, RecordError> {
        parse_record(input, MAX_RECORD_BYTES)
    }

    /// The bounty's status, exactly as written.
    pub fn status(&self) -> &BountyStatus {
        &self.status
    }

    /// The sweepers the owner credited, in the order written.
    ///
    /// As read from a record, this is whatever its writer put there, and
    /// anyone can hand-write their own records: a list may name the bounty's
    /// owner or name one sweeper twice. Whoever counts credits (the trust
    /// label) skips the owner and counts each bounty once.
    // `&[Pubky]`, a borrowed slice, rather than `&Vec<Pubky>`: the caller can
    // read and iterate it without learning, or depending on, how it is
    // stored.
    pub fn credits(&self) -> &[Pubky] {
        &self.credits
    }

    /// When the bounty was marked done, or `None` (`null`) while it is not.
    // `as_ref` turns `&Option<RecordTime>` into `Option<&RecordTime>`, the
    // usual shape for an optional borrowed value.
    pub fn done_at(&self) -> Option<&RecordTime> {
        self.done_at.as_ref()
    }

    /// The bounty rewritten as done, the record `sweepky done` writes back:
    /// `status` `done`, `doneAt` set to `done_at`, and `credits` the given
    /// sweepers, each once, in the order first given.
    ///
    /// Every other field is kept exactly as read: title, brief, createdAt,
    /// the reward, every target (one of an unknown kind with all its fields),
    /// and the unknown fields at the top level and inside `playbook`. So a
    /// bounty a newer client posted survives the rewrite.
    ///
    /// `owner` is the bounty's owner, the key whose homeserver holds it; the
    /// record does not name its owner, its path does. If `credits` holds the
    /// owner, whichever spelling it was parsed from, this returns
    /// [`MarkDoneError::OwnerCredited`] and builds nothing. An empty
    /// `credits` is fine: an abandoned bounty, or one nobody else helped
    /// with, is done with nobody credited.
    ///
    /// On a bounty already done, it replaces the credits and `doneAt`: the
    /// owner may adjust credits later (01). The old list is dropped whole, so
    /// a self-credit a hand-written record held does not survive.
    ///
    /// `done_at` is the caller's, because this crate reads no clock.
    // `&self`, not `self`: the bounty is borrowed and a new one is returned,
    // so on an error the caller still has the bounty it passed in, and on
    // success it has both. The cost is one clone of the record, which is
    // small.
    //
    // `impl IntoIterator<Item = Pubky>` accepts anything that yields keys: an
    // array, a `Vec`, or `slice.iter().copied()`. The compiler writes a copy
    // of this function (and of `checked_credits`) for each type it is called
    // with.
    pub fn mark_done(
        &self,
        owner: Pubky,
        credits: impl IntoIterator<Item = Pubky>,
        done_at: RecordTime,
    ) -> Result<Self, MarkDoneError> {
        let credits = checked_credits(owner, credits)?;
        // `..self.clone()` fills every field not named here from a copy of
        // this bounty. Fields added to `Bounty` later are kept automatically,
        // with no line to forget here.
        Ok(Self {
            status: KnownBountyStatus::Done.into(),
            credits,
            done_at: Some(done_at),
            ..self.clone()
        })
    }
}

/// `credits` with each key kept once, in the order first given, or
/// [`MarkDoneError::OwnerCredited`] if any of them is `owner`.
fn checked_credits(
    owner: Pubky,
    credits: impl IntoIterator<Item = Pubky>,
) -> Result<Vec<Pubky>, MarkDoneError> {
    let mut seen = HashSet::new();
    let mut kept = Vec::new();
    for credit in credits {
        // `Pubky`'s `==` compares the 32 key bytes, never a string, so the
        // owner is caught whether it was parsed from `pubky<z32>` or raw z32.
        // Not constant-time, and it need not be: both are public keys.
        if credit == owner {
            return Err(MarkDoneError::OwnerCredited);
        }
        // `insert` returns `false` when the set already held the key, so only
        // a key's first appearance is kept and the order of first appearances
        // stays. `Pubky` is `Copy`, so the set and the list each get their own
        // copy.
        if seen.insert(credit) {
            kept.push(credit);
        }
    }
    Ok(kept)
}

/// Reads a bounty's `targets`, refusing the list when two targets share an
/// id.
// serde calls this for the field marked `deserialize_with`. `'de` is serde's
// name for how long the input being read lives; the function works for any
// such lifetime and any `Deserializer`, so it runs on serde_json's.
fn unique_targets<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<Target>, D::Error> {
    let targets = Vec::<Target>::deserialize(deserializer)?;
    // A set of `&TargetId`s borrowed from `targets`, so no id is copied. The
    // borrow ends with the loop, which is what lets `targets` be moved out
    // (returned) afterwards.
    let mut seen = HashSet::new();
    for target in &targets {
        if !seen.insert(target.id()) {
            // `custom`, from serde's `de::Error` trait, builds the
            // deserializer's own error type (the return type says which), and
            // serde_json files it as a data error at the current position.
            // `RecordError` keeps only that category and position, and the
            // text names no id, so a stranger's input never reaches the CLI's
            // output.
            return Err(serde::de::Error::custom("two targets share an id"));
        }
    }
    Ok(targets)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{Bounty, BountyPlaybook, KnownBountyStatus, KnownFocus, MarkDoneError};
    use crate::error::{JsonCategory, RecordError};
    use crate::pubky::Pubky;
    use crate::schema::{MAX_RECORD_BYTES, UnknownFields};
    use crate::target::test_support::{REV, id, path, sha};
    use crate::target::{KnownTarget, Target};
    use crate::time::RecordTime;

    /// Synthetic keys from `fixtures/trust-labels.json`: A owns the bounty,
    /// S1 and S2 swept it.
    const OWNER: &str = "ybymzxgk1zd3a7dm3i15gcuq7ewqkbimft6r1n8oc9o6uay8mqfo";
    const S1: &str = "a8fyof86uespzzjc3hiryromqy6hgw1gem5htj76jn6sto4jokhy";
    const S2: &str = "kmjs3ec6imcijf5wknsbfrh1bk4ariso7en8tteestniygu159xo";

    const TITLE: &str = "Auth and session handling before the 0.15 release";
    const BRIEF: &str = "Markdown. What to look for, context, what is out of scope, how to report. No secrets: this is public.";
    const SUGGESTED: &str = "cloudflare/security-audit@c1c8a8c";
    /// 01's example repository, rather than `test_support::REPO`.
    const REPO: &str = "github.com/org/name";
    const CREATED_AT: &str = "2026-10-15T09:30:00Z";
    const DONE_AT: &str = "2026-10-20T17:00:00Z";

    /// 01's example bounty post, with a concrete SHA and time.
    fn example() -> Value {
        json!({
            "schemaVersion": 1,
            "title": TITLE,
            "focus": "security",
            "brief": BRIEF,
            "playbook": { "suggested": SUGGESTED, "required": false },
            "targets": [
                { "id": "t1", "kind": "repo", "repo": REPO, "rev": REV, "paths": ["src/auth/"] },
            ],
            "open": false,
            "reward": null,
            "status": "open",
            "credits": [],
            "createdAt": CREATED_AT,
            "doneAt": null,
        })
    }

    /// The example with what a newer client might add: a top-level field, a
    /// field inside `playbook`, a field inside the known `repo` target, a
    /// reward (05's reserved shape) and a target of a kind this build does not
    /// know.
    fn extended() -> Value {
        let mut input = example();
        input["addedLater"] = json!({ "nested": [1, "two", null] });
        input["playbook"]["profile"] = json!("standard");
        input["targets"][0]["addedLater"] = json!({ "by": "a newer client" });
        input["reward"] = json!({
            "kind": "sats",
            "perSeverity": { "critical": 100_000, "high": 50_000, "medium": 10_000, "low": 1_000 },
            "capSats": 250_000,
        });
        input["targets"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "id": "t2", "kind": "crate", "name": "serde", "version": "1.0.229" }));
        input
    }

    fn parse(input: &Value) -> Result<Bounty, RecordError> {
        Bounty::from_json(input.to_string().as_bytes())
    }

    fn pubky(text: &str) -> Pubky {
        text.parse().unwrap()
    }

    /// The same key as `pubky(raw)`, parsed from the `pubky<z32>` spelling.
    fn prefixed(raw: &str) -> Pubky {
        pubky(&format!("pubky{raw}"))
    }

    fn time(text: &str) -> RecordTime {
        text.parse().unwrap()
    }

    fn assert_data_error(input: &Value) {
        assert!(
            matches!(
                parse(input),
                Err(RecordError::Json {
                    category: JsonCategory::Data,
                    ..
                })
            ),
            "{input}"
        );
    }

    #[test]
    fn the_01_example_round_trips() {
        let bounty = parse(&example()).unwrap();
        assert_eq!(serde_json::to_value(&bounty).unwrap(), example());
    }

    #[test]
    fn unknown_fields_and_an_unknown_target_round_trip() {
        let input = extended();
        let bounty = parse(&input).unwrap();
        assert_eq!(bounty.extra.len(), 1);
        assert_eq!(bounty.playbook.extra.len(), 1);
        assert!(bounty.reward.is_some());
        assert_eq!(bounty.targets.len(), 2);
        assert!(matches!(
            bounty.targets[0].known(),
            Ok(Some(KnownTarget::Repo(_)))
        ));
        // Kept and skipped, not an error: the bounty still parses.
        assert_eq!(bounty.targets[1].known(), Ok(None));
        assert_eq!(serde_json::to_value(&bounty).unwrap(), input);
    }

    #[test]
    fn duplicate_target_ids_are_rejected() {
        // The same id on two targets, whatever their kinds: a sweep's
        // `targets` names targets by id, so the id must pick out one.
        for second in [
            json!({ "id": "t1", "kind": "commit", "repo": REPO, "rev": REV }),
            json!({ "id": "t1", "kind": "crate", "name": "serde" }),
        ] {
            let mut input = example();
            input["targets"].as_array_mut().unwrap().push(second);
            assert_data_error(&input);
        }
    }

    #[test]
    fn a_done_record_round_trips_with_its_credits_and_done_at() {
        let mut done = example();
        done["status"] = json!("done");
        done["credits"] = json!([S1]);
        done["doneAt"] = json!(DONE_AT);
        let bounty = parse(&done).unwrap();
        assert_eq!(bounty.status().as_known(), Some(KnownBountyStatus::Done));
        assert_eq!(bounty.credits(), [pubky(S1)]);
        assert_eq!(bounty.done_at(), Some(&time(DONE_AT)));
        assert_eq!(serde_json::to_value(&bounty).unwrap(), done);
    }

    #[test]
    fn status_and_focus_are_open_labels() {
        let bounty = parse(&example()).unwrap();
        assert_eq!(bounty.status().as_known(), Some(KnownBountyStatus::Open));
        assert_eq!(bounty.focus.as_known(), Some(KnownFocus::Security));

        // Values a newer client might write: kept as written, unknown here.
        let mut future = example();
        future["status"] = json!("archived");
        future["focus"] = json!("a11y");
        let bounty = parse(&future).unwrap();
        assert_eq!(bounty.status().as_known(), None);
        assert_eq!(bounty.status().as_str(), "archived");
        assert_eq!(bounty.focus.as_known(), None);
        assert_eq!(bounty.focus.as_str(), "a11y");
        assert_eq!(serde_json::to_value(&bounty).unwrap(), future);
    }

    #[test]
    fn new_writes_an_open_bounty_with_only_01s_fields() {
        let playbook = BountyPlaybook {
            suggested: Some(SUGGESTED.to_owned()),
            required: false,
            extra: UnknownFields::new(),
        };
        let target = Target::repo(
            id("t1"),
            REPO.parse().unwrap(),
            sha(REV),
            vec![path("src/auth/")],
        );
        let bounty = Bounty::new(
            TITLE.to_owned(),
            KnownFocus::Security.into(),
            BRIEF.to_owned(),
            playbook,
            vec![target],
            time(CREATED_AT),
        );
        // Exactly 01's keys: nothing else, so nothing from a sweep's findings.
        assert_eq!(serde_json::to_value(&bounty).unwrap(), example());
    }

    #[test]
    fn a_newer_version_is_refused() {
        let mut input = example();
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
        // A valid bounty padded with JSON whitespace to one byte over the cap.
        let mut bytes = example().to_string().into_bytes();
        bytes.resize(MAX_RECORD_BYTES + 1, b' ');
        assert_eq!(
            Bounty::from_json(&bytes).unwrap_err(),
            RecordError::TooLarge {
                limit: MAX_RECORD_BYTES,
                len: MAX_RECORD_BYTES + 1
            }
        );
    }

    #[test]
    fn mark_done_keeps_every_field_it_does_not_set() {
        let input = extended();
        let bounty = parse(&input).unwrap();
        let done = bounty
            .mark_done(pubky(OWNER), [pubky(S1), pubky(S2)], time(DONE_AT))
            .unwrap();

        // Unknown fields (top-level, inside `playbook` and inside the known
        // target), the unknown target and its fields, the reward, title, brief
        // and createdAt: all as read.
        let mut expected = input.clone();
        expected["status"] = json!("done");
        expected["credits"] = json!([S1, S2]);
        expected["doneAt"] = json!(DONE_AT);
        assert_eq!(serde_json::to_value(&done).unwrap(), expected);
        // The record it was made from is untouched.
        assert_eq!(serde_json::to_value(&bounty).unwrap(), input);
    }

    #[test]
    fn mark_done_refuses_the_owner_in_either_spelling() {
        let bounty = parse(&example()).unwrap();
        let owner = pubky(OWNER);

        // The owner in either spelling is the same key bytes, so either is
        // refused, wherever it sits in the list.
        for credits in [[pubky(S1), pubky(OWNER)], [prefixed(OWNER), pubky(S1)]] {
            assert_eq!(
                bounty.mark_done(owner, credits, time(DONE_AT)),
                Err(MarkDoneError::OwnerCredited)
            );
        }
        // The same when the owner itself was given in the other spelling.
        assert_eq!(
            bounty.mark_done(prefixed(OWNER), [pubky(OWNER)], time(DONE_AT)),
            Err(MarkDoneError::OwnerCredited)
        );
    }

    #[test]
    fn mark_done_with_no_credits_is_an_abandoned_bounty() {
        let bounty = parse(&example()).unwrap();
        let abandoned = bounty.mark_done(pubky(OWNER), [], time(DONE_AT)).unwrap();
        assert_eq!(abandoned.status().as_known(), Some(KnownBountyStatus::Done));
        assert!(abandoned.credits().is_empty());
        assert_eq!(abandoned.done_at(), Some(&time(DONE_AT)));
    }

    #[test]
    fn mark_done_keeps_each_credit_once_in_first_seen_order() {
        // Duplicates, in either spelling, go; first-seen order stays.
        let bounty = parse(&example()).unwrap();
        let credits = [pubky(S2), pubky(S1), prefixed(S2), pubky(S1)];
        let done = bounty
            .mark_done(pubky(OWNER), credits, time(DONE_AT))
            .unwrap();
        assert_eq!(done.credits(), [pubky(S2), pubky(S1)]);
    }

    #[test]
    fn mark_done_replaces_a_self_credited_list() {
        // A hand-written record may already credit its owner. Reading keeps
        // that (the read side ignores it), and the rewrite replaces the list.
        let mut self_credited = example();
        self_credited["status"] = json!("done");
        self_credited["credits"] = json!([OWNER, S1]);
        self_credited["doneAt"] = json!(CREATED_AT);
        let bounty = parse(&self_credited).unwrap();
        assert_eq!(bounty.credits(), [pubky(OWNER), pubky(S1)]);

        let rewritten = bounty
            .mark_done(pubky(OWNER), [pubky(S2)], time(DONE_AT))
            .unwrap();
        assert_eq!(rewritten.credits(), [pubky(S2)]);
    }
}
