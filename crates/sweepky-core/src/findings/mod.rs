//! The common findings format: [`Findings`], each [`Finding`] in it, and the
//! [`Location`]s a finding points at (01, "The sweep package"). The rules
//! that hold for all three are on [`Findings`], because this module is
//! private and only the re-exported types appear in the crate's docs.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::RecordError;
use crate::open_enum::open_enum;
use crate::schema::{MAX_FINDINGS_BYTES, SchemaVersion, UnknownFields, parse_record};

open_enum! {
    /// A finding's `status`: what the playbook concluded about it.
    pub struct FindingStatus;

    /// The finding statuses this build knows.
    pub enum KnownFindingStatus {
        /// The playbook established the finding. Under Cloudflare's rules
        /// that needs an observed local execution result, so a static-only
        /// sweep has few of these.
        Confirmed = "confirmed",
        /// Found, but not yet shown to be real.
        NeedsValidation = "needs_validation",
        /// Looked into and found not to be a problem.
        Rejected = "rejected",
    }
}

open_enum! {
    /// A finding's `severity`, when the playbook established one.
    pub struct Severity;

    /// The severities this build knows, from most to least severe.
    pub enum KnownSeverity {
        /// Critical.
        Critical = "critical",
        /// High.
        High = "high",
        /// Medium.
        Medium = "medium",
        /// Low.
        Low = "low",
        /// Informational: worth knowing, not a problem by itself.
        Info = "info",
    }
}

open_enum! {
    /// A finding's `confidence`, when the playbook established one.
    pub struct Confidence;

    /// The confidence levels this build knows.
    pub enum KnownConfidence {
        /// High.
        High = "high",
        /// Medium.
        Medium = "medium",
        /// Low.
        Low = "low",
    }
}

open_enum! {
    /// The `kind` of a [`Location`]: the part it plays in the finding.
    pub struct LocationKind;

    /// The location kinds this build knows: the steps of a trace from where
    /// input enters to where it does harm.
    pub enum KnownLocationKind {
        /// Where the input enters the code.
        Entrypoint = "entrypoint",
        /// A step the input passes through on the way.
        Propagation = "propagation",
        /// Where the problem happens. The owner's CLI groups findings by
        /// file plus the enclosing scope of their sink (P1b).
        Sink = "sink",
    }
}

/// A findings document: `{schemaVersion, playbook, findings}` (01, "The
/// sweep package").
///
/// Every playbook's output ends up in this one small shape, so the owner's
/// tooling can group findings from any sweep. A sweeper's agent writes it as
/// `findings.json`, or leaves Cloudflare's output for the CLI to convert; the
/// sweep package carries it as `findings`.
///
/// **Sealed content.** This type, [`Finding`] and [`Location`] exist only
/// inside the encrypted sweep package and in the owner's decrypted copies.
/// No public record has a field of any of them, and none may get one: `/pub/`
/// is world-readable, and even a severity count on a public repo is a
/// disclosure (01). Errors from [`from_json`](Self::from_json) are
/// [`RecordError`]s, which carry a category, a line and a column, never the
/// text that failed. `Debug` is derived and prints the content, so never log
/// a value of these types; show findings to the owner on purpose, not by
/// accident.
///
/// **Agents write this.** Every text field is whatever the sweeper's agent
/// wrote after reading untrusted code, so it is untrusted text: show it,
/// compare it, never run it or use it as a path. That is also why the strings
/// here are not checked the way names in public records are: a finding the
/// agent spelled oddly is still a finding.
///
/// **Open strings.** A finding's `status`, `severity` and `confidence` and a
/// location's `kind` are open-string enums with `as_known()`, so a value a
/// newer playbook adds parses and is written back unchanged.
///
/// **Unknown fields** are kept at each level (here, on [`Finding`] and on
/// [`Location`]) in a `#[serde(flatten)]` map named `unknown`, not `extra` as
/// on the public records, because a finding has a real JSON field called
/// `extra`.
// `PartialEq` and `Eq` let tests compare whole documents; every field's
// equality is total (a serde_json number is never NaN), as on the records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Findings {
    /// The document's `schemaVersion`.
    pub schema_version: SchemaVersion,
    /// The playbook that produced the findings, as the agent wrote it.
    ///
    /// A plain `String`, not a [`Playbook`](crate::Playbook): the agent
    /// writes this file, and a playbook name outside 01's pattern should not
    /// cost the sweep its findings. The checked name is the manifest's
    /// `playbook`, which `submit` writes. Untrusted text.
    pub playbook: String,
    /// The findings, in the order the playbook listed them. Empty when the
    /// sweep found nothing.
    pub findings: Vec<Finding>,
    /// The top-level fields this build does not know, kept for a rewrite.
    // `flatten` puts these keys beside `schemaVersion`, `playbook` and
    // `findings` in the JSON, not under a key of their own, so the Rust name
    // `unknown` never appears on the wire.
    #[serde(flatten)]
    pub unknown: UnknownFields,
}

/// One finding: `{id, title, severity, confidence, status, locations,
/// description, fix?, extra?}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    /// An id local to the sweep that wrote it. Two sweeps may name one bug
    /// differently and different bugs alike, so grouping never keys on it;
    /// equal ids are only a second hint (01).
    pub id: String,
    /// A one-line title. Untrusted text.
    pub title: String,
    /// The severity, or `None` when the playbook did not establish one, which
    /// is the usual case for a static-only sweep. Always written, as `null`
    /// when `None`; a missing key reads as `None`.
    // No `skip_serializing_if`, unlike `fix` below: 01 shows `severity` on
    // every finding, `null` included. `default` is what lets a missing key
    // read as `None` instead of failing the document.
    #[serde(default)]
    pub severity: Option<Severity>,
    /// The confidence, or `None` when the playbook did not establish one.
    /// Written like `severity`.
    #[serde(default)]
    pub confidence: Option<Confidence>,
    /// What the playbook concluded.
    pub status: FindingStatus,
    /// Where in the code the finding points, in the order the playbook gave
    /// them (Cloudflare's trace, then its evidence).
    pub locations: Vec<Location>,
    /// What the finding is, in Markdown. Untrusted text.
    pub description: String,
    /// A suggested fix, in Markdown or as a diff, if the playbook gave one.
    /// Untrusted: the owner's agent never applies an untrusted sweep's fix
    /// without a human (02). Left out when `None`; `null` reads as `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
    /// The JSON field `extra`: whatever the playbook keeps with a finding
    /// that the common fields have no place for. The Cloudflare converter
    /// keeps the original record here, under `cloudflare`, so it can be
    /// rebuilt exactly.
    ///
    /// Not the unknown-field map, which is [`unknown`](Self::unknown).
    // `Option` around the map, so that a missing `extra` and an empty one
    // (`{}`) each come back as written: `None` is left out, `Some` of an
    // empty map is written as `{}`. A `null` reads as `None` and is then
    // left out. `Map<String, Value>` is the same type as `UnknownFields`,
    // named plainly here because this is a field of the format, not the
    // catch-all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<Map<String, Value>>,
    /// The fields of this finding this build does not know, kept for a
    /// rewrite.
    // With `flatten`, serde first matches each key against the named fields
    // (`extra` among them) and collects only the rest here, so a JSON key
    // `extra` always lands in the field `extra`, and the two never mix.
    #[serde(flatten)]
    pub unknown: UnknownFields,
}

/// A place in the code a finding points at: `{file, line?, kind?, scope?}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Location {
    /// The file, as the playbook wrote it, normally relative to the target's
    /// root. Not checked as a [`RepoPath`](crate::RepoPath): an agent's
    /// absolute or odd path is still worth grouping on. Compare and show it;
    /// never open it.
    pub file: String,
    /// The line, counting from 1, if the playbook gave one. Left out when
    /// `None`.
    // `u64`, so a negative or fractional line is a parse error rather than
    // a silent rounding. Not checked to be at least 1: a 0 is kept as
    // written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u64>,
    /// The part this place plays in the finding, if the playbook said. Left
    /// out when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<LocationKind>,
    /// The enclosing function, method or other scope, as the playbook named
    /// it (`fn validate`). Left out when `None`. Untrusted text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The fields of this location this build does not know, kept for a
    /// rewrite.
    #[serde(flatten)]
    pub unknown: UnknownFields,
}

impl Findings {
    /// Parses a findings document, such as the `findings.json` a sweeper's
    /// agent wrote.
    ///
    /// Refuses input over [`MAX_FINDINGS_BYTES`] with
    /// [`RecordError::TooLarge`] and a newer `schemaVersion` with
    /// [`RecordError::UnsupportedVersion`], before reading the rest; anything
    /// malformed is a [`RecordError::Json`], which never quotes the input. An
    /// unknown `status`, `severity`, `confidence` or location `kind` is not
    /// malformed.
    ///
    /// Inside a sweep package the document is one field of a larger one;
    /// the package's own parse reads it there, with the package's cap (P1b).
    pub fn from_json(input: &[u8]) -> Result<Self, RecordError> {
        // The findings cap, not `MAX_RECORD_BYTES`: findings carry Markdown
        // descriptions and fixes, and are far longer than a public record.
        parse_record(input, MAX_FINDINGS_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Map, Value, json};

    use super::{Findings, KnownConfidence, KnownFindingStatus, KnownLocationKind, KnownSeverity};
    use crate::error::{JsonCategory, RecordError};
    use crate::schema::{MAX_FINDINGS_BYTES, MAX_RECORD_BYTES};

    /// 01's common-format example, filled in the way a static-only sweep
    /// leaves it: `severity` and `confidence` `null`, a fix, an `extra`
    /// object, and one field this build does not know at each level.
    fn example() -> Value {
        json!({
            "schemaVersion": 1,
            "playbook": "cloudflare/security-audit@c1c8a8c",
            "findings": [{
                "id": "sweep-local-id",
                "title": "Session token compared with ==",
                "severity": null,
                "confidence": null,
                "status": "needs_validation",
                "locations": [{
                    "file": "src/auth/session.rs",
                    "line": 120,
                    "kind": "sink",
                    "scope": "fn validate",
                    "column": 9,
                }],
                "description": "Markdown",
                "fix": "Compare in constant time.",
                "extra": { "tool": { "name": "synthetic", "runs": [1, 2.5, null] } },
                "addedLater": true,
            }],
            // Named after the Rust field that keeps unknown keys: in JSON it
            // is just another unknown key.
            "unknown": { "by": "a newer client" },
        })
    }

    /// [`example`] with the value at the JSON pointer `path` replaced.
    fn example_with(path: &str, value: Value) -> Value {
        let mut input = example();
        *input.pointer_mut(path).unwrap() = value;
        input
    }

    /// A finding with no fix and no `extra`, at a location with a file alone.
    fn bare() -> Value {
        json!({
            "schemaVersion": 1,
            "playbook": "my own careful review",
            "findings": [{
                "id": "f1",
                "title": "t",
                "severity": "low",
                "confidence": "low",
                "status": "confirmed",
                "locations": [{ "file": "src/lib.rs" }],
                "description": "d",
            }],
        })
    }

    fn parse(input: &Value) -> Result<Findings, RecordError> {
        Findings::from_json(input.to_string().as_bytes())
    }

    /// Parses `input`, checks it writes back as the same JSON value, and
    /// returns what it parsed.
    fn round_trip(input: &Value) -> Findings {
        let findings = parse(input).unwrap();
        assert_eq!(serde_json::to_value(&findings).unwrap(), *input);
        findings
    }

    #[test]
    fn the_common_format_example_round_trips_with_unknown_fields_at_each_level() {
        let findings = round_trip(&example());
        assert_eq!(findings.playbook, "cloudflare/security-audit@c1c8a8c");
        assert_eq!(findings.unknown.keys().collect::<Vec<_>>(), ["unknown"]);

        let [finding] = findings.findings.as_slice() else {
            panic!("expected one finding, got {}", findings.findings.len());
        };
        assert_eq!(finding.severity, None);
        assert_eq!(finding.confidence, None);
        assert_eq!(
            finding.status.as_known(),
            Some(KnownFindingStatus::NeedsValidation)
        );
        assert_eq!(finding.fix.as_deref(), Some("Compare in constant time."));
        // `extra` is a real field: its content stays under it, and the
        // unknown key beside it goes to `unknown`, not into `extra`.
        let extra = finding.extra.as_ref().unwrap();
        assert_eq!(extra.keys().collect::<Vec<_>>(), ["tool"]);
        assert_eq!(finding.unknown.keys().collect::<Vec<_>>(), ["addedLater"]);

        let [location] = finding.locations.as_slice() else {
            panic!("expected one location, got {}", finding.locations.len());
        };
        assert_eq!(location.file, "src/auth/session.rs");
        assert_eq!(location.line, Some(120));
        // P1b groups by file plus the sink's scope, so a sink must be
        // recognisable.
        let kind = location.kind.as_ref().unwrap();
        assert_eq!(kind.as_known(), Some(KnownLocationKind::Sink));
        assert_eq!(location.scope.as_deref(), Some("fn validate"));
        assert_eq!(location.unknown.keys().collect::<Vec<_>>(), ["column"]);
    }

    #[test]
    fn every_known_value_maps_through_as_known() {
        // The exact strings 01 lists, so a typo in a constant (say
        // "needs-validation") fails here. Each case starts from `example()`,
        // so no case depends on the one before.
        let severities = [
            ("critical", KnownSeverity::Critical),
            ("high", KnownSeverity::High),
            ("medium", KnownSeverity::Medium),
            ("low", KnownSeverity::Low),
            ("info", KnownSeverity::Info),
        ];
        let confidences = [
            ("high", KnownConfidence::High),
            ("medium", KnownConfidence::Medium),
            ("low", KnownConfidence::Low),
        ];
        let statuses = [
            ("confirmed", KnownFindingStatus::Confirmed),
            ("needs_validation", KnownFindingStatus::NeedsValidation),
            ("rejected", KnownFindingStatus::Rejected),
        ];
        let kinds = [
            ("entrypoint", KnownLocationKind::Entrypoint),
            ("propagation", KnownLocationKind::Propagation),
            ("sink", KnownLocationKind::Sink),
        ];
        for (text, known) in severities {
            let findings = round_trip(&example_with("/findings/0/severity", json!(text)));
            let severity = findings.findings[0].severity.as_ref().unwrap();
            assert_eq!(severity.as_known(), Some(known));
        }
        for (text, known) in confidences {
            let findings = round_trip(&example_with("/findings/0/confidence", json!(text)));
            let confidence = findings.findings[0].confidence.as_ref().unwrap();
            assert_eq!(confidence.as_known(), Some(known));
        }
        for (text, known) in statuses {
            let findings = round_trip(&example_with("/findings/0/status", json!(text)));
            assert_eq!(findings.findings[0].status.as_known(), Some(known));
        }
        for (text, known) in kinds {
            let input = example_with("/findings/0/locations/0/kind", json!(text));
            let findings = round_trip(&input);
            let kind = findings.findings[0].locations[0].kind.as_ref().unwrap();
            assert_eq!(kind.as_known(), Some(known));
        }
    }

    #[test]
    fn unknown_status_severity_confidence_and_location_kind_round_trip() {
        let mut input = example();
        input["findings"][0]["status"] = json!("duplicate");
        input["findings"][0]["severity"] = json!("urgent");
        input["findings"][0]["confidence"] = json!("certain");
        input["findings"][0]["locations"][0]["kind"] = json!("source");

        let findings = round_trip(&input);
        let finding = &findings.findings[0];
        let status = &finding.status;
        assert_eq!((status.as_known(), status.as_str()), (None, "duplicate"));
        let severity = finding.severity.as_ref().unwrap();
        assert_eq!((severity.as_known(), severity.as_str()), (None, "urgent"));
        let confidence = finding.confidence.as_ref().unwrap();
        assert_eq!(
            (confidence.as_known(), confidence.as_str()),
            (None, "certain")
        );
        let kind = finding.locations[0].kind.as_ref().unwrap();
        assert_eq!((kind.as_known(), kind.as_str()), (None, "source"));
    }

    #[test]
    fn the_optional_parts_can_be_left_out() {
        let findings = round_trip(&bare());
        let finding = &findings.findings[0];
        assert_eq!(finding.fix, None);
        assert_eq!(finding.extra, None);
        let location = &finding.locations[0];
        assert_eq!(location.line, None);
        assert_eq!(location.kind, None);
        assert_eq!(location.scope, None);
    }

    #[test]
    fn a_null_fix_or_extra_reads_as_absent_and_is_left_out() {
        let mut input = bare();
        input["findings"][0]["fix"] = Value::Null;
        input["findings"][0]["extra"] = Value::Null;
        let findings = parse(&input).unwrap();
        assert_eq!(findings.findings[0].fix, None);
        assert_eq!(findings.findings[0].extra, None);
        assert_eq!(serde_json::to_value(&findings).unwrap(), bare());
    }

    #[test]
    fn an_empty_extra_is_kept_as_an_empty_object() {
        // Not dropped: a missing `extra` and `{}` each come back as written.
        let mut input = bare();
        input["findings"][0]["extra"] = json!({});
        assert_eq!(round_trip(&input).findings[0].extra, Some(Map::new()));
    }

    #[test]
    fn a_sweep_that_found_nothing_round_trips() {
        let mut input = bare();
        input["findings"] = json!([]);
        assert!(round_trip(&input).findings.is_empty());
    }

    #[test]
    fn a_missing_severity_or_confidence_reads_as_null_and_is_written_as_null() {
        // 01 shows both keys on every finding, `null` included. An agent
        // that leaves one out still gets its findings read.
        let mut input = example();
        let finding = input["findings"][0].as_object_mut().unwrap();
        finding.remove("severity");
        finding.remove("confidence");
        let findings = parse(&input).unwrap();
        assert_eq!(findings.findings[0].severity, None);
        assert_eq!(findings.findings[0].confidence, None);
        assert_eq!(serde_json::to_value(&findings).unwrap(), example());
    }

    #[test]
    fn a_newer_version_is_refused() {
        let input = example_with("/schemaVersion", json!(2));
        assert_eq!(
            parse(&input).unwrap_err(),
            RecordError::UnsupportedVersion {
                found: 2,
                supported: 1
            }
        );
    }

    #[test]
    fn input_over_the_findings_cap_is_refused() {
        // A `const` block runs the assertion at compile time: both caps are
        // constants, so a change that made them equal fails the build.
        const { assert!(MAX_FINDINGS_BYTES > MAX_RECORD_BYTES) };
        // Padded with JSON whitespace: at the findings cap, far above the
        // public-record cap, it parses; one byte more is refused.
        let mut input = example().to_string().into_bytes();
        input.resize(MAX_FINDINGS_BYTES, b' ');
        assert!(Findings::from_json(&input).is_ok());
        input.push(b' ');
        assert_eq!(
            Findings::from_json(&input).unwrap_err(),
            RecordError::TooLarge {
                limit: MAX_FINDINGS_BYTES,
                len: MAX_FINDINGS_BYTES + 1
            }
        );
    }

    #[test]
    fn malformed_findings_are_an_error_that_never_quotes_them() {
        // Once decrypted, findings are sealed content: an error message may
        // end up in a terminal or a bug report, so it must not carry any.
        const MARKER: &str = "MARKER-7f3a";
        let wrong_type = |path: &str| example_with(path, json!(MARKER)).to_string();
        let deep = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));
        let cases = [
            // serde_json's own message quotes a string of the wrong type.
            wrong_type("/findings/0/locations/0/line"),
            wrong_type("/findings/0/extra"),
            wrong_type("/findings"),
            // A syntax error right after the marker.
            format!(r#"{{"schemaVersion":1,"playbook":"{MARKER}","findings":[],}}"#),
            // Nesting past serde_json's recursion limit, inside `extra`.
            example()
                .to_string()
                .replace(r#""tool":"#, &format!(r#""{MARKER}":{deep},"tool":"#)),
            // Cut off in the middle of a finding.
            example().to_string().chars().take(120).collect(),
        ];
        // The premise: serde_json's message would have leaked the marker.
        let raw = serde_json::from_str::<Findings>(&cases[0]).unwrap_err();
        assert!(raw.to_string().contains(MARKER));

        for input in &cases {
            let err = Findings::from_json(input.as_bytes()).unwrap_err();
            assert!(
                matches!(
                    err,
                    RecordError::Json {
                        category: JsonCategory::Data | JsonCategory::Syntax | JsonCategory::Eof,
                        ..
                    }
                ),
                "{err:?}"
            );
            assert!(!err.to_string().contains(MARKER), "{err}");
            assert!(!format!("{err:?}").contains(MARKER), "{err:?}");
        }
    }
}
