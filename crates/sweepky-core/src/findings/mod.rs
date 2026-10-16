//! The common findings format: [`Findings`], each [`Finding`] in it, and the
//! [`Location`]s a finding points at (01, "The sweep package"). The rules
//! that hold for all three are on [`Findings`], because this module is
//! private and only the re-exported types appear in the crate's docs.
//!
//! [`parse_audit_findings`] reads the findings a sweeper's agent left in
//! either format, the common one or Cloudflare's, which the `cloudflare`
//! module converts.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::RecordError;
use crate::names::Playbook;
use crate::open_enum::open_enum;
use crate::schema::{MAX_FINDINGS_BYTES, SchemaVersion, UnknownFields, check_size, parse_record};

mod cloudflare;

pub use cloudflare::{
    CloudflareField, ConvertError, from_cloudflare, is_cloudflare_shape, to_cloudflare,
};

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
/// `findings.json`, or leaves Cloudflare's output for the CLI to convert
/// ([`parse_audit_findings`] reads either); the sweep package carries it as
/// `findings`.
///
/// **Sealed content.** This type, [`Finding`] and [`Location`] exist only
/// inside the encrypted sweep package and in the owner's decrypted copies.
/// No public record has a field of any of them, and none may get one: `/pub/`
/// is world-readable, and even a severity count on a public repo is a
/// disclosure (01). Errors from [`from_json`](Self::from_json) are
/// [`RecordError`]s, which carry a category, a line and a column, never the
/// text that failed.
///
/// **`Debug` shows counts, not content.** The three types' `Debug` is written
/// by hand: it prints the type's name, the schema version and how many
/// findings, locations, `extra` fields and unknown fields there are, and `..`
/// for the rest, so a `{:?}` in a log line, an error or a panic message
/// carries no string an agent wrote, and no line number either. A failing
/// `assert_eq!` on them prints the counts only; compare their
/// `serde_json::to_value` to see what differs. Serializing still writes
/// everything, so it is no way to log them either: show findings to the
/// owner on purpose, not by accident.
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
// `Debug` is not derived, because the derived one prints every field: the
// hand-written impl below prints counts only. The same goes for `Finding` and
// `Location`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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
///
/// Its `Debug` prints counts only, as on [`Findings`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// ([`from_cloudflare`]) keeps the original record here, under
    /// `cloudflare`, so [`to_cloudflare`] can rebuild it exactly.
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
///
/// Its `Debug` prints counts only, as on [`Findings`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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

// The three `Debug` impls below share one shape. Each first takes the value
// apart with a `let Self { .. } = self;` that names every field and has no
// `..` of its own, so a field added to the struct later is a compile error
// here until someone decides whether it may print. The fields bound to `_`
// are the ones that never print: text, open strings and line numbers, all
// written by the sweeper's agent. `finish_non_exhaustive` writes the `..` that
// says fields were left out.

/// Prints `Findings { schema_version: SchemaVersion(1), findings: 2,
/// locations: 3, unknown_fields: 0, .. }`: the schema version and counts,
/// never the content. `locations` is the total over every finding.
impl fmt::Debug for Findings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            schema_version,
            playbook: _,
            findings,
            unknown,
        } = self;
        // The sum cannot overflow: every `Location` it counts is in memory,
        // so there are far fewer than `usize::MAX` of them.
        let locations: usize = findings.iter().map(|finding| finding.locations.len()).sum();
        f.debug_struct("Findings")
            .field("schema_version", schema_version)
            .field("findings", &findings.len())
            .field("locations", &locations)
            .field("unknown_fields", &unknown.len())
            .finish_non_exhaustive()
    }
}

/// Prints `Finding { locations: 2, extra_fields: Some(1), unknown_fields: 0,
/// .. }`: how many locations, `extra` fields (`None` when there is no
/// `extra`) and unknown fields it has, never the content. Not even `status`,
/// `severity` or `confidence` print, since an agent writes those strings too.
impl fmt::Debug for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            id: _,
            title: _,
            severity: _,
            confidence: _,
            status: _,
            locations,
            description: _,
            fix: _,
            extra,
            unknown,
        } = self;
        f.debug_struct("Finding")
            .field("locations", &locations.len())
            // `as_ref` borrows the map inside the `Option` instead of moving
            // it out of `self`, and `Map::len` then counts its keys.
            .field("extra_fields", &extra.as_ref().map(Map::len))
            .field("unknown_fields", &unknown.len())
            .finish_non_exhaustive()
    }
}

/// Prints `Location { unknown_fields: 0, .. }`: neither the file, the line,
/// the kind nor the scope, which together say where the problem is.
impl fmt::Debug for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            file: _,
            line: _,
            kind: _,
            scope: _,
            unknown,
        } = self;
        f.debug_struct("Location")
            .field("unknown_fields", &unknown.len())
            .finish_non_exhaustive()
    }
}

/// Which format [`parse_audit_findings`] found an audit's findings in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingsSource {
    /// Sweepky's common format, a JSON object, read as it is.
    Common,
    /// Cloudflare's `findings.json`, a JSON array, converted with
    /// [`from_cloudflare`].
    Cloudflare,
}

/// Reads the findings a sweeper's agent left, in the common format or in
/// Cloudflare's, as the common [`Findings`], and says which it was.
///
/// This is what `submit` calls on the `findings.json` in a sweep directory.
/// The format is detected by shape, after the bytes parse as JSON:
///
/// - **An object** is the common format, read with [`Findings::from_json`]
///   and its `schemaVersion` check. `playbook` is not used: the document
///   names its own, and the checked name is the manifest's.
/// - **An array** is Cloudflare's, converted with [`from_cloudflare`] and
///   `playbook` as the document's playbook. The common format is never an
///   array, so an array whose items do not all carry `verdict` and
///   `fingerprint` (01's rule, [`is_cloudflare_shape`]) is not some third
///   format but a broken Cloudflare file: the error names the first item that
///   is not a record, by index. An empty array converts to no findings.
/// - **Anything else** is a [`ConvertError::UnknownShape`].
///
/// The input is agent-written and untrusted. Input over
/// [`MAX_FINDINGS_BYTES`] is refused before parsing, with
/// [`RecordError::TooLarge`] inside [`ConvertError::Record`]; serde_json's
/// recursion limit stays on; malformed input is an error, never a panic; and
/// no error quotes the input.
pub fn parse_audit_findings(
    input: &[u8],
    playbook: &Playbook,
) -> Result<(Findings, FindingsSource), ConvertError> {
    // `?` turns the `RecordError` into a `ConvertError` through the `#[from]`
    // on `ConvertError::Record`.
    check_size(input, MAX_FINDINGS_BYTES)?;
    // `?` applies one `From` conversion, and there are two steps here
    // (serde_json's error to `RecordError`, then to `ConvertError`), so
    // `map_err` takes the first, keeping only the category and position.
    let document: Value = serde_json::from_slice(input).map_err(RecordError::from)?;
    match document {
        // `records` takes the array's `Vec` out of `document` without a copy,
        // and `from_cloudflare` moves each record on into its finding.
        Value::Array(records) => Ok((
            from_cloudflare(records, playbook)?,
            FindingsSource::Cloudflare,
        )),
        Value::Object(_) => {
            // The `Value` was only for telling the formats apart. Drop it
            // before parsing the bytes again into the typed `Findings`, so
            // the two never sit in memory together.
            drop(document);
            Ok((Findings::from_json(input)?, FindingsSource::Common))
        }
        _ => Err(ConvertError::UnknownShape),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Map, Value, json};

    use super::cloudflare::test_support::{FIXTURE, fixture, playbook};
    use super::{
        CloudflareField, ConvertError, Findings, FindingsSource, KnownConfidence,
        KnownFindingStatus, KnownLocationKind, KnownSeverity, is_cloudflare_shape,
        parse_audit_findings,
    };
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

    fn audit(input: &[u8]) -> Result<(Findings, FindingsSource), ConvertError> {
        parse_audit_findings(input, &playbook())
    }

    #[test]
    fn a_cloudflare_array_is_converted_with_the_callers_playbook() {
        // A top-level array whose items carry `verdict` and `fingerprint`.
        // Cloudflare's file names no playbook, so the caller's is used.
        assert!(is_cloudflare_shape(&Value::Array(fixture())));
        let (findings, source) = audit(FIXTURE.as_bytes()).unwrap();
        assert_eq!(source, FindingsSource::Cloudflare);
        assert_eq!(findings.findings.len(), 3);
        assert_eq!(findings.playbook, playbook().as_str());
    }

    #[test]
    fn an_empty_array_is_a_cloudflare_run_that_found_nothing() {
        assert!(is_cloudflare_shape(&json!([])));
        let (findings, source) = audit(b" [ ] ").unwrap();
        assert_eq!(source, FindingsSource::Cloudflare);
        assert!(findings.findings.is_empty());
    }

    #[test]
    fn an_object_is_read_as_the_common_format_with_its_own_playbook() {
        // `bare()` names a playbook other than the caller's, so reading it as
        // it is shows the caller's playbook is not used.
        let common = bare();
        assert_ne!(common["playbook"], playbook().as_str());
        assert!(!is_cloudflare_shape(&common));
        let (findings, source) = audit(common.to_string().as_bytes()).unwrap();
        assert_eq!(source, FindingsSource::Common);
        assert_eq!(serde_json::to_value(&findings).unwrap(), common);
    }

    #[test]
    fn a_json_scalar_is_an_unknown_shape() {
        for scalar in ["null", "true", "7", r#""findings""#] {
            assert!(!is_cloudflare_shape(&serde_json::from_str(scalar).unwrap()));
            assert_eq!(
                audit(scalar.as_bytes()).unwrap_err(),
                ConvertError::UnknownShape
            );
        }
    }

    #[test]
    fn an_array_item_that_is_not_a_cloudflare_record_is_named_by_index() {
        // The common format is never an array, so an array that mixes
        // Cloudflare records with anything else is a broken Cloudflare file;
        // the error names the first item that is not a record.
        let mut items = fixture();
        items.insert(1, json!({ "title": "no verdict or fingerprint" }));
        let mixed = Value::Array(items.clone());
        assert!(!is_cloudflare_shape(&mixed));
        assert_eq!(
            audit(mixed.to_string().as_bytes()).unwrap_err(),
            ConvertError::Missing {
                index: 1,
                field: CloudflareField::Key("fingerprint")
            }
        );
        items[1] = json!(1);
        let mixed = Value::Array(items);
        assert!(!is_cloudflare_shape(&mixed));
        assert_eq!(
            audit(mixed.to_string().as_bytes()).unwrap_err(),
            ConvertError::NotAnObject { index: 1 }
        );
    }

    #[test]
    fn audit_findings_over_the_cap_are_refused_before_parsing() {
        // At the findings cap an empty array padded with JSON whitespace
        // converts; one byte more is refused before any parsing, so input
        // that is not JSON at all gets the same answer.
        let mut input = b"[]".to_vec();
        input.resize(MAX_FINDINGS_BYTES, b' ');
        assert!(audit(&input).is_ok());
        let too_large = ConvertError::Record(RecordError::TooLarge {
            limit: MAX_FINDINGS_BYTES,
            len: MAX_FINDINGS_BYTES + 1,
        });
        input.push(b' ');
        assert_eq!(audit(&input).unwrap_err(), too_large);
        assert_eq!(
            audit(&vec![b'['; MAX_FINDINGS_BYTES + 1]).unwrap_err(),
            too_large
        );
    }

    #[test]
    fn malformed_audit_findings_are_an_error_that_never_quotes_them() {
        // Malformed JSON, and nesting past serde_json's recursion limit, are
        // errors that never quote the input, not a panic or a stack overflow.
        const MARKER: &str = "MARKER-7f3a";
        let deep = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));
        for input in [format!(r#"[{{"fingerprint":"{MARKER}",}}]"#), deep] {
            let err = audit(input.as_bytes()).unwrap_err();
            assert!(
                matches!(err, ConvertError::Record(RecordError::Json { .. })),
                "{err:?}"
            );
            assert!(!err.to_string().contains(MARKER), "{err}");
        }
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

    #[test]
    fn debug_never_prints_finding_content() {
        // P1a's carry-forward: decrypted findings are owner-only content, so a
        // `{:?}` in a log line, an error or a panic message must not carry
        // any. Every string an agent writes holds the marker here: each text
        // field, each open string, and every key and value of `extra` (its
        // `cloudflare` record included) and of the `unknown` maps. The line is
        // not text, but it is content too, so it gets a marker of its own.
        const MARKER: &str = "MARKER-7f3a";
        const LINE: u64 = 987_654_321;
        // `json!` takes an expression as a key, so `MARKER: MARKER` is a field
        // named by the marker with the marker as its value.
        let location = || {
            json!({
                "file": format!("src/{MARKER}.rs"),
                "line": LINE,
                "kind": MARKER,
                "scope": format!("fn {MARKER}"),
                MARKER: MARKER,
            })
        };
        let finding = |locations: usize| {
            json!({
                "id": MARKER,
                "title": MARKER,
                "severity": MARKER,
                "confidence": MARKER,
                "status": MARKER,
                "locations": vec![location(); locations],
                "description": MARKER,
                "fix": MARKER,
                "extra": { "cloudflare": { "title": MARKER, MARKER: MARKER }, MARKER: MARKER },
                MARKER: MARKER,
            })
        };
        let input = json!({
            "schemaVersion": 1,
            "playbook": MARKER,
            "findings": [finding(2), finding(1)],
            MARKER: MARKER,
        });
        // The premise: the content is all there, and serializing (which is
        // not a way to log it either) still writes every field of it.
        let findings = round_trip(&input);

        let finding = &findings.findings[0];
        let location = &finding.locations[0];
        // Each case: the `{:?}` and `{:#?}` output, and the exact `{:?}`
        // output expected (the type, its counts and `..` for the fields left
        // out). `{:#?}` is the same fields laid out one per line.
        let cases = [
            (
                format!("{findings:?}"),
                format!("{findings:#?}"),
                "Findings { schema_version: SchemaVersion(1), findings: 2, locations: 3, \
                 unknown_fields: 1, .. }",
            ),
            (
                format!("{finding:?}"),
                format!("{finding:#?}"),
                "Finding { locations: 2, extra_fields: Some(2), unknown_fields: 1, .. }",
            ),
            (
                format!("{location:?}"),
                format!("{location:#?}"),
                "Location { unknown_fields: 1, .. }",
            ),
        ];
        for (compact, pretty, expected) in cases {
            assert_eq!(compact, expected);
            for debug in [compact, pretty] {
                assert!(!debug.contains(MARKER), "{debug}");
                assert!(!debug.contains(&LINE.to_string()), "{debug}");
            }
        }
    }
}
