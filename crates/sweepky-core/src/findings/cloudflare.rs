//! The converter between Cloudflare's `findings.json` and the common findings
//! format (01, "The sweep package").
//!
//! Cloudflare's `security-audit` skill, at the commit the plan pins
//! (`c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`), writes its findings as one
//! top-level JSON array, described by `skills/security-audit/report-schema.json`
//! in its repository. Each item is one of three records, told apart by
//! `verdict`: `confirmed`, `needs_validation` or `rejected`. Only a
//! `confirmed` record carries `severity`, `confidence` and `remediation`.
//! [`from_cloudflare`] turns the array into [`Findings`], keeping each whole
//! record in its finding's `extra.cloudflare`, and [`to_cloudflare`] rebuilds
//! the array from there.

use std::fmt;

use serde::Deserialize;
use serde_json::{Map, Value};

use super::{
    Confidence, Finding, FindingStatus, Findings, KnownConfidence, KnownFindingStatus,
    KnownSeverity, Location, Severity,
};
use crate::error::RecordError;
use crate::names::Playbook;
use crate::schema::{SchemaVersion, UnknownFields};

/// The key in a converted finding's `extra` that holds the original record.
const CLOUDFLARE: &str = "cloudflare";

/// Why an audit's findings could not be read, converted or rebuilt.
///
/// Like [`RecordError`], every variant holds positions and fixed text, never
/// text from the findings: findings are sealed content, and an error may end
/// up in a terminal or a bug report. A position counts from 0, as JSON array
/// indexes do.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConvertError {
    /// The input is over [`MAX_FINDINGS_BYTES`](crate::MAX_FINDINGS_BYTES),
    /// is not JSON, or is a common-format document that does not parse.
    // `transparent` hands `Display` and `source()` straight to the
    // `RecordError` inside, and `#[from]` writes the `From<RecordError>` that
    // lets `?` convert one. Keeping the whole error is safe here, unlike
    // serde_json's: a `RecordError` never quotes its input.
    #[error(transparent)]
    Record(#[from] RecordError),
    /// The document is neither a JSON object (the common format) nor a JSON
    /// array (Cloudflare's).
    #[error(
        "findings are neither the common format (a JSON object) nor Cloudflare's (a JSON array)"
    )]
    UnknownShape,
    /// An item of Cloudflare's array is not a JSON object.
    #[error("Cloudflare finding {index} is not a JSON object")]
    NotAnObject {
        /// The item's position in the array.
        index: usize,
    },
    /// A field the converter needs is missing from a Cloudflare record.
    #[error("Cloudflare finding {index}: {field} is missing")]
    Missing {
        /// The record's position in the array.
        index: usize,
        /// Where the field is in the record.
        field: CloudflareField,
    },
    /// A field of a Cloudflare record holds the wrong kind of value.
    #[error("Cloudflare finding {index}: {field} is not {expected}")]
    Malformed {
        /// The record's position in the array.
        index: usize,
        /// Where the field is in the record.
        field: CloudflareField,
        /// What the field should hold.
        expected: &'static str,
    },
    /// [`to_cloudflare`] found a finding with no record in `extra.cloudflare`,
    /// so it was not converted from Cloudflare's format.
    #[error("finding {index} has no Cloudflare record in extra.cloudflare")]
    NotFromCloudflare {
        /// The finding's position in `findings`.
        index: usize,
    },
}

/// Where in one Cloudflare record a [`ConvertError`] is. Its `Display` is the
/// JSON path: `fingerprint`, `severity.overall_severity`, `trace[2]` or
/// `trace[2].line`.
// Only `&'static str` and numbers: the keys are this file's own literals, so
// a field can never carry text from the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudflareField {
    /// A key of the record, or a dotted path to a key in one of its objects.
    Key(&'static str),
    /// An entry of the record's `trace` or `evidence` list, or, when `key` is
    /// set, a key inside that entry.
    Entry {
        /// The list: `trace` or `evidence`.
        list: &'static str,
        /// The entry's position in the list.
        entry: usize,
        /// The key inside the entry, if the problem is in one.
        key: Option<&'static str>,
    },
}

impl fmt::Display for CloudflareField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Key(key) => f.write_str(key),
            Self::Entry {
                list,
                entry,
                key: None,
            } => write!(f, "{list}[{entry}]"),
            Self::Entry {
                list,
                entry,
                key: Some(key),
            } => write!(f, "{list}[{entry}].{key}"),
        }
    }
}

/// Whether `document` has the shape of Cloudflare's `findings.json`: a
/// top-level array whose items are objects that carry `verdict` and
/// `fingerprint` (01's detection rule).
///
/// An empty array counts: it is a run that found nothing, and Cloudflare's
/// schema allows it. Only the keys are looked at; [`from_cloudflare`] checks
/// their values, and accepts only arrays this is `true` for.
/// [`parse_audit_findings`](crate::parse_audit_findings) reads bytes in
/// either format, so a caller with bytes rarely needs this.
pub fn is_cloudflare_shape(document: &Value) -> bool {
    let Value::Array(items) = document else {
        return false;
    };
    // `all` is `true` for an empty array, which is the rule above.
    // `is_some_and` is `false` for an item that is not an object.
    items.iter().all(|item| {
        item.as_object().is_some_and(|record| {
            record.contains_key("verdict") && record.contains_key("fingerprint")
        })
    })
}

/// Converts the items of Cloudflare's `findings.json` array to the common
/// [`Findings`], one finding per record, in order.
///
/// Cloudflare's file names no playbook, so the document's `playbook` is the
/// one given: the playbook `submit` names in the manifest.
///
/// | Common field | From the Cloudflare record |
/// |---|---|
/// | `id` | `fingerprint`, a non-empty string |
/// | `title`, `description` | `title`, `description`, both strings |
/// | `status` | `verdict`, any string, kept as written |
/// | `severity` | on a `confirmed` record only, `severity.overall_severity`: `informational` becomes `info`, and `low`, `medium`, `high` and `critical` stay as they are |
/// | `confidence` | on a `confirmed` record only, `confidence.score`: `low`, `medium` or `high` |
/// | `locations` | each `trace` entry with its `file`, `line`, `kind` and `scope`, then each `evidence` entry with its `file` and `line` only |
/// | `fix` | `remediation.strategy` |
/// | `extra` | `{"cloudflare": <the whole record>}` |
///
/// **Severity is never invented.** It is `null` unless the verdict is exactly
/// `confirmed` and `overall_severity` is one of Cloudflare's five values; a
/// missing or other value, or any other verdict, gives `null`, even if the
/// record carries a `severity` that Cloudflare's schema does not allow there.
/// `confidence` follows the same rule.
///
/// `remediation.code_changes` (whole fixed files, not a diff) do not go into
/// `fix`; they stay in `extra.cloudflare` with the rest of the record, which
/// [`to_cloudflare`] gives back unchanged.
///
/// The record is untrusted, so reading it is strict about types and lenient
/// about presence. A field the table reads must hold the type Cloudflare's
/// schema gives it, and a `line` must be a whole number of 1 or more;
/// otherwise the conversion fails with a [`ConvertError`] naming the record's
/// index and the field, never its content. `fingerprint`, `verdict`, `title`
/// and `description`, and each location's `file`, must be present; anything
/// else may be left out, which gives an empty or `null` value. A field the
/// table does not read is not checked at all, only kept.
// `records` is taken by value, a `Vec` the caller hands over, so each record
// can be moved into its finding's `extra.cloudflare` instead of copied: the
// input can be up to 16 MiB. A caller that wants to keep the original clones
// it first, as the tests do. Taking a `Vec<Value>` rather than any `Value`
// also means the type itself says "an array": there is no "not an array"
// error to handle.
pub fn from_cloudflare(records: Vec<Value>, playbook: &Playbook) -> Result<Findings, ConvertError> {
    // Collecting an iterator of `Result`s into `Result<Vec<_>, _>` stops at the
    // first `Err` and returns it, so one bad record fails the conversion.
    let findings = records
        .into_iter()
        .enumerate()
        .map(|(index, record)| convert_record(index, record))
        .collect::<Result<Vec<Finding>, ConvertError>>()?;
    Ok(Findings {
        schema_version: SchemaVersion::CURRENT,
        playbook: playbook.as_str().to_owned(),
        findings,
        unknown: UnknownFields::new(),
    })
}

/// Rebuilds Cloudflare's `findings.json` array from findings that
/// [`from_cloudflare`] produced: each finding's `extra.cloudflare`, in order.
///
/// The result equals the array that was converted, value for value, whatever
/// was changed in the common fields since. A finding without an object in
/// `extra.cloudflare`, such as one written in the common format directly, is a
/// [`ConvertError::NotFromCloudflare`].
// `&Findings`: the caller keeps its findings, and the records are cloned out.
pub fn to_cloudflare(findings: &Findings) -> Result<Vec<Value>, ConvertError> {
    findings
        .findings
        .iter()
        .enumerate()
        .map(|(index, finding)| {
            // `and_then` looks inside `extra` only when there is one; the
            // pattern `record @ Value::Object(_)` matches an object and names
            // the whole value `record`.
            match finding
                .extra
                .as_ref()
                .and_then(|extra| extra.get(CLOUDFLARE))
            {
                Some(record @ Value::Object(_)) => Ok(record.clone()),
                _ => Err(ConvertError::NotFromCloudflare { index }),
            }
        })
        .collect()
}

/// Converts the record at `index` of Cloudflare's array.
fn convert_record(index: usize, record: Value) -> Result<Finding, ConvertError> {
    let Value::Object(record) = record else {
        return Err(ConvertError::NotAnObject { index });
    };
    // `Fields` borrows `record` only for this statement: `finding()` copies
    // what it needs into the `Finding` it returns, so the borrow has ended
    // and `record` can be moved into `extra` below without a copy.
    let mut finding = Fields {
        index,
        place: Place::Record,
        map: &record,
    }
    .finding()?;
    let mut extra = Map::new();
    extra.insert(CLOUDFLARE.to_owned(), Value::Object(record));
    finding.extra = Some(extra);
    Ok(finding)
}

/// Cloudflare's `overall_severity`, in the common format's words. `None` for
/// a value Cloudflare's schema does not list.
fn common_severity(overall: &str) -> Option<KnownSeverity> {
    match overall {
        "informational" => Some(KnownSeverity::Info),
        "low" => Some(KnownSeverity::Low),
        "medium" => Some(KnownSeverity::Medium),
        "high" => Some(KnownSeverity::High),
        "critical" => Some(KnownSeverity::Critical),
        _ => None,
    }
}

/// Cloudflare's `confidence.score`, in the common format's words. `None` for
/// a value Cloudflare's schema does not list.
fn common_confidence(score: &str) -> Option<KnownConfidence> {
    match score {
        "low" => Some(KnownConfidence::Low),
        "medium" => Some(KnownConfidence::Medium),
        "high" => Some(KnownConfidence::High),
        _ => None,
    }
}

/// Where a [`Fields`] sits in its record, for the errors it reports.
#[derive(Clone, Copy)]
enum Place {
    /// The record itself.
    Record,
    /// One entry of the record's `trace` or `evidence` list.
    Entry { list: &'static str, entry: usize },
}

/// One JSON object in a Cloudflare record, the record itself or one entry of
/// its `trace` or `evidence`, read with errors that say where it is.
///
/// The `'a` is the lifetime of the borrowed map: every `&'a str` a method
/// returns points into the record, not into the `Fields`, so it stays usable
/// after the `Fields` is gone.
struct Fields<'a> {
    index: usize,
    place: Place,
    map: &'a Map<String, Value>,
}

impl<'a> Fields<'a> {
    /// Reads the record into a [`Finding`], with `extra` still empty.
    fn finding(&self) -> Result<Finding, ConvertError> {
        let id = self.fingerprint()?;
        let status: FindingStatus = self.required_open("verdict")?;
        let title = self.required_str("title")?;
        let description = self.required_str("description")?;
        let mut locations = self.locations("trace", Self::trace_location)?;
        locations.extend(self.locations("evidence", Self::evidence_location)?);
        let fix = self.nested_str("remediation", "strategy", "remediation.strategy")?;
        // Never invent a severity: only a `confirmed` record's is read. The
        // others' would be refused by Cloudflare's schema, so whatever such a
        // record carries is ignored here (and kept in `extra.cloudflare`).
        let (severity, confidence) = if status.as_known() == Some(KnownFindingStatus::Confirmed) {
            self.severity_and_confidence()?
        } else {
            (None, None)
        };
        Ok(Finding {
            id: id.to_owned(),
            title: title.to_owned(),
            severity,
            confidence,
            status,
            locations,
            description: description.to_owned(),
            fix: fix.map(str::to_owned),
            extra: None,
            unknown: UnknownFields::new(),
        })
    }

    /// The record's `fingerprint`, which must be a non-empty string.
    fn fingerprint(&self) -> Result<&'a str, ConvertError> {
        let fingerprint = self.required_str("fingerprint")?;
        if fingerprint.is_empty() {
            return Err(self.malformed(self.field("fingerprint"), "a non-empty string"));
        }
        Ok(fingerprint)
    }

    /// A `confirmed` record's `severity.overall_severity` and
    /// `confidence.score`, in the common format's words. A missing value, or
    /// one outside Cloudflare's lists, gives `None`.
    fn severity_and_confidence(
        &self,
    ) -> Result<(Option<Severity>, Option<Confidence>), ConvertError> {
        let severity =
            self.nested_str("severity", "overall_severity", "severity.overall_severity")?;
        let confidence = self.nested_str("confidence", "score", "confidence.score")?;
        // `and_then` maps a present value through the lookup, which may
        // itself give `None`; `map` then wraps a known value in the open
        // enum the common format stores.
        Ok((
            severity.and_then(common_severity).map(Severity::from),
            confidence.and_then(common_confidence).map(Confidence::from),
        ))
    }

    /// The locations in the record's `trace` or `evidence` list, in order,
    /// each entry read with `read`. A missing list gives none.
    // `read` is a function pointer: `fn`, not a closure, because the readers
    // capture nothing. `Self::trace_location` names a method as a plain
    // function whose first argument is the `&Fields` it reads, so the caller
    // says how a list's entries are read instead of passing a `bool` flag.
    fn locations(
        &self,
        list: &'static str,
        read: fn(&Self) -> Result<Location, ConvertError>,
    ) -> Result<Vec<Location>, ConvertError> {
        let entries = match self.map.get(list) {
            None => return Ok(Vec::new()),
            Some(Value::Array(entries)) => entries,
            Some(_) => return Err(self.malformed(self.field(list), "a JSON array")),
        };
        entries
            .iter()
            .enumerate()
            .map(|(entry, value)| {
                let Value::Object(map) = value else {
                    let field = CloudflareField::Entry {
                        list,
                        entry,
                        key: None,
                    };
                    return Err(self.malformed(field, "a JSON object"));
                };
                read(&Fields {
                    index: self.index,
                    place: Place::Entry { list, entry },
                    map,
                })
            })
            .collect()
    }

    /// Reads a `trace` entry into a [`Location`]: the `file` and `line` an
    /// `evidence` entry has, plus the step's `kind` and `scope`.
    fn trace_location(&self) -> Result<Location, ConvertError> {
        let location = self.evidence_location()?;
        // `..location` fills every field not named here from `location`.
        Ok(Location {
            scope: self.optional_str("scope")?.map(str::to_owned),
            kind: self.optional_open("kind")?,
            ..location
        })
    }

    /// Reads an `evidence` entry into a [`Location`]: its `file` and `line`
    /// only. Cloudflare's schema gives evidence no `kind` or `scope`, so keys
    /// of those names are not read.
    fn evidence_location(&self) -> Result<Location, ConvertError> {
        Ok(Location {
            file: self.required_str("file")?.to_owned(),
            line: self.optional_line()?,
            kind: None,
            scope: None,
            unknown: UnknownFields::new(),
        })
    }

    /// The entry's `line`, a whole number of 1 or more, or `None` if the key
    /// is not there.
    fn optional_line(&self) -> Result<Option<u64>, ConvertError> {
        let Some(value) = self.map.get("line") else {
            return Ok(None);
        };
        // `as_u64` is `None` for anything but a whole number from 0 to
        // u64::MAX: a negative number, a float such as `2.5`, a string,
        // and a number past u64::MAX, which serde_json reads as a float.
        // The guard then refuses 0, below Cloudflare's minimum of 1.
        match value.as_u64() {
            Some(line) if line >= 1 => Ok(Some(line)),
            _ => Err(self.malformed(self.field("line"), "a whole number of 1 or more")),
        }
    }

    /// The string under `key`, which must be there.
    // `ok_or_else` builds the error only when the key is missing.
    fn required_str(&self, key: &'static str) -> Result<&'a str, ConvertError> {
        self.optional_str(key)?.ok_or_else(|| self.missing(key))
    }

    /// The string under `key`, or `None` if the key is not there.
    fn optional_str(&self, key: &'static str) -> Result<Option<&'a str>, ConvertError> {
        match self.map.get(key) {
            None => Ok(None),
            Some(Value::String(text)) => Ok(Some(text)),
            Some(_) => Err(self.malformed(self.field(key), "a string")),
        }
    }

    /// The string under `inner` in the object under `key`, such as
    /// `severity.overall_severity`, or `None` if either key is not there.
    /// `path` is the two keys joined by a dot, for errors.
    fn nested_str(
        &self,
        key: &'static str,
        inner: &'static str,
        path: &'static str,
    ) -> Result<Option<&'a str>, ConvertError> {
        let object = match self.map.get(key) {
            None => return Ok(None),
            Some(Value::Object(object)) => object,
            Some(_) => return Err(self.malformed(self.field(key), "a JSON object")),
        };
        match object.get(inner) {
            None => Ok(None),
            Some(Value::String(text)) => Ok(Some(text)),
            Some(_) => Err(self.malformed(CloudflareField::Key(path), "a string")),
        }
    }

    /// An open-string enum such as [`FindingStatus`] under `key`, which must
    /// be there.
    fn required_open<T: Deserialize<'a>>(&self, key: &'static str) -> Result<T, ConvertError> {
        self.optional_open(key)?.ok_or_else(|| self.missing(key))
    }

    /// An open-string enum such as [`LocationKind`](super::LocationKind)
    /// under `key`, or `None` if the key is not there.
    // An open enum has no public constructor from any string, only its
    // `Deserialize`, which takes any JSON string and nothing else. serde_json
    // implements `Deserializer` for a borrowed `&Value`, so `T::deserialize`
    // reads the value in place, the same way it would read the field of a
    // record. Its error is dropped, because serde_json's message quotes the
    // value; only "not a string" is reported. Use it for open enums only, or
    // that message would be wrong.
    fn optional_open<T: Deserialize<'a>>(
        &self,
        key: &'static str,
    ) -> Result<Option<T>, ConvertError> {
        match self.map.get(key) {
            None => Ok(None),
            Some(value) => T::deserialize(value)
                .map(Some)
                .map_err(|_| self.malformed(self.field(key), "a string")),
        }
    }

    /// Where `key` of this object is in the record.
    fn field(&self, key: &'static str) -> CloudflareField {
        match self.place {
            Place::Record => CloudflareField::Key(key),
            Place::Entry { list, entry } => CloudflareField::Entry {
                list,
                entry,
                key: Some(key),
            },
        }
    }

    fn missing(&self, key: &'static str) -> ConvertError {
        ConvertError::Missing {
            index: self.index,
            field: self.field(key),
        }
    }

    fn malformed(&self, field: CloudflareField, expected: &'static str) -> ConvertError {
        ConvertError::Malformed {
            index: self.index,
            field,
            expected,
        }
    }
}

/// The synthetic fixture and the playbook shared by the tests of this module,
/// of `findings/mod.rs` and of `package/build.rs`, so all of them read the
/// same file the same way.
// `pub(crate)` lets the parent module's tests import these, and the parent
// re-export them for the package tests; `#[cfg(test)]` leaves the module,
// and its `unwrap`s, out of every non-test build.
#[cfg(test)]
pub(crate) mod test_support {
    use serde_json::Value;

    use crate::names::Playbook;

    /// The synthetic fixture: a `confirmed`, a `needs_validation` and a
    /// `rejected` record, sorted by fingerprint.
    pub(crate) const FIXTURE: &str = include_str!("../../../../fixtures/cloudflare/findings.json");

    /// The playbook the tests convert with: Cloudflare's file names none.
    pub(crate) fn playbook() -> Playbook {
        "cloudflare/security-audit@c1c8a8c".parse().unwrap()
    }

    /// [`FIXTURE`]'s records.
    pub(crate) fn fixture() -> Vec<Value> {
        serde_json::from_str(FIXTURE).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Map, Value, json};

    use super::test_support::{fixture, playbook};
    use super::{CloudflareField, ConvertError, from_cloudflare, to_cloudflare};
    use crate::findings::{Findings, KnownConfidence, KnownFindingStatus, KnownSeverity};

    fn convert(records: Vec<Value>) -> Result<Findings, ConvertError> {
        from_cloudflare(records, &playbook())
    }

    /// A `confirmed` record written inline, with the fields the converter
    /// reads and an overall severity of `high`.
    fn confirmed_high() -> Value {
        json!({
            "verdict": "confirmed",
            "fingerprint": "inline-confirmed",
            "title": "Session token compared with ==",
            "description": "Markdown",
            "trace": [{
                "kind": "sink",
                "file": "src/auth/session.rs",
                "line": 120,
                "scope": "fn validate",
                "description": "d",
            }],
            "evidence": [{ "file": "src/auth/session.rs", "line": 120, "description": "d" }],
            "remediation": { "strategy": "Compare in constant time." },
            "severity": {
                "likelihood": { "score": "high", "reason": "r" },
                "impact": { "score": "high", "reason": "r" },
                "overall_severity": "high",
            },
            "confidence": { "score": "medium", "reason": "r" },
        })
    }

    #[test]
    fn the_fixture_holds_the_records_p1a_asks_for() {
        // At least one `confirmed` and one `needs_validation` record, sorted
        // by fingerprint as Cloudflare's validator requires.
        let records = fixture();
        let field = |key: &str| -> Vec<&str> {
            records
                .iter()
                .map(|record| record[key].as_str().unwrap())
                .collect()
        };
        assert_eq!(
            field("verdict"),
            ["confirmed", "needs_validation", "rejected"]
        );
        assert!(field("fingerprint").is_sorted());
    }

    #[test]
    fn the_fixture_converts_and_rebuilds_the_original_exactly() {
        let original = fixture();
        let findings = convert(original.clone()).unwrap();
        assert_eq!(findings.playbook, playbook().as_str());
        // Through bytes and back, the way the sweep package carries it.
        let bytes = serde_json::to_vec(&findings).unwrap();
        let read_back = Findings::from_json(&bytes).unwrap();
        assert_eq!(read_back, findings);
        assert_eq!(to_cloudflare(&read_back).unwrap(), original);
    }

    #[test]
    fn needs_validation_and_rejected_records_have_null_severity_and_confidence() {
        let findings = convert(fixture()).unwrap();
        for (finding, verdict) in findings.findings[1..]
            .iter()
            .zip(["needs_validation", "rejected"])
        {
            assert_eq!(finding.status.as_str(), verdict);
            assert_eq!(finding.severity, None);
            assert_eq!(finding.confidence, None);
        }

        // Never invented: Cloudflare's schema forbids `severity` and
        // `confidence` on a `needs_validation` record, and one that carries
        // them anyway still converts with neither.
        let mut forged = fixture()[1].clone();
        forged["severity"] = confirmed_high()["severity"].clone();
        forged["confidence"] = confirmed_high()["confidence"].clone();
        // A verdict that is not exactly `confirmed` is kept as the status, and
        // gets no severity either.
        let mut shouted = confirmed_high();
        shouted["verdict"] = json!("CONFIRMED");
        let findings = convert(vec![forged, shouted]).unwrap();
        for finding in &findings.findings {
            assert_eq!(finding.severity, None);
            assert_eq!(finding.confidence, None);
        }
        assert_eq!(findings.findings[1].status.as_str(), "CONFIRMED");
        assert_eq!(findings.findings[1].status.as_known(), None);
    }

    #[test]
    fn confirmed_records_carry_their_severity_and_confidence() {
        let findings = convert(fixture()).unwrap();
        let confirmed = &findings.findings[0];
        assert_eq!(
            confirmed.status.as_known(),
            Some(KnownFindingStatus::Confirmed)
        );
        // Cloudflare's `informational` is the common format's `info`.
        let severity = confirmed.severity.as_ref().unwrap();
        assert_eq!(
            (severity.as_known(), severity.as_str()),
            (Some(KnownSeverity::Info), "info")
        );
        let confidence = confirmed.confidence.as_ref().unwrap();
        assert_eq!(confidence.as_known(), Some(KnownConfidence::High));

        let inline = &convert(vec![confirmed_high()]).unwrap().findings[0];
        let severity = inline.severity.as_ref().unwrap();
        assert_eq!(severity.as_known(), Some(KnownSeverity::High));
        let confidence = inline.confidence.as_ref().unwrap();
        assert_eq!(confidence.as_known(), Some(KnownConfidence::Medium));
    }

    #[test]
    fn an_unknown_or_missing_confirmed_severity_or_confidence_reads_as_null() {
        // A value outside Cloudflare's lists is not guessed at, and neither is
        // a missing one.
        let mut unknown = confirmed_high();
        unknown["severity"]["overall_severity"] = json!("severe");
        unknown["confidence"]["score"] = json!("certain");
        let mut missing = confirmed_high();
        let record = missing.as_object_mut().unwrap();
        record.remove("severity");
        record.remove("confidence");
        for finding in convert(vec![unknown, missing]).unwrap().findings {
            assert_eq!(finding.severity, None);
            assert_eq!(finding.confidence, None);
        }
    }

    #[test]
    fn each_record_becomes_one_finding_with_the_record_kept_in_extra() {
        let records = fixture();
        let findings = convert(records.clone()).unwrap();
        assert_eq!(findings.findings.len(), records.len());
        for (finding, record) in findings.findings.iter().zip(&records) {
            assert_eq!(finding.id, record["fingerprint"].as_str().unwrap());
            assert_eq!(finding.title, record["title"].as_str().unwrap());
            assert_eq!(finding.description, record["description"].as_str().unwrap());
            assert_eq!(finding.extra.as_ref().unwrap()["cloudflare"], *record);
            assert!(finding.unknown.is_empty());
        }
    }

    #[test]
    fn locations_come_from_trace_then_evidence() {
        // The needs_validation record: its three trace steps with their kind
        // and scope, in order, then its two evidence entries without either.
        let findings = convert(fixture()).unwrap();
        let locations = serde_json::to_value(&findings.findings[1].locations).unwrap();
        assert_eq!(
            locations,
            json!([
                { "file": "src/auth/handler.rs", "line": 18, "kind": "entrypoint", "scope": "fn handle_request" },
                { "file": "src/auth/session.rs", "line": 64, "kind": "propagation", "scope": "fn from_header" },
                { "file": "src/auth/session.rs", "line": 120, "kind": "sink", "scope": "fn validate" },
                { "file": "src/auth/session.rs", "line": 120 },
                { "file": "src/auth/session.rs", "line": 12 },
            ])
        );
    }

    #[test]
    fn an_evidence_entry_never_gives_a_kind_or_scope() {
        // Not even when it carries keys of those names, which Cloudflare's
        // schema does not allow.
        let mut record = confirmed_high();
        record["evidence"][0]["kind"] = json!("sink");
        record["evidence"][0]["scope"] = json!("fn validate");
        let finding = &convert(vec![record]).unwrap().findings[0];
        let evidence = &finding.locations[1];
        assert_eq!((&evidence.kind, &evidence.scope), (&None, &None));
    }

    #[test]
    fn fix_is_the_remediation_strategy_alone() {
        // The code changes, whole fixed files, stay in `extra.cloudflare`.
        let records = fixture();
        let findings = convert(records.clone()).unwrap();
        let strategy = records[0]["remediation"]["strategy"].as_str();
        assert_eq!(findings.findings[0].fix.as_deref(), strategy);
        // Records without a remediation have no fix.
        assert_eq!(findings.findings[1].fix, None);
        assert_eq!(findings.findings[2].fix, None);
    }

    #[test]
    fn malformed_records_are_an_error_naming_the_index_and_field_never_the_content() {
        const MARKER: &str = "MARKER-7f3a";
        // Every string an error could quote holds the marker.
        let valid = || {
            let mut record = confirmed_high();
            for key in ["fingerprint", "title", "description"] {
                record[key] = json!(MARKER);
            }
            record["trace"][0]["file"] = json!(MARKER);
            record["trace"][0]["scope"] = json!(MARKER);
            record
        };
        let with = |path: &str, value: Value| {
            let mut record = valid();
            *record.pointer_mut(path).unwrap() = value;
            record
        };
        let without = |key: &str| {
            let mut record = valid();
            record.as_object_mut().unwrap().remove(key);
            record
        };
        let key = CloudflareField::Key;
        let entry = |list, entry, key| CloudflareField::Entry { list, entry, key };
        let malformed = |field, expected| ConvertError::Malformed {
            index: 1,
            field,
            expected,
        };
        let line = "a whole number of 1 or more";
        // Past u64::MAX, which serde_json reads as a float.
        let huge: Value = serde_json::from_str("18446744073709551616").unwrap();
        let mut no_file = valid();
        no_file["trace"][0].as_object_mut().unwrap().remove("file");

        let cases = [
            (json!(MARKER), ConvertError::NotAnObject { index: 1 }),
            (json!([MARKER]), ConvertError::NotAnObject { index: 1 }),
            (
                without("fingerprint"),
                ConvertError::Missing {
                    index: 1,
                    field: key("fingerprint"),
                },
            ),
            (
                with("/fingerprint", json!("")),
                malformed(key("fingerprint"), "a non-empty string"),
            ),
            (
                with("/fingerprint", json!(7)),
                malformed(key("fingerprint"), "a string"),
            ),
            (
                with("/verdict", json!(1)),
                malformed(key("verdict"), "a string"),
            ),
            (
                without("title"),
                ConvertError::Missing {
                    index: 1,
                    field: key("title"),
                },
            ),
            (
                with("/trace", json!(MARKER)),
                malformed(key("trace"), "a JSON array"),
            ),
            (
                with("/trace/0", json!(MARKER)),
                malformed(entry("trace", 0, None), "a JSON object"),
            ),
            (
                no_file,
                ConvertError::Missing {
                    index: 1,
                    field: entry("trace", 0, Some("file")),
                },
            ),
            (
                with("/trace/0/line", json!(-3)),
                malformed(entry("trace", 0, Some("line")), line),
            ),
            (
                with("/trace/0/line", json!(2.5)),
                malformed(entry("trace", 0, Some("line")), line),
            ),
            (
                with("/trace/0/line", huge),
                malformed(entry("trace", 0, Some("line")), line),
            ),
            (
                with("/trace/0/line", json!(0)),
                malformed(entry("trace", 0, Some("line")), line),
            ),
            (
                with("/evidence/0/line", json!("120")),
                malformed(entry("evidence", 0, Some("line")), line),
            ),
            (
                with("/severity/overall_severity", json!(3)),
                malformed(key("severity.overall_severity"), "a string"),
            ),
        ];
        for (record, expected) in cases {
            // The bad record comes second, so the index must point past the
            // good one.
            let err = convert(vec![valid(), record]).unwrap_err();
            assert_eq!(err, expected);
            let message = err.to_string();
            assert!(message.starts_with("Cloudflare finding 1"), "{message}");
            assert!(!message.contains(MARKER), "{message}");
            assert!(!format!("{err:?}").contains(MARKER), "{err:?}");
        }

        let err = convert(vec![valid(), with("/trace/0/line", json!(-3))]).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Cloudflare finding 1: trace[0].line is not a whole number of 1 or more"
        );
    }

    #[test]
    fn a_finding_not_converted_from_cloudflare_cannot_be_rebuilt() {
        let mut findings = convert(fixture()).unwrap();
        findings.findings[2].extra = None;
        let not_converted = ConvertError::NotFromCloudflare { index: 2 };
        assert_eq!(to_cloudflare(&findings).unwrap_err(), not_converted);
        findings.findings[2].extra = Some(Map::new());
        assert_eq!(to_cloudflare(&findings).unwrap_err(), not_converted);
    }
}
