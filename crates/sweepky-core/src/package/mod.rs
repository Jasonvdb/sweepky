//! The sweep package (01, "The sweep package"): [`SweepPackage`], the one
//! JSON document inside a sweep's `.age` file, and its [`Attachments`].
//!
//! No archive format and no compression (01). Sealing goes
//! [`SweepPackage::to_padded`], then [`encrypt`](crate::encrypt); opening
//! goes [`decrypt`](crate::decrypt), then [`SweepPackage::from_json`]. Turning
//! a sweep directory's files into a package and back is built on these.

use std::collections::BTreeMap;
use std::fmt;
use std::io;

use serde::{Deserialize, Deserializer, Serialize};

use crate::crypto::{PaddedPlaintext, PaddingError, PaddingWriter};
use crate::error::RecordError;
use crate::findings::Findings;
use crate::names::AttachmentPath;
use crate::records::Manifest;
use crate::schema::{MAX_PACKAGE_BYTES, SchemaVersion, UnknownFields, parse_record};

/// `findings.json`: the file a sweep's findings are read from and written
/// back to, and so the one name a package's [`Attachments`] refuse as a key.
///
/// In a package the findings are their own field, [`SweepPackage::findings`].
/// An attachment by this name would be a second `findings.json` when the
/// package is split back into files, so the map refuses it however it
/// arrives. Only this exact top-level name is reserved: `audit/findings.json`
/// is an ordinary attachment.
pub const FINDINGS_FILE: &str = "findings.json";

/// Why a sweep package could not be built or padded.
///
/// Like the padding and sealing errors, it holds no data, so it can never
/// carry a byte of the package into a log line. Reading a package fails with
/// a [`RecordError`] instead, like every other parse in this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PackageError {
    /// [`FINDINGS_FILE`] was given as an attachment's path.
    #[error("findings.json is the package's findings and cannot be an attachment")]
    ReservedName,
    /// The package's JSON is longer than [`MAX_PACKAGE_BYTES`] (32 MiB).
    /// Counted before the padded buffer is allocated.
    #[error("the sweep package is larger than the 32 MiB limit")]
    TooLarge,
    /// serde_json failed to write the package, or wrote a different length
    /// the second time than it counted the first. Neither happens to these
    /// types (every map key is a string, and writing to memory cannot fail);
    /// the variant exists so that [`SweepPackage::to_padded`] returns an
    /// error rather than panicking if one ever did.
    #[error("the sweep package could not be serialized")]
    Serialize,
}

/// A sweep package: `{schemaVersion, manifest, findings, attachments?}`
/// (01, "The sweep package"), the one JSON document a sweep's `.age` file
/// holds.
///
/// **Sealed content.** Everything here is for the bounty's owner (and the
/// sweeper) only. Reading one goes through [`from_json`](Self::from_json),
/// which never quotes the input in an error, and writing one for
/// [`encrypt`](crate::encrypt) through [`to_padded`](Self::to_padded).
///
/// **`Debug` shows structure and counts, never content.** It prints the
/// schema version, the [`Manifest`] and the [`Findings`] through their own
/// `Debug` (the manifest's typed fields, which echo the public records, and
/// counts for the rest), and only how many attachments and unknown fields
/// there are. There is no `Display`. Serializing still writes everything, so
/// it is no way to log one either.
///
/// **Not wiped.** The strings in a package (the findings' text, the
/// attachments) are ordinary `String`s and are not zeroized when dropped.
/// Only the byte buffers on the way in and out of age are:
/// [`PaddedPlaintext`] and [`Plaintext`](crate::Plaintext).
///
/// **Unknown fields** are kept in [`extra`](Self::extra) for a rewrite, like
/// on the public records.
// `Debug` is not derived, because the derived one would print every
// attachment and unknown field in full; the hand-written impl is below.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SweepPackage {
    /// The package's `schemaVersion`. The manifest has none of its own; the
    /// findings carry theirs.
    pub schema_version: SchemaVersion,
    /// What the sweep covers: sweeper, bounty, targets and their commits.
    /// The owner's CLI checks it against the sweep record and its path.
    pub manifest: Manifest,
    /// The findings, in the common format.
    pub findings: Findings,
    /// The other text files the playbook produced, by relative path. 01
    /// marks the field optional: a missing key or `null` reads as no
    /// attachments, and an empty map is left out when writing.
    // `default` fills a missing key with `Attachments::default()`, an empty
    // map. `deserialize_with` reads a present one, `null` included.
    // `skip_serializing_if` leaves an empty map out, so a package written
    // without the key writes back the same.
    #[serde(
        default,
        deserialize_with = "Attachments::deserialize_or_null",
        skip_serializing_if = "Attachments::is_empty"
    )]
    pub attachments: Attachments,
    /// The top-level fields this build does not know, kept for a rewrite.
    #[serde(flatten)]
    pub extra: UnknownFields,
}

impl SweepPackage {
    /// A package of the current schema version with `manifest` and
    /// `findings`, no attachments and no unknown fields. Add attachments
    /// through [`Attachments::insert`].
    // `manifest` and `findings` are taken by value and moved in, so nothing
    // is copied.
    pub fn new(manifest: Manifest, findings: Findings) -> Self {
        Self {
            schema_version: SchemaVersion::CURRENT,
            manifest,
            findings,
            attachments: Attachments::default(),
            extra: UnknownFields::new(),
        }
    }

    /// Parses a package, such as the plaintext [`decrypt`](crate::decrypt)
    /// returns, padding included: JSON reads the trailing spaces as
    /// whitespace, so nothing has to strip them first.
    ///
    /// This is the crate's one record parse with the package's cap:
    ///
    /// - Input over [`MAX_PACKAGE_BYTES`] is a [`RecordError::TooLarge`],
    ///   before a byte of it is parsed.
    /// - `schemaVersion` is read on its own first, and a newer one is a
    ///   [`RecordError::UnsupportedVersion`]. The findings' own
    ///   `schemaVersion` is checked as they are read, so a newer one there
    ///   is a [`RecordError::Json`].
    /// - Anything malformed is a [`RecordError::Json`], which never quotes
    ///   the input: a missing manifest or findings, a manifest reference
    ///   that fails its check, an unclean [`AttachmentPath`], or
    ///   [`FINDINGS_FILE`] as an attachment. One bad part rejects the whole
    ///   package.
    pub fn from_json(input: &[u8]) -> Result<Self, RecordError> {
        // The package cap, not `MAX_RECORD_BYTES`: the findings alone may be
        // 16 MiB, and the attachments come on top.
        parse_record(input, MAX_PACKAGE_BYTES)
    }

    /// Serializes the package and pads it with spaces to the next
    /// [`PADDING_BUCKET_BYTES`](crate::PADDING_BUCKET_BYTES) bucket, ready
    /// for [`encrypt`](crate::encrypt).
    ///
    /// It serializes twice. The first pass only counts the bytes, so a
    /// package over the cap is refused before anything is allocated. The
    /// second writes them straight into a [`Zeroizing`](crate::Zeroizing)
    /// buffer allocated once at the padded size, which refuses more than the
    /// counted bytes and so never grows; then the rest of the bucket is
    /// filled with spaces. No other buffer ever holds the package's JSON.
    ///
    /// # Errors
    ///
    /// [`PackageError::TooLarge`] when the JSON is longer than
    /// [`MAX_PACKAGE_BYTES`]; [`PackageError::Serialize`] if serde_json
    /// fails, which these types never make it do.
    pub fn to_padded(&self) -> Result<PaddedPlaintext, PackageError> {
        let package_len = self.json_len()?;
        // A `match` with no `_ =>` arm, so a new `PaddingError` variant is a
        // compile error here until someone maps it.
        let mut writer = PaddingWriter::new(package_len).map_err(|err| match err {
            PaddingError::TooLarge => PackageError::TooLarge,
        })?;
        self.write_json(&mut writer)?;
        writer.finish().ok_or(PackageError::Serialize)
    }

    /// `to_padded`'s first pass: the length of the package's JSON, counted
    /// without keeping a byte of it.
    fn json_len(&self) -> Result<usize, PackageError> {
        let mut counter = ByteCounter(0);
        self.write_json(&mut counter)?;
        Ok(counter.0)
    }

    /// Writes the package's JSON to `out`, for both of `to_padded`'s passes.
    // `map_err(|_| …)` drops serde_json's error, whose message could quote a
    // value, and keeps only the fact that it failed. The callers pass
    // `&mut writer`: std implements `io::Write` for `&mut W` too, so they
    // lend their writer and still own it afterwards.
    fn write_json(&self, out: impl io::Write) -> Result<(), PackageError> {
        serde_json::to_writer(out, self).map_err(|_| PackageError::Serialize)
    }
}

/// Prints the schema version, the manifest and the findings through their
/// own redacting `Debug`, then `attachments` and `extra_fields` as counts:
/// `SweepPackage { schema_version: SchemaVersion(1), manifest: Manifest {
/// …, extra_fields: 0 }, findings: Findings { …, .. }, attachments: 2,
/// extra_fields: 0 }`.
impl fmt::Debug for SweepPackage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Naming every field, with no `..`, makes a field added later a
        // compile error here until someone decides whether it may print.
        let Self {
            schema_version,
            manifest,
            findings,
            attachments,
            extra,
        } = self;
        // Every field is accounted for, the last two by their counts, so the
        // output ends with `}` (`finish`), not `..`.
        f.debug_struct("SweepPackage")
            .field("schema_version", schema_version)
            .field("manifest", manifest)
            .field("findings", findings)
            .field("attachments", &attachments.len())
            .field("extra_fields", &extra.len())
            .finish()
    }
}

/// A sweep package's `attachments`: relative path → UTF-8 text, for what the
/// playbook produced besides the findings (01).
///
/// Every key is an [`AttachmentPath`], so none can name a place outside the
/// sweep's directory, and none is [`FINDINGS_FILE`]: both ways in, reading
/// JSON and [`insert`](Self::insert) (or `TryFrom` a map), refuse that name,
/// so no package, parsed or built, holds two entries that split to
/// `findings.json`. Two keys that differ only in case are both kept; the
/// code that writes them to disk must refuse that (P2c). If JSON repeats a
/// key, the later entry wins, as in the manifest's `targetShas`.
///
/// Its `Debug` prints how many attachments it holds, never a path or a byte
/// of the text.
// A `BTreeMap` iterates in key order, so writing a package twice gives the
// same JSON, which `to_padded`'s two passes rely on. The field is private,
// so code outside this module cannot reach the map to skip the check.
// `Serialize` on a one-field tuple struct writes the field alone, a plain
// JSON object. `try_from` makes deserializing read the map, then run
// `TryFrom` below, so JSON goes through the same check as code.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "BTreeMap<AttachmentPath, String>")]
pub struct Attachments(BTreeMap<AttachmentPath, String>);

impl Attachments {
    /// Adds an attachment, or replaces the text of one already at `path`,
    /// and returns the text it replaced.
    ///
    /// # Errors
    ///
    /// [`PackageError::ReservedName`] when `path` is [`FINDINGS_FILE`]. The
    /// map is then unchanged.
    // `path` and `text` are taken by value and moved into the map, so the
    // text is never copied.
    pub fn insert(
        &mut self,
        path: AttachmentPath,
        text: String,
    ) -> Result<Option<String>, PackageError> {
        if is_reserved(&path) {
            return Err(PackageError::ReservedName);
        }
        Ok(self.0.insert(path, text))
    }

    /// The text of the attachment at `path`, if there is one.
    pub fn get(&self, path: &AttachmentPath) -> Option<&str> {
        // `map(String::as_str)` turns the `Option<&String>` the map lends
        // into an `Option<&str>`, still borrowed from the map.
        self.0.get(path).map(String::as_str)
    }

    /// Every attachment, in path order.
    // The returned iterator borrows `self`: in edition 2024 an `impl Trait`
    // return type captures the lifetime of `&self` without being told.
    pub fn iter(&self) -> impl Iterator<Item = (&AttachmentPath, &str)> {
        self.0.iter().map(|(path, text)| (path, text.as_str()))
    }

    /// How many attachments there are.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Reads `attachments` as written, or `null` as none, the way a `null`
    /// optional field reads as absent elsewhere in this crate.
    // `Option<Self>` reads `null` as `None` and anything else through
    // `Self`'s own `Deserialize`, reserved name check included.
    // `unwrap_or_default` turns `None` into an empty map; it cannot panic.
    fn deserialize_or_null<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Option::<Self>::deserialize(deserializer)?.unwrap_or_default())
    }
}

/// Checks a whole map the way [`Attachments::insert`] checks one entry.
/// Deserializing goes through this.
impl TryFrom<BTreeMap<AttachmentPath, String>> for Attachments {
    type Error = PackageError;

    /// [`PackageError::ReservedName`] when a key is [`FINDINGS_FILE`].
    fn try_from(map: BTreeMap<AttachmentPath, String>) -> Result<Self, PackageError> {
        if map.keys().any(is_reserved) {
            return Err(PackageError::ReservedName);
        }
        Ok(Self(map))
    }
}

/// Prints `Attachments { len: 2, .. }`: how many, never a path or the text.
impl fmt::Debug for Attachments {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Attachments")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// Whether `path` is the one name a package's attachments may not use.
/// Case-sensitive on purpose: `FINDINGS.json` is a different path here, and
/// a case-insensitive filesystem is the writer's to check.
fn is_reserved(path: &AttachmentPath) -> bool {
    path.as_str() == FINDINGS_FILE
}

/// An `io::Write` that keeps nothing and counts the bytes written to it:
/// what `json_len` writes into to learn the package's length without
/// allocating a buffer for it.
struct ByteCounter(usize);

impl io::Write for ByteCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        // `saturating_add` stops at `usize::MAX` instead of overflowing; any
        // count that large is over the cap and refused anyway.
        self.0 = self.0.saturating_add(bytes.len());
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use age::secrecy::ExposeSecret;
    use serde_json::{Value, json};

    use super::{Attachments, FINDINGS_FILE, PackageError, SweepPackage};
    use crate::crypto::PADDING_BUCKET_BYTES;
    use crate::error::{JsonCategory, RecordError};
    use crate::names::AttachmentPath;
    use crate::schema::{MAX_PACKAGE_BYTES, SchemaVersion};

    /// Sweeper S1 and owner A from `fixtures/trust-labels.json`.
    const SWEEPER: &str = "a8fyof86uespzzjc3hiryromqy6hgw1gem5htj76jn6sto4jokhy";
    const OWNER: &str = "ybymzxgk1zd3a7dm3i15gcuq7ewqkbimft6r1n8oc9o6uay8mqfo";
    /// One of A's bounty ids.
    const BOUNTY_ID: &str = "0035G87EK4XFE";
    const REV: &str = "4444444444444444444444444444444444444444";
    /// Text no output may contain: errors and `Debug` never quote content.
    const MARKER: &str = "MARKER-7f3a";

    /// 01's sweep-package example, filled in with synthetic values: a
    /// manifest, one finding in the common format, and the two attachments
    /// 01 names.
    fn example() -> Value {
        json!({
            "schemaVersion": 1,
            "manifest": {
                "sweeper": SWEEPER,
                "bounty": format!("pubky://{OWNER}/pub/sweepky/bounties/{BOUNTY_ID}.json"),
                "targets": ["t1"],
                "targetShas": { "t1": REV },
                "playbook": "cloudflare/security-audit@c1c8a8c",
                "startedAt": "2026-10-16T08:00:00Z",
                "finishedAt": "2026-10-16T09:10:00Z",
            },
            "findings": {
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
                    }],
                    "description": "Markdown",
                }],
            },
            "attachments": {
                "REPORT.md": "# Report\n",
                "coverage-ledger.json": "{\"files\": []}\n",
            },
        })
    }

    fn parse(input: &Value) -> Result<SweepPackage, RecordError> {
        SweepPackage::from_json(input.to_string().as_bytes())
    }

    fn path(value: &str) -> AttachmentPath {
        value.parse().unwrap()
    }

    /// Asserts that `err` is a JSON shape error and that neither its message
    /// nor its `Debug` quotes the marker.
    fn assert_quiet_json_error(err: &RecordError, context: &str) {
        assert!(
            matches!(
                err,
                RecordError::Json {
                    category: JsonCategory::Data | JsonCategory::Syntax,
                    ..
                }
            ),
            "{context}: {err:?}"
        );
        assert!(!err.to_string().contains(MARKER), "{context}: {err}");
        assert!(!format!("{err:?}").contains(MARKER), "{context}: {err:?}");
    }

    #[test]
    fn package_round_trips_with_unknown_fields() {
        let mut input = example();
        input["addedLater"] = json!({ "by": "a newer client" });
        let package = parse(&input).unwrap();
        assert_eq!(package.schema_version, SchemaVersion::CURRENT);
        assert_eq!(package.findings.findings.len(), 1);
        assert_eq!(package.attachments.len(), 2);
        assert_eq!(
            package.attachments.get(&path("REPORT.md")),
            Some("# Report\n")
        );
        assert_eq!(package.extra.len(), 1);
        assert_eq!(serde_json::to_value(&package).unwrap(), input);
    }

    #[test]
    fn attachments_are_optional() {
        // `attachments` is optional (01). Without it, or with `null`, a
        // package has none, and an empty map is left out when written.
        let mut without = example();
        without.as_object_mut().unwrap().remove("attachments");
        let package = parse(&without).unwrap();
        assert!(package.attachments.is_empty());
        assert_eq!(serde_json::to_value(&package).unwrap(), without);
        let mut null = example();
        null["attachments"] = Value::Null;
        assert!(parse(&null).unwrap().attachments.is_empty());
    }

    #[test]
    fn a_package_over_the_cap_is_refused_before_parsing() {
        // P1a's carry-forward: the envelope goes through `parse_record`, with
        // the package cap. At the cap a package parses, padding and all; one
        // byte more is refused before a byte of it is parsed.
        let mut input = example().to_string().into_bytes();
        input.resize(MAX_PACKAGE_BYTES, b' ');
        assert!(SweepPackage::from_json(&input).is_ok());
        input.push(b' ');
        let too_large = RecordError::TooLarge {
            limit: MAX_PACKAGE_BYTES,
            len: MAX_PACKAGE_BYTES + 1,
        };
        assert_eq!(SweepPackage::from_json(&input).unwrap_err(), too_large);
        // Freed now rather than at the end of the test: each is 32 MiB.
        drop(input);
        // Not JSON at all: the size check answers, so the parser never ran
        // (it would have reported a JSON error).
        let junk = vec![b'['; MAX_PACKAGE_BYTES + 1];
        assert_eq!(SweepPackage::from_json(&junk).unwrap_err(), too_large);
    }

    #[test]
    fn a_newer_package_version_is_refused_whatever_its_shape() {
        // `parse_record` reads the version first, so a v2 package is "too
        // new" whatever its shape.
        let unsupported = RecordError::UnsupportedVersion {
            found: 2,
            supported: 1,
        };
        let mut v2 = example();
        v2["schemaVersion"] = json!(2);
        assert_eq!(parse(&v2).unwrap_err(), unsupported);
        assert_eq!(
            parse(&json!({ "schemaVersion": 2, "renamed": true })).unwrap_err(),
            unsupported
        );
    }

    #[test]
    fn malformed_packages_are_an_error_that_never_quotes_them() {
        // Missing parts, bad references, and a syntax error: each a JSON
        // error that quotes nothing.
        let mut cases = Vec::new();
        for field in ["manifest", "findings"] {
            let mut input = example();
            input.as_object_mut().unwrap().remove(field);
            cases.push(input.to_string());
        }
        for (pointer, value) in [
            ("/manifest/sweeper", json!(MARKER)),
            (
                "/manifest/bounty",
                json!(format!("pubky://{OWNER}/pub/sweepky/sweeps/{MARKER}.json")),
            ),
            (
                "/manifest/targetShas",
                json!({ format!("../{MARKER}"): REV }),
            ),
            ("/manifest/playbook", json!(format!("{MARKER} x"))),
            // The findings' own version, checked by `SchemaVersion` itself.
            ("/findings/schemaVersion", json!(2)),
            ("/findings/findings/0/title", json!({ MARKER: MARKER })),
        ] {
            let mut input = example();
            *input.pointer_mut(pointer).unwrap() = value;
            cases.push(input.to_string());
        }
        cases.push(format!(r#"{{"schemaVersion":1,"manifest":"{MARKER}",}}"#));
        for input in &cases {
            let err = SweepPackage::from_json(input.as_bytes()).unwrap_err();
            assert_quiet_json_error(&err, input);
        }
    }

    #[test]
    fn padded_package_lands_on_a_bucket_and_parses_back() {
        let package = parse(&example()).unwrap();
        let json = serde_json::to_vec(&package).unwrap();
        let padded = package.to_padded().unwrap();
        let bytes = padded.expose_secret();
        // A small package fills one bucket: the JSON, then spaces.
        assert_eq!(bytes.len(), PADDING_BUCKET_BYTES);
        let (head, tail) = bytes.split_at(json.len());
        assert_eq!(head, &json[..]);
        assert!(tail.iter().all(|&byte| byte == b' '));
        // JSON reads the spaces as trailing whitespace, so the padded bytes
        // parse as they are.
        assert_eq!(SweepPackage::from_json(bytes).unwrap(), package);

        // One more bucket's worth of text moves it to the next bucket.
        let mut longer = package;
        longer
            .attachments
            .insert(path("notes/long.md"), "x".repeat(PADDING_BUCKET_BYTES))
            .unwrap();
        let padded = longer.to_padded().unwrap();
        assert_eq!(padded.len(), 2 * PADDING_BUCKET_BYTES);
        assert_eq!(
            SweepPackage::from_json(padded.expose_secret()).unwrap(),
            longer
        );
    }

    #[test]
    fn a_package_over_the_cap_is_not_padded() {
        // An attachment the size of the whole cap puts the JSON over it, and
        // the counting pass refuses it before a padded buffer is allocated.
        let mut too_large = parse(&example()).unwrap();
        too_large
            .attachments
            .insert(path("huge.txt"), "x".repeat(MAX_PACKAGE_BYTES))
            .unwrap();
        assert_eq!(too_large.to_padded().unwrap_err(), PackageError::TooLarge);
    }

    #[test]
    fn a_package_with_an_unclean_attachment_path_is_rejected_whole() {
        // `AttachmentPath`'s own test covers each rule; here, one bad key
        // fails the whole package, and the error quotes neither the key
        // (each holds the marker) nor the text.
        for key in [
            format!("{MARKER}/.."),
            format!("{MARKER}/../b"),
            format!("/{MARKER}"),
            format!("{MARKER}//b"),
            format!("./{MARKER}"),
            format!("{MARKER}/"),
            format!("{MARKER}\\b"),
            format!("{MARKER}\u{1b}[31m"),
            format!("{MARKER}\u{202e}b"),
            format!("-{MARKER}"),
            format!("{MARKER}{}", "a".repeat(AttachmentPath::MAX_LEN)),
        ] {
            let mut input = example();
            input["attachments"][&key] = json!(MARKER);
            let err = parse(&input).unwrap_err();
            assert_quiet_json_error(&err, &format!("{key:?}"));
        }
    }

    #[test]
    fn package_refuses_findings_json_as_an_attachment() {
        // In a package, `findings.json` is the findings. An attachment by
        // that name would be a second file of that name when the package is
        // split back out, so it is refused however it arrives.
        let mut input = example();
        input["attachments"][FINDINGS_FILE] = json!(MARKER);
        assert_quiet_json_error(&parse(&input).unwrap_err(), "parsed");

        let mut package = parse(&example()).unwrap();
        assert_eq!(
            package
                .attachments
                .insert(path(FINDINGS_FILE), MARKER.to_owned()),
            Err(PackageError::ReservedName)
        );
        assert_eq!(package.attachments.len(), 2);
        let map = BTreeMap::from([(path(FINDINGS_FILE), String::new())]);
        assert_eq!(
            Attachments::try_from(map).unwrap_err(),
            PackageError::ReservedName
        );
    }

    #[test]
    fn only_the_top_level_findings_json_is_reserved() {
        let mut package = parse(&example()).unwrap();
        assert_eq!(
            package
                .attachments
                .insert(path("audit/findings.json"), "[]".to_owned()),
            Ok(None)
        );
        let mut input = example();
        input["attachments"]["audit/findings.json"] = json!("[]");
        assert_eq!(parse(&input).unwrap().attachments.len(), 3);
    }

    #[test]
    fn package_debug_redacts_content() {
        // Sealed content never prints: the marker goes into an attachment's
        // path and text, a finding, a top-level unknown field (key and
        // value) and the manifest's `extra` (two fields, so its count tells
        // apart from the package's own).
        let mut input = example();
        input["attachments"]["REPORT.md"] = json!(MARKER);
        input["attachments"][format!("notes/{MARKER}.md")] = json!("text");
        input["findings"]["findings"][0]["title"] = json!(MARKER);
        input["findings"]["findings"][0]["description"] = json!(MARKER);
        input[MARKER] = json!(MARKER);
        input["manifest"][MARKER] = json!(MARKER);
        input["manifest"]["addedLater"] = json!({ "by": MARKER });
        // The premise: the content is all there, and serializing still
        // writes every field of it.
        let package = parse(&input).unwrap();
        assert_eq!(serde_json::to_value(&package).unwrap(), input);

        let compact = format!("{package:?}");
        let pretty = format!("{package:#?}");
        for debug in [&compact, &pretty] {
            assert!(debug.starts_with("SweepPackage {"), "{debug}");
            assert!(!debug.contains(MARKER), "{debug}");
            assert!(!debug.contains("addedLater"), "{debug}");
        }
        // The counts: the findings' own `Debug`, then three attachments and
        // one unknown field, with the manifest's two `extra` fields inside
        // it.
        assert!(
            compact.contains(
                "findings: Findings { schema_version: SchemaVersion(1), findings: 1, \
                 locations: 1, unknown_fields: 0, .. }"
            ),
            "{compact}"
        );
        assert!(compact.contains("extra_fields: 2 }"), "{compact}");
        assert!(
            compact.ends_with("attachments: 3, extra_fields: 1 }"),
            "{compact}"
        );
        assert!(pretty.contains("attachments: 3,\n"), "{pretty}");
        assert_eq!(
            format!("{:?}", package.attachments),
            "Attachments { len: 3, .. }"
        );
    }
}
