//! `schemaVersion`, the size caps, and the parse every record goes through.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::error::RecordError;

/// The most bytes a public record under `/pub/sweepky/` may have: 1 MiB.
///
/// A bounty with a long brief is a few kilobytes, so this leaves a wide
/// margin while stopping a stranger's homeserver from handing the CLI an
/// endless document to parse.
pub const MAX_RECORD_BYTES: usize = 1024 * 1024;

/// The most bytes a findings document may have: 16 MiB.
///
/// Findings carry descriptions and fixes in Markdown and can be far longer
/// than a public record.
pub const MAX_FINDINGS_BYTES: usize = 16 * 1024 * 1024;

/// The most bytes a sweep package may have, before and after padding: 32 MiB.
///
/// The package is the one JSON document inside a sweep's `.age` file: the
/// manifest, the findings (up to [`MAX_FINDINGS_BYTES`] on their own) and the
/// text attachments. [`PaddedPlaintext::pad`](crate::PaddedPlaintext::pad)
/// refuses a longer one, and [`decrypt`](crate::decrypt) stops reading once
/// a plaintext passes it. It is a whole number of 64 KiB padding buckets, so a
/// package at the cap pads to itself. P1b's choice; 01 and 02 set none. It is
/// above 16.2 MiB so that the largest C2SP CCTV age vectors (258 chunks of
/// 64 KiB) decrypt.
pub const MAX_PACKAGE_BYTES: usize = 32 * 1024 * 1024;

// Compile-time check (`const _` is evaluated while the crate compiles, so a
// failed `assert!` is a compile error, not a run-time panic): a package holds
// a whole findings document and more, so its cap is never the smaller one.
const _: () = assert!(MAX_PACKAGE_BYTES >= MAX_FINDINGS_BYTES);

/// The most bytes the `findings.json` that
/// [`SweepPackage::into_files`](crate::SweepPackage::into_files) writes may
/// have: 128 MiB, four times [`MAX_PACKAGE_BYTES`].
///
/// That file is the findings pretty-printed, which puts every value on a line
/// of its own, indented two spaces for each level it is nested, so it is
/// longer than the findings' compact JSON in the package. At the depth of the
/// two formats' own fields, the shapes measured come to at most four times
/// as long: the Cloudflare fixture, converted, to 1.5 times; findings of
/// nothing but locations with an empty `file` to 3.5 times; and a Cloudflare
/// array of nothing but empty evidence entries, which conversion keeps twice
/// (as locations and in `extra.cloudflare`), to 4 times, which is 8 times the
/// file it was read from. A package's JSON is within [`MAX_PACKAGE_BYTES`],
/// so the findings of every sweep `build` packages at that depth fit; four
/// times [`MAX_FINDINGS_BYTES`] would not hold the last shape. Values nested
/// far deeper, which a finding's `extra` and the unknown fields can hold,
/// grow by far more: a number 100 arrays down is 2 bytes compact and over
/// 200 pretty-printed, so a package within [`MAX_PACKAGE_BYTES`] could
/// pretty-print to gigabytes. `into_files` stops counting at this cap and
/// refuses such findings before it allocates anything for the file. P1b's
/// choice; 01 and 02 set none.
pub const MAX_FINDINGS_FILE_BYTES: usize = 4 * MAX_PACKAGE_BYTES;

/// A record's `schemaVersion`.
///
/// 01's rule is to reject a record only when its major version is greater
/// than the one this build supports. `schemaVersion` is a single integer, so
/// the whole number is the major: a record with version 2 is refused, and 1 or
/// lower is read.
///
/// A value of this type always holds a version this build reads. Deserializing
/// one checks the number (that is what `try_from = "u64"` asks serde to do: read
/// a `u64`, then call `TryFrom<u64>` below), so a nested document that carries
/// its own `schemaVersion` is checked too. Serializing writes the bare number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u64")]
pub struct SchemaVersion(u64);

impl SchemaVersion {
    /// The version this build writes, and the newest it reads: 1.
    pub const CURRENT: Self = Self(1);

    /// The version as a number.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl TryFrom<u64> for SchemaVersion {
    type Error = RecordError;

    /// Accepts any version up to [`SchemaVersion::CURRENT`].
    fn try_from(found: u64) -> Result<Self, RecordError> {
        if found > Self::CURRENT.0 {
            return Err(RecordError::UnsupportedVersion {
                found,
                supported: Self::CURRENT.0,
            });
        }
        Ok(Self(found))
    }
}

/// The fields of a record that its type does not know.
///
/// Every record type ends with
///
/// ```text
/// #[serde(flatten)]
/// pub extra: UnknownFields,
/// ```
///
/// `flatten` tells serde that the map's entries sit at the same level as the
/// record's own fields rather than under an `extra` key. Reading collects every
/// top-level key the type does not name into the map; writing puts them back
/// beside the named fields. So a field a newer client added survives when this
/// build rewrites the record, as `sweepky done` does with a bounty.
///
/// The values come back equal, not byte-identical: the unknown keys are
/// written after the known ones in sorted order, and an integer too large for
/// 64 bits comes back as a float. Unknown fields nested inside a known field
/// are kept only if that field's own type has an `extra` map too.
pub type UnknownFields = serde_json::Map<String, serde_json::Value>;

/// Refuses `input` longer than `limit` with [`RecordError::TooLarge`], without
/// looking at a single byte of it. Every from-bytes parse calls this first,
/// so a stranger's oversized document is never parsed at all.
pub(crate) fn check_size(input: &[u8], limit: usize) -> Result<(), RecordError> {
    if input.len() > limit {
        return Err(RecordError::TooLarge {
            limit,
            len: input.len(),
        });
    }
    Ok(())
}

/// The first pass of [`parse_record`]: only `schemaVersion`. serde skips every
/// other key, whatever its shape.
///
/// The field is a plain `u64`, not a [`SchemaVersion`]. A failed `TryFrom`
/// inside serde comes out as a generic data error, so the caller would get
/// [`RecordError::Json`] instead of [`RecordError::UnsupportedVersion`].
#[derive(Deserialize)]
struct VersionProbe {
    #[serde(rename = "schemaVersion")]
    schema_version: u64,
}

/// Parses a record of type `T` from bytes fetched from somewhere untrusted.
///
/// 1. Refuses input longer than `limit` with [`RecordError::TooLarge`] before
///    looking at a single byte of it. Callers pass [`MAX_RECORD_BYTES`],
///    [`MAX_FINDINGS_BYTES`] or, for a sweep package, [`MAX_PACKAGE_BYTES`].
/// 2. Reads `schemaVersion` alone and refuses a newer version with
///    [`RecordError::UnsupportedVersion`]. A v2 record may have renamed or
///    dropped v1 fields; parsing it straight into a v1 type would report a
///    confusing shape error instead of "this record is too new".
/// 3. Parses the whole of `T`.
///
/// serde_json's recursion limit (128 levels) stays on, so a deeply nested
/// input is an error rather than a stack overflow. A missing, repeated or
/// non-integer `schemaVersion` is a [`RecordError::Json`] error.
///
/// `T: DeserializeOwned` means `T` owns all of its data (`String`, not a `&str`
/// borrowed from `input`), so the result does not borrow `input` and the
/// caller can drop the bytes afterwards.
pub(crate) fn parse_record<T: DeserializeOwned>(
    input: &[u8],
    limit: usize,
) -> Result<T, RecordError> {
    check_size(input, limit)?;
    // `?` turns a serde_json error into a `RecordError` through the `From` impl
    // in error.rs, which keeps only the error's category and position.
    let probe: VersionProbe = serde_json::from_slice(input)?;
    SchemaVersion::try_from(probe.schema_version)?;
    Ok(serde_json::from_slice(input)?)
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use serde_json::json;

    use super::{MAX_RECORD_BYTES, SchemaVersion, UnknownFields, parse_record};
    use crate::error::{JsonCategory, RecordError};
    use crate::time::RecordTime;

    /// A stand-in with the parts every real record shares: a version, typed
    /// fields, and the unknown fields kept for a rewrite.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct TestRecord {
        schema_version: SchemaVersion,
        name: String,
        count: u64,
        created_at: RecordTime,
        #[serde(flatten)]
        extra: UnknownFields,
    }

    const V1: &str =
        r#"{"schemaVersion":1,"name":"a","count":3,"createdAt":"2026-10-15T00:00:00Z"}"#;

    fn parse(input: &[u8]) -> Result<TestRecord, RecordError> {
        parse_record(input, MAX_RECORD_BYTES)
    }

    #[test]
    fn version_1_and_older_parse() {
        let record = parse(V1.as_bytes()).unwrap();
        assert_eq!(record.schema_version, SchemaVersion::CURRENT);
        assert_eq!(record.name, "a");
        // 01's rule rejects only a greater version, so an older one is read.
        let v0 = V1.replace(r#""schemaVersion":1"#, r#""schemaVersion":0"#);
        assert_eq!(parse(v0.as_bytes()).unwrap().schema_version.get(), 0);
    }

    #[test]
    fn a_greater_version_is_unsupported_whatever_its_shape() {
        // A v2 record may have renamed or dropped v1 fields. The version is
        // read first, so the error says "too new", not "wrong shape".
        let err = parse(br#"{"schemaVersion":2,"renamed":true}"#).unwrap_err();
        assert_eq!(
            err,
            RecordError::UnsupportedVersion {
                found: 2,
                supported: 1
            }
        );
    }

    #[test]
    fn a_missing_or_malformed_version_is_rejected() {
        let rest = r#""name":"a","count":3,"createdAt":"t""#;
        for version in [
            "",
            r#""schemaVersion":"1","#,
            r#""schemaVersion":1.0,"#,
            r#""schemaVersion":-1,"#,
        ] {
            let input = format!("{{{version}{rest}}}");
            let err = parse(input.as_bytes()).unwrap_err();
            assert!(
                matches!(
                    err,
                    RecordError::Json {
                        category: JsonCategory::Data,
                        ..
                    }
                ),
                "{input}: {err:?}"
            );
        }
    }

    #[test]
    fn a_repeated_version_is_rejected() {
        // The version is read twice (probe, then full parse). If a repeated
        // key were allowed, the two reads could disagree.
        let input = V1.replace(
            r#""schemaVersion":1"#,
            r#""schemaVersion":1,"schemaVersion":2"#,
        );
        assert!(parse(input.as_bytes()).is_err());
    }

    #[test]
    fn unknown_fields_survive_a_round_trip() {
        let input = json!({
            "schemaVersion": 1,
            "name": "a",
            "count": 3,
            "createdAt": "t",
            "addedLater": { "nested": [1, "two", null, 2.5] },
            "another": false,
        });
        let record = parse(input.to_string().as_bytes()).unwrap();
        assert_eq!(record.extra.len(), 2);
        assert_eq!(serde_json::to_value(&record).unwrap(), input);
    }

    #[test]
    fn input_over_the_cap_is_refused_before_parsing() {
        // A valid record padded with JSON whitespace: at the cap it parses,
        // one byte more is refused.
        let mut input = V1.as_bytes().to_vec();
        input.resize(MAX_RECORD_BYTES, b' ');
        assert!(parse(&input).is_ok());
        input.push(b' ');
        let too_large = RecordError::TooLarge {
            limit: MAX_RECORD_BYTES,
            len: MAX_RECORD_BYTES + 1,
        };
        assert_eq!(parse(&input).unwrap_err(), too_large);
        // Not JSON at all: the size check answers, so the parser never ran
        // (it would have reported a JSON error).
        let junk = vec![b'['; MAX_RECORD_BYTES + 1];
        assert_eq!(parse(&junk).unwrap_err(), too_large);
    }

    #[test]
    fn malformed_input_is_an_error_not_a_panic() {
        let truncated = V1.as_bytes()[..V1.len() - 5].to_vec();
        let invalid_utf8 =
            b"{\"schemaVersion\":1,\"name\":\"\xff\",\"count\":3,\"createdAt\":\"t\"}".to_vec();
        // 10,000 levels would overflow the stack without serde_json's
        // recursion limit (128 levels), which must stay on.
        let deep = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));
        let deep_in_unknown_field =
            format!(r#"{{"schemaVersion":1,"name":"a","count":3,"createdAt":"t","deep":{deep}}}"#);
        for input in [
            truncated,
            invalid_utf8,
            deep.into_bytes(),
            deep_in_unknown_field.into_bytes(),
        ] {
            let err = parse(&input).unwrap_err();
            assert!(matches!(err, RecordError::Json { .. }), "{err:?}");
        }
    }

    #[test]
    fn errors_never_echo_record_content() {
        const MARKER: &str = "MARKER-7f3a";
        let cases = [
            // Wrong type: serde_json's own message quotes the string.
            format!(r#"{{"schemaVersion":1,"name":"a","count":"{MARKER}","createdAt":"t"}}"#),
            // A value the field's own check refuses (no spaces in a time).
            format!(r#"{{"schemaVersion":1,"name":"a","count":3,"createdAt":"{MARKER} x"}}"#),
            // A syntax error right after the marker.
            format!(r#"{{"schemaVersion":1,"name":"{MARKER}","count":3,"createdAt":"t",}}"#),
        ];
        // The premise: serde_json's message would have leaked the marker.
        let raw = serde_json::from_str::<TestRecord>(&cases[0]).unwrap_err();
        assert!(raw.to_string().contains(MARKER));

        for input in &cases {
            let err = parse(input.as_bytes()).unwrap_err();
            let RecordError::Json {
                category,
                line,
                column,
            } = err
            else {
                panic!("{input}: expected a JSON error, got {err:?}");
            };
            let message = err.to_string();
            assert!(message.contains(&category.to_string()), "{message}");
            assert!(message.contains(&format!("line {line}")), "{message}");
            assert!(message.contains(&format!("column {column}")), "{message}");
            assert!(!message.contains(MARKER), "{message}");
            assert!(!format!("{err:?}").contains(MARKER), "{err:?}");
        }
    }
}
