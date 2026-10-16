//! [`RecordError`], the error every parse in this crate returns.

use std::fmt;

/// Why a record could not be read.
///
/// Every variant holds numbers, a [`JsonCategory`] or `&'static str` text,
/// never text taken from the record. Records come from strangers' homeservers,
/// so an error that quoted its input would let a stranger put their own words
/// into the CLI's output and logs. `&'static str` makes that a compile-time
/// guarantee: it can only point at text written into this crate's source, not
/// at a string built at run time from the input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    /// The input is longer than the cap for its kind of document, so it was
    /// not parsed at all.
    #[error("input is {len} bytes, over the {limit}-byte limit")]
    TooLarge {
        /// The cap that applied, in bytes.
        limit: usize,
        /// The input's length, in bytes.
        len: usize,
    },
    /// The input is not JSON, or not JSON of the expected shape.
    #[error("invalid record: {category} at line {line}, column {column}")]
    Json {
        /// What kind of problem serde_json found.
        category: JsonCategory,
        /// The line of the input it found it on, counting from 1.
        line: usize,
        /// The column on that line, counting from 1.
        column: usize,
    },
    /// The record's `schemaVersion` is newer than this build reads.
    #[error("record has schemaVersion {found}, newer than the {supported} this build reads")]
    UnsupportedVersion {
        /// The version the record declares.
        found: u64,
        /// The newest version this build reads.
        supported: u64,
    },
    /// A value fails a check of its own type, such as an empty [`RecordTime`].
    ///
    /// [`RecordTime`]: crate::RecordTime
    #[error("invalid {field}: {reason}")]
    Invalid {
        /// Which kind of value failed.
        field: &'static str,
        /// What was wrong with it.
        reason: &'static str,
    },
}

/// What kind of problem serde_json found, from its own classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonCategory {
    /// The bytes are not valid JSON (or not valid UTF-8).
    Syntax,
    /// Valid JSON, but a field is missing, repeated, of the wrong type or
    /// holds a value its type refuses.
    Data,
    /// The input ends in the middle of a value.
    Eof,
    /// Reading the input failed. Parsing from a byte slice never reads, so
    /// this does not happen here; it exists because serde_json has it.
    Io,
}

impl fmt::Display for JsonCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Syntax => "malformed JSON",
            Self::Data => "wrong field or value",
            Self::Eof => "input ends too early",
            Self::Io => "read error",
        })
    }
}

// A hand-written `From` instead of thiserror's `#[from]`. `#[from]` would keep
// the whole `serde_json::Error` inside ours, and its message quotes the
// offending value ("invalid type: string \"...\", expected u64"). Only its
// category and position are copied out; the message is dropped here.
//
// Implementing `From` is also what lets `?` convert: `serde_json::from_slice(
// input)?` in a function returning `Result<_, RecordError>` calls this.
impl From<serde_json::Error> for RecordError {
    fn from(err: serde_json::Error) -> Self {
        // A `match` with no `_ =>` arm must name every variant, so the
        // compiler checks that each serde_json category gets a label here.
        let category = match err.classify() {
            serde_json::error::Category::Syntax => JsonCategory::Syntax,
            serde_json::error::Category::Data => JsonCategory::Data,
            serde_json::error::Category::Eof => JsonCategory::Eof,
            serde_json::error::Category::Io => JsonCategory::Io,
        };
        Self::Json {
            category,
            line: err.line(),
            column: err.column(),
        }
    }
}
