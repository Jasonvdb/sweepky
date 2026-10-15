//! Sweepky's core library: records, ids, paths, target pinning, trust labels,
//! the events-feed parser, finding groups, age encryption, the package envelope
//! and the manifest. P1a adds the records and parsing, P1b the encryption.
//!
//! So far it holds the machinery every record shares:
//!
//! - [`RecordError`], the error every parse here returns.
//! - [`SchemaVersion`] and the parse every record goes through: check the
//!   input's length against a cap ([`MAX_RECORD_BYTES`] or
//!   [`MAX_FINDINGS_BYTES`]) before parsing anything, read `schemaVersion` on
//!   its own, then read the whole record.
//! - [`UnknownFields`], which a record keeps with `#[serde(flatten)]` so that
//!   rewriting it keeps the fields a newer client added.
//! - Open-string enums (`kind`, `status`, `alg`, …): a `String` newtype with
//!   an `as_known()` helper, made by a macro inside this crate.
//! - [`RecordTime`], the opaque timestamp string in `createdAt` and the other
//!   time fields.
//! - The ids and keys records point at: [`RecordId`] (the 13-character
//!   `<id>` in a record's file name), [`EventCursor`] (a position in a
//!   homeserver's `/events/` feed) and [`Pubky`] (a public key, read in either
//!   of its two spellings and compared by its bytes). Each accepts only its
//!   canonical form, so two different strings never name the same thing.
//! - The names records carry that later become a path segment, a git argument
//!   or a public label: [`Playbook`], [`TargetId`], [`DeviceId`], [`GitSha`],
//!   [`Sha256Hex`], [`RepoName`] and [`RepoPath`]. Each is a `String` newtype
//!   whose every constructor runs its check, so holding one means the value
//!   passed. Only `Playbook`'s pattern comes from 01; the other limits are
//!   P1a's choice and are set out on each type.
//!
//! The rules that hold for everything here (see "Rust conventions" in
//! `docs/plan/03-cli-and-skill.md`):
//!
//! - **No network or file I/O, and no clock.** Functions take values and return
//!   values. That keeps the crate unit-testable without a network or a temp
//!   directory, and lets it compile to WASM later. The CLI owns the network,
//!   the disk and the clock: for example, the package envelope is built here
//!   from an in-memory list of files, while the directory walk and its safety
//!   rules live in `sweepky-cli`, and a record's `createdAt` is a value the CLI
//!   passes in.
//! - **Typed errors with `thiserror`.** A fallible function returns
//!   `Result<T, E>` where `E` is an error enum the caller can `match` on, so the
//!   CLI can react to one case (say, an unknown key) differently from another.
//!   `anyhow` turns every error into a message and loses that, which is fine in
//!   the binary, so it is used only there.
//! - **Never panic on someone else's data.** Every record was written by
//!   another person and served by a homeserver we do not control. A panic
//!   abandons whatever the program was doing, so one malformed sweep record
//!   would stop `pull` for every other sweep. Malformed input comes back as an
//!   `Err` instead; the lints at the top of this file forbid the usual ways to
//!   panic outside tests.
//! - **Bounded reads.** Every function that parses bytes checks their length
//!   against a documented cap first, and serde_json's recursion limit stays on.
//! - **Errors never quote the input.** A [`RecordError`] holds numbers and
//!   fixed text only, so a stranger's record cannot put its own words into the
//!   CLI's output.

// `forbid` is `deny` that nothing further down can switch back off: no
// `unsafe` anywhere in this crate, with no exceptions.
#![forbid(unsafe_code)]
// Every public item needs a `///` doc comment. CI runs clippy with
// `-D warnings`, which turns this warning into an error.
#![warn(missing_docs)]
// Outside tests, refuse the calls that panic on bad input: `.unwrap()`,
// `.expect()`, `panic!`, `v[i]` and `&s[a..b]`, and the placeholder macros
// `todo!`, `unimplemented!` and `unreachable!`, which panic when reached. Use
// `?`, `.get(i)` or a match instead. Tests may use them, because a panic is how
// a test reports a failure.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::string_slice,
        clippy::todo,
        clippy::unimplemented,
        clippy::unreachable
    )
)]

mod error;
mod ids;
mod names;
mod open_enum;
mod pubky;
mod schema;
mod time;
mod validated_string;

pub use error::{JsonCategory, RecordError};
pub use ids::{EventCursor, RecordId};
pub use names::{DeviceId, GitSha, Playbook, RepoName, RepoPath, Sha256Hex, TargetId};
pub use pubky::Pubky;
pub use schema::{MAX_FINDINGS_BYTES, MAX_RECORD_BYTES, SchemaVersion, UnknownFields};
pub use time::RecordTime;
// Re-exported because `RecordId::from_timestamp` takes one: the CLI names it
// as `sweepky_core::Timestamp` and is sure to get the same crate version this
// crate was built against. `no_inline` lists it in these docs as a re-export
// with a link, instead of copying pubky-timestamp's own pages in. Its `now()`
// reads the clock; the CLI may call it, this crate never does.
#[doc(no_inline)]
pub use pubky_timestamp::Timestamp;

/// This crate's version, `version` from Cargo.toml.
///
/// `env!` reads `CARGO_PKG_VERSION`, which Cargo sets while compiling, so the
/// value is baked in at compile time and cannot drift from the manifest. A
/// missing variable is a compile error, not a runtime one.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn version_is_major_minor_patch() {
        // `assert!` and `assert_eq!` panic when they fail, and a panic is how a
        // test reports a bad value. Library code itself must not panic on bad
        // input.
        let parts: Vec<&str> = VERSION.split('.').collect();
        assert_eq!(
            parts.len(),
            3,
            "VERSION {VERSION:?} is not major.minor.patch"
        );
        for part in parts {
            assert!(
                part.parse::<u64>().is_ok(),
                "VERSION {VERSION:?}: {part:?} is not a number"
            );
        }
    }
}
