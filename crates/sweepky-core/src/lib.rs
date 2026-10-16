//! Sweepky's core library: records, ids, paths, target pinning, trust labels,
//! the events-feed parser, finding groups, age encryption, the package envelope
//! and the manifest. P1a adds the records and parsing, P1b the encryption.
//!
//! So far it holds the machinery every record shares, and the first records:
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
//!   [`Sha256Hex`], [`RepoName`], [`RepoPath`] and (P1b) [`AttachmentPath`].
//!   Each is a `String` newtype whose every constructor runs its check, so
//!   holding one means the value passed. Only `Playbook`'s pattern comes from
//!   01; the other limits are P1a's or P1b's choice and are set out on each
//!   type.
//! - Where records live and how they point at each other. The [`paths`]
//!   module builds every path under `/pub/sweepky/` from a [`RecordId`] or a
//!   [`DeviceId`], so no builder can leave that directory, and
//!   [`paths::SweepkyPath`] classifies a path back strictly. [`PubkyUrl`]
//!   reads a `pubky://` URL of any app's file, as the events feed carries
//!   them, and [`BountyRef`] and [`SweepRef`] are the references records hold,
//!   written as `pubky://` URLs with the key in raw form.
//! - The first records: [`Circle`], the roster in `circle.json`;
//!   [`DeviceKey`], an install's public key in `keys/<deviceId>.json`, with
//!   its open-string [`KeyAlg`]; and [`Discovered`], an open bounty's
//!   `bounties/<id>.discovered.json`. Each reads bytes with `from_json`, the
//!   size-capped, version-first parse above.
//! - The bounty and sweep records: [`Bounty`], a bounty post with its
//!   open-string [`Focus`] and [`BountyStatus`], and [`Bounty::mark_done`],
//!   the rewrite `sweepky done` makes, which refuses to credit the owner;
//!   [`Sweep`], a sweep record with its open-string [`SweepStatus`]; and
//!   [`Manifest`], the part of a sweep package that names the sweeper, the
//!   bounty and the targets' commits, whose `Debug` prints how many unknown
//!   fields it has but not what they hold. [`Manifest::check_binding`]
//!   (P1b) ties a decrypted manifest to the [`Sweep`] record and the
//!   [`SweepRef`] path it was fetched with: the path's owner must be the
//!   sweeper named inside, the bounty the record's, and the targets the
//!   record's and the `targetShas` keys, as one set. Its [`BindingError`]
//!   holds no data.
//! - A bounty's targets: [`Target`], which keeps its open-string
//!   [`TargetKind`] and its other fields as written, so a kind this build
//!   does not know round-trips and is skipped; [`Target::known`], which
//!   checks a known kind's fields into [`PrTarget`], [`CommitTarget`] or
//!   [`RepoTarget`]; and [`TargetScope`], what a sweep of each covers, as
//!   `scope.json` hands it to the skill, built from those checked values
//!   alone.
//! - The common findings format every playbook's output ends up in:
//!   [`Findings`], its [`Finding`]s and their [`Location`]s, with the
//!   open-string [`FindingStatus`], [`Severity`], [`Confidence`] and
//!   [`LocationKind`]. `severity` and `confidence` are `null` unless the
//!   playbook established them. Findings are sealed content: they exist only
//!   inside the encrypted package and the owner's decrypted copies, never in
//!   a public record, and [`Findings::from_json`] reads them with the larger
//!   [`MAX_FINDINGS_BYTES`] cap. Their `Debug` prints counts, never a string
//!   the agent wrote.
//! - Reading what a sweeper's agent left: [`parse_audit_findings`] takes the
//!   bytes of a `findings.json` in the common format or in Cloudflare's,
//!   detected by shape, and says which with [`FindingsSource`].
//!   [`from_cloudflare`] converts Cloudflare's array, filling `severity` and
//!   `confidence` from `confirmed` records only and keeping each whole record
//!   in `extra.cloudflare`, and [`to_cloudflare`] rebuilds the array from
//!   there. Its errors are [`ConvertError`]s, which name a record by index
//!   and a field by its [`CloudflareField`] path, never the content.
//! - Trust labels: [`trust_labels`] gives every pubky named in a [`Circle`]
//!   or in a list of [`CreditedBounty`]s its [`Trust`], a [`TrustLabel`]
//!   (`circle`, `known` or `unknown`) and a [`CreditTally`] of the bounties
//!   and distinct owners whose credits counted, in a [`TrustTable`]. It
//!   applies every filter itself (only `done` bounties from roster members
//!   count, and a credit naming the bounty's own owner is skipped), so the
//!   caller passes every bounty it has.
//! - The events feed: [`parse_feed`] reads one page of a homeserver's public
//!   `/events/` feed into a [`FeedPage`] of [`FeedEvent`]s (a [`FeedOp`] and
//!   a [`PubkyUrl`]) and the page's [`EventCursor`], skipping and counting
//!   every malformed line. [`FeedPage::deduped`] keeps each URL's last event,
//!   and [`FeedPage::sweep_records`] picks out the sweep records `pull`
//!   re-fetches. The feed is only a hint from that homeserver, so the parse
//!   is bounded: a body over [`MAX_FEED_BODY_BYTES`] is a
//!   [`FeedError::TooLarge`], and a line over [`MAX_FEED_LINE_BYTES`] is
//!   malformed.
//! - Keys (P1b): [`DeviceIdentity`], this install's secret age key, which
//!   can be generated, give its recipient, and be turned into and read back
//!   from a [`SecretString`]; [`AgeRecipient`], a public `age1…` key read
//!   with a strict parse that refuses every string age's encryptor would
//!   panic on; and [`DeviceKey::encryption_recipient`], which takes a
//!   `keys/` record to a checked recipient only when its `alg` is exactly
//!   `age-x25519` and it is not revoked. Their errors, [`RecipientError`],
//!   [`IdentityError`] and [`DeviceKeyError`], hold no data at all.
//! - Sealing (P1b): [`PaddedPlaintext::pad`] copies a sweep package into a
//!   buffer padded with trailing spaces to the next [`PADDING_BUCKET_BYTES`]
//!   (64 KiB), refusing one over [`MAX_PACKAGE_BYTES`]; [`encrypt`] takes
//!   only that padded type and writes binary age v1 to 1 to
//!   [`MAX_RECIPIENTS`] distinct [`AgeRecipient`]s; and [`decrypt`] opens a
//!   file with one [`DeviceIdentity`] into a [`Plaintext`], after checking
//!   the file against [`MAX_CIPHERTEXT_BYTES`] and its header against
//!   [`MAX_HEADER_BYTES`] before age parses anything. Both plaintext types
//!   live in wiped buffers that never grow, print only their length, and
//!   have no `Display`, `Serialize` or `Clone`. Their errors,
//!   [`PaddingError`], [`EncryptError`] and [`DecryptError`], hold no data,
//!   and age's own errors are matched, never formatted.
//! - The sweep package (P1b): [`SweepPackage`], the one JSON document inside
//!   a sweep's `.age` file (a manifest, the findings, and [`Attachments`],
//!   text files by [`AttachmentPath`], none of them [`FINDINGS_FILE`]).
//!   [`SweepPackage::from_json`] reads one, padding included, through the
//!   same capped, version-first parse as the records, with the
//!   [`MAX_PACKAGE_BYTES`] cap; [`SweepPackage::to_padded`] writes one
//!   straight into a padded buffer for [`encrypt`]. Its `Debug` prints the
//!   manifest's and the findings' own redacted `Debug` and counts for the
//!   rest, and its errors, [`PackageError`]s, hold no data.
//!   [`SweepPackage::build`] makes one from a manifest and the
//!   [`SweepFile`]s the CLI read from a sweep directory: `findings.json`
//!   becomes the findings (through [`parse_audit_findings`], so Cloudflare's
//!   format is converted), every other UTF-8 file at a clean path an
//!   attachment, and the rest come back as [`SkippedFile`]s with a
//!   [`SkipReason`] in a [`BuiltPackage`], for the CLI to warn about.
//!   [`SweepPackage::into_files`] splits one back into [`PackageFiles`], one
//!   wiped buffer per path, `findings.json` exactly once.
//! - Sealing and opening a package in one call each (P1b), so the CLI cannot
//!   leave a step out: [`seal_package`] checks the manifest's targets, pads
//!   and encrypts; [`open_package`] decrypts, parses with the package cap and
//!   checks the manifest binding, and returns the package only when all
//!   three pass. Their errors, [`SealError`] and [`OpenError`], say which
//!   step failed and hold no data.
//! - Finding groups (P1b): [`group_findings`] takes the decrypted sweeps of
//!   a bounty as [`SweepFindings`] (the sweep, whether it is trusted, its
//!   findings), in upload order, and groups their findings by the place they
//!   point at: each finding's first sink, or else its first location, compared
//!   by file plus scope where both give one, or else by lines at most
//!   [`LINE_WINDOW`] apart, with an equal id joining findings only where
//!   location cannot decide. The [`FindingGroups`] it returns keep every
//!   sweep unchanged, and each [`FindingGroup`] lists its [`GroupMember`]s and
//!   every sweeper who reported it, once each, in upload order. Groups stay
//!   local: nothing here is serialized.
//! - The secret-holding types, re-exported so the CLI uses the same ones
//!   without depending on `age` for them: [`SecretString`] and
//!   [`ExposeSecret`] (age's re-export of `secrecy`) and [`Zeroizing`].
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
//!   CLI's output. The key errors go further and hold nothing, so they can
//!   never carry key material either.
//! - **Secrets are never printed.** A type that holds a secret has no
//!   `Debug`, `Display` or `Serialize` (and no `Clone` or `PartialEq`), and a
//!   secret string travels only as a [`SecretString`], whose `Debug` writes
//!   `[REDACTED]` and whose value is wiped when it is dropped. Two secrets are
//!   never compared; if that is ever needed, it must be in constant time.
//! - **Sealed content is never printed by accident.** What only the owner may
//!   read (the findings, the attachments and the unknown fields of a package
//!   or its manifest) has a hand-written `Debug` that shows structure and
//!   counts but no content, so a `{:?}` in a log line, an error or a panic
//!   message cannot leak it.

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

mod crypto;
mod error;
mod feed;
mod findings;
mod groups;
mod ids;
mod names;
mod open_enum;
mod package;
// A public module, unlike the rest, so callers write `paths::bounty(id)`: the
// builders' short names (`key`, `bounty`) would say too little at the crate
// root.
pub mod paths;
mod pubky;
mod records;
mod schema;
mod scope;
mod target;
mod time;
mod trust;
mod url;
mod validated_string;

pub use crypto::{
    AgeRecipient, DecryptError, DeviceIdentity, DeviceKeyError, EncryptError, IdentityError,
    MAX_CIPHERTEXT_BYTES, MAX_HEADER_BYTES, MAX_RECIPIENTS, PADDING_BUCKET_BYTES, PaddedPlaintext,
    PaddingError, Plaintext, RecipientError, decrypt, encrypt,
};
pub use error::{JsonCategory, RecordError};
pub use feed::{
    FeedError, FeedEvent, FeedOp, FeedPage, MAX_FEED_BODY_BYTES, MAX_FEED_LINE_BYTES, parse_feed,
};
pub use findings::{
    CloudflareField, Confidence, ConvertError, Finding, FindingStatus, Findings, FindingsSource,
    KnownConfidence, KnownFindingStatus, KnownLocationKind, KnownSeverity, Location, LocationKind,
    Severity, from_cloudflare, is_cloudflare_shape, parse_audit_findings, to_cloudflare,
};
pub use groups::{
    FindingGroup, FindingGroups, GroupMember, LINE_WINDOW, SweepFindings, group_findings,
};
pub use ids::{EventCursor, RecordId};
pub use names::{
    AttachmentPath, DeviceId, GitSha, Playbook, RepoName, RepoPath, Sha256Hex, TargetId,
};
pub use package::{
    Attachments, BuiltPackage, FINDINGS_FILE, OpenError, PackageError, PackageFiles, SealError,
    SkipReason, SkippedFile, SweepFile, SweepPackage, open_package, seal_package,
};
pub use pubky::Pubky;
pub use records::{
    BindingError, Bounty, BountyPlaybook, BountyStatus, Circle, CircleMember, DeviceKey,
    Discovered, Focus, KeyAlg, KnownBountyStatus, KnownFocus, KnownKeyAlg, KnownSweepStatus,
    Manifest, MarkDoneError, Sweep, SweepStatus,
};
pub use schema::{
    MAX_FINDINGS_BYTES, MAX_PACKAGE_BYTES, MAX_RECORD_BYTES, SchemaVersion, UnknownFields,
};
pub use scope::{CommitShape, TargetScope};
pub use target::{
    CommitTarget, KnownTarget, KnownTargetKind, PrTarget, RepoTarget, Target, TargetError,
    TargetKind,
};
pub use time::RecordTime;
pub use trust::{CreditTally, CreditedBounty, Trust, TrustLabel, TrustTable, trust_labels};
pub use url::{BountyRef, PubkyUrl, SweepRef};
// Re-exported because `RecordId::from_timestamp` takes one: the CLI names it
// as `sweepky_core::Timestamp` and is sure to get the same crate version this
// crate was built against. `no_inline` lists it in these docs as a re-export
// with a link, instead of copying pubky-timestamp's own pages in. Its `now()`
// reads the clock; the CLI may call it, this crate never does.
#[doc(no_inline)]
pub use pubky_timestamp::Timestamp;
// The secret-holding types, re-exported so the CLI uses exactly the versions
// this crate and age were built with, without a dependency of its own on
// `age`, `secrecy` or `zeroize` for them. `SecretString` is age's own
// re-export of `secrecy`, which is what `DeviceIdentity` hands out, so the two
// cannot disagree. `ExposeSecret` is the trait whose `expose_secret()` reads
// a secret: a method of a trait can only be called while the trait is in
// scope, so callers `use sweepky_core::ExposeSecret;`.
#[doc(no_inline)]
pub use age::secrecy::{ExposeSecret, SecretString};
#[doc(no_inline)]
pub use zeroize::Zeroizing;

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
