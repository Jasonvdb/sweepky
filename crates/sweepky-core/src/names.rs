//! Validated names: the identifiers records carry that later become a path
//! segment, a git argument or a public label.
//!
//! | Type | Where 01 puts it | What it later becomes |
//! |---|---|---|
//! | [`Playbook`] | `playbook` on a sweep record | a label, and nothing more |
//! | [`TargetId`] | a target's `id`, a sweep's `targets` | the `<tid>` in `./sweeps/<id>/target/<tid>/` |
//! | [`DeviceId`] | the `<deviceId>` in `keys/<deviceId>.json` | a file name |
//! | [`GitSha`] | a target's `rev`, `base`, `head` and `mergeBase` | a git argument |
//! | [`Sha256Hex`] | a sweep record's `sha256` | a public label |
//! | [`RepoName`] | a target's `repo` | the git URL `https://<repo>` |
//! | [`RepoPath`] | a repo target's `paths` | a git pathspec, and a path under the target |
//! | [`AttachmentPath`] | a key of a sweep package's `attachments` | a file under the owner's copy of the sweep |
//!
//! Each type is a `String` newtype whose field is private, so code outside
//! this module can make one only through `FromStr` (`"…".parse()`),
//! `TryFrom<String>` or deserializing. Each type writes only its own `check`;
//! the crate's `validated_string!` macro, which
//! [`RecordTime`](crate::RecordTime) uses too, writes those constructors and
//! runs the check in every one. Code that holds a `TargetId` never has to
//! check it again: the type is the proof that the check passed.
//!
//! The checks are written by hand, with no regex crate: each is a few lines,
//! and a dependency not taken is one less to audit. Each walks the value with
//! `bytes()`, `chars()` or `split`, never with `value[i]` or `&value[a..b]`:
//! slicing a `str` at an offset inside a multi-byte character panics, and the
//! lints in lib.rs refuse slicing outside tests.
//!
//! Only [`Playbook`]'s pattern comes from 01. The other limits are P1a's
//! choice, set out on each type and in the P1a phase doc, except
//! [`AttachmentPath`]'s, which are P1b's. A record from another client whose
//! identifier breaks one is rejected whole, like any other malformed record.

use serde::{Deserialize, Serialize};

use crate::error::RecordError;
use crate::validated_string::validated_string;

// The derives on every type below work the same way:
//
// - `Serialize` is derived. A struct with one unnamed field (a "newtype")
//   serializes as that field, so the JSON is a plain string.
// - `Deserialize` with `#[serde(try_from = "String")]` reads a `String`, then
//   calls `TryFrom<String>`, so deserializing runs the same check as parsing.
//   That holds for a JSON object key too, as in the manifest's `targetShas`.
// - `PartialEq`, `Eq`, `PartialOrd`, `Ord` and `Hash` compare the strings, so
//   a name can key a `HashMap` or a `BTreeMap`. Each type accepts one spelling
//   of a value, so comparing strings is comparing values.
// - `Debug` prints the string. None of these is a secret.

/// The playbook a sweep declares it followed, such as
/// `cloudflare/security-audit@c1c8a8c`: a name, then optionally `@` and 7 to
/// 40 lower-case hex characters of a commit.
///
/// The rule is 01's pattern for `playbook` on a sweep record,
/// `^[A-Za-z0-9._/-]{1,64}(@[0-9a-f]{7,40})?$`, checked by hand. It is 01's,
/// not P1a's, so changing it is a record-format change.
///
/// **A label, never a path or an argument.** The pattern allows `..`, a
/// leading `/` and a leading `-` or `.`, so `../../etc` and `-rf` are valid
/// playbooks. Print one, compare it, store it; never join it onto a
/// filesystem path or pass it to a command. Every character is printable
/// ASCII, so printing one is safe.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct Playbook(String);

impl Playbook {
    /// The longest name accepted before the optional `@`: 64 characters.
    pub const MAX_NAME_LEN: usize = 64;
    /// The shortest revision accepted after `@`: 7 hex characters.
    pub const MIN_REVISION_LEN: usize = 7;
    /// The longest revision accepted after `@`: 40 hex characters, a full
    /// SHA-1.
    pub const MAX_REVISION_LEN: usize = 40;

    fn check(value: &str) -> Result<(), RecordError> {
        let invalid = |reason| RecordError::Invalid {
            field: "playbook",
            reason,
        };
        // `split_once` splits at the first `@` and drops it, or returns `None`
        // when there is none. It finds the offset itself, always on a
        // character boundary, so it cannot panic. A second `@` stays in the
        // revision, where the hex check refuses it.
        let (name, revision) = match value.split_once('@') {
            Some((name, revision)) => (name, Some(revision)),
            None => (value, None),
        };
        // The helpers return only the reason, and `invalid` adds the field.
        // `invalid` captures nothing, so the closure is `Copy`: passing it by
        // name to `map_err` copies it rather than moving it away, and it can
        // be passed again.
        check_playbook_name(name).map_err(invalid)?;
        if let Some(revision) = revision {
            check_playbook_revision(revision).map_err(invalid)?;
        }
        Ok(())
    }
}

validated_string!(Playbook);

/// Checks the part of a [`Playbook`] before the `@`. The error is the reason
/// alone, for the caller to wrap.
fn check_playbook_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("has an empty name");
    }
    // Only ASCII passes the alphabet check below, so for any name that could
    // pass, `len()` (a count of bytes) is the count of characters.
    if name.len() > Playbook::MAX_NAME_LEN {
        return Err("has a name longer than 64 characters");
    }
    // 01 writes the rule as a regex ending in `$`. In some regex engines
    // (Python's, and PCRE's by default) `$` also matches just before a final
    // newline, so they would accept "name\n". Checking every byte has no such
    // gap.
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-'))
    {
        return Err("has a name character other than A-Z, a-z, 0-9, '.', '_', '/' and '-'");
    }
    Ok(())
}

/// Checks the part of a [`Playbook`] after the `@`. The error is the reason
/// alone, for the caller to wrap.
fn check_playbook_revision(revision: &str) -> Result<(), &'static str> {
    if !(Playbook::MIN_REVISION_LEN..=Playbook::MAX_REVISION_LEN).contains(&revision.len()) {
        return Err("has a revision that is not 7 to 40 characters");
    }
    if !is_lower_hex(revision) {
        return Err("has a revision that is not lower-case hex");
    }
    Ok(())
}

/// The id of one target within a bounty, such as `t1`: a target's `id`, the
/// entries of a sweep's `targets`, the keys of the manifest's `targetShas`,
/// and the `<tid>` directory in `./sweeps/<id>/target/<tid>/`.
///
/// 1 to 32 characters of `A-Z`, `a-z`, `0-9`, `-` and `_`, the first a letter
/// or digit. So it is always exactly one path segment: no `/` or `\`, never
/// `.` or `..`, no NUL or other control character, and no leading `.` (a
/// hidden file) or `-` (which a command would read as an option). 01 sets no
/// limits; these are P1a's choice. A record from another client whose target
/// id breaks them is rejected whole.
///
/// Two ids that differ only in case, `t1` and `T1`, are different values here
/// but the same directory on a case-insensitive filesystem, which is macOS's
/// default. Code that makes a directory per target must refuse a bounty whose
/// ids collide that way.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct TargetId(String);

impl TargetId {
    /// The longest id accepted: 32 characters.
    pub const MAX_LEN: usize = 32;

    fn check(value: &str) -> Result<(), RecordError> {
        check_segment_id(
            value,
            "target id",
            Self::MAX_LEN,
            "is longer than 32 characters",
        )
    }
}

validated_string!(TargetId);

/// The id of one CLI install's key: the `<deviceId>` in
/// `keys/<deviceId>.json`.
///
/// 1 to 64 characters of `A-Z`, `a-z`, `0-9`, `-` and `_`, the first a letter
/// or digit, so it is always exactly one path segment, with the same
/// guarantees as [`TargetId`]. 01 sets no limits; these are P1a's choice, and
/// the ids P2a's `login` makes stay within them. A `keys/` listing entry whose
/// name, without `.json`, is not a valid device id is skipped rather than
/// read.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct DeviceId(String);

impl DeviceId {
    /// The longest id accepted: 64 characters.
    pub const MAX_LEN: usize = 64;

    fn check(value: &str) -> Result<(), RecordError> {
        check_segment_id(
            value,
            "device id",
            Self::MAX_LEN,
            "is longer than 64 characters",
        )
    }
}

validated_string!(DeviceId);

/// The check [`TargetId`] and [`DeviceId`] share: 1 to `max_len` characters
/// of `A-Z`, `a-z`, `0-9`, `-` and `_`, the first a letter or digit.
/// `too_long` is the reason to give past `max_len`, with the number written
/// out, because a reason is a `&'static str` and cannot be built at run time.
fn check_segment_id(
    value: &str,
    field: &'static str,
    max_len: usize,
    too_long: &'static str,
) -> Result<(), RecordError> {
    let invalid = |reason| RecordError::Invalid { field, reason };
    let mut bytes = value.bytes();
    // `let … else` binds `first` when the pattern matches and runs the `else`
    // block, which must leave the function, when it does not. `next()` takes
    // the first byte off the iterator, so `bytes` then yields the rest.
    let Some(first) = bytes.next() else {
        return Err(invalid("is empty"));
    };
    // Only ASCII passes the checks below, so for any value that could pass,
    // a count of bytes is the count of characters.
    if value.len() > max_len {
        return Err(invalid(too_long));
    }
    if !first.is_ascii_alphanumeric() {
        return Err(invalid("does not start with a letter or digit"));
    }
    if !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')) {
        return Err(invalid(
            "has a character other than A-Z, a-z, 0-9, '-' and '_'",
        ));
    }
    Ok(())
}

/// A full git object name: 40 lower-case hex characters (SHA-1) or 64 (a
/// SHA-256 repository). What a target's `rev`, a pull request target's
/// `base`, `head` and `mergeBase`, and the values of the manifest's
/// `targetShas` hold.
///
/// Only the full name, never an abbreviation like `c1c8a8c`: a prefix can
/// match more than one object, and a target is pinned to exactly one. Hex
/// only, so it can never begin with `-` and be read as an option. Lower case
/// only, the form git prints, so each object has one spelling.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct GitSha(String);

impl GitSha {
    /// The length of a SHA-1 object name: 40 characters.
    pub const SHA1_LEN: usize = 40;
    /// The length of a SHA-256 object name: 64 characters.
    pub const SHA256_LEN: usize = 64;

    fn check(value: &str) -> Result<(), RecordError> {
        let invalid = |reason| RecordError::Invalid {
            field: "git sha",
            reason,
        };
        if value.len() != Self::SHA1_LEN && value.len() != Self::SHA256_LEN {
            return Err(invalid(
                "is not 40 or 64 characters, a full SHA-1 or SHA-256 object name",
            ));
        }
        if !is_lower_hex(value) {
            return Err(invalid("is not lower-case hex"));
        }
        Ok(())
    }
}

validated_string!(GitSha);

/// A SHA-256 digest as 64 lower-case hex characters, as in a sweep record's
/// `sha256`.
///
/// It sits in a public record, so comparing two with the derived `==`, which
/// is not constant-time, leaks nothing. Never reuse this type for a secret.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct Sha256Hex(String);

impl Sha256Hex {
    /// The length of every digest: 64 characters.
    pub const LEN: usize = 64;

    fn check(value: &str) -> Result<(), RecordError> {
        let invalid = |reason| RecordError::Invalid {
            field: "sha256",
            reason,
        };
        if value.len() != Self::LEN {
            return Err(invalid("is not 64 characters"));
        }
        if !is_lower_hex(value) {
            return Err(invalid("is not lower-case hex"));
        }
        Ok(())
    }
}

validated_string!(Sha256Hex);

/// Whether every byte of `value` is `0`-`9` or `a`-`f`. True for an empty
/// string, so callers check the length first.
fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// A repository as a target's `repo` names it: a host and a path, such as
/// `github.com/org/name`, with no scheme. The CLI fetches it as
/// `https://<repo>`.
///
/// Limits (P1a's choice; 01 sets none): at most 256 bytes, then
///
/// - a host in lower-case DNS form: two or more `.`-separated labels of
///   `a-z`, `0-9` and `-`, each 1 to 63 characters, none starting or ending
///   with `-`, and the last not all digits, so an IPv4 address such as
///   `127.0.0.1` cannot stand in for a host;
/// - then `/` and one or more `/`-separated segments of `A-Z`, `a-z`, `0-9`,
///   `.`, `_` and `-`, none of them empty, `.` or `..`, or starting with `-`.
///   So there is no trailing `/`.
///
/// `:`, `@`, `?`, `#`, `%`, spaces and control characters cannot appear, which
/// leaves no room for a scheme (`https://`), a user (`git@`), a port (`:22`),
/// an SSH-style `host:path`, a query or an escape. Nothing can start with `-`,
/// so no part can be read as a git option.
///
/// This is a check of form, not a network policy: a DNS name that resolves to
/// a private address still passes. "GitHub only for pull requests" is the
/// CLI's rule in P2b, not this type's, so tests may use a synthetic host such
/// as `example.invalid`.
///
/// Equality compares the strings: `github.com/org/name` and
/// `github.com/org/name.git` are two values even when the host serves one
/// repository at both.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct RepoName(String);

impl RepoName {
    /// The longest name accepted: 256 bytes.
    pub const MAX_LEN: usize = 256;

    fn check(value: &str) -> Result<(), RecordError> {
        let invalid = |reason| RecordError::Invalid {
            field: "repo name",
            reason,
        };
        if value.is_empty() {
            return Err(invalid("is empty"));
        }
        if value.len() > Self::MAX_LEN {
            return Err(invalid("is longer than 256 bytes"));
        }
        let Some((host, path)) = value.split_once('/') else {
            return Err(invalid("has no '/' and path after the host"));
        };
        // As in `Playbook::check`, the helpers return only the reason, and
        // `invalid` is `Copy`, so the loop can pass it to `map_err` each time.
        check_host(host).map_err(invalid)?;
        for segment in path.split('/') {
            check_repo_segment(segment).map_err(invalid)?;
        }
        Ok(())
    }
}

validated_string!(RepoName);

/// The longest DNS label: 63 characters (RFC 1035).
const MAX_HOST_LABEL_LEN: usize = 63;

/// Checks the host of a [`RepoName`]. The error is the reason alone, for the
/// caller to wrap.
fn check_host(host: &str) -> Result<(), &'static str> {
    // `rsplit_once` splits at the last `.`, so `last_label` is what follows
    // it, and `None` means the host has no `.` at all.
    let Some((_, last_label)) = host.rsplit_once('.') else {
        return Err("has a host without a '.'");
    };
    for label in host.split('.') {
        check_host_label(label)?;
    }
    // Every label is non-empty by now, so `all` here never sees an empty one.
    if last_label.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("has a host whose last label is all digits, such as an IP address");
    }
    Ok(())
}

/// Checks one `.`-separated label of a [`RepoName`]'s host.
fn check_host_label(label: &str) -> Result<(), &'static str> {
    if label.is_empty() {
        return Err("has an empty label in its host (a leading, trailing or doubled '.')");
    }
    if label.len() > MAX_HOST_LABEL_LEN {
        return Err("has a host label longer than 63 characters");
    }
    if !label
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(
            "has a host character other than a-z, 0-9, '-' and '.' (no scheme, user, port or upper case)",
        );
    }
    if label.starts_with('-') || label.ends_with('-') {
        return Err("has a host label that starts or ends with '-'");
    }
    Ok(())
}

/// Checks one path segment of a [`RepoName`]. The error is the reason alone,
/// for the caller to wrap.
fn check_repo_segment(segment: &str) -> Result<(), &'static str> {
    if segment.is_empty() {
        return Err("has an empty path segment (a doubled or trailing '/')");
    }
    if segment == "." || segment == ".." {
        return Err("has a '.' or '..' path segment");
    }
    if segment.starts_with('-') {
        return Err("has a path segment that starts with '-'");
    }
    if !segment
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err("has a path character other than A-Z, a-z, 0-9, '.', '_' and '-'");
    }
    Ok(())
}

/// A path inside a repository, relative to its root, as a repo target's
/// `paths` holds it: `src/auth/` (a directory) or `src/lib.rs` (a file).
///
/// Limits (P1a's choice; 01 sets none): at most 512 bytes of UTF-8,
/// `/`-separated, with
///
/// - no empty, `.` or `..` component, so it cannot climb out of the target
///   directory or spell one place two ways (`a//b`, `./a`); one trailing `/`
///   is allowed and marks a directory;
/// - no leading `/` (absolute), `-` (read as a git option) or `:` (git's
///   pathspec magic, as in `:(glob)x`);
/// - no backslash (a separator on Windows), no control character (C0, DEL and
///   C1, which include NUL, newline and the escape that starts a terminal
///   sequence), and none of the characters that reorder text or break a line
///   (U+061C, U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069, U+2028 and
///   U+2029), so a printed path reads as what it is.
///
/// Other Unicode, spaces and git's glob characters (`*`, `?`, `[`) are
/// allowed, because real file names contain them. Code that hands a path to
/// git as a pathspec puts it after `--` and runs git with
/// `--literal-pathspecs`, so git matches the characters as written.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct RepoPath(String);

impl RepoPath {
    /// The longest path accepted: 512 bytes.
    pub const MAX_LEN: usize = MAX_RELATIVE_PATH_LEN;

    fn check(value: &str) -> Result<(), RecordError> {
        check_relative_path(value).map_err(|reason| RecordError::Invalid {
            field: "repo path",
            reason,
        })
    }
}

validated_string!(RepoPath);

/// The key of one attachment in a sweep package: the path of a text file
/// relative to the sweep's directory, such as `REPORT.md` or
/// `notes/triage.md` (01, "The sweep package": "relative file name → UTF-8
/// text").
///
/// The sweeper writes these keys, and on an open bounty the sweeper is a
/// stranger. The owner's CLI writes each attachment back out as a file under
/// its copy of the sweep, so a key must name a file inside that directory and
/// print as what it is. The limits are P1b's choice, since 01 says only
/// "relative file name": everything a [`RepoPath`] refuses, and a trailing
/// `/` as well, because an attachment is a file, never a directory. That is:
/// at most 512 bytes of UTF-8, `/`-separated, with
///
/// - no empty, `.` or `..` component, so it cannot climb out of the
///   directory or spell one file two ways (`a//b`, `./a`), and no trailing
///   `/`;
/// - no leading `/` (absolute), `-` (read as an option by a command handed
///   the name) or `:` (meaningful only to git, but refused with the rest of
///   [`RepoPath`]'s rules);
/// - no backslash, no control character, and none of the characters that
///   reorder text or break a line.
///
/// `findings.json` is a valid path. A sweep package's attachments map
/// ([`Attachments`](crate::Attachments)) refuses that one name as a key,
/// because in a package it is the findings ([`FINDINGS_FILE`](crate::FINDINGS_FILE)).
///
/// **What a lexical check cannot see.** Two keys that differ only in case,
/// `notes.md` and `NOTES.md` (or `FINDINGS.json` and the findings), are one
/// file on a case-insensitive filesystem, which is macOS's default; and a
/// directory on the way may already exist as a symbolic link. The code that
/// writes the files checks both (P2c).
///
/// Inside a package the paths are sealed content like the rest of it. Its
/// `Debug` and `Display` print the path, so print one only on purpose, as
/// `submit` does when it lists the files it is about to encrypt; a sweep
/// package's own `Debug` counts its attachments instead.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct AttachmentPath(String);

impl AttachmentPath {
    /// The longest path accepted: 512 bytes, as for a [`RepoPath`].
    pub const MAX_LEN: usize = MAX_RELATIVE_PATH_LEN;

    fn check(value: &str) -> Result<(), RecordError> {
        let invalid = |reason| RecordError::Invalid {
            field: "attachment path",
            reason,
        };
        // `RepoPath`'s rules first, so a value both refuse gives the same
        // reason for both.
        check_relative_path(value).map_err(invalid)?;
        if value.ends_with('/') {
            return Err(invalid("ends with '/', which names a directory"));
        }
        Ok(())
    }
}

validated_string!(AttachmentPath);

/// The longest [`RepoPath`] or [`AttachmentPath`]: 512 bytes.
const MAX_RELATIVE_PATH_LEN: usize = 512;

/// The lexical check [`RepoPath`] and [`AttachmentPath`] share, with the
/// rules [`RepoPath`]'s docs set out: one trailing `/` passes here. The error
/// is the reason alone; each type wraps it in a [`RecordError`] that names
/// its own field.
fn check_relative_path(value: &str) -> Result<(), &'static str> {
    if value.is_empty() {
        return Err("is empty");
    }
    // Here `len()` is bytes and stays bytes: a path may be any UTF-8, so the
    // limit is in bytes, the unit a filesystem's own limit uses.
    if value.len() > MAX_RELATIVE_PATH_LEN {
        return Err("is longer than 512 bytes");
    }
    if value.starts_with('/') {
        return Err("is absolute (starts with '/')");
    }
    if value.starts_with('-') {
        return Err("starts with '-', which git would read as an option");
    }
    if value.starts_with(':') {
        return Err("starts with ':', which git would read as pathspec magic");
    }
    // `chars()` decodes the UTF-8 into whole characters, so a check on one
    // never lands inside a multi-byte sequence.
    if value.chars().any(is_forbidden_in_path) {
        return Err(
            "has a backslash, a control character or a character that reorders or breaks text",
        );
    }
    // `strip_suffix` returns the path without one trailing `/`, or `None`
    // when there is none. A second trailing `/` is left in place and then
    // shows up as an empty component.
    let body = value.strip_suffix('/').unwrap_or(value);
    for component in body.split('/') {
        if component.is_empty() {
            return Err("has an empty component (a doubled '/')");
        }
        if component == "." || component == ".." {
            return Err("has a '.' or '..' component");
        }
    }
    Ok(())
}

/// Whether `c` may not appear in a [`RepoPath`] or an [`AttachmentPath`].
fn is_forbidden_in_path(c: char) -> bool {
    // `is_control` is Unicode's Cc category: U+0000 to U+001F, U+007F, and
    // U+0080 to U+009F. U+2028 and U+2029, the line and paragraph
    // separators, print as a line break.
    c == '\\' || c.is_control() || reorders_text(c) || matches!(c, '\u{2028}' | '\u{2029}')
}

/// Whether `c` is one of the bidirectional controls that reorder printed
/// text: U+061C, U+200E, U+200F, U+202A to U+202E and U+2066 to U+2069.
/// They are behind "Trojan Source" text, which can make a path or a URL
/// print as a different one. [`RepoPath`] and [`PubkyUrl`](crate::PubkyUrl)
/// both refuse them, through this one list.
pub(crate) fn reorders_text(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fmt::{Debug, Display};
    use std::str::FromStr;

    use serde::Serialize;
    use serde::de::DeserializeOwned;

    use super::{
        AttachmentPath, DeviceId, GitSha, Playbook, RepoName, RepoPath, Sha256Hex, TargetId,
    };
    use crate::error::RecordError;

    /// The Cloudflare skill's pinned commit (03): a real 40-character SHA-1.
    const SHA1: &str = "c1c8a8c1471069fb0e188eeaff69b8e8db6564a8";
    /// The SHA-256 of the empty string: a real 64-character digest.
    const SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// Asserts that every way of making a `T` accepts `value`, and that every
    /// way of reading it back gives `value` unchanged: `as_str`, `Display`,
    /// `String::from`, and JSON, where it is a plain string.
    ///
    /// `as_str` is passed in because it is an inherent method, not a trait
    /// method, so a generic function cannot name it through `T`. A method
    /// path such as `TargetId::as_str` is an ordinary function value.
    fn assert_accepted<T>(value: &str, as_str: fn(&T) -> &str)
    where
        T: FromStr<Err = RecordError>
            + TryFrom<String, Error = RecordError>
            + Into<String>
            + Serialize
            + DeserializeOwned
            + Display
            + Debug
            + PartialEq,
    {
        let parsed: T = match value.parse() {
            Ok(parsed) => parsed,
            Err(err) => panic!("{value:?} was rejected: {err}"),
        };
        assert_eq!(as_str(&parsed), value);
        assert_eq!(parsed.to_string(), value);
        assert_eq!(T::try_from(value.to_owned()).unwrap(), parsed);
        let json = serde_json::to_string(&parsed).unwrap();
        assert_eq!(json, serde_json::to_string(value).unwrap(), "{value:?}");
        assert_eq!(
            serde_json::from_str::<T>(&json).unwrap(),
            parsed,
            "{value:?}"
        );
        let back: String = parsed.into();
        assert_eq!(back, value);
    }

    /// Asserts that every way of making a `T` rejects `value`: parsing and
    /// `TryFrom<String>` with an `Invalid` error for `field`, and reading it
    /// from a JSON string.
    fn assert_rejected<T>(value: &str, field: &str)
    where
        T: FromStr<Err = RecordError>
            + TryFrom<String, Error = RecordError>
            + DeserializeOwned
            + Debug,
    {
        match value.parse::<T>() {
            Err(RecordError::Invalid { field: found, .. }) => {
                assert_eq!(found, field, "{value:?}");
            }
            other => panic!("{value:?} gave {other:?}"),
        }
        assert!(T::try_from(value.to_owned()).is_err(), "{value:?}");
        let json = serde_json::to_string(value).unwrap();
        assert!(serde_json::from_str::<T>(&json).is_err(), "{value:?}");
    }

    /// Asserts that the error for `value` names `limit`. An error's reason
    /// is a `&'static str` with the number written out, so this keeps it in
    /// step with the constant.
    fn assert_names_limit<T: FromStr<Err = RecordError> + Debug>(value: &str, limit: usize) {
        let message = value.parse::<T>().unwrap_err().to_string();
        assert!(message.contains(&limit.to_string()), "{message}");
    }

    #[test]
    fn a_playbook_is_a_name_with_an_optional_revision() {
        let full_sha = format!("cloudflare/security-audit@{SHA1}");
        let longest = "a".repeat(Playbook::MAX_NAME_LEN);
        let longest_with_sha = format!("{longest}@{SHA1}");
        for value in [
            "cloudflare/security-audit@c1c8a8c",
            &full_sha,
            "cloudflare/security-audit",
            &longest,
            &longest_with_sha,
        ] {
            assert_accepted(value, Playbook::as_str);
        }
    }

    #[test]
    fn a_playbook_outside_the_01_pattern_is_rejected() {
        let too_long = "a".repeat(Playbook::MAX_NAME_LEN + 1);
        // Six hex characters, one too few.
        let six_hex = "name@c1c8a8";
        let forty_one_hex = format!("name@{SHA1}0");
        for value in [
            "",
            &too_long,
            "@c1c8a8c",
            "name@",
            six_hex,
            &forty_one_hex,
            "name@C1C8A8C",
            "name@c1c8a8c@c1c8a8c",
            "name with space",
            // A regex engine whose `$` matches before a final newline would
            // accept these two.
            "name\n",
            "name@c1c8a8c\n",
            "caf\u{e9}",
        ] {
            assert_rejected::<Playbook>(value, "playbook");
        }
        assert_names_limit::<Playbook>(&too_long, Playbook::MAX_NAME_LEN);
        assert_names_limit::<Playbook>(six_hex, Playbook::MIN_REVISION_LEN);
        assert_names_limit::<Playbook>(&forty_one_hex, Playbook::MAX_REVISION_LEN);
    }

    #[test]
    fn a_playbook_is_a_label_that_may_look_like_a_path() {
        // 01's pattern allows all of these. Refusing them would change a
        // record format, so the type's documentation says never to use a
        // playbook as a path or a command argument instead.
        for value in ["../../etc", "/etc/passwd", "-rf", ".hidden"] {
            assert_accepted(value, Playbook::as_str);
        }
    }

    #[test]
    fn target_and_device_ids_are_one_safe_path_segment() {
        let longest_target = "t".repeat(TargetId::MAX_LEN);
        let longest_device = "d".repeat(DeviceId::MAX_LEN);
        for value in ["t1", "web-0035G87EK4XFE", "A_b-9"] {
            assert_accepted(value, TargetId::as_str);
            assert_accepted(value, DeviceId::as_str);
        }
        assert_accepted(&longest_target, TargetId::as_str);
        assert_accepted(&longest_device, DeviceId::as_str);

        for value in [
            "",
            ".",
            "..",
            "a/b",
            "a\\b",
            "-a",
            ".a",
            "_a",
            "a\0",
            "a b",
            "a.b",
            "a\n",
            "caf\u{e9}",
        ] {
            assert_rejected::<TargetId>(value, "target id");
            assert_rejected::<DeviceId>(value, "device id");
        }
        let too_long_target = "t".repeat(TargetId::MAX_LEN + 1);
        let too_long_device = "d".repeat(DeviceId::MAX_LEN + 1);
        assert_rejected::<TargetId>(&too_long_target, "target id");
        assert_rejected::<DeviceId>(&too_long_device, "device id");
        assert_names_limit::<TargetId>(&too_long_target, TargetId::MAX_LEN);
        assert_names_limit::<DeviceId>(&too_long_device, DeviceId::MAX_LEN);
    }

    #[test]
    fn git_shas_are_full_lower_case_hex() {
        assert_accepted(SHA1, GitSha::as_str);
        assert_accepted(SHA256, GitSha::as_str);
        for value in [
            SHA1.to_uppercase(),
            SHA1[..39].to_owned(),
            format!("{SHA1}0"),
            SHA256[..63].to_owned(),
            format!("{SHA256}0"),
            "g".repeat(40),
            format!("-{}", &SHA1[1..]),
            // An abbreviation, which can match more than one object.
            "c1c8a8c".to_owned(),
            String::new(),
        ] {
            assert_rejected::<GitSha>(&value, "git sha");
        }
        assert_names_limit::<GitSha>("c1c8a8c", GitSha::SHA1_LEN);
        assert_names_limit::<GitSha>("c1c8a8c", GitSha::SHA256_LEN);
    }

    #[test]
    fn a_sha256_is_exactly_64_lower_case_hex() {
        assert_accepted(SHA256, Sha256Hex::as_str);
        for value in [
            // A SHA-1 is not a SHA-256.
            SHA1.to_owned(),
            SHA256.to_uppercase(),
            SHA256[..63].to_owned(),
            format!("{SHA256}0"),
            "g".repeat(64),
            String::new(),
        ] {
            assert_rejected::<Sha256Hex>(&value, "sha256");
        }
        assert_names_limit::<Sha256Hex>(SHA1, Sha256Hex::LEN);
    }

    #[test]
    fn a_repo_name_is_a_host_and_a_path_and_nothing_else() {
        let prefix = "example.invalid/";
        let longest = format!("{prefix}{}", "a".repeat(RepoName::MAX_LEN - prefix.len()));
        for value in [
            "github.com/org/name",
            "github.com/org/name.git",
            "example.invalid/fixture",
            "gitlab.example.com/group/sub/name",
            &longest,
        ] {
            assert_accepted(value, RepoName::as_str);
        }

        let too_long = format!("{longest}a");
        let long_label = format!("{}.com/o/n", "a".repeat(64));
        for value in [
            // A scheme, an SSH-style path, a user name, a port.
            "https://github.com/o/n",
            "git@github.com:o/n",
            "user@github.com/o/n",
            "github.com:22/o/n",
            // No path, or an empty or escaping segment.
            "github.com",
            "github.com/",
            "github.com//n",
            "github.com/o/n/",
            "github.com/../n",
            "github.com/./n",
            // What git would read as an option.
            "-oProxyCommand=x/a",
            "github.com/-o/n",
            // Hosts that are not a lower-case DNS name with a dot.
            "localhost/o/n",
            "GitHub.com/o/n",
            ".github.com/o/n",
            "github.com./o/n",
            "github..com/o/n",
            "-github.com/o/n",
            "github-.com/o/n",
            "127.0.0.1/o/n",
            &long_label,
            "/o/n",
            // Spaces, control characters and other punctuation.
            "github.com/o/my name",
            "github.com/o/n\n",
            "github.com/o/n\0",
            "github.com/o/n\u{1b}[31m",
            "github.com/o/n?x=1",
            "github.com/o/n#x",
            "github.com/o/%2e%2e",
            "",
            &too_long,
        ] {
            assert_rejected::<RepoName>(value, "repo name");
        }
        assert_names_limit::<RepoName>(&too_long, RepoName::MAX_LEN);
    }

    #[test]
    fn a_repo_path_stays_inside_the_repo_and_out_of_gits_options() {
        let longest = "a".repeat(RepoPath::MAX_LEN);
        for value in [
            "src/auth/",
            "src/lib.rs",
            "a",
            ".github/workflows/",
            // Other Unicode, spaces and glob characters are allowed.
            "docs/caf\u{e9} notes.md",
            "src/*.rs",
            &longest,
        ] {
            assert_accepted(value, RepoPath::as_str);
        }

        let too_long = "a".repeat(RepoPath::MAX_LEN + 1);
        for value in [
            "",
            // Absolute, or climbing out.
            "/etc",
            "/",
            "//",
            "../x",
            "a/../b",
            "a/..",
            "./a",
            "a/./b",
            // Empty components.
            "a//b",
            "a/b//",
            // A git option, or git's pathspec magic.
            "-x",
            ":(glob)x",
            ":x",
            // A backslash and control characters (C0, DEL, C1).
            "a\\b",
            "a\0b",
            "a\nb",
            "a\tb",
            "a\u{1b}[31m",
            "a\u{7f}",
            "a\u{85}",
            // Characters that reorder text or break a line.
            "a\u{202e}b",
            "a\u{2066}b",
            "a\u{2028}b",
            &too_long,
        ] {
            assert_rejected::<RepoPath>(value, "repo path");
        }
        assert_names_limit::<RepoPath>(&too_long, RepoPath::MAX_LEN);
    }

    #[test]
    fn attachment_paths_are_clean_relative_paths() {
        // A sweeper writes a package's attachment keys, and on an open bounty
        // the sweeper is a stranger. The owner's CLI writes each attachment
        // out as a file under that sweep's directory, so a key must name a
        // file inside it and print as what it is.
        let longest = "a".repeat(AttachmentPath::MAX_LEN);
        for value in [
            "REPORT.md",
            "coverage-ledger.json",
            "notes/triage.md",
            "audit/findings.json",
            // A valid path: only a package's attachments map refuses it as a
            // key, because there that name is the findings.
            "findings.json",
            &longest,
        ] {
            assert_accepted(value, AttachmentPath::as_str);
        }

        let too_long = "a".repeat(AttachmentPath::MAX_LEN + 1);
        for value in [
            "",
            // Climbing out, absolute, or one place spelled two ways.
            "..",
            "a/../b",
            "/abs",
            "a//b",
            "./a",
            // A directory, which a repo path may name but an attachment, a
            // file, may not.
            "a/",
            // A backslash and control characters (C0, DEL, C1).
            "a\\b",
            "a\0b",
            "a\nb",
            "a\u{1b}[31m",
            "a\u{7f}",
            "a\u{85}",
            // Characters that reorder text or break a line.
            "a\u{202e}b",
            "a\u{2066}b",
            "a\u{2028}b",
            // What a command would read as an option.
            "-a",
            &too_long,
        ] {
            assert_rejected::<AttachmentPath>(value, "attachment path");
        }
        assert_names_limit::<AttachmentPath>(&too_long, AttachmentPath::MAX_LEN);
    }

    #[test]
    fn checks_never_panic_on_multi_byte_input() {
        // Slicing a `str` panics when an offset lands inside a multi-byte
        // character, and a length limit is where code is tempted to slice.
        // Two- to four-byte characters, alone and around every limit here,
        // with the separators each check splits on, must come back as plain
        // results. A panic would fail this test.
        let mut inputs = Vec::new();
        for c in ['\u{e9}', '\u{202e}', '\u{2028}', '\u{1f600}'] {
            for len in [
                1, 7, 31, 32, 33, 40, 63, 64, 65, 255, 256, 257, 511, 512, 513,
            ] {
                let run: String = std::iter::repeat_n(c, len).collect();
                inputs.push(format!("a{run}"));
                inputs.push(format!("{run}@c1c8a8c"));
                inputs.push(format!("name@{run}"));
                inputs.push(format!("github.com/{run}"));
                inputs.push(format!("{run}.com/o"));
                inputs.push(format!("src/{run}/"));
            }
        }
        for input in &inputs {
            let _ = input.parse::<Playbook>();
            let _ = input.parse::<TargetId>();
            let _ = input.parse::<DeviceId>();
            let _ = input.parse::<GitSha>();
            let _ = input.parse::<Sha256Hex>();
            let _ = input.parse::<RepoName>();
            let _ = input.parse::<RepoPath>();
            let _ = input.parse::<AttachmentPath>();
        }
    }

    #[test]
    fn names_are_plain_json_strings_checked_on_read() {
        // `assert_accepted` and `assert_rejected` already run every case
        // through JSON. This covers the rest: a name as an object key, as in
        // the manifest's `targetShas`, and a value that is not a string.
        let json = format!(r#"{{"t1":"{SHA1}"}}"#);
        let shas: BTreeMap<TargetId, GitSha> = serde_json::from_str(&json).unwrap();
        let t1: TargetId = "t1".parse().unwrap();
        assert_eq!(shas.get(&t1).map(GitSha::as_str), Some(SHA1));
        assert_eq!(serde_json::to_string(&shas).unwrap(), json);

        // A bad key or a bad value fails the whole map.
        let bad_key = format!(r#"{{"../t1":"{SHA1}"}}"#);
        assert!(serde_json::from_str::<BTreeMap<TargetId, GitSha>>(&bad_key).is_err());
        assert!(serde_json::from_str::<BTreeMap<TargetId, GitSha>>(r#"{"t1":"c1c8a8c"}"#).is_err());

        // Only a JSON string is read, never a number or null.
        assert!(serde_json::from_str::<TargetId>("1").is_err());
        assert!(serde_json::from_str::<GitSha>("null").is_err());
    }
}
