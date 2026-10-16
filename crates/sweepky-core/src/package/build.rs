//! Building a [`SweepPackage`] from a sweep directory's files, and splitting
//! one back into files (01, "The sweep package"; 03, `submit`).
//!
//! `submit` walks the sweep directory under 02's safety rules, reads each
//! plain file it accepts into a [`SweepFile`], and hands the list to
//! [`SweepPackage::build`]. The owner's CLI decrypts a package, parses it and
//! calls [`SweepPackage::into_files`] to get the files back. Neither function
//! touches the disk: which directory to walk, reading the files and writing
//! them back out safely are the CLI's.

use std::collections::btree_map::{self, Entry};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::mem;

use zeroize::{Zeroize, Zeroizing};

use super::{Attachments, FINDINGS_FILE, PackageError, SweepPackage};
use crate::findings::{Findings, FindingsSource, parse_audit_findings};
use crate::names::AttachmentPath;
use crate::records::Manifest;
use crate::schema::{MAX_FINDINGS_FILE_BYTES, MAX_PACKAGE_BYTES};

/// One file of a sweep directory, as the CLI read it: what
/// [`SweepPackage::build`] takes.
///
/// The bytes are in a [`Zeroizing`] buffer, so they are wiped whenever they
/// are dropped rather than moved into a package. [`new`](Self::new) moves
/// the `Vec` a read returns into that buffer without copying it.
///
/// Its `Debug` prints the length of the bytes only: no byte of the content
/// and not the path, which the sweeper's agent chose.
// No `Clone`: a copy of the bytes is exactly what this type is for avoiding.
pub struct SweepFile {
    /// The path relative to the directory the CLI walked, with `/` between
    /// components, exactly as found. Unchecked here:
    /// [`SweepPackage::build`] checks it.
    pub path: String,
    /// The file's bytes, wiped when dropped.
    pub bytes: Zeroizing<Vec<u8>>,
}

impl SweepFile {
    /// A file at `path` holding `bytes`, which move into a wiped buffer
    /// without a copy.
    // `impl Into<String>` accepts a `String` (moved in) or a `&str` (copied
    // once), so callers need no `.to_owned()`.
    pub fn new(path: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            path: path.into(),
            bytes: Zeroizing::new(bytes),
        }
    }
}

/// Prints `SweepFile { len: 12, .. }`: the length, never the path or a byte.
impl fmt::Debug for SweepFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SweepFile")
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// Why [`SweepPackage::build`] left a file out of the package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// The bytes are not valid UTF-8, so the file is not text, and a
    /// package holds text only (01).
    NotText,
    /// The path is not a clean [`AttachmentPath`]: it climbs out of the
    /// directory, is absolute, ends in `/`, or holds a character a path may
    /// not.
    BadPath,
}

/// A file [`SweepPackage::build`] left out, for the CLI to warn about.
///
/// It holds the path as given and the reason, never the content. The path
/// is the agent's: sanitise it before printing it to a terminal. Its `Debug`
/// prints the reason only.
pub struct SkippedFile {
    /// The file's path, exactly as it was given in [`SweepFile::path`].
    pub path: String,
    /// Why it was left out.
    pub reason: SkipReason,
}

/// Prints `SkippedFile { reason: NotText, .. }`, without the path.
impl fmt::Debug for SkippedFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SkippedFile")
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}

/// What [`SweepPackage::build`] returns: the package, which format its
/// findings were in, and the files it left out.
// The derived `Debug` prints each field's own: the package's redacting one,
// the source, and each skipped file's reason.
#[derive(Debug)]
pub struct BuiltPackage {
    /// The package, at most [`MAX_PACKAGE_BYTES`] as JSON, so
    /// [`SweepPackage::to_padded`] accepts it.
    pub package: SweepPackage,
    /// Whether `findings.json` was in the common format or Cloudflare's,
    /// which was converted.
    pub findings_source: FindingsSource,
    /// The files left out, in the order they were given. Empty when every
    /// file made it in.
    pub skipped: Vec<SkippedFile>,
}

/// A package split back into files by [`SweepPackage::into_files`]: each
/// file's bytes by its path, in path order, `findings.json` among them.
///
/// It is a map, so no path appears twice and a writer never has to pick
/// between two files of one name. The bytes are in [`Zeroizing`] buffers,
/// wiped when dropped. Its `Debug` prints how many files there are, never a
/// path or a byte: inside a package the paths are sealed content too.
// No `Clone`, as for `SweepFile`.
pub struct PackageFiles(BTreeMap<AttachmentPath, Zeroizing<Vec<u8>>>);

impl PackageFiles {
    /// The bytes of the file at `path`, if there is one.
    pub fn get(&self, path: &AttachmentPath) -> Option<&[u8]> {
        // `as_slice` lends the `Vec` inside the `Zeroizing` (reached through
        // its `Deref`) as a plain `&[u8]`, still borrowed from the map.
        self.0.get(path).map(|bytes| bytes.as_slice())
    }

    /// Every file, in path order.
    pub fn iter(&self) -> impl Iterator<Item = (&AttachmentPath, &[u8])> {
        self.0.iter().map(|(path, bytes)| (path, bytes.as_slice()))
    }

    /// How many files there are: the attachments, and `findings.json`.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Always `false`: a split package always has its `findings.json`.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Hands over each file's path and buffer, in path order, so the writer
/// owns them: each buffer is wiped once the writer drops it.
// `IntoIterator` is what `for (path, bytes) in files` calls. Writing out
// the map's own iterator type, rather than `impl Iterator`, is what a trait's
// associated type requires here.
impl IntoIterator for PackageFiles {
    type Item = (AttachmentPath, Zeroizing<Vec<u8>>);
    type IntoIter = btree_map::IntoIter<AttachmentPath, Zeroizing<Vec<u8>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// Prints `PackageFiles { len: 3, .. }`: how many, never a path or a byte.
impl fmt::Debug for PackageFiles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PackageFiles")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
}

impl SweepPackage {
    /// Builds a package from `manifest` and the files of a sweep directory,
    /// as `submit` does (01, 03):
    ///
    /// - The file whose whole path is [`FINDINGS_FILE`] becomes
    ///   [`findings`](Self::findings), read with [`parse_audit_findings`] and
    ///   the manifest's playbook: Cloudflare's array is converted, and a
    ///   common-format document is kept as it is, its own `playbook`
    ///   included. Paths are relative to the directory the CLI chose to walk
    ///   (say `audit/`), so `audit/findings.json` is not it.
    /// - Every other file whose path is a clean [`AttachmentPath`] and whose
    ///   bytes are valid UTF-8 becomes an attachment at that path, its text
    ///   unchanged.
    /// - The rest are left out and listed in [`BuiltPackage::skipped`], in
    ///   the order given, for the CLI to warn about: a path that is not clean
    ///   as [`SkipReason::BadPath`], bytes that are not UTF-8 as
    ///   [`SkipReason::NotText`]. Non-text content is never packaged.
    ///
    /// The files' buffers are wiped as they drop: the findings' once read,
    /// the skipped ones' at once, and all of them on an error. An
    /// attachment's text moves into the package without a copy, and is from
    /// then on an ordinary `String`, not wiped, like the rest of a package
    /// (see [`SweepPackage`]).
    ///
    /// No file I/O, and nothing an agent wrote makes it panic.
    ///
    /// # Errors
    ///
    /// None quotes a path or a byte of content.
    ///
    /// - [`PackageError::DuplicatePath`] when two files have the same path,
    ///   `findings.json` included: neither is kept. Checked before any file
    ///   is read.
    /// - [`PackageError::MissingFindings`] when no file is `findings.json`.
    /// - [`PackageError::TooLarge`] when the attachments' text passes
    ///   [`MAX_PACKAGE_BYTES`] (counted as it is read, before the findings
    ///   are parsed), or the whole package's JSON does.
    /// - [`PackageError::Findings`] when `findings.json` is not findings in
    ///   either format: over [`MAX_FINDINGS_BYTES`](crate::MAX_FINDINGS_BYTES),
    ///   not JSON (or not UTF-8), nested past serde_json's recursion limit,
    ///   or the wrong shape.
    // `files` is taken by value, a `Vec` the caller hands over, so that each
    // buffer can move into the package instead of being copied. `manifest`
    // moves in too.
    pub fn build(manifest: Manifest, files: Vec<SweepFile>) -> Result<BuiltPackage, PackageError> {
        check_paths(&files)?;
        let SortedFiles {
            findings_bytes,
            texts,
            skipped,
        } = sort_files(files)?;
        // `?` turns a `ConvertError` into `PackageError::Findings` through
        // its `#[from]`. `&findings_bytes` lends the buffer as `&[u8]`
        // (deref coercion goes through `Zeroizing` and `Vec`).
        let (findings, findings_source) =
            parse_audit_findings(&findings_bytes, &manifest.playbook)?;
        // Wiped now that it is read, rather than at the end of the function.
        drop(findings_bytes);
        let package = assemble(manifest, findings, texts)?;
        Ok(BuiltPackage {
            package,
            findings_source,
            skipped,
        })
    }

    /// Splits the package back into files, keyed by path: `findings.json`,
    /// the findings as pretty-printed common-format JSON (which
    /// [`Findings::from_json`] reads back to the same findings), and each
    /// attachment's text as its bytes. The owner's CLI writes these out
    /// after decrypting (P2c).
    ///
    /// Every path appears once, and `findings.json` exactly once: the result
    /// is a map, and a package's [`Attachments`] never hold that name. What
    /// a lexical check cannot see, such as two paths that differ only in
    /// case or a symbolic link on the way, stays with the writer.
    ///
    /// It consumes the package. Each attachment's text moves into its
    /// file's buffer without a copy, and the findings' JSON is written into
    /// a buffer allocated once at its exact length, which is at most
    /// [`MAX_FINDINGS_FILE_BYTES`]; both are wiped when dropped. The
    /// manifest and the unknown top-level fields are not files and are
    /// dropped, so read them first.
    ///
    /// The work and the memory are bounded however the package is shaped.
    /// Pretty-printing indents every value by how deep it is nested, so
    /// values nested deep in a finding's `extra` or an unknown field could
    /// make a package within [`MAX_PACKAGE_BYTES`] gigabytes long as
    /// `findings.json`. Counting the bytes stops at the cap instead.
    ///
    /// # Errors
    ///
    /// No files at all, rather than some, on any of:
    /// [`PackageError::FindingsFileTooLarge`] when the findings
    /// pretty-printed would be longer than [`MAX_FINDINGS_FILE_BYTES`],
    /// found before the file's buffer is allocated;
    /// [`PackageError::Serialize`] if serde_json fails to write the
    /// findings, which these types never make it do; and
    /// [`PackageError::ReservedName`] if an attachment were at
    /// `findings.json`, which [`Attachments`] never allows.
    pub fn into_files(self) -> Result<PackageFiles, PackageError> {
        // `self` is taken apart, every field named so a field added later is
        // a compile error here until someone decides what becomes of it.
        // The fields bound to `_` are dropped when `self` goes out of scope.
        let Self {
            schema_version: _,
            manifest: _,
            findings,
            attachments,
            extra: _,
        } = self;
        // The texts move first, each into a wiped buffer (`into_bytes` hands
        // over the `String`'s buffer without a copy), so an error below
        // wipes them as `files` drops. This module is inside `package`, so
        // it may reach `Attachments`' private map.
        let mut files: BTreeMap<AttachmentPath, Zeroizing<Vec<u8>>> = attachments
            .0
            .into_iter()
            .map(|(path, text)| (path, Zeroizing::new(text.into_bytes())))
            .collect();
        let findings_json = serialize_findings(&findings)?;
        // A constant that passes the check (the tests split packages), but
        // `parse` returns a `Result` all the same, and this code may not
        // panic.
        let findings_path: AttachmentPath =
            FINDINGS_FILE.parse().map_err(|_| PackageError::Serialize)?;
        // Never overwrite, never pick: an attachment at `findings.json`
        // would fail the split.
        match files.entry(findings_path) {
            Entry::Vacant(entry) => {
                entry.insert(findings_json);
            }
            Entry::Occupied(_) => return Err(PackageError::ReservedName),
        }
        Ok(PackageFiles(files))
    }
}

/// Refuses a list of files in which two share a path
/// ([`PackageError::DuplicatePath`]) or none is [`FINDINGS_FILE`]
/// ([`PackageError::MissingFindings`]), before any file is read.
// The set holds `&str`s borrowed from `files`, so no path is copied; the
// borrow checker makes sure the set is gone before `build` consumes `files`.
fn check_paths(files: &[SweepFile]) -> Result<(), PackageError> {
    let mut seen = BTreeSet::new();
    for (index, file) in files.iter().enumerate() {
        // `insert` returns `false` when the value was already there.
        if !seen.insert(file.path.as_str()) {
            return Err(PackageError::DuplicatePath { index });
        }
    }
    if !seen.contains(FINDINGS_FILE) {
        return Err(PackageError::MissingFindings);
    }
    Ok(())
}

/// A sweep directory's files, sorted by what each becomes: `build`'s
/// first pass over them.
struct SortedFiles {
    /// The bytes of [`FINDINGS_FILE`], not yet parsed.
    findings_bytes: Zeroizing<Vec<u8>>,
    /// Each attachment's text by its path. Each stays in a `Zeroizing` until
    /// the package is assembled, so an early `return` (or `?`) wipes every
    /// one as the map drops.
    texts: BTreeMap<AttachmentPath, Zeroizing<String>>,
    /// The files left out, in the order they were given.
    skipped: Vec<SkippedFile>,
}

/// Sorts `files` into the findings' bytes, the attachments' texts and the
/// files left out, refusing the texts as [`PackageError::TooLarge`] as soon
/// as they pass [`MAX_PACKAGE_BYTES`].
fn sort_files(files: Vec<SweepFile>) -> Result<SortedFiles, PackageError> {
    let mut findings_bytes = None;
    let mut texts = BTreeMap::new();
    let mut text_len: usize = 0;
    let mut skipped = Vec::new();
    // `into_iter` moves each file out of the `Vec`, and the pattern takes it
    // apart into its two fields.
    for (index, SweepFile { path, bytes }) in files.into_iter().enumerate() {
        // The whole relative path, compared byte for byte.
        if path == FINDINGS_FILE {
            findings_bytes = Some(bytes);
            continue;
        }
        let (attachment_path, text) = match into_attachment(&path, bytes) {
            Ok(attachment) => attachment,
            Err(reason) => {
                skipped.push(SkippedFile { path, reason });
                continue;
            }
        };
        // A text's JSON string is never shorter than the text, so text over
        // the cap is a package over the cap: refused here, before the
        // findings are parsed. `saturating_add` cannot overflow.
        text_len = text_len.saturating_add(text.len());
        if text_len > MAX_PACKAGE_BYTES {
            return Err(PackageError::TooLarge);
        }
        // `check_paths` already refused a repeated path, so the entry is
        // always vacant. Matching on it anyway means a repeat could never
        // overwrite the first text, only fail.
        match texts.entry(attachment_path) {
            Entry::Vacant(entry) => {
                entry.insert(text);
            }
            Entry::Occupied(_) => return Err(PackageError::DuplicatePath { index }),
        }
    }
    // `check_paths` made sure there is one; this only satisfies the type.
    let findings_bytes = findings_bytes.ok_or(PackageError::MissingFindings)?;
    Ok(SortedFiles {
        findings_bytes,
        texts,
        skipped,
    })
}

/// The attachment a file other than `findings.json` becomes: its checked
/// path and its text. Otherwise the reason it is left out, the path checked
/// first; its bytes are then wiped as they drop.
// `Result` with a `SkipReason` as the error lets `?` stop at the first
// check that fails. `SkipReason` need not implement `std::error::Error` for
// that: `Result` accepts any error type.
fn into_attachment(
    path: &str,
    bytes: Zeroizing<Vec<u8>>,
) -> Result<(AttachmentPath, Zeroizing<String>), SkipReason> {
    // `parse` borrows `path` and copies it only if it passes, so the caller
    // still has the original to report. The parse error is dropped: a
    // skipped file needs no more than its reason. A file with a bad path
    // never has its bytes looked at.
    let attachment_path = path
        .parse::<AttachmentPath>()
        .map_err(|_| SkipReason::BadPath)?;
    let text = into_text(bytes).ok_or(SkipReason::NotText)?;
    Ok((attachment_path, text))
}

/// The bytes as text, in the same buffer, or `None`, with the bytes wiped,
/// when they are not valid UTF-8.
// `mut bytes` lets this function take the buffer out of its wrapper.
fn into_text(mut bytes: Zeroizing<Vec<u8>>) -> Option<Zeroizing<String>> {
    // `Zeroizing` has a `Drop`, so its `Vec` cannot be moved out by
    // destructuring. `mem::take` swaps an empty `Vec` in instead (`*bytes`
    // reaches the `Vec` through `DerefMut`), and the empty one is all the
    // wrapper has left to wipe. `String::from_utf8` takes the `Vec` by
    // value: valid UTF-8 becomes a `String` in the same buffer, with no
    // copy; otherwise `into_bytes` hands the same buffer back, and
    // `zeroize` wipes it at once.
    match String::from_utf8(mem::take(&mut *bytes)) {
        Ok(text) => Some(Zeroizing::new(text)),
        Err(not_text) => {
            not_text.into_bytes().zeroize();
            None
        }
    }
}

/// The package of `manifest`, `findings` and the attachments' `texts`.
/// [`PackageError::TooLarge`], with the texts wiped, when its JSON is longer
/// than [`MAX_PACKAGE_BYTES`].
fn assemble(
    manifest: Manifest,
    findings: Findings,
    texts: BTreeMap<AttachmentPath, Zeroizing<String>>,
) -> Result<SweepPackage, PackageError> {
    // Each `String` moves out of its wrapper (an empty one is left to be
    // wiped) into the package's map, which runs `Attachments`' own check.
    let texts: BTreeMap<AttachmentPath, String> = texts
        .into_iter()
        .map(|(path, mut text)| (path, mem::take(&mut *text)))
        .collect();
    let mut package = SweepPackage::new(manifest, findings);
    package.attachments = Attachments::try_from(texts)?;
    // The exact check, which `to_padded` makes too: JSON escaping and the
    // manifest, keys and findings around the text add bytes.
    if package.json_len()? > MAX_PACKAGE_BYTES {
        wipe_attachments(&mut package.attachments);
        return Err(PackageError::TooLarge);
    }
    Ok(package)
}

/// Overwrites every attachment's text with zeros. `assemble` does this to
/// a package it built and then refuses, because a `String` is not wiped
/// when it drops.
fn wipe_attachments(attachments: &mut Attachments) {
    // `Zeroize::zeroize` on a `String` overwrites its whole buffer, then
    // empties it.
    for text in attachments.0.values_mut() {
        text.zeroize();
    }
}

/// The findings as `findings.json`: common-format JSON, pretty-printed for
/// whoever reads the file, in a wiped buffer allocated once at its length.
///
/// Two passes, as in [`SweepPackage::to_padded`]: the first counts the bytes
/// and keeps none, stopping at [`MAX_FINDINGS_FILE_BYTES`]; the second writes
/// them into a buffer of exactly that size, which never grows. A `Vec` that
/// grows moves its bytes to a bigger allocation and frees the old one
/// without wiping it.
fn serialize_findings(findings: &Findings) -> Result<Zeroizing<Vec<u8>>, PackageError> {
    // At most the cap, so the buffer below is never larger.
    let len = pretty_len(findings, MAX_FINDINGS_FILE_BYTES)?;
    let mut writer = ExactWriter::new(len);
    // `map_err(|_| …)` drops serde_json's error, whose message could quote a
    // value, and keeps only the fact that it failed.
    serde_json::to_writer_pretty(&mut writer, findings).map_err(|_| PackageError::Serialize)?;
    writer.finish().ok_or(PackageError::Serialize)
}

/// The length of the findings' pretty-printed JSON, counted without keeping
/// a byte of it, or [`PackageError::FindingsFileTooLarge`] as soon as the
/// count would pass `cap`.
///
/// A deeply nested value is what makes the count large: a zero 100 arrays
/// down takes 2 bytes in the package's compact JSON and over 200 here. So
/// the count stops at `cap` rather than run on to its end, which for a
/// hostile package is gigabytes later.
// `cap` is a parameter rather than the constant so that the tests can check
// the edge with findings of any size.
fn pretty_len(findings: &Findings, cap: usize) -> Result<usize, PackageError> {
    let mut counter = CappedCounter::new(cap);
    // A writer's error is the only way to stop serde_json part way, and it
    // returns the first one at once. Its error is dropped, as above, and the
    // counter's flag says whether it was the cap or (never, for these types)
    // a failure of serde_json's own. `&mut counter` lends the counter, so it
    // can still be read once serde_json is done with it.
    let written = serde_json::to_writer_pretty(&mut counter, findings);
    match written {
        Ok(()) => Ok(counter.len),
        // A match guard: this arm is taken only when the `if` holds.
        Err(_) if counter.over_cap => Err(PackageError::FindingsFileTooLarge),
        Err(_) => Err(PackageError::Serialize),
    }
}

/// An `io::Write` that keeps nothing and counts the bytes written to it, up
/// to `cap`. The write that would pass `cap` is refused with an error, which
/// stops serde_json there.
///
/// Unlike the package's `ByteCounter`, which `to_padded` runs over the
/// compact JSON, this one has a cap, for the reason `pretty_len` gives.
struct CappedCounter {
    /// The bytes accepted so far: never more than `cap`.
    len: usize,
    cap: usize,
    /// Whether a write was refused because it would have passed `cap`.
    over_cap: bool,
}

impl CappedCounter {
    fn new(cap: usize) -> Self {
        Self {
            len: 0,
            cap,
            over_cap: false,
        }
    }
}

impl io::Write for CappedCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        // `len` never passes `cap`, so this cannot underflow; `saturating_sub`
        // says so without a panic path.
        let room = self.cap.saturating_sub(self.len);
        if bytes.len() > room {
            self.over_cap = true;
            // Built from its kind alone, so it carries none of the bytes.
            return Err(io::Error::from(io::ErrorKind::Other));
        }
        // At most `cap` afterwards, so this never saturates either.
        self.len = self.len.saturating_add(bytes.len());
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// An `io::Write` into a [`Zeroizing`] buffer allocated once for exactly
/// `len` bytes, which refuses any write past them, so the buffer never grows
/// or moves.
///
/// No `Debug`: nothing needs to print one, and it holds sealed content.
struct ExactWriter {
    buffer: Zeroizing<Vec<u8>>,
    /// The bytes expected, counted beforehand, and the buffer's capacity.
    len: usize,
}

impl ExactWriter {
    fn new(len: usize) -> Self {
        Self {
            buffer: Zeroizing::new(Vec::with_capacity(len)),
            len,
        }
    }

    /// The buffer, when exactly `len` bytes arrived. Otherwise `None`, and
    /// the buffer is wiped as it drops.
    fn finish(self) -> Option<Zeroizing<Vec<u8>>> {
        let Self { buffer, len } = self;
        (buffer.len() == len).then_some(buffer)
    }
}

impl io::Write for ExactWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        // `buffer.len()` never passes `len` (a write that would is refused),
        // so this cannot underflow; `saturating_sub` says so without a panic
        // path.
        let room = self.len.saturating_sub(self.buffer.len());
        if bytes.len() > room {
            // Refused whole: more bytes than were counted means the count
            // was wrong, and taking them would grow the buffer. The error is
            // built from its kind alone and carries none of the bytes.
            return Err(io::Error::from(io::ErrorKind::Other));
        }
        self.buffer.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use serde_json::{Value, json};

    use super::{BuiltPackage, CappedCounter, SkipReason, SweepFile, pretty_len};
    use crate::error::RecordError;
    use crate::findings::test_support::{FIXTURE as CLOUDFLARE_FINDINGS, fixture};
    use crate::findings::{
        ConvertError, Findings, FindingsSource, from_cloudflare, parse_audit_findings,
    };
    use crate::package::test_support::{MARKER, manifest_json, path};
    use crate::package::{FINDINGS_FILE, PackageError, SweepPackage};
    use crate::records::Manifest;
    use crate::schema::{MAX_FINDINGS_FILE_BYTES, MAX_PACKAGE_BYTES, SchemaVersion};

    fn manifest() -> Manifest {
        serde_json::from_value(manifest_json()).unwrap()
    }

    /// A common-format `findings.json` that names its own playbook, not the
    /// manifest's.
    fn common_findings() -> Value {
        json!({
            "schemaVersion": 1,
            "playbook": "my own careful review",
            "findings": [{
                "id": "f1",
                "title": "Session token compared with ==",
                "severity": null,
                "confidence": null,
                "status": "needs_validation",
                "locations": [{ "file": "src/auth/session.rs", "line": 120 }],
                "description": "Markdown",
            }],
        })
    }

    fn file(path: &str, bytes: impl Into<Vec<u8>>) -> SweepFile {
        SweepFile::new(path, bytes.into())
    }

    /// A sweep directory's files: common-format findings and two text
    /// attachments, one of them with a CRLF, a NUL and a non-ASCII character
    /// that must come through unchanged.
    fn run_dir() -> Vec<SweepFile> {
        vec![
            file(FINDINGS_FILE, common_findings().to_string()),
            file("REPORT.md", "# Report\n"),
            file("notes/a.md", "a\r\nb\u{0}\u{2014}\n"),
        ]
    }

    fn build(files: Vec<SweepFile>) -> Result<BuiltPackage, PackageError> {
        SweepPackage::build(manifest(), files)
    }

    /// `run_dir` plus two files to leave out, both holding `MARKER`: a PNG
    /// second, and a path that climbs out of the directory last.
    fn run_dir_with_rejects() -> Vec<SweepFile> {
        let mut files = run_dir();
        // A PNG's signature: the byte 0x89 cannot start a UTF-8 character.
        let png = [b"\x89PNG\r\n\x1a\n".as_slice(), MARKER.as_bytes()].concat();
        files.insert(1, file("shot.png", png));
        files.push(file("../x", MARKER));
        files
    }

    /// `run_dir`'s package, plus an ordinary attachment that is called
    /// findings.json one level down.
    fn package_to_split() -> SweepPackage {
        let mut files = run_dir();
        files.push(file("audit/findings.json", "[]"));
        build(files).unwrap().package
    }

    #[test]
    fn build_sorts_files_into_findings_and_attachments() {
        let built = build(run_dir()).unwrap();
        assert_eq!(built.findings_source, FindingsSource::Common);
        assert!(built.skipped.is_empty());
        let package = built.package;
        assert_eq!(package.schema_version, SchemaVersion::CURRENT);
        assert_eq!(package.manifest, manifest());
        // The common format is read as it is, its own playbook included.
        let findings = Findings::from_json(common_findings().to_string().as_bytes()).unwrap();
        assert_eq!(package.findings, findings);
        // Every other file is an attachment with its text unchanged, and
        // `findings.json` is not one of them.
        let attachments: Vec<(&str, &str)> = package
            .attachments
            .iter()
            .map(|(path, text)| (path.as_str(), text))
            .collect();
        assert_eq!(
            attachments,
            [
                ("REPORT.md", "# Report\n"),
                ("notes/a.md", "a\r\nb\u{0}\u{2014}\n")
            ]
        );
        assert_eq!(package.attachments.get(&path(FINDINGS_FILE)), None);
        assert!(package.extra.is_empty());
    }

    #[test]
    fn build_converts_cloudflare_findings_with_the_manifest_playbook() {
        // Cloudflare's file names no playbook, so the manifest's is used.
        let built = build(vec![file(FINDINGS_FILE, CLOUDFLARE_FINDINGS)]).unwrap();
        assert_eq!(built.findings_source, FindingsSource::Cloudflare);
        let converted = from_cloudflare(fixture(), &manifest().playbook).unwrap();
        assert_eq!(built.package.findings, converted);
        assert_eq!(built.package.findings.findings.len(), 3);
        assert_eq!(
            built.package.findings.playbook,
            manifest().playbook.as_str()
        );
        assert!(built.package.attachments.is_empty());
    }

    #[test]
    fn build_reports_non_text_and_bad_paths() {
        let built = build(run_dir_with_rejects()).unwrap();
        // Reported in input order, each with its path as given.
        let skipped: Vec<(&str, SkipReason)> = built
            .skipped
            .iter()
            .map(|skipped| (skipped.path.as_str(), skipped.reason))
            .collect();
        assert_eq!(
            skipped,
            [
                ("shot.png", SkipReason::NotText),
                ("../x", SkipReason::BadPath)
            ]
        );
        // Neither reaches the package: it is the one the files without them
        // build.
        assert_eq!(built.package, build(run_dir()).unwrap().package);
    }

    #[test]
    fn build_debug_prints_no_path_or_content() {
        let built = build(run_dir_with_rejects()).unwrap();
        let debug = format!("{built:?} {:?}", file("notes/b.md", MARKER));
        for secret in [MARKER, "shot.png", "../x", "notes/b.md"] {
            assert!(!debug.contains(secret), "{debug}");
        }
    }

    #[test]
    fn build_refuses_a_sweep_without_findings() {
        assert_eq!(
            build(Vec::new()).unwrap_err(),
            PackageError::MissingFindings
        );
        // Only the whole relative path is the findings, so a sweep whose only
        // `findings.json` is one level down has none.
        let nested = vec![
            file("audit/findings.json", common_findings().to_string()),
            file("REPORT.md", "# Report\n"),
        ];
        assert_eq!(build(nested).unwrap_err(), PackageError::MissingFindings);
    }

    #[test]
    fn build_refuses_a_path_given_twice() {
        // An error, never last-wins, `findings.json` included. The index is
        // the second one's.
        for (path, text) in [
            ("notes/a.md", "other"),
            (FINDINGS_FILE, CLOUDFLARE_FINDINGS),
        ] {
            let mut files = run_dir();
            files.push(file(path, text));
            assert_eq!(
                build(files).unwrap_err(),
                PackageError::DuplicatePath { index: 3 },
                "{path}"
            );
        }
    }

    #[test]
    fn build_refuses_a_package_over_the_cap() {
        // Text over the cap is refused as it is read. Text exactly at the cap
        // (the only attachment, so nothing else counts towards it) passes
        // that check, but the package's JSON around it does not.
        for len in [MAX_PACKAGE_BYTES + 1, MAX_PACKAGE_BYTES] {
            let files = vec![
                file(FINDINGS_FILE, common_findings().to_string()),
                file("big.txt", vec![b'x'; len]),
            ];
            assert_eq!(build(files).unwrap_err(), PackageError::TooLarge, "{len}");
        }
    }

    #[test]
    fn build_refuses_malformed_findings_without_quoting_them() {
        // A malformed `findings.json`, not JSON or not even UTF-8, is a
        // findings error that quotes nothing, in its message, its `Debug` or
        // its source's message.
        let not_json = format!(r#"{{"schemaVersion":1,"playbook":"{MARKER}","findings":[{MARKER}"#);
        let not_utf8 = [b"\xff".as_slice(), MARKER.as_bytes()].concat();
        for bytes in [not_json.into_bytes(), not_utf8] {
            let err = build(vec![file(FINDINGS_FILE, bytes)]).unwrap_err();
            assert!(
                matches!(
                    err,
                    PackageError::Findings(ConvertError::Record(RecordError::Json { .. }))
                ),
                "{err:?}"
            );
            let source = std::error::Error::source(&err).unwrap().to_string();
            for text in [err.to_string(), format!("{err:?}"), source] {
                assert!(!text.contains(MARKER), "{text}");
            }
        }
    }

    #[test]
    fn split_gives_back_findings_json_and_attachments() {
        let package = package_to_split();
        let split = package.clone().into_files().unwrap();
        assert_eq!(format!("{split:?}"), "PackageFiles { len: 4, .. }");

        // One key per file: `findings.json` exactly once, and every
        // attachment under its own path.
        let keys: Vec<&str> = split.iter().map(|(path, _)| path.as_str()).collect();
        assert_eq!(
            keys,
            [
                "REPORT.md",
                "audit/findings.json",
                "findings.json",
                "notes/a.md"
            ]
        );
        assert_eq!(split.len(), package.attachments.len() + 1);

        // `findings.json` is common-format JSON that reads back to the same
        // findings, and each attachment comes back as its text's bytes.
        let findings_json = split.get(&path(FINDINGS_FILE)).unwrap();
        assert_eq!(
            Findings::from_json(findings_json).unwrap(),
            package.findings
        );
        assert_eq!(
            parse_audit_findings(findings_json, &manifest().playbook).unwrap(),
            (package.findings.clone(), FindingsSource::Common)
        );
        for (path, text) in package.attachments.iter() {
            assert_eq!(split.get(path), Some(text.as_bytes()), "{path}");
        }
    }

    #[test]
    fn split_files_build_the_same_package_again() {
        let package = package_to_split();
        let files = package
            .clone()
            .into_files()
            .unwrap()
            .into_iter()
            .map(|(path, bytes)| SweepFile {
                path: path.into(),
                bytes,
            })
            .collect();
        assert_eq!(build(files).unwrap().package, package);
    }

    /// How many arrays [`package_with_deep_extra`] wraps around its array of
    /// zeros, so the zeros sit `DEPTH + 1` arrays down. With the package,
    /// the findings, their list, the finding and its `extra` around them,
    /// that is 106 levels, inside serde_json's recursion limit of 128, so
    /// [`SweepPackage::from_json`] reads it.
    const DEPTH: usize = 100;

    /// `run_dir`'s package with `scalars` zeros in an array [`DEPTH`] more
    /// arrays down in its finding's `extra`: small as compact JSON, but
    /// every zero sits on a line of its own when pretty-printed, indented
    /// two spaces per level.
    fn package_with_deep_extra(scalars: usize) -> SweepPackage {
        let mut deep = Value::Array(vec![Value::from(0); scalars]);
        for _ in 0..DEPTH {
            deep = Value::Array(vec![deep]);
        }
        let mut package = build(run_dir()).unwrap().package;
        let extra = serde_json::Map::from_iter([("deep".to_owned(), deep)]);
        package.findings.findings[0].extra = Some(extra);
        package
    }

    #[test]
    fn split_refuses_findings_that_pretty_print_past_the_cap() {
        // Each zero is 2 bytes compact ("0,") and over 2 × DEPTH bytes of
        // indentation alone pretty-printed, so these findings come to over
        // twice the cap pretty-printed (286 MB, which a split without the
        // cap would count to its end and then allocate).
        let scalars = 2 * MAX_FINDINGS_FILE_BYTES / (2 * DEPTH);
        let compact = serde_json::to_vec(&package_with_deep_extra(scalars)).unwrap();
        // Small compact, far inside the package cap, and a package as
        // `open_package` reads one: what a stranger can send.
        assert!(compact.len() < MAX_PACKAGE_BYTES / 8, "{}", compact.len());
        let package = SweepPackage::from_json(&compact).unwrap();
        // The split counts only up to the cap and then refuses, before it
        // allocates the buffer for the file.
        assert_eq!(
            package.into_files().unwrap_err(),
            PackageError::FindingsFileTooLarge
        );
    }

    #[test]
    fn pretty_len_cap_is_inclusive() {
        // Findings exactly at the cap pass, one byte over do not.
        let findings = package_to_split().findings;
        let len = serde_json::to_vec_pretty(&findings).unwrap().len();
        assert_eq!(pretty_len(&findings, len), Ok(len));
        assert_eq!(
            pretty_len(&findings, len - 1),
            Err(PackageError::FindingsFileTooLarge)
        );
    }

    #[test]
    fn capped_counter_refuses_the_write_that_would_pass_the_cap() {
        // The counter keeps none of a refused write, so the count never
        // passes the cap.
        let mut counter = CappedCounter::new(4);
        counter.write_all(b"abc").unwrap();
        assert!(!counter.over_cap);
        assert!(counter.write_all(b"de").is_err());
        assert_eq!(counter.len, 3);
        assert!(counter.over_cap);
    }
}
