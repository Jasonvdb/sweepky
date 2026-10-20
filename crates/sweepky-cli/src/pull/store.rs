//! Where `pull` writes each sweep it decrypted: the owner-only data
//! directory (03's `~/.local/share/sweepky/<bounty>/`), strangers' sweeps in
//! the bounty's `untrusted/` (02, "Untrusted reports are data").
//!
//! | Entry, under the data directory | What |
//! |---|---|
//! | `<bounty id>/` | one per bounty of the owner's |
//! | `<bounty id>/owner.json` | the owner check, `{schemaVersion: 1, owner: <z32>}` |
//! | `<bounty id>/<sweeper z32>-<sweep id>/` | a trusted sweep |
//! | `<bounty id>/untrusted/<sweeper z32>-<sweep id>/` | an untrusted one |
//! | `…/<sweep>/<path>` | each file the package split into: `findings.json`, pretty-printed, and every attachment at its own path |
//! | `…/<sweep>/.sweepky/findings.json` | the compact copy of the findings, which regrouping reads ([`read_stored_findings`]) |
//! | `<bounty id>/groups.json`, `<bounty id>/merged.json` | the bounty's triage, written by `pull::triage` |
//! | `staging/.pull.<pid>.<nanos>.<n>.tmp/` | one store's staging, removed when the store ends |
//!
//! A sweeper's z-base32 key is 52 lower-case characters and a sweep id 13 of
//! `0-9` and upper-case `A-Z`, so a sweep's name is never `untrusted`,
//! `owner.json` or another sweep's, even on a file system that ignores case.
//!
//! [`store_sweep`] keeps these rules:
//!
//! - **The paths are checked before anything is written** ([`check_paths`]).
//!   A package's paths passed core's lexical check (`AttachmentPath`), which
//!   lets through what a file system or a tool reads in its own way: a part
//!   that starts with `.` (`.git/config`, `.claude/settings.json`), which
//!   tools read as settings; a part named as a file an agent loads as its
//!   instructions (`CLAUDE.md`, `AGENTS.md`: the names `run` strips from a
//!   target, in any case), which the owner's agent, reading `untrusted/`,
//!   must take as data (02); and two paths that differ only in case
//!   (`README.md` and `readme.md`), which macOS's default file system takes
//!   as one. Each refuses the whole sweep, as do more entries than
//!   `submit`'s walk takes ([`MAX_ENTRIES`] files and directories) and a path
//!   of more than [`MAX_DEPTH`] parts.
//! - **Staged, then moved into place in one step.** The sweep is written into
//!   a new directory under `staging/`, then moved to its place with
//!   `renameat` and `RENAME_NOREPLACE` (`RENAME_EXCL` on macOS), which never
//!   replaces anything already at the name, a link included. So a sweep is
//!   there whole or not at all, and a write that fails leaves nothing: the
//!   staging directory is removed whatever happens ([`Staging`]). A data
//!   directory whose file system cannot promise not to replace gets the
//!   handle-only copy `run` falls back on (`run::place`), which makes the
//!   sweep's entries one by one and syncs none of them: a crash in the
//!   middle of it can leave part of a sweep, which a later store takes as
//!   stored.
//! - **Through handles that follow no link**, as `run` places a sweep and
//!   `submit` walks one, with their calls: every directory on the way is
//!   looked at with `statat(AT_SYMLINK_NOFOLLOW)`, opened with
//!   `O_DIRECTORY | O_NOFOLLOW` and `fstat`ed to check it is what was looked
//!   at; every new file and directory is made with `O_CREAT | O_EXCL |
//!   O_NOFOLLOW` or `mkdirat`, which fail on anything already at the name. A
//!   link at the bounty's directory, at `untrusted/` or where the sweep goes
//!   is refused, never followed. `O_EXCL` is also what catches two paths the
//!   case check passed that the file system still takes as one, such as two
//!   Unicode normalisations of one name on APFS.
//! - **Owner-only from the start**: every directory is made 0700 and every
//!   file 0600 in the call that creates it, never `chmod`ed afterwards
//!   (`private_fs` says why).
//! - **Once.** A sweep already stored, as trusted or as untrusted, is left as
//!   it is ([`Stored::AlreadyThere`]): where a sweep goes is decided when it
//!   is first stored.
//! - **One owner per bounty directory.** A bounty's id is the owner's own,
//!   so another owner logged in on the same `SWEEPKY_HOME` could have one
//!   with the same id. The directory is made with its owner check inside, in
//!   the same rename, and a store or a read for anyone else is refused.
//! - **Sealed content stays sealed.** The files' bytes stay in `Zeroizing`
//!   buffers until they are written. Nothing written is printed or logged,
//!   and no message names a package's path: on an open bounty the paths are
//!   a stranger's, and inside a package they are sealed content.
//!
//! **Why a compact copy.** The `findings.json` core's `into_files` writes is
//! pretty-printed for the owner's agent to read, and pretty-printing can make
//! it longer than `Findings::from_json` reads (16 MiB). Regrouping reads the
//! compact copy instead, through `private_fs::read_private_file` with the
//! package's cap: findings that came out of a package of at most
//! `MAX_PACKAGE_BYTES` are at most that long written compactly too, unless
//! they hold numbers serde_json writes back longer (`1e15` comes back as
//! `1000000000000000.0`), and such a sweep is refused rather than stored
//! without its copy.

use std::collections::HashSet;
use std::ffi::{CStr, CString, OsStr};
use std::fmt;
use std::fs::{self, DirBuilder, File};
use std::io::{self, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
// `DirBuilderExt` adds `.mode(...)` to `DirBuilder`, and `OsStrExt` lets a
// C string's bytes be a path: extension traits whose methods work only while
// they are in scope.
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, anyhow, bail};
use rustix::fs::{FileType, Mode, RenameFlags};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use sweepky_core::{
    BountyRef, Findings, MAX_PACKAGE_BYTES, PackageFiles, Pubky, RecordError, SchemaVersion,
    SweepRef, Zeroizing,
};

use crate::Dirs;
use crate::private_fs::{
    ensure_private_dir, lstat, read_private_file, refuse_unless_dir, temp_path_beside, write_synced,
};
use crate::run::place::{NEW_FILE_FLAGS, copy_sweep, open_dir_path};
use crate::run::strip::is_agent_file;
use crate::submit::walk::{DIR_FLAGS, MAX_DEPTH, MAX_ENTRIES, entry_at, kind, same_entry};

// `c"…"` is a C string literal, the bytes and a closing NUL, which is what
// the system calls take. Each is one path component.
/// Strangers' sweeps, in a bounty's directory.
const UNTRUSTED: &CStr = c"untrusted";
/// The owner check, in a bounty's directory.
const OWNER_FILE: &CStr = c"owner.json";
/// Sweepky's own files in a stored sweep: a name no package path can take,
/// since none may start with `.`.
const COPY_DIR: &CStr = c".sweepky";
/// The compact copy of the findings, in [`COPY_DIR`].
const COPY_FILE: &CStr = c"findings.json";

/// The most bytes an owner check may have: 1 KiB. Pull writes about 90.
const MAX_OWNER_FILE_BYTES: usize = 1024;

/// The mode of every directory made here: owner read, write and enter.
const DIR_MODE: Mode = Mode::RWXU;
/// The mode of every file made here: owner read and write.
// `union` is the `const` form of `|`, so this can be a constant.
const FILE_MODE: Mode = Mode::RUSR.union(Mode::WUSR);

/// Where a sweep's files go in its bounty's directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Placement {
    /// Directly in it, beside the other trusted sweeps.
    Trusted,
    /// In its `untrusted/`, kept apart from the merged report (01,
    /// "Attribution and content are two different steps").
    Untrusted,
}

/// What [`store_sweep`] did. Each holds the sweep's directory, which names
/// only the bounty, the sweeper and the sweep, so it may be printed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Stored {
    /// The sweep is written there now.
    Written(PathBuf),
    /// An earlier pull stored the sweep there, and it was left as it was.
    AlreadyThere(PathBuf),
}

/// A sweep's findings as compact JSON, at most `MAX_PACKAGE_BYTES`: what
/// [`store_sweep`] keeps beside the pretty `findings.json` for regrouping.
///
/// Made before the package is split, since `into_files` consumes the
/// findings. The bytes are in a `Zeroizing` buffer, which wipes itself when
/// dropped. No `Clone`, and the `Debug` below prints the length alone: the
/// bytes are sealed content.
pub(crate) struct CompactFindings(Zeroizing<Vec<u8>>);

impl CompactFindings {
    /// `findings` written as compact JSON, refused when that would be more
    /// than `MAX_PACKAGE_BYTES`.
    pub(crate) fn of(findings: &Findings) -> anyhow::Result<Self> {
        compact_with_cap(findings, MAX_PACKAGE_BYTES)
    }

    /// The JSON, borrowed: `&self.0` derefs through `Zeroizing` and `Vec`.
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Prints `CompactFindings { len: 1234 }`, never a byte.
impl fmt::Debug for CompactFindings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompactFindings")
            .field("len", &self.0.len())
            .finish()
    }
}

/// [`CompactFindings::of`] with the cap as a parameter, so a test can check
/// the edge with findings of any size.
fn compact_with_cap(findings: &Findings, cap: usize) -> anyhow::Result<CompactFindings> {
    let Some(bytes) = compact_json(findings, cap)? else {
        bail!(
            "the sweep's findings come to more than the {cap} bytes pull keeps of a sweep's \
             findings written compactly, so the sweep was not stored"
        );
    };
    Ok(CompactFindings(bytes))
}

/// What [`compact_json`] says when serde_json fails other than at the cap,
/// which the types `pull` writes never make it do.
const COMPACT_FAILED: &str = "could not write compact JSON for pull's own files";

/// `value` as compact JSON in a `Zeroizing` buffer of exactly its length, or
/// `None` when that would be more than `cap` bytes. The compact copy of a
/// sweep's findings is written with it, and so are `pull::triage`'s files.
///
/// Two passes, so the buffer is allocated once at its exact length: the first
/// counts the bytes and keeps none, stopping at the cap; the second writes
/// them. A `Vec` that grew while the JSON was written would copy it into a
/// bigger allocation each time and free the old one unwiped.
// Generic over `T`, any type serde can write: `&T` is only borrowed, twice.
pub(crate) fn compact_json<T: Serialize>(
    value: &T,
    cap: usize,
) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut counter = CappedWriter::new(io::sink(), cap);
    // serde_json's error is dropped (`map_err(|_| …)`): its message could
    // quote a value. The counter says whether it was the cap.
    let counted = serde_json::to_writer(&mut counter, value);
    if counter.over_cap {
        return Ok(None);
    }
    counted.map_err(|_| anyhow!(COMPACT_FAILED))?;
    let len = counter.written;
    let mut bytes = Zeroizing::new(Vec::with_capacity(len));
    // `&mut *bytes` lends the `Vec` inside the `Zeroizing`; `&mut Vec<u8>`
    // is an `io::Write`. The cap of exactly `len` keeps the `Vec` from ever
    // growing past the capacity it was given.
    serde_json::to_writer(CappedWriter::new(&mut *bytes, len), value)
        .map_err(|_| anyhow!(COMPACT_FAILED))?;
    Ok(Some(bytes))
}

/// An `io::Write` that passes at most `cap` bytes on to `inner`, and counts
/// them. The write that would pass `cap` is refused with an error, which
/// stops serde_json there, and sets `over_cap`.
// Generic over `W`, any writer: the counting pass gives it `io::sink()`,
// which keeps nothing, and the writing pass the buffer.
struct CappedWriter<W> {
    inner: W,
    written: usize,
    cap: usize,
    over_cap: bool,
}

impl<W> CappedWriter<W> {
    fn new(inner: W, cap: usize) -> Self {
        Self {
            inner,
            written: 0,
            cap,
            over_cap: false,
        }
    }
}

impl<W: Write> Write for CappedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // `checked_add` is `None` on overflow, and `filter` turns a total
        // past the cap into `None` too, so one `let … else` covers both.
        let Some(total) = self
            .written
            .checked_add(buf.len())
            .filter(|total| *total <= self.cap)
        else {
            self.over_cap = true;
            return Err(io::Error::other("over the cap"));
        };
        self.inner.write_all(buf)?;
        self.written = total;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// The owner check in a bounty's directory: the key whose bounty it holds.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OwnerCheck {
    schema_version: SchemaVersion,
    owner: Pubky,
}

/// Writes the decrypted sweep `sweep` of the owner's bounty `bounty` into
/// the data directory, its files from `files` and the compact copy
/// `findings`, as trusted or untrusted by `placement` (see the module docs).
///
/// Refuses, writing nothing, a package whose paths [`check_paths`] refuses,
/// a bounty directory of another owner's, and a link or anything but a
/// directory where a directory goes or where the sweep goes. A sweep already
/// stored is [`Stored::AlreadyThere`], on either side, and left as it was.
// `files` and `findings` are taken by value: each buffer is wiped as it is
// dropped, the files' one by one as they are written.
pub(crate) fn store_sweep(
    dirs: &Dirs,
    bounty: BountyRef,
    sweep: SweepRef,
    placement: Placement,
    findings: CompactFindings,
    files: PackageFiles,
) -> anyhow::Result<Stored> {
    check_paths(&files).with_context(|| format!("pull did not store {sweep}"))?;
    ensure_private_dir(dirs.data())?;
    let staging = Staging::create(dirs)?;
    let data = open_dir_path(dirs.data())?;
    let bounty_dir = open_bounty_dir(dirs, data.as_fd(), &staging, bounty)?;
    let name = c_name(&sweep_dir_name(sweep))?;
    if let Some(dir) = find_stored(dirs, bounty_dir.as_fd(), bounty, sweep, &name)? {
        return Ok(Stored::AlreadyThere(dir));
    }
    let dest = match placement {
        Placement::Trusted => bounty_dir,
        Placement::Untrusted => untrusted_dir(dirs, bounty_dir.as_fd(), bounty)?,
    };
    let shown = sweep_path(dirs, bounty, sweep, placement);
    let root = staging.new_dir(&name)?;
    write_sweep(root.as_fd(), files, &findings, &staging.path)?;
    match place(&staging, &name, dest.as_fd(), &shown)? {
        Placed::Moved => Ok(Stored::Written(shown)),
        // Another pull stored it in the meantime, or something else took
        // the name: a real directory there is the sweep, anything else is
        // refused.
        Placed::NameTaken => {
            if is_stored_at(dest.as_fd(), &name, &shown)? {
                Ok(Stored::AlreadyThere(shown))
            } else {
                bail!(changed(&shown))
            }
        }
    }
}

/// The owner's bounty `bounty`'s directory, `<data>/<bounty id>/`, once it
/// is seen to be a real directory whose owner check names `bounty`'s owner;
/// `None` when nothing is there, as before any sweep of it is stored. A
/// link there, or another owner's directory, is refused.
pub(crate) fn stored_bounty_dir(dirs: &Dirs, bounty: BountyRef) -> anyhow::Result<Option<PathBuf>> {
    let dir = dirs.pulled_bounty_dir(&bounty.id);
    if !is_real_dir(&dir)? {
        return Ok(None);
    }
    check_owner(dirs, bounty)?;
    Ok(Some(dir))
}

/// Where `sweep` of the owner's bounty `bounty` is stored, on whichever
/// side its first store put it, or `None` when it is not stored: what
/// `pull`'s report shows of a sweep an earlier run stored. As for
/// [`read_stored_findings`], the bounty directory's owner check must name
/// `bounty`'s owner, and each directory on the way is looked at without
/// following a link and refused when it is one.
pub(crate) fn stored_sweep_dir(
    dirs: &Dirs,
    bounty: BountyRef,
    sweep: SweepRef,
) -> anyhow::Result<Option<PathBuf>> {
    if stored_bounty_dir(dirs, bounty)?.is_none() {
        return Ok(None);
    }
    for placement in [Placement::Trusted, Placement::Untrusted] {
        // `lstat` does not follow a link in a path's last part, but does in
        // every part before it, so `untrusted/` is looked at on its own
        // first, as `stored_bounty_dir` has looked at the bounty's.
        if placement == Placement::Untrusted
            && !is_real_dir(&dirs.pulled_untrusted_dir(&bounty.id))?
        {
            continue;
        }
        let dir = sweep_path(dirs, bounty, sweep, placement);
        if is_real_dir(&dir)? {
            return Ok(Some(dir));
        }
    }
    Ok(None)
}

/// What [`read_stored_findings`] found of a stored sweep's compact copy of
/// its findings.
// `Debug` is derived: `Findings`' own `Debug` prints counts only.
#[derive(Debug)]
pub(crate) enum StoredCopy {
    /// Read back: its findings, and the copy's length in bytes. Which side
    /// the sweep was stored on is [`stored_sweep_dir`]'s to say.
    Read { findings: Findings, len: usize },
    /// Longer than the cap the caller gave, by its length in bytes: nothing
    /// of it was read.
    OverCap { len: u64 },
}

/// The compact copy of the findings of `sweep` of the owner's bounty
/// `bounty`, read back if it is at most `cap` bytes long (never more than
/// `MAX_PACKAGE_BYTES`), or `None` when it was not stored.
///
/// Its length is looked at first, without following a link, so a copy over
/// the cap is [`StoredCopy::OverCap`] and not a byte of it is read; then it
/// is read through `private_fs::read_private_file` with the same cap, which
/// checks the size again before it reads. Each directory on the way is
/// looked at first and refused when it is a link. A bounty directory of
/// another owner's is refused. The parse's error quotes nothing of the file.
pub(crate) fn read_stored_findings(
    dirs: &Dirs,
    bounty: BountyRef,
    sweep: SweepRef,
    cap: usize,
) -> anyhow::Result<Option<StoredCopy>> {
    if stored_bounty_dir(dirs, bounty)?.is_none() {
        return Ok(None);
    }
    let cap = cap.min(MAX_PACKAGE_BYTES);
    for placement in [Placement::Trusted, Placement::Untrusted] {
        let Some(path) = copy_path(dirs, bounty, sweep, placement)? else {
            continue;
        };
        let Some(seen) = lstat(&path)? else {
            continue;
        };
        // `try_from` turns the cap into the `u64` a file's length is; a
        // `usize` fits one on every platform Rust supports, so the fallback
        // never applies.
        if seen.len() > u64::try_from(cap).unwrap_or(u64::MAX) {
            return Ok(Some(StoredCopy::OverCap { len: seen.len() }));
        }
        let Some(bytes) = read_private_file(&path, cap)? else {
            continue;
        };
        // `RecordError::from` keeps only the kind of fault and where it is,
        // so the message quotes nothing of the findings.
        let findings = serde_json::from_slice(&bytes)
            .map_err(RecordError::from)
            .with_context(|| format!("{} is not valid", path.display()))?;
        return Ok(Some(StoredCopy::Read {
            findings,
            len: bytes.len(),
        }));
    }
    Ok(None)
}

/// The path of `sweep`'s compact copy as stored by `placement`, once each
/// directory below the bounty's on the way to it is seen to be a real one;
/// `None` when one is missing. A link at any is refused.
fn copy_path(
    dirs: &Dirs,
    bounty: BountyRef,
    sweep: SweepRef,
    placement: Placement,
) -> anyhow::Result<Option<PathBuf>> {
    let sweep_dir = sweep_path(dirs, bounty, sweep, placement);
    let copy_dir = sweep_dir.join(as_path(COPY_DIR));
    if placement == Placement::Untrusted && !is_real_dir(&dirs.pulled_untrusted_dir(&bounty.id))? {
        return Ok(None);
    }
    if !is_real_dir(&sweep_dir)? || !is_real_dir(&copy_dir)? {
        return Ok(None);
    }
    Ok(Some(copy_dir.join(as_path(COPY_FILE))))
}

/// Refuses `files` unless every path keeps the rules the module docs list:
/// no part that starts with `.` or is named as an agent's instruction file,
/// no two paths that name one entry once case is set aside, at most
/// [`MAX_ENTRIES`] files and directories, and at most [`MAX_DEPTH`] parts in
/// a path. No message names a path.
///
/// [`MAX_DEPTH`] is `submit`'s cap on how many directories deep its walk
/// goes below the sweep directory, where `audit/`, which a package's paths
/// are relative to, is the first; so a package `submit` built has at most
/// that many parts in a path, its file's name included.
///
/// The paths come sorted (`PackageFiles` is a map), so every path below a
/// directory follows the others below it: each path's directories shared
/// with the one before it were checked with that one, and only the rest are
/// added. Each entry is kept once, folded to lower case, and a second one
/// that folds the same is a collision, so the work is linear in the paths'
/// length and stops as the count passes [`MAX_ENTRIES`].
///
/// [`store_sweep`] runs it first. `pull::open` runs it too, before the
/// store, so that a package refused here, which every later run would
/// refuse again, is told apart from a store that failed.
pub(crate) fn check_paths(files: &PackageFiles) -> anyhow::Result<()> {
    if files.len() > MAX_ENTRIES {
        return Err(too_many_entries());
    }
    // Every entry so far, folded to lower case.
    let mut seen = HashSet::new();
    // The parts of the path before, which borrow from `files`.
    let mut previous: Vec<&str> = Vec::new();
    for (path, _) in files.iter() {
        let parts: Vec<&str> = path.as_str().split('/').collect();
        check_parts(&parts)?;
        add_entries(&mut seen, &parts, shared_dirs(&previous, &parts))?;
        if seen.len() > MAX_ENTRIES {
            return Err(too_many_entries());
        }
        previous = parts;
    }
    Ok(())
}

/// Refuses a path of `parts` that is deeper than [`MAX_DEPTH`], has a part
/// that starts with `.`, or has a part named as a file an agent loads as
/// its instructions.
fn check_parts(parts: &[&str]) -> anyhow::Result<()> {
    if parts.len() > MAX_DEPTH {
        bail!(
            "its package has a path of more than {MAX_DEPTH} parts, deeper than submit walks, \
             so pull writes none of its files"
        );
    }
    if parts.iter().any(|part| part.starts_with('.')) {
        bail!(
            "its package has a path with a part that starts with '.', which tools read as their \
             settings, so pull writes none of its files"
        );
    }
    // `run::strip`'s own check, so this list and the one `run` strips from
    // a target never drift apart. `OsStr::new` views the `&str` as the
    // `&OsStr` a file name is, without copying it.
    if parts.iter().any(|part| is_agent_file(OsStr::new(part))) {
        bail!(
            "its package has a path with a part named as a file that agents load as their \
             instructions, so pull writes none of its files"
        );
    }
    Ok(())
}

/// Adds to `seen` the entries of the path of `parts` past its first
/// `shared` directories, each folded to lower case: its other directories
/// and its file. Refuses one `seen` holds already.
fn add_entries(seen: &mut HashSet<String>, parts: &[&str], shared: usize) -> anyhow::Result<()> {
    let mut entry = String::new();
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            entry.push('/');
        }
        entry.push_str(part);
        // `insert` returns `false` when an equal value is there already.
        if index >= shared && !seen.insert(entry.to_lowercase()) {
            bail!(
                "its package has two paths that differ only in case, or a file where another \
                 path has a directory, which a file system that ignores case takes as one, so \
                 pull writes none of its files"
            );
        }
    }
    Ok(())
}

/// The refusal of a package with more entries than [`MAX_ENTRIES`].
fn too_many_entries() -> anyhow::Error {
    anyhow!(
        "its package holds more than {MAX_ENTRIES} files and directories, more than submit \
         packages, so pull writes none of them"
    )
}

/// How many leading directories `previous` and `parts`, two paths' parts,
/// have in common. A path's last part is its file, so it never counts.
fn shared_dirs(previous: &[&str], parts: &[&str]) -> usize {
    let dirs = previous.len().min(parts.len()).saturating_sub(1);
    previous
        .iter()
        .zip(parts)
        .take(dirs)
        .take_while(|(before, now)| before == now)
        .count()
}

/// A store's staging directory, `<data dir>/staging/.pull.<pid>.<nanos>.<n>.tmp/`:
/// new, 0700 and this store's alone, with its path and an open handle to it.
/// Removed with all it holds when this is dropped, whether its contents
/// were moved into place, a step failed or returned early with `?`, or the
/// command was cancelled.
struct Staging {
    path: PathBuf,
    dir: OwnedFd,
}

impl Staging {
    /// Makes a new staging directory under `dirs`' data directory, and
    /// `staging/` itself if need be, both 0700. The name is `private_fs`'s
    /// for a temp file, which no other entry of `staging/` has: `run`'s are
    /// sweep ids.
    fn create(dirs: &Dirs) -> anyhow::Result<Self> {
        let parent = dirs.staging_dir();
        ensure_private_dir(&parent)?;
        let path = temp_path_beside(&parent.join("pull"))?;
        // Not `recursive`: the `mkdir` fails if anything at all is there, a
        // link included.
        DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .with_context(|| format!("could not create {}", path.display()))?;
        let dir = open_dir_path(&path)?;
        Ok(Self { path, dir })
    }

    /// Makes the directory `name` in the staging directory and opens it.
    fn new_dir(&self, name: &CStr) -> anyhow::Result<OwnedFd> {
        make_dir_at(self.dir.as_fd(), name).map_err(|err| write_error(err, &self.path))
    }
}

/// Best effort: `drop` cannot return an error. std's `remove_dir_all` never
/// follows a link inside the directory. A process killed outright (`kill
/// -9`) runs no `drop`, and leaves the directory behind, inside the 0700 data
/// directory.
impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// The owner's bounty directory, `<data>/<bounty id>`, opened from `data`,
/// the data directory's handle: made through `staging`, its owner check
/// inside, when nothing is there; then checked to be a real directory whose
/// owner check names `bounty`'s owner.
fn open_bounty_dir(
    dirs: &Dirs,
    data: BorrowedFd<'_>,
    staging: &Staging,
    bounty: BountyRef,
) -> anyhow::Result<OwnedFd> {
    let name = c_name(&bounty.id.to_string())?;
    let shown = dirs.pulled_bounty_dir(&bounty.id);
    if entry_at(data, &name, &shown.display().to_string())?.is_none() {
        make_bounty_dir(data, staging, bounty.owner, &name, &shown)?;
    }
    let Some(dir) = real_dir_at(data, &name, &shown)? else {
        bail!(changed(&shown));
    };
    check_owner(dirs, bounty)?;
    Ok(dir)
}

/// Makes the bounty directory `name` in `data`, shown as `shown`: staged
/// with its owner check naming `owner`, then moved in, so it never exists
/// without one.
fn make_bounty_dir(
    data: BorrowedFd<'_>,
    staging: &Staging,
    owner: Pubky,
    name: &CStr,
    shown: &Path,
) -> anyhow::Result<()> {
    let staged = staging.new_dir(name)?;
    let check = OwnerCheck {
        schema_version: SchemaVersion::CURRENT,
        owner,
    };
    let mut json = serde_json::to_vec(&check).context("could not write an owner check")?;
    json.push(b'\n');
    write_file_at(staged.as_fd(), OWNER_FILE, &json, &staging.path)?;
    sync_dir(staged.as_fd(), &staging.path)?;
    // `NameTaken` is no error here: another pull made the directory in the
    // meantime, and the caller reads its owner check.
    place(staging, name, data, shown)?;
    Ok(())
}

/// Refuses `bounty`'s directory unless its owner check names `bounty`'s
/// owner, compared by key bytes.
fn check_owner(dirs: &Dirs, bounty: BountyRef) -> anyhow::Result<()> {
    let dir = dirs.pulled_bounty_dir(&bounty.id);
    let path = dir.join(as_path(OWNER_FILE));
    let Some(bytes) = read_private_file(&path, MAX_OWNER_FILE_BYTES)? else {
        bail!(
            "{} has no owner check, so pull cannot tell whose bounty it holds, and neither \
             writes into it nor reads it. Move it away and pull again",
            dir.display()
        );
    };
    let check: OwnerCheck = serde_json::from_slice(&bytes)
        .map_err(RecordError::from)
        .with_context(|| format!("{} is not valid", path.display()))?;
    if check.owner != bounty.owner {
        bail!(
            "{} holds a bounty of another owner, {}, with the same id, not one of {}'s; pull \
             never mixes two owners' sweeps",
            dir.display(),
            check.owner,
            bounty.owner
        );
    }
    Ok(())
}

/// The bounty directory's `untrusted/`, `bounty_dir` the bounty
/// directory's handle: made 0700 if nothing is there, then opened as a real
/// directory, whoever made it.
fn untrusted_dir(
    dirs: &Dirs,
    bounty_dir: BorrowedFd<'_>,
    bounty: BountyRef,
) -> anyhow::Result<OwnedFd> {
    let shown = dirs.pulled_untrusted_dir(&bounty.id);
    match rustix::fs::mkdirat(bounty_dir, UNTRUSTED, DIR_MODE) {
        Ok(()) => sync_dir(bounty_dir, &shown)?,
        Err(Errno::EXIST) => {}
        Err(err) => {
            return Err(err).with_context(|| format!("could not create {}", shown.display()));
        }
    }
    real_dir_at(bounty_dir, UNTRUSTED, &shown)?.ok_or_else(|| anyhow!(changed(&shown)))
}

/// Where `sweep` is stored already, if it is: a real directory at its name
/// `name` directly in the bounty directory `bounty_dir`, or in its
/// `untrusted/`. A link or anything else at either is refused.
fn find_stored(
    dirs: &Dirs,
    bounty_dir: BorrowedFd<'_>,
    bounty: BountyRef,
    sweep: SweepRef,
    name: &CStr,
) -> anyhow::Result<Option<PathBuf>> {
    let trusted = sweep_path(dirs, bounty, sweep, Placement::Trusted);
    if is_stored_at(bounty_dir, name, &trusted)? {
        return Ok(Some(trusted));
    }
    let shown = dirs.pulled_untrusted_dir(&bounty.id);
    if let Some(untrusted) = real_dir_at(bounty_dir, UNTRUSTED, &shown)? {
        let path = sweep_path(dirs, bounty, sweep, Placement::Untrusted);
        if is_stored_at(untrusted.as_fd(), name, &path)? {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

/// Whether a sweep is stored at `name` in `dir`, shown as `shown`: a real
/// directory there is one, nothing there is none, and anything else, a
/// link above all, is refused.
fn is_stored_at(dir: BorrowedFd<'_>, name: &CStr, shown: &Path) -> anyhow::Result<bool> {
    let Some(seen) = entry_at(dir, name, &shown.display().to_string())? else {
        return Ok(false);
    };
    if kind(&seen) == FileType::Directory {
        return Ok(true);
    }
    bail!(
        "{} is there and is not a sweep pull stored (it is a link or a file); pull never writes \
         over or through it. Move it away and pull again",
        shown.display()
    )
}

/// The real directory `name` in `dir`, shown as `shown`, opened; `None`
/// when nothing is there. Looked at without following a link, refused when
/// it is a link or anything but a directory, then opened with `O_NOFOLLOW`
/// and checked to be the very directory looked at, so one swapped in
/// between is refused, never followed.
fn real_dir_at(dir: BorrowedFd<'_>, name: &CStr, shown: &Path) -> anyhow::Result<Option<OwnedFd>> {
    let Some(seen) = entry_at(dir, name, &shown.display().to_string())? else {
        return Ok(None);
    };
    match kind(&seen) {
        FileType::Directory => {}
        FileType::Symlink => bail!(
            "{} is a symbolic link; pull keeps the sweeps it stores in real directories of the \
             data directory, never through a link. Remove the link and pull again",
            shown.display()
        ),
        _ => bail!(
            "{} exists and is not a directory; move it away and pull again",
            shown.display()
        ),
    }
    let opened =
        rustix::fs::openat(dir, name, DIR_FLAGS, Mode::empty()).map_err(|err| match err {
            // A link, a file or nothing where the look saw a directory: swapped.
            Errno::LOOP | Errno::NOTDIR | Errno::NOENT => anyhow!(changed(shown)),
            other => {
                anyhow::Error::new(other).context(format!("could not open {}", shown.display()))
            }
        })?;
    let now = rustix::fs::fstat(&opened)
        .with_context(|| format!("could not inspect {}", shown.display()))?;
    if !same_entry(&seen, &now) {
        bail!(changed(shown));
    }
    Ok(Some(opened))
}

/// What [`place`] did.
enum Placed {
    /// The staged directory is at its place now.
    Moved,
    /// Something was at the name already, and nothing was moved or copied.
    NameTaken,
}

/// Moves `name`, staged in `staging`, to `name` in `dest`, shown as `shown`,
/// in one rename that never replaces, then syncs `dest` so the move
/// survives a crash. A file system that cannot promise not to replace, or a
/// staging directory on another one (`EXDEV`), gets `run`'s handle-only
/// copy, which refuses anything in its way just as the rename does.
fn place(
    staging: &Staging,
    name: &CStr,
    dest: BorrowedFd<'_>,
    shown: &Path,
) -> anyhow::Result<Placed> {
    match rustix::fs::renameat_with(&staging.dir, name, dest, name, RenameFlags::NOREPLACE) {
        Ok(()) => {}
        Err(Errno::EXIST | Errno::NOTEMPTY) => return Ok(Placed::NameTaken),
        Err(Errno::XDEV | Errno::INVAL | Errno::NOTSUP) => {
            // The copy's own errors name the entries it copies, a package's
            // paths among them, so they are not passed on.
            copy_sweep(
                staging.dir.as_fd(),
                name,
                dest,
                &shown.display().to_string(),
            )
            .map_err(|_| {
                anyhow!(
                    "could not copy into {}: the data directory's file system cannot move \
                         a directory into place without replacing what is there, and the \
                         copy pull makes instead failed; nothing of it was kept",
                    shown.display()
                )
            })?;
        }
        Err(err) => {
            return Err(err).with_context(|| format!("could not move into {}", shown.display()));
        }
    }
    sync_dir(dest, shown)?;
    Ok(Placed::Moved)
}

/// Writes `files` and the compact copy `findings` into `root`, the new
/// staged directory of one sweep, through handles: each directory made with
/// `mkdirat`, each file with `O_CREAT | O_EXCL | O_NOFOLLOW`, so anything
/// already at a name fails the write rather than be followed or replaced.
/// Each file is synced as it is written and each directory once it is full.
/// `shown`, the staging directory, is the one path a message names.
///
/// The paths come sorted, so every path below a directory follows the
/// others below it, and the directories open are kept on a stack: a
/// directory is made the first time a path needs it, and closed once a
/// path outside it comes, never to be needed again. One that is there
/// already when it is made is a second spelling of a name the file system
/// takes as one, and refuses the sweep.
fn write_sweep(
    root: BorrowedFd<'_>,
    files: PackageFiles,
    findings: &CompactFindings,
    shown: &Path,
) -> anyhow::Result<()> {
    // The directories open on the way to the file being written, outermost
    // first, each with its name.
    let mut open: Vec<(String, OwnedFd)> = Vec::new();
    // `for … in files` consumes the map: each file's buffer is dropped, and
    // wiped, at the end of its turn.
    for (path, bytes) in files {
        let mut dirs: Vec<&str> = path.as_str().split('/').collect();
        // `split` gives at least one part, so there is always a name.
        let Some(file_name) = dirs.pop() else {
            continue;
        };
        let shared = open
            .iter()
            .zip(&dirs)
            .take_while(|((open_name, _), dir)| open_name == *dir)
            .count();
        close_dirs(&mut open, shared, shown)?;
        for dir in dirs.iter().skip(shared) {
            // `innermost` borrows `open` only for the call, so the push
            // after it may change `open`.
            let made = make_dir_at(innermost(&open, root), &c_name(dir)?)
                .map_err(|err| write_error(err, shown))?;
            open.push(((*dir).to_owned(), made));
        }
        write_file_at(innermost(&open, root), &c_name(file_name)?, &bytes, shown)?;
    }
    close_dirs(&mut open, 0, shown)?;
    let copy_dir = make_dir_at(root, COPY_DIR).map_err(|err| write_error(err, shown))?;
    write_file_at(copy_dir.as_fd(), COPY_FILE, findings.as_bytes(), shown)?;
    sync_dir(copy_dir.as_fd(), shown)?;
    sync_dir(root, shown)
}

/// The innermost directory open, or `root` when none is.
// Both inputs share the lifetime `'a`, so the handle lent out lives no
// longer than either.
fn innermost<'a>(open: &'a [(String, OwnedFd)], root: BorrowedFd<'a>) -> BorrowedFd<'a> {
    open.last().map_or(root, |(_, dir)| dir.as_fd())
}

/// Closes the directories in `open` past the first `keep`, innermost first,
/// each synced so that the entries made in it are on disk.
fn close_dirs(open: &mut Vec<(String, OwnedFd)>, keep: usize, shown: &Path) -> anyhow::Result<()> {
    while open.len() > keep {
        // `pop` moves the handle out; it closes when `dir` is dropped.
        let Some((_, dir)) = open.pop() else {
            break;
        };
        sync_dir(dir.as_fd(), shown)?;
    }
    Ok(())
}

/// Makes the directory `name` in `dir`, 0700, and opens it. `mkdirat` fails
/// on anything at all at the name, a link included, and never follows it.
fn make_dir_at(dir: BorrowedFd<'_>, name: &CStr) -> Result<OwnedFd, Errno> {
    rustix::fs::mkdirat(dir, name, DIR_MODE)?;
    rustix::fs::openat(dir, name, DIR_FLAGS, Mode::empty())
}

/// Writes `bytes` to the new file `name` in `dir`, 0600, and syncs it.
/// `shown` names the directory in an error.
fn write_file_at(
    dir: BorrowedFd<'_>,
    name: &CStr,
    bytes: &[u8],
    shown: &Path,
) -> anyhow::Result<()> {
    let file = rustix::fs::openat(dir, name, NEW_FILE_FLAGS, FILE_MODE)
        .map_err(|err| write_error(err, shown))?;
    // `File::from` takes the handle over; `write_synced` writes, syncs and
    // closes it.
    write_synced(shown, File::from(file), bytes)
}

/// The error for making an entry in the staging directory `shown` that
/// failed with `err`. Something already at the name (`EEXIST`) means two of
/// the package's paths are one name to this file system, as the case check
/// could not tell; any other error is the system's, with the staging
/// directory added. Neither names the path.
fn write_error(err: Errno, shown: &Path) -> anyhow::Error {
    if err == Errno::EXIST {
        return anyhow!(
            "two of the package's paths name one file on this file system (they differ only in \
             case or in how their characters are composed), so pull writes none of its files"
        );
    }
    anyhow::Error::new(err).context(format!("could not write into {}", shown.display()))
}

/// Syncs the directory `dir`, shown as `shown`, so that what was made or
/// moved in it survives a crash.
fn sync_dir(dir: BorrowedFd<'_>, shown: &Path) -> anyhow::Result<()> {
    // `try_clone_to_owned` duplicates the handle, so a `File` can own the
    // copy and std's `sync_all` run on it (on macOS a full sync, as
    // `private_fs` does); the original stays open for the caller.
    let copy = dir
        .try_clone_to_owned()
        .with_context(|| format!("could not sync {}", shown.display()))?;
    File::from(copy)
        .sync_all()
        .with_context(|| format!("could not sync {}", shown.display()))
}

/// Whether a real directory is at `path`: `false` when nothing is, and an
/// error for a link, dangling or not, or anything else.
fn is_real_dir(path: &Path) -> anyhow::Result<bool> {
    let Some(meta) = lstat(path)? else {
        return Ok(false);
    };
    refuse_unless_dir(path, &meta)?;
    Ok(true)
}

/// The name of `sweep`'s directory: `<sweeper z32>-<sweep id>`.
fn sweep_dir_name(sweep: SweepRef) -> String {
    format!("{}-{}", sweep.sweeper, sweep.id)
}

/// The path of `sweep`'s directory, by `placement`, in `bounty`'s.
fn sweep_path(dirs: &Dirs, bounty: BountyRef, sweep: SweepRef, placement: Placement) -> PathBuf {
    let shelf = match placement {
        Placement::Trusted => dirs.pulled_bounty_dir(&bounty.id),
        Placement::Untrusted => dirs.pulled_untrusted_dir(&bounty.id),
    };
    shelf.join(sweep_dir_name(sweep))
}

/// `name` as a C string for the system calls. A package's paths hold no
/// control character, NUL included, and nor do ids and keys, so this does
/// not fail; it returns a `Result` all the same, and its error names
/// nothing.
fn c_name(name: &str) -> anyhow::Result<CString> {
    CString::new(name).map_err(|_| anyhow!("a name to write holds a NUL byte"))
}

/// `name`, one of the constants above, as a path to join.
fn as_path(name: &CStr) -> &Path {
    Path::new(OsStr::from_bytes(name.to_bytes()))
}

/// What every refusal of an entry that changed under `pull` says.
fn changed(shown: &Path) -> String {
    format!(
        "{} changed while pull was storing a sweep, and pull follows nothing it did not look at; \
         pull again once nothing is changing the data directory",
        shown.display()
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs::{self, File};
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};

    use serde_json::{Map, Value, json};
    use sweepky_core::{BountyRef, MAX_PACKAGE_BYTES, SweepPackage, SweepRef, Zeroizing};
    use tempfile::TempDir;

    use super::{
        CompactFindings, Placement, Stored, StoredCopy, check_paths, compact_with_cap,
        read_stored_findings, store_sweep, sweep_dir_name,
    };
    use crate::Dirs;
    use crate::private_fs::ensure_private_dir;
    use crate::submit::walk::{MAX_DEPTH, MAX_ENTRIES};
    use crate::test_support::{
        PLANTED, SYNTHETIC_SHA, bounty_id, dirs_in, json_bytes, mode, private_temp, random_pubky,
        record_id, stored_findings,
    };

    /// What a tree holds, by path relative to its root, links not
    /// followed: each entry's kind, permission bits and, for a file, bytes.
    type Tree = BTreeMap<String, (&'static str, u32, Vec<u8>)>;

    /// A data directory of its own, and a bounty of a random owner's.
    struct Fixture {
        // Kept so the directory lives as long as the fixture.
        _home: TempDir,
        dirs: Dirs,
        bounty: BountyRef,
    }

    impl Fixture {
        fn new() -> Self {
            let home = private_temp();
            let dirs = dirs_in(&home);
            let bounty = BountyRef {
                owner: random_pubky(),
                id: bounty_id(),
            };
            Self {
                _home: home,
                dirs,
                bounty,
            }
        }

        /// Splits `package` as `pull` does, its compact findings first, and
        /// stores it as `sweep` of `bounty`.
        fn store_as(
            &self,
            bounty: BountyRef,
            sweep: SweepRef,
            placement: Placement,
            package: SweepPackage,
        ) -> anyhow::Result<Stored> {
            let findings = CompactFindings::of(&package.findings)?;
            let files = package.into_files()?;
            store_sweep(&self.dirs, bounty, sweep, placement, findings, files)
        }

        /// [`store_as`](Self::store_as) for the fixture's bounty.
        fn store(
            &self,
            sweep: SweepRef,
            placement: Placement,
            package: SweepPackage,
        ) -> anyhow::Result<Stored> {
            self.store_as(self.bounty, sweep, placement, package)
        }

        /// Why storing `package` as a new sweep is refused, which it must.
        fn refusal(&self, placement: Placement, package: SweepPackage) -> String {
            match self.store(new_sweep(), placement, package) {
                Ok(stored) => panic!("stored: {stored:?}"),
                Err(err) => format!("{err:#}"),
            }
        }

        fn bounty_dir(&self) -> PathBuf {
            self.dirs.data().join(self.bounty.id.to_string())
        }

        fn untrusted_dir(&self) -> PathBuf {
            self.bounty_dir().join("untrusted")
        }

        /// What is left in `staging/`: nothing, once a store is over.
        fn staged(&self) -> Vec<PathBuf> {
            match fs::read_dir(self.dirs.data().join("staging")) {
                Ok(entries) => entries.map(|entry| entry.expect("entry").path()).collect(),
                Err(_) => Vec::new(),
            }
        }
    }

    /// A new sweep by a random sweeper.
    fn new_sweep() -> SweepRef {
        SweepRef {
            sweeper: random_pubky(),
            id: record_id(7),
        }
    }

    /// A decrypted package with `attachments`, by path, and findings with
    /// [`PLANTED`] in their text and a number serde_json writes back longer
    /// than it was given, read by core as `open_package` reads one.
    fn package(attachments: &[(&str, &str)]) -> SweepPackage {
        let attachments: Map<String, Value> = attachments
            .iter()
            .map(|(path, text)| ((*path).to_owned(), json!(text)))
            .collect();
        let bounty = BountyRef {
            owner: random_pubky(),
            id: bounty_id(),
        };
        let value = json!({
            "schemaVersion": 1,
            "manifest": {
                "sweeper": random_pubky().to_string(),
                "bounty": bounty.to_string(),
                "targets": ["t1"],
                "targetShas": { "t1": SYNTHETIC_SHA },
                "playbook": "careful-review",
                "startedAt": "2026-10-19T09:00:00Z",
                "finishedAt": "2026-10-19T10:00:00Z",
            },
            "findings": {
                "schemaVersion": 1,
                "playbook": "careful-review",
                "findings": [{
                    "id": "session-expiry-off-by-one",
                    "title": PLANTED,
                    "severity": null,
                    "confidence": null,
                    "status": "needs_validation",
                    "locations": [
                        { "file": "src/auth/session.rs", "line": 88, "scope": "fn is_expired" },
                    ],
                    "description": PLANTED,
                    "extra": { "measured": 1e15 },
                }],
            },
            "attachments": attachments,
        });
        SweepPackage::from_json(&json_bytes(&value)).expect("a package")
    }

    /// `package` split, by path, as the store is handed it.
    fn split(package: &SweepPackage) -> BTreeMap<String, Vec<u8>> {
        package
            .clone()
            .into_files()
            .expect("split")
            .iter()
            .map(|(path, bytes)| (path.to_string(), bytes.to_vec()))
            .collect()
    }

    /// Everything under `root`.
    fn tree(root: &Path) -> Tree {
        let mut found = Tree::new();
        let mut pending = vec![root.to_path_buf()];
        while let Some(dir) = pending.pop() {
            for entry in fs::read_dir(&dir).expect("list") {
                let path = entry.expect("entry").path();
                let meta = fs::symlink_metadata(&path).expect("there");
                let relative = path
                    .strip_prefix(root)
                    .expect("under root")
                    .to_str()
                    .expect("UTF-8")
                    .to_owned();
                let bits = mode(&path);
                let what = if meta.is_dir() {
                    pending.push(path);
                    ("dir", bits, Vec::new())
                } else if meta.is_file() {
                    ("file", bits, fs::read(&path).expect("read"))
                } else {
                    ("other", bits, Vec::new())
                };
                found.insert(relative, what);
            }
        }
        found
    }

    /// Checks that `message` quotes none of the planted text and none of
    /// `paths`, a package's.
    fn assert_quotes_none(message: &str, paths: &[&str]) {
        assert!(!message.contains(PLANTED), "{message}");
        for path in paths {
            assert!(!message.contains(path), "{message}");
        }
    }

    #[test]
    fn a_package_is_written_whole_with_owner_only_modes() {
        let fixture = Fixture::new();
        let package = package(&[("REPORT.md", "# Report\n"), ("notes/triage.md", PLANTED)]);
        let expected = split(&package);
        let sweep = new_sweep();

        let stored = fixture
            .store(sweep, Placement::Trusted, package)
            .expect("stored");

        let dir = fixture.bounty_dir().join(sweep_dir_name(sweep));
        assert_eq!(stored, Stored::Written(dir.clone()));
        let tree = tree(&dir);
        // Every file byte for byte and 0600, every directory 0700, and the
        // compact copy beside them, where no package path can be.
        for (path, bytes) in &expected {
            assert_eq!(
                tree.get(path),
                Some(&("file", 0o600, bytes.clone())),
                "{path}"
            );
        }
        assert_eq!(tree.get("notes").map(|entry| entry.1), Some(0o700));
        assert_eq!(tree.get(".sweepky").map(|entry| entry.1), Some(0o700));
        assert_eq!(
            tree.get(".sweepky/findings.json").map(|entry| entry.1),
            Some(0o600)
        );
        assert_eq!(tree.len(), expected.len() + 3, "{:?}", tree.keys());
        // The sweep's, the bounty's and the data directory are 0700 too, and
        // the bounty's owner check is 0600.
        for dir in [&dir, &fixture.bounty_dir(), fixture.dirs.data()] {
            assert_eq!(mode(dir), 0o700, "{}", dir.display());
        }
        assert_eq!(mode(&fixture.bounty_dir().join("owner.json")), 0o600);
        assert!(fixture.staged().is_empty(), "{:?}", fixture.staged());
    }

    #[test]
    fn an_untrusted_sweep_is_kept_in_untrusted_and_a_trusted_one_is_not() {
        let fixture = Fixture::new();
        let (trusted, untrusted) = (new_sweep(), new_sweep());

        fixture
            .store(trusted, Placement::Trusted, package(&[]))
            .expect("stored");
        let stored = fixture
            .store(untrusted, Placement::Untrusted, package(&[]))
            .expect("stored");

        let untrusted_dir = fixture.untrusted_dir().join(sweep_dir_name(untrusted));
        assert_eq!(stored, Stored::Written(untrusted_dir.clone()));
        assert!(untrusted_dir.join("findings.json").is_file());
        assert!(
            !fixture
                .bounty_dir()
                .join(sweep_dir_name(untrusted))
                .exists()
        );
        assert!(fixture.bounty_dir().join(sweep_dir_name(trusted)).is_dir());
        assert!(
            !fixture
                .untrusted_dir()
                .join(sweep_dir_name(trusted))
                .exists()
        );
        assert_eq!(mode(&fixture.untrusted_dir()), 0o700);
        let side = |sweep| {
            stored_findings(&fixture.dirs, fixture.bounty, sweep)
                .expect("read")
                .map(|(placement, _)| placement)
        };
        assert_eq!(side(untrusted), Some(Placement::Untrusted));
        assert_eq!(side(trusted), Some(Placement::Trusted));
    }

    #[test]
    fn a_part_that_starts_with_a_dot_refuses_the_sweep_before_anything_is_written() {
        for path in [
            ".git/config",
            ".claude/settings.json",
            ".vscode/x",
            "notes/.hidden.md",
        ] {
            let fixture = Fixture::new();

            let message = fixture.refusal(
                Placement::Untrusted,
                package(&[("REPORT.md", "# Report\n"), (path, PLANTED)]),
            );

            assert!(message.contains("starts with '.'"), "{path}: {message}");
            assert_quotes_none(&message, &[path]);
            assert!(
                !fixture.dirs.data().exists(),
                "{path}: something was written"
            );
        }
    }

    #[test]
    fn a_part_named_as_an_agent_instruction_file_refuses_the_sweep_before_anything_is_written() {
        // The names `run` strips from a target, at any depth, as a file or a
        // directory, in any case, and with the long s, which APFS folds to
        // `s`.
        for path in [
            "audit/CLAUDE.md",
            "AGENTS.md",
            "claude.md",
            "CLAUDE.local.md",
            "AGENT\u{17F}.md",
            "notes/Claude.MD/inside.md",
        ] {
            let fixture = Fixture::new();

            let message = fixture.refusal(
                Placement::Untrusted,
                package(&[("REPORT.md", "# Report\n"), (path, PLANTED)]),
            );

            assert!(
                message.contains("load as their instructions"),
                "{path}: {message}"
            );
            assert_quotes_none(&message, &[path, "CLAUDE", "AGENTS", ".md"]);
            assert!(
                !fixture.dirs.data().exists(),
                "{path}: something was written"
            );
        }
    }

    #[test]
    fn a_name_that_only_looks_like_an_agent_instruction_file_is_stored() {
        let fixture = Fixture::new();
        let package = package(&[
            ("README.md", PLANTED),
            ("claude-notes.md", PLANTED),
            ("audit/CLAUDE.md.txt", PLANTED),
        ]);
        let expected = split(&package);
        let sweep = new_sweep();

        fixture
            .store(sweep, Placement::Untrusted, package)
            .expect("stored");

        let tree = tree(&fixture.untrusted_dir().join(sweep_dir_name(sweep)));
        for (path, bytes) in &expected {
            assert_eq!(
                tree.get(path),
                Some(&("file", 0o600, bytes.clone())),
                "{path}"
            );
        }
    }

    #[test]
    fn paths_equal_once_case_is_folded_refuse_the_sweep_before_anything_is_written() {
        // Two files, a file beside the findings, a file where another path
        // has a directory, and one directory spelt two ways.
        let cases: [&[&str]; 4] = [
            &["README.md", "readme.md"],
            &["FINDINGS.json"],
            &["Notes", "notes/triage.md"],
            &["A/x.md", "a/y.md"],
        ];
        for paths in cases {
            let fixture = Fixture::new();
            let attachments: Vec<(&str, &str)> =
                paths.iter().map(|path| (*path, PLANTED)).collect();

            let message = fixture.refusal(Placement::Trusted, package(&attachments));

            assert!(
                message.contains("differ only in case"),
                "{paths:?}: {message}"
            );
            assert_quotes_none(&message, paths);
            assert!(
                !fixture.dirs.data().exists(),
                "{paths:?}: something was written"
            );
        }
    }

    #[test]
    fn more_entries_or_a_deeper_path_than_submit_walks_refuses_the_sweep_before_anything_is_written()
     {
        let names: Vec<String> = (0..MAX_ENTRIES).map(|n| format!("f{n}")).collect();
        // findings.json and MAX_ENTRIES - 1 files: the cap exactly.
        let at_cap: Vec<(&str, &str)> = names
            .iter()
            .skip(1)
            .map(|name| (name.as_str(), "x"))
            .collect();
        let files = package(&at_cap).into_files().expect("split");
        assert_eq!(files.len(), MAX_ENTRIES);
        check_paths(&files).expect("within the cap");
        // One file more; and directories count as entries too.
        let over: Vec<(&str, &str)> = names.iter().map(|name| (name.as_str(), "x")).collect();
        let nested: Vec<String> = names
            .iter()
            .take(MAX_ENTRIES / 2)
            .map(|name| format!("{name}/x"))
            .collect();
        let in_dirs: Vec<(&str, &str)> = nested.iter().map(|path| (path.as_str(), "x")).collect();
        for attachments in [over, in_dirs] {
            let fixture = Fixture::new();
            let message = fixture.refusal(Placement::Untrusted, package(&attachments));
            assert!(
                message.contains(&format!("more than {MAX_ENTRIES} files and directories")),
                "{message}"
            );
            assert!(!fixture.dirs.data().exists());
        }

        // A path of MAX_DEPTH parts is within the cap, and one more is not.
        let deep = vec!["d"; MAX_DEPTH - 1].join("/") + "/leaf.md";
        let files = package(&[(deep.as_str(), "x")])
            .into_files()
            .expect("split");
        check_paths(&files).expect("within the cap");
        let deeper = format!("d/{deep}");
        let fixture = Fixture::new();
        let message = fixture.refusal(Placement::Untrusted, package(&[(deeper.as_str(), "x")]));
        assert!(
            message.contains(&format!("more than {MAX_DEPTH} parts")),
            "{message}"
        );
        assert!(!fixture.dirs.data().exists());
    }

    #[test]
    fn a_link_or_a_file_in_the_way_is_refused_and_nothing_is_written_through_it() {
        // Where the sweep goes, a link or a file; untrusted/ a link; the
        // bounty's directory a link. Each with what its refusal says.
        let cases: [(&str, Placement, &str); 4] = [
            (
                "link at the sweep",
                Placement::Trusted,
                "not a sweep pull stored",
            ),
            (
                "file at the sweep",
                Placement::Trusted,
                "not a sweep pull stored",
            ),
            ("link at untrusted", Placement::Untrusted, "symbolic link"),
            ("link at the bounty", Placement::Untrusted, "symbolic link"),
        ];
        for (case, placement, expected) in cases {
            let fixture = Fixture::new();
            let elsewhere = private_temp();
            let sweep = new_sweep();
            let planted = match case {
                "link at the sweep" | "file at the sweep" => {
                    fixture
                        .store(new_sweep(), Placement::Trusted, package(&[]))
                        .expect("stored");
                    fixture.bounty_dir().join(sweep_dir_name(sweep))
                }
                "link at untrusted" => {
                    fixture
                        .store(new_sweep(), Placement::Trusted, package(&[]))
                        .expect("stored");
                    fixture.untrusted_dir()
                }
                _ => {
                    ensure_private_dir(fixture.dirs.data()).expect("data directory");
                    fixture.bounty_dir()
                }
            };
            if case == "file at the sweep" {
                fs::write(&planted, PLANTED).expect("write");
            } else {
                symlink(elsewhere.path(), &planted).expect("symlink");
            }

            let error = fixture
                .store(sweep, placement, package(&[("REPORT.md", PLANTED)]))
                .expect_err(case);

            let message = format!("{error:#}");
            assert!(message.contains(expected), "{case}: {message}");
            assert_quotes_none(&message, &["REPORT.md"]);
            assert_eq!(
                fs::read_dir(elsewhere.path()).expect("list").count(),
                0,
                "{case}: written through the link"
            );
            let meta = fs::symlink_metadata(&planted).expect("still there");
            if case == "file at the sweep" {
                assert_eq!(fs::read_to_string(&planted).expect("read"), PLANTED);
            } else {
                assert!(meta.is_symlink(), "{case}");
            }
            assert!(
                fixture.staged().is_empty(),
                "{case}: {:?}",
                fixture.staged()
            );
        }
    }

    #[test]
    fn a_sweep_already_stored_is_not_overwritten() {
        let fixture = Fixture::new();
        let sweep = new_sweep();
        let dir = fixture.bounty_dir().join(sweep_dir_name(sweep));
        fixture
            .store(
                sweep,
                Placement::Trusted,
                package(&[("REPORT.md", "first")]),
            )
            .expect("stored");
        let before = tree(&dir);

        // Stored again, on either side, it stays where and as it was.
        for placement in [Placement::Trusted, Placement::Untrusted] {
            let stored = fixture
                .store(sweep, placement, package(&[("REPORT.md", "second")]))
                .expect("not an error");
            assert_eq!(stored, Stored::AlreadyThere(dir.clone()));
            assert_eq!(tree(&dir), before);
        }
        assert!(!fixture.untrusted_dir().join(sweep_dir_name(sweep)).exists());
    }

    #[test]
    fn a_failed_write_leaves_no_part_of_the_sweep() {
        let fixture = Fixture::new();
        // A name longer than file systems take: REPORT.md, which sorts
        // first, is written in staging, then the long name fails, and
        // nothing is left anywhere.
        let long = format!("{}.md", "a".repeat(300));
        let other = new_sweep();
        let error = fixture
            .store(
                other,
                Placement::Untrusted,
                package(&[("REPORT.md", PLANTED), (long.as_str(), PLANTED)]),
            )
            .expect_err("refused");
        assert_quotes_none(&format!("{error:#}"), &[long.as_str()]);
        assert!(!fixture.untrusted_dir().join(sweep_dir_name(other)).exists());
        assert!(fixture.staged().is_empty(), "{:?}", fixture.staged());
    }

    #[test]
    fn the_compact_copy_reads_back_equal_within_its_cap() {
        let fixture = Fixture::new();
        let sweep = new_sweep();
        let package = package(&[]);
        let findings = package.findings.clone();
        let compact = CompactFindings::of(&findings).expect("compact");
        // Compact: serde_json's output with no whitespace, unlike the
        // pretty findings.json, in a buffer that wipes itself.
        assert_eq!(
            compact.as_bytes(),
            serde_json::to_vec(&findings).expect("JSON").as_slice()
        );
        let _: &Zeroizing<Vec<u8>> = &compact.0;

        fixture
            .store(sweep, Placement::Trusted, package)
            .expect("stored");

        assert_eq!(
            stored_findings(&fixture.dirs, fixture.bounty, sweep).expect("read"),
            Some((Placement::Trusted, findings.clone()))
        );
        // A sweep never stored has none.
        assert_eq!(
            stored_findings(&fixture.dirs, fixture.bounty, new_sweep()).expect("read"),
            None
        );

        // Read back with the caller's cap: at the copy's length it is read,
        // and the length comes back; one byte under, nothing is read.
        let len = compact.as_bytes().len();
        let at_len = read_stored_findings(&fixture.dirs, fixture.bounty, sweep, len);
        assert!(
            matches!(at_len, Ok(Some(StoredCopy::Read { len: read, .. })) if read == len),
            "{at_len:?}"
        );
        let under = read_stored_findings(&fixture.dirs, fixture.bounty, sweep, len - 1);
        let expected = u64::try_from(len).expect("fits");
        assert!(
            matches!(under, Ok(Some(StoredCopy::OverCap { len })) if len == expected),
            "{under:?}"
        );

        // At its cap a copy is made; one byte under, it is refused.
        assert!(compact_with_cap(&findings, len).is_ok());
        let error = compact_with_cap(&findings, len - 1).expect_err("over the cap");
        let message = format!("{error:#}");
        assert!(message.contains("more than"), "{message}");
        assert_quotes_none(&message, &[]);

        // A copy on disk over the package's cap is never read, whatever cap
        // the caller asks for.
        let copy = fixture
            .bounty_dir()
            .join(sweep_dir_name(sweep))
            .join(".sweepky/findings.json");
        let too_long = u64::try_from(MAX_PACKAGE_BYTES + 1).expect("fits");
        File::options()
            .write(true)
            .open(&copy)
            .expect("open")
            .set_len(too_long)
            .expect("set_len");
        let over = read_stored_findings(&fixture.dirs, fixture.bounty, sweep, usize::MAX);
        assert!(
            matches!(over, Ok(Some(StoredCopy::OverCap { len })) if len == too_long),
            "{over:?}"
        );
    }

    #[test]
    fn a_bounty_directory_of_another_owner_is_never_written_into_or_read() {
        let fixture = Fixture::new();
        let sweep = new_sweep();
        fixture
            .store(sweep, Placement::Trusted, package(&[]))
            .expect("stored");
        let before = tree(&fixture.bounty_dir());
        // Another owner's bounty with the same id, on the same data
        // directory.
        let other = BountyRef {
            owner: random_pubky(),
            id: fixture.bounty.id,
        };

        let error = fixture
            .store_as(other, new_sweep(), Placement::Untrusted, package(&[]))
            .expect_err("refused");

        assert!(format!("{error:#}").contains("another owner"), "{error:#}");
        assert_eq!(tree(&fixture.bounty_dir()), before);
        let error = read_stored_findings(&fixture.dirs, other, sweep, MAX_PACKAGE_BYTES)
            .expect_err("refused");
        assert!(format!("{error:#}").contains("another owner"), "{error:#}");
    }
}
