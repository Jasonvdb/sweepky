//! `submit`'s walk of a sweep directory, and the file calls it is built
//! from, which [`sweep_dir`](super::sweep_dir) uses as well, and `run`'s
//! placement of a sweep in the project (`run::place`).
//!
//! The agent wrote the sweep directory after reading untrusted code, and may
//! have left a process running that changes it while `submit` reads it
//! (02, "`submit` trusts nothing in the sweep directory"). The walk:
//!
//! - **Follows nothing, and lets nothing be swapped in.** Every step is
//!   taken relative to a directory handle `submit` already holds open,
//!   never by looking a path up again from the top. An entry is looked at
//!   with `statat(AT_SYMLINK_NOFOLLOW)`, which describes a link itself, the
//!   handle-relative form of `symlink_metadata`. A directory is then opened
//!   with `O_DIRECTORY | O_NOFOLLOW` and a file with `O_NOFOLLOW |
//!   O_NONBLOCK`, so a link swapped in after the look makes the open fail
//!   rather than be followed, and a FIFO swapped in cannot make it wait.
//!   Each open handle is `fstat`ed and must be the very entry looked at: the
//!   same kind, device and inode, and for a file the same size and one
//!   link. Why not `symlink_metadata` on a path and then `open` it, as P2b's
//!   Build line words it: between the two calls a racing process can swap a
//!   directory on the path for a link, and the `open` would follow it into
//!   `~/.config/sweepky/`. A handle cannot be swapped.
//! - **Refuses** a symbolic link, a hard link (a regular file with more
//!   than one link, which can share a file outside the sweep directory), a
//!   FIFO, a socket and a device, wherever it walks: the command stops and
//!   names the entry.
//! - **Skips** two places it never looks into: `target/`, the fetched
//!   targets, directly in the sweep directory; and `scratch/` in each
//!   `audit/agents/<agent>/`, which Cloudflare's skill gives every hunter
//!   and verifier for target-controlled output (its `SKILL.md` at
//!   `c1c8a8c`, line 66: `<output-dir>/agents/<agent-id>/scratch/`, and
//!   `audit/` is the output directory `run` names in `scope.json`).
//!   Neither is read or packaged, so whatever is there, links included, is
//!   left alone.
//! - **Reads only `audit/`'s files**, the agent's output directory (02, 03).
//!   Everything else, `scope.json`, `brief.md`, the marker and the submitted
//!   stamp among them, is checked by the same rules but not read.
//! - **Is bounded before it reads**: at most [`MAX_ENTRIES`] entries and
//!   [`MAX_DEPTH`] directories deep, each file at most [`MAX_FILE_BYTES`]
//!   (`findings.json` at most `MAX_FINDINGS_BYTES`), and `audit/`'s files
//!   together at most `MAX_PACKAGE_BYTES`. Each cap is checked against what
//!   `statat` saw, before the open, so a file over one is never read, nor
//!   is anything after it.
//!
//! The bytes read go into `Zeroizing` buffers, which wipe themselves when
//! dropped: a sweep's audit is owner-only content until it is encrypted.
//!
//! Every call here is rustix's safe API, so this crate still has no
//! `unsafe`. `OwnedFd` is an open handle that closes itself when dropped,
//! and `BorrowedFd<'_>` lends one without giving it up: the borrow checker
//! makes sure no handle is used after it is closed.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::iter;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;

use anyhow::{Context as _, anyhow, bail};
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;
use sweepky_core::{FINDINGS_FILE, MAX_FINDINGS_BYTES, MAX_PACKAGE_BYTES, SweepFile, Zeroizing};

use super::sweep_dir::SweepDir;
use crate::display::sanitize;
use crate::private_fs::read_up_to_cap;

/// The most bytes one file of `audit/` may have, `findings.json` aside: 8
/// MiB. A report or a coverage ledger is far smaller; P2b's choice.
pub(super) const MAX_FILE_BYTES: usize = 8 * 1024 * 1024;

/// The most entries the walk looks at, directories and files alike, and the
/// most `submit` lists in `sweeps/` when it picks a sweep: 4096. Counting
/// every entry, not only files, bounds the work a directory of a million
/// empty directories could cause. `target/` and each skipped `scratch/`
/// count as one entry, their contents as none. P2b's choice.
pub(crate) const MAX_ENTRIES: usize = 4096;

/// The most directories deep the walk goes below the sweep directory:
/// `audit/` is 1 deep, `audit/notes/` 2. P2b's choice.
pub(crate) const MAX_DEPTH: usize = 32;

/// How many characters of a path in the sweep directory a message shows:
/// as many as core's `AttachmentPath` allows.
const MAX_PATH_CHARS: usize = 512;

// `c"…"` is a C string literal: a `&'static CStr`, the bytes and a closing
// NUL, which is what the system calls take. A name like these is one path
// component, so `openat` can never be sent through a `/` by one.
/// The agent's output directory, directly in the sweep directory.
const AUDIT: &CStr = c"audit";
/// The fetched targets, directly in the sweep directory: never walked.
const TARGET: &CStr = c"target";
/// The playbook's per-agent directories, directly in `audit/`.
const AGENTS: &CStr = c"agents";
/// Each agent's target-controlled output, in `audit/agents/<agent>/`: never
/// walked.
const SCRATCH: &CStr = c"scratch";

/// How a directory is opened: read-only, a directory or nothing
/// (`O_DIRECTORY`), never through a link (`O_NOFOLLOW`), never waiting
/// (`O_NONBLOCK`), and not handed to any program this one starts
/// (`O_CLOEXEC`). `union` is the `const` form of `|`, so this can be a
/// constant.
pub(crate) const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);

/// How a file is opened: as a directory is, without `O_DIRECTORY`, and with
/// `O_NOCTTY`, so a terminal device swapped in never becomes this process's
/// terminal. `O_NONBLOCK` makes the open of a FIFO return at once instead
/// of waiting for a writer; the `fstat` after it then refuses the FIFO.
pub(crate) const FILE_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::NOCTTY)
    .union(OFlags::CLOEXEC);

/// What the walk read from `audit/`.
// No `Debug` derive: a derived one would print nothing secret (`SweepFile`'s
// own `Debug` prints lengths only), but the agent's file names would still
// show, and nothing needs it.
pub(crate) struct AuditFiles {
    /// Every regular file under `audit/` at a UTF-8 path, relative to
    /// `audit/` (`findings.json`, `notes/triage.md`), in walk order: each
    /// directory's entries sorted by name, depth first. Their bytes are in
    /// `Zeroizing` buffers, ready for `SweepPackage::build`, which checks
    /// each path.
    pub(crate) files: Vec<SweepFile>,
    /// Files under `audit/` whose path is not UTF-8, which a package's
    /// paths must be: checked like the rest, never read, and left out.
    /// Each is shown relative to the sweep directory, written lossily and
    /// already sanitised.
    pub(crate) not_utf8: Vec<String>,
}

impl AuditFiles {
    /// The file list `submit` prints before it encrypts: one line per file,
    /// `audit/<path> (<n> bytes)`, then one per file left out because its
    /// name is not UTF-8. Every path is the agent's, so each goes through
    /// the terminal sanitiser.
    pub(crate) fn listing(&self) -> Vec<String> {
        let read = self.files.iter().map(|file| {
            format!(
                "audit/{} ({} bytes)",
                sanitize(&file.path, MAX_PATH_CHARS),
                file.bytes.len()
            )
        });
        let left_out = self
            .not_utf8
            .iter()
            .map(|shown| format!("{shown} (left out: its name is not UTF-8)"));
        read.chain(left_out).collect()
    }
}

/// Walks the sweep directory `sweep` (see the module docs) and reads
/// `audit/`'s files. Refuses, naming the entry, anything the rules above
/// refuse, and a sweep directory with no real `audit/` directory.
pub(super) fn read_audit(sweep: &SweepDir) -> anyhow::Result<AuditFiles> {
    let mut walk = Walk {
        sweep_dir: sweep.path(),
        entries: 0,
        total_bytes: 0,
        saw_audit: false,
        files: Vec::new(),
        not_utf8: Vec::new(),
    };
    walk.walk_dir(sweep.fd(), &mut Vec::new(), "")?;
    if !walk.saw_audit {
        bail!(
            "{}/audit/ is missing or is not a directory: the playbook writes its output there, so \
             there is nothing to submit",
            sweep.path().display()
        );
    }
    Ok(AuditFiles {
        files: walk.files,
        not_utf8: walk.not_utf8,
    })
}

/// One walk's running state. It borrows the sweep directory's path (the
/// lifetime `'a`) for its messages.
struct Walk<'a> {
    sweep_dir: &'a Path,
    /// Entries looked at so far, against [`MAX_ENTRIES`].
    entries: usize,
    /// Bytes of `audit/` read so far, against `MAX_PACKAGE_BYTES`.
    total_bytes: usize,
    /// Whether a real `audit/` directory was walked.
    saw_audit: bool,
    files: Vec<SweepFile>,
    not_utf8: Vec<String>,
}

impl Walk<'_> {
    /// Walks the directory `dir`, which is at `at` below the sweep
    /// directory (`[]` for the sweep directory itself, `["audit",
    /// "notes"]` for `audit/notes/`) and is shown as `shown_dir` (`""` for
    /// the sweep directory).
    ///
    /// It calls itself for each directory inside, at most [`MAX_DEPTH`]
    /// deep, so at most that many handles are open at once. `at` is one
    /// `Vec` shared by every level: a level pushes a name before it goes
    /// down and pops it on the way back, so no path is copied per level.
    fn walk_dir(
        &mut self,
        dir: BorrowedFd<'_>,
        at: &mut Vec<CString>,
        shown_dir: &str,
    ) -> anyhow::Result<()> {
        let names = self.list(dir, shown_dir)?;
        for name in names {
            if is_skipped(at, &name) {
                continue;
            }
            let shown = child_shown(shown_dir, &name);
            let full = self.full(&shown);
            let Some(seen) = entry_at(dir, &name, &full)? else {
                bail!(changed(&full));
            };
            if kind(&seen) == FileType::Directory {
                if at.len() >= MAX_DEPTH {
                    bail!(
                        "{full} is more than {MAX_DEPTH} directories deep in the sweep directory, \
                         deeper than submit walks; nothing more was read"
                    );
                }
                let child = open_dir_at(dir, &name, &seen, &full)?;
                if at.is_empty() && name.as_c_str() == AUDIT {
                    self.saw_audit = true;
                }
                // `push` moves the name into the stack, so it is not copied;
                // the call below borrows `child` and `at` only while it runs.
                at.push(name);
                self.walk_dir(child.as_fd(), at, &shown)?;
                at.pop();
            } else {
                refuse_unless_plain_file(&seen, &full)?;
                self.take_file(dir, at, &name, &seen, &shown)?;
            }
        }
        Ok(())
    }

    /// The names in `dir`, shown as `shown_dir`, sorted by their bytes so
    /// the walk and the file list come out the same every time. Refuses a
    /// walk that would pass [`MAX_ENTRIES`] before anything in `dir` is
    /// looked at.
    fn list(&mut self, dir: BorrowedFd<'_>, shown_dir: &str) -> anyhow::Result<Vec<CString>> {
        let shown = if shown_dir.is_empty() {
            self.sweep_dir.display().to_string()
        } else {
            self.full(shown_dir)
        };
        // `saturating_sub` cannot go below zero; `entries` never passes the
        // cap anyway, because passing it ends the walk.
        let budget = MAX_ENTRIES.saturating_sub(self.entries);
        let Some(names) = list_entries(dir, &shown, budget)? else {
            bail!(
                "{} holds more than {MAX_ENTRIES} entries outside target/ and the agents' \
                 scratch/ directories, more than submit walks; nothing more was read",
                self.sweep_dir.display()
            );
        };
        self.entries += names.len();
        Ok(names)
    }

    /// Takes the regular file `name` in `dir`, at `at` and shown as
    /// `shown`, which `seen` describes and [`refuse_unless_plain_file`]
    /// passed: inside `audit/` it is read (or, at a path that is not UTF-8,
    /// listed in `not_utf8`); anywhere else, checking it was all there was
    /// to do.
    fn take_file(
        &mut self,
        dir: BorrowedFd<'_>,
        at: &[CString],
        name: &CStr,
        seen: &Stat,
        shown: &str,
    ) -> anyhow::Result<()> {
        // A slice pattern: `[first, ..]` matches a non-empty slice and
        // binds its first element, with no indexing that could panic.
        let in_audit = matches!(at, [first, ..] if first.as_c_str() == AUDIT);
        if !in_audit {
            return Ok(());
        }
        let Some(path) = audit_path(at, name) else {
            self.not_utf8.push(shown.to_owned());
            return Ok(());
        };
        let full = self.full(shown);
        self.count_bytes(&path, seen, &full, shown)?;
        let bytes = read_file_at(dir, name, seen, &full)?;
        // The buffer moves into the `SweepFile` as it is: no copy is made
        // and none is left behind unwiped.
        self.files.push(SweepFile { path, bytes });
        Ok(())
    }

    /// Refuses the `audit/` file at `path` (relative to `audit/`), which
    /// `seen` describes, when its size is over its own cap or would take
    /// `audit/`'s total over `MAX_PACKAGE_BYTES`; otherwise adds it to the
    /// total. Runs before the file is opened.
    fn count_bytes(
        &mut self,
        path: &str,
        seen: &Stat,
        full: &str,
        shown: &str,
    ) -> anyhow::Result<()> {
        let (cap, what) = if path == FINDINGS_FILE {
            (MAX_FINDINGS_BYTES, "findings.json")
        } else {
            (MAX_FILE_BYTES, "any other file")
        };
        // `filter` turns `Some(len)` into `None` when the test fails, so
        // one `let … else` covers a size over the cap and one that does not
        // fit in a `usize`.
        let Some(len) = file_len(seen).filter(|len| *len <= cap) else {
            bail!(
                "{full} is {} bytes, more than the {cap} bytes submit packages from {what}; \
                 nothing more was read",
                seen.st_size
            );
        };
        let Some(total) = self
            .total_bytes
            .checked_add(len)
            .filter(|total| *total <= MAX_PACKAGE_BYTES)
        else {
            bail!(
                "the files in {}/audit/ come to more than the {MAX_PACKAGE_BYTES} bytes a sweep \
                 package may hold, at {shown}; nothing more was read",
                self.sweep_dir.display()
            );
        };
        self.total_bytes = total;
        Ok(())
    }

    /// `shown`, a path relative to the sweep directory, after the sweep
    /// directory's own path, for a message.
    fn full(&self, shown: &str) -> String {
        format!("{}/{shown}", self.sweep_dir.display())
    }
}

/// Whether the walk leaves `name`, at `at`, alone: `target` directly in the
/// sweep directory, and `scratch` directly in `audit/agents/<agent>/`.
/// Neither is looked at, so not even a link there is refused.
fn is_skipped(at: &[CString], name: &CStr) -> bool {
    match at {
        [] => name == TARGET,
        [audit, agents, _agent] => {
            audit.as_c_str() == AUDIT && agents.as_c_str() == AGENTS && name == SCRATCH
        }
        _ => false,
    }
}

/// The entry `name` of the directory shown as `shown_dir`, relative to the
/// sweep directory and `/`-separated: the name written lossily where it is
/// not UTF-8, and sanitised, since every name is the agent's.
fn child_shown(shown_dir: &str, name: &CStr) -> String {
    let name = sanitize(&name.to_string_lossy(), MAX_PATH_CHARS);
    if shown_dir.is_empty() {
        name
    } else {
        format!("{shown_dir}/{name}")
    }
}

/// The path of `name` at `at` relative to `audit/`, `at`'s first part, with
/// `/` between parts: what a package keys the file by. `None` when a part
/// is not UTF-8.
fn audit_path(at: &[CString], name: &CStr) -> Option<String> {
    // `collect` into `Option<Vec<_>>` stops at the first `None`.
    let parts: Option<Vec<&str>> = at
        .iter()
        .skip(1)
        .map(|part| part.as_c_str())
        .chain(iter::once(name))
        .map(|part| part.to_str().ok())
        .collect();
    parts.map(|parts| parts.join("/"))
}

/// The names in the directory `dir`, `.` and `..` left out, sorted; `None`
/// when it holds more than `limit`, found before any name past the limit is
/// kept. `shown` names the directory in an error.
pub(crate) fn list_entries(
    dir: BorrowedFd<'_>,
    shown: &str,
    limit: usize,
) -> anyhow::Result<Option<Vec<CString>>> {
    // `Dir::read_from` opens a second handle to the same directory for its
    // stream (an `openat` of `.`, which no link can stand in for), and
    // leaves `dir` itself untouched.
    let entries = Dir::read_from(dir).with_context(|| format!("could not list {shown}"))?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("could not list {shown}"))?;
        let name = entry.file_name();
        if name == c"." || name == c".." {
            continue;
        }
        if names.len() == limit {
            return Ok(None);
        }
        // `to_owned` copies the name out of the entry, which the stream
        // reuses for the next one.
        names.push(name.to_owned());
    }
    names.sort_unstable();
    Ok(Some(names))
}

/// What is at `name` in `dir`, the entry itself and never what a link there
/// points at (`statat` with `AT_SYMLINK_NOFOLLOW`), or `None` when nothing
/// is. `shown` names it in an error.
pub(crate) fn entry_at(
    dir: BorrowedFd<'_>,
    name: &CStr,
    shown: &str,
) -> anyhow::Result<Option<Stat>> {
    match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(seen) => Ok(Some(seen)),
        Err(Errno::NOENT) => Ok(None),
        Err(err) => Err(err).with_context(|| format!("could not inspect {shown}")),
    }
}

/// The kind of entry `stat` describes.
pub(crate) fn kind(stat: &Stat) -> FileType {
    FileType::from_raw_mode(stat.st_mode)
}

/// Refuses the entry `seen` describes, `shown` in messages, unless it is a
/// regular file with exactly one link: the only kind of file `submit` ever
/// reads. A symbolic link, a FIFO, a socket, a device, a directory and a
/// file with other hard links are each refused, saying which.
pub(super) fn refuse_unless_plain_file(seen: &Stat, shown: &str) -> anyhow::Result<()> {
    let what = match kind(seen) {
        FileType::RegularFile => {
            // Compared with `1` of whatever integer type the platform's
            // `st_nlink` is, so no conversion is needed.
            if seen.st_nlink != 1 {
                bail!(
                    "{shown} has {} hard links; submit reads only a file with one, because another \
                     link can be a file outside the sweep directory. Remove it and run submit \
                     again",
                    seen.st_nlink
                );
            }
            return Ok(());
        }
        FileType::Symlink => {
            bail!(
                "{shown} is a symbolic link; submit never follows a link or packages one. Remove it \
                 and run submit again"
            )
        }
        FileType::Directory => "a directory",
        FileType::Fifo => "a FIFO",
        FileType::Socket => "a socket",
        FileType::CharacterDevice => "a character device",
        FileType::BlockDevice => "a block device",
        FileType::Unknown => "of a kind submit does not know",
    };
    bail!(
        "{shown} is {what}, not a regular file; submit reads nothing else. Remove it and run \
         submit again"
    )
}

/// Opens the directory `name` in `dir`, which `seen`, its [`entry_at`],
/// shows is a real directory, without following a link, and checks the
/// handle is that very directory. `shown` names it in an error.
pub(super) fn open_dir_at(
    dir: BorrowedFd<'_>,
    name: &CStr,
    seen: &Stat,
    shown: &str,
) -> anyhow::Result<OwnedFd> {
    let opened = rustix::fs::openat(dir, name, DIR_FLAGS, Mode::empty())
        .map_err(|err| open_error(err, shown))?;
    let now = rustix::fs::fstat(&opened).with_context(|| format!("could not inspect {shown}"))?;
    if !same_entry(seen, &now) {
        bail!(changed(shown));
    }
    Ok(opened)
}

/// Reads the regular file `name` in `dir`, which `seen`, its [`entry_at`],
/// describes, into a buffer that wipes itself. `shown` names it in an
/// error.
///
/// The caller has refused anything [`refuse_unless_plain_file`] refuses and
/// checked `seen`'s size against its cap. Here the open handle must be the
/// file `seen` describes, still with one link and the same size, before a
/// byte is read and again after the last; at most one byte past that size
/// is read, so a file that grew is caught without reading the rest of it.
pub(super) fn read_file_at(
    dir: BorrowedFd<'_>,
    name: &CStr,
    seen: &Stat,
    shown: &str,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let Some(len) = file_len(seen) else {
        bail!("{shown} has a size submit cannot hold in memory, so it is not read");
    };
    let opened = rustix::fs::openat(dir, name, FILE_FLAGS, Mode::empty())
        .map_err(|err| open_error(err, shown))?;
    check_unchanged(seen, &opened, shown)?;
    // `File::from` takes the handle over, so std's `Read` can read from it;
    // the file closes when `file` is dropped.
    let mut file = File::from(opened);
    // `read_up_to_cap` reads into a zeroed buffer of that size, never
    // grown. `len + 1` cannot overflow: the caller capped `len`.
    let bytes =
        read_up_to_cap(&mut file, len + 1).with_context(|| format!("could not read {shown}"))?;
    if bytes.len() != len {
        bail!(changed(shown));
    }
    check_unchanged(seen, &file, shown)?;
    Ok(bytes)
}

/// Refuses `file` unless it is still the regular file `seen` describes,
/// with one link and the same size.
fn check_unchanged(seen: &Stat, file: impl AsFd, shown: &str) -> anyhow::Result<()> {
    let now = rustix::fs::fstat(file).with_context(|| format!("could not inspect {shown}"))?;
    let unchanged = kind(&now) == FileType::RegularFile
        && now.st_nlink == 1
        && now.st_size == seen.st_size
        && same_entry(seen, &now);
    if !unchanged {
        bail!(changed(shown));
    }
    Ok(())
}

/// Whether `a` and `b` describe the same entry: the same kind, on the same
/// device, at the same inode.
pub(crate) fn same_entry(a: &Stat, b: &Stat) -> bool {
    kind(a) == kind(b) && a.st_dev == b.st_dev && a.st_ino == b.st_ino
}

/// The size `stat` gives, or `None` when it does not fit in a `usize`
/// (`st_size` is a signed number, so a negative one does not either).
pub(super) fn file_len(stat: &Stat) -> Option<usize> {
    usize::try_from(stat.st_size).ok()
}

/// The error for an `openat` of `shown` that failed with `err`: a link
/// (`ELOOP`), a non-directory (`ENOTDIR`) or nothing (`ENOENT`) where the
/// look a moment before saw something else means the entry was swapped or
/// removed; any other error is the system's, with the name added.
fn open_error(err: Errno, shown: &str) -> anyhow::Error {
    match err {
        Errno::LOOP | Errno::NOTDIR | Errno::NOENT => anyhow!(changed(shown)),
        other => anyhow::Error::new(other).context(format!("could not open {shown}")),
    }
}

/// What every refusal of an entry that changed under `submit` says.
fn changed(shown: &str) -> String {
    format!(
        "{shown} changed while submit was reading it; run submit again once nothing is changing \
         the sweep directory"
    )
}

#[cfg(test)]
mod tests {
    use std::ffi::{CString, OsStr};
    use std::fs::{self, File};
    use std::os::fd::AsFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;
    use std::path::Path;
    use std::process::Command;

    use rustix::io::Errno;
    use sweepky_core::{MAX_FINDINGS_BYTES, MAX_PACKAGE_BYTES, Zeroizing};

    use super::{
        AuditFiles, MAX_DEPTH, MAX_ENTRIES, MAX_FILE_BYTES, entry_at, open_dir_at, read_audit,
        read_file_at,
    };
    use crate::submit::fixture::{ConfigDir, SweepFixture};
    use crate::test_support::{PLANTED, chmod};

    /// What the walk reads from `fixture`'s sweep directory, which must be
    /// accepted. (`AuditFiles` has no `Debug`, so `expect` is not used.)
    fn walked(fixture: &SweepFixture) -> AuditFiles {
        read_audit(&fixture.open()).unwrap_or_else(|err| panic!("refused: {err:#}"))
    }

    /// Why the walk refuses `fixture`'s sweep directory, which it must.
    fn refusal(fixture: &SweepFixture) -> String {
        match read_audit(&fixture.open()) {
            Ok(files) => panic!("accepted: {:?}", paths(&files)),
            Err(err) => format!("{err:#}"),
        }
    }

    /// The packaged paths, in order.
    fn paths(files: &AuditFiles) -> Vec<&str> {
        files.files.iter().map(|file| file.path.as_str()).collect()
    }

    /// A FIFO at `path`, made with the system's `mkfifo`: std has no call
    /// for one, and rustix has none on macOS.
    fn mkfifo(path: &Path) {
        let status = Command::new("mkfifo")
            .arg(path)
            .status()
            .expect("mkfifo runs");
        assert!(status.success(), "mkfifo {}", path.display());
    }

    /// A sparse file of `len` bytes at `path`: `set_len` grows it without
    /// writing, so a test of the size caps costs no disk.
    fn sparse(path: &Path, len: usize) {
        let file = File::create(path).expect("create");
        file.set_len(u64::try_from(len).expect("fits"))
            .expect("set_len");
    }

    #[test]
    fn audit_files_come_back_relative_to_audit_in_wiped_buffers() {
        let fixture = SweepFixture::new();
        let audit = fixture.audit();
        fs::write(audit.join("REPORT.md"), "# Report\n").expect("write");
        fs::create_dir(audit.join("notes")).expect("mkdir");
        fs::write(audit.join("notes/triage.md"), "triage\n").expect("write");

        let files = walked(&fixture);

        // Sorted by name in each directory, depth first. scope.json,
        // brief.md, the marker and target/ are there too, and none is
        // packaged.
        assert_eq!(
            paths(&files),
            ["REPORT.md", "findings.json", "notes/triage.md"]
        );
        let report = files.files.first().expect("a file");
        assert_eq!(report.bytes.as_slice(), b"# Report\n");
        // A compile-time check: the bytes are held in a buffer that wipes
        // itself when dropped.
        let _: &Zeroizing<Vec<u8>> = &report.bytes;
        assert!(files.not_utf8.is_empty());
        let findings = format!("audit/findings.json ({} bytes)", fixture.findings_len());
        assert_eq!(
            files.listing(),
            [
                "audit/REPORT.md (9 bytes)",
                findings.as_str(),
                "audit/notes/triage.md (7 bytes)",
            ]
        );
    }

    #[test]
    fn the_printed_list_is_sanitised() {
        let fixture = SweepFixture::new();
        fs::write(fixture.audit().join("evil\u{1b}[2J\u{202e}.md"), "x").expect("write");

        let listing = walked(&fixture).listing().join("\n");

        assert!(!listing.contains('\u{1b}'), "{listing}");
        assert!(!listing.contains('\u{202e}'), "{listing}");
        assert!(
            listing.contains("audit/evil\\u{1b}[2J\\u{202e}.md (1 bytes)"),
            "{listing}"
        );
    }

    #[test]
    fn a_name_that_is_not_utf8_is_left_out_unread() {
        let fixture = SweepFixture::new();
        // Made unreadable: were it read, the walk would fail on the
        // permission.
        let latin1 = fixture.audit().join(OsStr::from_bytes(b"caf\xe9.txt"));
        match fs::write(&latin1, "x") {
            Ok(()) => chmod(&latin1, 0o000),
            // APFS, macOS's filesystem, takes only UTF-8 names, so there
            // such a file cannot exist and there is nothing to test; ext4,
            // on which CI runs, takes any bytes.
            Err(err) if err.raw_os_error() == Some(Errno::ILSEQ.raw_os_error()) => return,
            Err(err) => panic!("write: {err}"),
        }

        let files = walked(&fixture);

        assert_eq!(files.not_utf8, ["audit/caf\u{fffd}.txt"]);
        assert_eq!(paths(&files), ["findings.json"]);
        assert!(
            files
                .listing()
                .contains(&"audit/caf\u{fffd}.txt (left out: its name is not UTF-8)".to_owned()),
            "{:?}",
            files.listing()
        );
    }

    #[test]
    fn a_link_to_a_config_file_is_refused_by_name_and_never_followed() {
        let fixture = SweepFixture::new();
        let config = ConfigDir::new(&fixture);
        // Unreadable: were the link followed, the walk would fail on the
        // permission, not on the link.
        chmod(&config.device_key(), 0o000);
        symlink(config.device_key(), fixture.audit().join("stolen")).expect("symlink");

        let message = refusal(&fixture);

        assert!(
            message.contains("audit/stolen is a symbolic link"),
            "{message}"
        );
        assert!(!message.contains(PLANTED), "{message}");
        assert!(!message.contains("ermission"), "{message}");
    }

    #[test]
    fn a_hard_link_and_any_file_with_two_links_are_refused() {
        // A hard link to a file in the config directory, which shares the
        // temp root's filesystem.
        let fixture = SweepFixture::new();
        let config = ConfigDir::new(&fixture);
        fs::hard_link(config.device_key(), fixture.audit().join("copy")).expect("hard link");
        let message = refusal(&fixture);
        assert!(message.contains("audit/copy has 2 hard links"), "{message}");
        assert!(!message.contains(PLANTED), "{message}");

        // Two names for one file inside audit/, and two outside it, which
        // are checked although they are not read.
        for (first, second) in [
            ("audit/a.md", "audit/b.md"),
            ("notes.txt", "more-notes.txt"),
        ] {
            let fixture = SweepFixture::new();
            let first = fixture.dir().join(first);
            fs::write(&first, "shared").expect("write");
            fs::hard_link(&first, fixture.dir().join(second)).expect("hard link");
            let message = refusal(&fixture);
            assert!(message.contains("has 2 hard links"), "{message}");
        }
    }

    #[test]
    fn fifos_sockets_and_linked_directories_are_refused() {
        // A FIFO: refused from the look alone, so the walk never waits on it.
        let fixture = SweepFixture::new();
        mkfifo(&fixture.audit().join("pipe"));
        let message = refusal(&fixture);
        assert!(message.contains("audit/pipe is a FIFO"), "{message}");

        // A socket, at a short name so the path fits a socket's limit.
        let fixture = SweepFixture::new();
        let _socket = UnixListener::bind(fixture.audit().join("s")).expect("bind");
        let message = refusal(&fixture);
        assert!(message.contains("audit/s is a socket"), "{message}");

        // A linked subdirectory, and a linked audit/ itself, into the
        // config directory.
        let fixture = SweepFixture::new();
        let config = ConfigDir::new(&fixture);
        symlink(config.path(), fixture.audit().join("sub")).expect("symlink");
        let message = refusal(&fixture);
        assert!(
            message.contains("audit/sub is a symbolic link"),
            "{message}"
        );

        let fixture = SweepFixture::new();
        let config = ConfigDir::new(&fixture);
        fs::remove_dir_all(fixture.audit()).expect("rm");
        symlink(config.path(), fixture.audit()).expect("symlink");
        let message = refusal(&fixture);
        assert!(message.contains("audit is a symbolic link"), "{message}");
        assert!(!message.contains(PLANTED), "{message}");

        // And a sweep directory with no audit/ at all, or a file there.
        let fixture = SweepFixture::new();
        fs::remove_dir_all(fixture.audit()).expect("rm");
        assert!(refusal(&fixture).contains("audit/ is missing"));
        fs::write(fixture.audit(), "not a directory").expect("write");
        assert!(refusal(&fixture).contains("audit/ is missing"));
    }

    #[test]
    fn target_and_the_agents_scratch_directories_are_never_looked_at() {
        let fixture = SweepFixture::new();
        let config = ConfigDir::new(&fixture);
        let target = fixture.dir().join("target/t1");
        fs::create_dir_all(&target).expect("mkdir");
        symlink(config.device_key(), target.join("planted")).expect("symlink");
        mkfifo(&target.join("pipe"));
        let agent = fixture.audit().join("agents/hunter-1");
        fs::create_dir_all(agent.join("scratch")).expect("mkdir");
        fs::create_dir_all(agent.join("artifacts")).expect("mkdir");
        symlink(config.path(), agent.join("scratch/out")).expect("symlink");
        fs::write(agent.join("artifacts/check.txt"), "observed").expect("write");

        let files = walked(&fixture);

        // The agent's retained artifacts are packaged; its scratch is not.
        assert_eq!(
            paths(&files),
            ["agents/hunter-1/artifacts/check.txt", "findings.json"]
        );

        // Only those exact places are skipped: a scratch/ elsewhere in
        // audit/ is walked like any directory.
        fs::create_dir(fixture.audit().join("scratch")).expect("mkdir");
        symlink(config.path(), fixture.audit().join("scratch/out")).expect("symlink");
        let message = refusal(&fixture);
        assert!(
            message.contains("audit/scratch/out is a symbolic link"),
            "{message}"
        );
    }

    #[test]
    fn a_file_over_its_cap_is_refused_before_it_is_read() {
        // One byte over the cap of an ordinary file, and of findings.json.
        // Each is unreadable, so a read would fail on the permission
        // instead of the cap.
        for (name, len) in [
            ("big.log", MAX_FILE_BYTES + 1),
            ("findings.json", MAX_FINDINGS_BYTES + 1),
        ] {
            let fixture = SweepFixture::new();
            let path = fixture.audit().join(name);
            sparse(&path, len);
            chmod(&path, 0o000);
            let message = refusal(&fixture);
            assert!(
                message.contains(&format!("audit/{name} is {len} bytes, more than the")),
                "{message}"
            );
        }

        // findings.json may be larger than any other file.
        let fixture = SweepFixture::new();
        sparse(&fixture.audit().join("findings.json"), MAX_FILE_BYTES + 1);
        walked(&fixture);
    }

    #[test]
    fn audit_files_over_the_package_cap_together_are_refused_before_the_rest_is_read() {
        let fixture = SweepFixture::new();
        let audit = fixture.audit();
        // a to d come to exactly the package's 32 MiB, which is allowed; e,
        // one byte more, is unreadable, so reading it would fail on the
        // permission rather than the cap.
        let quarter = MAX_PACKAGE_BYTES / 4;
        assert!(quarter <= MAX_FILE_BYTES);
        for name in ["a", "b", "c", "d"] {
            sparse(&audit.join(name), quarter);
        }
        let past = audit.join("e");
        fs::write(&past, "e").expect("write");
        chmod(&past, 0o000);

        let message = refusal(&fixture);

        assert!(
            message.contains(&format!(
                "come to more than the {MAX_PACKAGE_BYTES} bytes a sweep package may hold, at \
                 audit/e"
            )),
            "{message}"
        );
    }

    #[test]
    fn more_entries_than_the_cap_or_a_tree_deeper_than_the_cap_is_refused() {
        let fixture = SweepFixture::new();
        let many = fixture.audit().join("many");
        fs::create_dir(&many).expect("mkdir");
        for n in 0..MAX_ENTRIES {
            File::create(many.join(n.to_string())).expect("create");
        }
        let message = refusal(&fixture);
        assert!(
            message.contains(&format!("more than {MAX_ENTRIES} entries")),
            "{message}"
        );

        // audit/ is one deep, so MAX_DEPTH - 1 directories inside it are
        // within the cap, and one more is not.
        let fixture = SweepFixture::new();
        let mut deep = fixture.audit();
        for _ in 1..MAX_DEPTH {
            deep.push("d");
        }
        fs::create_dir_all(&deep).expect("mkdir");
        fs::write(deep.join("leaf.md"), "deep").expect("write");
        walked(&fixture);
        fs::create_dir(deep.join("d")).expect("mkdir");
        let message = refusal(&fixture);
        assert!(
            message.contains(&format!("more than {MAX_DEPTH} directories deep")),
            "{message}"
        );
    }

    #[test]
    fn a_file_that_changes_between_the_look_and_the_read_is_refused() {
        let fixture = SweepFixture::new();
        let config = ConfigDir::new(&fixture);
        let sweep = fixture.open();
        let seen_audit = entry_at(sweep.fd(), c"audit", "audit")
            .expect("lstat")
            .expect("there");
        let audit = open_dir_at(sweep.fd(), c"audit", &seen_audit, "audit").expect("opened");
        let dir = audit.as_fd();
        let path = fixture.audit().join("f.md");
        let second = path.with_extension("second");
        let name = CString::new("f.md").expect("no NUL");

        // Each case: the file is looked at, then changed, then read, which
        // must refuse. A FIFO in its place makes the open return at once
        // rather than wait for a writer.
        let cases: [(&str, &dyn Fn()); 5] = [
            ("grew", &|| {
                fs::write(&path, "longer than before").expect("write")
            }),
            ("replaced", &|| {
                let other = path.with_extension("new");
                fs::write(&other, "same").expect("write");
                fs::rename(&other, &path).expect("rename");
            }),
            ("hard-linked", &|| {
                fs::hard_link(&path, &second).expect("link");
            }),
            ("a link now", &|| {
                fs::remove_file(&path).expect("rm");
                symlink(config.device_key(), &path).expect("symlink");
            }),
            ("a FIFO now", &|| {
                fs::remove_file(&path).expect("rm");
                mkfifo(&path);
            }),
        ];
        for (case, change) in cases {
            fs::write(&path, "same").expect("write");
            let seen = entry_at(dir, &name, "audit/f.md")
                .expect("lstat")
                .expect("there");
            change();
            let err = read_file_at(dir, &name, &seen, "audit/f.md").expect_err(case);
            let message = format!("{err:#}");
            assert!(
                message.contains("changed while submit was reading it"),
                "{case}: {message}"
            );
            assert!(!message.contains(PLANTED), "{case}: {message}");
            for leftover in [&path, &second] {
                let _ = fs::remove_file(leftover);
            }
        }

        // A directory swapped for a link to one is refused the same way.
        let sub = fixture.audit().join("sub");
        fs::create_dir(&sub).expect("mkdir");
        let seen = entry_at(dir, c"sub", "audit/sub")
            .expect("lstat")
            .expect("there");
        fs::remove_dir(&sub).expect("rmdir");
        symlink(config.path(), &sub).expect("symlink");
        let err = open_dir_at(dir, c"sub", &seen, "audit/sub").expect_err("refused");
        assert!(
            format!("{err:#}").contains("changed while submit"),
            "{err:#}"
        );

        // And a file left as it was reads back whole.
        fs::write(&path, "same").expect("write");
        let seen = entry_at(dir, &name, "audit/f.md")
            .expect("lstat")
            .expect("there");
        let bytes = read_file_at(dir, &name, &seen, "audit/f.md").expect("read");
        assert_eq!(bytes.as_slice(), b"same");
    }
}
