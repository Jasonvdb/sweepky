//! Where `run` puts the sweep it built: `<project>/sweeps/<id>/`. This is
//! the one step of `run` that writes into the project, and it does so only
//! through directory handles that follow no link.
//!
//! **Why a step of its own.** The project is the agent's to write, and a
//! process an earlier, prompt-injected agent session left running there may
//! still be at work (02 names this adversary for `submit`). So `fetch`
//! builds the whole sweep directory first under the data directory, which
//! the sandbox keeps the agent from (`<data dir>/staging/<id>/`): git runs
//! there, the agent files are stripped there, and `scope.json`, `brief.md`
//! and the per-sweep marker are written there. [`place_sweep`] then brings
//! the finished directory into the project:
//!
//! - **Through handles.** The project directory is opened once (its own
//!   path is the user's, and `O_NOFOLLOW` refuses a link at its last part),
//!   then `sweeps` in it, made if it is missing: looked at with
//!   `statat(AT_SYMLINK_NOFOLLOW)`, which describes a link itself, opened
//!   with `O_DIRECTORY | O_NOFOLLOW`, and the handle `fstat`ed and compared
//!   with the look, the same device and inode. A link or anything else at
//!   `sweeps` is refused, never followed, and so is a directory swapped in
//!   between the look and the open. Why not `lstat` a path and then use
//!   it: between the two calls a racing process can swap a directory on
//!   the path for a link. A handle cannot be swapped.
//! - **In one move.** `renameat` with `RENAME_NOREPLACE` (`RENAME_EXCL` on
//!   macOS), relative to the staging directory's handle and `sweeps`'s,
//!   moves the staged directory to `sweeps/<id>` in one step: the project
//!   shows the whole sweep, marker and all, or nothing. Anything already at
//!   `sweeps/<id>`, a link, a file, or a directory holding a planted
//!   `.git/config`, makes the move fail rather than be replaced, merged
//!   with or written through.
//! - **Or as a copy, when it cannot move.** A data directory on another
//!   filesystem than the project (`EXDEV`), or a filesystem that cannot
//!   promise not to replace (`EINVAL` on Linux, `ENOTSUP` on macOS), gets a
//!   copy, through the handles alone: each directory made with `mkdirat`
//!   and opened as above, each file made with `O_CREAT | O_EXCL |
//!   O_NOFOLLOW`, so nothing already in the destination is followed,
//!   replaced or written into; regular files and directories only, `.git`
//!   among them, so the agent can still diff a pull request; at most
//!   [`MAX_COPY_DEPTH`] directories deep; the marker last, so a copy cut
//!   short holds none. A copy that fails is removed again through the same
//!   handles, best effort, and the staged original goes either way, with
//!   `fetch`'s guard.
//!
//! Every call here is rustix's safe API, as in `submit`'s walk, whose
//! look-ups this module shares, so the crate still has no `unsafe`.
//! `OwnedFd` is an open handle that closes itself when dropped, and
//! `BorrowedFd<'_>` lends one out without giving it up.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;

use anyhow::{Context as _, anyhow, bail};
use rustix::fs::{AtFlags, FileType, Mode, OFlags, RenameFlags, Stat};
use rustix::io::Errno;
use sweepky_core::RecordId;

use super::marker::MARKER_DIR;
use crate::display::sanitize;
use crate::submit::walk::{DIR_FLAGS, FILE_FLAGS, entry_at, kind, list_entries, same_entry};

// `c"…"` is a C string literal: a `&'static CStr`, the bytes and a closing
// NUL, which is what the system calls take.
/// The project's directory of sweeps, directly in the project.
const SWEEPS: &CStr = c"sweeps";

/// The most directories deep a copy goes below the sweep directory: 64.
/// Each level holds two open handles, the staged directory's and the
/// copy's, and macOS lets a process hold 256 by default, so the deepest copy
/// stays well within that. A deeper tree is refused, and the copy removed,
/// rather than copied in part. P2b's choice: a repository's tree is rarely
/// a third as deep.
const MAX_COPY_DEPTH: usize = 64;

/// How many characters of a name from the staged tree a message shows. The
/// names are the repository's, so each is sanitised first.
const MAX_NAME_CHARS: usize = 255;

/// How a copied file is made: write-only, new (`O_CREAT | O_EXCL`, which
/// fails on anything already at the name, a link included, dangling or
/// not), never through a link (`O_NOFOLLOW`, belt and braces), never this
/// process's terminal, and not handed to any program this one starts.
/// `union` is the `const` form of `|`, so this can be a constant.
pub(crate) const NEW_FILE_FLAGS: OFlags = OFlags::WRONLY
    .union(OFlags::CREATE)
    .union(OFlags::EXCL)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NOCTTY)
    .union(OFlags::CLOEXEC);

/// The permission bits a copied entry keeps: read, write and execute for
/// the owner, the group and others, and no set-user-ID, set-group-ID or
/// sticky bit. The umask takes off what it would take off a checkout.
const PERMISSIONS: Mode = Mode::RWXU.union(Mode::RWXG).union(Mode::RWXO);

/// Moves the sweep directory staged as `<staging>/<id>` to
/// `<project>/sweeps/<id>`, making `sweeps/` if it is missing (see the
/// module docs). Refuses, writing nothing through it, a link or anything
/// but a directory at `sweeps`, and anything at all already at
/// `sweeps/<id>`.
pub(super) fn place_sweep(staging: &Path, project: &Path, id: RecordId) -> anyhow::Result<()> {
    // A record id is 13 ASCII letters and digits: no NUL, so `CString::new`
    // cannot fail (it returns a `Result` all the same), and no `/`, so the
    // name is one directory entry.
    let name = CString::new(id.to_string()).context("a sweep id is plain ASCII")?;
    let sweeps_shown = format!("{}/sweeps", project.display());
    let shown = format!("{sweeps_shown}/{id}");
    let project_dir = open_dir_path(project)?;
    let sweeps = open_sweeps(project_dir.as_fd(), &sweeps_shown)?;
    let staging_dir = open_dir_path(staging)?;
    match rustix::fs::renameat_with(&staging_dir, &name, &sweeps, &name, RenameFlags::NOREPLACE) {
        Ok(()) => Ok(()),
        Err(Errno::EXIST | Errno::NOTEMPTY) => bail!(already_there(&shown)),
        // The copy refuses whatever is in its way just as the move does, so
        // it keeps the move's promise on any filesystem.
        Err(Errno::XDEV | Errno::INVAL | Errno::NOTSUP) => {
            copy_sweep(staging_dir.as_fd(), &name, sweeps.as_fd(), &shown)
        }
        Err(err) => Err(err).with_context(|| format!("could not move the sweep into {shown}")),
    }
}

/// What `run` says of `shown`, a part of a sweep directory, when something
/// is already at it.
pub(super) fn already_there(shown: &str) -> String {
    format!(
        "{shown} is already there; run puts every sweep in new entries of its own, and never \
         writes into, over or through one that exists"
    )
}

/// The directory at `path`, opened. Its path is the user's own (the
/// project's, or the data directory's), so the parts above it are taken as
/// they are; `O_NOFOLLOW` still refuses a link at its last part.
pub(crate) fn open_dir_path(path: &Path) -> anyhow::Result<OwnedFd> {
    rustix::fs::open(path, DIR_FLAGS, Mode::empty())
        .with_context(|| format!("could not open {}", path.display()))
}

/// `sweeps` in the project directory `project`, shown as `shown`: made if
/// nothing is there, then opened as a real directory, whoever made it.
fn open_sweeps(project: BorrowedFd<'_>, shown: &str) -> anyhow::Result<OwnedFd> {
    match rustix::fs::mkdirat(project, SWEEPS, PERMISSIONS) {
        Ok(()) | Err(Errno::EXIST) => {}
        Err(err) => return Err(err).with_context(|| format!("could not create {shown}")),
    }
    real_dir_at(project, SWEEPS, shown)
}

/// The real directory `name` in `dir`, shown as `shown`, opened: looked at
/// without following a link, refused when it is a link or anything but a
/// directory, then opened by [`open_seen_dir`].
fn real_dir_at(dir: BorrowedFd<'_>, name: &CStr, shown: &str) -> anyhow::Result<OwnedFd> {
    let Some(seen) = entry_at(dir, name, shown)? else {
        bail!(changed(shown));
    };
    match kind(&seen) {
        FileType::Directory => open_seen_dir(dir, name, &seen, shown),
        FileType::Symlink => bail!(
            "{shown} is a symbolic link; run puts a sweep only in real directories of the init \
             project, never through a link. Remove the link and try again"
        ),
        _ => bail!("{shown} exists and is not a directory; move it away and try again"),
    }
}

/// Makes the directory `name` in `dir`, shown as `shown`, with `mode`, and
/// opens it. Refused when anything at all is already at the name: `mkdirat`
/// fails on a link there too, and never follows it.
fn new_dir_at(
    dir: BorrowedFd<'_>,
    name: &CStr,
    mode: Mode,
    shown: &str,
) -> anyhow::Result<OwnedFd> {
    match rustix::fs::mkdirat(dir, name, mode) {
        Ok(()) => real_dir_at(dir, name, shown),
        Err(Errno::EXIST) => bail!(already_there(shown)),
        Err(err) => Err(err).with_context(|| format!("could not create {shown}")),
    }
}

/// Opens the directory `name` in `dir`, which `seen` shows was a real
/// directory a moment ago, without following a link, and checks the handle
/// is that very directory. A link or another directory swapped in since
/// the look is refused, never followed.
fn open_seen_dir(
    dir: BorrowedFd<'_>,
    name: &CStr,
    seen: &Stat,
    shown: &str,
) -> anyhow::Result<OwnedFd> {
    let opened = rustix::fs::openat(dir, name, DIR_FLAGS, Mode::empty())
        .map_err(|err| open_error(err, shown))?;
    check_same(seen, &opened, shown)?;
    Ok(opened)
}

/// Refuses `opened` unless it is the entry `seen` describes: the same
/// kind, on the same device, at the same inode.
fn check_same(seen: &Stat, opened: impl AsFd, shown: &str) -> anyhow::Result<()> {
    let now = rustix::fs::fstat(opened).with_context(|| format!("could not inspect {shown}"))?;
    if !same_entry(seen, &now) {
        bail!(changed(shown));
    }
    Ok(())
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

/// What every refusal of an entry that changed under `run` says.
fn changed(shown: &str) -> String {
    format!(
        "{shown} changed while run was putting the sweep in place, and run follows nothing it \
         did not look at; run it again once nothing is changing the project"
    )
}

/// The copy [`place_sweep`] falls back on: the staged sweep `name` in
/// `staging` copied to `name` in `sweeps`, shown as `shown`, through the
/// handles alone (see the module docs). A copy that fails is removed again,
/// best effort, so no part of a sweep is left for `submit` to find.
pub(crate) fn copy_sweep(
    staging: BorrowedFd<'_>,
    name: &CStr,
    sweeps: BorrowedFd<'_>,
    shown: &str,
) -> anyhow::Result<()> {
    let source = real_dir_at(staging, name, "the staged sweep")?;
    // 0700, as `fetch` made the staged one, so no other user of the machine
    // reads the audit the agent writes into it.
    let dest = new_dir_at(sweeps, name, Mode::RWXU, shown)?;
    // From here `sweeps/<id>` is this run's own, to take out again if the
    // copy fails.
    let copied = copy_contents(source.as_fd(), dest.as_fd(), shown, 0);
    if copied.is_err() {
        remove_tree_at(sweeps, name, 0);
    }
    copied
}

/// Copies what the staged directory `source` holds into the new directory
/// `dest`, shown as `shown`, `depth` directories below the sweep directory:
/// each directory made new and opened through its handle, each regular file
/// made new and filled, anything else refused. At the top, the marker's
/// directory goes last.
///
/// It calls itself for each directory inside, at most [`MAX_COPY_DEPTH`]
/// deep, so at most twice that many handles are open at once.
fn copy_contents(
    source: BorrowedFd<'_>,
    dest: BorrowedFd<'_>,
    shown: &str,
    depth: usize,
) -> anyhow::Result<()> {
    let mut names = names_in(source, shown)?;
    if depth == 0 {
        // `sort_by_key` keeps entries with equal keys in their order, and
        // `false` sorts before `true`: the marker's directory moves to the
        // end, and the rest stay sorted.
        names.sort_by_key(|name| name.as_bytes() == MARKER_DIR.as_bytes());
    }
    for name in names {
        let entry = format!(
            "{shown}/{}",
            sanitize(&name.to_string_lossy(), MAX_NAME_CHARS)
        );
        let Some(seen) = entry_at(source, &name, &entry)? else {
            bail!(changed(&entry));
        };
        match kind(&seen) {
            FileType::Directory => {
                if depth >= MAX_COPY_DEPTH {
                    bail!(
                        "{entry} is more than {MAX_COPY_DEPTH} directories deep in the sweep, \
                         deeper than run copies into the project; nothing more was copied"
                    );
                }
                let from = open_seen_dir(source, &name, &seen, &entry)?;
                // Always writable and searchable by the owner, so the copy
                // can fill it; git makes no directory that is not anyway.
                let mode = permissions(&seen).union(Mode::RWXU);
                let to = new_dir_at(dest, &name, mode, &entry)?;
                copy_contents(from.as_fd(), to.as_fd(), &entry, depth + 1)?;
            }
            FileType::RegularFile => copy_file(source, dest, &name, &seen, &entry)?,
            _ => bail!(
                "{entry} is neither a regular file nor a directory; run copies nothing else into \
                 the project"
            ),
        }
    }
    Ok(())
}

/// Copies the staged regular file `name` in `source`, which `seen`
/// describes, to a new file of that name in `dest`, with its permission
/// bits. `shown` names it in an error.
fn copy_file(
    source: BorrowedFd<'_>,
    dest: BorrowedFd<'_>,
    name: &CStr,
    seen: &Stat,
    shown: &str,
) -> anyhow::Result<()> {
    let from = rustix::fs::openat(source, name, FILE_FLAGS, Mode::empty())
        .map_err(|err| open_error(err, shown))?;
    check_same(seen, &from, shown)?;
    // A new file opened for writing can be written whatever mode it is
    // made with, so a read-only one, such as a git object, copies too.
    let to = match rustix::fs::openat(dest, name, NEW_FILE_FLAGS, permissions(seen)) {
        Ok(to) => to,
        Err(Errno::EXIST) => bail!(already_there(shown)),
        Err(err) => return Err(err).with_context(|| format!("could not create {shown}")),
    };
    // `File::from` takes each handle over, so std's `io::copy` can stream
    // one into the other; both close when they are dropped, here.
    io::copy(&mut File::from(from), &mut File::from(to))
        .with_context(|| format!("could not copy {shown}"))?;
    Ok(())
}

/// The permission bits of the entry `seen` describes, within
/// [`PERMISSIONS`].
fn permissions(seen: &Stat) -> Mode {
    Mode::from_raw_mode(seen.st_mode).intersection(PERMISSIONS)
}

/// The names in the directory `dir`, `.` and `..` left out, sorted. No cap:
/// the staged tree is `run`'s own checkout, which the fetch's and the
/// checkout's timeouts already bound.
fn names_in(dir: BorrowedFd<'_>, shown: &str) -> anyhow::Result<Vec<CString>> {
    // `list_entries` hands back `None` only past its limit, and no
    // directory holds `usize::MAX` names.
    Ok(list_entries(dir, shown, usize::MAX)?.unwrap_or_default())
}

/// Removes `name` in `dir` and, when it is a real directory, everything in
/// it, through handles: a link is removed itself and never followed, and
/// nothing deeper than [`MAX_COPY_DEPTH`] is looked into. A failed copy's
/// last step, best effort, so it returns nothing: the copy's own error is
/// the one to report.
fn remove_tree_at(dir: BorrowedFd<'_>, name: &CStr, depth: usize) {
    let Ok(seen) = rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) else {
        return;
    };
    if kind(&seen) != FileType::Directory {
        let _ = rustix::fs::unlinkat(dir, name, AtFlags::empty());
        return;
    }
    // `if … && let …` (a let chain) runs the block only when the depth is
    // within the cap and the directory opens, without following a link.
    if depth <= MAX_COPY_DEPTH
        && let Ok(opened) = rustix::fs::openat(dir, name, DIR_FLAGS, Mode::empty())
    {
        for child in names_in(opened.as_fd(), "a sweep run was removing").unwrap_or_default() {
            remove_tree_at(opened.as_fd(), &child, depth + 1);
        }
    }
    let _ = rustix::fs::unlinkat(dir, name, AtFlags::REMOVEDIR);
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use std::fs::{self, Permissions};
    use std::os::fd::{AsFd, OwnedFd};
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::os::unix::net::UnixListener;
    use std::path::Path;

    use sweepky_core::RecordId;
    use tempfile::TempDir;

    use super::{MAX_COPY_DEPTH, copy_contents, copy_sweep, open_dir_path, place_sweep};
    use crate::test_support::{PLANTED, bounty_id, mode, private_temp};

    /// What a tree holds, by path relative to its root: each entry's kind
    /// and permission bits, and a file's bytes.
    type Tree = BTreeMap<String, (&'static str, u32, Vec<u8>)>;

    /// The sweep id of the tests.
    fn id() -> RecordId {
        bounty_id()
    }

    fn id_name() -> CString {
        CString::new(id().to_string()).expect("ASCII")
    }

    /// Writes `bytes` to `root/relative` with `mode`, making its directories
    /// first.
    fn file(root: &Path, relative: &str, bytes: &[u8], mode: u32) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
        fs::write(&path, bytes).expect("write");
        fs::set_permissions(&path, Permissions::from_mode(mode)).expect("chmod");
    }

    /// A staging directory holding sweep [`id`], laid out as `fetch` lays
    /// one out: the marker, the brief, the scope and one target with a
    /// `.git`, a read-only object, an executable and an empty directory.
    fn staged() -> TempDir {
        let staging = private_temp();
        let sweep = staging.path().join(id().to_string());
        fs::create_dir(&sweep).expect("mkdir");
        fs::set_permissions(&sweep, Permissions::from_mode(0o700)).expect("chmod");
        file(
            &sweep,
            ".sweepky/sweep.json",
            b"{\"schemaVersion\":1}\n",
            0o600,
        );
        file(&sweep, "brief.md", b"# Brief\n", 0o644);
        file(&sweep, "scope.json", b"{}\n", 0o644);
        file(&sweep, "target/t1/.git/HEAD", b"791991b\n", 0o644);
        file(
            &sweep,
            "target/t1/.git/objects/79/1991b",
            b"\x78\x01",
            0o444,
        );
        file(&sweep, "target/t1/run.sh", b"#!/bin/sh\n", 0o755);
        file(&sweep, "target/t1/src/lib.rs", b"fn main() {}\n", 0o644);
        fs::create_dir(sweep.join("target/t1/empty")).expect("mkdir");
        staging
    }

    /// Everything under `root`, looked at without following a link.
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
                let bits = meta.mode() & 0o7777;
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

    fn open(path: &Path) -> OwnedFd {
        open_dir_path(path).expect("opens")
    }

    #[test]
    fn a_staged_sweep_is_moved_in_whole_and_sweeps_is_made_if_missing() {
        let staging = staged();
        let staged_sweep = staging.path().join(id().to_string());
        let before = tree(&staged_sweep);
        let project = private_temp();

        place_sweep(staging.path(), project.path(), id()).expect("placed");

        let placed = project.path().join("sweeps").join(id().to_string());
        assert_eq!(tree(&placed), before);
        assert_eq!(mode(&placed), 0o700);
        assert!(fs::symlink_metadata(&staged_sweep).is_err(), "still staged");
    }

    #[test]
    fn a_link_or_anything_in_the_way_is_refused_and_nothing_is_written_through_it() {
        let elsewhere = private_temp();
        let sweep_dir = |project: &Path| project.join("sweeps").join(id().to_string());
        // What the refusal says, and a closure that lays the project out.
        // `&dyn Fn` lets different closures share one array type.
        type Arrange<'a> = &'a dyn Fn(&Path);
        let cases: [(&str, Arrange<'_>); 5] = [
            ("symbolic link", &|project: &Path| {
                symlink(elsewhere.path(), project.join("sweeps")).expect("symlink");
            }),
            ("not a directory", &|project: &Path| {
                fs::write(project.join("sweeps"), PLANTED).expect("write");
            }),
            ("already there", &|project: &Path| {
                fs::create_dir(project.join("sweeps")).expect("mkdir");
                symlink(elsewhere.path(), sweep_dir(project)).expect("symlink");
            }),
            ("already there", &|project: &Path| {
                fs::create_dir_all(sweep_dir(project)).expect("mkdir");
                symlink(elsewhere.path(), sweep_dir(project).join("target")).expect("symlink");
            }),
            // Even an empty directory: the move never replaces one.
            ("already there", &|project: &Path| {
                fs::create_dir_all(sweep_dir(project)).expect("mkdir");
            }),
        ];
        for (expected, arrange) in cases {
            let staging = staged();
            let before = tree(staging.path());
            let project = private_temp();
            arrange(project.path());

            let error = place_sweep(staging.path(), project.path(), id()).expect_err(expected);

            let message = format!("{error:#}");
            assert!(message.contains(expected), "{message}");
            // The staged sweep is where it was, whole.
            assert_eq!(tree(staging.path()), before, "{expected}");
        }
        // Nothing was written through any link.
        assert_eq!(fs::read_dir(elsewhere.path()).expect("list").count(), 0);
    }

    #[test]
    fn the_copy_is_the_staged_tree_and_the_staged_one_stays_for_its_guard() {
        let staging = staged();
        let staged_sweep = staging.path().join(id().to_string());
        let before = tree(&staged_sweep);
        let project = private_temp();
        let sweeps = project.path().join("sweeps");
        fs::create_dir(&sweeps).expect("mkdir");
        let shown = sweeps.join(id().to_string()).display().to_string();

        copy_sweep(
            open(staging.path()).as_fd(),
            &id_name(),
            open(&sweeps).as_fd(),
            &shown,
        )
        .expect("copied");

        // The same entries, kinds, permission bits and bytes, `.git` and
        // the read-only object among them, and the sweep directory 0700.
        let copied = sweeps.join(id().to_string());
        assert_eq!(tree(&copied), before);
        assert_eq!(mode(&copied), 0o700);
        // `fetch`'s guard removes the staged original, not the copy.
        assert_eq!(tree(&staged_sweep), before);
    }

    #[test]
    fn the_copy_never_writes_into_or_through_what_is_in_the_destination() {
        let staging = staged();
        let staged_sweep = staging.path().join(id().to_string());
        let elsewhere = private_temp();
        fs::write(elsewhere.path().join("scope.json"), PLANTED).expect("write");
        // A destination someone made first, with a link where `target/`
        // goes, and one, in another, where `scope.json` goes.
        for (planted, target) in [
            ("target", elsewhere.path().to_path_buf()),
            ("scope.json", elsewhere.path().join("scope.json")),
        ] {
            let dest = private_temp();
            symlink(&target, dest.path().join(planted)).expect("symlink");

            let error = copy_contents(
                open(&staged_sweep).as_fd(),
                open(dest.path()).as_fd(),
                &dest.path().display().to_string(),
                0,
            )
            .expect_err("refused");

            let message = format!("{error:#}");
            assert!(message.contains("already there"), "{message}");
            assert!(
                fs::symlink_metadata(dest.path().join(planted))
                    .expect("there")
                    .is_symlink()
            );
        }
        // Nothing was written through either link.
        assert_eq!(
            fs::read_dir(elsewhere.path()).expect("list").count(),
            1,
            "a file appeared elsewhere"
        );
        assert_eq!(
            fs::read_to_string(elsewhere.path().join("scope.json")).expect("read"),
            PLANTED
        );
        // And a sweep directory that is there already is refused whole.
        let project = private_temp();
        let sweeps = project.path().join("sweeps");
        fs::create_dir_all(sweeps.join(id().to_string())).expect("mkdir");
        let error = copy_sweep(
            open(staging.path()).as_fd(),
            &id_name(),
            open(&sweeps).as_fd(),
            "sweeps/<id>",
        )
        .expect_err("refused");
        assert!(format!("{error:#}").contains("already there"), "{error:#}");
        assert_eq!(
            fs::read_dir(sweeps.join(id().to_string()))
                .expect("list")
                .count(),
            0
        );
    }

    #[test]
    fn a_copy_that_fails_leaves_no_marker_and_is_removed_again() {
        // A socket in the staged target, which the copy refuses: by then
        // the brief, the scope and part of the target are copied, and the
        // marker, which goes last, is not.
        let staging = staged();
        let staged_sweep = staging.path().join(id().to_string());
        let _socket = UnixListener::bind(staged_sweep.join("target/t1/socket")).expect("bind");
        let dest = private_temp();
        let error = copy_contents(
            open(&staged_sweep).as_fd(),
            open(dest.path()).as_fd(),
            "sweeps/<id>",
            0,
        )
        .expect_err("refused");
        assert!(
            format!("{error:#}").contains("neither a regular file nor a directory"),
            "{error:#}"
        );
        let partial = tree(dest.path());
        assert!(partial.contains_key("scope.json"), "{partial:?}");
        assert!(!partial.contains_key(".sweepky"), "{partial:?}");

        // Through `copy_sweep`, the partial copy is removed again, and so
        // is one past the depth cap.
        let deep = staged();
        let mut path = deep.path().join(id().to_string()).join("target/t1");
        for _ in 0..MAX_COPY_DEPTH {
            path.push("d");
        }
        fs::create_dir_all(&path).expect("mkdir");
        for (staging, expected) in [
            (&staging, "neither a regular file nor a directory"),
            (&deep, "directories deep"),
        ] {
            let project = private_temp();
            let sweeps = project.path().join("sweeps");
            fs::create_dir(&sweeps).expect("mkdir");
            let error = copy_sweep(
                open(staging.path()).as_fd(),
                &id_name(),
                open(&sweeps).as_fd(),
                "sweeps/<id>",
            )
            .expect_err("refused");
            assert!(format!("{error:#}").contains(expected), "{error:#}");
            assert_eq!(
                fs::read_dir(&sweeps).expect("list").count(),
                0,
                "{expected}"
            );
        }
    }
}
