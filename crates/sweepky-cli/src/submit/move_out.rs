//! Step 9 of `submit` (see the parent module): once the sweep's record is
//! final, `done` or `aborted` by a refused upload, the sweep directory's
//! plaintext `audit/` moves out of the `init` project to
//! `<data dir>/submitted/<id>/audit/`, which the sandbox keeps from every
//! agent session (`denyRead` on the data directory, and
//! `blockReadsOutsideWorkingDirectories` for a `SWEEPKY_HOME` outside it).
//! So a later session in the same project cannot read a finished sweep's
//! report. Never earlier: while the record says `running`, a retried
//! `submit` needs `audit/` where the walk looks for it.
//!
//! **The known limit.** A sweep that was run but never submitted, one whose
//! submit failed in a way that can be retried, and one abandoned, keep
//! their `audit/` in the project, and every later agent session there can
//! read it. The skill's "do not read other `sweeps/` directories" is an
//! instruction, not an enforcement (02, "Sweeper safety").
//!
//! **Through handles, as `run` places a sweep** (`run::place`): `audit` is
//! looked at in the sweep directory's open handle, the one the walk read,
//! without following a link; anything but a real directory there is left
//! where it is. Then one `renameat` with `RENAME_NOREPLACE`, relative to
//! that handle and the destination's, moves it: a rename never follows a
//! link at its last part, so an `audit` swapped for a link since the look
//! moves as the link itself, and anything already at the destination makes
//! the move fail rather than be replaced. Where the data directory is on
//! another filesystem (`EXDEV`), or the filesystem cannot promise not to
//! replace (`EINVAL`, `ENOTSUP`), `run::place::copy_sweep` copies it
//! through handles, and the project's copy is then removed without
//! following a link. Last, every directory moved is made 0700 and every
//! file 0600, through its own handle.
//!
//! A failure is a warning, never the command's error: the record is final
//! by then. Every message is fixed text and paths, sanitised.

use std::ffi::CStr;
use std::os::fd::{AsFd, BorrowedFd};
use std::path::PathBuf;

use anyhow::{Context as _, bail};
use rustix::fs::{FileType, Mode, RenameFlags};
use rustix::io::Errno;
use sweepky_core::RecordId;

use super::sweep_dir::SweepDir;
use super::walk::{FILE_FLAGS, MAX_ENTRIES, entry_at, kind, list_entries, open_dir_at, same_entry};
use crate::Dirs;
use crate::display::sanitize;
use crate::private_fs::{ensure_private_dir, lstat};
use crate::run::place::{
    MAX_COPY_DEPTH, MAX_NAME_CHARS, copy_sweep, open_dir_path, remove_tree_at,
};

/// The agent's output directory, directly in a sweep directory, and its
/// name under `submitted/<id>/`.
const AUDIT: &CStr = c"audit";

/// Refuses sweep `id` when its `audit/` was moved out already: its record
/// is final, so there is nothing to submit. Checked before the walk, which
/// would otherwise only say `audit/` is missing. The data directory is the
/// user's own, so a path-based look is enough here.
pub(super) fn refuse_moved_out(dirs: &Dirs, id: &RecordId) -> anyhow::Result<()> {
    let moved = dirs.submitted_dir(id).join("audit");
    if lstat(&moved)?.is_some() {
        bail!(
            "this sweep is finished already (its record says done or aborted), and submit moved \
             its audit/ to {}; a finished sweep is never submitted again: start a new sweep with \
             `sweepky run`",
            moved.display()
        );
    }
    Ok(())
}

/// Moves `sweep`'s `audit/` to `<data dir>/submitted/<id>/audit/` (see the
/// module docs) and gives where it now is. Call it only once the sweep's
/// record is final.
pub(super) fn move_audit_out(sweep: &SweepDir, dirs: &Dirs) -> anyhow::Result<PathBuf> {
    let shown = format!("{}/audit", sweep.path().display());
    let parent = dirs.submitted_dir(&sweep.sweep().id);
    let moved = parent.join("audit");
    let moved_shown = moved.display().to_string();
    refuse_unless_real_dir(sweep.fd(), &shown)?;
    // The data directory is the user's own, which no agent can write, so
    // its parts are made by path; the handle opened on the last is what
    // the move goes through.
    let dest = ensure_private_dir(&parent)
        .and_then(|()| open_dir_path(&parent))
        .with_context(|| not_moved(&shown, "its place in the data directory could not be made"))?;
    match rustix::fs::renameat_with(sweep.fd(), AUDIT, &dest, AUDIT, RenameFlags::NOREPLACE) {
        Ok(()) => {}
        Err(Errno::EXIST | Errno::NOTEMPTY) => bail!(not_moved(
            &shown,
            &format!("{moved_shown} is already there, and submit never replaces it")
        )),
        Err(Errno::XDEV | Errno::INVAL | Errno::NOTSUP) => {
            copy_out(sweep.fd(), dest.as_fd(), &shown, &moved_shown)?;
        }
        // `Errno`'s text is the system's fixed description of the error.
        Err(err) => bail!(not_moved(&shown, &format!("the move failed: {err}"))),
    }
    make_private(dest.as_fd(), AUDIT, &moved_shown, 0).with_context(|| {
        format!(
            "{shown} was moved to {moved_shown}, but not everything in it could be made private; \
             the data directory still keeps it from other users and from the agent"
        )
    })?;
    Ok(moved)
}

/// Refuses, leaving it where it is, anything at `audit` in the sweep
/// directory `sweep` (shown as `shown`) but a real directory, looked at
/// without following a link.
fn refuse_unless_real_dir(sweep: BorrowedFd<'_>, shown: &str) -> anyhow::Result<()> {
    let seen = entry_at(sweep, AUDIT, shown)
        .with_context(|| not_moved(shown, "it could not be looked at"))?;
    // `map` turns the `Option<Stat>` into an `Option<FileType>`, so one
    // `match` covers nothing being there too.
    match seen.as_ref().map(kind) {
        Some(FileType::Directory) => Ok(()),
        Some(FileType::Symlink) => bail!(not_moved(
            shown,
            "it is a symbolic link now, and submit never follows one"
        )),
        _ => bail!(not_moved(shown, "it is no longer a directory")),
    }
}

/// What a refusal to move `shown`, the project's `audit/`, says, with
/// `why`.
fn not_moved(shown: &str, why: &str) -> String {
    format!(
        "{shown} was not moved out of the project ({why}), so later agent sessions in the project \
         can still read it; move it out of the project yourself"
    )
}

/// The move's fallback: `audit` in `sweep` copied to `audit` in `dest`
/// through handles, then removed from the project without following a
/// link. A copy that fails removes its own part copy (`copy_sweep`), so the
/// project's `audit/` is then the only one, left where it was.
fn copy_out(
    sweep: BorrowedFd<'_>,
    dest: BorrowedFd<'_>,
    shown: &str,
    moved_shown: &str,
) -> anyhow::Result<()> {
    // `copy_sweep`'s own error speaks of `run` placing a sweep, so it is
    // dropped (`is_err`) for fixed text of this step's own.
    if copy_sweep(sweep, AUDIT, dest, moved_shown).is_err() {
        bail!(not_moved(
            shown,
            &format!(
                "the data directory is on another filesystem, and the copy to {moved_shown} \
                 failed: it takes regular files and directories only"
            )
        ));
    }
    remove_tree_at(sweep, AUDIT, 0);
    if entry_at(sweep, AUDIT, shown)?.is_some() {
        bail!(
            "{shown} was copied to {moved_shown}, but not all of it could be removed from the \
             project, so later agent sessions there can read what is left; remove it yourself"
        );
    }
    Ok(())
}

/// Makes `name` in `dir`, shown as `shown`, private, and everything in it
/// when it is a directory: a directory 0700 and a regular file 0600, each
/// through its own handle, `depth` directories below `audit/`.
///
/// Anything else is left as it is: a link is never followed, and a file
/// with other hard links keeps its mode, since that mode is shared with a
/// file outside `audit/` (the walk never reads such a file, but the
/// agents' `scratch/` it skips may hold one).
fn make_private(dir: BorrowedFd<'_>, name: &CStr, shown: &str, depth: usize) -> anyhow::Result<()> {
    let Some(seen) = entry_at(dir, name, shown)? else {
        bail!("{shown} is gone");
    };
    match kind(&seen) {
        FileType::Directory => {
            if depth > MAX_COPY_DEPTH {
                bail!("{shown} is more than {MAX_COPY_DEPTH} directories deep");
            }
            let opened = open_dir_at(dir, name, &seen, shown)?;
            rustix::fs::fchmod(&opened, Mode::RWXU)
                .with_context(|| format!("could not make {shown} private"))?;
            let Some(names) = list_entries(opened.as_fd(), shown, MAX_ENTRIES)? else {
                bail!("{shown} holds more than {MAX_ENTRIES} entries");
            };
            for child in names {
                let child_shown = format!(
                    "{shown}/{}",
                    sanitize(&child.to_string_lossy(), MAX_NAME_CHARS)
                );
                make_private(opened.as_fd(), &child, &child_shown, depth + 1)?;
            }
        }
        FileType::RegularFile if seen.st_nlink == 1 => {
            let opened = rustix::fs::openat(dir, name, FILE_FLAGS, Mode::empty())
                .with_context(|| format!("could not open {shown}"))?;
            let now =
                rustix::fs::fstat(&opened).with_context(|| format!("could not inspect {shown}"))?;
            if !same_entry(&seen, &now) || now.st_nlink != 1 {
                bail!("{shown} changed while submit was moving it");
            }
            rustix::fs::fchmod(&opened, Mode::RUSR | Mode::WUSR)
                .with_context(|| format!("could not make {shown} private"))?;
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::fd::{AsFd, OwnedFd};
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;
    use std::path::Path;

    use super::{copy_out, move_audit_out, refuse_moved_out};
    use crate::Dirs;
    use crate::private_fs::ensure_private_dir;
    use crate::run::place::open_dir_path;
    use crate::submit::fixture::SweepFixture;
    use crate::test_support::{PLANTED, chmod, dirs_in, mode, private_temp};

    fn open(path: &Path) -> OwnedFd {
        open_dir_path(path).expect("opens")
    }

    /// `audit/` as the agent leaves it, with loose modes: a report, a
    /// nested directory, and in an agent's `scratch/` a hard link and a
    /// symbolic link to a file outside, which the walk never reads.
    fn agent_output(fixture: &SweepFixture, outside: &Path) {
        let audit = fixture.audit();
        fs::write(audit.join("REPORT.md"), "# Report\n").expect("write");
        chmod(&audit.join("REPORT.md"), 0o644);
        fs::create_dir_all(audit.join("agents/a/scratch")).expect("mkdir");
        chmod(&audit.join("agents"), 0o755);
        fs::hard_link(outside, audit.join("agents/a/scratch/hard")).expect("hard link");
        symlink(outside, audit.join("agents/a/scratch/soft")).expect("symlink");
    }

    /// A file outside the project, 0644.
    fn outside_file(dir: &Path) -> std::path::PathBuf {
        let outside = dir.join("outside.txt");
        fs::write(&outside, PLANTED).expect("write");
        chmod(&outside, 0o644);
        outside
    }

    #[test]
    fn audit_moves_whole_to_the_data_directory_and_is_made_private() {
        let fixture = SweepFixture::new();
        let home = private_temp();
        let dirs = dirs_in(&home);
        let outside = outside_file(fixture.temp());
        agent_output(&fixture, &outside);

        let moved = move_audit_out(&fixture.open(), &dirs).expect("moved");

        assert_eq!(moved, dirs.submitted_dir(&fixture.id()).join("audit"));
        assert!(fs::symlink_metadata(fixture.audit()).is_err());
        assert_eq!(mode(&moved), 0o700);
        assert_eq!(mode(&moved.join("agents")), 0o700);
        assert_eq!(mode(&moved.join("REPORT.md")), 0o600);
        assert_eq!(mode(&moved.join("findings.json")), 0o600);
        // The links moved as links; neither was followed, and the file
        // they reach keeps its mode and its bytes.
        let soft = moved.join("agents/a/scratch/soft");
        assert!(fs::symlink_metadata(&soft).expect("there").is_symlink());
        assert_eq!(mode(&outside), 0o644);
        assert_eq!(fs::read_to_string(&outside).expect("read"), PLANTED);

        // Moved out, so a later submit of it is refused before the walk.
        let error = refuse_moved_out(&dirs, &fixture.id()).expect_err("finished");
        assert!(
            format!("{error:#}").contains("finished already"),
            "{error:#}"
        );
    }

    #[test]
    fn an_audit_swapped_for_a_link_is_never_followed() {
        let fixture = SweepFixture::new();
        let dirs = dirs_in(&private_temp());
        let elsewhere = private_temp();
        fs::write(elsewhere.path().join("REPORT.md"), PLANTED).expect("write");
        let sweep = fixture.open();
        // After the walk, `audit` becomes a link to another directory.
        fs::remove_dir_all(fixture.audit()).expect("rm");
        symlink(elsewhere.path(), fixture.audit()).expect("symlink");

        let error = move_audit_out(&sweep, &dirs).expect_err("refused");

        let message = format!("{error:#}");
        assert!(message.contains("symbolic link"), "{message}");
        assert!(message.contains("later agent sessions"), "{message}");
        assert!(!message.contains(PLANTED), "{message}");
        assert!(
            fs::symlink_metadata(fixture.audit())
                .expect("there")
                .is_symlink()
        );
        assert!(fs::symlink_metadata(dirs.submitted_dir(&fixture.id()).join("audit")).is_err());
        assert_eq!(
            fs::read_to_string(elsewhere.path().join("REPORT.md")).expect("read"),
            PLANTED
        );
        assert_eq!(mode(&elsewhere.path().join("REPORT.md")), 0o644);
    }

    #[test]
    fn a_destination_already_there_is_never_replaced() {
        let fixture = SweepFixture::new();
        let dirs = dirs_in(&private_temp());
        let dest = dirs.submitted_dir(&fixture.id()).join("audit");
        ensure_private_dir(&dest).expect("mkdir");
        fs::write(dest.join("kept"), PLANTED).expect("write");

        let error = move_audit_out(&fixture.open(), &dirs).expect_err("refused");

        assert!(
            format!("{error:#}").contains("is already there"),
            "{error:#}"
        );
        assert!(fixture.audit().join("findings.json").is_file());
        assert_eq!(
            fs::read_to_string(dest.join("kept")).expect("read"),
            PLANTED
        );
        assert!(fs::symlink_metadata(dest.join("findings.json")).is_err());
    }

    /// The cross-filesystem fallback, called as the move calls it on
    /// `EXDEV`, which one temp directory cannot produce.
    fn copy_to(fixture: &SweepFixture, dirs: &Dirs) -> anyhow::Result<()> {
        let parent = dirs.submitted_dir(&fixture.id());
        ensure_private_dir(&parent).expect("mkdir");
        let sweep = fixture.open();
        copy_out(
            sweep.fd(),
            open(&parent).as_fd(),
            &fixture.audit().display().to_string(),
            &parent.join("audit").display().to_string(),
        )
    }

    #[test]
    fn the_copy_fallback_removes_the_project_copy_without_following_links() {
        let fixture = SweepFixture::new();
        let dirs = dirs_in(&private_temp());
        fs::create_dir(fixture.audit().join("notes")).expect("mkdir");
        fs::write(fixture.audit().join("notes/a.md"), "a\n").expect("write");

        copy_to(&fixture, &dirs).expect("copied");

        let copied = dirs.submitted_dir(&fixture.id()).join("audit");
        assert!(fs::symlink_metadata(fixture.audit()).is_err());
        assert_eq!(
            fs::read_to_string(copied.join("notes/a.md")).expect("read"),
            "a\n"
        );
        assert!(copied.join("findings.json").is_file());
    }

    #[test]
    fn a_copy_that_fails_part_way_leaves_the_project_copy_and_says_so() {
        let fixture = SweepFixture::new();
        let dirs = dirs_in(&private_temp());
        let outside = outside_file(fixture.temp());
        agent_output(&fixture, &outside);
        // A socket, which the copy refuses, after it has copied the entries
        // before it in name order. Directly in audit/, since a socket's
        // path has a short length limit.
        let _socket = UnixListener::bind(fixture.audit().join("sock")).expect("bind");

        let error = copy_to(&fixture, &dirs).expect_err("refused");

        let message = format!("{error:#}");
        assert!(
            message.contains("was not moved out of the project"),
            "{message}"
        );
        assert!(
            message.contains("regular files and directories only"),
            "{message}"
        );
        assert!(!message.contains("run copies"), "{message}");
        // The project's copy is whole, and nothing is left in the data
        // directory.
        assert!(fixture.audit().join("REPORT.md").is_file());
        assert!(fixture.audit().join("findings.json").is_file());
        assert!(fs::symlink_metadata(dirs.submitted_dir(&fixture.id()).join("audit")).is_err());
        assert_eq!(mode(&outside), 0o644);
    }
}
