//! Which sweep directory `submit` completes, and the checks that make a
//! directory one (02, "`submit` trusts nothing in the sweep directory").
//!
//! **Where it may be.** A sweep directory is `<init dir>/sweeps/<id>/`, a
//! direct child of an `init` project's `sweeps/`, as `run` made it:
//!
//! - With `--run-dir <dir>`, the path must end in `sweeps/<id>`, as `run`'s
//!   report spells it (`sweeps/<id>` from the project, or an absolute
//!   path). Relative to the working directory, it is split into the
//!   project, `sweeps` and the id.
//! - Without it, the working directory must be the project, and the one
//!   sweep directory there waiting to be submitted is picked (below).
//!
//! Then the project's path is canonicalised (`fs::canonicalize`, which
//! resolves `..` and any link in the project's own path, which the human
//! gives and the agent cannot write) and must carry the project marker
//! `init` writes, read with `init`'s own reader. Below the project, where
//! the agent can write, nothing is resolved: `sweeps` and `<id>` are each
//! looked at without following a link and opened relative to the directory
//! above them (see the `walk` module), so a `sweeps` or a sweep directory
//! that is a link is refused rather than followed, and the directory
//! checked is the one the walk reads. The sweep directory's path is the
//! canonical project's with those two real names after it.
//!
//! **The marker is a pointer.** The sweep directory must hold
//! `.sweepky/sweep.json`, the per-sweep marker `run` writes last, read
//! through the open handle, at most 64 KiB, and parsed strictly: exactly the
//! fields `run` writes, each of its type. All `submit` takes from it is the
//! sweep record's URL, which must name this login's pubky and
//! `sweeps/<id>.json` for this directory's own id. The agent can rewrite the
//! marker, so nothing else in it, nor `scope.json` or the submitted stamp,
//! is trusted for anything: the bounty and the targets come from the sweep
//! record itself, which only this login can write.
//!
//! **Picking without `--run-dir`.** The candidates are the entries of
//! `sweeps/` named as a record id that are real directories holding a
//! marker but no `.sweepky/submitted` stamp, which `submit` writes once a
//! sweep is done. Exactly one is picked; none, or several, is an error that
//! lists the ids. The stamp is agent-writable too, so it only narrows the
//! pick: a stamp the agent deleted lets an old sweep be picked again, and
//! the command's check of the sweep record, which then reads `done`,
//! refuses it. [`SweepDir::stamp_submitted`] writes it, through the
//! directory's open handle, never through a link.

use std::ffi::{CStr, CString, OsStr};
use std::fs;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context as _, anyhow, bail};
use rustix::fs::{FileType, Mode, OFlags};
use rustix::io::Errno;
use serde::Deserialize;
use sweepky_core::{
    BountyRef, Playbook, Pubky, RecordError, RecordId, SchemaVersion, SweepRef, TargetId,
};

use super::walk::{
    DIR_FLAGS, MAX_ENTRIES, entry_at, file_len, kind, list_entries, open_dir_at, read_file_at,
    refuse_unless_plain_file,
};
use crate::init::read_project_marker;

/// The project's directory of sweeps, directly in the project.
const SWEEPS: &str = "sweeps";

/// The per-sweep marker's directory, directly in a sweep directory.
const MARKER_DIR: &CStr = c".sweepky";

/// The per-sweep marker, in [`MARKER_DIR`].
const MARKER_FILE: &CStr = c"sweep.json";

/// The stamp `submit` leaves in [`MARKER_DIR`] once a sweep is submitted,
/// so that picking without `--run-dir` passes it over.
const SUBMITTED_STAMP: &CStr = c"submitted";

/// How the stamp is made: a new file (`O_CREAT | O_EXCL`, which fails on
/// anything already at the name and never follows a link there), opened
/// write-only and left empty, never this process's terminal, and not handed
/// to any program this one starts.
const STAMP_FLAGS: OFlags = OFlags::WRONLY
    .union(OFlags::CREATE)
    .union(OFlags::EXCL)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NOCTTY)
    .union(OFlags::CLOEXEC);

/// The most bytes a per-sweep marker may have: 64 KiB, as for the project's
/// marker. The one `run` writes is a few hundred.
const MAX_MARKER_BYTES: usize = 64 * 1024;

/// What `submit` says of a `--run-dir` that does not end in `sweeps/<id>`.
/// It never quotes the argument.
const NOT_A_SWEEP_DIR: &str = "--run-dir must name a sweep directory directly inside an init \
                               project's sweeps/, as `sweepky run` printed it: sweeps/<id> from \
                               the project, or that path in full";

/// A sweep directory that passed every check above: where it is, the sweep
/// its marker points at, and the directory itself, held open.
#[derive(Debug)]
pub(crate) struct SweepDir {
    path: PathBuf,
    sweep: SweepRef,
    dir: OwnedFd,
}

impl SweepDir {
    /// `<init dir>/sweeps/<id>`, the project's canonical path and the two
    /// real directory names below it.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// The sweep record this directory belongs to: this login's, with the
    /// directory's id. The marker pointed at it; what the record says is
    /// still to be read.
    // `SweepRef` is `Copy`, 40 bytes of public data, so this hands out a
    // copy rather than a borrow.
    pub(crate) fn sweep(&self) -> SweepRef {
        self.sweep
    }

    /// The sweep directory's open handle, lent out. The walk starts here,
    /// so it reads the very directory these checks passed, whatever has
    /// happened to its path since.
    pub(super) fn fd(&self) -> BorrowedFd<'_> {
        self.dir.as_fd()
    }

    /// Stamps this sweep directory as submitted: an empty
    /// `.sweepky/submitted`, made 0600 through the directory's open handle,
    /// so picking without `--run-dir` passes it over.
    ///
    /// Anything already at that name, a link included, counts as the stamp
    /// and is left alone: `O_EXCL` fails on it rather than follow or
    /// overwrite it, and the stamp only narrows a pick (module docs).
    pub(super) fn stamp_submitted(&self) -> anyhow::Result<()> {
        let shown = format!("{}/.sweepky", self.path.display());
        let Some(marker_dir) = real_dir(self.dir.as_fd(), MARKER_DIR, &shown)? else {
            bail!("{shown} is gone");
        };
        match rustix::fs::openat(
            marker_dir.as_fd(),
            SUBMITTED_STAMP,
            STAMP_FLAGS,
            Mode::RUSR | Mode::WUSR,
        ) {
            // `_` binds nothing, so the new file's handle is dropped, and
            // closed, with the match: the stamp is its name, and it holds
            // nothing.
            Ok(_) | Err(Errno::EXIST) => Ok(()),
            Err(err) => Err(err).with_context(|| format!("could not write {shown}/submitted")),
        }
    }
}

/// Finds the sweep directory `submit` completes for `sweeper`, this
/// login's pubky: the one `run_dir` names, relative to `cwd`, or without
/// it the one waiting in the project at `cwd`. See the module docs for the
/// checks.
pub(super) fn find_sweep_dir(
    cwd: &Path,
    run_dir: Option<&Path>,
    sweeper: &Pubky,
) -> anyhow::Result<SweepDir> {
    let (project, id) = match run_dir {
        Some(run_dir) => {
            // `join` keeps `run_dir` as it is when it is absolute.
            let given = cwd.join(run_dir);
            let (project, name) = split_run_dir(&given)?;
            let id = parse_sweep_id(name)?;
            let project = Project::open(&project)
                .context("--run-dir must be a sweep directory in the sweeps/ of an init project")?;
            (project, id)
        }
        None => {
            let project = Project::open(cwd).context(
                "without --run-dir, submit must be run in the init project's own directory, \
                 where `sweepky run` was run",
            )?;
            let id = project.pick_unsubmitted()?;
            (project, id)
        }
    };
    project.open_sweep(id, sweeper)
}

/// `given` split into the project directory and the sweep directory's
/// name, which must be the path's last two parts after `sweeps`. Only a
/// path written that way is taken: `.` parts and a trailing `/` drop out,
/// but `..` or anything else at the end is refused.
///
/// The name borrows from `given` (one input reference, so the output's
/// lifetime is tied to it without being written out).
fn split_run_dir(given: &Path) -> anyhow::Result<(PathBuf, &OsStr)> {
    let mut parts = given.components();
    // `next_back` takes parts from the end; what is left is the project.
    let (Some(Component::Normal(name)), Some(Component::Normal(sweeps))) =
        (parts.next_back(), parts.next_back())
    else {
        bail!(NOT_A_SWEEP_DIR);
    };
    if sweeps != SWEEPS {
        bail!(NOT_A_SWEEP_DIR);
    }
    Ok((parts.as_path().to_path_buf(), name))
}

/// The sweep id a sweep directory's `name` must be, `run`'s record id.
fn parse_sweep_id(name: &OsStr) -> anyhow::Result<RecordId> {
    name.to_str()
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| {
            anyhow!(
                "--run-dir must end in a sweep's id, sweeps/<id>, the 13 characters `sweepky run` \
                 printed; {NOT_A_SWEEP_DIR}"
            )
        })
}

/// An `init` project, checked, with its `sweeps/` open.
struct Project {
    /// The project's canonical path.
    path: PathBuf,
    /// `<project>/sweeps`, a real directory, opened without following a
    /// link.
    sweeps: OwnedFd,
}

/// Whether a directory in `sweeps/` is a sweep waiting to be submitted.
#[derive(Debug, PartialEq, Eq)]
enum Candidate {
    /// Not a real directory, or one with no marker.
    Unmarked,
    /// A marker, and no submitted stamp.
    Waiting,
    /// A marker and a submitted stamp.
    Submitted,
}

impl Project {
    /// The project at `dir`: canonicalised, holding `init`'s marker, and
    /// with a real `sweeps/` directory, which is opened.
    fn open(dir: &Path) -> anyhow::Result<Self> {
        let path =
            fs::canonicalize(dir).with_context(|| format!("could not find {}", dir.display()))?;
        read_project_marker(&path)?;
        // The canonical path holds no link, and `O_NOFOLLOW` refuses one
        // swapped in at its last part since; the parts above it are not the
        // agent's to change.
        let project = rustix::fs::open(path.as_path(), DIR_FLAGS, Mode::empty())
            .with_context(|| format!("could not open {}", path.display()))?;
        let shown = format!("{}/{SWEEPS}", path.display());
        // `c"sweeps"` is `SWEEPS` as the C string the system call takes.
        let Some(sweeps) = real_dir(project.as_fd(), c"sweeps", &shown)? else {
            bail!("{shown} is missing, so there is no sweep to submit; `sweepky run` makes it");
        };
        Ok(Self { path, sweeps })
    }

    /// `<project>/sweeps/<id>` as text, for a message: the canonical path
    /// and two names, a record id the last.
    fn shown(&self, id: RecordId) -> String {
        format!("{}/{SWEEPS}/{id}", self.path.display())
    }

    /// The one sweep in `sweeps/` waiting to be submitted (see the module
    /// docs).
    fn pick_unsubmitted(&self) -> anyhow::Result<RecordId> {
        let sweeps = format!("{}/{SWEEPS}", self.path.display());
        let Some(names) = list_entries(self.sweeps.as_fd(), &sweeps, MAX_ENTRIES)? else {
            bail!(
                "{sweeps} holds more than {MAX_ENTRIES} entries, more than submit looks through; \
                 give --run-dir sweeps/<id>"
            );
        };
        // The names are sorted, so the ids are in the order they were made.
        let mut waiting = Vec::new();
        let mut submitted = Vec::new();
        for name in names {
            // A name that is not a record id is no sweep `run` made; it is
            // passed over without a look.
            let Some(id) = name
                .to_str()
                .ok()
                .and_then(|text| text.parse::<RecordId>().ok())
            else {
                continue;
            };
            match self.candidate(&name, &self.shown(id))? {
                Candidate::Unmarked => {}
                Candidate::Waiting => waiting.push(id),
                Candidate::Submitted => submitted.push(id),
            }
        }
        choose_waiting(&sweeps, &waiting, &submitted)
    }

    /// Whether the entry `name` of `sweeps/`, shown as `shown`, is a sweep
    /// waiting to be submitted. Looks only: a link is never followed, and
    /// nothing is read.
    fn candidate(&self, name: &CStr, shown: &str) -> anyhow::Result<Candidate> {
        let At::Dir(sweep) = look_at(self.sweeps.as_fd(), name, shown)? else {
            return Ok(Candidate::Unmarked);
        };
        let marker_shown = format!("{shown}/.sweepky");
        let At::Dir(marker_dir) = look_at(sweep.as_fd(), MARKER_DIR, &marker_shown)? else {
            return Ok(Candidate::Unmarked);
        };
        let marker = entry_at(marker_dir.as_fd(), MARKER_FILE, &marker_shown)?;
        if !marker.is_some_and(|seen| kind(&seen) == FileType::RegularFile) {
            return Ok(Candidate::Unmarked);
        }
        Ok(
            match entry_at(marker_dir.as_fd(), SUBMITTED_STAMP, &marker_shown)? {
                Some(_) => Candidate::Submitted,
                None => Candidate::Waiting,
            },
        )
    }

    /// The sweep directory `sweeps/<id>`, checked for `sweeper`: a real
    /// directory whose marker points at `sweeper`'s sweep `id`.
    fn open_sweep(self, id: RecordId, sweeper: &Pubky) -> anyhow::Result<SweepDir> {
        let shown = self.shown(id);
        // A record id is 13 ASCII characters, so it holds no NUL and
        // `CString::new` cannot fail; it returns a `Result` all the same.
        let name = CString::new(id.to_string()).context("a sweep id is plain ASCII")?;
        let Some(dir) = real_dir(self.sweeps.as_fd(), &name, &shown)? else {
            bail!("{shown} is missing");
        };
        let sweep = read_marker(&dir, &shown)?;
        // `Pubky` compares by its key bytes, so the spelling the marker used
        // does not matter. Neither refusal quotes the marker.
        if sweep.sweeper != *sweeper {
            bail!(
                "{shown}/.sweepky/sweep.json points at a sweep of another identity, not this \
                 login's; submit completes only this login's own sweeps"
            );
        }
        if sweep.id != id {
            bail!(
                "{shown}/.sweepky/sweep.json points at another sweep than sweeps/{id}.json; a \
                 sweep directory's marker names its own sweep"
            );
        }
        Ok(SweepDir {
            path: self.path.join(SWEEPS).join(id.to_string()),
            sweep,
            dir,
        })
    }
}

/// What is at a name in a directory, looked at without following a link.
enum At {
    /// Nothing.
    Missing,
    /// A real directory, opened.
    Dir(OwnedFd),
    /// Anything else, a link included: never opened.
    Other(FileType),
}

/// What is at `name` in `dir`, shown as `shown`, opening it when it is a
/// real directory.
fn look_at(dir: BorrowedFd<'_>, name: &CStr, shown: &str) -> anyhow::Result<At> {
    let Some(seen) = entry_at(dir, name, shown)? else {
        return Ok(At::Missing);
    };
    Ok(match kind(&seen) {
        FileType::Directory => At::Dir(open_dir_at(dir, name, &seen, shown)?),
        other => At::Other(other),
    })
}

/// The real directory `name` in `dir`, shown as `shown`, opened; `None`
/// when nothing is there, for the caller to say what that means. A link
/// there, or anything but a directory, is refused, never followed.
fn real_dir(dir: BorrowedFd<'_>, name: &CStr, shown: &str) -> anyhow::Result<Option<OwnedFd>> {
    match look_at(dir, name, shown)? {
        At::Dir(opened) => Ok(Some(opened)),
        At::Missing => Ok(None),
        At::Other(FileType::Symlink) => bail!(
            "{shown} is a symbolic link; submit reads a sweep only through real directories of \
             its init project, never through a link"
        ),
        At::Other(_) => bail!("{shown} is not a directory, so it holds no sweep"),
    }
}

/// The sweep directory `sweeps/` (shown as `sweeps`) picks: the one
/// `waiting` id. None waiting, or several, is an error that lists the ids,
/// the `submitted` ones when none waits.
fn choose_waiting(
    sweeps: &str,
    waiting: &[RecordId],
    submitted: &[RecordId],
) -> anyhow::Result<RecordId> {
    // A slice pattern: `[id]` matches a slice of exactly one, and binds it.
    match waiting {
        [id] => Ok(*id),
        [] if submitted.is_empty() => bail!(
            "no sweep in {sweeps} is waiting to be submitted: none there has the marker \
             `sweepky run` writes; run `sweepky run` first"
        ),
        [] => bail!(
            "no sweep in {sweeps} is waiting to be submitted: every one there is stamped as \
             submitted already ({}); give --run-dir sweeps/<id> to submit one again",
            list(submitted)
        ),
        several => bail!(
            "several sweeps in {sweeps} are waiting to be submitted ({}); give --run-dir \
             sweeps/<id> to say which",
            list(several)
        ),
    }
}

/// The sweep the marker of the sweep directory `dir` (shown as `shown`)
/// points at, read through `dir` (see the module docs).
fn read_marker(dir: &OwnedFd, shown: &str) -> anyhow::Result<SweepRef> {
    let no_marker = || {
        anyhow!(
            "{shown} has no .sweepky/sweep.json marker: `sweepky run` writes it last, once a \
             sweep directory is whole, so this is no sweep submit can complete"
        )
    };
    let Some(marker_dir) = real_dir(dir.as_fd(), MARKER_DIR, &format!("{shown}/.sweepky"))? else {
        return Err(no_marker());
    };
    let marker = format!("{shown}/.sweepky/sweep.json");
    let Some(seen) = entry_at(marker_dir.as_fd(), MARKER_FILE, &marker)? else {
        return Err(no_marker());
    };
    refuse_unless_plain_file(&seen, &marker)?;
    // `is_none_or` is true for `None` (a size that does not fit) and for a
    // size over the cap: either way the file is not read.
    if file_len(&seen).is_none_or(|len| len > MAX_MARKER_BYTES) {
        bail!("{marker} is longer than the {MAX_MARKER_BYTES} bytes a sweep marker may have");
    }
    let bytes = read_file_at(marker_dir.as_fd(), MARKER_FILE, &seen, &marker)?;
    parse_marker(&bytes).map_err(|fault| {
        anyhow!(
            "{marker} is not a sweep marker `sweepky run` wrote ({fault}); submit completes only \
             a sweep directory run made"
        )
    })
}

/// The marker's shape, exactly as `run` writes it (`run::marker`), parsed
/// strictly: `deny_unknown_fields` refuses a key `run` never writes, and
/// each field must be of its type. Only `sweep` is used; the rest is
/// parsed so that a marker `run` did not write is refused whole, and is
/// never trusted for anything.
// `_`-named fields are never read, which the leading underscore tells the
// compiler; `rename` gives each its key in the file.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MarkerFile {
    #[serde(rename = "schemaVersion")]
    _schema_version: SchemaVersion,
    sweep: SweepRef,
    #[serde(rename = "bounty")]
    _bounty: BountyRef,
    #[serde(rename = "targets")]
    _targets: Vec<TargetId>,
    // `run` leaves the key out when the project names no playbook.
    #[serde(rename = "playbook", default)]
    _playbook: Option<Playbook>,
}

/// The sweep a marker's `bytes` point at. The `Err` says what is wrong and
/// never quotes the bytes: a parse error goes through core's `RecordError`,
/// which keeps only the kind of fault and where it is, as every record
/// parse does. `SweepRef` refuses any URL but a sweep record's,
/// `pubky://<sweeper>/pub/sweepky/sweeps/<id>.json`.
fn parse_marker(bytes: &[u8]) -> Result<SweepRef, String> {
    serde_json::from_slice::<MarkerFile>(bytes)
        .map(|marker| marker.sweep)
        .map_err(|err| RecordError::from(err).to_string())
}

/// `ids`, comma-separated. Record ids are 13 characters of Crockford
/// base32, so they print as they are.
fn list(ids: &[RecordId]) -> String {
    ids.iter()
        .map(RecordId::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};

    use serde_json::json;
    use sweepky_core::SweepRef;

    use super::{SweepDir, find_sweep_dir, parse_marker};
    use crate::submit::fixture::SweepFixture;
    use crate::test_support::{PLANTED, bounty_id, json_bytes, mode, random_pubky, record_id};

    /// The sweep directory `run_dir` names from `cwd` for `fixture`'s
    /// sweeper, which must be accepted.
    fn found(fixture: &SweepFixture, cwd: &Path, run_dir: Option<&Path>) -> SweepDir {
        find_sweep_dir(cwd, run_dir, &fixture.sweeper())
            .unwrap_or_else(|err| panic!("refused: {err:#}"))
    }

    /// Why the same is refused, which it must be.
    fn refusal(fixture: &SweepFixture, cwd: &Path, run_dir: Option<&Path>) -> String {
        format!(
            "{:#}",
            find_sweep_dir(cwd, run_dir, &fixture.sweeper()).expect_err("refused")
        )
    }

    /// `path`, canonical.
    fn canonical(path: &Path) -> PathBuf {
        fs::canonicalize(path).expect("canonical")
    }

    #[test]
    fn a_run_dir_inside_sweeps_is_found_canonical_by_its_marker() {
        let fixture = SweepFixture::new();
        let expected = SweepRef {
            sweeper: fixture.sweeper(),
            id: fixture.id(),
        };

        // As `run` prints it, from the project; in full; and with a `.`
        // part and a trailing `/`, which drop out.
        let relative = PathBuf::from(format!("sweeps/{}", fixture.id()));
        let full = fixture.dir();
        let dotted = PathBuf::from(format!("./sweeps/./{}/", fixture.id()));
        for (cwd, run_dir) in [
            (fixture.project(), relative.as_path()),
            (fixture.temp(), full.as_path()),
            (fixture.project(), dotted.as_path()),
        ] {
            let sweep = found(&fixture, cwd, Some(run_dir));
            assert_eq!(sweep.sweep(), expected);
            assert_eq!(sweep.path(), canonical(&fixture.dir()));
        }

        // A project reached through a link above it, which the human
        // controls, is canonicalised to the real one.
        let link = fixture.temp().join("project-link");
        symlink(fixture.project(), &link).expect("symlink");
        let sweep = found(
            &fixture,
            fixture.temp(),
            Some(&link.join(format!("sweeps/{}", fixture.id()))),
        );
        assert_eq!(sweep.path(), canonical(&fixture.dir()));
    }

    #[test]
    fn a_run_dir_that_is_not_a_direct_child_of_sweeps_is_refused() {
        let fixture = SweepFixture::new();
        let id = fixture.id();
        let elsewhere = fixture.project().join("other").join(id.to_string());
        fs::create_dir_all(&elsewhere).expect("mkdir");
        for run_dir in [
            format!("sweeps/{id}/audit"),
            format!("sweeps/{id}/.."),
            format!("other/{id}"),
            "sweeps".to_owned(),
            ".".to_owned(),
        ] {
            let message = refusal(&fixture, fixture.project(), Some(Path::new(&run_dir)));
            assert!(
                message.contains("--run-dir must name a sweep directory"),
                "{run_dir}: {message}"
            );
        }

        // A name that is not a sweep id.
        let named = fixture.project().join("sweeps/not-an-id");
        fs::create_dir(&named).expect("mkdir");
        let message = refusal(&fixture, fixture.project(), Some(&named));
        assert!(message.contains("must end in a sweep's id"), "{message}");
    }

    #[test]
    fn a_project_with_no_valid_marker_is_refused() {
        let fixture = SweepFixture::new();
        let run_dir = PathBuf::from(format!("sweeps/{}", fixture.id()));
        let marker = fixture.project().join(".sweepky");

        // No marker, then a file that is not one, quoted nowhere.
        fs::remove_file(&marker).expect("rm");
        let message = refusal(&fixture, fixture.project(), Some(&run_dir));
        assert!(message.contains("is not a Sweepky project"), "{message}");
        fs::write(&marker, PLANTED).expect("write");
        let message = refusal(&fixture, fixture.project(), Some(&run_dir));
        assert!(
            message.contains("is not a Sweepky project marker"),
            "{message}"
        );
        assert!(!message.contains(PLANTED), "{message}");
    }

    #[test]
    fn a_sweeps_or_sweep_directory_reached_through_a_link_is_refused() {
        // `sweeps` a link to another project's real sweeps/, holding a whole
        // sweep directory of the same id and sweeper.
        let fixture = SweepFixture::new();
        let other = SweepFixture::in_temp_with(&fixture, "other");
        let run_dir = PathBuf::from(format!("sweeps/{}", fixture.id()));
        fs::remove_dir_all(fixture.project().join("sweeps")).expect("rm");
        symlink(
            other.project().join("sweeps"),
            fixture.project().join("sweeps"),
        )
        .expect("symlink");
        let message = refusal(&fixture, fixture.project(), Some(&run_dir));
        assert!(message.contains("sweeps is a symbolic link"), "{message}");
        let message = refusal(&fixture, fixture.project(), None);
        assert!(message.contains("sweeps is a symbolic link"), "{message}");

        // The sweep directory itself a link to that one.
        let fixture = SweepFixture::new();
        let other = SweepFixture::in_temp_with(&fixture, "other");
        fs::remove_dir_all(fixture.dir()).expect("rm");
        symlink(other.dir(), fixture.dir()).expect("symlink");
        let message = refusal(&fixture, fixture.project(), Some(&run_dir));
        assert!(
            message.contains(&format!("{} is a symbolic link", fixture.id())),
            "{message}"
        );
    }

    #[test]
    fn a_sweep_directory_without_its_marker_is_refused() {
        let fixture = SweepFixture::new();
        let run_dir = PathBuf::from(format!("sweeps/{}", fixture.id()));
        let marker_dir = fixture.dir().join(".sweepky");

        fs::remove_file(marker_dir.join("sweep.json")).expect("rm");
        let message = refusal(&fixture, fixture.project(), Some(&run_dir));
        assert!(
            message.contains("has no .sweepky/sweep.json marker"),
            "{message}"
        );

        fs::remove_dir(&marker_dir).expect("rmdir");
        let message = refusal(&fixture, fixture.project(), Some(&run_dir));
        assert!(
            message.contains("has no .sweepky/sweep.json marker"),
            "{message}"
        );

        // A marker that is a link, or whose directory is one, to a real
        // marker elsewhere.
        let other = SweepFixture::in_temp_with(&fixture, "other");
        symlink(other.dir().join(".sweepky"), &marker_dir).expect("symlink");
        let message = refusal(&fixture, fixture.project(), Some(&run_dir));
        assert!(message.contains(".sweepky is a symbolic link"), "{message}");
        fs::remove_file(&marker_dir).expect("rm");
        fs::create_dir(&marker_dir).expect("mkdir");
        symlink(
            other.dir().join(".sweepky/sweep.json"),
            marker_dir.join("sweep.json"),
        )
        .expect("symlink");
        let message = refusal(&fixture, fixture.project(), Some(&run_dir));
        assert!(
            message.contains("sweep.json is a symbolic link"),
            "{message}"
        );
    }

    #[test]
    fn the_marker_must_point_at_this_login_s_own_sweep_of_this_directory() {
        let fixture = SweepFixture::new();
        let run_dir = PathBuf::from(format!("sweeps/{}", fixture.id()));
        let refused_with = |marker: Vec<u8>| {
            fixture.write_marker(&fixture.dir(), &marker);
            refusal(&fixture, fixture.project(), Some(&run_dir))
        };

        // Another identity's sweep, and this login's sweep of another id.
        let message = refused_with(fixture.marker_bytes(random_pubky(), fixture.id()));
        assert!(message.contains("a sweep of another identity"), "{message}");
        let message = refused_with(fixture.marker_bytes(fixture.sweeper(), record_id(7)));
        assert!(message.contains("points at another sweep"), "{message}");

        // Not a sweep record's URL: a bounty's, and the package's.
        let sweep = SweepRef {
            sweeper: fixture.sweeper(),
            id: fixture.id(),
        };
        let bounty = format!(
            "pubky://{}/pub/sweepky/bounties/{}.json",
            fixture.sweeper(),
            fixture.id()
        );
        let package = sweep.package_url().to_string();
        for url in [bounty, package] {
            let message = refused_with(json_bytes(&json!({
                "schemaVersion": 1,
                "sweep": url,
                "bounty": url,
                "targets": ["t1"],
            })));
            assert!(message.contains("is not a sweep marker"), "{message}");
        }

        // Too long, a link count of two, and every fault of shape, none
        // quoted: the planted word sits where serde_json would quote it.
        let message = refused_with(vec![b' '; 64 * 1024 + 1]);
        assert!(message.contains("longer than the 65536 bytes"), "{message}");
        fixture.write_marker(
            &fixture.dir(),
            &fixture.marker_bytes(fixture.sweeper(), fixture.id()),
        );
        let marker = fixture.dir().join(".sweepky/sweep.json");
        fs::hard_link(&marker, fixture.temp().join("second")).expect("hard link");
        let message = refusal(&fixture, fixture.project(), Some(&run_dir));
        assert!(message.contains("has 2 hard links"), "{message}");
        fs::remove_file(fixture.temp().join("second")).expect("rm");
        found(&fixture, fixture.project(), Some(&run_dir));
    }

    #[test]
    fn the_marker_is_parsed_strictly_and_never_quoted() {
        let sweep = SweepRef {
            sweeper: random_pubky(),
            id: bounty_id(),
        };
        let whole = json!({
            "schemaVersion": 1,
            "sweep": sweep.to_string(),
            "bounty": format!("pubky://{}/pub/sweepky/bounties/{}.json", random_pubky(), bounty_id()),
            "targets": ["t1", "t2"],
            "playbook": "cloudflare/security-audit@c1c8a8c",
        });
        assert_eq!(parse_marker(&json_bytes(&whole)), Ok(sweep));
        let mut no_playbook = whole.clone();
        no_playbook
            .as_object_mut()
            .expect("object")
            .remove("playbook");
        assert_eq!(parse_marker(&json_bytes(&no_playbook)), Ok(sweep));

        let mut unknown = whole.clone();
        unknown[PLANTED] = json!(1);
        let mut newer = whole.clone();
        newer["schemaVersion"] = json!(2);
        let mut bad_target = whole.clone();
        bad_target["targets"] = json!([PLANTED.repeat(10)]);
        let mut bad_playbook = whole.clone();
        bad_playbook["playbook"] = json!(format!("{PLANTED} ../x"));
        let mut no_bounty = whole.clone();
        no_bounty.as_object_mut().expect("object").remove("bounty");
        let cases: [(&str, Vec<u8>); 7] = [
            ("unknown field", json_bytes(&unknown)),
            ("newer version", json_bytes(&newer)),
            ("bad target id", json_bytes(&bad_target)),
            ("bad playbook", json_bytes(&bad_playbook)),
            ("no bounty", json_bytes(&no_bounty)),
            ("not JSON", PLANTED.as_bytes().to_vec()),
            ("not an object", json_bytes(&json!([PLANTED]))),
        ];
        for (case, bytes) in cases {
            let fault = parse_marker(&bytes).expect_err(case);
            assert!(!fault.contains(PLANTED), "{case}: {fault}");
        }
    }

    #[test]
    fn without_run_dir_the_one_unsubmitted_sweep_is_picked() {
        let fixture = SweepFixture::new();
        let first = fixture.id();
        // Made later than the fixture's own sweep, so it lists second.
        let second = record_id(1 << 62);
        assert!(first < second);
        let second_dir = fixture.add_sweep(second);
        // Not candidates: an unmarked directory, a name that is not an id,
        // and a link to a whole sweep directory, which is never followed.
        fs::create_dir(fixture.project().join(format!("sweeps/{}", record_id(5)))).expect("mkdir");
        fs::create_dir(fixture.project().join("sweeps/notes")).expect("mkdir");
        let other = SweepFixture::in_temp_with(&fixture, "other");
        symlink(
            other.dir(),
            fixture.project().join(format!("sweeps/{}", record_id(6))),
        )
        .expect("symlink");

        // Two waiting: refused, naming both in the order they were made.
        let message = refusal(&fixture, fixture.project(), None);
        assert!(
            message.contains("several sweeps in")
                && message.contains(&format!("({first}, {second})")),
            "{message}"
        );

        // The first stamped as submitted: the second is picked.
        fixture.stamp(&fixture.dir());
        let picked = found(&fixture, fixture.project(), None);
        assert_eq!(picked.sweep().id, second);
        assert_eq!(picked.path(), canonical(&second_dir));

        // Both stamped: none is waiting, and the error lists them.
        fixture.stamp(&second_dir);
        let message = refusal(&fixture, fixture.project(), None);
        assert!(message.contains("no sweep in"), "{message}");
        assert!(
            message.contains(&format!("({first}, {second})")),
            "{message}"
        );

        // With --run-dir, a stamped sweep is still found: the stamp only
        // narrows the pick, and the sweep record decides.
        let run_dir = PathBuf::from(format!("sweeps/{first}"));
        found(&fixture, fixture.project(), Some(&run_dir));

        // A working directory that is no project is refused, saying why.
        let message = refusal(&fixture, &fixture.dir(), None);
        assert!(
            message.contains("without --run-dir, submit must be run in the init project"),
            "{message}"
        );
    }

    #[test]
    fn without_run_dir_a_project_with_no_marked_sweep_is_refused() {
        let fixture = SweepFixture::new();
        fs::remove_file(fixture.dir().join(".sweepky/sweep.json")).expect("rm");
        let message = refusal(&fixture, fixture.project(), None);
        assert!(message.contains("none there has the marker"), "{message}");
    }

    #[test]
    fn the_stamp_is_an_empty_private_file_and_never_written_through_a_link() {
        let fixture = SweepFixture::new();
        let sweep = fixture.open();

        sweep.stamp_submitted().expect("stamped");

        let stamp = fixture.dir().join(".sweepky/submitted");
        let meta = fs::symlink_metadata(&stamp).expect("there");
        assert!(meta.is_file() && meta.len() == 0, "{meta:?}");
        assert_eq!(mode(&stamp), 0o600);
        // Picking now passes the sweep over, and stamping again is fine.
        let message = refusal(&fixture, fixture.project(), None);
        assert!(
            message.contains("stamped as submitted already"),
            "{message}"
        );
        sweep.stamp_submitted().expect("stamped again");

        // A link the agent planted at the name counts as the stamp and is
        // never followed: what it points at is not made.
        let other = SweepFixture::in_temp_with(&fixture, "other");
        let elsewhere = fixture.temp().join("elsewhere");
        symlink(&elsewhere, other.dir().join(".sweepky/submitted")).expect("symlink");
        other.open().stamp_submitted().expect("counts as stamped");
        assert!(fs::symlink_metadata(&elsewhere).is_err(), "followed");
    }
}
