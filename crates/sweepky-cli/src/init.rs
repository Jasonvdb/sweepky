//! `sweepky init <dir>`, the minimal version (P2a): create the directory, a
//! `.gitignore` that ignores `sweeps/`, and the `.sweepky` marker that `run`
//! requires. Nothing else; the sandbox settings, the project `CLAUDE.md`, the
//! skill and the playbook arrive in P3.
//!
//! The marker is a small JSON file, `{"schemaVersion":1}` and a newline, so
//! later phases can add fields to it the way records grow.
//!
//! File safety: init writes into a directory the user named, which may
//! already hold files, so it never writes through a link and never replaces
//! anything:
//!
//! - New files are opened with `create_new`, which is `O_CREAT | O_EXCL`: the
//!   open fails if anything at all is at that path, a symlink included (even
//!   one that points nowhere), so it can neither follow a link nor truncate a
//!   file.
//! - An existing `.gitignore` is only ever appended to, and only when it is a
//!   regular file; a symlink is refused, because appending through one would
//!   write into whatever file it points at. It is not appended to when it has
//!   other hard links either, which share its contents.
//! - The marker is written last, so its presence means a finished `init`; a
//!   second run sees it and changes nothing.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{ErrorKind, Read, Write};
// `MetadataExt` is a Unix-only extension trait that adds `dev()`, `ino()` and
// `nlink()` to `fs::Metadata`. A trait's methods are callable only while the
// trait is in scope, hence the `use`.
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::{Context as _, bail};
use serde::Serialize;
use sweepky_core::SchemaVersion;

use crate::Report;

/// The project marker's file name, directly inside the project directory.
pub(crate) const MARKER: &str = ".sweepky";

/// The project's git ignore file.
const GITIGNORE: &str = ".gitignore";

/// The line init makes sure `.gitignore` has. `sweeps/` holds fetched targets
/// and the agent's output, which must never be committed.
const SWEEPS_LINE: &[u8] = b"sweeps/";

/// The marker's contents. Serialized with `serde` so that adding a field later
/// is one line here.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectMarker {
    schema_version: SchemaVersion,
}

/// Runs `sweepky init <dir>`.
pub(crate) fn init(dir: &Path) -> anyhow::Result<Report> {
    // Like `mkdir -p`: creates every missing parent, and succeeds if the
    // directory is already there.
    fs::create_dir_all(dir).with_context(|| format!("could not create {}", dir.display()))?;

    let marker = dir.join(MARKER);
    if is_initialised(&marker)? {
        return Ok(Report::new(format!(
            "{} is already initialised: it has a {MARKER} marker. Nothing changed.\n",
            dir.display()
        )));
    }

    let gitignore = ensure_gitignore(&dir.join(GITIGNORE))?;
    write_new(&marker, &marker_bytes()?)?;

    Ok(Report::new(format!(
        "Initialised {} as a Sweepky project:\n  wrote {MARKER}\n  {}\n",
        dir.display(),
        gitignore.describe()
    )))
}

/// Whether a finished `init` already left its marker at `marker`. Anything
/// there other than a regular file is an error, because init would have to
/// write through it or replace it.
fn is_initialised(marker: &Path) -> anyhow::Result<bool> {
    match existing(marker)? {
        Existing::Missing => Ok(false),
        Existing::File(_) => Ok(true),
        Existing::Symlink => bail!(
            "{} is a symbolic link; init never writes through a link. Remove it and run init \
             again",
            marker.display()
        ),
        Existing::Other => bail!(
            "{} exists and is not a regular file; remove it and run init again",
            marker.display()
        ),
    }
}

/// What was at a path, as `symlink_metadata` saw it.
enum Existing {
    /// Nothing.
    Missing,
    /// A regular file, with its metadata, so a later open can check it got
    /// the same file.
    File(Metadata),
    /// A symbolic link, wherever it points.
    Symlink,
    /// A directory, a FIFO, a device or a socket.
    Other,
}

/// Looks at `path` itself, never at what a symlink there points to.
///
/// `fs::symlink_metadata` is `lstat`: for a symlink it describes the link.
/// `fs::metadata` (`stat`) would follow it and describe the target instead,
/// which is exactly what must not decide whether init writes here.
fn existing(path: &Path) -> anyhow::Result<Existing> {
    match fs::symlink_metadata(path) {
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(Existing::Missing),
        Err(err) => Err(err).with_context(|| format!("could not inspect {}", path.display())),
        Ok(meta) => {
            let kind = meta.file_type();
            Ok(if kind.is_symlink() {
                Existing::Symlink
            } else if kind.is_file() {
                Existing::File(meta)
            } else {
                Existing::Other
            })
        }
    }
}

/// The marker file's bytes: the JSON object and a newline.
fn marker_bytes() -> anyhow::Result<Vec<u8>> {
    let marker = ProjectMarker {
        schema_version: SchemaVersion::CURRENT,
    };
    let mut bytes = serde_json::to_vec(&marker).context("could not write the marker")?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// What [`ensure_gitignore`] did.
enum GitignoreChange {
    Created,
    Appended,
    AlreadyListed,
}

impl GitignoreChange {
    /// One line for the report.
    fn describe(&self) -> &'static str {
        match self {
            Self::Created => "wrote .gitignore with sweeps/",
            Self::Appended => "added sweeps/ to .gitignore",
            Self::AlreadyListed => "kept .gitignore, which lists sweeps/",
        }
    }
}

/// Makes sure the `.gitignore` at `path` has a line that reads exactly
/// `sweeps/`, creating the file if there is none.
fn ensure_gitignore(path: &Path) -> anyhow::Result<GitignoreChange> {
    match existing(path)? {
        Existing::Missing => {
            write_new(path, &sweeps_line_after(b""))?;
            Ok(GitignoreChange::Created)
        }
        Existing::File(seen) => append_sweeps_line(path, &seen),
        Existing::Symlink => bail!(
            "{} is a symbolic link; init never writes through a link. Replace it with a regular \
             file and run init again",
            path.display()
        ),
        Existing::Other => bail!("{} exists and is not a regular file", path.display()),
    }
}

/// Appends `sweeps/` to the existing regular file at `path` unless one of its
/// lines already reads exactly that. Every existing byte is kept.
fn append_sweeps_line(path: &Path, seen: &Metadata) -> anyhow::Result<GitignoreChange> {
    let (mut file, opened) = open_seen_file(path, seen)?;

    // Bytes, not a `String`: a `.gitignore` need not be UTF-8, and its other
    // lines are left exactly as they are.
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)
        .with_context(|| format!("could not read {}", path.display()))?;
    if has_sweeps_line(&contents) {
        return Ok(GitignoreChange::AlreadyListed);
    }

    // A file with several hard links shares its contents with other names,
    // possibly outside this directory, so appending would change those too.
    if opened.nlink() > 1 {
        bail!(
            "{} has other hard links; init will not append to it. Replace it with a file of its \
             own and run init again",
            path.display()
        );
    }

    file.write_all(&sweeps_line_after(&contents))
        .with_context(|| format!("could not append to {}", path.display()))?;
    Ok(GitignoreChange::Appended)
}

/// Opens the file at `path` to read and append, and checks it is the very
/// file `seen` describes. Returns the open file and its own metadata.
fn open_seen_file(path: &Path, seen: &Metadata) -> anyhow::Result<(File, Metadata)> {
    // `append(true)` sends every write to the end of the file, whatever the
    // read position, so no existing byte can be overwritten; reading still
    // starts at the beginning. Opening never truncates without `truncate`.
    let file = OpenOptions::new()
        .read(true)
        .append(true)
        .open(path)
        .with_context(|| format!("could not open {}", path.display()))?;

    // `open` follows symlinks, so check that it opened the very file
    // `symlink_metadata` looked at: same device, same inode. If the path was
    // swapped for a link in between, the numbers differ and nothing is
    // written.
    let opened = file
        .metadata()
        .with_context(|| format!("could not inspect {}", path.display()))?;
    if opened.dev() != seen.dev() || opened.ino() != seen.ino() {
        bail!(
            "{} changed while init was reading it; run init again",
            path.display()
        );
    }
    Ok((file, opened))
}

/// Whether one of the lines of `contents`, split on `\n`, reads exactly
/// `sweeps/`.
fn has_sweeps_line(contents: &[u8]) -> bool {
    contents
        .split(|&byte| byte == b'\n')
        .any(|line| line == SWEEPS_LINE)
}

/// The bytes that end `contents` with a line of its own reading `sweeps/`.
fn sweeps_line_after(contents: &[u8]) -> Vec<u8> {
    let mut addition = Vec::new();
    // Start a new line first if the file does not end with one, so `sweeps/`
    // is a line of its own rather than the tail of the last pattern.
    if !contents.is_empty() && !contents.ends_with(b"\n") {
        addition.push(b'\n');
    }
    addition.extend_from_slice(SWEEPS_LINE);
    addition.push(b'\n');
    addition
}

/// Creates the file at `path` with `bytes`, failing if anything is already
/// there (see the module comment on `create_new`).
fn write_new(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("could not create {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("could not write {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};

    use tempfile::TempDir;

    use super::{GITIGNORE, MARKER, init};

    /// A new, empty directory `name` inside `temp`.
    fn project_dir(temp: &TempDir, name: &str) -> PathBuf {
        let dir = temp.path().join(name);
        fs::create_dir(&dir).expect("mkdir");
        dir
    }

    /// The names directly inside `dir`, sorted.
    fn entries(dir: &Path) -> BTreeSet<String> {
        fs::read_dir(dir)
            .expect("readable")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .into_string()
                    .expect("UTF-8 name")
            })
            .collect()
    }

    fn names(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|name| (*name).to_owned()).collect()
    }

    #[test]
    fn init_creates_directory_marker_and_gitignore() {
        let temp = tempfile::tempdir().expect("temp dir");
        let dir = temp.path().join("project");

        init(&dir).expect("init succeeds");

        assert!(dir.is_dir());
        assert_eq!(entries(&dir), names(&[MARKER, GITIGNORE]));
        assert_eq!(
            fs::read_to_string(dir.join(MARKER)).expect("marker"),
            "{\"schemaVersion\":1}\n"
        );
        assert_eq!(
            fs::read_to_string(dir.join(GITIGNORE)).expect("gitignore"),
            "sweeps/\n"
        );

        // Nested directories are created too.
        let nested = temp.path().join("a").join("b");
        init(&nested).expect("init succeeds");
        assert_eq!(entries(&nested), names(&[MARKER, GITIGNORE]));
    }

    #[test]
    fn init_appends_sweeps_line_to_an_existing_gitignore() {
        let temp = tempfile::tempdir().expect("temp dir");

        // Other lines, no `sweeps/` line, no final newline, and a byte that is
        // not UTF-8: `sweeps/` is appended on a line of its own and every
        // existing byte stays as it was.
        let dir = project_dir(&temp, "append");
        let before: &[u8] = b"target/\n# sweeps/\nsweeps/x\n/sweeps/\n\xff.log";
        fs::write(dir.join(GITIGNORE), before).expect("write");
        init(&dir).expect("init succeeds");
        let after = fs::read(dir.join(GITIGNORE)).expect("read");
        assert_eq!(after, [before, b"\nsweeps/\n"].concat());
        assert_eq!(entries(&dir), names(&[MARKER, GITIGNORE]));

        // A file that ends in a newline gets just the one line.
        let dir = project_dir(&temp, "newline");
        fs::write(dir.join(GITIGNORE), "target/\n").expect("write");
        init(&dir).expect("init succeeds");
        assert_eq!(
            fs::read_to_string(dir.join(GITIGNORE)).expect("read"),
            "target/\nsweeps/\n"
        );

        // An empty file gets the line and nothing before it.
        let dir = project_dir(&temp, "empty");
        fs::write(dir.join(GITIGNORE), "").expect("write");
        init(&dir).expect("init succeeds");
        assert_eq!(
            fs::read_to_string(dir.join(GITIGNORE)).expect("read"),
            "sweeps/\n"
        );
    }

    #[test]
    fn init_keeps_a_gitignore_that_lists_sweeps() {
        let temp = tempfile::tempdir().expect("temp dir");

        // A file that already has the line is left exactly as it is, even
        // without a final newline.
        let dir = project_dir(&temp, "present");
        let before: &[u8] = b"target/\nsweeps/\n*.tmp";
        fs::write(dir.join(GITIGNORE), before).expect("write");
        init(&dir).expect("init succeeds");
        assert_eq!(fs::read(dir.join(GITIGNORE)).expect("read"), before);
        assert_eq!(entries(&dir), names(&[MARKER, GITIGNORE]));
    }

    #[test]
    fn init_refuses_a_symlinked_gitignore() {
        let temp = tempfile::tempdir().expect("temp dir");
        let outside = temp.path().join("outside.txt");
        fs::write(&outside, "not yours\n").expect("write");

        // A `.gitignore` that is a symlink is refused and its target is not
        // touched, and no marker is written.
        let dir = project_dir(&temp, "gitignore-link");
        symlink(&outside, dir.join(GITIGNORE)).expect("symlink");
        assert!(init(&dir).is_err());
        assert_eq!(fs::read_to_string(&outside).expect("read"), "not yours\n");
        assert_eq!(entries(&dir), names(&[GITIGNORE]));

        // A dangling `.gitignore` link is refused too, and nothing is created
        // where it points.
        let dir = project_dir(&temp, "gitignore-dangling");
        let nowhere = temp.path().join("nowhere");
        symlink(&nowhere, dir.join(GITIGNORE)).expect("symlink");
        assert!(init(&dir).is_err());
        assert!(!nowhere.exists());
        assert_eq!(entries(&dir), names(&[GITIGNORE]));
    }

    #[test]
    fn init_refuses_a_symlinked_marker() {
        let temp = tempfile::tempdir().expect("temp dir");
        let outside = temp.path().join("outside.txt");
        fs::write(&outside, "not yours\n").expect("write");
        let nowhere = temp.path().join("nowhere");

        // A marker that is a symlink, to a file or to nothing, is refused
        // before anything is written.
        for (name, target) in [("marker-link", &outside), ("marker-dangling", &nowhere)] {
            let dir = project_dir(&temp, name);
            symlink(target, dir.join(MARKER)).expect("symlink");
            assert!(init(&dir).is_err(), "{name}");
            assert_eq!(entries(&dir), names(&[MARKER]), "{name}");
        }
        assert_eq!(fs::read_to_string(&outside).expect("read"), "not yours\n");
        assert!(!nowhere.exists());
    }

    #[test]
    fn init_refuses_to_append_to_a_hard_linked_gitignore() {
        let temp = tempfile::tempdir().expect("temp dir");

        // A `.gitignore` with a second hard link is refused, because appending
        // would change the other name's contents too.
        let dir = project_dir(&temp, "gitignore-hardlink");
        let shared = temp.path().join("shared.txt");
        fs::write(&shared, "target/\n").expect("write");
        fs::hard_link(&shared, dir.join(GITIGNORE)).expect("hard link");
        assert!(init(&dir).is_err());
        assert_eq!(fs::read_to_string(&shared).expect("read"), "target/\n");
        assert_eq!(entries(&dir), names(&[GITIGNORE]));

        // One that already lists `sweeps/` needs no append, so it is kept.
        let dir = project_dir(&temp, "gitignore-hardlink-listed");
        let listed = temp.path().join("listed.txt");
        fs::write(&listed, "sweeps/\n").expect("write");
        fs::hard_link(&listed, dir.join(GITIGNORE)).expect("hard link");
        init(&dir).expect("init succeeds");
        assert_eq!(fs::read_to_string(&listed).expect("read"), "sweeps/\n");
        assert_eq!(entries(&dir), names(&[MARKER, GITIGNORE]));
    }

    #[test]
    fn init_refuses_a_marker_or_gitignore_that_is_a_directory() {
        let temp = tempfile::tempdir().expect("temp dir");

        let dir = temp.path().join("marker-dir");
        fs::create_dir_all(dir.join(MARKER)).expect("mkdir");
        assert!(init(&dir).is_err());
        assert_eq!(entries(&dir), names(&[MARKER]));

        let dir = temp.path().join("gitignore-dir");
        fs::create_dir_all(dir.join(GITIGNORE)).expect("mkdir");
        assert!(init(&dir).is_err());
        assert_eq!(entries(&dir), names(&[GITIGNORE]));
    }

    #[test]
    fn init_twice_is_idempotent() {
        let temp = tempfile::tempdir().expect("temp dir");
        let dir = temp.path().join("project");

        let first = init(&dir).expect("first run");
        assert!(!first.text().contains("already"));
        let marker = fs::read(dir.join(MARKER)).expect("marker");
        let gitignore = fs::read(dir.join(GITIGNORE)).expect("gitignore");

        let second = init(&dir).expect("second run");
        assert!(
            second.text().contains("already initialised"),
            "{}",
            second.text()
        );
        assert_eq!(entries(&dir), names(&[MARKER, GITIGNORE]));
        assert_eq!(fs::read(dir.join(MARKER)).expect("marker"), marker);
        assert_eq!(fs::read(dir.join(GITIGNORE)).expect("gitignore"), gitignore);
    }
}
