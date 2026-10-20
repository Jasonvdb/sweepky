//! `sweepky init <dir>`: create the directory, a `.gitignore` that ignores
//! `sweeps/`, the files Claude Code reads (the sandbox settings
//! `.claude/settings.json`, the project's `CLAUDE.md` and a copy of the
//! `/sweepky` skill, see [`project_files`]), when the sweeper agrees the
//! Cloudflare playbook (see [`playbook`]), and, last, the `.sweepky` marker
//! that `run` requires. P2a built the directory, the `.gitignore` and the
//! marker; P3 adds the Claude Code files and the playbook.
//!
//! The marker is a small JSON file, `{"schemaVersion":1}` and a newline, so
//! later phases can add fields to it the way records grow. One is there
//! when `init` installed the playbook: `playbook`,
//! `cloudflare/security-audit@<full commit>`, which [`read_project_marker`]
//! hands `run`, which writes it into the sweep record that `submit`
//! completes. The marker is written only once the install is checked.
//!
//! File safety: init writes into a directory the user named, which may
//! already hold files, so it never writes through a link and never replaces
//! anything:
//!
//! - A new file is created all or nothing. Its bytes go into a temp file
//!   beside it, opened with `create_new`, which is `O_CREAT | O_EXCL`: the
//!   open fails if anything at all is at that path, a symlink included (even
//!   one that points nowhere), so it can neither follow a link nor truncate a
//!   file. Once the bytes are on disk, a hard link gives the temp file its
//!   real name, which fails in the same way if anything is there, the
//!   directory is synced so that name is on disk too, and the temp name is
//!   removed. A failure at any step removes the temp file, so the real name
//!   never shows an empty or half-written file.
//! - An existing `.gitignore` is only ever appended to, and only when it is a
//!   regular file; a symlink is refused, because appending through one would
//!   write into whatever file it points at. It is not appended to when it has
//!   other hard links either, which share its contents.
//! - The marker is written last, once everything before it is on disk, so
//!   its presence means a finished `init`. A second run reads it and changes
//!   nothing when it is a marker this build reads; any other file at that
//!   name is refused, never taken for a finished `init`.

use std::fs::{self, Metadata, OpenOptions};
use std::io::{ErrorKind, Write};
// `MetadataExt` is a Unix-only extension trait that adds `nlink()` to
// `fs::Metadata`. A trait's methods are callable only while the trait is in
// scope, hence the `use`.
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::{Context as _, anyhow, bail};
use serde::{Deserialize, Serialize};
use sweepky_core::{Playbook, RecordError, SchemaVersion, UnknownFields};

use crate::Report;
use crate::prompt::Terminal;
#[cfg(test)]
pub(crate) use playbook::PLAYBOOK_COMMIT;
pub(crate) use playbook::{NpxRunner, PlaybookChoice};
use playbook::{RunNpx, check_before_install, installed_line, wants_install};
use project_files::{ClaudeFiles, SETTINGS, glob_safe};
// File steps shared with the secret files' writer: the temp name, the synced
// write, the open that checks it got the file it inspected, the capped read
// and the directory sync.
use crate::private_fs::{
    open_seen_file, read_up_to_cap, sync_parent, temp_path_beside, write_synced,
};

/// The project marker's file name, directly inside the project directory.
pub(crate) const MARKER: &str = ".sweepky";

mod playbook;
mod project_files;

/// The project's git ignore file.
const GITIGNORE: &str = ".gitignore";

/// The line init makes sure `.gitignore` has. `sweeps/` holds fetched targets
/// and the agent's output, which must never be committed.
const SWEEPS_LINE: &[u8] = b"sweeps/";

/// The marker's contents, as [`read_project_marker`] hands them out.
/// Serialized with `serde` so that adding a field later is one line here,
/// and read back with it to tell a marker from any other file at that name.
// `Debug` so a test can print one; nothing in it is secret. The fields are
// private: a marker comes only from `marker_bytes` or from a file that
// passed `parse_marker`, so `playbook()` always gives a checked value.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProjectMarker {
    /// The format's version, 1. Reading one refuses a newer version, as a
    /// record's does.
    schema_version: SchemaVersion,
    /// The playbook the project has installed, which `init` records after
    /// a checked install and `run` writes into the sweep record. Read
    /// through core's
    /// [`Playbook`], so a value outside 01's pattern makes the file no
    /// marker this build reads.
    // `default` reads a missing key as `None`, and `skip_serializing_if`
    // leaves `None` out, so the marker of a project without the playbook is
    // still exactly `{"schemaVersion":1}`: P2a's marker, unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    playbook: Option<Playbook>,
    /// Fields a newer Sweepky wrote. `flatten` collects every key not named
    /// above into this map instead of failing, so a marker a later phase
    /// added fields to still reads as a marker.
    #[serde(flatten)]
    extra: UnknownFields,
}

impl ProjectMarker {
    /// The playbook the project's `init` recorded, or `None` for a marker
    /// that names none, such as every one P2a's `init` writes.
    // `as_ref` lends the value inside the `Option` out, `Option<&Playbook>`,
    // so the caller reads it without taking it from the marker.
    pub(crate) fn playbook(&self) -> Option<&Playbook> {
        self.playbook.as_ref()
    }
}

/// The most bytes a marker may have: 64 KiB. The one init writes is 20; the
/// cap leaves room for fields later phases add, and keeps init from reading a
/// huge file someone left at that name into memory.
const MAX_MARKER_BYTES: usize = 64 * 1024;

/// The most bytes an existing `.gitignore` may have for init to edit it:
/// 1 MiB. Init only needs to know whether a line reads `sweeps/` and whether
/// the file ends in a newline; a `.gitignore` larger than this is not one
/// init should edit, and the cap keeps an untrusted checkout's huge (or
/// sparse) file from being read into memory whole.
const MAX_GITIGNORE_BYTES: usize = 1024 * 1024;

/// Runs `sweepky init <dir>`, installing the playbook as `playbook` says,
/// asking on `terminal` when it says ask, through `npx`.
///
/// Every check runs before the first write: the path, the marker, the
/// answer, the Claude Code files ([`ClaudeFiles::inspect`]), what npm would
/// read ([`check_before_install`]) and the `.gitignore`. Then the
/// `.gitignore`, the Claude Code files, the playbook and, last, the marker,
/// so a failed install leaves no marker and the next run starts again.
pub(crate) fn init(
    dir: &Path,
    playbook: PlaybookChoice,
    terminal: Terminal<'_>,
    npx: &impl RunNpx,
) -> anyhow::Result<Report> {
    // The path goes into a glob pattern in the settings, so one that would
    // change the pattern is refused before even the directory is made. The
    // canonical path is checked again below, since a parent link can lead
    // anywhere.
    glob_safe(dir)?;

    // Looked at before the directory is made: `lstat` of a name inside a
    // directory that does not exist is simply nothing there.
    let marker = dir.join(MARKER);
    if is_initialised(&marker)? {
        return already_initialised(dir);
    }
    // The question comes before anything is made, so `--no-input` without
    // either playbook flag fails with nothing written.
    let install = wants_install(playbook, terminal)?;

    // Like `mkdir -p`: creates every missing parent, and succeeds if the
    // directory is already there.
    fs::create_dir_all(dir).with_context(|| format!("could not create {}", dir.display()))?;
    refuse_symlinked_project_dir(&marker)?;
    // `canonicalize` resolves every link and `..` in the path, which now
    // exists. Claude Code matches `claudeMdExcludes` against files' real
    // absolute paths, so that is the path the settings name: on macOS a
    // project under `/tmp` is really under `/private/tmp`.
    let canonical =
        fs::canonicalize(dir).with_context(|| format!("could not resolve {}", dir.display()))?;
    let claude_files = ClaudeFiles::inspect(dir, &canonical)?;
    if install {
        check_before_install(dir)?;
    }

    let mut done = vec![
        ensure_gitignore(&dir.join(GITIGNORE))?
            .describe()
            .to_owned(),
    ];
    done.extend(claude_files.write()?);
    // `then` runs the install only when `install` is true, giving
    // `Some(result)`, and `transpose` turns that `Option<Result<…>>` into
    // a `Result<Option<…>>`, so `?` stops here on a failed install, before
    // the marker.
    let installed = install.then(|| playbook::install(dir, npx)).transpose()?;
    match &installed {
        Some(playbook) => {
            done.push(installed_line());
            write_new(&marker, &marker_bytes(Some(playbook))?)?;
            done.push(format!("wrote {MARKER}, naming the playbook {playbook}"));
        }
        None => {
            done.push(NO_PLAYBOOK_LINE.to_owned());
            write_new(&marker, &marker_bytes(None)?)?;
            done.push(format!("wrote {MARKER}"));
        }
    }
    Ok(finished(dir, &canonical, &done))
}

/// The report's line when no playbook was installed.
const NO_PLAYBOOK_LINE: &str = "installed no playbook, so the agent does a careful review unless                                 the bounty's suggested playbook is installed here";

/// The report of a finished `init`: what it did, one line each, then the
/// project's real path, the Node requirement and how to launch a sweep.
fn finished(dir: &Path, canonical: &Path, done: &[String]) -> Report {
    let mut text = format!("Initialised {} as a Sweepky project:\n", dir.display());
    for line in done {
        text.push_str(&format!("  {line}\n"));
    }
    text.push_str(&format!(
        "The sandbox settings name the project by its real path, {}.\n{NODE_LINE}\n\
         {LAUNCH_LINE}\n",
        canonical.display()
    ));
    Report::new(text)
}

/// The report's line on Node, which sandboxed commands can run only when it
/// is installed outside the home directory.
const NODE_LINE: &str = "Install Node outside $HOME (Homebrew: `brew install node`), not with nvm \
                         or another installer under your home directory: sandboxed commands \
                         cannot read $HOME, and the sandbox needs Node to run the playbook's \
                         validators.";

/// The report's line on how a sweep runs in the project.
const LAUNCH_LINE: &str = "To sweep: run `sweepky run <bounty-url>` here, then start the agent \
                           here with `claude --setting-sources project,local` and type \
                           `/sweepky`, then run `sweepky submit` once the agent has exited.";

/// The report for a project that already has its marker. Nothing is
/// changed. A project without `.claude/settings.json` was made by P2a's
/// `init`, before the sandbox existed; the report says so, and points at a
/// new directory rather than adding files beside an older marker.
fn already_initialised(dir: &Path) -> anyhow::Result<Report> {
    let mut text = format!(
        "{} is already initialised: it has a {MARKER} marker. Nothing changed.\n",
        dir.display()
    );
    if let Existing::Missing = existing(&dir.join(SETTINGS))? {
        text.push_str(&format!(
            "It has no {SETTINGS}, so it has no sandbox: an older `sweepky init` made it. Run \
             `sweepky init` on a new directory and sweep there.\n"
        ));
    }
    Ok(Report::new(text))
}

/// Refuses a project directory that is a symbolic link, before anything is
/// written. Each new file's name is synced to disk through its directory
/// ([`create_with`]), and [`sync_parent`] refuses a directory that is a link
/// rather than follow it, so without this check that refusal would come only
/// once `.gitignore` was already written.
///
/// It looks at `marker`'s parent, which is the directory exactly as
/// `sync_parent` will name it: `dir` as typed may end in `/`, and `lstat`
/// follows a link written that way.
fn refuse_symlinked_project_dir(marker: &Path) -> anyhow::Result<()> {
    // `let ... else` binds the parent or leaves the function; a marker path
    // always has one, so the `else` is only there because `parent` returns
    // an `Option`.
    let Some(dir) = marker.parent() else {
        return Ok(());
    };
    if let Existing::Symlink = existing(dir)? {
        bail!(
            "{} is a symbolic link; init writes only into a real directory, whose entries it can \
             sync to disk. Run init on the directory the link points to",
            dir.display()
        );
    }
    Ok(())
}

/// Whether a finished `init` already left its marker at `marker`. A regular
/// file there counts only when it holds a marker this build reads (see
/// [`read_marker`]). Anything else there is an error, because init would
/// have to write through it or replace it.
fn is_initialised(marker: &Path) -> anyhow::Result<bool> {
    match existing(marker)? {
        Existing::Missing => Ok(false),
        Existing::File(seen) => {
            read_marker(marker, &seen)?;
            Ok(true)
        }
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

/// The project marker directly inside `dir`, read with the rules `init`
/// reads its own with: a regular file, never a link followed, at most
/// [`MAX_MARKER_BYTES`], parsed as a [`ProjectMarker`] with its optional
/// `playbook` checked. Anything else at that name, or nothing, is an error
/// that names the path and quotes none of the file.
///
/// `run` and `submit` call it on their working directory, and only there:
/// a directory inside a project is not one, as `git` would take it to be.
/// A sweep's files are written relative to the project, so the command must
/// be run where they go.
pub(crate) fn read_project_marker(dir: &Path) -> anyhow::Result<ProjectMarker> {
    let marker = dir.join(MARKER);
    match existing(&marker)? {
        Existing::File(seen) => read_marker(&marker, &seen),
        Existing::Missing => bail!(
            "{} is not a Sweepky project: it has no {MARKER} marker. `sweepky init <dir>` makes \
             one",
            dir.display()
        ),
        Existing::Symlink => bail!(
            "{} is a symbolic link, which is never followed to a marker",
            marker.display()
        ),
        Existing::Other => bail!(
            "{} is not a regular file, so not a Sweepky project marker",
            marker.display()
        ),
    }
}

/// Reads the regular file at `marker`, which `seen` describes, and refuses
/// it unless it holds a marker this build reads (see [`parse_marker`]). An
/// empty or half-written file, or someone else's file of that name, is not
/// a finished `init`, so it is refused rather than reported as one, and
/// left as it is.
fn read_marker(marker: &Path, seen: &Metadata) -> anyhow::Result<ProjectMarker> {
    // Were the file swapped for a FIFO between the `lstat` and this `open`,
    // the open would wait for a writer. That needs someone who can write the
    // directory and costs a hung command, nothing more, so it is left at
    // that, as the `--identity` argument's read does. `(mut file, _)` keeps
    // the open file and drops its metadata, which nothing here needs.
    let (mut file, _) = open_seen_file(marker, seen, OpenOptions::new().read(true))?;
    // One byte past the cap is enough to tell that the file is too long,
    // without reading a huge one. The crate's bounded read hands back a
    // buffer that wipes itself; nothing here is secret, it simply comes so.
    let bytes = read_up_to_cap(&mut file, MAX_MARKER_BYTES + 1)
        .with_context(|| format!("could not read {}", marker.display()))?;
    // `map_err` turns only the `Err` side into an `anyhow::Error`, adding the
    // path; an `Ok` marker passes through untouched.
    parse_marker(&bytes).map_err(|fault| {
        anyhow!(
            "{} is not a Sweepky project marker ({fault}); move it away and run init again",
            marker.display()
        )
    })
}

/// Parses `bytes` as a marker this build reads: at most
/// [`MAX_MARKER_BYTES`] long, JSON whose `schemaVersion` is at most 1 and
/// whose `playbook`, if any, is a valid [`Playbook`], any other fields
/// allowed. The `Err` says what is wrong, for the caller's message.
///
/// It never quotes `bytes`. serde_json's own messages can, so a parse error
/// goes through core's `RecordError`, which keeps only the kind of fault and
/// where it is, as every record parse does.
fn parse_marker(bytes: &[u8]) -> Result<ProjectMarker, String> {
    if bytes.len() > MAX_MARKER_BYTES {
        return Err(format!(
            "it is longer than the {MAX_MARKER_BYTES} bytes a marker may have"
        ));
    }
    serde_json::from_slice(bytes).map_err(|err| RecordError::from(err).to_string())
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

/// The marker file's bytes, naming `playbook` when there is one: the JSON
/// object and a newline.
fn marker_bytes(playbook: Option<&Playbook>) -> anyhow::Result<Vec<u8>> {
    let marker = ProjectMarker {
        schema_version: SchemaVersion::CURRENT,
        // `cloned` copies the borrowed playbook, a short string, into the
        // marker, which owns its fields.
        playbook: playbook.cloned(),
        extra: UnknownFields::new(),
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
    // `append(true)` sends every write to the end of the file, whatever the
    // read position, so no existing byte can be overwritten; reading still
    // starts at the beginning. Opening never truncates without `truncate`.
    let (mut file, opened) =
        open_seen_file(path, seen, OpenOptions::new().read(true).append(true))?;

    // Bytes, not a `String`: a `.gitignore` need not be UTF-8, and its other
    // lines are left exactly as they are. As for the marker, one byte past
    // the cap is enough to tell the file is too long without reading a huge
    // one.
    let contents = read_up_to_cap(&mut file, MAX_GITIGNORE_BYTES + 1)
        .with_context(|| format!("could not read {}", path.display()))?;
    if contents.len() > MAX_GITIGNORE_BYTES {
        bail!(
            "{} is larger than the {MAX_GITIGNORE_BYTES} bytes init will edit, so init changed \
             nothing. Add a line reading `sweeps/` to it yourself; init finishes only once the \
             file is under that size",
            path.display()
        );
    }
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
    // Wait until the appended line is on disk, as `write_synced` does for a
    // new file, before the marker that says init finished is written.
    file.sync_all()
        .with_context(|| format!("could not save {} to disk", path.display()))?;
    Ok(GitignoreChange::Appended)
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

/// Creates the file at `path` with `bytes`, all or nothing, failing if
/// anything is already there.
///
/// Opening `path` itself and writing into it would let a failed write (a full
/// disk, say) leave an empty or half-written file under the real name, which
/// the next run would refuse as not a marker or, cut off just before the
/// final newline, take for a finished `init`. So the bytes go into a temp
/// file beside it first, named by [`temp_path_beside`] (in the same
/// directory, since a hard link cannot cross filesystems); see
/// [`create_with`].
fn write_new(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    create_with(&temp_path_beside(path)?, path, bytes)
}

/// Creates `temp` with `bytes`, gives that finished file its real name,
/// `path`, with a hard link, and removes the name `temp` again.
///
/// - `temp` is opened with `create_new` (see the module comment), so a file
///   someone else left at that name is refused, and is neither reused nor
///   removed.
/// - [`write_synced`] waits until the bytes are on disk, and closes the file,
///   before the link, so not even a crash can leave `path` naming a file
///   without them.
/// - `fs::hard_link` is `link(2)`: it adds a second name for the same file,
///   and fails if anything at all is at `path`, a dangling symlink included,
///   without following it. So, like `create_new`, it never replaces a file and
///   never writes through a link, and `path` appears only once the file is
///   whole. `rename` is one step too, but it would replace whatever is at
///   `path`.
/// - [`sync_parent`] then syncs the directory, because the file's own sync
///   makes its bytes durable but not the new name. So when this returns, the
///   file survives a crash under its name: init creates `.gitignore` (or
///   syncs its append) before the marker, and reports success only once the
///   marker's name is on disk. A failed sync is an error, with `path` already
///   in place, as after a rename in `private_fs`.
///
/// The name `temp` is removed whether the link worked or not, so a failure
/// before the link leaves the directory as it was. A filesystem without hard
/// links, such as FAT, fails at the link, and nothing is created.
fn create_with(temp: &Path, path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(temp)
        .with_context(|| format!("could not create {}", temp.display()))?;
    // Each `and_then` runs only when the step before it worked, so `linked`
    // holds the first error, if any.
    let linked = write_synced(temp, file, bytes)
        .and_then(|()| {
            fs::hard_link(temp, path)
                .with_context(|| format!("could not create {}", path.display()))
        })
        .and_then(|()| sync_parent(path));
    // From the link on, `path` keeps the file by itself.
    let removed =
        fs::remove_file(temp).with_context(|| format!("could not remove {}", temp.display()));
    // `and` keeps the first error: the write's, the link's or the sync's when
    // one failed (a failed removal then goes unreported, as in `private_fs`),
    // otherwise the removal's, which names the stray file.
    linked.and(removed)
}

/// `init <dir> --no-playbook`, with nothing to ask and an npx that fails
/// the run if anything starts it: what most tests need of a project.
#[cfg(test)]
pub(crate) fn init_without_playbook(dir: &Path) -> anyhow::Result<Report> {
    init_with(dir, PlaybookChoice::Skip, &playbook::FakeNpx::failing())
}

/// `init <dir> --install-playbook`, with an npx that installs what
/// skills@1.7.2 would: a project whose marker names the playbook.
#[cfg(test)]
pub(crate) fn init_with_fake_playbook(dir: &Path) -> anyhow::Result<Report> {
    init_with(
        dir,
        PlaybookChoice::Install,
        &playbook::FakeNpx::installing(),
    )
}

/// [`init`] with `choice` and `npx`, an empty standard input and standard
/// error thrown away.
#[cfg(test)]
fn init_with(dir: &Path, choice: PlaybookChoice, npx: &impl RunNpx) -> anyhow::Result<Report> {
    let stdin = crate::StdinReader::new(std::io::empty());
    let stderr = crate::StderrWriter::new(std::io::sink());
    let terminal = Terminal {
        stdin: &stdin,
        stderr: &stderr,
        prompting: crate::prompt::Prompting::Allowed,
    };
    init(dir, choice, terminal, npx)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, symlink};
    use std::path::{Path, PathBuf};

    use sweepky_core::Playbook;
    use tempfile::TempDir;

    // Most tests here are about the files, not the playbook, so they call
    // `init --no-playbook` by the short name `init`; the playbook's own
    // tests call the real `super::init` with their choice and fake npx.
    use super::playbook::{FakeNpx, NpxCommand, PLAYBOOK_COMMIT, SKILL_DIR, install_command};
    use super::{
        GITIGNORE, MARKER, MAX_GITIGNORE_BYTES, PlaybookChoice, create_with,
        init_without_playbook as init, read_project_marker, write_new,
    };
    use crate::prompt::{MAX_ANSWER_BYTES, Prompting, Terminal};
    use crate::test_support::SharedBuffer;
    use crate::{Report, StderrWriter, StdinReader};

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

    /// The names directly inside a project init finished in an empty
    /// directory.
    fn initialised() -> BTreeSet<String> {
        names(&[MARKER, GITIGNORE, ".claude", "CLAUDE.md"])
    }

    #[test]
    fn init_creates_directory_marker_and_gitignore() {
        let temp = tempfile::tempdir().expect("temp dir");
        let dir = temp.path().join("project");

        init(&dir).expect("init succeeds");

        assert!(dir.is_dir());
        assert_eq!(entries(&dir), initialised());
        assert_eq!(
            fs::read_to_string(dir.join(MARKER)).expect("marker"),
            "{\"schemaVersion\":1}\n"
        );
        assert_eq!(
            fs::read_to_string(dir.join(GITIGNORE)).expect("gitignore"),
            "sweeps/\n"
        );

        assert_eq!(
            entries(&dir.join(".claude")),
            names(&["settings.json", "skills"])
        );
        assert_eq!(entries(&dir.join(".claude/skills")), names(&["sweepky"]));
        assert_eq!(
            entries(&dir.join(".claude/skills/sweepky")),
            names(&["SKILL.md"])
        );

        // Each file was made through a temp file and a hard link, and the
        // temp name is gone again, so each has the one name.
        for name in [
            MARKER,
            GITIGNORE,
            "CLAUDE.md",
            ".claude/settings.json",
            ".claude/skills/sweepky/SKILL.md",
        ] {
            let meta = fs::symlink_metadata(dir.join(name)).expect("lstat");
            assert_eq!(meta.nlink(), 1, "{name}");
        }

        // Nested directories are created too.
        let nested = temp.path().join("a").join("b");
        init(&nested).expect("init succeeds");
        assert_eq!(entries(&nested), initialised());
    }

    #[test]
    fn a_new_file_is_created_whole_leaving_no_temp_file() {
        let temp = tempfile::tempdir().expect("temp dir");
        let dir = project_dir(&temp, "create");

        write_new(&dir.join(MARKER), b"whole\n").expect("created");
        assert_eq!(fs::read(dir.join(MARKER)).expect("read"), b"whole\n");
        assert_eq!(entries(&dir), names(&[MARKER]));
        let meta = fs::symlink_metadata(dir.join(MARKER)).expect("lstat");
        assert_eq!(meta.nlink(), 1);
    }

    #[test]
    fn a_new_name_is_never_synced_through_a_linked_directory() {
        let temp = tempfile::tempdir().expect("temp dir");
        let real = project_dir(&temp, "real");
        let link = temp.path().join("link");
        symlink(&real, &link).expect("symlink");

        // The link step works through the linked directory, but the sync of
        // the directory that holds the new name refuses the link rather than
        // follow it. That is an error with the file already in place and the
        // temp name gone, as for a failed sync after a rename in `private_fs`.
        let err = create_with(&link.join("marker.tmp"), &link.join(MARKER), b"linked\n")
            .expect_err("the sync refuses a linked directory");
        assert!(format!("{err:#}").contains("symbolic link"), "{err:#}");
        assert_eq!(fs::read(real.join(MARKER)).expect("read"), b"linked\n");
        assert_eq!(entries(&real), names(&[MARKER]));
    }

    #[test]
    fn a_failed_create_removes_its_temp_file_and_replaces_nothing() {
        let temp = tempfile::tempdir().expect("temp dir");

        // The link fails when a file is already at the target: that file
        // keeps its bytes and the temp file is removed again.
        let dir = project_dir(&temp, "taken");
        let target = dir.join(MARKER);
        fs::write(&target, "first\n").expect("write");
        assert!(create_with(&dir.join("marker.tmp"), &target, b"second\n").is_err());
        assert_eq!(fs::read_to_string(&target).expect("read"), "first\n");
        assert_eq!(entries(&dir), names(&[MARKER]));

        // A dangling symlink at the target counts as something there: the
        // link is not followed, so nothing appears where it points, and it is
        // left as it was.
        let dir = project_dir(&temp, "dangling");
        let target = dir.join(MARKER);
        let nowhere = temp.path().join("nowhere");
        symlink(&nowhere, &target).expect("symlink");
        assert!(create_with(&dir.join("marker.tmp"), &target, b"never\n").is_err());
        assert!(!nowhere.exists());
        let meta = fs::symlink_metadata(&target).expect("lstat");
        assert!(meta.file_type().is_symlink());
        assert_eq!(entries(&dir), names(&[MARKER]));

        // A temp name someone else already holds is refused by `create_new`
        // before anything is written, and that file is not this run's to
        // remove, so it stays, and no target appears.
        let dir = project_dir(&temp, "temp-taken");
        let temp_file = dir.join("marker.tmp");
        fs::write(&temp_file, "someone else's\n").expect("write");
        assert!(create_with(&temp_file, &dir.join(MARKER), b"never\n").is_err());
        assert_eq!(
            fs::read_to_string(&temp_file).expect("read"),
            "someone else's\n"
        );
        assert_eq!(entries(&dir), names(&["marker.tmp"]));
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
        assert_eq!(entries(&dir), initialised());

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
    fn init_edits_an_existing_gitignore_only_up_to_the_cap() {
        let temp = tempfile::tempdir().expect("temp dir");

        // A file exactly at the cap is read whole and gets the line.
        let dir = project_dir(&temp, "at-cap");
        let at_cap = vec![b'#'; MAX_GITIGNORE_BYTES];
        fs::write(dir.join(GITIGNORE), &at_cap).expect("write");
        init(&dir).expect("init succeeds");
        let after = fs::read(dir.join(GITIGNORE)).expect("read");
        assert_eq!(after, [at_cap.as_slice(), b"\nsweeps/\n"].concat());
        assert_eq!(entries(&dir), initialised());

        // One byte more is refused with a message that names the file and the
        // line to add by hand; the file is left byte for byte as it was, and
        // no marker is written.
        let dir = project_dir(&temp, "over-cap");
        let over_cap = vec![b'#'; MAX_GITIGNORE_BYTES + 1];
        fs::write(dir.join(GITIGNORE), &over_cap).expect("write");
        let err = init(&dir).expect_err("a file over the cap is refused");
        let message = format!("{err:#}");
        assert!(
            message.contains(&dir.join(GITIGNORE).display().to_string()),
            "{message}"
        );
        assert!(message.contains("`sweeps/`"), "{message}");
        assert_eq!(fs::read(dir.join(GITIGNORE)).expect("read"), over_cap);
        assert_eq!(entries(&dir), names(&[GITIGNORE]));
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
        assert_eq!(entries(&dir), initialised());
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
        assert_eq!(entries(&dir), initialised());
    }

    #[test]
    fn init_refuses_a_project_directory_that_is_a_symlink() {
        let temp = tempfile::tempdir().expect("temp dir");
        let real = project_dir(&temp, "real");
        let link = temp.path().join("link");
        symlink(&real, &link).expect("symlink");

        // Each new name is synced through the directory that holds it, which
        // must not be a link, so a linked project directory is refused before
        // anything is written. Spelled with a trailing `/` too, a form whose
        // `lstat` would follow the link.
        let mut with_slash = link.clone().into_os_string();
        with_slash.push("/");
        for dir in [link, PathBuf::from(with_slash)] {
            let err = init(&dir).expect_err("a linked directory is refused");
            assert!(format!("{err:#}").contains("symbolic link"), "{err:#}");
            assert!(entries(&real).is_empty(), "{}", dir.display());
        }
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
    fn init_refuses_a_marker_that_is_not_a_marker() {
        let temp = tempfile::tempdir().expect("temp dir");

        // A regular `.sweepky` that is not the document init writes is not a
        // finished init: an empty one, as a write cut short by a full disk
        // left before markers were written all or nothing, a cut-off one,
        // other JSON, a newer version and a file over the cap. Each is
        // refused, left as it is, and nothing else is written. The planted
        // word sits where serde_json's own message would quote it.
        let too_long = format!("{{\"schemaVersion\":1,\"pad\":\"{}\"}}", "x".repeat(70_000));
        let cases: [(&str, &[u8]); 8] = [
            ("empty", b""),
            ("cut-off", b"{\"schemaVersion\":"),
            ("not-json", b"PLANTED-7f3a\n"),
            ("not-an-object", b"[\"PLANTED-7f3a\"]\n"),
            ("no-version", b"{\"name\":\"PLANTED-7f3a\"}\n"),
            ("wrong-type", b"{\"schemaVersion\":\"PLANTED-7f3a\"}\n"),
            ("newer", b"{\"schemaVersion\":2}\n"),
            ("too-long", too_long.as_bytes()),
        ];
        for (name, contents) in cases {
            let dir = project_dir(&temp, name);
            fs::write(dir.join(MARKER), contents).expect("write");
            let err = init(&dir).expect_err(name);
            let message = format!("{err:#}");
            assert!(
                message.contains(&dir.join(MARKER).display().to_string()),
                "{name}: {message}"
            );
            assert!(
                message.contains("is not a Sweepky project marker"),
                "{name}: {message}"
            );
            assert!(!message.contains("PLANTED"), "{name}: {message}");
            assert!(!message.contains("already"), "{name}: {message}");
            assert_eq!(
                fs::read(dir.join(MARKER)).expect("read"),
                contents,
                "{name}"
            );
            assert_eq!(entries(&dir), names(&[MARKER]), "{name}");
        }
    }

    #[test]
    fn init_accepts_a_marker_a_newer_sweepky_added_fields_to() {
        let temp = tempfile::tempdir().expect("temp dir");

        // Later phases add fields to the marker the way records grow, so a
        // marker with fields this build does not know, pretty-printed or not,
        // still means a finished init. Nothing changes.
        let dir = project_dir(&temp, "newer-fields");
        let marker: &[u8] = b"{\n  \"schemaVersion\": 1,\n  \"addedLater\": {\"x\": [1]}\n}\n";
        fs::write(dir.join(MARKER), marker).expect("write");
        let report = init(&dir).expect("init succeeds");
        assert!(
            report.text().contains("already initialised"),
            "{}",
            report.text()
        );
        assert_eq!(fs::read(dir.join(MARKER)).expect("read"), marker);
        assert_eq!(entries(&dir), names(&[MARKER]));
    }

    #[test]
    fn the_marker_init_writes_reads_back_with_no_playbook() {
        let temp = tempfile::tempdir().expect("temp dir");
        let dir = temp.path().join("project");
        init(&dir).expect("init succeeds");

        let marker = read_project_marker(&dir).expect("init's own marker reads");
        assert_eq!(marker.playbook(), None);
    }

    #[test]
    fn a_marker_s_playbook_is_read_and_a_bad_one_refused_unquoted() {
        let temp = tempfile::tempdir().expect("temp dir");

        // P3's init records the playbook it installed, beside fields a
        // later build may add.
        let dir = project_dir(&temp, "with-playbook");
        fs::write(
            dir.join(MARKER),
            "{\"schemaVersion\":1,\"playbook\":\"cloudflare/security-audit@c1c8a8c\",\
             \"addedLater\":[1]}\n",
        )
        .expect("write");
        let marker = read_project_marker(&dir).expect("reads");
        assert_eq!(
            marker.playbook().map(Playbook::as_str),
            Some("cloudflare/security-audit@c1c8a8c")
        );

        // A playbook outside 01's pattern, or not a string at all, makes the
        // file no marker this build reads: refused by name, never quoted,
        // and left as it is by init too.
        let cases: [(&str, &[u8]); 3] = [
            (
                "pattern",
                b"{\"schemaVersion\":1,\"playbook\":\"PLANTED-7f3a ../x\"}\n",
            ),
            (
                "escape",
                b"{\"schemaVersion\":1,\"playbook\":\"PLANTED-7f3a\\u001b[2J\"}\n",
            ),
            (
                "not-a-string",
                b"{\"schemaVersion\":1,\"playbook\":[\"PLANTED-7f3a\"]}\n",
            ),
        ];
        for (name, contents) in cases {
            let dir = project_dir(&temp, name);
            fs::write(dir.join(MARKER), contents).expect("write");
            for err in [
                read_project_marker(&dir).expect_err(name),
                init(&dir).expect_err(name),
            ] {
                let message = format!("{err:#}");
                assert!(
                    message.contains(&dir.join(MARKER).display().to_string()),
                    "{name}: {message}"
                );
                assert!(
                    message.contains("is not a Sweepky project marker"),
                    "{name}: {message}"
                );
                assert!(!message.contains("PLANTED"), "{name}: {message}");
            }
            assert_eq!(fs::read(dir.join(MARKER)).expect("read"), contents);
        }
    }

    #[test]
    fn the_report_gives_the_launch_line_and_the_node_requirement() {
        let temp = tempfile::tempdir().expect("temp dir");
        let report = init(&temp.path().join("project")).expect("init succeeds");
        let text = report.text();
        for phrase in [
            "claude --setting-sources project,local",
            "Install Node outside $HOME (Homebrew",
            "wrote .claude/settings.json",
            "wrote CLAUDE.md",
            "wrote .claude/skills/sweepky/SKILL.md",
        ] {
            assert!(text.contains(phrase), "{phrase} not in {text}");
        }
    }

    #[test]
    fn a_p2a_project_without_settings_is_left_and_pointed_at_a_new_directory() {
        let temp = tempfile::tempdir().expect("temp dir");
        // What P2a's init left: the marker and the `.gitignore`, no
        // `.claude/`. Init changes nothing and says why it will not add
        // the sandbox here.
        let dir = project_dir(&temp, "p2a");
        fs::write(dir.join(MARKER), "{\"schemaVersion\":1}\n").expect("write");
        fs::write(dir.join(GITIGNORE), "sweeps/\n").expect("write");
        let report = init(&dir).expect("init succeeds");
        let text = report.text();
        assert!(text.contains("already initialised"), "{text}");
        assert!(text.contains("no .claude/settings.json"), "{text}");
        assert!(text.contains("new directory"), "{text}");
        assert_eq!(entries(&dir), names(&[MARKER, GITIGNORE]));
    }

    #[test]
    fn init_twice_is_idempotent() {
        let temp = tempfile::tempdir().expect("temp dir");
        let dir = temp.path().join("project");

        let first = init(&dir).expect("first run");
        assert!(!first.text().contains("already"));
        let marker = fs::read(dir.join(MARKER)).expect("marker");
        let gitignore = fs::read(dir.join(GITIGNORE)).expect("gitignore");

        let settings = fs::read(dir.join(".claude/settings.json")).expect("settings");

        let second = init(&dir).expect("second run");
        assert!(
            second.text().contains("already initialised"),
            "{}",
            second.text()
        );
        assert!(!second.text().contains("no .claude"), "{}", second.text());
        assert_eq!(
            fs::read(dir.join(".claude/settings.json")).expect("settings"),
            settings
        );
        assert_eq!(entries(&dir), initialised());
        assert_eq!(fs::read(dir.join(MARKER)).expect("marker"), marker);
        assert_eq!(fs::read(dir.join(GITIGNORE)).expect("gitignore"), gitignore);
    }

    // -----------------------------------------------------------------------
    // The playbook.

    /// Runs the real `init` on `dir` with `choice`, `answer` as standard
    /// input, `prompting` and `npx`, and returns its result and what it
    /// wrote to standard error.
    fn init_answering(
        dir: &Path,
        choice: PlaybookChoice,
        answer: &str,
        prompting: Prompting,
        npx: &FakeNpx,
    ) -> (anyhow::Result<Report>, String) {
        let stdin = StdinReader::new(std::io::Cursor::new(answer.to_owned()));
        let said = SharedBuffer::default();
        let stderr = StderrWriter::new(said.clone());
        let terminal = Terminal {
            stdin: &stdin,
            stderr: &stderr,
            prompting,
        };
        (super::init(dir, choice, terminal, npx), said.text())
    }

    /// A test's way of planting one case: given the project and a file
    /// outside it.
    type Plant = fn(&Path, &Path);

    /// The full playbook value the marker names after an install.
    fn full_playbook() -> String {
        format!("cloudflare/security-audit@{PLAYBOOK_COMMIT}")
    }

    #[test]
    fn install_playbook_runs_03_s_line_in_the_project_and_the_marker_names_it() {
        let temp = tempfile::tempdir().expect("temp dir");
        let dir = temp.path().join("project");
        let npx = FakeNpx::installing();

        let (result, said) = init_answering(
            &dir,
            PlaybookChoice::Install,
            "",
            Prompting::Forbidden,
            &npx,
        );
        let report = result.expect("init succeeds");

        // Exactly one run: the pinned argv, in the project, with telemetry
        // off. Under --no-input too, since the flag answered the question.
        assert_eq!(
            npx.calls(),
            [NpxCommand {
                args: [
                    "skills@1.7.2",
                    "add",
                    "https://github.com/cloudflare/security-audit-skill#\
                     c1c8a8c1471069fb0e188eeaff69b8e8db6564a8",
                    "--skill",
                    "security-audit",
                    "--agent",
                    "claude-code",
                    "--copy",
                    "-y",
                ]
                .map(str::to_owned)
                .to_vec(),
                dir: dir.clone(),
                env: &[("DISABLE_TELEMETRY", "1")],
            }]
        );
        assert_eq!(said, "", "nothing asked");
        let marker = read_project_marker(&dir).expect("the marker reads");
        assert_eq!(
            marker
                .playbook()
                .map(|playbook| playbook.as_str().to_owned()),
            Some(full_playbook())
        );
        assert!(dir.join(SKILL_DIR).join("SKILL.md").is_file());
        assert!(
            report.text().contains(&full_playbook()),
            "{}",
            report.text()
        );
    }

    #[test]
    fn no_playbook_never_runs_npx_and_the_marker_names_none() {
        let temp = tempfile::tempdir().expect("temp dir");
        let dir = temp.path().join("project");
        let npx = FakeNpx::installing();

        let (result, said) =
            init_answering(&dir, PlaybookChoice::Skip, "", Prompting::Allowed, &npx);
        let report = result.expect("init succeeds");

        assert!(npx.calls().is_empty());
        assert_eq!(said, "");
        assert_eq!(
            fs::read_to_string(dir.join(MARKER)).expect("marker"),
            "{\"schemaVersion\":1}\n"
        );
        assert!(
            report.text().contains("installed no playbook"),
            "{}",
            report.text()
        );
    }

    #[test]
    fn without_a_flag_init_asks_once_and_only_yes_installs() {
        let temp = tempfile::tempdir().expect("temp dir");
        for (answer, installs) in [
            ("y\n", true),
            ("YES\n", true),
            ("n\n", false),
            ("\n", false),
            ("", false),
            ("sure\n", false),
        ] {
            let dir = temp.path().join(format!("p{}", answer.len()));
            let _ = fs::remove_dir_all(&dir);
            let npx = FakeNpx::installing();
            let (result, said) =
                init_answering(&dir, PlaybookChoice::Ask, answer, Prompting::Allowed, &npx);
            result.expect("init succeeds");
            // One question on standard error, naming the commit and both
            // flags.
            assert_eq!(said.matches("[y/N]").count(), 1, "{answer:?}: {said}");
            for phrase in [PLAYBOOK_COMMIT, "--install-playbook", "--no-playbook"] {
                assert!(said.contains(phrase), "{answer:?}: {said}");
            }
            assert_eq!(npx.calls().len(), usize::from(installs), "{answer:?}");
            let marker = read_project_marker(&dir).expect("reads");
            assert_eq!(marker.playbook().is_some(), installs, "{answer:?}");
        }

        // An answer past the cap is an error before anything is written.
        let dir = temp.path().join("too-long");
        let npx = FakeNpx::installing();
        let long = format!("{}\n", "y".repeat(MAX_ANSWER_BYTES));
        let (result, _) =
            init_answering(&dir, PlaybookChoice::Ask, &long, Prompting::Allowed, &npx);
        assert!(result.is_err());
        assert!(npx.calls().is_empty());
        assert!(!dir.exists());
    }

    #[test]
    fn no_input_without_a_flag_fails_naming_both_flags_with_nothing_written() {
        let temp = tempfile::tempdir().expect("temp dir");
        let npx = FakeNpx::installing();

        // A directory that does not exist yet is not even made, and one
        // that does is left empty.
        let missing = temp.path().join("missing");
        let empty = project_dir(&temp, "empty");
        for dir in [&missing, &empty] {
            let (result, said) =
                init_answering(dir, PlaybookChoice::Ask, "y\n", Prompting::Forbidden, &npx);
            let message = format!("{:#}", result.expect_err("refused"));
            for phrase in ["--no-input", "--install-playbook", "--no-playbook"] {
                assert!(message.contains(phrase), "{message}");
            }
            assert_eq!(said, "");
        }
        assert!(!missing.exists());
        assert!(entries(&empty).is_empty());
        assert!(npx.calls().is_empty());
    }

    #[test]
    fn a_failed_install_leaves_no_marker_and_the_next_run_finishes() {
        let temp = tempfile::tempdir().expect("temp dir");
        let dir = temp.path().join("project");

        // npx fails as the real runner does on a bad exit, a timeout or too
        // much output (its own tests check those say none of npx's words).
        let (result, _) = init_answering(
            &dir,
            PlaybookChoice::Install,
            "",
            Prompting::Allowed,
            &FakeNpx::failing(),
        );
        assert!(result.is_err());
        assert!(!dir.join(MARKER).exists());

        // A failure part way through the copy, as a killed npx leaves it.
        let (result, _) = init_answering(
            &dir,
            PlaybookChoice::Install,
            "",
            Prompting::Allowed,
            &FakeNpx::doing(|dir| {
                fs::create_dir_all(dir.join(SKILL_DIR))?;
                fs::write(dir.join(SKILL_DIR).join("HALF.md"), "half\n")?;
                anyhow::bail!("killed")
            }),
        );
        assert!(result.is_err());
        assert!(!dir.join(MARKER).exists());

        // The next run keeps the identical files, installs over what was
        // left, and finishes.
        let npx = FakeNpx::installing();
        let (result, _) =
            init_answering(&dir, PlaybookChoice::Install, "", Prompting::Allowed, &npx);
        let report = result.expect("the second run finishes");
        assert!(
            report.text().contains("kept CLAUDE.md"),
            "{}",
            report.text()
        );
        assert_eq!(npx.calls(), [install_command(&dir)]);
        let marker = read_project_marker(&dir).expect("reads");
        assert!(marker.playbook().is_some());
    }

    #[test]
    fn an_install_that_holds_a_link_is_refused_and_leaves_no_marker() {
        let temp = tempfile::tempdir().expect("temp dir");
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).expect("mkdir");
        fs::write(outside.join("secret"), "not the playbook\n").expect("write");
        let dir = temp.path().join("project");
        let planted = outside.clone();

        let (result, _) = init_answering(
            &dir,
            PlaybookChoice::Install,
            "",
            Prompting::Allowed,
            &FakeNpx::doing(move |dir| {
                let skill = dir.join(SKILL_DIR);
                fs::create_dir_all(&skill)?;
                fs::write(skill.join("SKILL.md"), "skill\n")?;
                symlink(&planted, skill.join("refs"))?;
                Ok(())
            }),
        );
        let message = format!("{:#}", result.expect_err("refused"));
        assert!(message.contains("symbolic link"), "{message}");
        assert!(!dir.join(MARKER).exists());
    }

    #[test]
    fn a_project_npm_would_read_config_from_is_refused_before_npx_runs() {
        let temp = tempfile::tempdir().expect("temp dir");
        let elsewhere = temp.path().join("elsewhere");
        fs::write(&elsewhere, "{}\n").expect("write");

        // npm's own project files, of any kind, and a lock file or skill
        // directory that npx would write through.
        let cases: [(&str, Plant); 6] = [
            (".npmrc", |dir, _| {
                fs::write(dir.join(".npmrc"), "x\n").expect("write")
            }),
            ("package.json", |dir, _| {
                fs::write(dir.join("package.json"), "{}\n").expect("write")
            }),
            ("node_modules", |dir, _| {
                fs::create_dir(dir.join("node_modules")).expect("mkdir")
            }),
            ("linked-npmrc", |dir, elsewhere| {
                symlink(elsewhere, dir.join(".npmrc")).expect("symlink")
            }),
            ("linked-lock", |dir, elsewhere| {
                symlink(elsewhere, dir.join("skills-lock.json")).expect("symlink")
            }),
            ("linked-skill", |dir, elsewhere| {
                let skills = dir.join(".claude/skills");
                fs::create_dir_all(&skills).expect("mkdir");
                symlink(
                    elsewhere.parent().expect("parent"),
                    skills.join("security-audit"),
                )
                .expect("symlink");
            }),
        ];
        for (name, plant) in cases {
            let dir = project_dir(&temp, &format!("p-{name}"));
            plant(&dir, &elsewhere);
            let before = entries(&dir);
            let npx = FakeNpx::installing();
            let (result, _) =
                init_answering(&dir, PlaybookChoice::Install, "", Prompting::Allowed, &npx);
            assert!(result.is_err(), "{name}");
            assert!(npx.calls().is_empty(), "{name}");
            assert_eq!(entries(&dir), before, "{name}: nothing written");
        }
        assert_eq!(fs::read_to_string(&elsewhere).expect("read"), "{}\n");
    }
}
