//! Owner-only files: the primitives every secret or state file in
//! [`Dirs`](crate::Dirs) goes through, the SSH model.
//!
//! - [`ensure_private_dir`] creates a directory 0700 (owner only), or checks
//!   that the one already there is.
//! - [`write_private_file`] writes a file 0600 (owner read and write): a new
//!   temp file next to it, then a rename over the old one, then a sync of
//!   the directory.
//! - [`read_private_file`] reads one back, refusing anything another user
//!   could read, anything over a size cap, and links, into a buffer that
//!   zeroes itself.
//! - [`read_up_to_cap`] reads an already open file up to a cap, into the
//!   same kind of buffer. It is for the files a user's argument names
//!   (`--identity`, `--passphrase-file`), which are not Sweepky's own, so
//!   each caller makes its own checks before it reads.
//! - [`remove_private_file`] deletes one, a missing file counting as success.
//! - [`lstat`] says what is at a path, a link itself rather than what it
//!   points at, or `None` when nothing is.
//! - [`open_private_lock_file`] opens the writers' lock file, creating it
//!   empty and 0600, and never replaces or truncates it.
//! - [`temp_path_beside`], [`write_synced`], [`open_seen_file`] and
//!   [`sync_parent`] are steps the functions above are built from. `init`
//!   uses them too, for the files it writes into a project, which are not
//!   private.
//!
//! The rules, and why:
//!
//! - **The mode is set when the file or directory is created**, never by a
//!   `chmod` afterwards. Between a create and a later `chmod` there is a
//!   moment when another user could open the file, and an open file stays
//!   readable to them after the `chmod`. Unix's `umask` can only take bits
//!   away from the mode asked for, never add any, so 0600 and 0700 are the
//!   most a file or directory made here can have.
//! - **A file is written to a temp file and renamed into place.** `rename`
//!   swaps the name over in one step, so a reader sees the old file or the
//!   new one, never half of either, and a crash mid-write leaves the old file
//!   whole. The temp file is synced before the rename and the directory
//!   after it, so that once a write returns, both the bytes and the name
//!   that points at them are on disk.
//! - **No links and no special files.** A symlink in the config directory
//!   would send a write somewhere else, or feed a read from somewhere else,
//!   so a link where a file or directory should be is refused rather than
//!   followed, as are FIFOs, sockets and devices.
//! - **A file other users can read is refused, not fixed**, as ssh refuses a
//!   loose private key: if it was ever readable, its secret may already be
//!   out, and the user should know. The error says what `chmod` fixes it.
//!   Ownership is not checked separately: a 0600 file or 0700 directory that
//!   belongs to someone else cannot be opened by this user anyway (root
//!   aside, which can read everything regardless).
//! - **Reads are bounded.** The size is checked against the caller's cap
//!   before a byte is read, so a huge file cannot exhaust memory.
//!
//! Unix only, like the rest of this crate: the modes, inode numbers and
//! `create_new` + mode come from `std::os::unix`.

use std::ffi::OsString;
use std::fs::{self, DirBuilder, File, Metadata, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
// Extension traits: Unix-only methods added to std's types. `DirBuilderExt`
// and `OpenOptionsExt` add `.mode(...)`, the mode a new directory or file is
// created with; `MetadataExt` adds `.mode()`, `.dev()` and `.ino()`. A
// trait's methods can only be called while the trait is in scope, hence the
// `use`.
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, bail};
use sweepky_core::Zeroizing;

/// The mode of a private directory: owner read, write and enter.
const DIR_MODE: u32 = 0o700;

/// The mode of a private file: owner read and write.
const FILE_MODE: u32 = 0o600;

/// Every group and other permission bit. A private file or directory has none.
const GROUP_OR_OTHER: u32 = 0o077;

/// The permission bits of a mode, without the file-type bits `st_mode` also
/// carries.
const PERMISSION_BITS: u32 = 0o777;

/// Makes sure `path` is a private directory: creates it 0700 if nothing is
/// there (with any missing parents, also 0700), or checks the one that is.
///
/// Refuses a symlink, anything that is not a directory, and a directory with
/// any group or other permission bit, saying how to fix it. It never changes
/// the mode of a directory that is already there.
pub(crate) fn ensure_private_dir(path: &Path) -> anyhow::Result<()> {
    if let Some(meta) = lstat(path)? {
        return check_private_dir(path, &meta);
    }
    // `recursive(true)` is `mkdir -p`, and the mode applies to every
    // directory it creates, the parents included.
    DirBuilder::new()
        .recursive(true)
        .mode(DIR_MODE)
        .create(path)
        .with_context(|| format!("could not create {}", path.display()))?;
    // Check what is there now, in case something else made it first.
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("could not inspect {}", path.display()))?;
    check_private_dir(path, &meta)
}

/// Refuses `path` unless `meta`, its `lstat`, is a directory with no group or
/// other permission bit.
fn check_private_dir(path: &Path, meta: &Metadata) -> anyhow::Result<()> {
    refuse_unless_dir(path, meta)?;
    if let Some(mode) = loose_permissions(meta) {
        bail!(
            "{} is open to other users (mode {mode:03o}); Sweepky keeps it private, as ssh does \
             ~/.ssh. Run `chmod 700 {}` and try again",
            path.display(),
            path.display()
        );
    }
    Ok(())
}

/// Refuses `path` unless `meta`, its `lstat`, is a directory: a symlink there,
/// dangling or not, is refused, as is anything else that is not a directory.
fn refuse_unless_dir(path: &Path, meta: &Metadata) -> anyhow::Result<()> {
    let kind = meta.file_type();
    if kind.is_symlink() {
        bail!(
            "{} is a symbolic link; Sweepky keeps its files in a real directory, never through a \
             link. Remove the link and try again",
            path.display()
        );
    }
    if !kind.is_dir() {
        bail!(
            "{} exists and is not a directory; move it away and try again",
            path.display()
        );
    }
    Ok(())
}

/// Writes `bytes` to `path` as a private 0600 file, replacing any regular
/// file there in one step.
///
/// The directory must already exist; make it with [`ensure_private_dir`].
/// A symlink or anything but a regular file at `path` is refused, and on any
/// failure the temp file is removed again.
pub(crate) fn write_private_file(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(meta) = lstat(path)? {
        refuse_unless_regular(path, &meta)?;
    }
    // Were `path` swapped for a link after the check above, the rename below
    // would still not write through it: `rename` replaces whatever entry has
    // the target name, a link included, and never follows it.
    replace_with(&temp_path_beside(path)?, path, bytes)
}

/// Creates `temp` with `bytes`, renames it over `target`, then syncs the
/// directory that holds them ([`sync_parent`]). Removes `temp` again if the
/// write or the rename fails.
fn replace_with(temp: &Path, target: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let file = create_private_temp(temp)?;
    // `and_then` runs the rename only when the write succeeded; either
    // step's error ends up in `result`.
    let result = write_synced(temp, file, bytes).and_then(|()| {
        fs::rename(temp, target).with_context(|| format!("could not replace {}", target.display()))
    });
    if result.is_err() {
        // Best effort, and `let _ =` ignores its own failure: the error worth
        // reporting is the first one, which `result` carries.
        let _ = fs::remove_file(temp);
        return result;
    }
    // The rename is done, so `temp` is gone and there is nothing left to
    // remove: from here on the new file is in place, and only whether it
    // survives a crash is in doubt.
    sync_parent(target)
}

/// Waits until the directory that holds `path` is on disk, so the name a
/// rename just gave `path` survives a crash.
///
/// [`write_synced`]'s `sync_all` on the temp file makes its bytes durable,
/// not the directory entry that names it. On filesystems that keep the two
/// apart, a power loss after the rename could still bring back the old entry,
/// or none, while the caller has gone on as if the write were done (after
/// `login`'s signup, say, or once a device key is published). An `fsync` on
/// a handle to the directory itself, which Linux and macOS both allow, closes
/// that gap. Its failure is an error, never ignored, for the same reason: the
/// caller is about to rely on the file.
///
/// The directory is opened read-only, which is all a sync needs, and only
/// once an `lstat` has shown a real directory at its path
/// ([`refuse_unless_dir`]): a symlink there, dangling or not, is refused
/// rather than followed. [`open_seen_file`] then checks the open handle is
/// that very directory (device and inode), as every read here does, since
/// `open` itself would follow a link.
pub(crate) fn sync_parent(path: &Path) -> anyhow::Result<()> {
    let dir = parent_dir(path)?;
    let Some(seen) = lstat(dir)? else {
        bail!(
            "{} is gone, so Sweepky could not make sure {} is saved; check it and try again",
            dir.display(),
            path.display()
        );
    };
    refuse_unless_dir(dir, &seen)
        .with_context(|| format!("could not make sure {} is saved", path.display()))?;
    let (handle, _) = open_seen_file(dir, &seen, OpenOptions::new().read(true))?;
    handle.sync_all().with_context(|| {
        format!(
            "{} is written, but its directory {} could not be synced to disk, so a crash could \
             still lose it",
            path.display(),
            dir.display()
        )
    })
}

/// The directory that holds `path`.
///
/// The `&Path` it returns borrows from `path` (the one input reference, so
/// lifetime elision ties the output to it); `Path::new(".")` borrows a
/// `'static` string, which outlives any such borrow, so it fits too.
fn parent_dir(path: &Path) -> anyhow::Result<&Path> {
    match path.parent() {
        // A bare file name, such as `login.json`, lives in the current
        // directory, which `Path` spells as an empty parent.
        Some(parent) if parent.as_os_str().is_empty() => Ok(Path::new(".")),
        Some(parent) => Ok(parent),
        None => bail!("{} has no parent directory", path.display()),
    }
}

/// Creates the empty file `temp`, 0600 from the start.
///
/// `create_new` is `O_CREAT | O_EXCL`: the open fails if anything at all is
/// at that path, a symlink included (even one that points nowhere), so it can
/// neither follow a link nor reuse a file someone else left there. `mode` is
/// the mode the new file is created with, in the same system call.
fn create_private_temp(temp: &Path) -> anyhow::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(temp)
        .with_context(|| format!("could not create {}", temp.display()))
}

/// Writes `bytes` into `file`, the open temp file at `temp`, and waits until
/// they are on disk.
///
/// Takes the `File` by value, so it is closed when this returns, before the
/// rename (or `init`'s hard link). `mut file` makes only this function's own
/// binding mutable, which `write_all` needs; the caller has already handed
/// the file over.
pub(crate) fn write_synced(temp: &Path, mut file: File, bytes: &[u8]) -> anyhow::Result<()> {
    file.write_all(bytes)
        .with_context(|| format!("could not write {}", temp.display()))?;
    // `sync_all` waits until the bytes are on disk, so a crash after the
    // rename cannot leave the new name pointing at an empty file.
    file.sync_all()
        .with_context(|| format!("could not write {}", temp.display()))
}

/// A temp file name next to `path`, in the same directory so a rename or a
/// hard link stays on one filesystem: `.<name>.<pid>.<nanos>.<n>.tmp`. The
/// leading dot hides it; a name that already starts with one, such as
/// `init`'s `.sweepky`, gets no second.
///
/// The process id, the clock and a counter keep two writers, or two writes in
/// one process, from picking the same name; `create_new` refuses a clash
/// anyway. Nothing secret depends on the name, so no random number is needed.
pub(crate) fn temp_path_beside(path: &Path) -> anyhow::Result<PathBuf> {
    // A `static` lives for the whole program and is shared by every call;
    // an atomic integer can be bumped from any thread without a lock.
    // `Relaxed` is enough because only the number's uniqueness matters, not
    // its order against other memory. `fetch_add` wraps rather than
    // panicking at the maximum.
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let Some(name) = path.file_name() else {
        bail!("{} does not name a file", path.display());
    };
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    // A clock before 1970 only makes the name less unique, so it counts as 0
    // rather than failing the write.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    // `OsString`, not `String`: the file name need not be UTF-8.
    // `as_encoded_bytes` views it as bytes, whatever its encoding, to test
    // its first one.
    let mut temp = OsString::new();
    if !name.as_encoded_bytes().starts_with(b".") {
        temp.push(".");
    }
    temp.push(name);
    temp.push(format!(".{}.{nanos}.{count}.tmp", std::process::id()));
    Ok(path.with_file_name(temp))
}

/// Reads the private file at `path`, at most `cap` bytes long.
///
/// `Ok(None)` when nothing is at `path`. An error for a symlink (even one
/// that points nowhere: a dangling link is not a missing file), anything
/// but a regular file, a file with any group or other permission bit, and a
/// file over `cap` bytes; each check runs before a byte is read. The bytes
/// come back in a [`Zeroizing`] buffer, which overwrites them with zeros when
/// it is dropped.
pub(crate) fn read_private_file(
    path: &Path,
    cap: usize,
) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
    let Some(seen) = lstat(path)? else {
        return Ok(None);
    };
    check_private_file(path, &seen, cap)?;
    let (mut file, opened) = open_seen_file(path, &seen, OpenOptions::new().read(true))?;
    // The checks again, on the open file: its mode or size may have changed
    // between the `lstat` and the open.
    let len = check_private_file(path, &opened, cap)?;
    read_exactly(path, &mut file, len).map(Some)
}

/// Refuses `path` unless `meta` is a regular file with no group or other
/// permission bit and at most `cap` bytes. Returns its length.
fn check_private_file(path: &Path, meta: &Metadata, cap: usize) -> anyhow::Result<usize> {
    refuse_unless_private(path, meta)?;
    // `try_from` fails only for a length that does not fit in `usize`, which
    // is over any cap anyway, so it falls into the same refusal. `if len <=
    // cap` is a match guard: the arm matches only when it holds.
    match usize::try_from(meta.len()) {
        Ok(len) if len <= cap => Ok(len),
        _ => bail!(
            "{} is {} bytes, larger than the {cap} bytes Sweepky reads from it",
            path.display(),
            meta.len()
        ),
    }
}

/// Refuses `path` unless `meta` is a regular file with no group or other
/// permission bit, saying which `chmod` fixes a loose one.
fn refuse_unless_private(path: &Path, meta: &Metadata) -> anyhow::Result<()> {
    refuse_unless_regular(path, meta)?;
    if let Some(mode) = loose_permissions(meta) {
        bail!(
            "{} is open to other users (mode {mode:03o}); Sweepky refuses it, as ssh refuses a \
             loose key file. If the file is yours and nobody else has read it, run \
             `chmod 600 {}` and try again",
            path.display(),
            path.display()
        );
    }
    Ok(())
}

/// Refuses `path` unless `meta`, its `lstat`, is a regular file.
fn refuse_unless_regular(path: &Path, meta: &Metadata) -> anyhow::Result<()> {
    let kind = meta.file_type();
    if kind.is_symlink() {
        bail!(
            "{} is a symbolic link; Sweepky never reads or writes its files through a link. \
             Remove it and try again",
            path.display()
        );
    }
    if !kind.is_file() {
        bail!(
            "{} is not a regular file; move it away and try again",
            path.display()
        );
    }
    Ok(())
}

/// Opens `path` with `options` and checks it is the very file `seen`, its
/// `lstat`, describes. Returns the open file and its own metadata.
///
/// `open` follows symlinks, and std has no portable "do not follow" flag, so
/// the check is by device and inode: if the path was swapped for a link in
/// between, the numbers differ and the file is refused before it is used.
pub(crate) fn open_seen_file(
    path: &Path,
    seen: &Metadata,
    options: &OpenOptions,
) -> anyhow::Result<(File, Metadata)> {
    let file = options
        .open(path)
        .with_context(|| format!("could not open {}", path.display()))?;
    let opened = file
        .metadata()
        .with_context(|| format!("could not inspect {}", path.display()))?;
    if opened.dev() != seen.dev() || opened.ino() != seen.ino() {
        bail!(
            "{} changed while Sweepky was opening it; try again",
            path.display()
        );
    }
    Ok((file, opened))
}

/// Reads exactly `len` bytes from `file`, the open file at `path`, and
/// refuses a file that turns out shorter or longer than that.
fn read_exactly(path: &Path, file: &mut File, len: usize) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    // A zeroed buffer of exactly `len` bytes, filled in place by
    // `read_exact`. It never grows, so the secret is never copied into a
    // bigger allocation and left behind, unwiped, in the old one. `Zeroizing`
    // wipes this one when the caller drops it.
    let mut bytes = Zeroizing::new(vec![0_u8; len]);
    match file.read_exact(bytes.as_mut_slice()) {
        Ok(()) => {}
        Err(err) if err.kind() == ErrorKind::UnexpectedEof => bail!(
            "{} got shorter while Sweepky was reading it; try again",
            path.display()
        ),
        Err(err) => {
            return Err(err).with_context(|| format!("could not read {}", path.display()));
        }
    }
    ensure_at_end(path, file)?;
    Ok(bytes)
}

/// Refuses `file`, the open file at `path`, if any byte is left to read: it
/// grew past the size checked before.
fn ensure_at_end(path: &Path, file: &mut File) -> anyhow::Result<()> {
    // The probe is wiped too, in case it caught a byte of the secret.
    let mut probe = Zeroizing::new([0_u8; 1]);
    match file.read_exact(probe.as_mut_slice()) {
        Err(err) if err.kind() == ErrorKind::UnexpectedEof => Ok(()),
        Ok(()) => bail!(
            "{} grew while Sweepky was reading it; try again",
            path.display()
        ),
        Err(err) => Err(err).with_context(|| format!("could not read {}", path.display())),
    }
}

/// Reads `file` up to `cap` bytes or its end, whichever comes first.
///
/// For a file whose size is not known before reading, such as a pipe: a
/// zeroed buffer of exactly `cap` bytes, filled in place and never grown,
/// so the bytes are never copied into a bigger allocation and left behind,
/// unwiped, in the old one. `Zeroizing` wipes all of it, spare capacity
/// included, when the caller drops it. Its error is the system's, which
/// never names the file.
pub(crate) fn read_up_to_cap(file: &mut File, cap: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(vec![0_u8; cap]);
    let mut filled = 0;
    // `get_mut(filled..)` is the unfilled rest, or `None` past the end, so
    // this cannot index out of bounds; the loop ends at the cap or at the
    // end of the file. `rest` borrows `bytes` only inside each pass.
    while let Some(rest) = bytes.get_mut(filled..).filter(|rest| !rest.is_empty()) {
        match file.read(rest) {
            Ok(0) => break,
            // `read` fills at most `rest.len()` bytes, so `filled` never
            // passes the cap.
            Ok(count) => filled += count,
            // A signal arrived before any byte did: try again.
            Err(err) if err.kind() == ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    bytes.truncate(filled);
    Ok(bytes)
}

/// Deletes the file at `path`. Nothing there counts as success, so `logout`
/// can tidy up after a login that left only some of its files.
///
/// A symlink at `path` is removed itself; `unlink` never follows it to the
/// file it points at. The bytes are not overwritten first: on SSDs and
/// copy-on-write filesystems an overwrite need not reach the old blocks, so
/// it would promise more than it does.
pub(crate) fn remove_private_file(path: &Path) -> anyhow::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("could not delete {}", path.display())),
    }
}

/// Opens the lock file at `path` to read and write, creating it empty and
/// 0600 when nothing is there. For the writers' lock (`crate::lock`).
///
/// Unlike [`write_private_file`], this never replaces the file, and unlike a
/// plain create it never truncates it. A `flock` belongs to the file itself
/// (its inode), so two commands only exclude each other while both have the
/// very same file open; a lock file swapped for a new one would let a second
/// writer in.
///
/// The file rules are the others': a symlink, dangling or not, anything but a
/// regular file, and a file with any group or other permission bit are
/// refused, and an existing file is checked on its `lstat` before the open
/// and again on the opened file, which must be the one inspected (same device
/// and inode). The directory must already exist; make it with
/// [`ensure_private_dir`].
pub(crate) fn open_private_lock_file(path: &Path) -> anyhow::Result<File> {
    if let Some(seen) = lstat(path)? {
        return open_existing_lock_file(path, &seen);
    }
    // `create_new` (`O_CREAT | O_EXCL`) creates the file 0600 in the same
    // call, and fails on anything already at the path, a symlink included,
    // so it never follows one.
    match lock_file_options()
        .create_new(true)
        .mode(FILE_MODE)
        .open(path)
    {
        Ok(file) => Ok(file),
        // Another command created it between the `lstat` above and this
        // call: open the one it made, with the same checks.
        Err(err) if err.kind() == ErrorKind::AlreadyExists => match lstat(path)? {
            Some(seen) => open_existing_lock_file(path, &seen),
            None => bail!(
                "{} kept changing while Sweepky was opening it; try again",
                path.display()
            ),
        },
        Err(err) => Err(err).with_context(|| format!("could not create {}", path.display())),
    }
}

/// Opens the existing lock file at `path`, whose `lstat` is `seen`, as it
/// is: no create, no truncate.
fn open_existing_lock_file(path: &Path, seen: &Metadata) -> anyhow::Result<File> {
    refuse_unless_private(path, seen)?;
    let (file, opened) = open_seen_file(path, seen, &lock_file_options())?;
    // The checks again, on the open file: its mode may have changed between
    // the `lstat` and the open.
    refuse_unless_private(path, &opened)?;
    Ok(file)
}

/// How the lock file is opened: read and write. `flock` itself needs
/// neither, but `fcntl` locks, which some systems use in its place, need
/// write access for an exclusive lock.
///
/// `OpenOptions` is a builder: each call sets one flag on it and returns it
/// again (`&mut Self`), so `let mut` plus two calls, then the value, is how a
/// function hands one back for the caller to add to.
fn lock_file_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    options
}

/// What is at `path` itself, or `None` when nothing is.
///
/// `symlink_metadata` is `lstat`: for a link it describes the link itself.
/// `fs::metadata` would follow it and describe the target, which is exactly
/// what must not decide where secrets are written or read.
pub(crate) fn lstat(path: &Path) -> anyhow::Result<Option<Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(meta) => Ok(Some(meta)),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("could not inspect {}", path.display())),
    }
}

/// The permission bits of `meta` when any group or other bit is among them;
/// `None` when the mode is private.
pub(crate) fn loose_permissions(meta: &Metadata) -> Option<u32> {
    let mode = meta.mode() & PERMISSION_BITS;
    // `then_some` turns `true` into `Some(mode)` and `false` into `None`.
    (mode & GROUP_OR_OTHER != 0).then_some(mode)
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, symlink};
    use std::os::unix::net::UnixListener;
    use std::path::Path;

    use sweepky_core::Zeroizing;

    use super::{
        create_private_temp, ensure_private_dir, parent_dir, read_private_file,
        remove_private_file, replace_with, sync_parent, temp_path_beside, write_private_file,
    };
    use crate::test_support::{chmod, mode, private_temp};

    /// The names directly inside `dir`, sorted.
    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .expect("readable")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .into_string()
                    .expect("UTF-8 name")
            })
            .collect();
        names.sort();
        names
    }

    #[test]
    fn private_dir_is_created_0700() {
        let temp = private_temp();
        let nested = temp.path().join("a").join("b").join("sweepky");

        ensure_private_dir(&nested).expect("created");
        assert!(fs::symlink_metadata(&nested).expect("exists").is_dir());
        // Every directory it had to create, parents included, is 0700.
        for dir in [
            temp.path().join("a"),
            temp.path().join("a").join("b"),
            nested.clone(),
        ] {
            assert_eq!(mode(&dir), 0o700, "{}", dir.display());
        }

        // A second call on the private directory it made succeeds and
        // changes nothing.
        ensure_private_dir(&nested).expect("already private");
        assert_eq!(mode(&nested), 0o700);
    }

    #[test]
    fn private_dir_refuses_a_symlink_dangling_or_not() {
        let temp = private_temp();

        // A link to a private directory is refused: the path itself must be
        // the directory.
        let real = temp.path().join("real");
        ensure_private_dir(&real).expect("created");
        let link = temp.path().join("link");
        symlink(&real, &link).expect("symlink");
        let err = ensure_private_dir(&link).expect_err("a link is refused");
        assert!(format!("{err:#}").contains("symbolic link"), "{err:#}");

        // A dangling link is refused, and nothing is created where it points.
        let nowhere = temp.path().join("nowhere");
        let dangling = temp.path().join("dangling");
        symlink(&nowhere, &dangling).expect("symlink");
        assert!(ensure_private_dir(&dangling).is_err());
        assert!(fs::symlink_metadata(&nowhere).is_err());
    }

    #[test]
    fn private_dir_refuses_a_file_in_its_place() {
        let temp = private_temp();
        let file = temp.path().join("file");
        fs::write(&file, "x").expect("write");
        assert!(ensure_private_dir(&file).is_err());
    }

    #[test]
    fn private_dir_refuses_a_loose_mode_without_changing_it() {
        let temp = private_temp();

        // Any group or other bit is refused with the fix, and the mode is
        // left as it was: the refusal never chmods.
        for loose in [0o750, 0o710, 0o701, 0o707, 0o755, 0o777] {
            let dir = temp.path().join(format!("loose-{loose:o}"));
            fs::create_dir(&dir).expect("mkdir");
            chmod(&dir, loose);
            let err = ensure_private_dir(&dir).expect_err("loose dir is refused");
            assert!(format!("{err:#}").contains("chmod 700"), "{err:#}");
            assert_eq!(mode(&dir), loose);
        }
    }

    #[test]
    fn temp_file_is_0600_before_any_byte_is_in_it() {
        let temp = private_temp();

        // The mode is set by the call that creates the file, not after.
        let probe = temp.path().join(".probe.tmp");
        let file = create_private_temp(&probe).expect("created");
        assert_eq!(file.metadata().expect("stat").len(), 0);
        assert_eq!(mode(&probe), 0o600);
    }

    #[test]
    fn temp_name_is_hidden_beside_its_file() {
        // A leading dot hides the temp name, and a name that already starts
        // with one gets no second.
        for (file, prefix) in [("device.key", ".device.key."), (".sweepky", ".sweepky.")] {
            let temp = temp_path_beside(&Path::new("/dir").join(file)).expect("a name");
            assert_eq!(temp.parent(), Some(Path::new("/dir")), "{file}");
            let name = temp
                .file_name()
                .and_then(|name| name.to_str())
                .expect("UTF-8 name");
            assert!(name.starts_with(prefix), "{name}");
            assert!(name.ends_with(".tmp"), "{name}");
        }
    }

    #[test]
    fn new_file_is_written_0600_leaving_no_temp_file() {
        let temp = private_temp();
        let target = temp.path().join("device.key");

        write_private_file(&target, b"first").expect("written");
        assert_eq!(mode(&target), 0o600);
        assert_eq!(fs::read(&target).expect("read"), b"first");
        assert_eq!(entries(temp.path()), ["device.key"]);
    }

    #[test]
    fn existing_file_is_replaced_by_rename_not_rewritten() {
        let temp = private_temp();
        let target = temp.path().join("device.key");
        write_private_file(&target, b"first").expect("written");

        // An existing file, here a loose 0644 one, is replaced as a whole by
        // the rename: the path now names a new 0600 file, while a handle
        // opened on the old file still reads the old bytes, so nothing was
        // rewritten in place.
        chmod(&target, 0o644);
        let old_inode = fs::symlink_metadata(&target).expect("stat").ino();
        let mut old = File::open(&target).expect("open old");
        write_private_file(&target, b"second").expect("replaced");
        assert_eq!(fs::read(&target).expect("read"), b"second");
        assert_eq!(mode(&target), 0o600);
        assert_ne!(
            fs::symlink_metadata(&target).expect("stat").ino(),
            old_inode
        );
        let mut old_bytes = Vec::new();
        old.read_to_end(&mut old_bytes).expect("read old");
        assert_eq!(old_bytes, b"first");
        assert_eq!(entries(temp.path()), ["device.key"]);
    }

    #[test]
    fn directory_sync_never_follows_a_link() {
        let temp = private_temp();
        let real = temp.path().join("real");
        ensure_private_dir(&real).expect("created");
        fs::write(real.join("login.json"), "{}").expect("write");

        // The directory itself syncs.
        sync_parent(&real.join("login.json")).expect("a real directory syncs");

        // A link in the directory's place, to a real directory or to
        // nothing, is refused rather than followed.
        let link = temp.path().join("link");
        symlink(&real, &link).expect("symlink");
        let dangling = temp.path().join("dangling");
        symlink(temp.path().join("nowhere"), &dangling).expect("symlink");
        for dir in [&link, &dangling] {
            let err = sync_parent(&dir.join("login.json")).expect_err("a link is refused");
            assert!(format!("{err:#}").contains("symbolic link"), "{err:#}");
        }

        // A directory that is not there is an error, not a panic.
        let gone = temp.path().join("gone").join("login.json");
        let err = sync_parent(&gone).expect_err("a missing directory is refused");
        assert!(format!("{err:#}").contains("is gone"), "{err:#}");
    }

    #[test]
    fn bare_file_name_is_in_the_current_directory() {
        // `Path::parent` gives a bare name an empty parent, which is the
        // current directory; only a path with no parent at all is an error.
        for (path, parent) in [("login.json", "."), ("/dir/login.json", "/dir")] {
            let found = parent_dir(Path::new(path)).expect("a parent");
            assert_eq!(found, Path::new(parent), "{path}");
        }
        assert!(parent_dir(Path::new("/")).is_err());
    }

    #[test]
    fn failed_write_removes_its_temp_file() {
        let temp = private_temp();

        // A write that fails after the temp file exists (here the rename,
        // onto a directory) removes the temp file and leaves the target as
        // it was.
        let blocked = temp.path().join("blocked");
        fs::create_dir(&blocked).expect("mkdir");
        let temp_file = temp.path().join(".blocked.tmp");
        assert!(replace_with(&temp_file, &blocked, b"never").is_err());
        assert!(fs::symlink_metadata(&temp_file).is_err(), "temp file left");
        assert!(fs::symlink_metadata(&blocked).expect("exists").is_dir());
        assert_eq!(entries(temp.path()), ["blocked"]);
    }

    #[test]
    fn write_and_read_refuse_a_symlink() {
        let temp = private_temp();
        let dir = temp.path();
        let outside = dir.join("outside");
        fs::write(&outside, "not yours").expect("write");
        chmod(&outside, 0o600);

        // A link to a private regular file: neither written nor read, and
        // the file it points at is untouched.
        let link = dir.join("link.key");
        symlink(&outside, &link).expect("symlink");
        assert!(write_private_file(&link, b"secret").is_err());
        assert!(read_private_file(&link, 1024).is_err());
        assert_eq!(fs::read(&outside).expect("read"), b"not yours");
        assert!(
            fs::symlink_metadata(&link)
                .expect("still there")
                .is_symlink()
        );
        // The refused write left no temp file behind.
        assert_eq!(entries(dir), ["link.key", "outside"]);
    }

    #[test]
    fn write_and_read_refuse_a_dangling_symlink() {
        let temp = private_temp();
        let dir = temp.path();

        // A dangling link is not "missing": reading it is an error, not
        // `None`, and writing creates nothing where it points.
        let nowhere = dir.join("nowhere");
        let dangling = dir.join("dangling.key");
        symlink(&nowhere, &dangling).expect("symlink");
        assert!(write_private_file(&dangling, b"secret").is_err());
        assert!(read_private_file(&dangling, 1024).is_err());
        assert!(fs::symlink_metadata(&nowhere).is_err());
        assert_eq!(entries(dir), ["dangling.key"]);
    }

    #[test]
    fn write_and_read_refuse_special_files() {
        let temp = private_temp();
        let dir = temp.path();

        // Not a regular file: a directory and a Unix socket.
        let subdir = dir.join("subdir");
        fs::create_dir(&subdir).expect("mkdir");
        let socket_path = dir.join("socket");
        let _socket = UnixListener::bind(&socket_path).expect("bind");
        for special in [&subdir, &socket_path] {
            assert!(
                write_private_file(special, b"secret").is_err(),
                "{}",
                special.display()
            );
            assert!(
                read_private_file(special, 1024).is_err(),
                "{}",
                special.display()
            );
        }
        // The refused writes left no temp file behind.
        assert_eq!(entries(dir), ["socket", "subdir"]);
    }

    #[test]
    fn private_file_reads_back_into_a_zeroizing_buffer() {
        let temp = private_temp();
        let path = temp.path().join("login.json");
        write_private_file(&path, b"{}").expect("written");

        // The buffer zeroes itself on drop (the type annotation is the
        // check).
        let bytes: Zeroizing<Vec<u8>> = read_private_file(&path, 1024)
            .expect("readable")
            .expect("present");
        assert_eq!(bytes.as_slice(), b"{}");
    }

    #[test]
    fn read_refuses_group_or_world_accessible_file() {
        let temp = private_temp();
        let path = temp.path().join("login.json");
        write_private_file(&path, b"{}").expect("written");

        // Any group or other bit is refused, with the fix.
        for loose in [0o640, 0o620, 0o610, 0o604, 0o602, 0o601, 0o644, 0o666] {
            chmod(&path, loose);
            let err = read_private_file(&path, 1024).expect_err("loose file is refused");
            assert!(
                format!("{err:#}").contains("chmod 600"),
                "{loose:o}: {err:#}"
            );
        }

        // The mode is checked before the file is opened: with the owner's
        // read bit off, opening would fail with "permission denied", yet the
        // error is the mode refusal.
        chmod(&path, 0o240);
        let err = read_private_file(&path, 1024).expect_err("refused");
        assert!(format!("{err:#}").contains("chmod 600"), "{err:#}");
    }

    #[test]
    fn read_refuses_file_over_cap() {
        let temp = private_temp();
        let path = temp.path().join("installs.json");
        write_private_file(&path, b"0123456789").expect("written");

        // At the cap is fine; one byte over is refused.
        let bytes = read_private_file(&path, 10)
            .expect("at the cap")
            .expect("present");
        assert_eq!(bytes.as_slice(), b"0123456789");
        let err = read_private_file(&path, 9).expect_err("over the cap");
        assert!(format!("{err:#}").contains("larger than"), "{err:#}");

        // The size is checked before the file is opened: with the owner's
        // read bit off, opening would fail, yet the error is the size.
        chmod(&path, 0o200);
        let err = read_private_file(&path, 9).expect_err("over the cap");
        assert!(format!("{err:#}").contains("larger than"), "{err:#}");
    }

    #[test]
    fn empty_file_reads_as_an_empty_buffer() {
        let temp = private_temp();
        let empty = temp.path().join("empty");
        write_private_file(&empty, b"").expect("written");
        let bytes = read_private_file(&empty, 0)
            .expect("readable")
            .expect("present");
        assert!(bytes.is_empty());
    }

    #[test]
    fn missing_file_reads_as_none() {
        let temp = private_temp();
        let path = temp.path().join("device.key");
        assert!(read_private_file(&path, 1024).expect("no error").is_none());
    }

    #[test]
    fn remove_succeeds_whether_or_not_the_file_is_there() {
        let temp = private_temp();
        let path = temp.path().join("device.key");

        // Nothing there: removing it succeeds.
        remove_private_file(&path).expect("missing is fine");

        // A file there is removed, and removing it again still succeeds.
        write_private_file(&path, b"key").expect("written");
        remove_private_file(&path).expect("removed");
        assert!(fs::symlink_metadata(&path).is_err());
        remove_private_file(&path).expect("and again");
    }
}
