//! The passphrase that wraps this install's secret files, and the one way
//! every secret file is written and read.
//!
//! A dedicated identity's key file and this install's `device.key` may be
//! wrapped with a passphrase (`login --passphrase-file`). So that each is
//! written and read one way, every command goes through:
//!
//! - [`Passphrase`], read from `--passphrase-file` by
//!   [`Passphrase::from_file`]: one line of at most
//!   [`MAX_PASSPHRASE_BYTES`], kept in a [`SecretString`] and never printed;
//! - [`write_secret_file`], which writes a secret file through
//!   [`crate::private_fs`] (0600, a temp file then a rename), wrapped when a
//!   passphrase is given;
//! - [`open_secret_file`], which reads one back: a file whose first bytes
//!   are an age header is unwrapped with the passphrase (core's
//!   `unwrap_with_passphrase`, which bounds the input and the scrypt work),
//!   and a wrapped file read without one is a [`NeedsPassphrase`] error that
//!   says how to give it.
//!
//! The cryptography is sweepky-core's. This module needs only core and
//! [`crate::private_fs`], so the modules that own the secret files'
//! formats (`identity`, `state`, `device`) read and write through it without
//! depending on `session`, which itself depends on them.

use std::fmt;
use std::fs::{File, Metadata};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, anyhow, bail};
use sweepky_core::{
    SecretString, WRITE_WORK_FACTOR, WorkFactor, Zeroizing, looks_wrapped, unwrap_with_passphrase,
    wrap_with_passphrase,
};

use crate::private_fs::{loose_permissions, read_up_to_cap, write_private_file};

/// The longest passphrase `--passphrase-file` takes: 1 KiB, its line ending
/// not counted. P2a's choice: far more than any passphrase needs, and a cap
/// on what is read from a pipe.
pub(crate) const MAX_PASSPHRASE_BYTES: usize = 1024;

/// How many bytes are read from `--passphrase-file` at most: the longest
/// passphrase, a `\r\n` after it, and one byte more, which is there only
/// when the file is too long.
const PASSPHRASE_READ_CAP: usize = MAX_PASSPHRASE_BYTES + 3;

/// The passphrase that wraps this install's secret files, from
/// `--passphrase-file`.
///
/// `login` wraps the identity file and `device.key` it creates with it, and
/// every command that reads a wrapped one unwraps it with it. The text lives
/// only in a [`SecretString`], which wipes it when dropped, and the type has
/// no `Debug`, `Display`, `Clone`, `PartialEq` or serde impls (checked at
/// compile time), so it cannot be printed, copied or compared by accident.
///
/// It also carries the work factor its wraps are written with, always
/// sweepky-core's `WRITE_WORK_FACTOR` (18) outside the tests, which wrap at
/// a low one to stay fast. The field is private and only the test
/// constructor can set another, so the binary never writes a weaker file.
pub struct Passphrase {
    secret: SecretString,
    write_work_factor: WorkFactor,
}

impl Passphrase {
    /// Reads the passphrase from the file at `path`, as `--passphrase-file`
    /// names it.
    ///
    /// The file holds one line: the passphrase, then optionally `\n` or
    /// `\r\n`, and nothing after. The passphrase is 1 to 1024 bytes of UTF-8
    /// (age's scrypt takes text), kept exactly, spaces included.
    ///
    /// The file may be a pipe, which is what process substitution gives
    /// (`--passphrase-file <(pass show sweepky)`): that keeps the passphrase
    /// out of the argument list, the shell history and the disk, and leaves
    /// standard input free. A regular file is refused when other users may
    /// read or write it, as ssh refuses a loose key; a directory is refused.
    /// At most 1027 bytes are read (the longest passphrase, a `\r\n` and one
    /// byte that shows the file is too long), into a wiped buffer that never
    /// grows.
    ///
    /// No error quotes the content; each names `path`, the user's own
    /// argument.
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let secret = read_passphrase_file(path).with_context(|| {
            format!(
                "could not read the passphrase from --passphrase-file {}",
                path.display()
            )
        })?;
        Ok(Self {
            secret,
            write_work_factor: WRITE_WORK_FACTOR,
        })
    }

    /// A passphrase of `text` that wraps at work factor 10 (1 MiB of memory,
    /// milliseconds of work), for tests that cannot wait for 18.
    /// `cfg(test)`: not in the binary.
    #[cfg(test)]
    pub(crate) fn for_tests(text: &str) -> Self {
        Self {
            secret: SecretString::from(text),
            write_work_factor: WorkFactor::new(10).expect("10 is in range"),
        }
    }

    /// The passphrase itself, lent out for age.
    pub(crate) fn secret(&self) -> &SecretString {
        &self.secret
    }

    /// `plaintext`, a secret file's content, wrapped with this passphrase:
    /// binary age v1 to one scrypt recipient at this passphrase's write work
    /// factor. Core's error is fixed text.
    pub(crate) fn wrap(&self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        wrap_with_passphrase(plaintext, &self.secret, self.write_work_factor)
            .context("could not wrap the file with the passphrase from --passphrase-file")
    }
}

/// Opens and reads the file `--passphrase-file` names: the checks of
/// [`Passphrase::from_file`], whose context names the file.
fn read_passphrase_file(path: &Path) -> anyhow::Result<SecretString> {
    // `File::open` follows a symlink, unlike `private_fs`: process
    // substitution's `/dev/fd/63` is one on Linux, pointing at the pipe. The
    // path is the user's own choice and is only read, never written.
    // An `io::Error` prints the system's reason, never the path.
    let mut file = File::open(path).map_err(|error| anyhow!("could not open it ({error})"))?;
    refuse_directory_or_loose_file(&file.metadata()?, path)?;
    // The read buffer is wiped when dropped and never grows, so no
    // reallocation leaves an unwiped copy of the passphrase behind.
    let bytes = read_up_to_cap(&mut file, PASSPHRASE_READ_CAP)
        .map_err(|error| anyhow!("could not read it ({error})"))?;
    passphrase_from_bytes(&bytes)
}

/// Refuses what `--passphrase-file` must not name, going by `meta`: a
/// directory, and a regular file that other users may read or write, as ssh
/// refuses a loose key. `path` is for the `chmod` that fixes it.
fn refuse_directory_or_loose_file(meta: &Metadata, path: &Path) -> anyhow::Result<()> {
    if meta.is_dir() {
        bail!("it is a directory, not a file holding the passphrase");
    }
    // Only a regular file has a mode worth checking: a pipe from process
    // substitution belongs to this user and lives only as long as the
    // command.
    if !meta.is_file() {
        return Ok(());
    }
    if let Some(mode) = loose_permissions(meta) {
        bail!(
            "other users may read or write it (mode {mode:03o}), and Sweepky refuses a loose \
             passphrase file as ssh refuses a loose key; run `chmod 600 {}`, or pass the \
             passphrase through a pipe such as <(pass show sweepky)",
            path.display()
        );
    }
    Ok(())
}

/// The passphrase in `bytes`, what was read from `--passphrase-file`: one
/// line, its `\n` or `\r\n` removed. Every message is fixed text.
fn passphrase_from_bytes(bytes: &[u8]) -> anyhow::Result<SecretString> {
    // `strip_suffix` is `None` when the bytes do not end that way; each step
    // borrows a shorter slice of the same buffer, copying nothing.
    let line = match bytes.strip_suffix(b"\n") {
        Some(line) => line.strip_suffix(b"\r").unwrap_or(line),
        None => bytes,
    };
    if line.contains(&b'\n') {
        bail!(
            "it holds more than one line; Sweepky reads a passphrase file of exactly one line \
             (for a pass entry with notes, use <(pass show sweepky | head -n 1))"
        );
    }
    if line.is_empty() {
        bail!("the passphrase is empty");
    }
    if line.len() > MAX_PASSPHRASE_BYTES {
        bail!("the passphrase is longer than {MAX_PASSPHRASE_BYTES} bytes");
    }
    // `from_utf8` borrows the bytes as a `&str`, copying nothing; its error,
    // which says where the bad byte is, is dropped for fixed text.
    let Ok(text) = std::str::from_utf8(line) else {
        bail!("the passphrase is not UTF-8 text");
    };
    // One copy, into a `SecretString`, made at exactly the text's length, so
    // turning it into the boxed `str` a `SecretString` holds does not
    // reallocate it and leave an unwiped copy behind. The buffer it came
    // from is wiped when the caller drops it.
    Ok(SecretString::from(text))
}

/// The error for a wrapped secret file read without `--passphrase-file`.
///
/// A type of its own, not only a message, so a caller can tell it apart
/// with `error.is::<NeedsPassphrase>()`: `login` then says it changed
/// nothing, rather than pointing at a backup as it does for a damaged file.
/// It holds the file's path, the user's own, and nothing secret.
#[derive(Debug)]
pub(crate) struct NeedsPassphrase {
    path: PathBuf,
}

impl fmt::Display for NeedsPassphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} is wrapped with a passphrase: give it with --passphrase-file <file>, such as \
             --passphrase-file <(pass show sweepky), which keeps it out of the argument list and \
             off the disk",
            self.path.display()
        )
    }
}

/// Makes it an error type, so `anyhow` takes it as one and can hand it back
/// by type. `Display` and `Debug` are all the trait needs.
impl std::error::Error for NeedsPassphrase {}

/// Writes `plaintext`, the content of a secret file, to `path` through
/// [`crate::private_fs`] (0600, a temp file then a rename): wrapped with
/// `passphrase` when there is one, as it is otherwise. The caller has made
/// the directory.
pub(crate) fn write_secret_file(
    path: &Path,
    plaintext: &[u8],
    passphrase: Option<&Passphrase>,
) -> anyhow::Result<()> {
    match passphrase {
        Some(passphrase) => write_private_file(path, &passphrase.wrap(plaintext)?),
        None => write_private_file(path, plaintext),
    }
}

/// The plain content of the secret file at `path`, given `stored`, the
/// bytes read from it.
///
/// A file whose first bytes are an age header (core's `looks_wrapped`) is
/// wrapped: it is unwrapped with `passphrase`, which bounds the input and
/// the scrypt work before age does any, and without one it is a
/// [`NeedsPassphrase`] error. Any other file is plain and comes back as it
/// is. `stored` is taken by value, so a plain file's buffer moves out
/// unchanged, with no copy, and a wrapped file's is wiped once unwrapped.
pub(crate) fn open_secret_file(
    path: &Path,
    stored: Zeroizing<Vec<u8>>,
    passphrase: Option<&Passphrase>,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    if !looks_wrapped(&stored) {
        return Ok(stored);
    }
    let Some(passphrase) = passphrase else {
        return Err(NeedsPassphrase {
            path: path.to_path_buf(),
        }
        .into());
    };
    // Core's `PassphraseError` holds no data, so it goes in the chain as it
    // is, after the file it is about.
    unwrap_with_passphrase(&stored, passphrase.secret()).with_context(|| {
        format!(
            "could not unwrap {} with the passphrase from --passphrase-file",
            path.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use sweepky_core::{ExposeSecret, MAX_WRAPPED_BYTES, Zeroizing, unwrap_with_passphrase};

    use super::{
        MAX_PASSPHRASE_BYTES, NeedsPassphrase, Passphrase, open_secret_file, write_secret_file,
    };
    use crate::private_fs::read_private_file;
    use crate::test_support::{TEST_PASSPHRASE, chmod, contains_bytes, mode, private_temp};

    /// Writes `bytes` to `name` in `dir` as a 0600 file, and returns its path.
    fn write_passphrase_file(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, bytes).expect("write");
        chmod(&path, 0o600);
        path
    }

    /// The bytes of the secret file at `path`, read as the CLI reads one.
    fn read_stored(path: &Path) -> Zeroizing<Vec<u8>> {
        read_private_file(path, MAX_WRAPPED_BYTES)
            .expect("reads")
            .expect("there")
    }

    /// What `Passphrase::from_file` reads from a file holding `bytes`, or its
    /// whole error chain.
    fn read_passphrase(bytes: &[u8]) -> Result<String, String> {
        let temp = private_temp();
        let path = write_passphrase_file(temp.path(), "passphrase", bytes);
        Passphrase::from_file(&path)
            .map(|passphrase| passphrase.secret().expose_secret().to_owned())
            .map_err(|error| format!("{error:#}"))
    }

    #[test]
    fn passphrase_file_is_one_line_of_at_most_1_kib() {
        // One line, with its `\n` or `\r\n` stripped, or none at all.
        // Spaces are part of a passphrase and stay.
        for (bytes, expected) in [
            (&b"synthetic phrase\n"[..], "synthetic phrase"),
            (b"synthetic phrase\r\n", "synthetic phrase"),
            (b"synthetic phrase", "synthetic phrase"),
            (b"  spaced out  \n", "  spaced out  "),
        ] {
            assert_eq!(read_passphrase(bytes).as_deref(), Ok(expected), "{bytes:?}");
        }

        // 1 KiB exactly, with or without its line ending, and no more.
        // `~`, which no temp path holds, so the check below that the error
        // quotes none of it cannot trip on the path the error names.
        let longest = "~".repeat(MAX_PASSPHRASE_BYTES);
        assert_eq!(
            read_passphrase(longest.as_bytes()).as_deref(),
            Ok(longest.as_str())
        );
        assert_eq!(
            read_passphrase(format!("{longest}\r\n").as_bytes()).as_deref(),
            Ok(longest.as_str())
        );
        for too_long in [
            format!("{longest}~"),
            format!("{longest}~\n"),
            "~".repeat(5000),
        ] {
            let error = read_passphrase(too_long.as_bytes()).expect_err("refused");
            assert!(error.contains("1024 bytes"), "{error}");
            assert!(!error.contains('~'), "{error}");
        }
    }

    #[test]
    fn empty_passphrase_is_refused() {
        for empty in [&b""[..], b"\n", b"\r\n"] {
            let error = read_passphrase(empty).expect_err("refused");
            assert!(error.contains("empty"), "{empty:?}: {error}");
        }
    }

    #[test]
    fn passphrase_file_refusals_never_quote_it() {
        // More than one line (as from a pass entry with notes), and bytes
        // that are not text: refused with fixed words, the content unquoted.
        for (bytes, reason) in [
            (&b"synthetic first\nsynthetic notes\n"[..], "one line"),
            (b"synthetic first\n\n", "one line"),
            (b"synthetic \xff\xfe bytes\n", "UTF-8"),
        ] {
            let error = read_passphrase(bytes).expect_err("refused");
            assert!(error.contains(reason), "{error}");
            assert!(!error.contains("synthetic"), "{error}");
        }

        let temp = private_temp();
        // A file other users can read is refused, as ssh refuses a loose key,
        // with the chmod that fixes it.
        let loose = write_passphrase_file(temp.path(), "loose", b"synthetic loose\n");
        chmod(&loose, 0o644);
        let error = format!(
            "{:#}",
            Passphrase::from_file(&loose).err().expect("refused")
        );
        assert!(error.contains("chmod 600"), "{error}");
        assert!(!error.contains("synthetic"), "{error}");
        // A directory, and nothing at all: the path is named, as the user
        // typed it.
        for path in [temp.path().to_path_buf(), temp.path().join("missing")] {
            let error = format!("{:#}", Passphrase::from_file(&path).err().expect("refused"));
            assert!(error.contains(&path.display().to_string()), "{error}");
            assert!(error.contains("--passphrase-file"), "{error}");
        }
    }

    #[test]
    fn the_passphrase_lives_only_in_secret_types() {
        // No way to print, serialize, copy or compare it, checked when the
        // test compiles. Its text is reached only through the
        // `SecretString` it holds, whose `Debug` is redacted.
        crate::test_support::assert_not_impl_any!(
            Passphrase: std::fmt::Debug,
            std::fmt::Display,
            serde::Serialize,
            serde::de::DeserializeOwned,
            Clone,
            PartialEq,
        );
        let passphrase = Passphrase::for_tests(TEST_PASSPHRASE);
        assert!(!format!("{:?}", passphrase.secret()).contains(TEST_PASSPHRASE));
    }

    #[test]
    fn secret_files_are_read_through_one_unwrap_path() {
        let temp = private_temp();
        let path = temp.path().join("secret.key");
        let content = b"synthetic secret file\n";
        let passphrase = Passphrase::for_tests(TEST_PASSPHRASE);

        // Without a passphrase the file is written as it is.
        write_secret_file(&path, content, None).expect("writes");
        assert_eq!(mode(&path), 0o600);
        assert_eq!(fs::read(&path).expect("read"), content);
        let stored = read_stored(&path);
        let plain = open_secret_file(&path, stored, Some(&passphrase)).expect("plain");
        assert_eq!(plain.as_slice(), content);

        // With one it is written wrapped, 0600, through the same private
        // file writer, and read back unwrapped.
        write_secret_file(&path, content, Some(&passphrase)).expect("writes");
        assert_eq!(mode(&path), 0o600);
        let raw = fs::read(&path).expect("read");
        assert!(raw.starts_with(b"age-encryption.org/v1\n-> scrypt "));
        assert!(!contains_bytes(&raw, b"synthetic"));
        let plain = unwrap_with_passphrase(&raw, passphrase.secret()).expect("age reads it");
        assert_eq!(plain.as_slice(), content);
        let stored = read_stored(&path);
        let plain: Zeroizing<Vec<u8>> =
            open_secret_file(&path, stored, Some(&passphrase)).expect("unwraps");
        assert_eq!(plain.as_slice(), content);

        // Read without the passphrase: a typed error that names the file and
        // says how to give it.
        let stored = read_stored(&path);
        let error = open_secret_file(&path, stored, None).expect_err("refused");
        assert!(error.is::<NeedsPassphrase>(), "{error:#}");
        let shown = format!("{error:#}");
        for part in [
            path.display().to_string(),
            "--passphrase-file".to_owned(),
            "<(pass show sweepky)".to_owned(),
        ] {
            assert!(shown.contains(&part), "{part:?} missing from: {shown}");
        }

        // With the wrong one: refused, quoting neither passphrase.
        let wrong = Passphrase::for_tests("synthetic wrong guess");
        let stored = read_stored(&path);
        let shown = format!(
            "{:#}",
            open_secret_file(&path, stored, Some(&wrong)).expect_err("refused")
        );
        assert!(shown.contains("does not open"), "{shown}");
        assert!(!shown.contains("synthetic"), "{shown}");
    }
}
