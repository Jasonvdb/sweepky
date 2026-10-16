//! The local material behind `login --identity <name>` (login option B), and
//! the rules that refuse anyone else's secret.
//!
//! - [`IdentityName`], the checked name: 1 to 32 characters of `a-z`, `0-9`,
//!   `-` and `_`, starting with a letter.
//! - [`IdentitySecret`], a dedicated identity's 32-byte secret, and its file,
//!   `identities/<name>.key`, in Sweepky's own format, which is never a Pubky
//!   recovery file:
//!
//!   ```text
//!   sweepky-identity/v1
//!   <64 lower-case hex digits>
//!   ```
//!
//!   each line ending in `\n`, and nothing before, between or after.
//! - [`IdentityMeta`], the identity's public details in
//!   `identities/<name>.json`: its name, pubky, homeserver and whether it
//!   has signed up. It is a cache `login` can rebuild; `<name>.key` alone is
//!   the Sweepky identity file.
//! - [`refuse_secret_material`] and [`Refusal`]: the classifier that turns
//!   away a Pubky recovery file, a raw key and a recovery phrase, each with a
//!   fixed one-line reason.
//! - [`IdentityName::from_arg`], which reads the `--identity` argument: a
//!   name when it is a valid name, and otherwise a file or text to classify,
//!   never imported.
//!
//! Why refuse at all (03, "Two ways to log in"): an identity's secret
//! controls that identity forever, including moving it to another
//! homeserver, and this CLI runs beside agents that read untrusted code. Ring
//! exists to keep that secret off the laptop, so Sweepky only ever holds the
//! secret of a dedicated identity it created itself.

use std::fmt;
use std::fs::{self, File};
use std::io::{self, ErrorKind, Read};
// `MetadataExt` adds `.dev()` and `.ino()`, the device and inode numbers, to
// `Metadata`. A trait's methods can only be called while it is in scope.
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context as _, anyhow, bail};
use pubky::Keypair;
use serde::{Deserialize, Serialize};
use sweepky_core::{Pubky, RecordError, SchemaVersion, UnknownFields, Zeroizing};

/// The most Sweepky reads of a file that should hold an identity: the file
/// an `--identity` argument names, and (for `login`) an identity file read
/// back. An identity file is 85 bytes and a recovery file under 100; the
/// rest of the room lets the classifier see what else someone put there.
pub(crate) const MAX_IDENTITY_FILE_BYTES: usize = 4096;

// ---------------------------------------------------------------------------
// The name.

/// What `--identity <file>` gets when the file is not a recognised secret:
/// still not imported.
const NOT_IMPORTED: &str = "Sweepky does not import identities; --identity takes a name, and \
                            creates a new identity under it the first time";

/// What the `--identity` argument is meant to be, said before the reason a
/// value is not a valid name.
const NAME_EXPECTED: &str = "--identity takes the name of a Sweepky identity, new or existing";

/// The name of a dedicated identity, as in `login --identity <name>`, and the
/// stem of its files in `config/identities/`.
///
/// 1 to 32 characters of `a-z`, `0-9`, `-` and `_`, the first a letter, P2a's
/// choice. So a name is always exactly one path segment: no `/`, never `.` or
/// `..`, no hidden file, no leading `-`, nothing a terminal would interpret.
/// Lower case only, because macOS filesystems ignore case by default and
/// `Throwaway` and `throwaway` would be one file there. At most 32
/// characters, so no raw key (64 hex digits, 43 of base64, 52 of z-base32)
/// and no recovery phrase (it has spaces) is ever a valid name, and
/// `IdentityName::from_arg` can treat every valid name as a name without
/// looking further.
///
/// A `String` newtype whose field is private: the only ways to get one are
/// [`FromStr`] (`"name".parse()`) and deserializing, and both run the check,
/// so holding an `IdentityName` is proof the check passed. `try_from =
/// "String"` tells serde to read a string and pass it to `TryFrom<String>`
/// below; the derived `Serialize` writes a one-field tuple struct as its
/// field, a plain JSON string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct IdentityName(String);

impl IdentityName {
    /// The longest name accepted, in bytes (every allowed character is one
    /// byte).
    pub const MAX_LEN: usize = 32;

    /// The name as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Reads the `--identity` argument `value`, which must be a name. Only
    /// when it is not a valid name does it look further, and then only to
    /// say why it is refused:
    ///
    /// 1. A valid name is a name, and nothing else: `read_file` is not
    ///    called, so a stray file of that name in the working directory is
    ///    never read in its place.
    /// 2. Otherwise, when `value` names a regular file, `read_file` reads at
    ///    most [`MAX_IDENTITY_FILE_BYTES`] of it and the bytes are
    ///    classified: a recovery file, raw key or recovery phrase gets its
    ///    [`Refusal`], and any other file [`NOT_IMPORTED`]. So
    ///    `--identity <path to a recovery file>` gets the recovery reason.
    /// 3. Otherwise the text itself is classified, for a raw key or a phrase
    ///    pasted in place of a name, and failing that the name's own error
    ///    is returned.
    ///
    /// No error quotes `value` or the file: either may be a secret. A
    /// [`Refusal`] comes back as the error itself, so a caller can
    /// `downcast_ref::<Refusal>()` to tell it apart.
    ///
    /// `read_file` is a parameter so the tests can watch it, or stand in
    /// for the working directory; the command passes [`read_argument_file`].
    /// `F: FnOnce(&Path) -> …` accepts any function or closure called at
    /// most once with a path; `Option` is `None` when no regular file is
    /// there.
    pub(crate) fn from_arg<F>(value: &str, read_file: F) -> anyhow::Result<Self>
    where
        F: FnOnce(&Path) -> io::Result<Option<Zeroizing<Vec<u8>>>>,
    {
        value
            .parse::<Self>()
            .map_err(|name_error| not_a_name(value, name_error, read_file))
    }
}

/// The error for `value`, an `--identity` argument that failed the name
/// check with `name_error`: steps 2 and 3 of [`IdentityName::from_arg`].
fn not_a_name<F>(value: &str, name_error: anyhow::Error, read_file: F) -> anyhow::Error
where
    F: FnOnce(&Path) -> io::Result<Option<Zeroizing<Vec<u8>>>>,
{
    let read = read_file(Path::new(value));
    // `&read` borrows the result, so it is still there for the error check
    // below; `bytes` is then a `&Zeroizing<Vec<u8>>`, which the call reads
    // as a `&[u8]` through `Deref`.
    if let Ok(Some(bytes)) = &read {
        return refusal_or(bytes, NOT_IMPORTED);
    }
    if let Some(refusal) = refuse_secret_material(value.as_bytes()) {
        return refusal.into();
    }
    if let Err(err) = read {
        // An `io::Error` prints the system's reason ("permission denied"),
        // never the path, and `read_argument_file` makes its own with fixed
        // text.
        return anyhow!(
            "could not read the file --identity names ({err}); --identity takes a name, and \
             Sweepky does not import identities"
        );
    }
    name_error.context(NAME_EXPECTED)
}

impl FromStr for IdentityName {
    type Err = anyhow::Error;

    /// Checks the name. The messages are fixed text and never quote
    /// `value`: an argument that fails here may be a pasted secret.
    fn from_str(value: &str) -> anyhow::Result<Self> {
        // `bytes()` walks the UTF-8 bytes; every allowed character is ASCII,
        // so any byte of a multi-byte character fails the checks below.
        let Some(first) = value.bytes().next() else {
            bail!("an identity name cannot be empty");
        };
        if !first.is_ascii_lowercase() {
            bail!("an identity name starts with a lower-case letter, a to z");
        }
        if !value.bytes().all(is_name_byte) {
            bail!("an identity name has only lower-case letters, digits, '-' and '_'");
        }
        // Last, so the value is known to be ASCII here and its length in
        // bytes is its length in characters, the unit the message names.
        if value.len() > Self::MAX_LEN {
            bail!("an identity name is at most {} characters", Self::MAX_LEN);
        }
        Ok(Self(value.to_owned()))
    }
}

/// Whether `byte` may appear in an identity name.
fn is_name_byte(byte: u8) -> bool {
    matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_')
}

/// So `#[serde(try_from = "String")]` can call the same check.
impl TryFrom<String> for IdentityName {
    type Error = anyhow::Error;

    fn try_from(value: String) -> anyhow::Result<Self> {
        value.parse()
    }
}

impl fmt::Display for IdentityName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Reads the file an `--identity` argument names, for
/// [`IdentityName::from_arg`] to classify: at most
/// [`MAX_IDENTITY_FILE_BYTES`] from its start, into a buffer that wipes
/// itself.
///
/// `Ok(None)` when no regular file is there: nothing at the path, a path
/// that cannot name a file (a missing directory on the way, a name too long,
/// a NUL byte), or something else, such as a directory or a device, which is
/// never opened. A symlink is followed: this read only ever leads to a
/// refusal, never to an import, so reading through a link changes nothing,
/// and someone pointing `--identity` at a link to their recovery file should
/// still get the recovery reason.
///
/// Unlike `private_fs`, it does not refuse a file other users can read: a
/// recovery file someone downloaded is usually 0644, and the point is to
/// recognise it. Its errors never name the path.
pub(crate) fn read_argument_file(path: &Path) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    // `metadata` is `stat`: it follows a link and describes the target.
    let seen = match fs::metadata(path) {
        Ok(meta) => meta,
        Err(err) if names_no_file(&err) => return Ok(None),
        Err(err) => return Err(err),
    };
    if !seen.is_file() {
        return Ok(None);
    }
    // Were the file swapped for a FIFO between the `stat` and this `open`,
    // the open would wait for a writer. That needs someone who can write the
    // directory, and costs a hung command, not a secret, so it is left at
    // that rather than reaching for `O_NONBLOCK`, which std does not offer.
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.dev() != seen.dev() || opened.ino() != seen.ino() {
        return Err(io::Error::other(
            "the file changed while Sweepky was opening it; try again",
        ));
    }
    read_up_to_cap(&mut file).map(Some)
}

/// Whether `err`, from a `stat`, means no file can be at that path.
fn names_no_file(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::NotFound
            | ErrorKind::NotADirectory
            | ErrorKind::InvalidFilename
            | ErrorKind::InvalidInput
    )
}

/// Reads `file` up to [`MAX_IDENTITY_FILE_BYTES`] or its end, whichever
/// comes first.
fn read_up_to_cap(file: &mut File) -> io::Result<Zeroizing<Vec<u8>>> {
    // A zeroed buffer of exactly the cap, filled in place and never grown,
    // so the bytes are never copied into a bigger allocation and left
    // behind, unwiped, in the old one. `Zeroizing` wipes all of it, spare
    // capacity included, when the caller drops it.
    let mut bytes = Zeroizing::new(vec![0_u8; MAX_IDENTITY_FILE_BYTES]);
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

// ---------------------------------------------------------------------------
// The refusal rules.

/// Why some bytes were refused as an identity: they are, or look like,
/// another identity's secret, which Sweepky never imports.
///
/// Holds no data, so neither its `Display` nor its `Debug` can carry any of
/// the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// A Pubky recovery file: it starts with `pubky.org/recovery`, or the
    /// legacy `pkarr.org/recovery`, which the SDK still reads.
    RecoveryFile,
    /// A 32-byte secret or 64-byte keypair in hex, base64 or base64url, a
    /// 32-byte value in z-base32, or an age secret key
    /// (`AGE-SECRET-KEY-1…`).
    RawKey,
    /// 12, 15, 18, 21 or 24 words and nothing else: a recovery phrase.
    Mnemonic,
}

/// Why every [`Refusal`] is one, after the line that says what was found.
const WHY_REFUSED: &str = ", and Sweepky never imports one: an identity's secret controls that \
                           identity forever, and this CLI runs beside agents that read untrusted \
                           code. Use a dedicated identity (sweepky login --identity <name> creates \
                           one) or log in with Pubky Ring (sweepky login)";

impl fmt::Display for Refusal {
    /// One line: what the input looks like, then why it is refused and what
    /// to do instead.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RecoveryFile => "this is a Pubky recovery file",
            Self::RawKey => "this looks like a raw key",
            Self::Mnemonic => "this looks like a recovery phrase",
        })?;
        f.write_str(WHY_REFUSED)
    }
}

/// Makes a `Refusal` an error type, so `?` and `anyhow` take it as one. The
/// trait's methods all have defaults; `Display` and `Debug` are what it
/// needs.
impl std::error::Error for Refusal {}

/// The error for `bytes` that are not what the caller expected: their
/// [`Refusal`] when they hold another identity's secret, and the fixed
/// message `otherwise` when they hold nothing the classifier recognises.
fn refusal_or(bytes: &[u8], otherwise: &'static str) -> anyhow::Error {
    match refuse_secret_material(bytes) {
        // `into()` makes the `Refusal` the error itself, which `anyhow` can
        // hand back by type.
        Some(refusal) => refusal.into(),
        None => anyhow!(otherwise),
    }
}

/// The [`Refusal`] for `bytes`, or `None` when they look like none of
/// another identity's secrets.
///
/// Runs on the `--identity` argument, on the file it names, and on every
/// identity file read back that is not in Sweepky's format, so a recovery
/// file or key someone drops into `identities/` is refused by name too.
/// Each check is a shape, so it errs on the side of refusing: whatever it
/// sees has already failed to be a name or an identity file, so a false
/// match only changes the wording of a refusal.
///
/// - A recovery file: after any byte-order mark and leading whitespace, the
///   bytes start with one of the two first lines, in any case.
/// - A recovery phrase: the whole input is 12, 15, 18, 21 or 24 words of
///   letters (any script, so other wordlists count), at most 16 each.
/// - A raw key: any token of the input has a key's shape (see
///   [`Refusal::RawKey`]), so a key inside `KEY=…` or a JSON string counts.
pub(crate) fn refuse_secret_material(bytes: &[u8]) -> Option<Refusal> {
    if is_recovery_file(bytes) {
        Some(Refusal::RecoveryFile)
    } else if is_mnemonic(bytes) {
        Some(Refusal::Mnemonic)
    } else if holds_raw_key(bytes) {
        Some(Refusal::RawKey)
    } else {
        None
    }
}

/// The first lines a Pubky recovery file starts with, as the SDK checks them
/// (`pubky-common` 0.16.2, `recovery_file.rs`).
const RECOVERY_FILE_MARKERS: [&[u8]; 2] = [b"pubky.org/recovery", b"pkarr.org/recovery"];

/// The UTF-8 byte-order mark some editors put at the start of a file.
const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";

fn is_recovery_file(bytes: &[u8]) -> bool {
    let bytes = bytes
        .strip_prefix(UTF8_BOM)
        .unwrap_or(bytes)
        .trim_ascii_start();
    RECOVERY_FILE_MARKERS
        .iter()
        .any(|marker| starts_with_ignore_ascii_case(bytes, marker))
}

/// Whether `bytes` starts with `prefix`, ignoring the case of ASCII letters.
fn starts_with_ignore_ascii_case(bytes: &[u8], prefix: &[u8]) -> bool {
    // `get(..n)` is `None` when there are fewer than `n` bytes, where
    // `bytes[..n]` would panic.
    bytes
        .get(..prefix.len())
        .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
}

/// The word counts BIP-39 recovery phrases come in.
const MNEMONIC_WORD_COUNTS: [usize; 5] = [12, 15, 18, 21, 24];

/// The most words a phrase has, the largest of [`MNEMONIC_WORD_COUNTS`], so
/// counting can stop past it.
const MAX_MNEMONIC_WORDS: usize = 24;

/// The longest word counted as one of a phrase's; BIP-39's English words are
/// 3 to 8 letters.
const MAX_MNEMONIC_WORD_CHARS: usize = 16;

fn is_mnemonic(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let mut count = 0_usize;
    // `split_whitespace` splits on any Unicode whitespace, the ideographic
    // space that Japanese phrases use included, and skips empty pieces.
    for word in text.split_whitespace() {
        count += 1;
        // Stop early: a long text is no phrase, and this bounds the count.
        if count > MAX_MNEMONIC_WORDS || !is_mnemonic_word(word) {
            return false;
        }
    }
    MNEMONIC_WORD_COUNTS.contains(&count)
}

/// Whether `word` could be a phrase's: letters in any script, so other
/// wordlists count, and at most [`MAX_MNEMONIC_WORD_CHARS`] of them.
fn is_mnemonic_word(word: &str) -> bool {
    word.chars().count() <= MAX_MNEMONIC_WORD_CHARS && word.chars().all(char::is_alphabetic)
}

/// The prefix of an age secret key; bech32 is read in either case.
const AGE_SECRET_KEY_PREFIX: &[u8] = b"AGE-SECRET-KEY-";

/// The z-base32 alphabet, which a pubky and the SDK's keys are written in.
const Z32_ALPHABET: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

/// Whether any token of `bytes` has a raw key's shape.
///
/// One pass per alphabet, each splitting at every byte outside it, so a key
/// is found inside a path, after `KEY_NAME=` or in a JSON string. Base64
/// adds `+` and `/` to letters and digits; base64url, and the `-` of an age
/// key's prefix, add `-` and `_`; hex and z-base32 are letters and digits
/// alone. `=` is in none of them, so base64 padding splits off. A base64
/// key inside a path is missed when the key itself holds a `/`, because
/// nothing tells that `/` from the path's; the input is refused all the
/// same, only with another reason.
fn holds_raw_key(bytes: &[u8]) -> bool {
    tokens(bytes, b"+/").any(is_base64_key)
        || tokens(bytes, b"-_").any(|token| is_base64_key(token) || is_age_secret_key(token))
        || tokens(bytes, b"").any(|token| is_hex_key(token) || is_z32_key(token))
}

/// The runs of `bytes` made of ASCII letters, digits and the bytes in
/// `extra`. `split` with a closure yields the pieces between the bytes the
/// closure picks, empty ones included, which no check below matches.
/// `move` hands `extra` to the closure, which the iterator keeps.
fn tokens<'a>(bytes: &'a [u8], extra: &'a [u8]) -> impl Iterator<Item = &'a [u8]> {
    bytes.split(move |byte| !(byte.is_ascii_alphanumeric() || extra.contains(byte)))
}

fn is_age_secret_key(token: &[u8]) -> bool {
    token.len() > AGE_SECRET_KEY_PREFIX.len()
        && starts_with_ignore_ascii_case(token, AGE_SECRET_KEY_PREFIX)
}

/// 32 or 64 bytes in base64 or base64url without padding: 43 or 86
/// characters. [`tokens`] has already kept the token to one alphabet.
fn is_base64_key(token: &[u8]) -> bool {
    matches!(token.len(), 43 | 86)
}

/// 32 bytes (a secret) or 64 (a secret and its public key) in hex, either
/// case.
fn is_hex_key(token: &[u8]) -> bool {
    matches!(token.len(), 64 | 128) && token.iter().all(u8::is_ascii_hexdigit)
}

/// 32 bytes in z-base32: 52 characters, either case.
fn is_z32_key(token: &[u8]) -> bool {
    token.len() == 52
        && token
            .iter()
            .all(|byte| Z32_ALPHABET.contains(&byte.to_ascii_lowercase()))
}

// ---------------------------------------------------------------------------
// The secret and its file.

/// The first line of a Sweepky identity file, without its newline.
const IDENTITY_FILE_MARKER: &[u8] = b"sweepky-identity/v1";

/// What the first line of every version of the format starts with, so a
/// file from a later version gets its own message.
const IDENTITY_FILE_FAMILY: &[u8] = b"sweepky-identity/";

/// The secret's length: an Ed25519 seed.
const SECRET_BYTES: usize = 32;

/// The secret spelled in hex: two digits a byte.
const SECRET_HEX_DIGITS: usize = 2 * SECRET_BYTES;

/// A whole identity file: the marker line, the digits, and a newline after
/// each.
const IDENTITY_FILE_BYTES: usize = IDENTITY_FILE_MARKER.len() + 1 + SECRET_HEX_DIGITS + 1;

/// A file that starts with the marker line but is not exactly the format.
const MALFORMED: &str = "not a valid Sweepky identity file: it must be the line \
                         sweepky-identity/v1, then 64 lower-case hex digits and a newline, and \
                         nothing more";

/// A file from a version of the format this build does not read.
const OTHER_VERSION: &str = "a Sweepky identity file in a version this Sweepky does not read; \
                             use the Sweepky that wrote it, or a newer one";

/// A file that is neither the format nor a recognised secret.
const NOT_SWEEPKY: &str =
    "not a Sweepky identity file, and Sweepky does not import identities in any other format";

/// A dedicated identity's secret: the 32-byte Ed25519 seed its keypair comes
/// from.
///
/// The bytes live in a [`Zeroizing`] array, which overwrites them with zeros
/// when it is dropped, and the type has no `Debug`, `Display`, `Serialize`,
/// `Deserialize`, `Clone` or `PartialEq` (a test checks that at compile
/// time), so it cannot be printed, written out as JSON, copied around or
/// compared by accident. It is held as bytes rather than as a
/// [`Keypair`], because `Keypair` derives `Clone` and has a `Debug`; one is
/// made from the bytes when signing needs it ([`IdentitySecret::keypair`]).
pub(crate) struct IdentitySecret {
    secret: Zeroizing<[u8; SECRET_BYTES]>,
}

impl IdentitySecret {
    /// A new random secret, from the SDK's keypair generator (the operating
    /// system's random numbers).
    pub(crate) fn generate() -> Self {
        let keypair = Keypair::random();
        // `secret()` returns a plain `[u8; 32]` copy, so it moves into a
        // `Zeroizing` at once. A move is a byte copy the compiler may leave
        // behind on the stack, where nothing can wipe it: zeroizing is a
        // best effort in Rust, not a guarantee. `keypair` wipes its own copy
        // when it is dropped at the end of this function (ed25519-dalek's
        // `zeroize` feature is on in this build).
        Self {
            secret: Zeroizing::new(keypair.secret()),
        }
    }

    /// The identity's keypair, for signing up and signing in. It wipes
    /// itself when dropped, so drop it as soon as it has been used.
    pub(crate) fn keypair(&self) -> Keypair {
        // `&self.secret` is a `&Zeroizing<[u8; 32]>`; Rust turns it into the
        // `&[u8; 32]` the function asks for through `Deref` (a "deref
        // coercion"), without copying the bytes.
        Keypair::from_secret(&self.secret)
    }

    /// The identity's public key.
    pub(crate) fn pubky(&self) -> Pubky {
        Pubky::from_bytes(self.keypair().public_key().to_bytes())
    }

    /// The identity file's bytes: the marker line, then the secret as 64
    /// lower-case hex digits and a newline.
    ///
    /// The buffer is a `Zeroizing<Vec<u8>>` made with exactly the room the
    /// file needs, so the pushes below never make it reallocate, which
    /// would copy the secret into a new buffer and free the old one without
    /// wiping it.
    pub(crate) fn to_file_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(IDENTITY_FILE_BYTES));
        out.extend_from_slice(IDENTITY_FILE_MARKER);
        out.push(b'\n');
        for &byte in self.secret.iter() {
            out.push(hex_digit(byte >> 4));
            out.push(hex_digit(byte & 0x0f));
        }
        out.push(b'\n');
        out
    }

    /// Reads an identity file's bytes back.
    ///
    /// Only the exact format is read: the marker line, 64 lower-case hex
    /// digits and a newline, 85 bytes in all. A file that starts with the
    /// marker but differs anywhere (upper-case digits, a `\r`, a byte too
    /// many or too few) is [`MALFORMED`]; one from another version of the
    /// format is [`OTHER_VERSION`]; and anything else goes through
    /// [`refuse_secret_material`], so a recovery file or raw key dropped in
    /// as `<name>.key` gets its [`Refusal`], and the rest [`NOT_SWEEPKY`].
    /// Every message is fixed text.
    pub(crate) fn from_file_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if first_line(bytes) != IDENTITY_FILE_MARKER {
            return Err(not_an_identity_file(bytes));
        }
        // From here on the file says it is a v1 identity file, so every fault
        // is the same one.
        let Some(pairs) = secret_hex_pairs(bytes) else {
            bail!(MALFORMED);
        };
        let mut secret = Zeroizing::new([0_u8; SECRET_BYTES]);
        // `&mut secret` reaches the array inside through `DerefMut`, so the
        // digits are decoded straight into the buffer that wipes itself. On
        // the early return, `secret` is dropped and so wiped.
        if !decode_hex_pairs(pairs, &mut secret) {
            bail!(MALFORMED);
        }
        Ok(Self { secret })
    }
}

/// The first line of `bytes`, without its `\n` or a `\r` before that.
fn first_line(bytes: &[u8]) -> &[u8] {
    // `split` always yields at least one piece, the bytes up to the first
    // `\n` (all of them when there is none), so `unwrap_or` is never used;
    // it only saves a panic path.
    let line = bytes.split(|&byte| byte == b'\n').next().unwrap_or(bytes);
    line.strip_suffix(b"\r").unwrap_or(line)
}

/// The error for `bytes`, whose first line is not the v1 marker.
fn not_an_identity_file(bytes: &[u8]) -> anyhow::Error {
    if bytes.starts_with(IDENTITY_FILE_FAMILY) {
        return anyhow!(OTHER_VERSION);
    }
    refusal_or(bytes, NOT_SWEEPKY)
}

/// The secret's digits in a v1 identity file, as 32 pairs, one a byte:
/// everything between the marker line and the final newline. `None` when
/// the file is not framed exactly that way or the digits are not 64.
fn secret_hex_pairs(bytes: &[u8]) -> Option<&[[u8; 2]; SECRET_BYTES]> {
    // Each `strip_…` is `None` when the bytes are not there, and `?` on an
    // `Option` returns that `None` from the function at once.
    let digits = bytes
        .strip_prefix(IDENTITY_FILE_MARKER)?
        .strip_prefix(b"\n")?
        .strip_suffix(b"\n")?;
    // `as_chunks::<2>()` views the digits as pairs plus a remainder; the
    // pattern `(pairs, [])` matches only when the remainder is empty, so
    // when there is an even number of digits.
    let (pairs, []) = digits.as_chunks::<2>() else {
        return None;
    };
    // A slice converts to a reference to a fixed-size array only when its
    // length is exactly the array's, so this is the check for 32 pairs.
    pairs.try_into().ok()
}

/// Decodes `pairs`, each two lower-case hex digits, into `secret`, and says
/// whether every digit was one.
///
/// Every digit's check is folded into one mask and looked at once at the
/// end, so the work done does not depend on where a bad digit is. It fills
/// the caller's buffer rather than returning a new array, so the secret is
/// not moved, and so perhaps copied, on the way out.
fn decode_hex_pairs(pairs: &[[u8; 2]; SECRET_BYTES], secret: &mut [u8; SECRET_BYTES]) -> bool {
    let mut valid = 0xff_u8;
    for (byte, &[high, low]) in secret.iter_mut().zip(pairs) {
        let (high, high_ok) = hex_value(high);
        let (low, low_ok) = hex_value(low);
        *byte = (high << 4) | low;
        valid &= high_ok & low_ok;
    }
    valid == 0xff
}

/// The lower-case hex digit for `nibble`, a value from 0 to 15.
///
/// Written without a branch or a table lookup on the value, because the
/// value is part of a secret: how long a branch takes, or which part of a
/// table a lookup touched, can be measured by other code on the same machine,
/// and key decoders have leaked keys that way (Sieck et al., "Util::Lookup",
/// CCS 2021). The compiler could still add a branch, so this is a best
/// effort, not a proof. The digits for 10 to 15 sit 39 places after the
/// ones `b'0' + nibble` gives (`b'a'` is 97, `b'9' + 1` is 58), so the mask
/// adds 39 exactly when `nibble` is over 9.
fn hex_digit(nibble: u8) -> u8 {
    // `9 - nibble`, wrapping: 0 to 9 for a decimal digit, 250 to 255 (top
    // bit set) for 10 to 15. The top bit, spread to all eight, is the mask.
    let over_nine = (9_u8.wrapping_sub(nibble) >> 7) & 1;
    let mask = 0_u8.wrapping_sub(over_nine);
    // At most 48 + 15 + 39 = 102, so this cannot overflow.
    b'0' + nibble + (mask & 39)
}

/// The value of `digit` as a lower-case hex digit, with `0xff` when it is
/// one and `0x00` when it is not, without a branch or a table lookup on it
/// (see [`hex_digit`]).
fn hex_value(digit: u8) -> (u8, u8) {
    let c = i16::from(digit);
    // For a range `lo..=hi`, `(lo - 1 - c)` is negative exactly when
    // `c >= lo`, and `(c - hi - 1)` exactly when `c <= hi`. For a byte, both
    // lie between -256 and 255, so their high bytes are 0xff when negative
    // and 0x00 when not: `&` keeps 0xff only when both are, and `>> 8` on a
    // signed number copies the sign bit down, giving -1 (every bit set) in
    // range and 0 outside it.
    let in_range = |lo: u8, hi: u8| ((i16::from(lo) - 1 - c) & (c - i16::from(hi) - 1)) >> 8;
    let is_digit = in_range(b'0', b'9');
    let is_letter = in_range(b'a', b'f');
    let value = ((c - i16::from(b'0')) & is_digit) | ((c - i16::from(b'a') + 10) & is_letter);
    // `value` is 0 to 15 and each mask -1 or 0, so `as u8`, which keeps the
    // low eight bits, loses nothing: -1 becomes 0xff.
    (value as u8, (is_digit | is_letter) as u8)
}

// ---------------------------------------------------------------------------
// The public details.

/// The most Sweepky reads of an identity's details file. A few hundred bytes
/// in practice; the rest is room for fields a newer Sweepky adds.
pub(crate) const MAX_IDENTITY_META_BYTES: usize = 64 * 1024;

/// A dedicated identity's public details, `identities/<name>.json`.
///
/// ```json
/// {"schemaVersion": 1, "name": "throwaway", "pubky": "<z32>", "homeserver": "<z32>", "signedUp": true}
/// ```
///
/// A cache, not a source of truth: `pubky` is the key `<name>.key` gives,
/// and `login` can rebuild the file from that and the homeserver. Copying
/// `<name>.key` alone into another `SWEEPKY_HOME` carries the identity
/// (P2c's second install does that). The fields this build does not know
/// are kept in `extra` and written back, as for a record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
// The Rust fields are snake_case; the JSON keys camelCase, as in records.
#[serde(rename_all = "camelCase")]
pub(crate) struct IdentityMeta {
    /// The format's version, 1.
    pub(crate) schema_version: SchemaVersion,
    /// The identity's name, the stem of its two files.
    pub(crate) name: IdentityName,
    /// The identity's public key, raw z-base32.
    pub(crate) pubky: Pubky,
    /// The homeserver it signed up on, raw z-base32.
    pub(crate) homeserver: Pubky,
    /// Whether the signup on `homeserver` went through, so a later `login`
    /// signs in rather than spending another signup token.
    pub(crate) signed_up: bool,
    /// Fields a newer Sweepky wrote, kept for the rewrite.
    #[serde(flatten)]
    pub(crate) extra: UnknownFields,
}

impl IdentityMeta {
    /// The details of a new identity, at the current version.
    pub(crate) fn new(
        name: IdentityName,
        pubky: Pubky,
        homeserver: Pubky,
        signed_up: bool,
    ) -> Self {
        Self {
            schema_version: SchemaVersion::CURRENT,
            name,
            pubky,
            homeserver,
            signed_up,
            extra: UnknownFields::new(),
        }
    }

    /// The file's bytes: pretty-printed JSON and a newline.
    pub(crate) fn to_json(&self) -> anyhow::Result<Vec<u8>> {
        let mut json =
            serde_json::to_vec_pretty(self).context("could not write an identity's details")?;
        json.push(b'\n');
        Ok(json)
    }

    /// Reads the file's bytes, at most 64 KiB. A newer version, a name that
    /// fails its check or a key that is not one is an error.
    pub(crate) fn from_json(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() > MAX_IDENTITY_META_BYTES {
            bail!(
                "an identity's details are {} bytes, more than the {MAX_IDENTITY_META_BYTES} \
                 Sweepky reads",
                bytes.len()
            );
        }
        // serde_json's own messages can quote the input. Converting to core's
        // `RecordError`, as every record parse does, keeps only the kind of
        // fault and where it is.
        serde_json::from_slice(bytes)
            .map_err(RecordError::from)
            .context("not valid identity details")
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io;
    use std::path::Path;

    use pubky::Keypair;
    use serde_json::json;
    use sweepky_core::{DeviceIdentity, ExposeSecret, Pubky, SchemaVersion, Zeroizing};

    use super::{
        IdentityMeta, IdentityName, IdentitySecret, MALFORMED, MAX_IDENTITY_FILE_BYTES,
        NOT_IMPORTED, NOT_SWEEPKY, OTHER_VERSION, Refusal, read_argument_file,
        refuse_secret_material,
    };
    use crate::network::TESTNET_HOMESERVER;
    use crate::test_support::private_temp;

    /// A recovery file for a fresh random keypair, made by the SDK at run
    /// time, so no recovery file or secret is ever committed.
    ///
    /// `create_recovery_file` is on the crate's clippy ban list, because
    /// Sweepky never keeps a secret in that format. A test that needs a real
    /// one to refuse is the one place that may call it, and `expect` (rather
    /// than `allow`) fails the lint run if the ban ever stops applying here.
    #[expect(
        clippy::disallowed_methods,
        reason = "a synthetic recovery file is the input the refusal is tested on"
    )]
    fn synthetic_recovery_file() -> Vec<u8> {
        pubky::recovery_file::create_recovery_file(&Keypair::random(), "synthetic passphrase")
    }

    /// The bytes after a recovery file's first line: the encrypted secret.
    fn after_first_line(bytes: &[u8]) -> &[u8] {
        let newline = bytes
            .iter()
            .position(|&b| b == b'\n')
            .expect("a first line");
        &bytes[newline + 1..]
    }

    /// Lower-case hex, as a test spells a key out.
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    const BASE64_STANDARD: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const BASE64_URL: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    /// Base64 in `alphabet`, with or without `=` padding. The crate has no
    /// base64 dependency, and a test should not add one for this.
    fn base64(bytes: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let byte = |i: usize| u32::from(chunk.get(i).copied().unwrap_or(0));
            let group = (byte(0) << 16) | (byte(1) << 8) | byte(2);
            for i in 0..4 {
                if i <= chunk.len() {
                    let index = (group >> (18 - 6 * i)) & 0x3f;
                    out.push(char::from(alphabet[index as usize]));
                } else if pad {
                    out.push('=');
                }
            }
        }
        out
    }

    /// Every raw-key spelling the classifier must refuse, built from fresh
    /// keys at run time.
    fn raw_key_shapes() -> Vec<String> {
        let keypair = Keypair::random();
        // A test may hold a secret in a plain array; library code wraps it.
        let secret = keypair.secret();
        let mut expanded = secret.to_vec();
        expanded.extend_from_slice(&keypair.public_key().to_bytes());
        vec![
            hex(&secret),
            hex(&secret).to_uppercase(),
            hex(&expanded),
            base64(&secret, BASE64_STANDARD, true),
            base64(&secret, BASE64_STANDARD, false),
            base64(&secret, BASE64_URL, true),
            base64(&secret, BASE64_URL, false),
            // `Pubky` prints 32 bytes as z-base32, so it spells the secret's
            // bytes in that alphabet here; nothing treats them as a key.
            Pubky::from_bytes(secret).to_string(),
            DeviceIdentity::generate()
                .to_secret_string()
                .expose_secret()
                .to_owned(),
        ]
    }

    /// `count` synthetic lower-case words separated by spaces.
    fn mnemonic(count: usize) -> String {
        const WORDS: [&str; 8] = [
            "quartz", "meadow", "lantern", "harbor", "pebble", "violet", "summit", "willow",
        ];
        (0..count)
            .map(|i| WORDS[i % WORDS.len()])
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// A `read_file` for an argument that names no file.
    fn no_file(_: &Path) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(None)
    }

    /// The refusal inside an error, if it is one.
    fn refusal_of(err: &anyhow::Error) -> Option<Refusal> {
        err.downcast_ref::<Refusal>().copied()
    }

    /// The error `IdentitySecret::from_file_bytes` returns for `bytes`.
    ///
    /// `IdentitySecret` has no `Debug`, so `Result::unwrap_err`, which prints
    /// the `Ok` value when there is one, cannot be called on its result;
    /// `.err()` drops the `Ok` side first.
    fn file_error(bytes: &[u8]) -> anyhow::Error {
        IdentitySecret::from_file_bytes(bytes)
            .err()
            .expect("refused")
    }

    #[test]
    fn recovery_file_is_rejected_with_one_line_reason() {
        let recovery = synthetic_recovery_file();
        assert!(recovery.starts_with(b"pubky.org/recovery\n"));
        assert_eq!(
            refuse_secret_material(&recovery),
            Some(Refusal::RecoveryFile)
        );

        // The legacy first line, which the SDK still reads.
        let mut legacy = b"pkarr.org/recovery\n".to_vec();
        legacy.extend_from_slice(after_first_line(&recovery));
        assert_eq!(refuse_secret_material(&legacy), Some(Refusal::RecoveryFile));

        // Passed as `--identity <path>`, and dropped into `identities/` as a
        // `.key` file, it gets the same reason.
        for bytes in [&recovery, &legacy] {
            let err = IdentityName::from_arg("./recovery.txt", |_| {
                Ok(Some(Zeroizing::new(bytes.clone())))
            })
            .expect_err("refused");
            assert_eq!(refusal_of(&err), Some(Refusal::RecoveryFile), "{err:#}");
            assert_eq!(refusal_of(&file_error(bytes)), Some(Refusal::RecoveryFile));
        }

        // One line, and it says why and what to do instead.
        let reason = Refusal::RecoveryFile.to_string();
        assert!(!reason.contains('\n'), "{reason}");
        assert!(reason.contains("recovery file"), "{reason}");
        assert!(reason.contains("forever"), "{reason}");
        assert!(reason.contains("dedicated identity"), "{reason}");
        assert!(reason.contains("Ring"), "{reason}");
    }

    #[test]
    fn raw_key_shapes_are_rejected() {
        for shape in raw_key_shapes() {
            // No key shape can be a valid name, so none is ever taken for one.
            assert!(shape.parse::<IdentityName>().is_err(), "{shape}");

            // As file content, with or without a final newline.
            assert_eq!(
                refuse_secret_material(shape.as_bytes()),
                Some(Refusal::RawKey),
                "{shape}"
            );
            let line = format!("{shape}\n");
            assert_eq!(
                refuse_secret_material(line.as_bytes()),
                Some(Refusal::RawKey),
                "{shape}"
            );
            let err = IdentityName::from_arg("./key.txt", |_| {
                Ok(Some(Zeroizing::new(line.clone().into_bytes())))
            })
            .expect_err("refused");
            assert_eq!(refusal_of(&err), Some(Refusal::RawKey), "{shape}");

            // As the `--identity` argument itself.
            let err = IdentityName::from_arg(&shape, no_file).expect_err("refused");
            assert_eq!(refusal_of(&err), Some(Refusal::RawKey), "{shape}");
        }

        let reason = Refusal::RawKey.to_string();
        assert!(!reason.contains('\n'), "{reason}");
        assert!(reason.contains("raw key"), "{reason}");
        assert!(reason.contains("forever"), "{reason}");
    }

    #[test]
    fn raw_keys_inside_other_text_are_found() {
        for shape in raw_key_shapes() {
            let mut wrapped = vec![
                format!("SWEEPKY_SECRET_KEY={shape}\n"),
                format!("{{\"secret\": \"{shape}\"}}\n"),
            ];
            // A `/` or `+` inside a base64 key cannot be told from the
            // path's own bytes, so only keys without one are looked for in
            // a path.
            if !shape.contains(['/', '+']) {
                wrapped.push(format!("/home/someone/.keys/{shape}.txt"));
            }
            for text in wrapped {
                assert_eq!(
                    refuse_secret_material(text.as_bytes()),
                    Some(Refusal::RawKey),
                    "{text}"
                );
            }
        }
        // Text with no key in it is not taken for one.
        assert_eq!(
            refuse_secret_material(b"/home/someone/notes/todo-list.txt"),
            None
        );
    }

    #[test]
    fn mnemonic_shaped_input_is_rejected() {
        for count in [12, 24] {
            let phrase = mnemonic(count);
            assert_eq!(
                refuse_secret_material(phrase.as_bytes()),
                Some(Refusal::Mnemonic),
                "{count} words"
            );
            let file = format!("{phrase}\n");
            assert_eq!(
                refuse_secret_material(file.as_bytes()),
                Some(Refusal::Mnemonic),
                "{count} words"
            );
            let err = IdentityName::from_arg(&phrase, no_file).expect_err("refused");
            assert_eq!(refusal_of(&err), Some(Refusal::Mnemonic), "{count} words");
        }
        // A phrase is 12, 15, 18, 21 or 24 words; eleven words are not one.
        assert_eq!(refuse_secret_material(mnemonic(11).as_bytes()), None);

        let reason = Refusal::Mnemonic.to_string();
        assert!(!reason.contains('\n'), "{reason}");
        assert!(reason.contains("recovery phrase"), "{reason}");
        assert!(reason.contains("forever"), "{reason}");
    }

    /// Fails if `message` holds any run of 8 bytes from `input`: long enough
    /// that no ordinary word of a message matches by chance, short enough
    /// that no echo of a key or phrase gets past.
    fn assert_no_echo(input: &[u8], message: &str) {
        for window in input.windows(8) {
            assert!(
                !message.as_bytes().windows(8).any(|part| part == window),
                "{message:?} echoes {:?}",
                String::from_utf8_lossy(window)
            );
        }
    }

    #[test]
    fn reasons_never_contain_the_input() {
        // Each rejected input, with the part of it that must not come back.
        let mut cases: Vec<(String, Vec<String>)> = Vec::new();

        let mut texts: Vec<String> = raw_key_shapes();
        texts.push(mnemonic(12));
        texts.push(mnemonic(24));
        // Invalid names, each at least 8 bytes so the window check bites.
        texts.extend(
            [
                "Throwaway-Upper",
                "../outside-dir",
                "name.with.dots",
                "-leading-dash",
            ]
            .map(String::from),
        );
        texts.push("n".repeat(33));
        for text in texts {
            let as_argument = IdentityName::from_arg(&text, no_file).expect_err("refused");
            let in_a_file = IdentityName::from_arg("./input.txt", |_| {
                Ok(Some(Zeroizing::new(text.clone().into_bytes())))
            })
            .expect_err("refused");
            let messages = [as_argument, in_a_file]
                .iter()
                .flat_map(|err| [format!("{err}"), format!("{err:#}"), format!("{err:?}")])
                .collect();
            cases.push((text, messages));
        }

        // A recovery file: its first line is fixed public text, so only the
        // encrypted secret after it counts as input. The marker is not
        // repeated either.
        let recovery = synthetic_recovery_file();
        let err = IdentityName::from_arg("./recovery.txt", |_| {
            Ok(Some(Zeroizing::new(recovery.clone())))
        })
        .expect_err("refused");
        for message in [
            format!("{err:#}"),
            format!("{err:?}"),
            format!("{:#}", file_error(&recovery)),
        ] {
            assert!(!message.contains("pubky.org/recovery"), "{message}");
            assert_no_echo(after_first_line(&recovery), &message);
        }

        // Broken identity files: the hex of a fresh secret must not come back.
        let secret_hex = hex(&Keypair::random().secret());
        for broken in [
            format!("sweepky-identity/v1\n{secret_hex}\n\n"),
            format!("sweepky-identity/v1\n{}\n", secret_hex.to_uppercase()),
            format!("sweepky-identity/v2\n{secret_hex}\n"),
            format!("{secret_hex}\n"),
            format!("sweepky-identity/v1\n{}\n", &secret_hex[1..]),
        ] {
            let err = file_error(broken.as_bytes());
            cases.push((
                secret_hex.clone(),
                vec![format!("{err:#}"), format!("{err:?}")],
            ));
        }

        for (input, messages) in cases {
            for message in messages {
                assert_no_echo(input.as_bytes(), &message);
            }
        }
    }

    #[test]
    fn identity_names() {
        let longest = format!("a{}", "0".repeat(31));
        for good in ["a", "throwaway", "bot-1", "ci_runner", "x9", &longest] {
            let name: IdentityName = good.parse().expect(good);
            assert_eq!(name.as_str(), good);
            assert_eq!(name.to_string(), good);
        }
        let too_long = format!("a{}", "0".repeat(32));
        for bad in [
            "",
            "Throwaway",
            "UPPER",
            "a/b",
            "a\\b",
            ".",
            "..",
            "a.b",
            ".hidden",
            "0abc",
            "-x",
            "_x",
            "a b",
            "a\0b",
            "é",
            &too_long,
        ] {
            assert!(bad.parse::<IdentityName>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn identity_name_is_refused_for_its_characters_before_its_length() {
        // 21 characters but 41 bytes: a length check that ran first would
        // count the bytes and call it too long.
        let err = format!("a{}", "é".repeat(20))
            .parse::<IdentityName>()
            .expect_err("not ASCII");
        assert!(
            format!("{err:#}").contains("only lower-case letters"),
            "{err:#}"
        );

        let err = format!("a{}", "0".repeat(32))
            .parse::<IdentityName>()
            .expect_err("too long");
        assert!(
            format!("{err:#}").contains("at most 32 characters"),
            "{err:#}"
        );
    }

    #[test]
    fn argument_is_a_path_only_when_it_is_not_a_valid_name() {
        let dir = private_temp();
        let recovery = synthetic_recovery_file();
        // `dir` stands in for the working directory: the closure reads a
        // relative argument against it, as a real run reads against `.`.
        let read_in_dir = |path: &Path| read_argument_file(&dir.path().join(path));

        // A valid name is never read as a file, even when a file of that name
        // sits in the working directory: `read_file` is not even called.
        fs::write(dir.path().join("throwaway"), &recovery).expect("write");
        let name = IdentityName::from_arg("throwaway", |_| -> io::Result<_> {
            panic!("a valid name was read as a path")
        })
        .expect("a name");
        assert_eq!(name.as_str(), "throwaway");
        let name = IdentityName::from_arg("throwaway", read_in_dir).expect("a name");
        assert_eq!(name.as_str(), "throwaway");

        // Not a name, and an existing regular file: read and classified.
        fs::write(dir.path().join("recovery.txt"), &recovery).expect("write");
        let err = IdentityName::from_arg("./recovery.txt", read_in_dir).expect_err("refused");
        assert_eq!(refusal_of(&err), Some(Refusal::RecoveryFile), "{err:#}");
        let absolute = dir.path().join("recovery.txt");
        let err = IdentityName::from_arg(absolute.to_str().expect("UTF-8"), read_argument_file)
            .expect_err("refused");
        assert_eq!(refusal_of(&err), Some(Refusal::RecoveryFile), "{err:#}");

        // At most 4 KiB of it is read; the marker is at the start anyway.
        let mut large = recovery.clone();
        large.resize(10 * 1024, b'x');
        fs::write(dir.path().join("large.txt"), &large).expect("write");
        let read = read_in_dir(Path::new("large.txt"))
            .expect("read")
            .expect("a file");
        assert_eq!(read.len(), MAX_IDENTITY_FILE_BYTES);
        let err = IdentityName::from_arg("./large.txt", read_in_dir).expect_err("refused");
        assert_eq!(refusal_of(&err), Some(Refusal::RecoveryFile), "{err:#}");

        // A file the classifier does not recognise is still not imported.
        fs::write(dir.path().join("notes.txt"), b"just some notes\n").expect("write");
        let err = IdentityName::from_arg("./notes.txt", read_in_dir).expect_err("refused");
        assert_eq!(refusal_of(&err), None);
        assert!(format!("{err:#}").contains(NOT_IMPORTED), "{err:#}");

        // Neither a name nor a file: the text itself is classified...
        let key = hex(&Keypair::random().secret());
        let err = IdentityName::from_arg(&key, read_in_dir).expect_err("refused");
        assert_eq!(refusal_of(&err), Some(Refusal::RawKey), "{err:#}");
        // ... and otherwise it is an invalid name. A directory is not a file.
        fs::create_dir(dir.path().join("Some-Dir")).expect("mkdir");
        for value in ["./missing.txt", "Not-A-Name", "Some-Dir"] {
            let err = IdentityName::from_arg(value, read_in_dir).expect_err("refused");
            assert_eq!(refusal_of(&err), None, "{value}");
            assert!(format!("{err:#}").contains("identity name"), "{err:#}");
        }
    }

    #[test]
    fn identity_file_round_trips() {
        let secret = IdentitySecret::generate();
        let file_bytes = secret.to_file_bytes();
        // The marker line, 64 lower-case hex digits, a newline.
        let text = std::str::from_utf8(&file_bytes).expect("ASCII");
        let hex_line = text.strip_prefix("sweepky-identity/v1\n").expect("marker");
        let hex_digits = hex_line.strip_suffix('\n').expect("newline");
        assert_eq!(hex_digits.len(), 64);
        assert!(
            hex_digits
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        );
        let read = IdentitySecret::from_file_bytes(&file_bytes).expect("reads back");
        assert_eq!(read.pubky(), secret.pubky());
        assert_eq!(
            read.pubky(),
            Pubky::from_bytes(secret.keypair().public_key().to_bytes())
        );

        // Every byte value spells and reads back exactly, in eight secrets of
        // 32 consecutive values each.
        for start in (0..=255_u8).step_by(32) {
            let mut bytes = [0_u8; 32];
            for (offset, byte) in (0_u8..).zip(bytes.iter_mut()) {
                *byte = start + offset;
            }
            let known = IdentitySecret {
                secret: Zeroizing::new(bytes),
            };
            let file = known.to_file_bytes();
            assert_eq!(
                *file,
                format!("sweepky-identity/v1\n{}\n", hex(&bytes)).into_bytes()
            );
            let read = IdentitySecret::from_file_bytes(&file).expect("reads back");
            assert_eq!(*read.secret, bytes);
        }

        // Anything else is refused with fixed text.
        let good = String::from_utf8(file_bytes.to_vec()).expect("ASCII");
        let digits = &good["sweepky-identity/v1\n".len()..good.len() - 1];
        for (broken, expected) in [
            (format!("{good}\n"), MALFORMED),
            (format!("{good}x"), MALFORMED),
            (good.trim_end().to_owned(), MALFORMED),
            (good.replace('\n', "\r\n"), MALFORMED),
            (
                format!("sweepky-identity/v1\n{}\n", digits.to_uppercase()),
                MALFORMED,
            ),
            (
                format!("sweepky-identity/v1\n{}\n", &digits[1..]),
                MALFORMED,
            ),
            (format!("sweepky-identity/v1\n{digits}0\n"), MALFORMED),
            (
                format!("sweepky-identity/v1\n{}g\n", &digits[1..]),
                MALFORMED,
            ),
            (format!("sweepky-identity/v2\n{digits}\n"), OTHER_VERSION),
            ("not an identity\n".to_owned(), NOT_SWEEPKY),
            (String::new(), NOT_SWEEPKY),
        ] {
            let err = file_error(broken.as_bytes());
            assert_eq!(format!("{err:#}"), expected, "{broken:?}");
        }
        // A wrong marker before a key is refused as the raw key it holds.
        let err = file_error(format!("Sweepky-Identity/v1\n{digits}\n").as_bytes());
        assert_eq!(refusal_of(&err), Some(Refusal::RawKey));
    }

    #[test]
    fn identity_metadata_round_trips() {
        let name: IdentityName = "throwaway".parse().expect("valid name");
        let pubky = IdentitySecret::generate().pubky();
        let homeserver: Pubky = TESTNET_HOMESERVER.parse().expect("testnet homeserver");
        let meta = IdentityMeta::new(name, pubky, homeserver, true);
        assert_eq!(meta.schema_version, SchemaVersion::CURRENT);

        let bytes = meta.to_json().expect("serializes");
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");
        assert_eq!(
            value,
            json!({
                "schemaVersion": 1,
                "name": "throwaway",
                "pubky": pubky.to_string(),
                "homeserver": TESTNET_HOMESERVER,
                "signedUp": true,
            })
        );
        assert_eq!(IdentityMeta::from_json(&bytes).expect("parses"), meta);

        // A field a newer Sweepky added survives a rewrite.
        let mut newer = value.clone();
        newer["addedLater"] = json!({"x": 1});
        let newer = serde_json::to_vec(&newer).expect("JSON");
        let read = IdentityMeta::from_json(&newer).expect("parses");
        assert_eq!(read.extra.get("addedLater"), Some(&json!({"x": 1})));
        let rewritten: serde_json::Value =
            serde_json::from_slice(&read.to_json().expect("serializes")).expect("JSON");
        assert_eq!(rewritten["addedLater"], json!({"x": 1}));

        // A bad name, a bad key or a newer version is refused.
        for (field, bad) in [
            ("name", json!("Not/A-Name")),
            ("pubky", json!("not-a-key")),
            ("schemaVersion", json!(2)),
        ] {
            let mut broken = value.clone();
            broken[field] = bad;
            let broken = serde_json::to_vec(&broken).expect("JSON");
            assert!(IdentityMeta::from_json(&broken).is_err(), "{field}");
        }
    }

    #[test]
    fn identity_secret_has_no_debug_display_serialize_or_clone() {
        // Checked when the test compiles; there is nothing left to run.
        crate::test_support::assert_not_impl_any!(
            IdentitySecret: std::fmt::Debug,
            std::fmt::Display,
            serde::Serialize,
            serde::de::DeserializeOwned,
            Clone,
            PartialEq,
        );
    }
}
