//! The C2SP CCTV age test vectors, run offline against
//! [`sweepky_core::decrypt`] and [`DeviceIdentity::from_secret`].
//!
//! `fixtures/cctv-age/` holds the 147 files of `age/testdata` from
//! C2SP/CCTV at commit `50a8ecf2a220f4c8bdc4f085789b8e85c26829e7`, byte for
//! byte (see `fixtures/README.md`). Each file is one vector: a few
//! `key: value` lines, an empty line, then an age file, zlib-compressed when
//! the vector says `compressed: zlib`.
//!
//! **This test reads files; the library never does.** sweepky-core does no
//! file I/O, so the test reads each vector itself and hands `decrypt` the
//! bytes, as the CLI will hand it a downloaded `.age` file. A file under
//! `tests/` is an integration test: Cargo compiles it as a separate crate
//! that links sweepky-core like any other user, so it sees only the public
//! API, and the disk access stays here, outside the library.
//!
//! Every vector lands in exactly one group, and each group's size is
//! asserted, so no vector can be skipped without the test failing:
//!
//! - 19 **hybrid** vectors, each with an `AGE-SECRET-KEY-PQ-` identity (the
//!   18 `hybrid*` files and `armor_hybrid`), are skipped: age 0.12.1 has no
//!   hybrid post-quantum identity to run them with.
//! - 36 **armored** vectors (`armored: yes`) must each be refused by
//!   `decrypt`. Sweep packages are binary age, and sweepky-core builds age
//!   without its `armor` feature, so ASCII armor is never decoded. CCTV
//!   allows ignoring them; asserting the refusal is stricter.
//! - 24 **scrypt** vectors (a passphrase and no identity) run through age's
//!   own `age::scrypt::Identity`, since `decrypt` only ever takes an X25519
//!   key. 02 has the CLI read a passphrase-wrapped key file with that
//!   identity, so the parse it relies on is checked here too.
//! - 68 **X25519** vectors run through `decrypt`, each with its identity read
//!   by `DeviceIdentity::from_secret` (`empty`, which has none, with a newly
//!   generated one).
//!
//! Then every one of the 147, hybrid ones included, goes through `decrypt`
//! once more with a key it was not written to, so the remote-data path is
//! shown never to panic on any of them.

use std::fs;
use std::io::Read;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::str;

use sha2::{Digest, Sha256};
use sweepky_core::{DecryptError, DeviceIdentity, ExposeSecret, SecretString, Sha256Hex, decrypt};

/// How many files the pinned commit's `age/testdata` holds.
const TOTAL_VECTORS: usize = 147;
/// The vectors skipped because they need a hybrid identity.
const HYBRID_VECTORS: usize = 19;
/// The armored vectors that are not hybrid.
const ARMORED_VECTORS: usize = 36;
/// The passphrase-only vectors, run through age's scrypt identity.
const SCRYPT_VECTORS: usize = 24;
/// The vectors run through `decrypt` with their own identity.
const X25519_VECTORS: usize = 68;

// A compile-time check: `const _` is evaluated while the test compiles, so
// groups that do not add up to the whole set are a compile error.
const _: () =
    assert!(HYBRID_VECTORS + ARMORED_VECTORS + SCRYPT_VECTORS + X25519_VECTORS == TOTAL_VECTORS);

/// The two vectors age 0.12.1 opens although CCTV expects a header failure.
/// age still accepts stanzas written without the short final body line, an
/// older form of the format, and age's own CCTV test makes the same two
/// exceptions. This test asserts that both still decrypt, so if a later age
/// starts refusing them, the test fails and the list has to shrink.
const LEGACY_STANZA_VECTORS: [&str; 2] = ["stanza_missing_body", "stanza_missing_final_line"];

/// The one vector `decrypt` refuses as `HeaderTooLarge`: an armored file
/// that inflates past the 8 KiB header cap, whose first `\n---` is its END
/// line, past the cap. Every other vector is under the cap or has its MAC
/// line inside it, so for them a size cap is a failure.
const OVERSIZED_ARMOR_VECTOR: &str = "armor_garbage_encoded";

/// How a hybrid post-quantum identity starts.
const HYBRID_IDENTITY_PREFIX: &str = "AGE-SECRET-KEY-PQ-";

/// The highest scrypt work factor (log2 of N) the scrypt identity will
/// compute. The vectors that decrypt use 10. `scrypt_work_factor_23` asks for
/// 2^23, which a reader must refuse before doing any work; CCTV counts that
/// refusal as a header failure. age's own CCTV test uses the same 16.
const SCRYPT_MAX_WORK_FACTOR: u8 = 16;

/// The most bytes a compressed vector may inflate to: 32 MiB. The largest
/// vector inflates to 16,847,065 bytes. The limit keeps a bad file from
/// making the test allocate without bound.
const MAX_INFLATED_BYTES: usize = 32 * 1024 * 1024;

/// A vector's `expect`: what decrypting its age file must give.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    Success,
    NoMatch,
    HmacFailure,
    HeaderFailure,
    PayloadFailure,
    ArmorFailure,
}

impl Expect {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "success" => Some(Self::Success),
            "no match" => Some(Self::NoMatch),
            "HMAC failure" => Some(Self::HmacFailure),
            "header failure" => Some(Self::HeaderFailure),
            "payload failure" => Some(Self::PayloadFailure),
            "armor failure" => Some(Self::ArmorFailure),
            _ => None,
        }
    }
}

/// One vector file, parsed.
struct Vector {
    header: Header,
    /// The age file itself, inflated if the vector was compressed.
    age_file: Vec<u8>,
}

/// A vector's `key: value` lines.
struct Header {
    expect: Expect,
    /// `payload`: the plaintext's SHA-256.
    payload: Option<Sha256Hex>,
    identities: Vec<String>,
    passphrases: Vec<String>,
    armored: bool,
    compressed: bool,
}

/// The way a vector is run. Each vector is in exactly one group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Group {
    Hybrid,
    Armored,
    Scrypt,
    X25519,
}

impl Header {
    fn group(&self) -> Group {
        // The order matters: `armor_hybrid` is armored and hybrid, and counts
        // as hybrid; `scrypt_and_x25519` has a passphrase and an identity,
        // and counts as X25519.
        if self
            .identities
            .iter()
            .any(|identity| identity.starts_with(HYBRID_IDENTITY_PREFIX))
        {
            Group::Hybrid
        } else if self.armored {
            Group::Armored
        } else if !self.passphrases.is_empty() && self.identities.is_empty() {
            Group::Scrypt
        } else {
            Group::X25519
        }
    }
}

/// How many vectors ran in each group.
#[derive(Debug, Default, PartialEq, Eq)]
struct GroupSizes {
    hybrid: usize,
    armored: usize,
    scrypt: usize,
    x25519: usize,
}

impl GroupSizes {
    /// The sizes the pinned commit gives.
    const EXPECTED: Self = Self {
        hybrid: HYBRID_VECTORS,
        armored: ARMORED_VECTORS,
        scrypt: SCRYPT_VECTORS,
        x25519: X25519_VECTORS,
    };

    fn count(&mut self, group: Group) {
        // The `match` picks which field to borrow mutably; the borrow ends
        // once that one field is incremented.
        let size = match group {
            Group::Hybrid => &mut self.hybrid,
            Group::Armored => &mut self.armored,
            Group::Scrypt => &mut self.scrypt,
            Group::X25519 => &mut self.x25519,
        };
        *size += 1;
    }
}

/// What a decryption gave, in CCTV's terms.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// Decrypted to the end. Only the plaintext's hash is kept, so a failure
    /// message never prints the plaintext.
    Success {
        sha256: Sha256Hex,
    },
    NoMatch,
    HmacFailure,
    HeaderFailure,
    PayloadFailure,
    /// Refused by one of `decrypt`'s size caps, which CCTV has no class for.
    /// A failure for every vector but [`OVERSIZED_ARMOR_VECTOR`].
    OverSizeCap(DecryptError),
    /// `decrypt` panicked. Always a failure: it reads strangers' files.
    Panicked,
}

#[test]
fn cctv_age_vectors() {
    let dir = fixture_dir();
    let names = vector_names(&dir);
    assert_eq!(
        names.len(),
        TOTAL_VECTORS,
        "fixtures/cctv-age must hold exactly the {TOTAL_VECTORS} vectors of the pinned commit"
    );

    // A key none of the vectors was written to, for the second pass.
    let stranger = DeviceIdentity::generate();
    let mut failures: Vec<String> = Vec::new();
    let mut group_sizes = GroupSizes::default();
    let mut legacy_stanza_runs = 0;

    // One vector at a time: the largest inflate to 16 MiB, so each is
    // dropped before the next is read.
    for name in &names {
        let vector = match read_vector(&dir.join(name)) {
            Ok(vector) => vector,
            Err(why) => {
                failures.push(format!("{name}: {why}"));
                continue;
            }
        };
        let group = vector.header.group();
        group_sizes.count(group);
        if group == Group::X25519 && is_legacy_stanza_vector(name) {
            legacy_stanza_runs += 1;
        }
        if let Err(why) = check_in_group(group, name, &vector) {
            failures.push(format!("{name} ({group:?}): {why}"));
        }
        // Any vector, hybrid ones too, with a key it was not written to.
        // Without the file key there is no MAC to check and no payload to
        // read, so no later stage can be reached.
        if let Err(why) = ensure_refused_at_header(name, &vector.age_file, &stranger) {
            failures.push(format!("{name}, with a key it was not written to: {why}"));
        }
    }

    assert!(
        failures.is_empty(),
        "{} vector check(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
    // The exact group sizes, so a vector that moved group (or a new file in
    // a re-vendored set) fails the test rather than being skipped quietly.
    assert_eq!(group_sizes, GroupSizes::EXPECTED, "vectors per group");
    assert_eq!(
        legacy_stanza_runs,
        LEGACY_STANZA_VECTORS.len(),
        "both legacy-stanza vectors must be present and run as X25519 vectors"
    );
}

/// `fixtures/cctv-age/`. `env!` is filled in at compile time with the
/// directory of this crate's `Cargo.toml`, so the path does not depend on
/// where the test is run from.
fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/cctv-age")
}

/// The file names in `dir`, sorted. Anything there that is not a plain file
/// fails the test: the fixture is data only.
fn vector_names(dir: &Path) -> Vec<String> {
    let entries =
        fs::read_dir(dir).unwrap_or_else(|error| panic!("cannot read {}: {error}", dir.display()));
    let mut names: Vec<String> = entries
        .map(|entry| {
            let entry = entry.expect("a readable directory entry");
            // `DirEntry::file_type` does not follow symbolic links, so a link
            // is reported as a link, not as the file it points at.
            let file_type = entry.file_type().expect("a file type");
            let name = entry.file_name().into_string().expect("a UTF-8 file name");
            assert!(file_type.is_file(), "{name} is not a plain file");
            name
        })
        .collect();
    names.sort();
    names
}

/// Reads and parses one vector file: its header, then its age file, inflated
/// when the header says `compressed: zlib`.
fn read_vector(path: &Path) -> Result<Vector, String> {
    let file = fs::read(path).map_err(|error| format!("cannot read: {error}"))?;
    let (header, body) = split_header(&file)?;
    let header = parse_header(header)?;
    let age_file = if header.compressed {
        inflate_zlib(body)?
    } else {
        body.to_vec()
    };
    Ok(Vector { header, age_file })
}

/// Splits a vector into its textual header and its age file. The header ends
/// at the first empty line, so at the first `\n\n`.
///
/// Both halves borrow from `file`, so nothing is copied. With one reference
/// argument, Rust ties the returned references to it without a written
/// lifetime.
fn split_header(file: &[u8]) -> Result<(&str, &[u8]), String> {
    let end = file
        .windows(2)
        .position(|pair| pair == b"\n\n")
        .ok_or("no empty line after the header")?;
    // `split_at(end + 1)` keeps the header's last newline with the header;
    // the age file starts after the empty line's own newline.
    let (header, rest) = file.split_at(end + 1);
    let body = rest.get(1..).ok_or("no body")?;
    let header = str::from_utf8(header).map_err(|_| "the header is not UTF-8")?;
    Ok((header, body))
}

/// Reads a vector's `key: value` lines.
fn parse_header(header: &str) -> Result<Header, String> {
    let mut expect = None;
    let mut payload = None;
    let mut identities = Vec::new();
    let mut passphrases = Vec::new();
    let mut armored = false;
    let mut compressed = false;
    // `split('\n')` rather than `lines()`: `lines()` would also strip a `\r`
    // at a line's end, and the header must be read exactly as written.
    // `strip_suffix` drops the header's final newline first, so the split
    // yields no empty last line.
    let lines = header.strip_suffix('\n').unwrap_or(header).split('\n');
    for line in lines {
        let (key, value) = line
            .split_once(": ")
            .ok_or_else(|| format!("header line without `: `: {line:?}"))?;
        match key {
            "expect" => {
                let parsed = Expect::parse(value)
                    .ok_or_else(|| format!("unknown expect value {value:?}"))?;
                set_once(&mut expect, parsed, key)?;
            }
            "payload" => {
                // `Sha256Hex` is sweepky-core's own checked digest type: its
                // parse accepts exactly 64 lower-case hex characters.
                let parsed: Sha256Hex = value
                    .parse()
                    .map_err(|_| format!("payload is not a SHA-256 in hex: {value:?}"))?;
                set_once(&mut payload, parsed, key)?;
            }
            "identity" => identities.push(value.to_owned()),
            "passphrase" => passphrases.push(value.to_owned()),
            "armored" if value == "yes" => armored = true,
            "compressed" if value == "zlib" => compressed = true,
            "armored" | "compressed" => return Err(format!("unknown {key} value {value:?}")),
            // `file key` (a debugging aid) and `comment` are not checked.
            "file key" | "comment" => {}
            // The arms above are every key the CCTV age README defines. CCTV
            // says to ignore a file with any other key; this test fails
            // instead, so a re-vendored set with a new key cannot quietly
            // drop vectors.
            _ => return Err(format!("unknown header key {key:?}")),
        }
    }
    Ok(Header {
        expect: expect.ok_or("no `expect` line")?,
        payload,
        identities,
        passphrases,
        armored,
        compressed,
    })
}

/// Stores the value of a key the header may give only once.
fn set_once<T>(slot: &mut Option<T>, value: T, key: &str) -> Result<(), String> {
    // `Option::replace` stores the new value and hands back the old one, so
    // `Some` means the key came twice.
    if slot.replace(value).is_some() {
        Err(format!("two `{key}` lines"))
    } else {
        Ok(())
    }
}

/// Inflates a zlib-compressed age file, to at most [`MAX_INFLATED_BYTES`].
fn inflate_zlib(body: &[u8]) -> Result<Vec<u8>, String> {
    // Bounded: `_with_limit` stops with an error once the output would pass
    // the limit, instead of growing its buffer without end. The error's
    // `Debug` would print everything inflated so far, so only its status is
    // kept.
    miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(body, MAX_INFLATED_BYTES)
        .map_err(|error| format!("zlib inflate failed: {:?}", error.status))
}

/// Runs a vector the way its group says.
fn check_in_group(group: Group, name: &str, vector: &Vector) -> Result<(), String> {
    match group {
        Group::Hybrid => check_hybrid(name),
        Group::Armored => check_armored(name, vector),
        Group::Scrypt => check_scrypt(vector),
        Group::X25519 => check_x25519(name, vector),
    }
}

/// A hybrid vector is skipped. Its name must say it is one, so a vector that
/// lands here by mistake is caught.
fn check_hybrid(name: &str) -> Result<(), String> {
    if name.contains("hybrid") {
        Ok(())
    } else {
        Err("has a hybrid identity but is not a hybrid vector".into())
    }
}

/// An armored vector must be refused by `decrypt`, with the vector's X25519
/// identity when it has one, and refused at the header, before any key is
/// tried: `decrypt` reads binary age only, so armor is never decoded. If it
/// were, `armor_x25519` would open and `armor_no_match` would be a no match,
/// and both would fail here.
///
/// Each gives exactly one result. age refuses the header
/// (`-----BEGIN AGE ENCRYPTED FILE-----` is not an age v1 first line), except
/// for [`OVERSIZED_ARMOR_VECTOR`], which `decrypt` refuses as too large
/// before age reads it.
fn check_armored(name: &str, vector: &Vector) -> Result<(), String> {
    let identity = identity_for(&vector.header.identities)?;
    let expected = if name == OVERSIZED_ARMOR_VECTOR {
        Outcome::OverSizeCap(DecryptError::HeaderTooLarge)
    } else {
        Outcome::HeaderFailure
    };
    ensure_outcome(x25519_outcome(&vector.age_file, &identity), expected)
}

/// Passes when `decrypt` refuses the file before any key could open a
/// stanza, without a panic: age refuses the header, or reads a valid header
/// in which no stanza opens, or, for [`OVERSIZED_ARMOR_VECTOR`] alone, the
/// header is over the cap.
fn ensure_refused_at_header(
    name: &str,
    age_file: &[u8],
    identity: &DeviceIdentity,
) -> Result<(), String> {
    match x25519_outcome(age_file, identity) {
        Outcome::NoMatch | Outcome::HeaderFailure => Ok(()),
        Outcome::OverSizeCap(DecryptError::HeaderTooLarge) if name == OVERSIZED_ARMOR_VECTOR => {
            Ok(())
        }
        outcome => Err(format!("expected a refusal at the header, got {outcome:?}")),
    }
}

/// A passphrase vector, through age's scrypt identity.
fn check_scrypt(vector: &Vector) -> Result<(), String> {
    let expected = expected_outcome(&vector.header)?;
    let actual = scrypt_outcome(&vector.age_file, &vector.header.passphrases);
    ensure_outcome(actual, expected)
}

/// An X25519 vector, through `decrypt` and `DeviceIdentity::from_secret`.
fn check_x25519(name: &str, vector: &Vector) -> Result<(), String> {
    let identity = identity_for(&vector.header.identities)?;
    let actual = x25519_outcome(&vector.age_file, &identity);
    if is_legacy_stanza_vector(name) {
        return check_legacy_stanza(vector.header.expect, &actual);
    }
    ensure_outcome(actual, expected_outcome(&vector.header)?)
}

fn is_legacy_stanza_vector(name: &str) -> bool {
    LEGACY_STANZA_VECTORS.contains(&name)
}

/// One of the [`LEGACY_STANZA_VECTORS`]: CCTV expects a header failure, and
/// age opens it. These files carry no `payload` line, since CCTV expects them
/// to fail; that they open at all is the point.
fn check_legacy_stanza(expect: Expect, actual: &Outcome) -> Result<(), String> {
    match (expect, actual) {
        (Expect::HeaderFailure, Outcome::Success { .. }) => Ok(()),
        (expect, actual) => Err(format!(
            "allowlisted as a header failure age accepts; now expect is {expect:?} \
             and decrypt gives {actual:?}: update LEGACY_STANZA_VECTORS"
        )),
    }
}

/// Passes when `actual` is the one result `expected` allows.
fn ensure_outcome(actual: Outcome, expected: Outcome) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("expected {expected:?}, got {actual:?}"))
    }
}

/// The one result each `expect` class allows.
fn expected_outcome(header: &Header) -> Result<Outcome, String> {
    Ok(match header.expect {
        Expect::Success => Outcome::Success {
            sha256: header
                .payload
                .clone()
                .ok_or("a success vector without a `payload` hash")?,
        },
        Expect::NoMatch => Outcome::NoMatch,
        Expect::HmacFailure => Outcome::HmacFailure,
        // A size cap (`HeaderTooLarge`) is not accepted here: no
        // header-failure vector is longer than 1,674 bytes, far under the
        // 8 KiB cap, and `empty` is no bytes at all, so only age's own
        // refusal counts.
        Expect::HeaderFailure => Outcome::HeaderFailure,
        // CCTV also asks that any plaintext released before the failure
        // match `payload`. `decrypt` releases none: it returns the whole
        // plaintext or nothing, so there is nothing to hash.
        Expect::PayloadFailure => Outcome::PayloadFailure,
        Expect::ArmorFailure => {
            return Err("`armor failure` on a vector that is not armored".into());
        }
    })
}

/// The vector's X25519 identity, read by `DeviceIdentity::from_secret`, or a
/// newly generated one when it has none (`empty`, `armor_empty` and
/// `armor_scrypt`).
fn identity_for(identities: &[String]) -> Result<DeviceIdentity, String> {
    // Slice patterns: `[]` matches an empty list, `[identity]` a list of
    // exactly one, binding it.
    match identities {
        [] => Ok(DeviceIdentity::generate()),
        // The CCTV keys are published test keys, not secrets, but they take
        // the same path as a real key file: into a `SecretString`, then the
        // strict parse. `IdentityError` holds no data, so its `Debug` cannot
        // print the key.
        [identity] => DeviceIdentity::from_secret(&SecretString::from(identity.clone()))
            .map_err(|error| format!("from_secret refused the vector's identity: {error:?}")),
        _ => Err("more than one identity, but decrypt takes one".into()),
    }
}

/// Runs `sweepky_core::decrypt` and names its result in CCTV's terms.
fn x25519_outcome(age_file: &[u8], identity: &DeviceIdentity) -> Outcome {
    // `catch_unwind` turns a panic inside the closure into an `Err`, so a
    // panic is reported as this vector's failure, with its name, instead of
    // ending the test at the first one. It asks for a closure that is
    // `UnwindSafe`, a promise that nothing it borrows is left half-updated
    // by a panic. `AssertUnwindSafe` makes that promise by hand, which holds
    // here: the closure only reads.
    let result = panic::catch_unwind(AssertUnwindSafe(|| decrypt(age_file, identity)));
    match result {
        Err(_) => Outcome::Panicked,
        Ok(Ok(plaintext)) => Outcome::Success {
            sha256: sha256_hex(plaintext.expose_secret()),
        },
        Ok(Err(DecryptError::NoMatchingKey)) => Outcome::NoMatch,
        Ok(Err(DecryptError::InvalidMac)) => Outcome::HmacFailure,
        Ok(Err(DecryptError::InvalidHeader)) => Outcome::HeaderFailure,
        Ok(Err(DecryptError::InvalidPayload)) => Outcome::PayloadFailure,
        // Every other variant, named one by one rather than with `_`: if
        // `DecryptError` gains a variant, this match stops compiling and the
        // new variant has to be placed.
        Ok(Err(
            error @ (DecryptError::TooLarge
            | DecryptError::HeaderTooLarge
            | DecryptError::PlaintextTooLarge),
        )) => Outcome::OverSizeCap(error),
    }
}

/// Decrypts with age's own scrypt identity, one per passphrase, and names
/// the result in CCTV's terms. The stages map as `decrypt` maps them.
///
/// age's errors are matched on their variant and dropped, never formatted:
/// age builds its messages through a translation library that, in a debug
/// build, reads message files from age's source directory at run time.
fn scrypt_outcome(age_file: &[u8], passphrases: &[String]) -> Outcome {
    // `&[u8]` implements `BufRead`, which the buffered parser reads from.
    let Ok(decryptor) = age::Decryptor::new_buffered(age_file) else {
        return Outcome::HeaderFailure;
    };
    let identities = scrypt_identities(passphrases);
    // age takes its identities as trait objects (`&dyn age::Identity`), so
    // one list can mix kinds; `as` turns each borrowed scrypt identity into
    // one.
    let decrypted = decryptor.decrypt(
        identities
            .iter()
            .map(|identity| identity as &dyn age::Identity),
    );
    match decrypted {
        Ok(reader) => read_outcome(reader),
        Err(error) => age_error_outcome(error),
    }
}

/// One scrypt identity per passphrase, each refusing a work factor over
/// [`SCRYPT_MAX_WORK_FACTOR`].
fn scrypt_identities(passphrases: &[String]) -> Vec<age::scrypt::Identity> {
    passphrases
        .iter()
        .map(|passphrase| {
            let mut identity = age::scrypt::Identity::new(SecretString::from(passphrase.clone()));
            identity.set_max_work_factor(SCRYPT_MAX_WORK_FACTOR);
            identity
        })
        .collect()
}

/// An error from age's `Decryptor::decrypt`, in CCTV's terms.
fn age_error_outcome(error: age::DecryptError) -> Outcome {
    match error {
        age::DecryptError::NoMatchingKeys | age::DecryptError::DecryptionFailed => Outcome::NoMatch,
        age::DecryptError::InvalidMac => Outcome::HmacFailure,
        // age's enum is `#[non_exhaustive]`, so a match on it needs a
        // catch-all. Everything else is a malformed header or stanza, or
        // `ExcessiveWork`: a work factor over the maximum, refused before
        // any scrypt work.
        _ => Outcome::HeaderFailure,
    }
}

/// Reads a decrypted payload to its end. `impl Read` takes age's reader
/// without naming its type.
fn read_outcome(mut reader: impl Read) -> Outcome {
    // The plaintext is shorter than the file, which is at most
    // MAX_INFLATED_BYTES, so this read is bounded too.
    let mut plaintext = Vec::new();
    match reader.read_to_end(&mut plaintext) {
        Ok(_) => Outcome::Success {
            sha256: sha256_hex(&plaintext),
        },
        Err(_) => Outcome::PayloadFailure,
    }
}

/// The SHA-256 of `bytes`, as the vectors write `payload`: each byte as two
/// lower-case hex digits (`{byte:02x}`), then checked into a [`Sha256Hex`].
fn sha256_hex(bytes: &[u8]) -> Sha256Hex {
    let hex: String = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Sha256Hex::try_from(hex).expect("32 bytes in hex are a valid Sha256Hex")
}
