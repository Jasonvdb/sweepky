//! `grant.token`: the grant token of a Pubky Ring login, the one secret that
//! login keeps, from which every later command restores a session (the
//! SDK's `restore_session`).
//!
//! **What the file holds.** The string the SDK exports after approval
//! (`export_local_secret`), exactly, with no newline:
//! `pubky-grant-credential-v1:`, the homeserver's key, the secret half of
//! the client key the grant is bound to, and the grant Ring signed. That is
//! about 600 bytes for the bare grant Sweepky asks for (a grant with
//! encryption keys would be `-v2:`, which Sweepky never asks for). With
//! `--passphrase-file` the file holds that string wrapped with the
//! passphrase instead, through the writer and reader every secret file uses
//! ([`crate::passphrase`]).
//!
//! **What reading it checks**, every refusal in fixed text that quotes none
//! of the file:
//!
//! - the file ([`crate::private_fs`]): a regular file, never a link, with no
//!   group or other permission bit, at most 4 KiB, all checked on its
//!   `lstat` before it is opened, and read into a buffer that never grows
//!   and wipes itself;
//! - the token ([`MalformedToken`]): at most [`MAX_GRANT_TOKEN_BYTES`],
//!   starting `pubky-grant-credential-`, printable ASCII and nothing else.
//!   The prefix matters: `restore_session` reads anything that does not
//!   start that way as the secret of a cookie session, the deprecated
//!   sign-in Sweepky never uses.
//!
//! The token is the grant's bearer: whoever holds it can write Sweepky
//! records as this user until the grant expires or is revoked (02, "Device
//! keys"). So [`GrantToken`] keeps it in a [`SecretString`] and has no
//! `Debug`, `Display`, `Serialize`, `Clone` or `PartialEq`.

use std::fmt;

use anyhow::Context as _;
use sweepky_core::{ExposeSecret, MAX_SECRET_BYTES, MAX_WRAPPED_BYTES, SecretString, Zeroizing};

use crate::Dirs;
use crate::passphrase::{Passphrase, open_secret_file, write_secret_file};
use crate::private_fs::{ensure_private_dir, read_private_file, remove_private_file};

/// What every grant token the SDK exports starts with, whatever its
/// version: `STORED_GRANT_CREDENTIAL_PREFIX_FAMILY` in pubky 0.16.2's
/// `actors/auth/grant/credential.rs`, the prefix `restore_session` tells a
/// grant token by.
const GRANT_TOKEN_PREFIX: &str = "pubky-grant-credential-";

/// The longest grant token Sweepky takes: 1 KiB, sweepky-core's
/// `MAX_SECRET_BYTES`, the most it wraps with a passphrase, so that every
/// token taken can be written wrapped as well as plain. A bare-grant token
/// is about 600 bytes.
pub(crate) const MAX_GRANT_TOKEN_BYTES: usize = MAX_SECRET_BYTES;

/// The most Sweepky reads of `grant.token`: 4 KiB, sweepky-core's
/// `MAX_WRAPPED_BYTES`, the most it unwraps, so the two caps cannot drift
/// apart (as for `device.key`). A 1 KiB token wrapped is 1206 bytes at most.
const MAX_GRANT_TOKEN_FILE_BYTES: usize = MAX_WRAPPED_BYTES;

/// A Pubky Ring login's grant token, checked to look like one
/// ([`MalformedToken`] lists the checks).
///
/// The text lives only in a [`SecretString`], which wipes it when dropped.
/// The type derives nothing, so it has no `Debug`, `Display`, `Clone`,
/// `PartialEq` or serde impls (checked at compile time in the tests): it
/// cannot be printed, logged, copied or compared by accident. The field is
/// private and both ways to get one, [`GrantToken::from_exported`] and
/// [`read_grant_token`], run the checks, so every `GrantToken` passes them.
pub(crate) struct GrantToken(SecretString);

impl GrantToken {
    /// The token the SDK exported after approval, checked.
    ///
    /// The SDK hands it back as a plain `String` (`export_local_secret`);
    /// taking it by value moves it in at once, so the caller keeps no copy,
    /// and it is wiped here once its one copy into the [`SecretString`] is
    /// made, whether or not the checks pass. A token that fails them is
    /// refused before it is ever written, since no later run would read it
    /// back.
    pub(crate) fn from_exported(exported: String) -> anyhow::Result<Self> {
        // `Zeroizing` wipes the SDK's buffer, spare capacity included, when
        // it is dropped at the end of this function.
        let exported = Zeroizing::new(exported);
        Self::from_bytes(exported.as_bytes())
            .context("the grant token the Pubky SDK handed back is not one Sweepky can save")
    }

    /// The token itself, lent out for the SDK's `restore_session`, which
    /// takes a `&str`. The borrow cannot outlive the `GrantToken`, so no
    /// copy is made here.
    pub(crate) fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }

    /// `bytes` as a token, when they pass every check of
    /// [`MalformedToken`].
    fn from_bytes(bytes: &[u8]) -> Result<Self, MalformedToken> {
        if bytes.len() > MAX_GRANT_TOKEN_BYTES {
            return Err(MalformedToken::TooLong);
        }
        if !bytes.starts_with(GRANT_TOKEN_PREFIX.as_bytes()) {
            return Err(MalformedToken::WrongPrefix);
        }
        // `is_ascii_graphic` is `!` to `~`: no space, no line break, no
        // control byte and nothing that is not ASCII.
        if !bytes.iter().all(u8::is_ascii_graphic) {
            return Err(MalformedToken::NotPrintableAscii);
        }
        // Printable ASCII is always UTF-8, so this cannot fail; it returns
        // the refusal rather than panicking anyway. `from_utf8` borrows the
        // bytes as a `&str`, copying nothing.
        let Ok(text) = std::str::from_utf8(bytes) else {
            return Err(MalformedToken::NotPrintableAscii);
        };
        // One copy, into the `SecretString`, made at exactly the text's
        // length, so turning it into the boxed `str` a `SecretString` holds
        // does not reallocate it and leave an unwiped copy behind. (Handing
        // it the SDK's `String` itself could: a `String` with spare capacity
        // is copied into a new allocation, and the old one freed unwiped.)
        Ok(Self(SecretString::from(text)))
    }
}

/// Why some bytes are not a grant token Sweepky reads.
///
/// Holds no data, so neither its `Display` nor its `Debug` can carry any of
/// the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MalformedToken {
    /// More than [`MAX_GRANT_TOKEN_BYTES`].
    TooLong,
    /// It does not start `pubky-grant-credential-`.
    WrongPrefix,
    /// A space, a line break, a control byte or a byte that is not ASCII.
    NotPrintableAscii,
}

impl fmt::Display for MalformedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => write!(
                f,
                "it is longer than {MAX_GRANT_TOKEN_BYTES} bytes, the most a grant token can be"
            ),
            Self::WrongPrefix => write!(
                f,
                "it does not start with {GRANT_TOKEN_PREFIX}, as every grant token the Pubky \
                 SDK exports does"
            ),
            Self::NotPrintableAscii => f.write_str(
                "it holds a space, a line break, a control character or a character that is not \
                 ASCII; a grant token is one line of printable ASCII with nothing after it",
            ),
        }
    }
}

/// Makes it an error type, so `anyhow` takes it as one and can hand it back
/// by type (`error.downcast_ref::<MalformedToken>()`). `Display` and
/// `Debug` are all the trait needs.
impl std::error::Error for MalformedToken {}

/// Writes `token` to `grant.token` (0600, in the 0700 config directory,
/// which it creates if need be), replacing the file there; wrapped with
/// `passphrase` when there is one.
///
/// Through the one writer of secret files ([`write_secret_file`]): a new
/// 0600 temp file beside it, synced, renamed over the old one, then the
/// directory synced. The mode is set when the file is created, never by a
/// `chmod` afterwards. Every caller holds the writers' lock, so no other
/// command writes the config directory meanwhile.
pub(crate) fn write_grant_token(
    dirs: &Dirs,
    token: &GrantToken,
    passphrase: Option<&Passphrase>,
) -> anyhow::Result<()> {
    ensure_private_dir(dirs.config())?;
    write_secret_file(
        &dirs.grant_token_file(),
        token.expose_secret().as_bytes(),
        passphrase,
    )
}

/// Reads the grant token back from `grant.token`, or `None` when there is no
/// such file. A wrapped file is unwrapped with `passphrase`, and without one
/// is a [`NeedsPassphrase`](crate::passphrase::NeedsPassphrase) error that
/// says how to give it. A file that is not a token is a [`MalformedToken`]
/// error naming the file and none of its content.
pub(crate) fn read_grant_token(
    dirs: &Dirs,
    passphrase: Option<&Passphrase>,
) -> anyhow::Result<Option<GrantToken>> {
    let path = dirs.grant_token_file();
    let Some(stored) = read_private_file(&path, MAX_GRANT_TOKEN_FILE_BYTES)? else {
        return Ok(None);
    };
    // The one unwrap path every secret file goes through; its own errors
    // name the file. `stored` moves in, and the buffer that comes back,
    // plain or unwrapped, wipes itself when dropped at the end of this
    // function, after the token's one copy is made.
    let bytes = open_secret_file(&path, stored, passphrase)?;
    GrantToken::from_bytes(&bytes).map(Some).with_context(|| {
        format!(
            "{} is not a grant token as Sweepky saves one; restore it from a backup of the \
                 config directory, or run `sweepky login` again",
            path.display()
        )
    })
}

/// Deletes `grant.token`, then syncs the config directory. A missing file
/// counts as success, so `logout` can tidy up after a login that left only
/// some of its files.
pub(crate) fn remove_grant_token(dirs: &Dirs) -> anyhow::Result<()> {
    remove_private_file(&dirs.grant_token_file())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use pubky::{Capability, ClientId, GRANT_JWS_TYP, GrantClaims, GrantId, Keypair};
    use sweepky_core::{MAX_SECRET_BYTES, MAX_WRAPPED_BYTES, looks_wrapped};

    use super::{
        GrantToken, MAX_GRANT_TOKEN_BYTES, MalformedToken, read_grant_token, remove_grant_token,
        write_grant_token,
    };
    use crate::Dirs;
    use crate::network::{CLIENT_ID, SWEEPKY_CAPABILITY};
    use crate::passphrase::{NeedsPassphrase, Passphrase};
    use crate::private_fs::{ensure_private_dir, lstat};
    use crate::test_support::{
        PLANTED, TEST_PASSPHRASE, chmod, contains_bytes, dirs_in, mode, private_temp,
    };

    /// A synthetic grant token of the shape and length pubky 0.16.2 exports
    /// for a bare grant (`StoredGrantCredential::encode` in
    /// `actors/auth/grant/credential.rs`): `pubky-grant-credential-v1:`, the
    /// homeserver's z-base32, the client key's 32 bytes in unpadded
    /// base64url, and the grant JWS. The JWS is a real one, signed with a
    /// key made here for the test, for the capability and client id Sweepky
    /// asks for; the client key's 43 characters are a placeholder.
    fn synthetic_token() -> String {
        let user = Keypair::random();
        let iat = 1_792_454_400;
        let claims = GrantClaims {
            iss: user.public_key(),
            client_id: ClientId::new(CLIENT_ID).expect("a valid client id"),
            caps: vec![SWEEPKY_CAPABILITY.parse::<Capability>().expect("valid")],
            cnf: Keypair::random().public_key(),
            jti: GrantId::generate(),
            iat,
            exp: iat + 2 * 365 * 86_400,
        };
        let grant_jws = claims.sign(&user, GRANT_JWS_TYP);
        let homeserver = Keypair::random().public_key().z32();
        let client_key = "A".repeat(43);
        format!("pubky-grant-credential-v1:{homeserver}:{client_key}:{grant_jws}")
    }

    #[test]
    fn the_token_lives_only_in_secret_types() {
        // No way to print, serialize, copy or compare it, checked when the
        // test compiles.
        crate::test_support::assert_not_impl_any!(
            GrantToken: std::fmt::Debug,
            std::fmt::Display,
            serde::Serialize,
            serde::de::DeserializeOwned,
            Clone,
            PartialEq,
        );
    }

    #[test]
    fn token_file_round_trips_0600_in_a_0700_directory() {
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        assert!(read_grant_token(&dirs, None).expect("reads").is_none());

        let exported = synthetic_token();
        let token = GrantToken::from_exported(exported.clone()).expect("accepted");
        write_grant_token(&dirs, &token, None).expect("writes");
        let path = dirs.grant_token_file();
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(dirs.config()), 0o700);
        // The SDK's string exactly, no newline after it.
        assert_eq!(fs::read(&path).expect("read"), exported.as_bytes());
        let read = read_grant_token(&dirs, None)
            .expect("reads")
            .expect("present");
        assert_eq!(read.expose_secret(), exported);

        // Removing it twice: the second time there is nothing, which is
        // success too.
        remove_grant_token(&dirs).expect("removes");
        assert!(lstat(&path).expect("lstat").is_none());
        remove_grant_token(&dirs).expect("a missing file is no error");
    }

    #[test]
    fn a_realistic_token_wraps_and_reads_back_only_with_the_passphrase() {
        // A bare-grant token is about 600 bytes, well under the 1 KiB core
        // wraps, which is also the most this module takes.
        let exported = synthetic_token();
        assert!(
            (500..=700).contains(&exported.len()),
            "{} bytes",
            exported.len()
        );
        assert_eq!(MAX_GRANT_TOKEN_BYTES, MAX_SECRET_BYTES);

        let temp = private_temp();
        let dirs = dirs_in(&temp);
        let passphrase = Passphrase::for_tests(TEST_PASSPHRASE);
        let token = GrantToken::from_exported(exported.clone()).expect("accepted");
        write_grant_token(&dirs, &token, Some(&passphrase)).expect("wraps");

        let path = dirs.grant_token_file();
        assert_eq!(mode(&path), 0o600);
        let raw = fs::read(&path).expect("read");
        assert!(looks_wrapped(&raw));
        assert!(raw.len() <= MAX_WRAPPED_BYTES, "{} bytes", raw.len());
        assert!(!contains_bytes(&raw, b"pubky-grant-credential"));
        let read = read_grant_token(&dirs, Some(&passphrase))
            .expect("unwraps")
            .expect("present");
        assert_eq!(read.expose_secret(), exported);

        let error = read_refusal(&dirs);
        assert!(error.is::<NeedsPassphrase>(), "{error:#}");
    }

    #[test]
    fn a_token_the_sdk_hands_back_is_checked_too() {
        let error = GrantToken::from_exported(format!("cookie-session:{PLANTED}"))
            .err()
            .expect("refused");
        assert_eq!(
            error.downcast_ref::<MalformedToken>(),
            Some(&MalformedToken::WrongPrefix),
            "{error:#}"
        );
        assert!(!format!("{error:#}").contains(PLANTED), "{error:#}");
    }

    #[test]
    fn malformed_token_files_are_refused_without_quoting_them() {
        let prefix = "pubky-grant-credential-v1:";
        let long = "A".repeat(MAX_GRANT_TOKEN_BYTES);
        for (content, expected) in [
            // A cookie session's token, which the SDK's `restore_session`
            // would try as one, or any other text; and an empty file.
            (format!("{PLANTED}:{prefix}x"), MalformedToken::WrongPrefix),
            (String::new(), MalformedToken::WrongPrefix),
            // A newline after it, as an editor leaves, a space, a control
            // byte and a byte that is not ASCII.
            (
                format!("{prefix}{PLANTED}\n"),
                MalformedToken::NotPrintableAscii,
            ),
            (
                format!("{prefix}{PLANTED} x"),
                MalformedToken::NotPrintableAscii,
            ),
            (
                format!("{prefix}{PLANTED}\u{1b}[31m"),
                MalformedToken::NotPrintableAscii,
            ),
            (
                format!("{prefix}{PLANTED}\u{e9}"),
                MalformedToken::NotPrintableAscii,
            ),
            // Within the file's cap but longer than a token can be.
            (format!("{prefix}{PLANTED}{long}"), MalformedToken::TooLong),
        ] {
            let temp = private_temp();
            let dirs = dirs_in(&temp);
            write_raw(&dirs.grant_token_file(), content.as_bytes(), 0o600);
            let error = read_refusal(&dirs);
            assert_eq!(
                error.downcast_ref::<MalformedToken>(),
                Some(&expected),
                "{content:?}: {error:#}"
            );
            let shown = format!("{error:#}");
            assert!(!shown.contains(PLANTED), "{shown}");
            assert!(
                shown.contains(&dirs.grant_token_file().display().to_string()),
                "{shown}"
            );
        }
    }

    #[test]
    fn oversized_linked_or_loose_token_files_are_refused_unread() {
        // Each holds what would pass as a token, so only the file check
        // stands between it and a read.
        let token = format!("pubky-grant-credential-v1:{PLANTED}");

        // Over the file's read cap, checked on the `lstat` before the open.
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        let huge = format!("{token}{}", "A".repeat(MAX_WRAPPED_BYTES));
        write_raw(&dirs.grant_token_file(), huge.as_bytes(), 0o600);
        let shown = format!("{:#}", read_refusal(&dirs));
        assert!(shown.contains("larger than"), "{shown}");
        assert!(!shown.contains(PLANTED), "{shown}");

        // A symbolic link to a private file holding a token.
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        let elsewhere = temp.path().join("elsewhere.token");
        write_raw(&elsewhere, token.as_bytes(), 0o600);
        ensure_private_dir(dirs.config()).expect("mkdir");
        symlink(&elsewhere, dirs.grant_token_file()).expect("symlink");
        let shown = format!("{:#}", read_refusal(&dirs));
        assert!(shown.contains("symbolic link"), "{shown}");
        assert!(!shown.contains(PLANTED), "{shown}");

        // A file other users may read.
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        write_raw(&dirs.grant_token_file(), token.as_bytes(), 0o644);
        let shown = format!("{:#}", read_refusal(&dirs));
        assert!(shown.contains("chmod 600"), "{shown}");
        assert!(!shown.contains(PLANTED), "{shown}");
    }

    /// The error `read_grant_token` gives for the token file in `dirs`, with
    /// no passphrase.
    fn read_refusal(dirs: &Dirs) -> anyhow::Error {
        read_grant_token(dirs, None).err().expect("refused")
    }

    /// Writes `bytes` to `path` with `file_mode`, making its directory 0700
    /// first, as a person editing the config directory by hand might.
    fn write_raw(path: &std::path::Path, bytes: &[u8], file_mode: u32) {
        ensure_private_dir(path.parent().expect("a parent")).expect("mkdir");
        fs::write(path, bytes).expect("write");
        chmod(path, file_mode);
    }
}
