//! `sweepky login` without `--identity`: login option A, the Pubky Ring
//! sign-in, from the checks before the flow to the report (03, "Two ways to
//! log in").
//!
//! In order ([`login`]):
//!
//! 1. **Checks before any request** ([`check_install_is_free`]), files only:
//!    `login.json` must not exist (an install logged in with `--identity`
//!    is told to log out first or use another `SWEEPKY_HOME`, and for now so
//!    is one already logged in through Ring), and nothing may be at
//!    `device.key`, which `login.json` would then not record: P2a's rule
//!    that Sweepky never replaces a device key, run here before the human
//!    scans a code rather than after. Only the path is looked at, so a
//!    wrapped key file stops the login the same way without
//!    `--passphrase-file`. A `grant.token` that `login.json` does not record
//!    is noted, not refused.
//! 2. **The approval** ([`sign_in_with_ring`]), with no lock held: a human
//!    may take minutes to scan, and every other command on the install
//!    would wait for the lock that long. It asks no question on standard
//!    input, so `--no-input` does not stop it.
//! 3. **What the grant is** ([`ApprovedGrant::of`]): its pubky, homeserver
//!    and expiry, as the homeserver reports them with the session, and the
//!    grant token the SDK exports, moved into a [`GrantToken`] in the same
//!    statement.
//! 4. **Under the writers' lock** ([`save_grant`]): the checks of step 1
//!    again, since another login may have finished meanwhile; the token
//!    saved to `grant.token` (0600, wrapped with `--passphrase-file`); then
//!    P2a's shared tail with the grant's session (`login`'s
//!    [`record_login_and_check_keys`]): this install's device key made,
//!    saved, recorded in `installs.json` and published as
//!    `keys/<deviceId>.json`, the write that proves the grant can write
//!    `/pub/sweepky/`, then `login.json` written as a `ring` login, then the
//!    check of `keys/`.
//! 5. **The report** ([`report`]): who and where, the grant's expiry in RFC
//!    3339 and that it is two years from approval, the device key and the
//!    reminder to back up the config directory, the files wrapped, and the
//!    key check.
//!
//! **Ordering.** `login.json` never names a Ring login whose token is not
//! on disk: the token is written just before the tail, and the tail writes
//! `login.json` last. Nothing the user will not use stays valid: a grant
//! that is not saved (its details cannot be read, the lock cannot be
//! taken, another login won the race, or the tail failed) is signed out,
//! which revokes it on the homeserver, and a token written for it is
//! removed again. A grant that is saved is *not* signed out, since that
//! would revoke it; its session is dropped, and later commands restore it
//! from the token.
//!
//! **Secrets.** Neither the token nor the sign-in link is ever printed:
//! the report names the token's file only, and every SDK error reaches the
//! user through `remote::request_error` or `remote::write_error`, in fixed
//! text.

use anyhow::{Context as _, bail};
use pubky::{PubkySession, PublicKey};
use sweepky_core::{DeviceId, Pubky, Zeroizing};

use super::expiry_text;
use super::flow::{LOGIN_TIMEOUT, sign_in_with_ring};
use super::token::{GrantToken, remove_grant_token, write_grant_token};
use crate::device::{KeyIds, KeyStore, PublicKeys, SessionKeyStore, refuse_unrecorded_device_key};
use crate::login::{TailOutcome, device_key_report, record_login_and_check_keys, wrapped_report};
use crate::private_fs::lstat;
use crate::remote::pubky_of;
use crate::session::{sign_out, with_writers_lock};
use crate::state::{KnownLoginKind, LoginState, read_login_state};
use crate::{Context, Dirs, Report};

/// What the error of a login that saved nothing says, once the grant Ring
/// approved has been signed out again.
const NOT_SAVED: &str = "login saved nothing and signed the grant Pubky Ring approved out again, \
     which revokes it";

/// Runs `sweepky login` without `--identity`: steps 1 to 5 of the module
/// docs.
pub(crate) async fn login(ctx: &Context) -> anyhow::Result<Report> {
    // 1. Files only, before any request. The orphan token it notes is
    // looked at again under the lock, where it counts.
    check_install_is_free(&ctx.dirs)?;
    // 2. No lock held while the human scans.
    let session = sign_in_with_ring(ctx, LOGIN_TIMEOUT).await?;
    // 3. A grant whose details cannot be read is not saved, so it is
    // signed out before the error is returned.
    let grant = match ApprovedGrant::of(&session).await {
        Ok(grant) => grant,
        Err(error) => {
            sign_out(ctx, session).await;
            return Err(error.context(NOT_SAVED));
        }
    };
    // 4. The store owns the session from here, so whichever way
    // `save_grant` ends, it decides the session's fate: signed out on a
    // failure, dropped (still valid) on success.
    let keys = GrantKeyStore {
        session,
        client: ctx.network.pubky(),
    };
    let saved = save_grant(ctx, &grant, keys, async |keys| {
        sign_out(ctx, keys.session).await;
    })
    .await?;
    // 5.
    Ok(Report::new(report(ctx, &grant, &saved)))
}

// ---------------------------------------------------------------------------
// Before the flow, and again under the lock.

/// Refuses a Ring login on this install when `login.json` exists or a
/// device key is at `device.key`, reading files only; otherwise says
/// whether a `grant.token` is there that `login.json` does not record.
///
/// Such a token is what a login that stopped between the token's write and
/// `login.json` leaves. It is replaced, not refused (`rename` swaps the
/// file whole), but its grant may still be live, so the report warns.
fn check_install_is_free(dirs: &Dirs) -> anyhow::Result<bool> {
    if let Some(current) = read_login_state(dirs)? {
        bail!(already_logged_in(&current));
    }
    refuse_unrecorded_device_key(dirs)?;
    Ok(lstat(&dirs.grant_token_file())?.is_some())
}

/// The refusal for an install whose `login.json` already records a login.
/// The name and the pubky are values this install wrote itself and checked
/// when reading them, so they are safe to print.
fn already_logged_in(current: &LoginState) -> String {
    match (current.kind.as_known(), &current.name) {
        (Some(KnownLoginKind::Identity), Some(name)) => format!(
            "this install is logged in with the dedicated identity {name}, pubky {}, so it \
             cannot also log in through Pubky Ring; run `sweepky logout` first, or set \
             SWEEPKY_HOME to another directory to keep a Ring login apart",
            current.pubky
        ),
        _ => format!(
            "this install is already logged in as {}; run `sweepky logout` first to log in \
             through Pubky Ring, or set SWEEPKY_HOME to another directory to keep a second \
             login apart",
            current.pubky
        ),
    }
}

// ---------------------------------------------------------------------------
// The approved grant.

/// What `login` keeps of the grant Ring approved: the token, and the public
/// details `login.json` records.
///
/// No `Debug`: the token has none, so the compiler could not derive one.
struct ApprovedGrant {
    /// The grant token the SDK exported, the bearer of the grant.
    token: GrantToken,
    /// The pubky that approved, as the homeserver reports it.
    pubky: Pubky,
    /// The homeserver that issued the session.
    homeserver: Pubky,
    /// When the grant expires, Unix seconds: the grant's `exp`.
    expires_at: u64,
}

impl ApprovedGrant {
    /// Reads the grant behind `session`: its details from the homeserver's
    /// session info, and its exported token.
    async fn of(session: &PubkySession) -> anyhow::Result<Self> {
        // `as_grant` is `None` for a cookie session, which a grant flow never
        // gives; the view it returns borrows `session`.
        let Some(grant) = session.as_grant() else {
            bail!("the Pubky Ring sign-in did not give a grant session");
        };
        let info = grant.session_info().await;
        // `export_local_secret` hands the token back as a plain `String`.
        // `map` moves it straight into `GrantToken::from_exported`, which
        // wipes the `String` once its one copy is in a `SecretString`, all in
        // this one statement, so no variable ever holds it as plain text.
        // `transpose` turns the `Option<Result<_>>` into a `Result<Option<_>>`
        // for the `?`. `None` is a browser-held client key, which a CLI
        // never has.
        let Some(token) = grant
            .export_local_secret()
            .await
            .map(GrantToken::from_exported)
            .transpose()?
        else {
            bail!("the Pubky SDK handed back no grant token to save");
        };
        Ok(Self {
            token,
            pubky: pubky_of(&info.pubky),
            homeserver: pubky_of(&info.homeserver),
            expires_at: info.grant_expires_at,
        })
    }
}

/// The approved grant's session, owned, as the [`KeyStore`] the shared tail
/// writes through.
///
/// [`SessionKeyStore`] only borrows a session, so a store made from one
/// would keep the session borrowed for as long as the store lives, and the
/// sign-out after a failed tail, which takes the session by value, could
/// not run. Owning it here lets [`save_grant`] hand the whole store to the
/// sign-out instead. Each call makes a borrowing store on the spot, which
/// costs nothing (two references).
///
/// No `Debug`: the session holds the grant's credential.
struct GrantKeyStore<'a> {
    session: PubkySession,
    client: &'a pubky::Pubky,
}

impl GrantKeyStore<'_> {
    /// A store borrowing this one's session and client.
    fn borrowed(&self) -> SessionKeyStore<'_> {
        SessionKeyStore::new(&self.session, self.client)
    }
}

impl PublicKeys for GrantKeyStore<'_> {
    async fn list_key_ids(&self, owner: &PublicKey) -> anyhow::Result<KeyIds> {
        self.borrowed().list_key_ids(owner).await
    }

    async fn get_key(
        &self,
        owner: &PublicKey,
        id: &DeviceId,
    ) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
        self.borrowed().get_key(owner, id).await
    }
}

impl KeyStore for GrantKeyStore<'_> {
    async fn get_own_key(&self, id: &DeviceId) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
        self.borrowed().get_own_key(id).await
    }

    async fn put_key(&self, id: &DeviceId, record: Vec<u8>) -> pubky::Result<()> {
        self.borrowed().put_key(id, record).await
    }
}

// ---------------------------------------------------------------------------
// Saving it, under the writers' lock.

/// What [`save_grant`] did.
#[derive(Debug)]
struct Saved {
    /// What the shared tail did.
    tail: TailOutcome,
    /// Whether a `grant.token` that `login.json` did not record was there,
    /// and was replaced.
    replaced_token: bool,
}

/// Saves `grant` under the writers' lock ([`save_locked`]), with `keys` as
/// the grant's session; and when that fails, for any reason, signs the
/// grant out through `sign_out` before the error is returned.
///
/// Generic over the [`KeyStore`] `K`, with the sign-out passed in as an
/// async closure, as `logout::retire` does, so the unit tests run it with
/// a fake store and see whether, and how often, it signs out. The lock
/// work only borrows `keys` (`&keys`); that borrow ends when the work's
/// future is done, so `keys` can then move into `sign_out`, which takes it
/// by value and so ends the session. On success `keys` is dropped at the
/// end of this function instead, and the grant stays valid.
async fn save_grant<K: KeyStore>(
    ctx: &Context,
    grant: &ApprovedGrant,
    keys: K,
    sign_out: impl AsyncFnOnce(K),
) -> anyhow::Result<Saved> {
    let saved = with_writers_lock(ctx, async || save_locked(ctx, grant, &keys).await).await;
    if saved.is_err() {
        sign_out(keys).await;
    }
    saved.context(NOT_SAVED)
}

/// [`save_grant`]'s work under the lock: the checks again, the token, the
/// shared tail. A tail that fails removes the token again: the tail has
/// rolled its own files back by then, and wrote no `login.json`, so the
/// token would be a secret nothing uses.
async fn save_locked(
    ctx: &Context,
    grant: &ApprovedGrant,
    keys: &impl KeyStore,
) -> anyhow::Result<Saved> {
    let dirs = &ctx.dirs;
    let passphrase = ctx.passphrase.as_ref();
    // Another login may have finished while the human was scanning.
    let replaced_token = check_install_is_free(dirs)?;
    write_grant_token(dirs, &grant.token, passphrase)?;
    let state = LoginState::ring(grant.pubky, grant.homeserver, grant.expires_at);
    match record_login_and_check_keys(dirs, passphrase, keys, state).await {
        Ok(tail) => Ok(Saved {
            tail,
            replaced_token,
        }),
        Err(error) => Err(match remove_grant_token(dirs) {
            Ok(()) => error,
            Err(left) => error.context(format!(
                "could not remove {} again ({left:#}); delete it by hand",
                dirs.grant_token_file().display()
            )),
        }),
    }
}

// ---------------------------------------------------------------------------
// The report.

/// What `login` reports after a Ring login: fixed text, the user's own
/// pubky, homeserver and paths, and the grant's expiry.
fn report(ctx: &Context, grant: &ApprovedGrant, saved: &Saved) -> String {
    let dirs = &ctx.dirs;
    let token_file = dirs.grant_token_file();
    let mut text = format!(
        "Logged in through Pubky Ring as {}, on homeserver {}.\n\
         Saved the grant token in {}. The grant expires at {}, two years from your approval in \
         Ring, a lifetime the Pubky SDK fixes; Sweepky warns within 30 days of it, and `sweepky \
         login` then approves a new one.\n",
        grant.pubky,
        grant.homeserver,
        token_file.display(),
        expiry_text(grant.expires_at)
    );
    if saved.replaced_token {
        text.push_str(
            "warning: an earlier grant.token was there with no login.json, as a login that \
             stopped halfway leaves it, and was replaced; its sweepky-cli grant may still be \
             listed in Pubky Ring, so revoke it there if it is.\n",
        );
    }
    text.push_str(&device_key_report(dirs, &saved.tail.device));
    // A first Ring login always makes a new device key, so with a
    // passphrase both files this run wrote are wrapped.
    if ctx.passphrase.is_some() {
        text.push_str(&wrapped_report(&[token_file, dirs.device_key_file()]));
    }
    text.push_str(&saved.tail.key_check);
    text
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{self, Cursor};
    use std::time::{SystemTime, UNIX_EPOCH};

    use clap::Parser as _;
    use pubky::{Capabilities, StatusCode};
    use serde_json::Value;
    use sweepky_core::{DeviceIdentity, DeviceKey, MAX_RECORD_BYTES, SecretString, looks_wrapped};
    use tokio::sync::mpsc::UnboundedReceiver;
    use tokio::sync::mpsc::error::TryRecvError;
    use url::Url;

    use super::{ApprovedGrant, NOT_SAVED, save_grant};
    use crate::cli::Cli;
    use crate::device::{
        PublicKeyReader, PublicKeys as _, create_device_key, holds_key, read_device_key,
    };
    use crate::identity::IdentityName;
    use crate::installs::read_installs;
    use crate::passphrase::Passphrase;
    use crate::private_fs::{ensure_private_dir, lstat};
    use crate::remote::{WRITE_FORBIDDEN, pubky_of};
    use crate::ring::expiry_text;
    use crate::ring::flow::NARROWED_GRANT;
    use crate::ring::token::{GrantToken, read_grant_token};
    use crate::state::{LoginState, read_login_state, write_login_state};
    use crate::test_support::{
        FAKE_SERVER_TEXT, FakeKeyStore, KeyStoreCall, PLANTED, RingPage, RingStandIn,
        TEST_PASSPHRASE, mode, offline_network, private_temp, random_pubky, ring_context,
        ring_network, ring_testnet,
    };
    use crate::{Context, Dirs};

    /// Two years in seconds, the grant lifetime the SDK fixes.
    const TWO_YEARS: u64 = 2 * 365 * 86_400;

    /// A synthetic token that passes `GrantToken`'s checks; only the unit
    /// tests below, which never send it anywhere, use it.
    fn synthetic_token() -> String {
        format!("pubky-grant-credential-v1:{PLANTED}")
    }

    /// Seconds since the Unix epoch, now.
    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("after 1970")
            .as_secs()
    }

    /// Asserts that nothing is at `path`, not even a dangling link.
    fn assert_gone(path: &std::path::Path) {
        assert!(
            lstat(path).expect("lstat").is_none(),
            "{} is there",
            path.display()
        );
    }

    /// Asserts that no Ring login was saved in `dirs`: no `login.json`, no
    /// `grant.token`, no `device.key`, and no install entry for `owner`.
    fn assert_nothing_saved(dirs: &Dirs, owner: &sweepky_core::Pubky) {
        assert_gone(&dirs.login_file());
        assert_gone(&dirs.grant_token_file());
        assert_gone(&dirs.device_key_file());
        assert!(read_installs(dirs).expect("reads").ids_of(owner).is_empty());
    }

    /// Asserts that no sign-in flow started: the browser seam was handed
    /// no page URL.
    fn assert_no_flow(urls: &mut UnboundedReceiver<Url>) {
        assert!(matches!(urls.try_recv(), Err(TryRecvError::Empty)));
    }

    /// An approved grant for the unit tests, with a synthetic token and
    /// random keys.
    fn approved() -> ApprovedGrant {
        ApprovedGrant {
            token: GrantToken::from_exported(synthetic_token()).expect("a token"),
            pubky: random_pubky(),
            homeserver: random_pubky(),
            expires_at: now() + TWO_YEARS,
        }
    }

    /// Runs `save_grant` for `grant` with `keys`, counting the sign-outs.
    async fn save_with(
        ctx: &Context,
        grant: &ApprovedGrant,
        keys: FakeKeyStore,
    ) -> (anyhow::Result<super::Saved>, Vec<FakeKeyStore>) {
        // The sign-out gets the store back by value, as the real one gets
        // the session; keeping it lets the test count the calls and look at
        // what the store was asked.
        let mut signed_out = Vec::new();
        let saved = save_grant(ctx, grant, keys, async |keys| signed_out.push(keys)).await;
        (saved, signed_out)
    }

    #[tokio::test]
    async fn a_failed_tail_removes_the_token_and_signs_the_grant_out() {
        let home = private_temp();
        let (ctx, stderr, _urls) = ring_context(offline_network(), &home, io::empty());
        let grant = approved();

        let (saved, signed_out) = save_with(
            &ctx,
            &grant,
            FakeKeyStore::refusing_puts(StatusCode::FORBIDDEN),
        )
        .await;
        let Err(error) = saved else {
            panic!("a refused probe saved the login");
        };
        // write_error's message for a 403, never the server's own text, and
        // never the token.
        assert_eq!(error.root_cause().to_string(), WRITE_FORBIDDEN);
        let shown = format!("{error:#}");
        assert!(shown.starts_with(NOT_SAVED), "{shown}");
        assert!(!shown.contains(FAKE_SERVER_TEXT), "{shown}");
        assert!(!shown.contains(PLANTED), "{shown}");
        assert!(!stderr.text().contains(PLANTED));

        // Signed out once, after the one PUT of the probe.
        let [keys] = signed_out.as_slice() else {
            panic!("signed out {} times", signed_out.len());
        };
        assert!(matches!(keys.calls().as_slice(), [KeyStoreCall::PutKey(_)]));
        // The token is gone again, login.json was never written, and P2a's
        // tail rolled its device key and install entry back.
        assert_nothing_saved(&ctx.dirs, &grant.pubky);
    }

    #[tokio::test]
    async fn a_login_that_finished_meanwhile_wins_and_the_grant_is_signed_out() {
        let home = private_temp();
        let (ctx, _stderr, _urls) = ring_context(offline_network(), &home, io::empty());
        let grant = approved();
        // Another `sweepky login` wrote login.json while this one waited
        // for Ring.
        let other = LoginState::ring(random_pubky(), random_pubky(), now() + TWO_YEARS);
        write_login_state(&ctx.dirs, &other).expect("writes");

        let (saved, signed_out) = save_with(&ctx, &grant, FakeKeyStore::default()).await;
        let Err(error) = saved else {
            panic!("saved over another login");
        };
        assert!(
            format!("{error:#}").contains("already logged in"),
            "{error:#}"
        );
        let [keys] = signed_out.as_slice() else {
            panic!("signed out {} times", signed_out.len());
        };
        // Refused before anything was written or sent.
        assert!(keys.calls().is_empty());
        assert_gone(&ctx.dirs.grant_token_file());
        assert_eq!(read_login_state(&ctx.dirs).expect("reads"), Some(other));
    }

    #[tokio::test]
    async fn identity_flags_without_identity_are_refused_unquoted() {
        let home = private_temp();
        let (ctx, _stderr, mut urls) = ring_context(offline_network(), &home, io::empty());
        let token = SecretString::from(PLANTED);
        for (homeserver, signup_token, flag) in [
            (Some(PLANTED), None, "--homeserver"),
            (None, Some(&token), "--signup-token"),
        ] {
            let error = crate::login::login(&ctx, None, homeserver, signup_token)
                .await
                .expect_err("refused");
            let shown = format!("{error:#}");
            assert!(shown.starts_with(flag), "{shown}");
            assert!(shown.contains("--identity"), "{shown}");
            assert!(!shown.contains(PLANTED), "{shown}");
        }
        // Before any request, and before any file: not even the config
        // directory was made.
        assert_no_flow(&mut urls);
        assert_gone(ctx.dirs.config());
    }

    #[tokio::test]
    async fn one_login_per_install_either_way_round() {
        let home = private_temp();
        let (ctx, _stderr, mut urls) = ring_context(offline_network(), &home, io::empty());
        let name: IdentityName = "throwaway".parse().expect("a name");

        // Logged in with --identity: a Ring login is refused before the flow.
        let identity = LoginState::identity(name, random_pubky(), random_pubky());
        write_login_state(&ctx.dirs, &identity).expect("writes");
        let shown = format!(
            "{:#}",
            crate::login::login(&ctx, None, None, None)
                .await
                .expect_err("refused")
        );
        for part in ["throwaway", "`sweepky logout`", "SWEEPKY_HOME"] {
            assert!(shown.contains(part), "{part:?} missing from: {shown}");
        }
        assert_no_flow(&mut urls);

        // Logged in through Ring: `login --identity` is refused by P2a's
        // plan, which allows only the identity logged in.
        let ring = LoginState::ring(random_pubky(), random_pubky(), now() + TWO_YEARS);
        write_login_state(&ctx.dirs, &ring).expect("writes");
        let shown = format!(
            "{:#}",
            crate::login::login(&ctx, Some("x"), None, None)
                .await
                .expect_err("refused")
        );
        assert!(
            shown.contains(&format!("already logged in as {}", ring.pubky)),
            "{shown}"
        );
        assert!(shown.contains("`sweepky logout`"), "{shown}");
        assert_eq!(read_login_state(&ctx.dirs).expect("reads"), Some(ring));
    }

    #[tokio::test]
    async fn an_unrecorded_device_key_stops_a_first_ring_login_before_the_flow() {
        // Plain, and wrapped with no --passphrase-file given: either way
        // only the path is looked at, so neither needs the passphrase.
        let passphrase = Passphrase::for_tests(TEST_PASSPHRASE);
        for wrap in [None, Some(&passphrase)] {
            let home = private_temp();
            let (ctx, _stderr, mut urls) = ring_context(offline_network(), &home, io::empty());
            let orphan = DeviceIdentity::generate();
            create_device_key(&ctx.dirs, &orphan, wrap).expect("writes device.key");
            let before = fs::read(ctx.dirs.device_key_file()).expect("reads");

            let error = crate::login::login(&ctx, None, None, None)
                .await
                .expect_err("refused");
            // P2a's rule, in P2a's words, and not the error any request on
            // the offline network would have given.
            let shown = format!("{error:#}");
            assert!(shown.contains("never replaces a device key"), "{shown}");
            assert_no_flow(&mut urls);
            assert_eq!(fs::read(ctx.dirs.device_key_file()).expect("reads"), before);
            assert_gone(&ctx.dirs.login_file());
            assert_gone(&ctx.dirs.grant_token_file());
        }
    }

    #[tokio::test]
    #[pubky_testnet::test]
    async fn a_first_ring_login_saves_the_grant_and_publishes_the_device_key() {
        let testnet = ring_testnet().await;
        let home = private_temp();
        let (ctx, stderr, mut urls) = ring_context(ring_network(&testnet), &home, io::empty());
        let ring = RingStandIn::sign_up(&testnet).await;

        let (logged_in, ()) = tokio::join!(crate::login::login(&ctx, None, None, None), async {
            let page = RingPage::open(&mut urls).await;
            ring.approve(&page).await;
        });
        let report = logged_in.expect("logs in");
        let report = report.text();
        let dirs = &ctx.dirs;
        let owner = pubky_of(&ring.public_key());

        // grant.token is 0600 and restores a session as the approver.
        assert_eq!(mode(&dirs.grant_token_file()), 0o600);
        let token = read_grant_token(dirs, None)
            .expect("reads")
            .expect("present");
        let Ok(restored) = testnet
            .sdk()
            .expect("client")
            .restore_session(token.expose_secret())
            .await
        else {
            panic!("the saved token does not restore");
        };
        assert_eq!(restored.public_key(), ring.public_key());

        // login.json is a `ring` login with the grant's expiry, about two
        // years from now, and no name.
        let login: Value =
            serde_json::from_slice(&fs::read(dirs.login_file()).expect("reads")).expect("JSON");
        assert_eq!(login["schemaVersion"], 1);
        assert_eq!(login["kind"], "ring");
        assert_eq!(login["pubky"], owner.to_string());
        assert_eq!(
            login["homeserver"],
            pubky_of(&testnet.homeserver_app().public_key()).to_string()
        );
        assert_eq!(login.get("name"), None);
        let expires_at = login["grantExpiresAt"].as_u64().expect("a number");
        assert!(
            expires_at.abs_diff(now() + TWO_YEARS) < 3 * 86_400,
            "expires at {expires_at}"
        );
        let id = login["deviceId"]
            .as_str()
            .expect("a device id")
            .parse()
            .expect("valid");

        // device.key is 0600, and installs.json lists its id with its key.
        assert_eq!(mode(&dirs.device_key_file()), 0o600);
        let local = read_device_key(dirs, None)
            .expect("reads")
            .expect("present")
            .recipient();
        let installs = read_installs(dirs).expect("reads");
        let [install] = installs.installs_of(&owner) else {
            panic!("one install expected");
        };
        assert_eq!(install.device_id, id);
        assert_eq!(install.recipient.as_ref(), Some(&local));

        // Done when: the grant wrote keys/<deviceId>.json, readable by
        // anyone within the record cap, unrevoked, holding device.key's key.
        let anonymous = testnet.sdk().expect("client");
        let bytes = PublicKeyReader::new(&anonymous)
            .get_key(&ring.public_key(), &id)
            .await
            .expect("reads")
            .expect("published");
        assert!(bytes.len() <= MAX_RECORD_BYTES);
        let raw: Value = serde_json::from_slice(&bytes).expect("JSON");
        assert_eq!(raw["revokedAt"], Value::Null);
        let record = DeviceKey::from_json(&bytes).expect("a device key record");
        assert!(!record.is_revoked());
        assert!(holds_key(&record, &local).expect("a usable key"));

        // The report: the expiry in RFC 3339, two years from approval, the
        // backup reminder naming the config directory, and the key check,
        // which found nothing to say. Never the token, here or on stderr.
        assert!(report.contains(&expiry_text(expires_at)), "{report}");
        assert!(report.contains("two years from your approval"), "{report}");
        assert!(
            report.contains(&format!("Back up {}", dirs.config().display())),
            "{report}"
        );
        assert!(report.contains(&format!("keys/{id}.json")), "{report}");
        assert!(!report.contains("alarm"), "{report}");
        assert!(!report.contains("could not check keys/"), "{report}");
        assert!(!report.contains("Wrapped"), "{report}");
        assert!(!report.contains(token.expose_secret()), "{report}");
        assert!(!stderr.text().contains(token.expose_secret()));
    }

    #[tokio::test]
    #[pubky_testnet::test]
    async fn a_narrowed_approval_through_login_saves_nothing() {
        let testnet = ring_testnet().await;
        let home = private_temp();
        let (ctx, _stderr, mut urls) = ring_context(ring_network(&testnet), &home, io::empty());
        let ring = RingStandIn::sign_up(&testnet).await;
        let read_only = Capabilities::builder()
            .read("/pub/sweepky/")
            .expect("a scope")
            .finish();

        let (logged_in, ()) = tokio::join!(crate::login::login(&ctx, None, None, None), async {
            let page = RingPage::open(&mut urls).await;
            ring.approve_with(&page, &read_only).await;
        });
        let error = logged_in.expect_err("refused");
        assert_eq!(format!("{error:#}"), NARROWED_GRANT);
        assert_nothing_saved(&ctx.dirs, &pubky_of(&ring.public_key()));
    }

    #[tokio::test]
    #[pubky_testnet::test]
    async fn no_input_login_wraps_both_files_and_replaces_an_orphan_token() {
        let testnet = ring_testnet().await;
        let home = private_temp();
        // Were anything asked, `--no-input` would fail it at once, and the
        // `no` waiting on stdin would stop it otherwise.
        let (mut ctx, _stderr, mut urls) =
            ring_context(ring_network(&testnet), &home, Cursor::new(b"no\n".to_vec()));
        ctx.passphrase = Some(Passphrase::for_tests(TEST_PASSPHRASE));
        // A grant.token with no login.json, as a crash between the token's
        // write and login.json's leaves.
        ensure_private_dir(ctx.dirs.config()).expect("mkdir");
        fs::write(ctx.dirs.grant_token_file(), synthetic_token()).expect("writes");
        let ring = RingStandIn::sign_up(&testnet).await;

        let cli = Cli::try_parse_from(["sweepky", "--no-input", "login"]).expect("parses");
        let (logged_in, ()) = tokio::join!(crate::run(cli, &ctx), async {
            let page = RingPage::open(&mut urls).await;
            ring.approve(&page).await;
        });
        let report = logged_in.expect("logs in");
        let report = report.text();
        let dirs = &ctx.dirs;

        // Both secret files this run wrote are wrapped, and the report
        // names both.
        let token_file = fs::read(dirs.grant_token_file()).expect("reads");
        assert!(looks_wrapped(&token_file));
        assert!(looks_wrapped(
            &fs::read(dirs.device_key_file()).expect("reads")
        ));
        for path in [dirs.grant_token_file(), dirs.device_key_file()] {
            assert!(report.contains(&path.display().to_string()), "{report}");
        }
        assert!(report.contains("Wrapped"), "{report}");
        // The orphan was replaced whole, and the report warns of its grant.
        let token = read_grant_token(dirs, ctx.passphrase.as_ref())
            .expect("unwraps")
            .expect("present");
        assert_ne!(token.expose_secret(), synthetic_token());
        assert!(
            report.contains("may still be listed in Pubky Ring"),
            "{report}"
        );
        assert!(read_login_state(dirs).expect("reads").is_some());
    }
}
