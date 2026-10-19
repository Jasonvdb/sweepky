//! `sweepky login --identity <name> [--homeserver <pk>] [--signup-token
//! <code>]`: login option B, a dedicated identity the CLI holds itself.
//!
//! The flow, every step after the first under the writers' lock:
//!
//! 1. **Classify the argument.** `--identity` must be a name
//!    ([`IdentityName::from_arg`]); a recovery file, raw key or recovery
//!    phrase gets its one-line refusal and is never imported. `--homeserver`
//!    is parsed with the SDK's `PublicKey`, which also checks that the key is
//!    a valid Ed25519 point.
//! 2. **Plan** ([`plan_login`], pure): which homeserver, whether to sign up,
//!    and whether to warn. It refuses a second identity on an install that is
//!    already logged in, a homeserver that disagrees with the identity's own
//!    record, and a signup on homeserver.pubky.app without a token.
//! 3. **Create or reuse the identity.** A new one is written to disk (secret,
//!    then details with `signedUp: false`) *before* anything goes out, so a
//!    crash can never lose a signup token already spent on it. A key file
//!    without its details, as P2c copies it, gets its details back from the
//!    key and the identity's pkarr record.
//! 4. **Sign up** if the details say it has not: `PubkySigner::signup`, then
//!    `signedUp: true`. A 409 ("user already exists") counts as done.
//! 5. **Sign in** with `signin_blocking`, which waits until the identity's
//!    pkarr record is published.
//! 6. **The shared tail**, on this install's first login (`login.json`
//!    records no device id for this pubky yet), with the session open
//!    ([`record_login`]): a new age device key, its secret in `device.key`
//!    (0600), its id and public key in `installs.json` under this owner, and
//!    then the write of `keys/<deviceId>.json`. That write is also the check
//!    that this identity may write under `/pub/sweepky/` at all: a 403 or a
//!    507 aborts with its own message ([`crate::remote::write_error`]), and
//!    any failure removes the key file and the install entry this run made,
//!    and nothing else; the identity stays. On a later login (`login.json`
//!    records a device id) the tail reuses that key instead, one age key per
//!    install: it reads `device.key`, reads `keys/<deviceId>.json` back,
//!    publishes it again if it is gone, and refuses, changing nothing, when
//!    the file is missing or the record is revoked or holds another key
//!    ([`reuse_device_key`]).
//! 7. **Record and sign out**: write `login.json`, with the device id, and
//!    sign out again: every later command signs in and out on its own
//!    ([`crate::session`]). The report ends with the reminder to back up the
//!    config directory when a new key was made.
//! 8. **Check `keys/`** (before the sign-out, [`check_key_ids`]): list the
//!    identity's `keys/` and raise 02's alarm for every id this owner's
//!    installs did not create and whose record is not revoked, and for every
//!    id they did create whose unrevoked record no longer holds the key
//!    `installs.json` records for it, the same check, with the same bounds,
//!    that `keys list` makes (`keys::key_alarms`). A check that cannot
//!    finish (`keys::KeyCheckError`: the listing fails or is past its
//!    limits, the records pass the check's byte budget, or a known id's
//!    record cannot be read) is a warning in the report; login has done its
//!    work by then. `pull` prints the same failure as an alarm.
//!
//! **The passphrase.** With `--passphrase-file`, the two secret files login
//! creates, the identity's key file (step 3) and `device.key` (step 6), are
//! written wrapped with that passphrase, and every secret file it reads is
//! unwrapped with it ([`crate::passphrase::open_secret_file`]). A wrapped file
//! read without the flag stops login before anything is written, with how
//! to give it. Files that already exist are never rewritten, so the flag
//! never wraps or unwraps a file that is there.
//!
//! **The signup token is never printed.** The SDK puts it in the signup
//! request's URL (`?signup_token=…`), and a transport error's `Display`
//! includes that URL, so a failed signup is reported as fixed text and the
//! HTTP status only ([`signup_error`]), never through the SDK's own message.

use std::fmt;
use std::path::PathBuf;

use anyhow::{Context as _, anyhow, bail};
use pubky::{PubkySigner, PublicKey, StatusCode};
use sweepky_core::{
    AgeRecipient, DeviceId, DeviceIdentity, DeviceKey, ExposeSecret, Pubky, SecretString,
};

use crate::clock;
use crate::device::{
    KeyStore, PublicKeys, SessionKeyStore, create_device_key, device_key_bytes, device_key_record,
    holds_key, new_device_id, read_device_key, remove_device_key,
};
use crate::identity::{IdentityMeta, IdentityName, IdentitySecret, read_argument_file};
use crate::installs::{forget_install, read_installs, record_install_key, replaced_key_alarm};
use crate::keys::{KeyAlarm, key_alarms};
use crate::network::{NetworkKind, client_id};
use crate::passphrase::{NeedsPassphrase, Passphrase};
use crate::remote::{pubky_of, public_key_of, request_error, status_of, write_error};
use crate::session::{sign_out, with_writers_lock};
use crate::state::{
    LoginState, StoredIdentity, create_identity, read_identity, read_login_state,
    write_identity_meta, write_login_state,
};
use crate::{Context, Dirs, Report};

/// What `login` without `--identity` says until P2d builds the Ring sign-in.
const RING_LOGIN_LATER: &str =
    "the Pubky Ring sign-in arrives in a later build; use --identity <name>";

/// Why a signup on homeserver.pubky.app needs `--signup-token`, and the ways
/// to get one, from 06 ("Production homeserver").
const SIGNUP_TOKEN_NEEDED: &str = "signing a new identity up on homeserver.pubky.app needs a \
     signup token: pass --signup-token <code>. Ways to get one: from Homegate \
     (homegate.pubky.app), by SMS verification, Google sign-in or a Lightning payment; the `st` \
     parameter of the \"copy sign-up link\" on pubky.app's sign-up page; or the code in an invite \
     link, pubky.app/invite/<code>. A token from Homegate's free IP verification allows only Paykit \
     and Bitkit paths, so Sweepky's first write would be refused";

/// What `--homeserver` takes, said when its value is not that. The value is
/// not quoted: a secret key pasted into the wrong flag must not be printed.
const NOT_A_HOMESERVER: &str = "--homeserver takes a homeserver's public key: 52 characters of \
     z-base32, with or without the pubky prefix, that are a valid Ed25519 public key";

// ---------------------------------------------------------------------------
// The plan: pure, so every rule is tested without a network.

/// What the config directory holds for the identity's name, as the plan
/// sees it.
///
/// The `'a` lifetime says the variant borrows its details from the caller,
/// which keeps the [`StoredIdentity`] they came from (and its secret); the
/// plan never sees the secret.
enum Found<'a> {
    /// No key file: the name is free, and a new identity is created.
    New,
    /// The key and its details.
    Known(&'a IdentityMeta),
    /// The key without its details, as P2c copies it. `resolved` is the
    /// homeserver the identity's pkarr record names, if it has one.
    KeyOnly {
        /// The key's own pubky.
        pubky: Pubky,
        /// The homeserver its pkarr record names, or `None` for no record.
        resolved: Option<Pubky>,
    },
}

impl Found<'_> {
    /// The identity's pubky, or `None` for a new identity, whose key does
    /// not exist yet.
    ///
    /// `Found<'_>`: the impl works for any lifetime, and `'_` says so without
    /// naming one, as nothing here needs to refer to it.
    fn pubky(&self) -> Option<Pubky> {
        match self {
            Self::New => None,
            Self::Known(meta) => Some(meta.pubky),
            Self::KeyOnly { pubky, .. } => Some(*pubky),
        }
    }
}

/// Everything [`plan_login`] decides from.
struct PlanInput<'a> {
    /// The identity's name, for messages.
    name: &'a IdentityName,
    /// Which network this is.
    network: NetworkKind,
    /// The network's default homeserver.
    default_homeserver: Pubky,
    /// `--homeserver`, parsed.
    homeserver_flag: Option<Pubky>,
    /// Whether `--signup-token` was given. Only whether: the plan never
    /// needs the token itself.
    has_signup_token: bool,
    /// What is on disk for the name.
    found: Found<'a>,
    /// `login.json`, when this install is already logged in.
    current_login: Option<&'a LoginState>,
}

/// What `login` does, as [`plan_login`] decided it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LoginPlan {
    /// The homeserver the identity lives on, or is signed up on.
    homeserver: Pubky,
    /// Whether to sign up before signing in.
    signup: bool,
    /// The warning to print before anything is created or sent, if any.
    warning: Option<ProductionWarning>,
}

/// The warning before a dedicated identity is signed up on the production
/// network (03, "Two ways to log in").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProductionWarning {
    /// Whether a signup token goes with the signup, and so is spent.
    spends_token: bool,
}

impl fmt::Display for ProductionWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "this signs up a dedicated identity on the production network: a separate public \
             pubky of its own, not the one you have in Pubky Ring",
        )?;
        if self.spends_token {
            f.write_str(", and the signup spends your signup token")?;
        }
        Ok(())
    }
}

/// Decides what `login --identity` does, or refuses.
///
/// - **One login per install.** When `login.json` already names a pubky,
///   only that identity may log in again; anything else is refused, with
///   the way out (`logout`, or another `SWEEPKY_HOME`).
/// - **The homeserver.** A new identity, or a key that was never signed up
///   (no pkarr record), signs up on `--homeserver`, or else on the network's
///   default. A known identity lives where its details say, and a key
///   without details where its pkarr record says; a `--homeserver` that
///   names another one is refused rather than followed.
/// - **Whether to sign up.** A new identity and a never-signed-up key do; a
///   known one does when its details say `signedUp: false`; a key whose
///   record resolves does not (it is signed up there already).
/// - **The token.** A signup on the production network's default
///   homeserver, homeserver.pubky.app, needs `--signup-token`, and the
///   refusal lists the ways to get one. Another homeserver may not ask for
///   one, and says so itself if it does.
/// - **The warning.** Every signup on the production network warns that it
///   makes a separate public pubky (and spends the token, when there is
///   one). The testnet and an injected network never warn.
fn plan_login(input: &PlanInput<'_>) -> anyhow::Result<LoginPlan> {
    refuse_another_login(input)?;
    let (homeserver, signup) = match &input.found {
        // `|` matches either pattern; `resolved: None, ..` is a key whose
        // pkarr record names nothing, so it was never signed up.
        Found::New | Found::KeyOnly { resolved: None, .. } => (
            input.homeserver_flag.unwrap_or(input.default_homeserver),
            true,
        ),
        Found::Known(meta) => {
            refuse_another_homeserver(input, meta.homeserver, "as its details record")?;
            (meta.homeserver, !meta.signed_up)
        }
        Found::KeyOnly {
            resolved: Some(resolved),
            ..
        } => {
            refuse_another_homeserver(input, *resolved, "as its pkarr record says")?;
            (*resolved, false)
        }
    };
    let on_production = input.network == NetworkKind::Production;
    // Only homeserver.pubky.app is known to ask for a token.
    let token_required = signup && on_production && homeserver == input.default_homeserver;
    if token_required && !input.has_signup_token {
        bail!(SIGNUP_TOKEN_NEEDED);
    }
    // `then_some` is `Some(value)` when the condition holds, else `None`.
    let warning = (signup && on_production).then_some(ProductionWarning {
        spends_token: input.has_signup_token,
    });
    Ok(LoginPlan {
        homeserver,
        signup,
        warning,
    })
}

/// Refuses a login as another identity than the one `login.json` names.
fn refuse_another_login(input: &PlanInput<'_>) -> anyhow::Result<()> {
    let Some(current) = input.current_login else {
        return Ok(());
    };
    // A new identity has no pubky yet, so it is never the one logged in.
    if input.found.pubky() == Some(current.pubky) {
        return Ok(());
    }
    // `map_or` gives the default for `None` and applies the closure to a
    // `Some`: here " (identity <name>)" or nothing.
    let current_name = current
        .name
        .as_ref()
        .map_or(String::new(), |name| format!(" (identity {name})"));
    bail!(
        "this install is already logged in as {}{current_name}; run `sweepky logout` first to \
         log in as {}, or set SWEEPKY_HOME to another directory to keep a second identity apart",
        current.pubky,
        input.name
    )
}

/// Refuses a `--homeserver` that names another homeserver than `lives_on`,
/// where the identity already is; `source` says how that is known.
fn refuse_another_homeserver(
    input: &PlanInput<'_>,
    lives_on: Pubky,
    source: &str,
) -> anyhow::Result<()> {
    match input.homeserver_flag {
        // `if flag != lives_on` is a match guard: the arm matches only when
        // it holds. `Pubky`'s `!=` compares the key bytes.
        Some(flag) if flag != lives_on => bail!(
            "--homeserver names {flag}, but the identity {} is on {lives_on}, {source}; leave \
             --homeserver out to log in there, or choose another name for a new identity",
            input.name
        ),
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Signing up.

/// How a signup ended, when it did not fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignupOutcome {
    /// The homeserver created the account (2xx).
    SignedUp,
    /// The homeserver already has an account for this key (409): an earlier
    /// signup went through before Sweepky could record it.
    AlreadyRegistered,
}

/// The outcome of the SDK's `signup`, or the error to report.
///
/// A 409 Conflict is the homeserver's "user already exists" (pubky-homeserver
/// 0.16.2 checks for an existing account before it looks at the token, and
/// answers 409; confirmed on an `EphemeralTestnet` on 2026-10-16). It means
/// an earlier signup of this key went through, so it counts as done.
fn signup_outcome(result: pubky::Result<()>) -> anyhow::Result<SignupOutcome> {
    match result {
        Ok(()) => Ok(SignupOutcome::SignedUp),
        Err(error) if status_of(&error) == Some(StatusCode::CONFLICT) => {
            Ok(SignupOutcome::AlreadyRegistered)
        }
        Err(error) => Err(signup_error(&error)),
    }
}

/// A failed signup as a message: fixed text and the HTTP status, never the
/// SDK's own `Display`, which for a transport error includes the request URL
/// and so the signup token in its query, and for a server's answer carries
/// the server's own text.
fn signup_error(error: &pubky::Error) -> anyhow::Error {
    // The answers a missing, mistyped or spent token gets. `A | B | C` inside
    // `Some(..)` matches any of the three.
    let hint = match status_of(error) {
        Some(StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) => {
            "; check --signup-token: it may be missing, mistyped or already used"
        }
        _ => "",
    };
    // `request_error` is fixed words only: "the homeserver answered 401
    // Unauthorized" (the code and the `http` crate's standard reason, never
    // the server's words) for an answer, the kind of failure (network,
    // pkarr, ...) for the rest.
    anyhow!(
        "could not sign the identity up: {:#}{hint}",
        request_error(error)
    )
}

/// Signs the identity up on `homeserver`, with the signup token if there is
/// one.
async fn sign_up(
    signer: &PubkySigner,
    homeserver: &PublicKey,
    signup_token: Option<&SecretString>,
) -> anyhow::Result<SignupOutcome> {
    // The SDK takes the token as `Option<&str>`. `expose_secret` lends the
    // text out of the `SecretString` for this one call; nothing keeps a copy.
    // `map(ExposeSecret::expose_secret)` calls the trait method on the
    // `&SecretString` inside the `Option`.
    let token = signup_token.map(ExposeSecret::expose_secret);
    let outcome = signup_outcome(signer.signup(homeserver, token).await)?;
    if outcome == SignupOutcome::AlreadyRegistered {
        // The SDK publishes the identity's pkarr record, which tells everyone
        // its homeserver, only after a signup the server accepted. After a
        // 409 the record may never have gone out (a crash between the two),
        // and `signin_blocking` needs it to find the homeserver, so it is
        // published here.
        signer
            .pkdns()
            .publish_homeserver_force(Some(homeserver))
            .await
            .map_err(|err| request_error(&err))
            .context("could not publish the identity's homeserver record")?;
    }
    Ok(outcome)
}

// ---------------------------------------------------------------------------
// The shared tail: this install's device key.

/// What [`record_login`] did about this install's device key.
#[derive(Debug)]
enum DeviceKeyOutcome {
    /// This run made a new device key and published it under this id.
    Published(DeviceId),
    /// `login.json` already records this install's key under this id, and
    /// its published record holds this install's key: nothing was made or
    /// written.
    Reused(DeviceId),
    /// `login.json` already records this install's key under this id, but
    /// the record was gone, so this run published it again.
    Republished(DeviceId),
}

impl DeviceKeyOutcome {
    /// This install's device id, whichever it was.
    fn id(&self) -> &DeviceId {
        // An or-pattern: the three arms bind `id` the same way, so one arm
        // serves them all.
        match self {
            Self::Published(id) | Self::Reused(id) | Self::Republished(id) => id,
        }
    }
}

/// What the shared tail did, and what the check of `keys/` after it found.
#[derive(Debug)]
struct TailOutcome {
    /// What [`record_login`] did about this install's device key.
    device: DeviceKeyOutcome,
    /// The report's lines from the check of `keys/` ([`check_key_ids`]): an
    /// alarm per unknown id or replaced key, or a warning that the check
    /// could not run. Empty when all is well.
    key_check: String,
}

/// The shared tail ([`record_login`]) and then the check of the identity's
/// `keys/` for ids this owner's installs did not create and records that no
/// longer hold their install's key ([`check_key_ids`]), on the first login
/// and on every later one alike. The check runs only once the tail has
/// succeeded, so this install's own key is published and recorded in
/// `installs.json`, with its key, by then, and never reads as unknown.
async fn record_login_and_check_keys(
    dirs: &Dirs,
    passphrase: Option<&Passphrase>,
    keys: &impl KeyStore,
    state: LoginState,
) -> anyhow::Result<TailOutcome> {
    // `Pubky` is `Copy` (32 bytes), so this keeps a copy while `state`
    // moves into `record_login`.
    let owner = state.pubky;
    let device = record_login(dirs, passphrase, keys, state).await?;
    let key_check = check_key_ids(dirs, keys, owner, device.id()).await;
    Ok(TailOutcome { device, key_check })
}

/// The alarm of 02 at `login`: one line per id under `owner`'s `keys/` that
/// none of this owner's installs here created and whose record is not
/// revoked, and per id one of them did create whose unrevoked record no
/// longer holds the key `installs.json` records for it ([`key_alarms`]),
/// each with what to do about it. `this_install` is this install's device
/// id, which the tail has just published or checked.
///
/// Never an error: by now the key is published and `login.json` written,
/// so a check that cannot run (`installs.json` cannot be read, or
/// [`key_alarms`] fails with its `KeyCheckError`: the listing fails or is
/// past its limits, the records pass the budget, a known id's record
/// cannot be read) becomes a warning in the report that points at
/// `keys list`, rather than a failed login.
///
/// It only reads, so it takes the read-only [`PublicKeys`]; the tail's
/// `&impl KeyStore` is one, because `PublicKeys` is its supertrait.
async fn check_key_ids(
    dirs: &Dirs,
    keys: &impl PublicKeys,
    owner: Pubky,
    this_install: &DeviceId,
) -> String {
    // An `async` block whose `?`s return from the block, so every failure
    // ends up in the one `Err` below. Its last line spells out the error
    // type (`anyhow::Ok`), which the compiler cannot infer for a block. The
    // `?` after `key_alarms` turns its typed `KeyCheckError` into an
    // `anyhow::Error`, which keeps the failure's cause in its chain.
    let checked = async {
        let installs = read_installs(dirs)?;
        let alarms = key_alarms(
            keys,
            &public_key_of(&owner)?,
            installs.installs_of(&owner),
            Some(this_install),
        )
        .await?;
        anyhow::Ok(alarms)
    }
    .await;
    match checked {
        // `collect` joins the `String`s into one.
        Ok(alarms) => alarms.iter().map(KeyAlarm::line).collect(),
        Err(error) => format!(
            "warning: could not check keys/ for device keys this owner's installs did not create \
             ({error:#}); run `sweepky keys list` to check.\n"
        ),
    }
}

/// Writes `login.json` for `state`, running the shared tail of `login` first.
///
/// - When `state` records no device key yet (this install's first login, or
///   an earlier tail that rolled back), the tail makes and publishes one
///   ([`publish_device_key`]).
/// - When it records one, the tail reuses it ([`reuse_device_key`]): one
///   age key per install (00), so a second login never makes another.
///
/// `keys` is where `keys/<deviceId>.json` is read and written: the
/// signed-in session in `login`, a fake in the tests. `passphrase`, from
/// `--passphrase-file`, wraps a new `device.key` and unwraps an existing
/// one. On any failure of the tail `login.json` is left as it was, so it
/// never names a device key that is not published.
async fn record_login(
    dirs: &Dirs,
    passphrase: Option<&Passphrase>,
    keys: &impl KeyStore,
    mut state: LoginState,
) -> anyhow::Result<DeviceKeyOutcome> {
    // `if let Some(id) = &state.device_id` borrows the id inside `state`
    // rather than moving it out, so `state` is still whole for the write
    // below; both borrows are shared, which Rust allows at once.
    if let Some(id) = &state.device_id {
        let outcome = reuse_device_key(dirs, passphrase, keys, state.pubky, id).await?;
        write_login_state(dirs, &state)?;
        return Ok(outcome);
    }
    let id = publish_device_key(dirs, passphrase, keys, state.pubky).await?;
    state.device_id = Some(id.clone());
    // The key is published by now and its secret is on disk, so a failure
    // here undoes nothing: removing the secret of a published key would make
    // the sweeps encrypted to it unreadable.
    write_login_state(dirs, &state).with_context(|| {
        format!(
            "this install's device key {id} is published and its secret is in {}, but \
             login.json could not record it",
            dirs.device_key_file().display()
        )
    })?;
    Ok(DeviceKeyOutcome::Published(id))
}

/// Makes this install's device key and publishes it, for `owner`: the
/// shared tail's steps, in an order that never publishes a key whose secret
/// is not saved, and never leaves the key unknown to this owner's list.
///
/// 1. a new age identity, from the operating system's random numbers;
/// 2. its secret in `device.key`, wrapped with `passphrase` when there is
///    one, refused (with nothing changed) when a key file is there already;
/// 3. its id in `installs.json` under `owner`, with its public key, which
///    `keys list` and the check after the tail compare the published record
///    with;
/// 4. the record, `keys/<id>.json`, written through `keys`: the capability
///    probe. A 403 or a 507 becomes its own message, never the server's.
///
/// On a failure after step 2 the key file and the install entry this run
/// made are removed again, and nothing else: an existing key file is
/// refused in step 2, before there is anything to undo.
async fn publish_device_key(
    dirs: &Dirs,
    passphrase: Option<&Passphrase>,
    keys: &impl KeyStore,
    owner: Pubky,
) -> anyhow::Result<DeviceId> {
    let created_at = clock::now()?;
    let id = new_device_id()?;
    let identity = DeviceIdentity::generate();
    let recipient = identity.recipient();
    let record = device_key_bytes(&device_key_record(&recipient, created_at))?;
    // The secret is saved before anything is published, so a crash can
    // never leave a published key that nothing on this machine can open.
    create_device_key(dirs, &identity, passphrase)?;
    // The id and its key are recorded before the write too, so this owner's
    // own key never shows up as unknown under `keys/`, and a record rewritten
    // with another key later never passes for it.
    if let Err(error) = record_install_key(dirs, owner, &id, &recipient) {
        return Err(rolled_back(error, [remove_device_key(dirs)]));
    }
    if let Err(error) = keys.put_key(&id, record).await {
        // `write_error` gives 403 and 507 their messages, and every other
        // failure fixed text and a status. The key file goes first: were
        // only the install entry to go, the next login would find a key file
        // that login.json does not record, and refuse. An array literal's
        // elements are evaluated left to right, so both cleanups run, in that
        // order, before `rolled_back` is called with their results.
        return Err(rolled_back(
            write_error(&error),
            [remove_device_key(dirs), forget_install(dirs, owner, &id)],
        ));
    }
    Ok(id)
}

/// `cause`, why the tail stopped, as the error `login` aborts with, saying
/// what the rollback could not undo. `cleanups` are the results of the
/// rollback's steps, run already: an array of one or two, which
/// `impl IntoIterator` takes whatever its length.
fn rolled_back(
    cause: anyhow::Error,
    cleanups: impl IntoIterator<Item = anyhow::Result<()>>,
) -> anyhow::Error {
    // `filter_map(Result::err)` keeps the errors and drops the successes.
    let left: Vec<String> = cleanups
        .into_iter()
        .filter_map(Result::err)
        .map(|error| format!("{error:#}"))
        .collect();
    if left.is_empty() {
        cause.context("could not publish this install's device key, so login removed it again")
    } else {
        cause.context(format!(
            "could not publish this install's device key, and could not remove all of it again \
             ({}); delete what is left by hand",
            left.join("; ")
        ))
    }
}

// ---------------------------------------------------------------------------
// The shared tail on a later login: reusing this install's device key.

/// Reuses the device key `login.json` records as `id`, on a later login of
/// the same identity on this install. It never makes a second key, and never
/// writes over or deletes `device.key`, which may be the only key that opens
/// the sweeps encrypted to it:
///
/// 1. `device.key` must be there and hold an age identity, unwrapped with
///    `passphrase` when it is wrapped, or login refuses before anything goes
///    out ([`read_recorded_device_key`]).
/// 2. `keys/<id>.json` is read back (the key store caps it at
///    `MAX_RECORD_BYTES`):
///    - gone: it is published again with this install's key
///      ([`republish_device_key`]), which is the capability probe once more,
///      so a 403 or 507 gets its message; a failure removes nothing;
///    - this install's key, unrevoked: reused, with nothing written;
///    - anything else is refused with nothing changed ([`check_own_record`]).
/// 3. The id goes back into `installs.json`, with this install's key, if it
///    went missing there, and the key is filled in when an earlier build
///    recorded the id alone (it has just been checked against the published
///    record). That comes last, so a refusal leaves the file as it was, and
///    when the id is there with this key the file is not written. An entry
///    that records another key for the id is refused and left alone.
async fn reuse_device_key(
    dirs: &Dirs,
    passphrase: Option<&Passphrase>,
    keys: &impl KeyStore,
    owner: Pubky,
    id: &DeviceId,
) -> anyhow::Result<DeviceKeyOutcome> {
    // Only the public half is needed from here on. `.recipient()` is called
    // on the temporary identity, which is dropped (and wiped, by age) at the
    // end of this statement, so the secret is not held while the requests
    // below wait on the network.
    let local = read_recorded_device_key(dirs, passphrase, id)?.recipient();
    let published = keys.get_own_key(id).await.with_context(|| {
        format!("could not read back keys/{id}.json, this install's device key record")
    })?;
    let outcome = match published {
        None => {
            republish_device_key(dirs, keys, &local, id).await?;
            DeviceKeyOutcome::Republished(id.clone())
        }
        Some(bytes) => {
            check_own_record(id, &bytes, &local)?;
            DeviceKeyOutcome::Reused(id.clone())
        }
    };
    record_install_key(dirs, owner, id, &local).with_context(|| {
        format!("could not record this install's device id {id} in installs.json")
    })?;
    Ok(outcome)
}

/// Reads `device.key`, the secret of the key `login.json` records as `id`.
///
/// A missing or unreadable file is refused with the two ways out, restoring
/// it or retiring the key, and nothing is written: the file may only be
/// misplaced, and making a new key in its place would give this install a
/// second published key while the sweeps encrypted to the first stay
/// unopened. A wrapped file read without `passphrase` is refused with how to
/// give it, and nothing else: the file is fine.
fn read_recorded_device_key(
    dirs: &Dirs,
    passphrase: Option<&Passphrase>,
    id: &DeviceId,
) -> anyhow::Result<DeviceIdentity> {
    let path = dirs.device_key_file();
    // `display()` borrows `path` as something `{}` can print; a path is not
    // always UTF-8, so it has no `Display` of its own.
    let shown = path.display();
    match read_device_key(dirs, passphrase) {
        Ok(Some(identity)) => Ok(identity),
        Ok(None) => bail!(
            "{shown} is missing, but login.json records it as the secret of this install's device \
             key keys/{id}.json, so login changed nothing: restore {shown} from your backup, or \
             run `sweepky logout` to retire keys/{id}.json"
        ),
        // A match guard: this arm is taken only for the error that says the
        // passphrase is missing, which `is` finds through any context. The
        // file is fine, so the advice below about a backup would mislead;
        // the error's own message names the file and the flag.
        Err(error) if error.is::<NeedsPassphrase>() => Err(error.context("login changed nothing")),
        // `read_device_key`'s own error says what is wrong with the file, in
        // fixed words, and comes after this context in the printed chain.
        Err(error) => Err(error.context(format!(
            "could not read {shown}, the secret of this install's device key keys/{id}.json, so \
             login changed nothing (if the file cannot be put right, restore it from your backup, \
             or run `sweepky logout` to retire keys/{id}.json)"
        ))),
    }
}

/// Publishes `keys/<id>.json` again with `local`, this install's own key,
/// after the homeserver turned out not to have it.
///
/// It is this install's key under this install's id, so writing it back
/// grants nobody anything new. `createdAt` is now: the record's first time
/// went with it. A refusal is mapped as the first login's probe is (403 and
/// 507 to their messages, never the server's words), but nothing local is
/// undone: `device.key` may open sweeps already encrypted to this key.
async fn republish_device_key(
    dirs: &Dirs,
    keys: &impl KeyStore,
    local: &AgeRecipient,
    id: &DeviceId,
) -> anyhow::Result<()> {
    let record = device_key_bytes(&device_key_record(local, clock::now()?))?;
    keys.put_key(id, record).await.map_err(|error| {
        write_error(&error).context(format!(
            "keys/{id}.json, this install's device key record, is missing and could not be \
             published again, so login changed nothing and kept {}",
            dirs.device_key_file().display()
        ))
    })
}

/// Checks that `bytes`, this install's own `keys/<id>.json` as its
/// homeserver holds it, publishes `local`, this install's key, unrevoked.
///
/// Core parses the record ([`DeviceKey::from_json`], capped, version first)
/// and turns it into a key with [`DeviceKey::encryption_recipient`], the only
/// way to the key a sweeper's CLI would encrypt to, which also checks `alg`
/// and the recipient's strict form. That key is then compared with `local`
/// as [`AgeRecipient`] values, not as the record's text, so only a valid,
/// canonical key can ever match.
///
/// - Revoked: refused, pointing at `logout`.
/// - Not a record, not a usable key, or another key: this CLI wrote this
///   install's key there, so someone else wrote this, and it is refused as
///   an alarm (02, "Who can read a sweep").
///
/// The messages name the device id and never the record's recipient: that
/// text is the homeserver's, and repeating it would only help a lookalike.
/// Core's errors in the chain are fixed text too.
fn check_own_record(id: &DeviceId, bytes: &[u8], local: &AgeRecipient) -> anyhow::Result<()> {
    // `with_context` (anyhow's `Context` trait) turns core's typed error into
    // an `anyhow::Error` with the alarm in front of it. It takes a closure, so
    // the message is only built when there is an error.
    let record = DeviceKey::from_json(bytes).with_context(|| not_this_installs_key(id))?;
    if record.is_revoked() {
        bail!(
            "this install's device key keys/{id}.json is revoked, so sweeps are no longer \
             encrypted to it, and login changed nothing. Run `sweepky logout` to retire it, which \
             also forgets this identity: giving an identity a new device key on an install is \
             not part of this build"
        );
    }
    // `holds_key` is the comparison `keys list` makes of every record under
    // a known id: core's key from the record, then `==` on `AgeRecipient`.
    // Its error (another `alg`, a recipient that fails the strict parse) is
    // core's fixed text and goes in the chain after the alarm.
    let holds = holds_key(&record, local).with_context(|| not_this_installs_key(id))?;
    if !holds {
        bail!(not_this_installs_key(id));
    }
    Ok(())
}

/// The alarm for a `keys/<id>.json` of this install's that does not hold
/// this install's key: the one `keys list` raises for it, as an error
/// rather than a line of a report, so without the newline, and saying that
/// login changed nothing. Fixed text and the id.
fn not_this_installs_key(id: &DeviceId) -> String {
    // `trim_end` borrows the line without its trailing newline.
    format!(
        "{} login changed nothing",
        replaced_key_alarm(id, true).trim_end()
    )
}

/// What the report says about this install's device key, for each thing
/// [`record_login`] can have done with it.
fn device_key_report(dirs: &Dirs, outcome: &DeviceKeyOutcome) -> String {
    match outcome {
        DeviceKeyOutcome::Published(id) => published_key_report(dirs, id),
        DeviceKeyOutcome::Reused(id) => {
            format!("Reusing this install's device key, keys/{id}.json.\n")
        }
        DeviceKeyOutcome::Republished(id) => format!(
            "keys/{id}.json was missing, so login published this install's device key there \
             again; sweeps for you are encrypted to it.\n"
        ),
    }
}

/// What the report adds once the tail has published `id`: where the key
/// went, and the reminder to back it up, from 02 ("Who can read a sweep").
///
/// A `\` at the end of a line inside a string literal drops that line break
/// and the next line's indentation; the `\n`s are the report's own line
/// breaks, one after each sentence.
fn published_key_report(dirs: &Dirs, id: &DeviceId) -> String {
    format!(
        "Published this install's device key as keys/{id}.json; sweeps for you are encrypted \
         to it.\n\
         Back up {} the way you would an SSH key: it holds this install's device key, and \
         losing that file loses every sweep encrypted to it that you have not pulled yet.\n",
        dirs.config().display()
    )
}

// ---------------------------------------------------------------------------
// The command.

/// Runs `login`. `identity`, `homeserver` and `signup_token` are the flags,
/// `None` when not given.
pub(crate) async fn login(
    ctx: &Context,
    identity: Option<&str>,
    homeserver: Option<&str>,
    signup_token: Option<&SecretString>,
) -> anyhow::Result<Report> {
    let Some(identity) = identity else {
        bail!(RING_LOGIN_LATER);
    };
    // 1. The argument is a name or is refused, before the lock is taken or
    // any file is touched.
    let name = IdentityName::from_arg(identity, read_argument_file)?;
    // `map` gives an `Option<Result<Pubky>>`; `transpose` turns it inside out
    // into a `Result<Option<Pubky>>`, so `?` can return a bad value's error
    // while a missing flag stays `None`.
    let homeserver_flag = homeserver.map(parse_homeserver).transpose()?;
    // 2. The rest under the writers' lock. `async ||` is an async closure
    // borrowing `name` and the rest from this function.
    with_writers_lock(ctx, async || {
        login_locked(ctx, &name, homeserver_flag, signup_token).await
    })
    .await
}

/// `login`'s work under the writers' lock.
async fn login_locked(
    ctx: &Context,
    name: &IdentityName,
    homeserver_flag: Option<Pubky>,
    signup_token: Option<&SecretString>,
) -> anyhow::Result<Report> {
    let current = read_login_state(&ctx.dirs)?;
    // A wrapped key file read without --passphrase-file stops login here,
    // before anything is written.
    let stored = read_identity(&ctx.dirs, name, ctx.passphrase.as_ref())?;
    let settings = ctx.network.settings();
    let plan = plan_login(&PlanInput {
        name,
        network: settings.kind(),
        default_homeserver: pubky_of(settings.default_homeserver()),
        homeserver_flag,
        has_signup_token: signup_token.is_some(),
        found: found_on_disk(ctx, &stored).await?,
        current_login: current.as_ref(),
    })?;
    // Said before any identity file is written or the signup sent (only the
    // lock file and a key-only identity's pkarr lookup come first). If it
    // cannot be said, nothing is done: `?` returns the write error.
    if let Some(warning) = plan.warning {
        ctx.stderr.line(&format!("warning: {warning}"))?;
    }

    // The SDK's form of the homeserver key, which checks it is a valid
    // point. Done before any file is written, so a bad key in an old details
    // file fails with nothing changed.
    let homeserver = public_key_of(&plan.homeserver)?;

    let mut report = String::new();
    // The secret files this run creates wrapped with the passphrase, for the
    // report.
    let mut wrapped_files = Vec::new();
    // 3. Create or reuse. `stored` is moved apart here: each arm takes the
    // secret out of it by value.
    let (secret, mut meta) = match stored {
        StoredIdentity::Complete { secret, meta } => (secret, meta),
        StoredIdentity::Missing => {
            let secret = IdentitySecret::generate();
            let meta = IdentityMeta::new(name.clone(), secret.pubky(), plan.homeserver, false);
            create_identity(&ctx.dirs, &secret, &meta, ctx.passphrase.as_ref())?;
            if ctx.passphrase.is_some() {
                wrapped_files.push(ctx.dirs.identity_key_file(name));
            }
            report.push_str(&format!(
                "Created the dedicated identity {name}, pubky {}.\n",
                meta.pubky
            ));
            (secret, meta)
        }
        StoredIdentity::KeyOnly(secret) => {
            // Signed up already when its pkarr record names a homeserver.
            let meta =
                IdentityMeta::new(name.clone(), secret.pubky(), plan.homeserver, !plan.signup);
            write_identity_meta(&ctx.dirs, &meta)?;
            (secret, meta)
        }
    };

    // The signer owns a keypair made from the secret, which it wipes when
    // it is dropped at the end of this function.
    let signer = ctx.network.pubky().signer(secret.keypair());
    // 4. Sign up.
    if plan.signup {
        let outcome = sign_up(&signer, &homeserver, signup_token).await?;
        meta.signed_up = true;
        write_identity_meta(&ctx.dirs, &meta)?;
        report.push_str(&match outcome {
            SignupOutcome::SignedUp => format!("Signed up on homeserver {}.\n", meta.homeserver),
            SignupOutcome::AlreadyRegistered => format!(
                "Already signed up on homeserver {}; recorded that.\n",
                meta.homeserver
            ),
        });
    } else if signup_token.is_some() {
        report.push_str(&format!(
            "{name} is already signed up, so --signup-token was not sent and is still unspent.\n"
        ));
    }

    // 5. to 8. Sign in, publish this install's device key on its first
    // login, record the login, check keys/, sign out.
    let tail = sign_in_and_record(ctx, &signer, &meta, current).await?;
    report.push_str(&format!(
        "Logged in as {name}, pubky {}, on homeserver {}.\n",
        meta.pubky, meta.homeserver
    ));
    report.push_str(&device_key_report(&ctx.dirs, &tail.device));
    if ctx.passphrase.is_some() && matches!(tail.device, DeviceKeyOutcome::Published(_)) {
        wrapped_files.push(ctx.dirs.device_key_file());
    }
    report.push_str(&wrapped_report(&wrapped_files));
    report.push_str(&tail.key_check);
    Ok(Report::new(report))
}

/// What the report says about the secret files this run wrapped with the
/// passphrase, `paths`: nothing when it wrapped none.
///
/// `&[PathBuf]` is a borrowed slice, so the caller keeps its `Vec`.
fn wrapped_report(paths: &[PathBuf]) -> String {
    if paths.is_empty() {
        return String::new();
    }
    let shown: Vec<String> = paths
        .iter()
        .map(|path| path.display().to_string())
        .collect();
    format!(
        "Wrapped {} with the passphrase from --passphrase-file. Give --passphrase-file again to \
         every command that signs in or reads this install's key (login, logout, keys revoke, \
         circle create, add and remove), and keep the passphrase as safe as the files: without \
         it they cannot be opened.\n",
        shown.join(" and ")
    )
}

/// What the plan needs to know of `stored`. For a key without its details,
/// that includes where the identity's pkarr record says it lives.
///
/// The returned [`Found`] borrows its details from `stored`, which is why
/// both carry the lifetime `'a`.
async fn found_on_disk<'a>(ctx: &Context, stored: &'a StoredIdentity) -> anyhow::Result<Found<'a>> {
    Ok(match stored {
        StoredIdentity::Missing => Found::New,
        StoredIdentity::Complete { meta, .. } => Found::Known(meta),
        StoredIdentity::KeyOnly(secret) => {
            // `keypair()` makes a copy of the secret, which this statement
            // drops (and wipes) as soon as the public key is out of it, before
            // the lookup waits on the network.
            let user = secret.keypair().public_key();
            Found::KeyOnly {
                pubky: pubky_of(&user),
                resolved: resolve_homeserver(ctx, &user).await?,
            }
        }
    })
}

/// The homeserver `user`'s pkarr record names, or `None` when it has no
/// record (it was never signed up). Only the public key goes in: the lookup
/// needs nothing secret.
async fn resolve_homeserver(ctx: &Context, user: &PublicKey) -> anyhow::Result<Option<Pubky>> {
    let found = ctx
        .network
        .pubky()
        .get_homeserver_of(user)
        .await
        .map_err(|err| request_error(&err))
        .context("could not look up the identity's homeserver")?;
    // `as_ref().map(pubky_of)` converts the key inside the `Option` without
    // taking it apart.
    Ok(found.as_ref().map(pubky_of))
}

/// Signs in, publishes this install's device key if `login.json` records
/// none for this pubky or checks the one it records ([`record_login`]),
/// writes `login.json` for the identity `meta` describes
/// ([`login_state_for`], which `current` is moved into), checks `keys/` for
/// keys this owner's installs did not create ([`check_key_ids`]), and signs
/// out again.
///
/// The sign-out runs whether that worked or not; the error is returned
/// after it.
async fn sign_in_and_record(
    ctx: &Context,
    signer: &PubkySigner,
    meta: &IdentityMeta,
    current: Option<LoginState>,
) -> anyhow::Result<TailOutcome> {
    let session = signer
        .signin_blocking(client_id()?)
        .await
        .map_err(|err| request_error(&err))
        .context("could not sign in to the homeserver")?;
    let state = login_state_for(meta, current);
    // The store borrows the session. That borrow ends when the tail's
    // future is done, so the session can then be moved into `sign_out`,
    // which consumes it.
    let keys = SessionKeyStore::new(&session, ctx.network.pubky());
    let recorded =
        record_login_and_check_keys(&ctx.dirs, ctx.passphrase.as_ref(), &keys, state).await;
    sign_out(ctx, session).await;
    recorded
}

/// The `login.json` to write for the identity `meta` describes. `current`,
/// the `login.json` read before, is moved in, because its unknown fields
/// and its device id move into the new state.
fn login_state_for(meta: &IdentityMeta, current: Option<LoginState>) -> LoginState {
    let mut state = LoginState::identity(meta.name.clone(), meta.pubky, meta.homeserver);
    // Logging in again as the same identity (the only case the plan lets
    // through when a login exists) keeps the fields this build does not know,
    // as every rewrite does, and the device key this install recorded for it.
    if let Some(current) = current {
        state.extra = current.extra;
        if current.pubky == meta.pubky {
            state.device_id = current.device_id;
        }
    }
    state
}

/// `--homeserver`'s value as a key, parsed with the SDK, which also checks it
/// is a valid Ed25519 point. The error never quotes the value.
fn parse_homeserver(value: &str) -> anyhow::Result<Pubky> {
    value
        .parse::<PublicKey>()
        .map(|key| pubky_of(&key))
        .map_err(|_| anyhow!(NOT_A_HOMESERVER))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use pubky::StatusCode;
    use pubky::errors::RequestError;
    use serde_json::{Value, json};
    use sweepky_core::{DeviceId, DeviceIdentity, DeviceKey, Pubky};
    use tempfile::TempDir;

    use super::{
        DeviceKeyOutcome, Found, LoginPlan, PlanInput, ProductionWarning, SignupOutcome,
        plan_login, record_login, record_login_and_check_keys, signup_error, signup_outcome,
    };
    use crate::device::{create_device_key, device_key_bytes, device_key_record, read_device_key};
    use crate::identity::{IdentityMeta, IdentityName, IdentitySecret};
    use crate::installs::{Install, read_installs, record_install, record_install_key};
    use crate::network::{NetworkKind, PRODUCTION_HOMESERVER, TESTNET_HOMESERVER};
    use crate::passphrase::{NeedsPassphrase, Passphrase};
    use crate::remote::{ListLimits, QUOTA_FULL, WRITE_FORBIDDEN, public_key_of};
    use crate::state::{
        LoginState, StoredIdentity, create_identity, read_identity, read_login_state,
        write_login_state,
    };
    use crate::test_support::{
        FAKE_SERVER_TEXT, FakeKeyStore, FileSnapshot, KeyStoreCall, TEST_PASSPHRASE, dirs_in,
        private_temp, random_pubky,
    };
    use crate::{Dirs, clock};

    fn key(z32: &str) -> Pubky {
        z32.parse().expect("a valid key")
    }

    fn throwaway() -> IdentityName {
        "throwaway".parse().expect("valid")
    }

    /// The default homeserver of each kind of network: production's and the
    /// testnet's are built in, an injected one is whatever the caller gave.
    fn default_of(network: NetworkKind) -> Pubky {
        match network {
            NetworkKind::Production => key(PRODUCTION_HOMESERVER),
            NetworkKind::Testnet => key(TESTNET_HOMESERVER),
            // Any fixed key will do; core's `Pubky` does not check that it is
            // a valid point, and the plan never needs it to be.
            NetworkKind::Injected => Pubky::from_bytes([7; 32]),
        }
    }

    /// The input for a new identity on `network`, no flags, not logged in.
    fn new_on<'a>(name: &'a IdentityName, network: NetworkKind) -> PlanInput<'a> {
        PlanInput {
            name,
            network,
            default_homeserver: default_of(network),
            homeserver_flag: None,
            has_signup_token: false,
            found: Found::New,
            current_login: None,
        }
    }

    fn plan(input: &PlanInput<'_>) -> LoginPlan {
        plan_login(input).expect("plans")
    }

    fn refusal(input: &PlanInput<'_>) -> String {
        // `{:#}` is the whole chain, as `main.rs` prints it.
        format!("{:#}", plan_login(input).expect_err("refused"))
    }

    #[test]
    fn production_new_identity_needs_a_signup_token() {
        let name = throwaway();
        let message = refusal(&new_on(&name, NetworkKind::Production));
        // Every way 06 lists to get one, in plain text.
        for way in [
            "--signup-token",
            "Homegate",
            "SMS",
            "Google",
            "Lightning",
            "`st`",
            "copy sign-up link",
            "pubky.app/invite/<code>",
        ] {
            assert!(message.contains(way), "{way:?} missing from: {message}");
        }

        // With a token it plans the signup on homeserver.pubky.app.
        let with_token = PlanInput {
            has_signup_token: true,
            ..new_on(&name, NetworkKind::Production)
        };
        let planned = plan(&with_token);
        assert!(planned.signup);
        assert_eq!(planned.homeserver, key(PRODUCTION_HOMESERVER));

        // Another homeserver on production may not ask for a token, and says
        // so itself if it does; only homeserver.pubky.app is known to.
        let elsewhere = PlanInput {
            homeserver_flag: Some(random_pubky()),
            ..new_on(&name, NetworkKind::Production)
        };
        assert!(plan(&elsewhere).signup);

        // The testnet and an injected network sign up without one.
        for network in [NetworkKind::Testnet, NetworkKind::Injected] {
            assert!(plan(&new_on(&name, network)).signup, "{network:?}");
        }
    }

    #[test]
    fn production_new_identity_warns_separate_pubky_and_token() {
        let name = throwaway();
        let input = PlanInput {
            has_signup_token: true,
            ..new_on(&name, NetworkKind::Production)
        };
        let warning = plan(&input).warning.expect("production warns");
        assert_eq!(warning, ProductionWarning { spends_token: true });
        let text = warning.to_string();
        for part in ["separate public pubky", "spends", "signup token"] {
            assert!(text.contains(part), "{part:?} missing from: {text}");
        }

        // A reused identity that is already signed up signs in only: no
        // warning, nothing created or spent.
        let meta = IdentityMeta::new(
            name.clone(),
            random_pubky(),
            key(PRODUCTION_HOMESERVER),
            true,
        );
        let reused = PlanInput {
            has_signup_token: true,
            found: Found::Known(&meta),
            ..new_on(&name, NetworkKind::Production)
        };
        assert_eq!(plan(&reused).warning, None);

        for network in [NetworkKind::Testnet, NetworkKind::Injected] {
            let input = PlanInput {
                has_signup_token: true,
                ..new_on(&name, network)
            };
            assert_eq!(plan(&input).warning, None, "{network:?}");
        }
    }

    #[test]
    fn homeserver_defaults_per_network_and_reuse_mismatch_is_refused() {
        let name = throwaway();
        // Without --homeserver, each network's default.
        for network in [
            NetworkKind::Production,
            NetworkKind::Testnet,
            NetworkKind::Injected,
        ] {
            let input = PlanInput {
                has_signup_token: true,
                ..new_on(&name, network)
            };
            assert_eq!(plan(&input).homeserver, default_of(network), "{network:?}");
        }
        // With it, the one named.
        let named = random_pubky();
        let input = PlanInput {
            homeserver_flag: Some(named),
            ..new_on(&name, NetworkKind::Testnet)
        };
        assert_eq!(plan(&input).homeserver, named);

        // A reused identity lives where its details say, flag or not; the
        // details decide whether it still has to sign up.
        let lives_on = random_pubky();
        for signed_up in [true, false] {
            let meta = IdentityMeta::new(name.clone(), random_pubky(), lives_on, signed_up);
            for flag in [None, Some(lives_on)] {
                let input = PlanInput {
                    homeserver_flag: flag,
                    found: Found::Known(&meta),
                    ..new_on(&name, NetworkKind::Testnet)
                };
                let planned = plan(&input);
                assert_eq!(planned.homeserver, lives_on);
                assert_eq!(planned.signup, !signed_up);
            }
            // A --homeserver that names another one is refused, and says
            // which homeserver the identity is on.
            let input = PlanInput {
                homeserver_flag: Some(random_pubky()),
                found: Found::Known(&meta),
                ..new_on(&name, NetworkKind::Testnet)
            };
            let message = refusal(&input);
            assert!(message.contains(&lives_on.to_string()), "{message}");
            assert!(!message.contains("  "), "a run of spaces: {message}");
        }
    }

    #[test]
    fn key_file_without_metadata_is_reused() {
        let name = throwaway();
        let pubky = random_pubky();
        let key_only = |resolved, flag| PlanInput {
            homeserver_flag: flag,
            found: Found::KeyOnly { pubky, resolved },
            ..new_on(&name, NetworkKind::Testnet)
        };

        // Its pkarr record names a homeserver: signed up there already, so no
        // signup (and the details are written with `signedUp: true`), with
        // or without a --homeserver that agrees.
        let resolved = random_pubky();
        for flag in [None, Some(resolved)] {
            let planned = plan(&key_only(Some(resolved), flag));
            assert_eq!(planned.homeserver, resolved);
            assert!(!planned.signup);
            assert_eq!(planned.warning, None);
        }
        // A --homeserver that disagrees with the record is refused.
        let message = refusal(&key_only(Some(resolved), Some(random_pubky())));
        assert!(message.contains(&resolved.to_string()), "{message}");

        // No record: never signed up, so it signs up on --homeserver, or on
        // the network's default.
        let named = random_pubky();
        let planned = plan(&key_only(None, Some(named)));
        assert_eq!(planned.homeserver, named);
        assert!(planned.signup);
        let planned = plan(&key_only(None, None));
        assert_eq!(planned.homeserver, default_of(NetworkKind::Testnet));
        assert!(planned.signup);
    }

    #[test]
    fn signup_409_counts_as_already_registered() {
        // A signup, such as the one of a key with no pkarr record, may find
        // an account already there: a 409 is done, and anything else non-2xx
        // is an error.
        let answer = |status| {
            Err(pubky::Error::from(RequestError::Server {
                status,
                message: "User already exists".to_owned(),
            }))
        };
        assert_eq!(signup_outcome(Ok(())).expect("ok"), SignupOutcome::SignedUp);
        assert_eq!(
            signup_outcome(answer(StatusCode::CONFLICT)).expect("409 is done"),
            SignupOutcome::AlreadyRegistered
        );
        assert!(signup_outcome(answer(StatusCode::UNAUTHORIZED)).is_err());
        assert!(signup_outcome(answer(StatusCode::INTERNAL_SERVER_ERROR)).is_err());
    }

    #[test]
    fn signup_failure_never_prints_the_token() {
        let token = "SYNTH-TOKN-0000";
        // What the SDK can hand back for a failed signup with the token in
        // its URL's query: a server's answer whose text echoes the request,
        // and a validation error that quotes the URL.
        let url = format!("https://{TESTNET_HOMESERVER}/auth/grant/signup?signup_token={token}");
        let server = pubky::Error::from(RequestError::Server {
            status: StatusCode::UNAUTHORIZED,
            message: format!("Invalid token for {url}"),
        });
        let validation = pubky::Error::from(RequestError::Validation {
            message: format!("invalid signup url: {url}"),
        });
        // The SDK's own text does carry the token, which is the point.
        assert!(server.to_string().contains(token));
        assert!(validation.to_string().contains(token));

        let message = format!("{:#}", signup_error(&server));
        assert!(!message.contains(token), "{message}");
        assert!(!message.contains("Invalid token"), "server text: {message}");
        assert!(message.contains("401"), "the status is shown: {message}");

        let message = format!("{:#}", signup_error(&validation));
        assert!(!message.contains(token), "{message}");
        assert!(!message.contains("signup_token"), "{message}");

        // Through `signup_outcome`, the path `login` takes.
        let failed = signup_outcome(Err(server)).expect_err("an error");
        assert!(!format!("{failed:#}").contains(token));
        assert!(!format!("{failed:?}").contains(token));
    }

    #[test]
    fn already_logged_in_as_another_identity_is_refused() {
        let name = throwaway();
        let logged_in = random_pubky();
        let state = LoginState::identity(name.clone(), logged_in, key(TESTNET_HOMESERVER));

        // A new identity next to a login: refused, naming the pubky in use
        // and saying how to log out first.
        let input = PlanInput {
            current_login: Some(&state),
            ..new_on(&name, NetworkKind::Testnet)
        };
        let message = refusal(&input);
        assert!(message.contains(&logged_in.to_string()), "{message}");
        assert!(message.contains("logout"), "{message}");
        assert!(!message.contains("  "), "a run of spaces: {message}");

        // Another existing identity, or a key file of another pubky: refused.
        let other = IdentityMeta::new(name.clone(), random_pubky(), key(TESTNET_HOMESERVER), true);
        for found in [
            Found::Known(&other),
            Found::KeyOnly {
                pubky: random_pubky(),
                resolved: Some(key(TESTNET_HOMESERVER)),
            },
        ] {
            let input = PlanInput {
                found,
                current_login: Some(&state),
                ..new_on(&name, NetworkKind::Testnet)
            };
            assert!(plan_login(&input).is_err());
        }

        // The identity already logged in logs in again.
        let same = IdentityMeta::new(name.clone(), logged_in, key(TESTNET_HOMESERVER), true);
        let input = PlanInput {
            found: Found::Known(&same),
            current_login: Some(&state),
            ..new_on(&name, NetworkKind::Testnet)
        };
        assert!(!plan(&input).signup);
    }

    /// A temp `SWEEPKY_HOME` holding what is there by the time the shared
    /// tail runs: the identity's two files, a `login.json` without a device
    /// id (as a build before the tail left it), and in `installs.json` an
    /// earlier install of the same owner and another owner's. Returns the
    /// directory, its `Dirs`, the state the tail is given, and that earlier
    /// install's id.
    fn before_the_tail() -> (TempDir, Dirs, LoginState, DeviceId) {
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        let name = throwaway();
        let secret = IdentitySecret::generate();
        let meta = IdentityMeta::new(name.clone(), secret.pubky(), random_pubky(), true);
        create_identity(&dirs, &secret, &meta, None).expect("creates");
        let state = LoginState::identity(name, meta.pubky, meta.homeserver);
        write_login_state(&dirs, &state).expect("writes");
        let earlier: DeviceId = "earlier-install".parse().expect("valid");
        record_install(&dirs, meta.pubky, &earlier).expect("records");
        record_install(
            &dirs,
            random_pubky(),
            &"other-owner".parse().expect("valid"),
        )
        .expect("records");
        (temp, dirs, state, earlier)
    }

    #[tokio::test]
    async fn probe_refusal_rolls_back_local_device_state() {
        // 403 and 507 get their own messages; any other refusal its status.
        for (status, message) in [
            (StatusCode::FORBIDDEN, WRITE_FORBIDDEN),
            (StatusCode::INSUFFICIENT_STORAGE, QUOTA_FULL),
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "the homeserver answered 500 Internal Server Error",
            ),
        ] {
            let (_temp, dirs, state, earlier) = before_the_tail();
            let installs_before = fs::read(dirs.installs_file()).expect("readable");
            let keys = FakeKeyStore::refusing_puts(status);

            let err = record_login(&dirs, None, &keys, state.clone())
                .await
                .expect_err("login aborts");
            // Our message, never the server's own text.
            assert_eq!(err.root_cause().to_string(), message, "{status}");
            let shown = format!("{err:#}");
            assert!(!shown.contains(FAKE_SERVER_TEXT), "{shown}");
            assert!(!format!("{err:?}").contains(FAKE_SERVER_TEXT), "{shown}");

            // The probe was the run's one remote call: the PUT of a new
            // `keys/<deviceId>.json`.
            let calls = keys.calls();
            let [KeyStoreCall::PutKey(probed)] = calls.as_slice() else {
                panic!("expected one PUT, got {calls:?}");
            };
            assert_ne!(probed, &earlier);

            // Nothing of the new key is left: no device.key, no install
            // entry (the file is byte for byte what it was, the earlier
            // install and the other owner included), and login.json is
            // unchanged, with no device id.
            assert!(fs::symlink_metadata(dirs.device_key_file()).is_err());
            assert_eq!(
                fs::read(dirs.installs_file()).expect("readable"),
                installs_before
            );
            assert_eq!(
                read_installs(&dirs).expect("reads").ids_of(&state.pubky),
                [earlier]
            );
            let login = read_login_state(&dirs).expect("reads").expect("present");
            assert_eq!(login, state);
            assert_eq!(login.device_id, None);
            // The identity and its details stay: its signup may have spent a
            // token.
            let name = state.name.as_ref().expect("a name");
            assert!(matches!(
                read_identity(&dirs, name, None).expect("reads"),
                StoredIdentity::Complete { .. }
            ));
        }
    }

    #[tokio::test]
    async fn an_unrecorded_device_key_is_kept_and_nothing_is_published() {
        // A device.key that login.json does not record, as a crash in an
        // earlier run could leave: the tail refuses before it publishes
        // anything, and the key it did not make is never deleted.
        let (_temp, dirs, state, earlier) = before_the_tail();
        let existing = DeviceIdentity::generate();
        create_device_key(&dirs, &existing, None).expect("written");
        let keys = FakeKeyStore::default();

        let err = record_login(&dirs, None, &keys, state.clone())
            .await
            .expect_err("refused");
        assert!(format!("{err:#}").contains("never replaces"), "{err:#}");
        assert_eq!(keys.calls(), []);
        let kept = read_device_key(&dirs, None).expect("reads").expect("kept");
        assert_eq!(kept.recipient(), existing.recipient());
        assert_eq!(
            read_installs(&dirs).expect("reads").ids_of(&state.pubky),
            [earlier]
        );
        assert_eq!(read_login_state(&dirs).expect("reads"), Some(state));
    }

    /// A temp `SWEEPKY_HOME` after this install's first login against
    /// `keys`: the identity's two files, `device.key`, this one install in
    /// `installs.json`, and `login.json` naming its device id, whose record
    /// `keys` now holds. Returns the directory, its `Dirs`, the `login.json`
    /// the next login starts from, and the device id.
    async fn after_a_first_login(keys: &FakeKeyStore) -> (TempDir, Dirs, LoginState, DeviceId) {
        after_a_first_login_with(keys, None).await
    }

    /// [`after_a_first_login`], with the identity and `device.key` wrapped
    /// with `passphrase` when there is one, as `login --passphrase-file`
    /// leaves them.
    async fn after_a_first_login_with(
        keys: &FakeKeyStore,
        passphrase: Option<&Passphrase>,
    ) -> (TempDir, Dirs, LoginState, DeviceId) {
        let temp = private_temp();
        let dirs = dirs_in(&temp);
        let secret = IdentitySecret::generate();
        let meta = IdentityMeta::new(throwaway(), secret.pubky(), random_pubky(), true);
        create_identity(&dirs, &secret, &meta, passphrase).expect("creates");
        let state = LoginState::identity(meta.name.clone(), meta.pubky, meta.homeserver);
        let outcome = record_login(&dirs, passphrase, keys, state)
            .await
            .expect("the first login");
        let DeviceKeyOutcome::Published(id) = outcome else {
            panic!("expected a new key, got {outcome:?}");
        };
        let state = read_login_state(&dirs).expect("reads").expect("present");
        assert_eq!(state.device_id.as_ref(), Some(&id));
        (temp, dirs, state, id)
    }

    /// Snapshots of `device.key`, `installs.json` and `login.json`, the
    /// local files a reuse of the device key could change: equal snapshots
    /// mean a file was not written at all.
    fn device_state(dirs: &Dirs) -> [Option<FileSnapshot>; 3] {
        [
            dirs.device_key_file(),
            dirs.installs_file(),
            dirs.login_file(),
        ]
        .map(|path| FileSnapshot::of(&path))
    }

    #[tokio::test]
    async fn second_login_reuses_the_device_key() {
        let keys = FakeKeyStore::default();
        let (_temp, dirs, state, id) = after_a_first_login(&keys).await;
        let published = keys.record(&id).expect("published");
        let [device_key, installs, _] = device_state(&dirs);
        let calls_before = keys.calls().len();

        let outcome = record_login(&dirs, None, &keys, state.clone())
            .await
            .expect("the second login");
        assert!(
            matches!(&outcome, DeviceKeyOutcome::Reused(reused) if reused == &id),
            "{outcome:?}"
        );
        // The second login's one remote call reads its own record back; it
        // writes nothing there.
        let calls = keys.calls();
        assert_eq!(calls[calls_before..], [KeyStoreCall::GetOwnKey(id.clone())]);
        assert_eq!(keys.record(&id), Some(published));
        // device.key and installs.json are not written at all, and this
        // owner has exactly the one install.
        let [device_key_after, installs_after, _] = device_state(&dirs);
        assert_eq!(device_key_after, device_key);
        assert_eq!(installs_after, installs);
        assert_eq!(
            read_installs(&dirs).expect("reads").ids_of(&state.pubky),
            [id]
        );
        // login.json still names the same key.
        assert_eq!(read_login_state(&dirs).expect("reads"), Some(state));
    }

    #[tokio::test]
    async fn second_login_reuses_a_wrapped_device_key() {
        // `for_tests` wraps at work factor 10, so the test stays fast;
        // `--passphrase-file` always writes at 18.
        let passphrase = Passphrase::for_tests(TEST_PASSPHRASE);
        let keys = FakeKeyStore::default();
        let (_temp, dirs, state, id) = after_a_first_login_with(&keys, Some(&passphrase)).await;
        // The first login wrote the new device.key wrapped, and published
        // the key inside it.
        let raw = fs::read(dirs.device_key_file()).expect("readable");
        assert!(raw.starts_with(b"age-encryption.org/v1\n-> scrypt "));
        let local = read_device_key(&dirs, Some(&passphrase))
            .expect("reads")
            .expect("present");
        let published = keys.record(&id).expect("published");
        let record = DeviceKey::from_json(&published).expect("parses");
        assert_eq!(
            record.encryption_recipient().expect("usable"),
            local.recipient()
        );
        let [device_key, installs, login_file] = device_state(&dirs);
        let calls_before = keys.calls().len();

        // Without the passphrase: the how-to-supply error, before anything
        // goes out, and nothing written here or there.
        let err = record_login(&dirs, None, &keys, state.clone())
            .await
            .expect_err("needs the passphrase");
        assert!(err.is::<NeedsPassphrase>(), "{err:#}");
        let shown = format!("{err:#}");
        for part in [
            "login changed nothing",
            "wrapped with a passphrase",
            "--passphrase-file <file>",
        ] {
            assert!(shown.contains(part), "{part:?} missing from: {shown}");
        }
        assert!(!shown.contains("synthetic"), "{shown}");
        assert_eq!(keys.calls().len(), calls_before);
        assert_eq!(keys.record(&id).as_ref(), Some(&published));
        assert_eq!(device_state(&dirs), [device_key, installs, login_file]);

        // With it: the reuse branch reads the wrapped key, finds its record
        // in order, and writes neither device.key nor the record.
        let [device_key, installs, _] = device_state(&dirs);
        let outcome = record_login(&dirs, Some(&passphrase), &keys, state.clone())
            .await
            .expect("the second login");
        assert!(
            matches!(&outcome, DeviceKeyOutcome::Reused(reused) if reused == &id),
            "{outcome:?}"
        );
        let calls = keys.calls();
        assert_eq!(calls[calls_before..], [KeyStoreCall::GetOwnKey(id.clone())]);
        assert_eq!(keys.record(&id), Some(published));
        let [device_key_after, installs_after, _] = device_state(&dirs);
        assert_eq!(device_key_after, device_key);
        assert_eq!(installs_after, installs);
        assert_eq!(read_login_state(&dirs).expect("reads"), Some(state));
    }

    #[tokio::test]
    async fn second_login_republishes_a_missing_key_record() {
        let (_temp, dirs, state, id) = after_a_first_login(&FakeKeyStore::default()).await;
        let local = read_device_key(&dirs, None)
            .expect("reads")
            .expect("present");
        let [device_key, installs, _] = device_state(&dirs);
        // A homeserver that has lost the record: this store holds none.
        let keys = FakeKeyStore::default();

        let outcome = record_login(&dirs, None, &keys, state.clone())
            .await
            .expect("republished");
        assert!(
            matches!(&outcome, DeviceKeyOutcome::Republished(again) if again == &id),
            "{outcome:?}"
        );
        assert_eq!(
            keys.calls(),
            [
                KeyStoreCall::GetOwnKey(id.clone()),
                KeyStoreCall::PutKey(id.clone())
            ]
        );
        // The same id, holding this install's own key again.
        let record = DeviceKey::from_json(&keys.record(&id).expect("published")).expect("parses");
        assert_eq!(record.revoked_at, None);
        assert_eq!(
            record.encryption_recipient().expect("usable"),
            local.recipient()
        );
        // No new key and no second install.
        let [device_key_after, installs_after, _] = device_state(&dirs);
        assert_eq!(device_key_after, device_key);
        assert_eq!(installs_after, installs);
        assert_eq!(read_login_state(&dirs).expect("reads"), Some(state));
    }

    #[tokio::test]
    async fn reuse_republish_refusal_keeps_the_device_key() {
        for (status, message) in [
            (StatusCode::FORBIDDEN, WRITE_FORBIDDEN),
            (StatusCode::INSUFFICIENT_STORAGE, QUOTA_FULL),
        ] {
            let (_temp, dirs, state, id) = after_a_first_login(&FakeKeyStore::default()).await;
            let before = device_state(&dirs);
            // The record is gone and the homeserver refuses to take it back.
            let keys = FakeKeyStore::refusing_puts(status);

            let err = record_login(&dirs, None, &keys, state)
                .await
                .expect_err("login aborts");
            assert_eq!(err.root_cause().to_string(), message, "{status}");
            let shown = format!("{err:#}");
            assert!(shown.contains(&format!("keys/{id}.json")), "{shown}");
            assert!(!shown.contains(FAKE_SERVER_TEXT), "{shown}");
            assert!(!format!("{err:?}").contains(FAKE_SERVER_TEXT), "{shown}");
            assert_eq!(
                keys.calls(),
                [
                    KeyStoreCall::GetOwnKey(id.clone()),
                    KeyStoreCall::PutKey(id)
                ]
            );
            // Unlike the first login's probe, nothing is rolled back: the
            // key may open sweeps already encrypted to it.
            assert_eq!(device_state(&dirs), before, "{status}");
        }
    }

    #[tokio::test]
    async fn revoked_or_mismatched_own_key_is_refused_without_changes() {
        for case in [
            "revoked",
            "another key",
            "another alg",
            "not a recipient",
            "not a record",
        ] {
            let keys = FakeKeyStore::default();
            let (_temp, dirs, state, id) = after_a_first_login(&keys).await;
            let local = read_device_key(&dirs, None)
                .expect("reads")
                .expect("present");
            let other = DeviceIdentity::generate();
            let created_at = clock::now().expect("a time");
            let ours = device_key_record(&local.recipient(), created_at.clone());
            // What the homeserver holds as keys/<id>.json by the next login.
            let tampered = |field: &str, value: Value| {
                let mut json = serde_json::to_value(&ours).expect("JSON");
                json[field] = value;
                serde_json::to_vec(&json).expect("JSON")
            };
            let local_text = local.recipient().to_string();
            let published = match case {
                // As this install's own logout, or `keys revoke` from another
                // install, leaves it.
                "revoked" => tampered("revokedAt", json!(created_at.as_str())),
                "another key" => {
                    device_key_bytes(&device_key_record(&other.recipient(), created_at))
                        .expect("JSON")
                }
                "another alg" => tampered("alg", json!("AGE-X25519")),
                // The local key, but not in the one spelling age accepts.
                "not a recipient" => tampered("recipient", json!(local_text.to_uppercase())),
                "not a record" => b"{\"schemaVersion\":1,\"alg\":".to_vec(),
                _ => unreachable!("{case}"),
            };
            keys.set_record(&id, published.clone());
            let before = device_state(&dirs);
            let calls_before = keys.calls().len();

            let err = record_login(&dirs, None, &keys, state)
                .await
                .expect_err(case);
            let shown = format!("{err:#}");
            // The device id, and never a recipient's text: neither this
            // install's, nor the one in the record, in either case. (Core's
            // fixed reason may name the "age1" prefix; that is no key.)
            assert!(
                shown.contains(&format!("keys/{id}.json")),
                "{case}: {shown}"
            );
            for text in [local_text.as_str(), &other.recipient().to_string()] {
                assert!(!shown.contains(text), "{case}: {shown}");
                assert!(!shown.contains(&text.to_uppercase()), "{case}: {shown}");
            }
            if case == "revoked" {
                assert!(shown.contains("revoked"), "{shown}");
                assert!(shown.contains("`sweepky logout`"), "{shown}");
                assert!(!shown.contains("alarm"), "{shown}");
            } else {
                assert!(shown.starts_with("alarm: "), "{case}: {shown}");
                assert!(
                    shown.contains("someone other than this install wrote it"),
                    "{case}: {shown}"
                );
            }
            // It read the record and changed nothing, here or there.
            let calls = keys.calls();
            assert_eq!(calls[calls_before..], [KeyStoreCall::GetOwnKey(id.clone())]);
            assert_eq!(keys.record(&id), Some(published), "{case}");
            assert_eq!(device_state(&dirs), before, "{case}");
        }
    }

    #[tokio::test]
    async fn missing_device_key_file_is_refused_with_restore_hint() {
        for case in ["missing", "not an age identity"] {
            let keys = FakeKeyStore::default();
            let (_temp, dirs, state, id) = after_a_first_login(&keys).await;
            let path = dirs.device_key_file();
            match case {
                "missing" => fs::remove_file(&path).expect("remove"),
                // Written over the 0600 file, which keeps its mode, so the
                // refusal is about what it holds.
                _ => fs::write(&path, b"synthetic damage").expect("write"),
            }
            let before = device_state(&dirs);
            let calls_before = keys.calls().len();

            let err = record_login(&dirs, None, &keys, state)
                .await
                .expect_err(case);
            let shown = format!("{err:#}");
            for part in [
                path.display().to_string(),
                "from your backup".to_owned(),
                "`sweepky logout`".to_owned(),
                format!("keys/{id}.json"),
            ] {
                assert!(
                    shown.contains(&part),
                    "{case}: {part:?} missing from: {shown}"
                );
            }
            assert!(!shown.contains("synthetic damage"), "{shown}");
            // Refused before anything went out, with nothing written.
            assert_eq!(keys.calls().len(), calls_before, "{case}");
            assert_eq!(device_state(&dirs), before, "{case}");
        }
    }

    /// A `keys/<id>.json` this install did not write, as an operator of the
    /// homeserver or a holder of a leaked grant could put there: a usable
    /// key, revoked or not.
    fn injected_record(revoked: bool) -> Vec<u8> {
        let mut record = device_key_record(
            &DeviceIdentity::generate().recipient(),
            clock::now().expect("a time"),
        );
        if revoked {
            record.revoked_at = Some(clock::now().expect("a time"));
        }
        device_key_bytes(&record).expect("JSON")
    }

    /// The device id of the record [`injected_record`] is put under.
    fn injected_id() -> DeviceId {
        "injected-key".parse().expect("valid")
    }

    /// Asserts that `report` raises the alarm for [`injected_id`], with
    /// both of its fixes.
    fn assert_alarms_on_injected(report: &str) {
        for part in [
            "alarm: keys/injected-key.json",
            "`sweepky keys revoke injected-key`",
            "revoke it in Pubky Ring and log in again",
        ] {
            assert!(report.contains(part), "{part:?} missing from: {report}");
        }
    }

    #[tokio::test]
    async fn login_alarms_on_unknown_key_ids() {
        // The first login: the key it publishes is this owner's, the one
        // already there is not.
        let (_temp, dirs, state, _earlier) = before_the_tail();
        let keys = FakeKeyStore::default();
        keys.set_record(&injected_id(), injected_record(false));
        let tail = record_login_and_check_keys(&dirs, None, &keys, state.clone())
            .await
            .expect("the first login");
        let DeviceKeyOutcome::Published(own) = &tail.device else {
            panic!("expected a new key, got {:?}", tail.device);
        };
        assert_alarms_on_injected(&tail.key_check);
        assert!(!tail.key_check.contains(&format!("keys/{own}.json")));
        // The check listed keys/ after the key was published, and read
        // every listed record: this install's own, to compare it with the
        // key installs.json records for it, and the unknown one, to see
        // whether it is revoked. The fake lists by id, and an id made from
        // the clock (digits and upper-case letters) sorts before a
        // lower-case one.
        let calls = keys.calls();
        assert!(
            calls.ends_with(&[
                KeyStoreCall::ListKeyIds(public_key_of(&state.pubky).expect("a key")),
                KeyStoreCall::GetKey(own.clone()),
                KeyStoreCall::GetKey(injected_id()),
            ]),
            "{calls:?}"
        );
    }

    #[tokio::test]
    async fn login_alarms_when_a_known_record_names_another_key() {
        // Another install of this owner's here, recorded in installs.json
        // with the key it published, as the shared tail records one.
        let keys = FakeKeyStore::default();
        let (_temp, dirs, state, own) = after_a_first_login(&keys).await;
        let sibling: DeviceId = "sibling-install".parse().expect("valid");
        let published = DeviceIdentity::generate().recipient();
        record_install_key(&dirs, state.pubky, &sibling, &published).expect("records");
        let created_at = clock::now().expect("a time");
        keys.set_record(
            &sibling,
            device_key_bytes(&device_key_record(&published, created_at)).expect("JSON"),
        );

        // Its record holds that key: nothing to say.
        let tail = record_login_and_check_keys(&dirs, None, &keys, state.clone())
            .await
            .expect("a login");
        assert_eq!(tail.key_check, "");

        // Rewritten behind this install's back with another valid,
        // unrevoked key: the id is known, so only the comparison with the
        // recorded key can tell, and login raises the alarm. The login
        // itself goes through, reusing this install's key.
        keys.set_record(&sibling, injected_record(false));
        let tail = record_login_and_check_keys(&dirs, None, &keys, state.clone())
            .await
            .expect("a login");
        assert!(
            matches!(&tail.device, DeviceKeyOutcome::Reused(reused) if reused == &own),
            "{:?}",
            tail.device
        );
        for part in [
            "alarm: keys/sibling-install.json, the device key record of another of this owner's \
             installs here, does not hold the key that install published",
            "`sweepky keys revoke sibling-install`",
        ] {
            assert!(
                tail.key_check.contains(part),
                "{part:?} missing from: {}",
                tail.key_check
            );
        }
        assert!(
            !tail.key_check.contains(&published.to_string()),
            "{}",
            tail.key_check
        );
        assert!(
            !tail.key_check.contains(&format!("keys/{own}.json")),
            "{}",
            tail.key_check
        );

        // Revoked, it takes no further sweeps, and login says nothing more.
        keys.set_record(&sibling, injected_record(true));
        let tail = record_login_and_check_keys(&dirs, None, &keys, state)
            .await
            .expect("a login");
        assert_eq!(tail.key_check, "");
    }

    #[tokio::test]
    async fn later_login_alarms_until_the_unknown_key_is_revoked() {
        // A later login that reuses this install's key: the same alarm.
        let keys = FakeKeyStore::default();
        let (_temp, dirs, state, own) = after_a_first_login(&keys).await;
        keys.set_record(&injected_id(), injected_record(false));
        let tail = record_login_and_check_keys(&dirs, None, &keys, state.clone())
            .await
            .expect("the second login");
        assert!(
            matches!(&tail.device, DeviceKeyOutcome::Reused(reused) if reused == &own),
            "{:?}",
            tail.device
        );
        assert_alarms_on_injected(&tail.key_check);

        // Once the injected key is revoked, the fix is in, and login says
        // nothing more about it.
        keys.set_record(&injected_id(), injected_record(true));
        let tail = record_login_and_check_keys(&dirs, None, &keys, state)
            .await
            .expect("a third login");
        assert_eq!(tail.key_check, "");
    }

    #[tokio::test]
    async fn login_with_only_its_own_key_raises_no_alarm() {
        let keys = FakeKeyStore::default();
        let (_temp, dirs, state, _own) = after_a_first_login(&keys).await;
        let tail = record_login_and_check_keys(&dirs, None, &keys, state)
            .await
            .expect("the second login");
        assert_eq!(tail.key_check, "");
    }

    #[tokio::test]
    async fn a_key_check_that_cannot_finish_is_a_warning_not_a_failed_login() {
        // The check fails with its typed failure, which login reports as a
        // warning pointing at `keys list` (`pull` reports it as an alarm):
        // by now the key is published and login.json written.
        for case in ["a listing past the limit", "a failed read"] {
            let keys = FakeKeyStore::default();
            let (_temp, dirs, state, own) = after_a_first_login(&keys).await;
            if case == "a failed read" {
                keys.fail_reads_of(&own);
            } else {
                for n in 0..=ListLimits::DEFAULT.max_entries {
                    keys.list_without_record(&format!("k{n}").parse().expect("valid"));
                }
            }
            let tail = record_login_and_check_keys(&dirs, None, &keys, state)
                .await
                .expect(case);
            assert!(
                matches!(&tail.device, DeviceKeyOutcome::Reused(reused) if reused == &own),
                "{case}: {:?}",
                tail.device
            );
            let report = &tail.key_check;
            assert!(
                report.starts_with("warning: could not check keys/"),
                "{case}: {report}"
            );
            assert!(report.contains("`sweepky keys list`"), "{case}: {report}");
            assert!(!report.contains("alarm"), "{case}: {report}");
        }
    }

    #[tokio::test]
    async fn reuse_fills_in_the_key_of_an_entry_without_one_and_never_replaces_one() {
        let keys = FakeKeyStore::default();
        let (_temp, dirs, state, id) = after_a_first_login(&keys).await;
        let local = read_device_key(&dirs, None)
            .expect("reads")
            .expect("present")
            .recipient();
        // The first login recorded the id with this install's key.
        assert_eq!(
            read_installs(&dirs)
                .expect("reads")
                .installs_of(&state.pubky),
            [Install::new(id.clone(), Some(local.clone()))]
        );

        // installs.json as an earlier build left it, the id alone: the next
        // login checks the published record against device.key, as it always
        // does, and then records that key.
        fs::remove_file(dirs.installs_file()).expect("remove");
        record_install(&dirs, state.pubky, &id).expect("records");
        record_login(&dirs, None, &keys, state.clone())
            .await
            .expect("the second login");
        assert_eq!(
            read_installs(&dirs)
                .expect("reads")
                .installs_of(&state.pubky),
            [Install::new(id.clone(), Some(local.clone()))]
        );

        // An entry that records another key for this install's id is never
        // overwritten: login stops, naming the record and neither key, and
        // leaves installs.json and login.json as they were.
        fs::remove_file(dirs.installs_file()).expect("remove");
        let other = DeviceIdentity::generate().recipient();
        record_install_key(&dirs, state.pubky, &id, &other).expect("records");
        let before = device_state(&dirs);
        let err = record_login(&dirs, None, &keys, state)
            .await
            .expect_err("another key is recorded for this install");
        let shown = format!("{err:#}");
        assert!(shown.contains(&format!("keys/{id}.json")), "{shown}");
        assert!(shown.contains("never replaces a recorded key"), "{shown}");
        for key in [&local, &other] {
            assert!(!shown.contains(&key.to_string()), "{shown}");
        }
        assert_eq!(device_state(&dirs), before);
    }

    #[tokio::test]
    async fn reuse_records_an_install_entry_that_is_missing() {
        // installs.json lost this install's id (deleted, or restored from an
        // older copy): a login that finds the key and its record in order
        // puts the id back, so the owner's own key never reads as unknown.
        let keys = FakeKeyStore::default();
        let (_temp, dirs, state, id) = after_a_first_login(&keys).await;
        fs::remove_file(dirs.installs_file()).expect("remove");

        record_login(&dirs, None, &keys, state.clone())
            .await
            .expect("the second login");
        assert_eq!(
            read_installs(&dirs).expect("reads").ids_of(&state.pubky),
            [id]
        );
    }
}
