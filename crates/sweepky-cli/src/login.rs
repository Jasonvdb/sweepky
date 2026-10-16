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
//!    (0600), its id in `installs.json` under this owner, and then the write
//!    of `keys/<deviceId>.json`. That write is also the check that this
//!    identity may write under `/pub/sweepky/` at all: a 403 or a 507 aborts
//!    with its own message ([`crate::remote::write_error`]), and any failure
//!    removes the key file and the install entry this run made, and nothing
//!    else; the identity stays.
//! 7. **Record and sign out**: write `login.json`, with the device id, and
//!    sign out again: every later command signs in and out on its own
//!    ([`crate::session`]). The report ends with the reminder to back up the
//!    config directory when a new key was made.
//!
//! **The signup token is never printed.** The SDK puts it in the signup
//! request's URL (`?signup_token=…`), and a transport error's `Display`
//! includes that URL, so a failed signup is reported as fixed text and the
//! HTTP status only ([`signup_error`]), never through the SDK's own message.

use std::fmt;

use anyhow::{Context as _, anyhow, bail};
use pubky::{PubkySigner, PublicKey, StatusCode};
use sweepky_core::{DeviceId, DeviceIdentity, ExposeSecret, Pubky, SecretString};

use crate::clock;
use crate::device::{
    KeyStore, SessionKeyStore, create_device_key, device_key_bytes, device_key_record,
    new_device_id, remove_device_key,
};
use crate::identity::{IdentityMeta, IdentityName, IdentitySecret, read_argument_file};
use crate::installs::{forget_install, record_install};
use crate::network::{NetworkKind, client_id};
use crate::remote::{request_error, status_of, write_error};
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
    /// `login.json` already records this install's device key, so the tail
    /// did not run and nothing was made.
    AlreadyRecorded,
}

/// Writes `login.json` for `state`, running the shared tail of `login` first
/// when `state` records no device key yet: on this install's first login, or
/// after an earlier tail rolled back.
///
/// `keys` is where `keys/<deviceId>.json` goes: the signed-in session in
/// `login`, a fake in the tests. On any failure of the tail `login.json` is
/// left as it was, so it never names a device key that is not published.
async fn record_login(
    dirs: &Dirs,
    keys: &impl KeyStore,
    mut state: LoginState,
) -> anyhow::Result<DeviceKeyOutcome> {
    if state.device_id.is_some() {
        write_login_state(dirs, &state)?;
        return Ok(DeviceKeyOutcome::AlreadyRecorded);
    }
    let id = publish_device_key(dirs, keys, state.pubky).await?;
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
/// 2. its secret in `device.key`, refused (with nothing changed) when a key
///    file is there already;
/// 3. its id in `installs.json` under `owner`;
/// 4. the record, `keys/<id>.json`, written through `keys`: the capability
///    probe. A 403 or a 507 becomes its own message, never the server's.
///
/// On a failure after step 2 the key file and the install entry this run
/// made are removed again, and nothing else: an existing key file is
/// refused in step 2, before there is anything to undo.
async fn publish_device_key(
    dirs: &Dirs,
    keys: &impl KeyStore,
    owner: Pubky,
) -> anyhow::Result<DeviceId> {
    let created_at = clock::now()?;
    let id = new_device_id()?;
    let identity = DeviceIdentity::generate();
    let record = device_key_bytes(&device_key_record(&identity, created_at))?;
    // The secret is saved before anything is published, so a crash can
    // never leave a published key that nothing on this machine can open.
    create_device_key(dirs, &identity)?;
    // The id is recorded before the write too, so this owner's own key never
    // shows up as unknown under `keys/`.
    if let Err(error) = record_install(dirs, owner, &id) {
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
    let stored = read_identity(&ctx.dirs, name)?;
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
    // 3. Create or reuse. `stored` is moved apart here: each arm takes the
    // secret out of it by value.
    let (secret, mut meta) = match stored {
        StoredIdentity::Complete { secret, meta } => (secret, meta),
        StoredIdentity::Missing => {
            let secret = IdentitySecret::generate();
            let meta = IdentityMeta::new(name.clone(), secret.pubky(), plan.homeserver, false);
            create_identity(&ctx.dirs, &secret, &meta)?;
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

    // 5. to 7. Sign in, publish this install's device key on its first
    // login, record the login, sign out.
    let device = sign_in_and_record(ctx, &signer, &meta, current).await?;
    report.push_str(&format!(
        "Logged in as {name}, pubky {}, on homeserver {}.\n",
        meta.pubky, meta.homeserver
    ));
    if let DeviceKeyOutcome::Published(id) = device {
        report.push_str(&published_key_report(&ctx.dirs, &id));
    }
    Ok(Report::new(report))
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
/// none for this pubky ([`record_login`]), writes `login.json` for the
/// identity `meta` describes ([`login_state_for`], which `current` is moved
/// into), and signs out again.
///
/// The sign-out runs whether that worked or not; the error is returned
/// after it.
async fn sign_in_and_record(
    ctx: &Context,
    signer: &PubkySigner,
    meta: &IdentityMeta,
    current: Option<LoginState>,
) -> anyhow::Result<DeviceKeyOutcome> {
    let session = signer
        .signin_blocking(client_id()?)
        .await
        .map_err(|err| request_error(&err))
        .context("could not sign in to the homeserver")?;
    let state = login_state_for(meta, current);
    // The store borrows the session. That borrow ends when `record_login`'s
    // future is done, so the session can then be moved into `sign_out`,
    // which consumes it.
    let keys = SessionKeyStore::new(&session, ctx.network.pubky());
    let recorded = record_login(&ctx.dirs, &keys, state).await;
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

/// The SDK's key as core's `Pubky`: the same 32 bytes.
fn pubky_of(key: &PublicKey) -> Pubky {
    Pubky::from_bytes(key.to_bytes())
}

/// Core's `Pubky` as the SDK's key, which checks it is a valid Ed25519 point.
fn public_key_of(pubky: &Pubky) -> anyhow::Result<PublicKey> {
    PublicKey::try_from_z32(&pubky.to_string())
        .map_err(|_| anyhow!("{pubky} is not a valid public key"))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use pubky::StatusCode;
    use pubky::errors::RequestError;
    use sweepky_core::{DeviceId, DeviceIdentity, Pubky};
    use tempfile::TempDir;

    use super::{
        Found, LoginPlan, PlanInput, ProductionWarning, SignupOutcome, plan_login, record_login,
        signup_error, signup_outcome,
    };
    use crate::Dirs;
    use crate::device::{create_device_key, read_device_key};
    use crate::identity::{IdentityMeta, IdentityName, IdentitySecret};
    use crate::installs::{read_installs, record_install};
    use crate::network::{NetworkKind, PRODUCTION_HOMESERVER, TESTNET_HOMESERVER};
    use crate::remote::{QUOTA_FULL, WRITE_FORBIDDEN};
    use crate::state::{
        LoginState, StoredIdentity, create_identity, read_identity, read_login_state,
        write_login_state,
    };
    use crate::test_support::{
        FAKE_SERVER_TEXT, FakeKeyStore, KeyStoreCall, dirs_in, private_temp, random_pubky,
    };

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
        create_identity(&dirs, &secret, &meta).expect("creates");
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

            let err = record_login(&dirs, &keys, state.clone())
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
                read_identity(&dirs, name).expect("reads"),
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
        create_device_key(&dirs, &existing).expect("written");
        let keys = FakeKeyStore::default();

        let err = record_login(&dirs, &keys, state.clone())
            .await
            .expect_err("refused");
        assert!(format!("{err:#}").contains("never replaces"), "{err:#}");
        assert_eq!(keys.calls(), []);
        let kept = read_device_key(&dirs).expect("reads").expect("kept");
        assert_eq!(kept.recipient(), existing.recipient());
        assert_eq!(
            read_installs(&dirs).expect("reads").ids_of(&state.pubky),
            [earlier]
        );
        assert_eq!(read_login_state(&dirs).expect("reads"), Some(state));
    }
}
