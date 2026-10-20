//! The Pubky Ring login, `sweepky login` without `--identity` (login option
//! A in 03, "Two ways to log in"): the user approves a grant in Pubky Ring,
//! and this install keeps the grant token the SDK exports, from which every
//! later command restores its session.
//!
//! What is here so far:
//!
//! - [`grants_sweepky_write`], the check after approval. A future Ring may
//!   approve less than Sweepky asked for (`/pub/sweepky/:rw`); a grant that
//!   cannot write every Sweepky record is signed out again, and `login`
//!   says what it needed.
//! - [`expiry_notice`], what a later run says within
//!   [`EXPIRY_WARNING_SECS`] (30 days) of the grant's expiry and once it is
//!   past, and [`expiry_text`], how that expiry is shown, as `login` shows
//!   it after approval. The grant lasts two years from approval, a lifetime
//!   the SDK fixes; `login.json` keeps its end as `grantExpiresAt`
//!   (`crate::state::LoginState`). [`expiry_warning`] is the notice as
//!   `crate::run` prints it, once per command, from `login.json` alone.
//! - What a writing command checks when it restores its session from the
//!   token (`crate::session`): [`refuse_expired_grant`] before any request,
//!   [`check_restored_session`] on what the homeserver restored, and
//!   [`restore_error`], the restore's own errors in fixed text.
//! - [`revoke_grant`], how `logout` ends a grant and proves it ended:
//!   restore, the work that needs the live session, sign-out, then a second
//!   restore that must get a 401 ([`GrantRevocation`]).
//! - [`token`], `grant.token`, the owner-only file that holds the token.
//! - [`page`], the sign-in page the loopback server serves, with the
//!   authorization URL's QR code as an inline SVG, a copy button and a live
//!   status, and the QR code `login` prints in the terminal as its fallback.
//! - [`loopback`], that server: one flow's page and status on `127.0.0.1`
//!   at a random port and secret path, under a strict CSP, with bounded
//!   connections, reads and lifetime.
//! - [`flow`], the approval itself: the SDK's grant flow on this network's
//!   own relay, the page, the terminal fallback and the browser, a bounded
//!   wait, and the refusal (signed out again) of an approval that cannot
//!   write `/pub/sweepky/`.
//! - [`login`], `sweepky login` without `--identity`, which puts them
//!   together: the checks before the flow, the approval, and under the
//!   writers' lock the token, P2a's shared tail and `login.json`.
//!
//! The checks are pure: they take the capabilities and the times as
//! arguments, so they are tested without a network or a clock.

use std::fmt;

use anyhow::bail;
use pubky::{Capability, StatusCode};
use sweepky_core::{Pubky, RecordTime};

use crate::Dirs;
use crate::clock;
use crate::network::{CLIENT_ID, SWEEPKY_CAPABILITY};
use crate::remote::{request_error, status_of};
use crate::state::{KnownLoginKind, LoginState, read_login_state};

pub(crate) mod flow;
pub(crate) mod login;
pub(crate) mod loopback;
pub(crate) mod page;
pub(crate) mod token;

/// The letter for write in a capability's actions, as in `/pub/sweepky/:rw`.
const WRITE_ACTION: char = 'w';

/// Whether `granted`, the capabilities of the grant Ring approved, let this
/// install write every Sweepky record: whether one of them both covers the
/// whole of `/pub/sweepky/` and allows write.
///
/// The scope is the one in [`SWEEPKY_CAPABILITY`], what Sweepky asks for,
/// and the SDK's `scope_covers_path` decides what covers it: the same
/// directory, or a broader one such as `/pub/` or the root `/`. A narrower
/// directory (`/pub/sweepky/keys/`), the file scope `/pub/sweepky` without
/// the trailing slash, and a sibling such as `/pub/sweepkyx/` do not. Only
/// write is checked: everything under `/pub/` is readable by anyone, so a
/// grant that writes there can read there too (02, "What Pubky gives us").
/// The scope and the action must come from one capability: read on
/// `/pub/sweepky/` and write somewhere else is not write on `/pub/sweepky/`.
pub(crate) fn grants_sweepky_write(granted: &[Capability]) -> bool {
    // Our own constant, so the parse cannot fail in practice (the network
    // module's tests check it). Should it ever, the answer is `false`: a
    // check that cannot run must never pass a grant.
    let Ok(requested) = SWEEPKY_CAPABILITY.parse::<Capability>() else {
        return false;
    };
    granted.iter().any(|capability| {
        capability.scope_covers_path(requested.scope()) && allows_write(capability)
    })
}

/// Whether `capability`'s actions include write.
fn allows_write(capability: &Capability) -> bool {
    // pubky 0.16.2 does not re-export the SDK's `Action` enum, so
    // `Action::Write` cannot be named here without a direct dependency on
    // pubky-common. Each action converts to the letter the capability text
    // uses for it (the SDK's `From<&Action> for char`, an impl the compiler
    // finds without the type in scope), and write's is `w`. The SDK parses
    // `w` into its write action, so a granted write always shows up as `w`.
    capability
        .actions()
        .iter()
        .any(|action| char::from(action) == WRITE_ACTION)
}

/// How long before its grant expires a Ring login starts warning: 30 days
/// (03, "Two ways to log in").
pub(crate) const EXPIRY_WARNING_SECS: u64 = 30 * SECONDS_PER_DAY;

/// One day in seconds. Unix time counts every day as exactly this many.
const SECONDS_PER_DAY: u64 = 86_400;

/// What a run tells the user about the expiry of the grant its Ring login
/// holds. `Display` writes the line to print: the expiry in RFC 3339 and
/// what to run.
///
/// Holds a public time only, so it derives `Debug` and compares freely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExpiryNotice {
    /// The grant expires within [`EXPIRY_WARNING_SECS`], at `expires_at`
    /// (Unix seconds).
    Soon {
        /// When it expires.
        expires_at: u64,
    },
    /// The grant expired at `expires_at` (Unix seconds), or expires this
    /// very second, so the homeserver no longer takes it.
    Expired {
        /// When it expired.
        expires_at: u64,
    },
}

/// The notice for a grant that expires at `expires_at`, as seen at `now`,
/// both Unix seconds; `None` while more than [`EXPIRY_WARNING_SECS`] are
/// left.
///
/// Exactly 30 days left, or less, is [`ExpiryNotice::Soon`]; none left
/// (`now` at or past `expires_at`) is [`ExpiryNotice::Expired`]. Any two
/// values are safe, `0` and `u64::MAX` included: the expiry is what the
/// homeserver reported, so nothing here may overflow or panic on it.
// Denies plain `+`, `-` and `*` on integers inside this function, which
// could overflow, so a later edit cannot slip one in.
#[deny(clippy::arithmetic_side_effects)]
pub(crate) fn expiry_notice(now: u64, expires_at: u64) -> Option<ExpiryNotice> {
    // `checked_sub` is `None` when `now` is past `expires_at`. A plain `-`
    // would overflow there: a panic in a debug build, and in a release
    // build a wrap to some 584 billion years left, which would never warn.
    match expires_at.checked_sub(now) {
        None | Some(0) => Some(ExpiryNotice::Expired { expires_at }),
        // A match guard: this arm matches only when the `if` holds.
        Some(left) if left <= EXPIRY_WARNING_SECS => Some(ExpiryNotice::Soon { expires_at }),
        Some(_) => None,
    }
}

impl fmt::Display for ExpiryNotice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `*self` copies the value out (the enum is `Copy`), so the
        // patterns bind plain `u64`s rather than references to them.
        match *self {
            Self::Soon { expires_at } => write!(
                f,
                "this install's Pubky Ring grant expires at {}; run `sweepky login` before then to \
                 approve a new one in Ring",
                expiry_text(expires_at)
            ),
            Self::Expired { expires_at } => write!(
                f,
                "this install's Pubky Ring grant expired at {}, so Sweepky can no longer sign in \
                 with it; run `sweepky login` to approve a new one in Ring",
                expiry_text(expires_at)
            ),
        }
    }
}

/// The expiry notice for this install's Ring login, as `crate::run` prints
/// it once per command: `None` unless `login.json` records a Ring login
/// within [`EXPIRY_WARNING_SECS`] of its `grantExpiresAt`, or past it.
///
/// It reads `login.json` and the clock, and nothing else: no `grant.token`,
/// no passphrase and no network, so it works offline and before any command
/// has started. Whatever it cannot read gives `None` (`.ok()` turns an
/// error into `None`, and `?` on an `Option` returns `None` early): the
/// command itself reads `login.json` again and reports a broken file or
/// clock in its own words, so a second report here would only repeat it.
pub(crate) fn expiry_warning(dirs: &Dirs) -> Option<ExpiryNotice> {
    let login = read_login_state(dirs).ok().flatten()?;
    if login.kind.as_known() != Some(KnownLoginKind::Ring) {
        return None;
    }
    let expires_at = login.grant_expires_at?;
    expiry_notice(clock::now_unix_seconds().ok()?, expires_at)
}

/// Refuses a Ring `login` whose grant has expired by `now` (Unix seconds),
/// or that records no expiry at all, in fixed text and before any request:
/// the homeserver would refuse the restore anyway, and asking it would only
/// send the token for nothing.
pub(crate) fn refuse_expired_grant(login: &LoginState, now: u64) -> anyhow::Result<()> {
    let Some(expires_at) = login.grant_expires_at else {
        bail!(NO_GRANT_EXPIRY);
    };
    // `@` binds the whole matched value to `notice` while the pattern still
    // checks it is the `Expired` variant; a grant that is merely close to its
    // end is the dispatch's warning, not a refusal.
    if let Some(notice @ ExpiryNotice::Expired { .. }) = expiry_notice(now, expires_at) {
        bail!(notice.to_string());
    }
    Ok(())
}

/// What a Ring login whose `login.json` has no `grantExpiresAt` says.
pub(crate) const NO_GRANT_EXPIRY: &str = "login.json records a Pubky Ring login with no \
     grantExpiresAt, so Sweepky cannot tell whether its grant is still valid; run `sweepky login` \
     again";

/// What a writing command says when the homeserver no longer takes the
/// saved grant: it was revoked (in Ring, or by a `logout` elsewhere) or has
/// expired.
pub(crate) const GRANT_NOT_ACCEPTED: &str = "the homeserver no longer accepts this install's \
     Pubky Ring grant (it was revoked, or it expired), so Sweepky cannot write with it; run \
     `sweepky login` again to approve a new one in Ring";

/// What a restored session for another pubky than `login.json`'s says.
pub(crate) const RESTORED_OTHER_PUBKY: &str = "the saved Pubky Ring grant restored a session \
     for another pubky than the one login.json records, so Sweepky will not write with it; run \
     `sweepky login` again";

/// What a restored session made for another app than `sweepky-cli` says.
pub(crate) const RESTORED_OTHER_CLIENT: &str = "the saved Pubky Ring grant was not made for \
     sweepky-cli, so Sweepky will not write with it; run `sweepky login` again";

/// What a restored session that cannot write `/pub/sweepky/` says.
pub(crate) const RESTORED_NO_WRITE: &str = "the saved Pubky Ring grant cannot write \
     /pub/sweepky/, so Sweepky will not write with it; run `sweepky login` again and approve \
     the full request in Ring";

/// Checks what the homeserver restored from the saved token before any
/// write: the session's `pubky` must be `expected`, `login.json`'s; its
/// `client_id` must be `sweepky-cli`; and its `capabilities` must write
/// `/pub/sweepky/` ([`grants_sweepky_write`]).
///
/// The values come from the server, so they are only compared, never
/// printed: each refusal is one of the fixed texts above. The pubky is
/// compared as bytes (`Pubky`'s `==`), the client id as an exact string.
pub(crate) fn check_restored_session(
    expected: Pubky,
    pubky: Pubky,
    client_id: &str,
    capabilities: &[Capability],
) -> anyhow::Result<()> {
    if pubky != expected {
        bail!(RESTORED_OTHER_PUBKY);
    }
    if client_id != CLIENT_ID {
        bail!(RESTORED_OTHER_CLIENT);
    }
    if !grants_sweepky_write(capabilities) {
        bail!(RESTORED_NO_WRITE);
    }
    Ok(())
}

/// The error of `restore_session` as fixed text: [`GRANT_NOT_ACCEPTED`]
/// when the homeserver or the SDK refused the grant itself (a 401 or 403,
/// or the SDK's authentication error, which covers an expired or mismatched
/// stored grant), and `remote::request_error`'s fixed text for anything
/// else, such as a network failure, which says nothing about the grant.
///
/// The SDK's own `Display` is never used: it can quote the server's answer.
pub(crate) fn restore_error(error: &pubky::Error) -> anyhow::Error {
    let refused = matches!(
        status_of(error),
        Some(StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN)
    ) || matches!(error, pubky::Error::Authentication(_));
    if refused {
        anyhow::Error::msg(GRANT_NOT_ACCEPTED)
    } else {
        request_error(error).context("could not restore this install's Pubky Ring session")
    }
}

/// `login.json`'s `grantExpiresAt` when it is at or before `now` (both Unix
/// seconds), so the grant has expired; `None` while it has not. A login
/// that records no expiry is not known to have expired, so that is `None`
/// too, and the homeserver decides.
pub(crate) fn expired_grant_at(login: &LoginState, now: u64) -> Option<u64> {
    // `filter` keeps the value only when the closure says `true`, so a
    // missing expiry and a future one both come out as `None`.
    login.grant_expires_at.filter(|&expires_at| {
        matches!(
            expiry_notice(now, expires_at),
            Some(ExpiryNotice::Expired { .. })
        )
    })
}

/// What one restore of the saved grant token gave, for [`revoke_grant`].
///
/// Generic over the session type `S`, so the tests can stand a fake in for
/// the real `crate::session::WriterSession`.
pub(crate) enum Restored<S> {
    /// The homeserver took the token: a live session.
    Live(S),
    /// The homeserver answered 401: it no longer takes this grant, because
    /// it was revoked (in Ring, or by an earlier sign-out) or has expired.
    Refused,
}

/// How [`revoke_grant`] ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum GrantRevocation<T> {
    /// Signed out, and the restore after the sign-out got a 401: the grant
    /// is revoked for certain. `T` is what the live-session work gave.
    Revoked(T),
    /// The first restore got a 401 already, so there was no session to do
    /// anything with: the grant was revoked or had expired before.
    AlreadyRevoked,
    /// The sign-out failed, or the restore after it was anything but a 401
    /// (a session, or an error that says nothing about the grant). The grant
    /// may still be live, so the token must be kept for another try.
    NotConfirmed,
}

/// Ends the grant behind the saved token, and proves it is ended:
///
/// 1. `restore` a session from the token; a 401 is
///    [`GrantRevocation::AlreadyRevoked`] at once, any other error is
///    returned;
/// 2. `with_live`, the work that needs the live session (for `logout`, the
///    revoke of this install's device key), which borrows it;
/// 3. `sign_out`, which takes the session by value and revokes the grant;
/// 4. `restore` again, which must now get a 401
///    ([`GrantRevocation::Revoked`]); anything else is
///    [`GrantRevocation::NotConfirmed`].
///
/// When step 2 fails, its error comes back and the session is dropped, *not*
/// signed out: a grant revoked first would lock this install out of the
/// device key it could not yet revoke. The closures are the seams, as in
/// `logout::retire`, so the tests run every ending without a homeserver.
/// `restore` is an `AsyncFn` (callable more than once, through a shared
/// borrow) because it runs twice; the others run once.
pub(crate) async fn revoke_grant<S, T>(
    restore: impl AsyncFn() -> anyhow::Result<Restored<S>>,
    with_live: impl AsyncFnOnce(&S) -> anyhow::Result<T>,
    sign_out: impl AsyncFnOnce(S) -> anyhow::Result<()>,
) -> anyhow::Result<GrantRevocation<T>> {
    let session = match restore().await? {
        Restored::Live(session) => session,
        Restored::Refused => return Ok(GrantRevocation::AlreadyRevoked),
    };
    // `?` returns here with `session` still owned by this function, so it
    // is dropped on the way out, never signed out.
    let done = with_live(&session).await?;
    if sign_out(session).await.is_err() {
        return Ok(GrantRevocation::NotConfirmed);
    }
    Ok(match restore().await {
        Ok(Restored::Refused) => GrantRevocation::Revoked(done),
        // A session that still restores is dropped unused when the match
        // ends; an error proves nothing either way.
        Ok(Restored::Live(_)) | Err(_) => GrantRevocation::NotConfirmed,
    })
}

/// `expires_at`, Unix seconds, as `login` and the notices show it: RFC 3339
/// in UTC to the second, such as `2028-10-19T09:41:07Z`, the form Sweepky
/// writes in records (core's `RecordTime::from_unix_seconds`).
///
/// RFC 3339 has no year past 9999, and core refuses to write one; only a
/// broken or hostile homeserver would report such an expiry, so it is shown
/// as `after 9999-12-31T23:59:59Z` instead of failing.
pub(crate) fn expiry_text(expires_at: u64) -> String {
    match RecordTime::from_unix_seconds(expires_at) {
        Ok(time) => time.as_str().to_owned(),
        Err(_) => "after 9999-12-31T23:59:59Z".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use pubky::Capability;
    use sweepky_core::RecordTime;

    use super::{
        EXPIRY_WARNING_SECS, ExpiryNotice, NO_GRANT_EXPIRY, RESTORED_NO_WRITE,
        RESTORED_OTHER_CLIENT, RESTORED_OTHER_PUBKY, check_restored_session, expiry_notice,
        expiry_text, grants_sweepky_write, refuse_expired_grant,
    };
    use crate::CLIENT_ID;
    use crate::state::LoginState;
    use crate::test_support::random_pubky;

    /// One day in seconds.
    const DAY: u64 = 86_400;

    /// 2026-10-20T00:00:00Z.
    const NOW: u64 = 1_792_454_400;

    /// `list` parsed as the SDK parses a grant's capabilities.
    fn caps(list: &[&str]) -> Vec<Capability> {
        list.iter()
            .map(|cap| cap.parse().expect("a valid capability"))
            .collect()
    }

    #[test]
    fn write_on_the_whole_sweepky_directory_is_what_counts() {
        // What Sweepky asks for, write alone, and broader directory scopes
        // that cover all of `/pub/sweepky/`.
        for granted in ["/pub/sweepky/:rw", "/pub/sweepky/:w", "/:rw", "/pub/:rw"] {
            assert!(grants_sweepky_write(&caps(&[granted])), "{granted}");
        }
        // Read only (the narrowed approval of the end-to-end test), a
        // narrower directory, the file scope `/pub/sweepky` without its
        // trailing slash, a sibling whose name only starts the same, and
        // nothing at all.
        for granted in [
            &["/pub/sweepky/:r"][..],
            &["/pub/sweepky/keys/:rw"],
            &["/pub/sweepky:rw"],
            &["/pub/sweepkyx/:rw"],
            &[],
        ] {
            assert!(!grants_sweepky_write(&caps(granted)), "{granted:?}");
        }
        // Read here and write elsewhere do not add up to write here: one
        // capability has to give both the scope and the action.
        assert!(!grants_sweepky_write(&caps(&[
            "/pub/sweepky/:r",
            "/pub/other/:w"
        ])));
    }

    #[test]
    fn more_than_30_days_left_gives_no_notice() {
        assert_eq!(EXPIRY_WARNING_SECS, 30 * DAY);
        assert_eq!(expiry_notice(NOW, NOW + 30 * DAY + 1), None);
        // A fresh grant: two years.
        assert_eq!(expiry_notice(NOW, NOW + 2 * 365 * DAY), None);
    }

    #[test]
    fn thirty_days_or_less_warns_with_the_expiry_and_login() {
        // Exactly 30 days left: 2026-11-19T00:00:00Z.
        let notice = expiry_notice(NOW, NOW + 30 * DAY).expect("a warning");
        assert_eq!(
            notice,
            ExpiryNotice::Soon {
                expires_at: NOW + 30 * DAY
            }
        );
        let text = notice.to_string();
        assert!(text.contains("2026-11-19T00:00:00Z"), "{text}");
        assert!(text.contains("`sweepky login`"), "{text}");
        assert!(!text.contains("expired"), "{text}");

        for left in [12 * DAY + 5, 1] {
            let expires_at = NOW + left;
            let notice = expiry_notice(NOW, expires_at).expect("a warning");
            assert_eq!(notice, ExpiryNotice::Soon { expires_at });
            let shown = RecordTime::from_unix_seconds(expires_at).expect("a time");
            assert!(notice.to_string().contains(shown.as_str()), "{notice}");
        }
    }

    #[test]
    fn at_or_past_the_expiry_is_the_expired_form() {
        for now in [NOW, NOW + 1, NOW + 400 * DAY] {
            let notice = expiry_notice(now, NOW).expect("a notice");
            assert_eq!(notice, ExpiryNotice::Expired { expires_at: NOW });
            let text = notice.to_string();
            assert!(text.contains("expired"), "{text}");
            assert!(text.contains("2026-10-20T00:00:00Z"), "{text}");
            assert!(text.contains("`sweepky login`"), "{text}");
        }
    }

    #[test]
    fn extreme_times_never_panic() {
        for (now, expires_at) in [
            (0, 0),
            (0, u64::MAX),
            (u64::MAX, 0),
            (u64::MAX, u64::MAX),
            (u64::MAX - 1, u64::MAX),
        ] {
            // `to_string` runs `Display`, which writes the time.
            if let Some(notice) = expiry_notice(now, expires_at) {
                assert!(notice.to_string().contains("sweepky login"), "{notice}");
            }
        }
        assert_eq!(expiry_notice(0, u64::MAX), None);
        assert_eq!(
            expiry_notice(u64::MAX, 0),
            Some(ExpiryNotice::Expired { expires_at: 0 })
        );
        assert_eq!(
            expiry_notice(u64::MAX - 1, u64::MAX),
            Some(ExpiryNotice::Soon {
                expires_at: u64::MAX
            })
        );
    }

    #[test]
    fn the_expiry_is_shown_as_rfc_3339() {
        assert_eq!(expiry_text(NOW), "2026-10-20T00:00:00Z");
        assert_eq!(expiry_text(0), "1970-01-01T00:00:00Z");
        // RFC 3339 has no year past 9999, so such a time says so.
        assert_eq!(expiry_text(u64::MAX), "after 9999-12-31T23:59:59Z");
    }

    #[test]
    fn a_restored_session_must_be_this_login_for_sweepky_cli_with_write() {
        let expected = random_pubky();
        let full = caps(&["/pub/sweepky/:rw"]);
        assert!(check_restored_session(expected, expected, CLIENT_ID, &full).is_ok());

        // Each value wrong on its own, with the others right: each refusal
        // is its fixed text, quoting none of the values.
        let other = random_pubky();
        for (pubky, client_id, granted, refusal) in [
            (other, CLIENT_ID, full.clone(), RESTORED_OTHER_PUBKY),
            (expected, "another-app", full.clone(), RESTORED_OTHER_CLIENT),
            (
                expected,
                "sweepky-cli ",
                full.clone(),
                RESTORED_OTHER_CLIENT,
            ),
            (
                expected,
                CLIENT_ID,
                caps(&["/pub/sweepky/:r"]),
                RESTORED_NO_WRITE,
            ),
            (expected, CLIENT_ID, Vec::new(), RESTORED_NO_WRITE),
        ] {
            let error =
                check_restored_session(expected, pubky, client_id, &granted).expect_err("refused");
            assert_eq!(format!("{error:#}"), refusal);
            assert!(!refusal.contains(&other.to_string()), "{refusal}");
        }
    }

    #[test]
    fn only_an_expired_grant_is_refused_before_the_restore() {
        let login = |expires_at| LoginState::ring(random_pubky(), random_pubky(), expires_at);
        // Plenty left, and close to the end: both restore.
        assert!(refuse_expired_grant(&login(NOW + 400 * DAY), NOW).is_ok());
        assert!(refuse_expired_grant(&login(NOW + 10 * DAY), NOW).is_ok());
        // At or past the end: the expired notice's own text.
        for expires_at in [NOW, NOW - 1, 0] {
            let error = refuse_expired_grant(&login(expires_at), NOW).expect_err("refused");
            assert_eq!(
                error.to_string(),
                ExpiryNotice::Expired { expires_at }.to_string()
            );
        }
        // No expiry recorded at all: refused too, never taken as unlimited.
        let mut unknown = login(NOW + 400 * DAY);
        unknown.grant_expires_at = None;
        let error = refuse_expired_grant(&unknown, NOW).expect_err("refused");
        assert_eq!(error.to_string(), NO_GRANT_EXPIRY);
    }
}
