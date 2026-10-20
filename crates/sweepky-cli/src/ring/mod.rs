//! The Pubky Ring login, `sweepky login` without `--identity` (login option
//! A in 03, "Two ways to log in"): the user approves a grant in Pubky Ring,
//! and this install keeps the grant token the SDK exports, from which every
//! later command restores its session.
//!
//! What is here so far, all of it the local half of that login:
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
//!   (`crate::state::LoginState`).
//! - [`token`], `grant.token`, the owner-only file that holds the token.
//! - [`page`], the sign-in page the loopback server serves, with the
//!   authorization URL's QR code as an inline SVG, a copy button and a live
//!   status, and the QR code `login` prints in the terminal as its fallback.
//! - [`loopback`], that server: one flow's page and status on `127.0.0.1`
//!   at a random port and secret path, under a strict CSP, with bounded
//!   connections, reads and lifetime.
//!
//! The checks are pure: they take the capabilities and the times as
//! arguments, so they are tested without a network or a clock.

use std::fmt;

use pubky::Capability;
use sweepky_core::RecordTime;

use crate::network::SWEEPKY_CAPABILITY;

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
        EXPIRY_WARNING_SECS, ExpiryNotice, expiry_notice, expiry_text, grants_sweepky_write,
    };

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
}
