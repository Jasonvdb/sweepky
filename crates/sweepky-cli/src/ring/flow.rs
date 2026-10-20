//! The approval half of the Pubky Ring login (login option A in 03, "How
//! the Ring sign-in looks"): [`sign_in_with_ring`] asks Ring for a grant,
//! waits for the approval and hands back the session of the identity that
//! approved it, once its capabilities are known to write `/pub/sweepky/`.
//!
//! In order, it:
//!
//! 1. builds the SDK's grant flow with `PubkyGrantAuthFlow::builder`, this
//!    network's own relay and client, exactly [`SWEEPKY_CAPABILITY`] and the
//!    default grant format (a bare grant, no encryption scopes), which
//!    today's Ring approves. Never the convenience constructor, which sets
//!    no relay, so a testnet login would post its approval through the
//!    production relay; `clippy.toml` bans it;
//! 2. opens the loopback page ([`LoopbackServer`]) for the flow's
//!    `pubkyauth://` link, prints the terminal fallback (what is asked
//!    for, the page's URL, the link and its QR code) and opens the page in
//!    the browser ([`crate::Browser`]);
//! 3. serves the page while it waits for the approval, at most the timeout
//!    it is given ([`LOGIN_TIMEOUT`] for `login`), and tells the page how
//!    it ended through a `watch` channel;
//! 4. refuses an approval whose granted capabilities do not write all of
//!    `/pub/sweepky/` ([`super::grants_sweepky_write`]): it signs that
//!    session out, which revokes the grant, and only then returns the
//!    error.
//!
//! **The writers' lock is not held here.** A human may take minutes to
//! scan the code, and every other command on this install would wait for
//! the lock that long and then time out. `login` takes the lock once this
//! has returned an approved session.
//!
//! **Secrets.** The `pubkyauth://` link carries the relay channel's secret,
//! and the page's URL the path that guards the page. Both go to standard
//! error (the fallback) and the page only: never into an error, a log line
//! or a file. Every SDK error goes through [`request_error`], whose text is
//! fixed, because the SDK's own `Display` of a transport error can hold the
//! relay URL with the channel in it. The SDK's `GrantAuthFlowState` and
//! `save_local`, which would write the pending flow's secrets out, are
//! never used. Nothing here calls `Debug` on the flow or the session.
//!
//! **The timeout.** pubky 0.16.2's relay listener long-polls the relay with
//! no deadline of its own (`HttpRelayInboxChannel::poll` with no timeout,
//! retried on each of the relay's ~25 s `408` answers), so a pending flow
//! never runs out by itself: `RequestExpired` comes only when the listener
//! stops without a message. The relay's 5-minute TTL is how long it keeps
//! an approval nobody has collected, which the flow collects at once. So
//! [`LOGIN_TIMEOUT`] alone bounds the wait.

use std::time::Duration;

use anyhow::{Context as _, anyhow, bail};
use pubky::errors::AuthError;
use pubky::{AuthFlowKind, Capabilities, PubkyGrantAuthFlow, PubkySession};
use tokio::sync::watch;
use tokio::time::Instant;
use url::Url;

use super::grants_sweepky_write;
use super::loopback::{Limits, LoopbackServer};
use super::page::{SignInStatus, terminal_qr};
use crate::Context;
use crate::network::{CLIENT_ID, SWEEPKY_CAPABILITY, client_id};
use crate::remote::request_error;

/// How long `login` waits for the approval in Ring: ten minutes, time
/// enough to find the phone and scan, and no longer, so a forgotten
/// terminal does not hold a live relay channel for good.
pub(crate) const LOGIN_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// The error for an approval that cannot write all of `/pub/sweepky/`,
/// once its session is signed out again.
pub(crate) const NARROWED_GRANT: &str = "Pubky Ring approved less than Sweepky asked for: \
     Sweepky needs write on /pub/sweepky/, so it signed out again and saved nothing; approve \
     the full request in Ring, or log in with `sweepky login --identity <name>` instead";

/// The same refusal when signing that session out failed too, so the grant
/// is still live on the homeserver.
const NARROWED_GRANT_STILL_LIVE: &str = "Pubky Ring approved less than Sweepky asked for: \
     Sweepky needs write on /pub/sweepky/ and saved nothing, but could not sign out again, so \
     revoke the grant of sweepky-cli in Ring; then approve the full request, or log in with \
     `sweepky login --identity <name>` instead";

/// Asks Pubky Ring for a grant of [`SWEEPKY_CAPABILITY`] and waits up to
/// `timeout` for its approval: the session of the identity that approved
/// it, whose grant writes all of `/pub/sweepky/`.
///
/// Errors, all fixed text that quotes neither the link nor the page's URL:
/// no approval within `timeout` (the page then says `expired`), an
/// approval narrowed below write on `/pub/sweepky/` ([`NARROWED_GRANT`],
/// after the session is signed out; the page says `refused`), or a failure
/// of the flow, the server or standard error.
///
/// The caller holds no lock while this waits (see the module docs).
pub(crate) async fn sign_in_with_ring(
    ctx: &Context,
    timeout: Duration,
) -> anyhow::Result<PubkySession> {
    let flow = start_flow(ctx)?;
    // The SDK hands the link back as a `Url`, a copy it does not wipe; it
    // lives only until the page and the fallback are made from it.
    let link = flow.authorization_url();
    let server = LoopbackServer::bind(link.as_str()).await?;
    // Our own server's URL, so it parses; the error is fixed text anyway,
    // because the URL's path is a secret.
    let page_url = Url::parse(server.url())
        .map_err(|_| anyhow!("the Pubky Ring sign-in page's URL does not parse"))?;
    print_fallback(ctx, &page_url, link.as_str(), timeout)?;
    drop(link);
    // Whether the browser opened changes nothing: the fallback is already
    // on the terminal, and a failure to open has printed its warning.
    ctx.browser.open(&page_url, &ctx.stderr).await?;
    drop(page_url);
    serve_until_approved(server, flow, timeout).await
}

/// Serves the page while it waits up to `timeout` for the flow's approval,
/// and returns the checked approval ([`await_checked_approval`]) once the
/// server has stopped too.
async fn serve_until_approved(
    server: LoopbackServer,
    flow: PubkyGrantAuthFlow,
    timeout: Duration,
) -> anyhow::Result<PubkySession> {
    let limits = Limits::DEFAULT;
    // The server outlives the wait by one linger, so a page still open
    // when the time runs out can read `expired` before the server stops.
    // `checked_add` is `None` on overflow, where `+` would panic.
    let deadline = Instant::now()
        .checked_add(timeout)
        .and_then(|end| end.checked_add(limits.linger))
        .ok_or_else(|| anyhow!("the Pubky Ring sign-in's timeout is too long"))?;
    let (status, watched) = watch::channel(SignInStatus::Waiting);
    // `join!` runs both futures in this one task, taking turns whenever one
    // waits, and finishes when both have. So the server can borrow nothing
    // and needs no `'static` spawn, and neither outlives this function.
    // The server stops by itself once the page has seen the final status
    // (or after its linger), or at once if `status` is dropped while still
    // `waiting`, which is what a failed flow does.
    let ((), approval) = tokio::join!(
        server.serve(watched, deadline, limits),
        await_checked_approval(flow, timeout, status),
    );
    approval
}

/// The grant flow for this network: the builder, never the convenience
/// constructor, with the network's own relay and client, exactly
/// [`SWEEPKY_CAPABILITY`] and `sweepky-cli`.
///
/// `.approval_format()` is never called, so the flow asks for the default
/// bare grant, the format today's Ring signs; the signed-approval format
/// exists for encryption scopes, which Sweepky does not ask for.
fn start_flow(ctx: &Context) -> anyhow::Result<PubkyGrantAuthFlow> {
    // Our own constant, so neither parse can fail in practice (the network
    // module's tests check the capability). Each error is fixed text all
    // the same, as everything here returns.
    let capabilities: Capabilities = SWEEPKY_CAPABILITY
        .parse()
        .map_err(|_| anyhow!("the capability {SWEEPKY_CAPABILITY} does not parse"))?;
    let relay = Url::parse(ctx.network.settings().relay_url())
        .map_err(|_| anyhow!("this network's Pubky relay URL does not parse"))?;
    PubkyGrantAuthFlow::builder(&capabilities, AuthFlowKind::signin(), client_id()?)
        .relay(relay)
        // `clone` of a client shares its connection pool and pkarr cache
        // (it is reference-counted inside); the builder takes its own.
        .client(ctx.network.pubky().client().clone())
        .start()
        .map_err(|error| request_error(&error))
        .context("could not start the Pubky Ring sign-in")
}

/// Writes the terminal fallback to standard error: what is asked for, the
/// page's URL, the link's QR code and the link itself, for an SSH session
/// or a machine with no browser. The one place outside the page that
/// shows the link.
fn print_fallback(
    ctx: &Context,
    page_url: &Url,
    link: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let qr = terminal_qr(link)?;
    ctx.stderr.write_flushed(&format!(
        "Sweepky asks Pubky Ring for {SWEEPKY_CAPABILITY} (read and write under /pub/sweepky/) \
         for the app {CLIENT_ID}.\n\
         Approve it on the page opening in your browser:\n  {page_url}\n\
         or scan this code with Pubky Ring, or paste the link below it into Ring:\n\
         {qr}\n{link}\n\
         Waiting up to {} for the approval.\n",
        duration_text(timeout)
    ))
}

/// Waits up to `timeout` for the approval, checks what it grants, and
/// sends the page its final status through `status`.
///
/// Takes `flow` by value because `await_approval(self)` consumes it, and
/// `status` by value so that it is dropped when this returns: on an SDK
/// error it is dropped still `waiting`, which stops the server at once.
async fn await_checked_approval(
    flow: PubkyGrantAuthFlow,
    timeout: Duration,
    status: watch::Sender<SignInStatus>,
) -> anyhow::Result<PubkySession> {
    // `timeout` gives `Err(Elapsed)` when the time ran out, and otherwise
    // the flow's own result. Dropping the flow's future on timeout drops
    // the flow, which stops its relay poller.
    let session = match tokio::time::timeout(timeout, flow.await_approval()).await {
        Ok(Ok(session)) => session,
        // The SDK's listener stopping without a message is a timeout too.
        Err(_) | Ok(Err(pubky::Error::Authentication(AuthError::RequestExpired))) => {
            // `send_replace` sets the value even when no receiver is left
            // (the server may have stopped at its deadline); `send` would
            // fail then.
            status.send_replace(SignInStatus::Expired);
            bail!(
                "no approval from Pubky Ring within {}; run `sweepky login` again",
                duration_text(timeout)
            );
        }
        Ok(Err(error)) => {
            return Err(request_error(&error).context("the Pubky Ring sign-in failed"));
        }
    };
    // The capabilities the homeserver reports for the session, only
    // compared, never printed: they are the server's words.
    if !grants_sweepky_write(session.info().capabilities()) {
        status.send_replace(SignInStatus::Refused);
        return Err(sign_out_refused(session).await);
    }
    status.send_replace(SignInStatus::Approved);
    Ok(session)
}

/// Signs out the session of a refused approval, which revokes its grant on
/// the homeserver, and gives the error to stop with: [`NARROWED_GRANT`],
/// or, when the sign-out failed, a message that says the grant is still
/// live and how to revoke it.
async fn sign_out_refused(session: PubkySession) -> anyhow::Error {
    // `signout(self)` consumes the session; on failure the SDK hands it
    // back beside the error, and `_session` drops it here.
    match session.signout().await {
        Ok(()) => anyhow::Error::msg(NARROWED_GRANT),
        Err((error, _session)) => request_error(&error).context(NARROWED_GRANT_STILL_LIVE),
    }
}

/// `duration` as the messages say it: whole minutes when it is some, else
/// seconds.
fn duration_text(duration: Duration) -> String {
    let seconds = duration.as_secs();
    match (seconds / 60, seconds % 60) {
        (1, 0) => "1 minute".to_owned(),
        // A match guard: this arm matches only when the `if` holds.
        (minutes, 0) if minutes > 0 => format!("{minutes} minutes"),
        _ if seconds == 1 => "1 second".to_owned(),
        _ => format!("{seconds} seconds"),
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use pubky::Capabilities;
    use pubky_testnet::EphemeralTestnet;
    use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};
    use url::Url;

    use super::{LOGIN_TIMEOUT, NARROWED_GRANT, duration_text, sign_in_with_ring};
    use crate::network::{CLIENT_ID, SWEEPKY_CAPABILITY};
    use crate::ring::page::terminal_qr;
    use crate::test_support::{
        RingPage, RingStandIn, SharedBuffer, loopback_get, private_temp, test_context,
    };
    use crate::{Browser, Context, Network};

    /// Two years in seconds, the grant lifetime the SDK fixes.
    const TWO_YEARS: u64 = 2 * 365 * 86_400;

    async fn testnet() -> EphemeralTestnet {
        EphemeralTestnet::builder()
            .with_http_relay()
            .build()
            .await
            .expect("testnet starts")
    }

    /// A context on `testnet` whose browser hands the page's URL to the
    /// returned receiver, as a test playing Ring needs.
    fn ring_context(
        testnet: &EphemeralTestnet,
        home: &tempfile::TempDir,
    ) -> (Context, SharedBuffer, UnboundedReceiver<Url>) {
        let network = Network::injected(
            testnet.sdk().expect("client"),
            format!("{}inbox", testnet.http_relay().local_url()),
            testnet.homeserver_app().public_key(),
        );
        let (mut ctx, stderr) = test_context(network, home, io::empty());
        let (urls, received) = unbounded_channel();
        ctx.browser = Browser::Notify(urls);
        (ctx, stderr, received)
    }

    /// The value of the query parameter `name` in `link`, if it has one.
    fn query_value(link: &str, name: &str) -> Option<String> {
        Url::parse(link)
            .expect("the link is a URL")
            .query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    }

    /// Checks that an error's text names neither the link nor its relay
    /// channel's secret.
    fn assert_quotes_no_secret(text: &str, link: &str) {
        assert!(!text.contains(link), "{text}");
        let secret = query_value(link, "secret").expect("a bare grant's link has a secret");
        assert!(!text.contains(&secret), "{text}");
    }

    #[tokio::test]
    #[pubky_testnet::test]
    async fn an_approval_in_ring_flips_the_page_and_signs_in_the_approver() {
        let testnet = testnet().await;
        let home = private_temp();
        let (ctx, stderr, mut urls) = ring_context(&testnet, &home);
        let ring = RingStandIn::sign_up(&testnet).await;
        let relay = testnet.http_relay().local_url();

        let (signed_in, page) = tokio::join!(sign_in_with_ring(&ctx, LOGIN_TIMEOUT), async {
            let page = RingPage::open(&mut urls).await;
            // The QR code and the link are on the page, and it is waiting.
            assert!(page.html.contains("<svg"), "no QR code");
            assert!(page.link.starts_with("pubkyauth://"), "{}", page.link);
            assert_eq!(page.status().await, "waiting");

            // The link asks through the injected relay, a local one, for
            // exactly Sweepky's capability as `sweepky-cli`, in the default
            // bare-grant format: no `af`, no encryption key, no `e` action.
            let link_relay = Url::parse(&query_value(&page.link, "relay").expect("a relay"))
                .expect("the relay is a URL");
            assert_eq!(link_relay.host_str(), relay.host_str());
            assert_eq!(
                link_relay.port_or_known_default(),
                relay.port_or_known_default()
            );
            assert!(
                matches!(link_relay.host_str(), Some("localhost" | "127.0.0.1")),
                "{link_relay}"
            );
            assert_eq!(
                query_value(&page.link, "caps").as_deref(),
                Some(SWEEPKY_CAPABILITY)
            );
            assert_eq!(query_value(&page.link, "cid").as_deref(), Some(CLIENT_ID));
            assert_eq!(query_value(&page.link, "af"), None);
            assert_eq!(query_value(&page.link, "epk"), None);

            // Another path on the same port is refused while the flow waits.
            let mut wrong = page.url.clone();
            wrong.set_path(&format!("{}x", page.url.path()));
            let (code, _) = loopback_get(&wrong).await.expect("the server answers");
            assert_eq!(code, 404);

            ring.approve(&page).await;
            assert_eq!(page.final_status().await, "approved");
            page
        });
        // `let … else` rather than `expect`: `expect` on a `Result` would
        // print the session with `Debug` if it failed the other way.
        let Ok(session) = signed_in else {
            panic!("the approval did not sign in");
        };
        assert_eq!(session.public_key(), ring.public_key());

        // The grant lasts about two years from now.
        let grant = session.as_grant().expect("a grant session");
        let expires_at = grant.session_info().await.grant_expires_at;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("after 1970")
            .as_secs();
        assert!(
            expires_at.abs_diff(now + TWO_YEARS) < 3 * 86_400,
            "expires at {expires_at}, now {now}"
        );
        assert_eq!(ring.active_grants_for(CLIENT_ID).await.len(), 1);

        // The terminal fallback: what is asked for, the page's URL, the link
        // and its QR code.
        let said = stderr.text();
        assert!(said.contains(SWEEPKY_CAPABILITY), "{said}");
        assert!(said.contains(CLIENT_ID), "{said}");
        assert!(said.contains(page.url.as_str()), "{said}");
        assert!(said.contains(&page.link), "{said}");
        assert!(
            said.contains(&terminal_qr(&page.link).expect("a QR code")),
            "{said}"
        );
    }

    #[tokio::test]
    #[pubky_testnet::test]
    async fn a_read_only_approval_is_refused_and_its_grant_revoked() {
        let testnet = testnet().await;
        let home = private_temp();
        let (ctx, _stderr, mut urls) = ring_context(&testnet, &home);
        let ring = RingStandIn::sign_up(&testnet).await;
        let read_only = Capabilities::builder()
            .read("/pub/sweepky/")
            .expect("a scope")
            .finish();

        let (signed_in, page) = tokio::join!(sign_in_with_ring(&ctx, LOGIN_TIMEOUT), async {
            let page = RingPage::open(&mut urls).await;
            ring.approve_with(&page, &read_only).await;
            assert_eq!(page.final_status().await, "refused");
            page
        });
        let Err(error) = signed_in else {
            panic!("a read-only approval signed in");
        };
        let text = format!("{error:#}");
        assert_eq!(text, NARROWED_GRANT);
        assert_quotes_no_secret(&text, &page.link);
        // Signed out before the error came back: the grant is gone.
        assert!(ring.active_grants_for(CLIENT_ID).await.is_empty());
    }

    #[tokio::test]
    #[pubky_testnet::test]
    async fn no_approval_in_time_expires_the_flow() {
        let testnet = testnet().await;
        let home = private_temp();
        let (ctx, _stderr, mut urls) = ring_context(&testnet, &home);

        let (signed_in, page) =
            tokio::join!(sign_in_with_ring(&ctx, Duration::from_secs(3)), async {
                let page = RingPage::open(&mut urls).await;
                assert_eq!(page.status().await, "waiting");
                assert_eq!(page.final_status().await, "expired");
                page
            });
        let Err(error) = signed_in else {
            panic!("signed in with no approval");
        };
        let text = format!("{error:#}");
        assert_eq!(
            text,
            "no approval from Pubky Ring within 3 seconds; run `sweepky login` again"
        );
        assert_quotes_no_secret(&text, &page.link);
    }

    #[test]
    fn durations_read_as_minutes_or_seconds() {
        assert_eq!(duration_text(Duration::from_secs(600)), "10 minutes");
        assert_eq!(duration_text(Duration::from_secs(60)), "1 minute");
        assert_eq!(duration_text(Duration::from_secs(90)), "90 seconds");
        assert_eq!(duration_text(Duration::from_secs(1)), "1 second");
    }
}
