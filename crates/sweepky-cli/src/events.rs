//! A homeserver's public events, as `post --open` and `pull` read them: the
//! [`EventsFeed`] seam, its real implementation [`HomeserverEvents`], and
//! [`find_head`], the search for where a watched homeserver's feed ends,
//! which `post --open` keeps as an open bounty's starting cursor there.
//!
//! - [`EventsFeed::page`] reads one page of a homeserver's `/events/` feed,
//!   `GET https://<homeserver>/events/?cursor=<c>&limit=<n>`: the public
//!   events after event `c`, at most `n` (1 to 1000), parsed by core's
//!   [`parse_feed`]. A page with more events than were asked for breaks the
//!   protocol and is refused, so the limit bounds what one page can make
//!   `pull` re-fetch.
//! - [`EventsFeed::latest_event`] reads the id of the owner's latest event
//!   of one file from the homeserver's non-live `/events-stream`
//!   (`?user=<owner>&reverse=true&limit=1&path=<file>`), parsed by core's
//!   [`parse_event_stream`]. Only a PUT of exactly that file is an answer:
//!   the event of the bounty's own write, `post --open`'s starting cursor on
//!   the owner's homeserver.
//! - [`find_head`] finds the id of a homeserver's last public event, the
//!   starting cursor on every other watched homeserver: an exponential, then
//!   binary, search with `limit=1`, where an empty page means the cursor is
//!   at or past the head (01, "Starting cursor"). It is paced for
//!   production's rate limit, and a 429 stops it.
//!
//! The rules, and why:
//!
//! - **Every request goes through [`get_unredirected`]** on the SDK's HTTP
//!   client, which resolves the homeserver's key through pkarr, so an answer
//!   that came through a redirect is refused before its status or body is
//!   looked at.
//! - **Every body is capped before it is buffered**: a feed page at
//!   [`MAX_FEED_BODY_BYTES`] (4 MiB), a stream answer at
//!   [`MAX_EVENT_STREAM_BODY_BYTES`] (64 KiB). Core's parsers check the caps
//!   again.
//! - **Every answer but a 2xx is an error that names its status**, a 404
//!   included: unlike a listing, the feed has no "empty directory". A 429
//!   says the homeserver is rate limiting, in fixed words.
//! - **Errors never quote** the homeserver, a URL or a line of the feed:
//!   fixed text, a status, numbers, and the keys and path the caller named.
//! - **The work is bounded.** The limit asked bounds the events of a page,
//!   and the search sends at most 125 requests whatever the homeserver
//!   answers (one at cursor 0, at most 63 exponential steps up to its
//!   ceiling, at most 61 binary ones), never asking for a cursor past 2^62.

use std::time::Duration;

use anyhow::{Context as _, anyhow, bail};
use pubky::{PubkyHttpClient, PublicKey, StatusCode};
use sweepky_core::paths::SweepkyPath;
use sweepky_core::{
    EventCursor, FeedOp, FeedPage, MAX_EVENT_STREAM_BODY_BYTES, MAX_FEED_BODY_BYTES, Pubky,
    PubkyUrl, Zeroizing, parse_event_stream, parse_feed,
};
use url::Url;

use crate::remote::{
    Answer, MAX_PAGE_SIZE, PageStatus, get_unredirected, public_key_of, status_error,
};

/// What a 429 from `/events/` or `/events-stream` is refused with: the
/// homeserver is throttling requests from this address (06, "Production
/// homeserver": 3 a second with a burst of 10 on `/events/`, 1 a second
/// with a burst of 5 on `/events-stream`). Fixed text: never the server's
/// own words or its `Retry-After`.
const EVENTS_RATE_LIMITED: &str = "the homeserver answered 429 Too Many Requests: \
     it is rate limiting its events for this address; wait a minute and try again";

/// What a feed page or a stream answer with more events than were asked for
/// is refused with: the homeserver sends at most `limit`.
const MORE_EVENTS_THAN_ASKED: &str =
    "the homeserver sent more events than were asked for, which breaks the protocol";

/// What [`EventsFeed::latest_event`] says when the answer holds no event it
/// could read: none was sent, or the one sent was malformed.
const NO_EVENT: &str = "the homeserver's events stream gave no readable event";

/// What [`EventsFeed::latest_event`] says when the latest event is a DEL.
const NOT_A_PUT: &str = "the latest event of the file is a deletion, not a write";

/// What [`EventsFeed::latest_event`] says when the event names another
/// file, of the owner or of anyone else, than the one asked for.
const ANOTHER_FILE: &str = "the homeserver's events stream answered with an event of another file";

/// The highest cursor [`find_head`] asks for: 2^62.
///
/// The 0.16.2 homeserver keeps event ids as Postgres `BIGINT`s, and turns
/// the cursor it is given into one with `i64::try_from(..).unwrap()`
/// (sea-query-sqlx 0.8.1), so a cursor above `i64::MAX` would make the
/// request's handler panic: never send one. 2^62 is the highest power of two
/// below `i64::MAX`, so the exponential steps (1, 2, 4, ...) stop there, and
/// the binary steps stay between two of them.
const SEARCH_CEILING: u64 = 1 << 62;

/// How long [`find_head`] waits before each request after the first
/// [`UNPACED_REQUESTS`], given this as its pace: 350 ms, a little slower than
/// production's 3 `/events/` requests a second per IP (06), so the search
/// never runs its burst dry. A search of about 50 requests, for event ids
/// near 10^7, then takes some 15 seconds, once per open bounty and watched
/// homeserver.
pub(crate) const SEARCH_PACE: Duration = Duration::from_millis(350);

/// How many requests [`find_head`] sends at once before it starts to wait:
/// 5, half of production's burst of 10, so a small search is quick and some
/// of the burst is left for whatever else this address sends.
const UNPACED_REQUESTS: usize = 5;

// A compile-time check (a failed `assert!` in a `const` is a build error,
// not a panic at run time): the pace keeps under production's 3 requests a
// second, and the requests sent at once under its burst of 10.
const _: () = assert!(SEARCH_PACE.as_millis() * 3 >= 1000 && UNPACED_REQUESTS < 10);

/// A homeserver's public events, read with no session: the seam between
/// `post --open` and `pull` and everyone's homeservers.
///
/// A trait so that both can be tested without a network, as
/// `records::PublicRecords` is. Its methods are `async fn`s, so it cannot be
/// a `dyn EventsFeed` (each implementation's futures are a different type);
/// callers take `&impl EventsFeed`, and the compiler makes one copy of the
/// caller for each implementation.
///
/// An implementation writes the two methods that fetch bytes,
/// [`feed_body`](Self::feed_body) and [`stream_body`](Self::stream_body).
/// The two that parse and check them, [`page`](Self::page) and
/// [`latest_event`](Self::latest_event), are written once here, so the fake
/// in the tests is held to exactly the checks the real one is.
pub(crate) trait EventsFeed {
    /// The body of one page of `homeserver`'s `/events/` feed, at most
    /// [`MAX_FEED_BODY_BYTES`]: its public events after `cursor`, at most
    /// `limit`, which [`page`](Self::page) has checked is 1 to 1000.
    async fn feed_body(
        &self,
        homeserver: Pubky,
        cursor: EventCursor,
        limit: u16,
    ) -> anyhow::Result<Zeroizing<Vec<u8>>>;

    /// The body of `homeserver`'s non-live `/events-stream` answer, at most
    /// [`MAX_EVENT_STREAM_BODY_BYTES`], to a request for `owner`'s latest
    /// event of the file at `path`.
    async fn stream_body(
        &self,
        homeserver: Pubky,
        owner: Pubky,
        path: &SweepkyPath,
    ) -> anyhow::Result<Zeroizing<Vec<u8>>>;

    /// One page of `homeserver`'s `/events/` feed: its public events after
    /// `cursor`, at most `limit`, parsed by core's [`parse_feed`].
    ///
    /// `limit` must be 1 to 1000; above 1000 the homeserver would quietly
    /// send 1000, which a reader looping while a page is full would take
    /// for a short last page. A page with more events than `limit` is
    /// refused ([`MORE_EVENTS_THAN_ASKED`]), so `limit` bounds the re-fetch
    /// work one page can cause. Lines the parse skips are counted in
    /// [`FeedPage::malformed`], and a page of nothing else is not caught up.
    // A *provided* method: the trait writes its body, so every
    // implementation gets it without writing it again.
    async fn page(
        &self,
        homeserver: Pubky,
        cursor: EventCursor,
        limit: u16,
    ) -> anyhow::Result<FeedPage> {
        // An `async` block is a future that runs the code inside when
        // awaited; `?` inside it leaves the block, not `page`, so the
        // context below is added to every error the block gives.
        async {
            if !(1..=MAX_PAGE_SIZE).contains(&limit) {
                bail!("a page of the events feed holds 1 to {MAX_PAGE_SIZE} events, not {limit}");
            }
            let body = self.feed_body(homeserver, cursor, limit).await?;
            // `FeedError` holds numbers only, so `?` passes on nothing of
            // the body.
            let page = parse_feed(&body)?;
            if page.events().len() > usize::from(limit) {
                bail!(MORE_EVENTS_THAN_ASKED);
            }
            Ok(page)
        }
        .await
        .with_context(|| format!("could not read the events feed of {homeserver}"))
    }

    /// The id of `owner`'s latest event of the file at `path`, from
    /// `homeserver`'s non-live `/events-stream` (newest first, one event),
    /// parsed by core's [`parse_event_stream`].
    ///
    /// Only a PUT of exactly that file counts: `post --open` asks right
    /// after it wrote the bounty, so its answer is the id of that write. A
    /// DEL ([`NOT_A_PUT`]), an event of another file or another owner
    /// ([`ANOTHER_FILE`]), an answer with no readable event ([`NO_EVENT`])
    /// and one with more than one ([`MORE_EVENTS_THAN_ASKED`]) are errors in
    /// fixed text. The id is still the homeserver's word, like every event.
    async fn latest_event(
        &self,
        homeserver: Pubky,
        owner: Pubky,
        path: &SweepkyPath,
    ) -> anyhow::Result<EventCursor> {
        async {
            let body = self.stream_body(homeserver, owner, path).await?;
            let answer = parse_event_stream(&body)?;
            // A slice pattern: `[event]` matches a slice of exactly one item
            // and names it, `[]` an empty one, and `[_, _, ..]` one of two
            // or more, so the length is checked and the item taken in one
            // step, with no index that could panic.
            let event = match answer.events() {
                [event] => event,
                [] => bail!(NO_EVENT),
                [_, _, ..] => bail!(MORE_EVENTS_THAN_ASKED),
            };
            if event.op != FeedOp::Put {
                bail!(NOT_A_PUT);
            }
            // `PubkyUrl`'s `==` compares the user by key bytes and the path
            // exactly, so the two spellings of a key are one owner.
            if event.url != PubkyUrl::sweepky(owner, path) {
                bail!(ANOTHER_FILE);
            }
            Ok(event.cursor)
        }
        .await
        .with_context(|| {
            format!(
                "could not read the latest event of {} of {owner} on {homeserver}",
                path.to_path()
            )
        })
    }
}

/// The real [`EventsFeed`]: each homeserver asked directly, by its key,
/// through the SDK's HTTP client, which resolves the key through pkarr. It
/// borrows the client, which is what the `'a` says.
pub(crate) struct HomeserverEvents<'a> {
    client: &'a PubkyHttpClient,
}

impl<'a> HomeserverEvents<'a> {
    /// A reader on `client`, the one `ctx.network.pubky().client()` gives.
    pub(crate) fn new(client: &'a PubkyHttpClient) -> Self {
        Self { client }
    }
}

impl EventsFeed for HomeserverEvents<'_> {
    async fn feed_body(
        &self,
        homeserver: Pubky,
        cursor: EventCursor,
        limit: u16,
    ) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        // The SDK's key type also checks that the 32 bytes are a point on
        // Ed25519; core's `Pubky` checks only the spelling.
        let url = feed_url(&public_key_of(&homeserver)?, cursor, limit)?;
        fetch_feed(self.client, url).await
    }

    async fn stream_body(
        &self,
        homeserver: Pubky,
        owner: Pubky,
        path: &SweepkyPath,
    ) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let url = stream_url(&public_key_of(&homeserver)?, &public_key_of(&owner)?, path)?;
        fetch_stream(self.client, url).await
    }
}

/// `https://<homeserver z32><path>`, the way the SDK addresses a homeserver
/// itself (its event stream asks `https://<z32>/events-stream`): the SDK's
/// client reads a host that is a key as one to resolve through pkarr.
/// `path` is one of this module's own, never a stranger's text.
fn homeserver_url(homeserver: &PublicKey, path: &str) -> anyhow::Result<Url> {
    // A parse error says only what kind of fault it found, but the message
    // is fixed text anyway, as `remote::request_error`'s is.
    Url::parse(&format!("https://{}{path}", homeserver.z32()))
        .map_err(|_| anyhow!("could not build the request URL"))
}

/// The URL of one page of `homeserver`'s `/events/` feed:
/// `https://<homeserver>/events/?cursor=<cursor>&limit=<limit>`.
fn feed_url(homeserver: &PublicKey, cursor: EventCursor, limit: u16) -> anyhow::Result<Url> {
    let mut url = homeserver_url(homeserver, "/events/")?;
    // `query_pairs_mut` lends out a writer for the URL's query that
    // percent-encodes every key and value. The loan ends with the
    // statement, so `url` can be returned after it.
    url.query_pairs_mut()
        .append_pair("cursor", &cursor.to_string())
        .append_pair("limit", &limit.to_string());
    Ok(url)
}

/// The URL of a non-live `/events-stream` request for `owner`'s latest
/// event of the file at `path`: `user=<owner z32>` (the homeserver refuses
/// the `pubky`-prefixed form), `reverse=true` for newest first, `limit=1`,
/// and `path=<path>`, a file's path, which the 0.16.2 homeserver matches
/// exactly (a directory's, ending in `/`, would match all of it).
fn stream_url(
    homeserver: &PublicKey,
    owner: &PublicKey,
    path: &SweepkyPath,
) -> anyhow::Result<Url> {
    let mut url = homeserver_url(homeserver, "/events-stream")?;
    url.query_pairs_mut()
        .append_pair("user", &owner.z32())
        .append_pair("reverse", "true")
        .append_pair("limit", "1")
        .append_pair("path", &path.to_path());
    Ok(url)
}

/// The body of the `/events/` page at `url`, at most
/// [`MAX_FEED_BODY_BYTES`], the most core's [`parse_feed`] reads.
async fn fetch_feed(client: &PubkyHttpClient, url: Url) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    fetch_events(client, url, MAX_FEED_BODY_BYTES).await
}

/// The body of the `/events-stream` answer at `url`, at most
/// [`MAX_EVENT_STREAM_BODY_BYTES`], the most core's [`parse_event_stream`]
/// reads.
async fn fetch_stream(client: &PubkyHttpClient, url: Url) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    fetch_events(client, url, MAX_EVENT_STREAM_BODY_BYTES).await
}

/// An anonymous `GET` of `url` through [`get_unredirected`], its body read
/// with `cap`: a redirected answer is refused, any status but 2xx is an
/// error ([`events_status`]), and the body is capped before it is buffered.
async fn fetch_events(
    client: &PubkyHttpClient,
    url: Url,
    cap: usize,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    match get_unredirected(client, url, &[], cap, events_status).await? {
        // `..` leaves the `ETag` out: an events answer is read once, never
        // compared.
        Answer::Body { body, .. } => Ok(body),
        // `events_status` gives neither, so this cannot happen; should it,
        // it is an error, never a panic.
        Answer::Empty | Answer::NotModified => bail!("the homeserver's events answer had no body"),
    }
}

/// What `status` means for an events answer: read a 2xx, refuse a 429 with
/// [`EVENTS_RATE_LIMITED`], and refuse anything else with its status alone,
/// a 404 included. It is given the status alone, so it cannot read an error
/// answer's body.
fn events_status(status: StatusCode) -> anyhow::Result<PageStatus> {
    if status.is_success() {
        Ok(PageStatus::Read)
    } else if status == StatusCode::TOO_MANY_REQUESTS {
        bail!(EVENTS_RATE_LIMITED)
    } else {
        Err(status_error(status))
    }
}

/// The id of `homeserver`'s last public event, found with `feed`, the
/// cursor from which its feed lists only what comes after now: an open
/// bounty's starting cursor on a watched homeserver other than the owner's.
///
/// `/events/` has no "latest" shortcut, so this asks for one event at a
/// time (`limit=1`) and reads an empty page as "this cursor is at or past
/// the head". After cursor 0 (an empty feed's head), it doubles the cursor
/// (1, 2, 4, ...) until a page is empty, then halves the gap between the
/// last cursor before the head and the first at or past it until they
/// meet. A head near 10^7 takes about 50 requests: about 2 x log2(head),
/// plus one. Each request after the first [`UNPACED_REQUESTS`] waits `pace`
/// first: [`SEARCH_PACE`] for production's rate limit, zero in the tests.
/// The first error, a 429 among them, stops the search.
///
/// The answer is never above the head as the feed shows it: a cursor counts
/// as before the head only when its page holds an event or a cursor. A page
/// of only malformed lines is not caught up ([`FeedPage::is_caught_up`]),
/// and `pull` stops at one; but it shows no event either, so here it counts
/// as at or past the head, and a broken answer can only bring the cursor
/// down, never past an event. Events written while the search runs may
/// fall below the cursor it finds; a sweep is written more than once
/// (`running`, then its package and `done`), so its later events are still
/// seen.
pub(crate) async fn find_head(
    feed: &impl EventsFeed,
    homeserver: Pubky,
    pace: Duration,
) -> anyhow::Result<EventCursor> {
    let mut search = Search {
        feed,
        homeserver,
        pace,
        sent: 0,
    };
    if search.at_or_past_head(0).await? {
        return Ok(EventCursor::new(0));
    }
    let (before, at_or_past) = search.double_past_head().await?;
    let head = search.halve_to_head(before, at_or_past).await?;
    Ok(EventCursor::new(head))
}

/// One run of [`find_head`]: the feed and homeserver it asks, its pace, and
/// how many requests it has sent, which decides when to wait.
// `F` is the feed's type, generic so the search runs on the real reader
// and the fake alike; `'a` is how long the borrowed feed lives.
struct Search<'a, F> {
    feed: &'a F,
    homeserver: Pubky,
    pace: Duration,
    sent: usize,
}

impl<F: EventsFeed> Search<'_, F> {
    /// The exponential steps, once cursor 0 is known to be before the head:
    /// asks for cursors 1, 2, 4 and so on until one is at or past the head,
    /// and gives the last cursor before it and that one. A feed still
    /// before its head at [`SEARCH_CEILING`] is refused.
    async fn double_past_head(&mut self) -> anyhow::Result<(u64, u64)> {
        let mut before = 0;
        let mut step = 1;
        while !self.at_or_past_head(step).await? {
            if step >= SEARCH_CEILING {
                bail!(
                    "the events feed of {} claims events past id 2^62, further than Sweepky \
                     searches",
                    self.homeserver
                );
            }
            before = step;
            // `step` is below 2^62 here, so doubling it is exact:
            // saturating arithmetic, which stops at `u64::MAX` rather than
            // wrapping or panicking, never has to stop.
            step = step.saturating_mul(2);
        }
        Ok((before, step))
    }

    /// The binary steps: halves the gap between `before`, a cursor before
    /// the head, and `at_or_past`, one at or past it, until the two are
    /// next to each other, and gives the second, which is then the head.
    async fn halve_to_head(&mut self, mut before: u64, mut at_or_past: u64) -> anyhow::Result<u64> {
        // `before < at_or_past` throughout, so the subtraction is exact, and
        // the middle lies strictly between the two while the gap is 2 or
        // more.
        while at_or_past.saturating_sub(before) > 1 {
            let middle = before.saturating_add(at_or_past.saturating_sub(before) / 2);
            if self.at_or_past_head(middle).await? {
                at_or_past = middle;
            } else {
                before = middle;
            }
        }
        Ok(at_or_past)
    }

    /// Whether `cursor` is at or past the head: whether the page of one
    /// event after it holds neither an event nor a cursor.
    async fn at_or_past_head(&mut self, cursor: u64) -> anyhow::Result<bool> {
        if self.sent >= UNPACED_REQUESTS && !self.pace.is_zero() {
            // tokio's `sleep` waits without holding a thread, unlike
            // `std::thread::sleep`, which would stall every task on it.
            tokio::time::sleep(self.pace).await;
        }
        // At most 125 requests, so this never comes near saturating.
        self.sent = self.sent.saturating_add(1);
        let page = self
            .feed
            .page(self.homeserver, EventCursor::new(cursor), 1)
            .await?;
        Ok(page.events().is_empty() && page.cursor().is_none())
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use pubky::{ClientId, Keypair};
    use pubky_testnet::EphemeralTestnet;
    use sweepky_core::paths::SweepkyPath;
    use sweepky_core::{EventCursor, MAX_EVENT_STREAM_BODY_BYTES, MAX_FEED_BODY_BYTES, PubkyUrl};

    use super::{
        ANOTHER_FILE, EVENTS_RATE_LIMITED, EventsFeed, HomeserverEvents, MORE_EVENTS_THAN_ASKED,
        NO_EVENT, NOT_A_PUT, SEARCH_CEILING, UNPACED_REQUESTS, feed_url, fetch_feed, fetch_stream,
        find_head, stream_url,
    };
    use crate::CLIENT_ID;
    use crate::remote::{BodyTooLarge, MAX_PAGE_SIZE, REDIRECTED, pubky_of};
    use crate::test_support::{
        Canned, FakeEventsFeed, LocalHttp, PLANTED, canned, feed_page, offline_network,
        random_pubky, record_id,
    };

    /// No pause between the search's requests: the tests' pace.
    const UNPACED: Duration = Duration::ZERO;

    /// `ceil(log2(head))` for a head of at least 1: the bits needed to write
    /// `head - 1`.
    fn ceil_log2(head: u64) -> usize {
        let bits = u64::BITS - (head - 1).leading_zeros();
        usize::try_from(bits).expect("at most 64")
    }

    #[tokio::test]
    async fn the_head_is_the_last_public_event_whatever_the_gaps() {
        // Event ids skip numbers: private events and other rows take them.
        let feeds: &[(&[u64], u64)] = &[
            (&[], 0),
            (&[1], 1),
            (&[7], 7),
            (&[2, 3, 9, 40, 41, 1000, 1023], 1023),
            (&[1024], 1024),
            (&[5, 1025], 1025),
        ];
        for &(ids, head) in feeds {
            let feed = FakeEventsFeed::of_ids(ids);
            let found = find_head(&feed, random_pubky(), UNPACED)
                .await
                .expect("a head");
            assert_eq!(found, EventCursor::new(head), "{ids:?}");
        }
    }

    #[tokio::test]
    async fn the_search_is_bounded_and_never_asks_past_the_ceiling() {
        let highest_i64 = u64::try_from(i64::MAX).expect("positive");
        for head in [
            1,
            2,
            3,
            5,
            1000,
            1024,
            1025,
            10_000_000,
            SEARCH_CEILING - 1,
            SEARCH_CEILING,
        ] {
            let feed = FakeEventsFeed::of_ids(&[head]);
            let found = find_head(&feed, random_pubky(), UNPACED)
                .await
                .expect("a head");
            assert_eq!(found, EventCursor::new(head));
            let asked = feed.asked();
            assert!(
                asked.len() <= 2 * ceil_log2(head) + 2,
                "{head}: {} requests",
                asked.len()
            );
            for (cursor, limit) in asked {
                assert!(cursor.id() <= SEARCH_CEILING, "{head}: {cursor}");
                assert!(cursor.id() <= highest_i64, "{head}: {cursor}");
                assert_eq!(limit, 1, "{head}");
            }
        }

        // A feed that claims an event past the ceiling is refused once the
        // exponential steps reach it, without a request past it.
        let feed = FakeEventsFeed::of_ids(&[u64::MAX]);
        let homeserver = random_pubky();
        let error = find_head(&feed, homeserver, UNPACED)
            .await
            .expect_err("past the ceiling");
        assert_eq!(
            format!("{error:#}"),
            format!(
                "the events feed of {homeserver} claims events past id 2^62, further than \
                 Sweepky searches"
            )
        );
        let asked = feed.asked();
        assert_eq!(asked.len(), 64, "cursor 0, then 2^0 to 2^62");
        assert!(
            asked
                .iter()
                .all(|(cursor, _)| cursor.id() <= SEARCH_CEILING)
        );
    }

    #[tokio::test]
    async fn a_page_of_only_malformed_lines_is_not_caught_up_and_cannot_lift_the_head() {
        // Honest for the events 5, 9 and 12, except that for cursors 12 to
        // 19, where an honest homeserver answers the empty page, this one
        // answers lines no parser reads.
        let junk = b"PUT not-a-url\ncursor: twelve".to_vec();
        let feed = FakeEventsFeed::answering(move |cursor, limit| {
            Ok(if (12..20).contains(&cursor.id()) {
                junk.clone()
            } else {
                feed_page(&[5, 9, 12], cursor, limit)
            })
        });

        // Through the seam, such a page is not caught up: `pull` stops at it
        // and reports it, rather than taking it for the end of the feed.
        let page = feed
            .page(random_pubky(), EventCursor::new(12), 1)
            .await
            .expect("a page");
        assert!(!page.is_caught_up());
        assert!(page.events().is_empty());
        assert_eq!(page.cursor(), None);
        assert_eq!(page.malformed(), 2);

        // The search takes it as no event after the cursor, so the broken
        // pages cannot lift its answer past the head: 12, where a search that
        // read them as events would have climbed to 20.
        let head = find_head(&feed, random_pubky(), UNPACED)
            .await
            .expect("a head");
        assert_eq!(head, EventCursor::new(12));
    }

    #[tokio::test]
    async fn a_page_with_more_events_than_asked_for_is_refused() {
        // A homeserver that sends every event it has, whatever the limit.
        let feed =
            FakeEventsFeed::answering(|cursor, _limit| Ok(feed_page(&[3, 4, 5], cursor, 1000)));
        let homeserver = random_pubky();

        let error = feed
            .page(homeserver, EventCursor::new(0), 2)
            .await
            .expect_err("three events for a limit of two");
        assert_eq!(
            format!("{error:#}"),
            format!("could not read the events feed of {homeserver}: {MORE_EVENTS_THAN_ASKED}")
        );
        // As many as were asked for is a page.
        let page = feed
            .page(homeserver, EventCursor::new(0), 3)
            .await
            .expect("three for three");
        assert_eq!(page.events().len(), 3);

        // The search asks for one event a page, so it is refused there too.
        let error = find_head(&feed, homeserver, UNPACED)
            .await
            .expect_err("two events for a limit of one");
        assert!(
            format!("{error:#}").ends_with(MORE_EVENTS_THAN_ASKED),
            "{error:#}"
        );

        // A limit the homeserver does not honour is refused before a request.
        let feed = FakeEventsFeed::of_ids(&[1]);
        for limit in [0, MAX_PAGE_SIZE + 1] {
            let error = feed
                .page(homeserver, EventCursor::new(0), limit)
                .await
                .expect_err("not 1 to 1000");
            assert!(
                format!("{error:#}").ends_with(&format!(
                    "a page of the events feed holds 1 to 1000 events, not {limit}"
                )),
                "{error:#}"
            );
        }
        assert!(feed.asked().is_empty());
    }

    /// The query of `url` as decoded pairs, in order.
    fn query_pairs(url: &url::Url) -> Vec<(String, String)> {
        url.query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect()
    }

    fn pair(key: &str, value: &str) -> (String, String) {
        (key.to_owned(), value.to_owned())
    }

    #[test]
    fn the_page_and_stream_urls_name_the_homeserver_and_carry_an_encoded_query() {
        let homeserver = Keypair::random().public_key();
        let owner = Keypair::random().public_key();

        let url = feed_url(&homeserver, EventCursor::new(42), 1000).expect("a URL");
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some(homeserver.z32().as_str()));
        assert_eq!(url.port(), None);
        assert_eq!(url.path(), "/events/");
        assert_eq!(
            query_pairs(&url),
            [pair("cursor", "42"), pair("limit", "1000")]
        );

        let path = SweepkyPath::Bounty(record_id(7));
        let url = stream_url(&homeserver, &owner, &path).expect("a URL");
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some(homeserver.z32().as_str()));
        assert_eq!(url.path(), "/events-stream");
        assert_eq!(
            query_pairs(&url),
            [
                pair("user", &owner.z32()),
                pair("reverse", "true"),
                pair("limit", "1"),
                pair("path", &path.to_path()),
            ]
        );
        // The path goes percent-encoded, so no character in it can start a
        // parameter of its own.
        let query = url.query().expect("a query");
        assert!(
            query.ends_with(&format!(
                "&path=%2Fpub%2Fsweepky%2Fbounties%2F{}.json",
                record_id(7)
            )),
            "{query}"
        );
    }

    /// One event of an `/events-stream` answer, as pubky-homeserver 0.16.2
    /// writes it: its type, the file's URL, its cursor and, for a PUT, a
    /// content hash, then a blank line.
    fn stream_event(op: &str, url: &str, cursor: u64) -> String {
        let hash = if op == "PUT" {
            "data: content_hash: r0NJufX5oaagQE3qNtzJSZvLJcmtwRK3zJqTyuQfMmI=\n"
        } else {
            ""
        };
        format!("event: {op}\ndata: {url}\ndata: cursor: {cursor}\n{hash}\n")
    }

    #[tokio::test]
    async fn the_latest_event_counts_only_as_a_put_of_exactly_the_file_asked_for() {
        let homeserver = random_pubky();
        let owner = random_pubky();
        let path = SweepkyPath::Bounty(record_id(7));
        let url = PubkyUrl::sweepky(owner, &path).to_string();

        // A keep-alive comment before it changes nothing.
        let answer = format!(":\n\n{}", stream_event("PUT", &url, 42));
        let feed = FakeEventsFeed::of_ids(&[]).with_stream(answer.as_bytes());
        let latest = feed
            .latest_event(homeserver, owner, &path)
            .await
            .expect("a PUT of the file");
        assert_eq!(latest, EventCursor::new(42));

        let another_file = PubkyUrl::sweepky(owner, &SweepkyPath::Bounty(record_id(8))).to_string();
        let another_owner = PubkyUrl::sweepky(random_pubky(), &path).to_string();
        let planted = format!("pubky://{owner}/pub/{PLANTED}/x.json");
        let answers = [
            (stream_event("PUT", &another_file, 42), ANOTHER_FILE),
            (stream_event("PUT", &another_owner, 42), ANOTHER_FILE),
            (stream_event("PUT", &planted, 42), ANOTHER_FILE),
            (stream_event("DEL", &url, 42), NOT_A_PUT),
            (String::new(), NO_EVENT),
            (":\n\n:\n".to_owned(), NO_EVENT),
            (format!("event: PUT\ndata: {PLANTED}\n\n"), NO_EVENT),
            (
                format!(
                    "{}{}",
                    stream_event("PUT", &url, 43),
                    stream_event("PUT", &url, 42)
                ),
                MORE_EVENTS_THAN_ASKED,
            ),
        ];
        for (answer, expected) in answers {
            let feed = FakeEventsFeed::of_ids(&[]).with_stream(answer.as_bytes());
            let error = feed
                .latest_event(homeserver, owner, &path)
                .await
                .expect_err("refused");
            let message = format!("{error:#}");
            assert_eq!(
                message,
                format!(
                    "could not read the latest event of {} of {owner} on {homeserver}: \
                     {expected}",
                    path.to_path()
                ),
                "{answer:?}"
            );
            assert!(!message.contains(PLANTED), "{message}");
        }
    }

    #[tokio::test]
    async fn an_events_answer_that_is_not_a_2xx_is_its_status_alone() {
        let page =
            b"PUT pubky://8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo/pub/x\ncursor: 3";
        let server = LocalHttp::start(vec![
            ("/events/", canned("200 OK", &[], page)),
            ("/missing", canned("404 Not Found", &[], PLANTED.as_bytes())),
            ("/bad", canned("400 Bad Request", &[], PLANTED.as_bytes())),
            (
                "/broken",
                canned("500 Internal Server Error", &[], PLANTED.as_bytes()),
            ),
            (
                "/unavailable",
                canned("503 Service Unavailable", &[], PLANTED.as_bytes()),
            ),
            (
                "/busy",
                canned(
                    "429 Too Many Requests",
                    &[("retry-after", "1")],
                    PLANTED.as_bytes(),
                ),
            ),
            (
                "/moved",
                canned("302 Found", &[("location", "/events/")], b""),
            ),
        ])
        .await;
        let network = offline_network();
        let client = network.pubky().client();

        let body = fetch_feed(client, server.url("/events/"))
            .await
            .expect("a page");
        assert_eq!(body.as_slice(), page);

        let refusals = [
            ("/missing", "the homeserver answered 404 Not Found"),
            ("/bad", "the homeserver answered 400 Bad Request"),
            (
                "/broken",
                "the homeserver answered 500 Internal Server Error",
            ),
            (
                "/unavailable",
                "the homeserver answered 503 Service Unavailable",
            ),
            ("/busy", EVENTS_RATE_LIMITED),
            // Whatever the answer at the end of the redirect says, it is not
            // read: here the page above.
            ("/moved", REDIRECTED),
        ];
        for (path, expected) in refusals {
            for error in [
                fetch_feed(client, server.url(path)).await.err(),
                fetch_stream(client, server.url(path)).await.err(),
            ] {
                let message = format!("{:#}", error.expect("refused"));
                assert_eq!(message, expected, "{path}");
                assert!(!message.contains(PLANTED), "{message}");
                assert!(!message.contains("127.0.0.1"), "{message}");
            }
        }
    }

    /// A 200 whose `Content-Length` is one byte over `cap`, with no body
    /// behind it.
    fn claims_over(cap: usize) -> Canned {
        Canned::Bytes(
            format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                cap + 1
            )
            .into_bytes(),
        )
    }

    #[tokio::test]
    async fn an_events_body_over_its_cap_is_refused_before_it_is_buffered() {
        let server = LocalHttp::start(vec![
            ("/feed-claims", claims_over(MAX_FEED_BODY_BYTES)),
            ("/stream-claims", claims_over(MAX_EVENT_STREAM_BODY_BYTES)),
            ("/endless", Canned::Endless),
        ])
        .await;
        let network = offline_network();
        let client = network.pubky().client();

        // A Content-Length over the cap is refused before a byte is read, and
        // a body with no length at the chunk that would cross the cap.
        for path in ["/feed-claims", "/endless"] {
            let error = fetch_feed(client, server.url(path))
                .await
                .expect_err("over the cap");
            assert_eq!(
                error.downcast_ref::<BodyTooLarge>(),
                Some(&BodyTooLarge {
                    cap: MAX_FEED_BODY_BYTES
                }),
                "{path}: {error:#}"
            );
        }
        for path in ["/stream-claims", "/endless"] {
            let error = fetch_stream(client, server.url(path))
                .await
                .expect_err("over the cap");
            assert_eq!(
                error.downcast_ref::<BodyTooLarge>(),
                Some(&BodyTooLarge {
                    cap: MAX_EVENT_STREAM_BODY_BYTES
                }),
                "{path}: {error:#}"
            );
        }
    }

    #[tokio::test]
    async fn a_429_stops_the_search_at_once() {
        // Honest up to cursor 16, then rate limited.
        let feed = FakeEventsFeed::answering(|cursor, limit| {
            if cursor.id() >= 16 {
                Err(anyhow::Error::msg(EVENTS_RATE_LIMITED))
            } else {
                Ok(feed_page(&[1000], cursor, limit))
            }
        });
        let error = find_head(&feed, random_pubky(), UNPACED)
            .await
            .expect_err("rate limited");
        assert!(
            format!("{error:#}").ends_with(EVENTS_RATE_LIMITED),
            "{error:#}"
        );
        // 0, 1, 2, 4, 8 and 16: nothing after the 429.
        let asked: Vec<u64> = feed.asked().iter().map(|(cursor, _)| cursor.id()).collect();
        assert_eq!(asked, [0, 1, 2, 4, 8, 16]);
    }

    #[tokio::test]
    async fn the_search_waits_between_requests_after_the_first_few() {
        // The production pace, `SEARCH_PACE`, is checked against the rate
        // limit at compile time; a shorter one keeps the test quick.
        let pace = Duration::from_millis(10);
        let feed = FakeEventsFeed::of_ids(&[1000]);
        let started = Instant::now();
        find_head(&feed, random_pubky(), pace)
            .await
            .expect("a head");
        let elapsed = started.elapsed();
        // `tokio::time::sleep` never wakes early, so this cannot flake.
        let waits = feed.asked().len().saturating_sub(UNPACED_REQUESTS);
        assert!(waits > 0);
        let waits = u32::try_from(waits).expect("a few");
        assert!(elapsed >= pace * waits, "{elapsed:?} for {waits} waits");
    }

    #[tokio::test]
    #[pubky_testnet::test]
    async fn on_a_testnet_the_head_is_the_newest_event_the_stream_reports() {
        let testnet = EphemeralTestnet::builder()
            .build()
            .await
            .expect("testnet starts");
        let pubky = testnet.sdk().expect("client");
        let homeserver = testnet.homeserver_app().public_key();
        let signer = pubky.signer(Keypair::random());
        signer.signup(&homeserver, None).await.expect("signs up");
        let session = signer
            .signin(ClientId::new(CLIENT_ID).expect("a valid client id"))
            .await
            .expect("signs in");
        let owner = pubky_of(&session.public_key());
        let paths: Vec<SweepkyPath> = (1..=3).map(|n| SweepkyPath::Bounty(record_id(n))).collect();
        for path in &paths {
            session
                .storage()
                .put(path.to_path().as_str(), "{}")
                .await
                .expect("writes");
        }

        let events = HomeserverEvents::new(pubky.client());
        let homeserver = pubky_of(&homeserver);
        let head = find_head(&events, homeserver, UNPACED)
            .await
            .expect("a head");
        let newest = events
            .latest_event(homeserver, owner, &paths[2])
            .await
            .expect("the newest write's event");
        assert_eq!(head, newest);
        // The first write's own event comes before it.
        let first = events
            .latest_event(homeserver, owner, &paths[0])
            .await
            .expect("the first write's event");
        assert!(first < head, "{first} {head}");
    }
}
