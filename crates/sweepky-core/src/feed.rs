//! A homeserver's public `/events/` feed: [`parse_feed`] reads one page of it
//! into a [`FeedPage`].
//!
//! The format and the reading rules are on [`parse_feed`], because this
//! module is private and only the re-exported items appear in the crate's
//! docs. Advancing the cursor, and re-fetching each record through the user's
//! pkarr-resolved homeserver rather than trusting this one's word, are the
//! CLI's job (P2c).

use std::collections::HashSet;

use crate::ids::EventCursor;
use crate::url::{PubkyUrl, SweepRef};

/// The longest feed body read, in bytes: 4 MiB.
///
/// The homeserver caps a page at 1000 events, and the longest line
/// [`PubkyUrl`] accepts is under 1100 bytes, so a full page is about 1.1 MB.
/// The cap leaves room for that several times over and bounds what one
/// response can make the parse do. P1a's choice; 01 sets none.
pub const MAX_FEED_BODY_BYTES: usize = 4 * 1024 * 1024;

/// The longest feed line read, in bytes, not counting its `\n` or `\r\n`:
/// 4096. A longer line is malformed.
///
/// Well above the longest line [`PubkyUrl`] accepts, so it never refuses a
/// valid event; it bounds the work on one line before the line is even
/// decoded. P1a's choice; 01 sets none.
pub const MAX_FEED_LINE_BYTES: usize = 4096;

/// What starts a cursor line.
const CURSOR_PREFIX: &str = "cursor: ";

/// Why a feed page could not be read at all. A malformed line is not an
/// error: it is skipped and counted in [`FeedPage::malformed`].
///
/// Like [`RecordError`](crate::RecordError), it holds numbers only, never
/// text from the feed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FeedError {
    /// The body is longer than [`MAX_FEED_BODY_BYTES`], so no line of it was
    /// read.
    #[error("events feed body is {len} bytes, over the {limit}-byte limit")]
    TooLarge {
        /// The cap that applied, in bytes.
        limit: usize,
        /// The body's length, in bytes.
        len: usize,
    },
}

/// What happened to a file: the operation at the start of a feed line.
// A closed enum, unlike the open-string enums records use (`open_enum!`).
// Those keep a value a newer client wrote so that rewriting the record keeps
// it; a feed line is never written back, and a line with an operation this
// build does not know gives it nothing to act on, so the line is skipped as
// malformed instead. `Copy`: it is one byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FeedOp {
    /// `PUT`: the file was written or rewritten.
    Put,
    /// `DEL`: the file was deleted.
    Del,
}

/// One event line of the feed: an operation on one file.
// Any operation and any checked URL make a valid event, so the fields can be
// public: there is nothing for a constructor to check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedEvent {
    /// What happened to the file.
    pub op: FeedOp,
    /// The file's URL, of any app. [`PubkyUrl::sweepky_path`] says whether
    /// it is one of Sweepky's.
    pub url: PubkyUrl,
}

/// One page of a homeserver's `/events/` feed, as [`parse_feed`] read it.
///
/// Every part of it is a hint from that homeserver: the events say which
/// files to look at, not what they hold.
// The fields are private and there is no other constructor, so every
// `FeedPage` is one `parse_feed` built, and `malformed` always counts what
// that parse skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedPage {
    events: Vec<FeedEvent>,
    cursor: Option<EventCursor>,
    malformed: usize,
}

impl FeedPage {
    /// Every event, in the order the feed listed them, including several for
    /// one file. [`deduped`](Self::deduped) keeps the last one per file.
    // `&[FeedEvent]` rather than `&Vec<FeedEvent>`: a slice is the borrowed
    // view of a list, so the caller can read it but not push to it.
    pub fn events(&self) -> &[FeedEvent] {
        &self.events
    }

    /// The page's cursor, from its first valid `cursor:` line wherever that
    /// came, or `None` when it had none.
    ///
    /// The next page starts after it (`?cursor=<id>`). The homeserver can
    /// send any number here, so checking that it moved forward from the
    /// cursor asked for is the caller's job.
    pub const fn cursor(&self) -> Option<EventCursor> {
        self.cursor
    }

    /// How many lines were skipped as malformed, a second cursor line among
    /// them. Empty lines are not counted.
    ///
    /// A count, not the lines: they are a stranger's text, and this crate
    /// never hands it back for display.
    pub const fn malformed(&self) -> usize {
        self.malformed
    }

    /// Whether the page was empty, the homeserver's way of saying the reader
    /// is caught up: no events, no cursor and no malformed line (empty lines
    /// aside).
    ///
    /// A page whose lines were all malformed is not caught up. It has no
    /// cursor to continue from either, so the caller stops and reports it,
    /// rather than reading it as the end of the feed.
    pub fn is_caught_up(&self) -> bool {
        self.events.is_empty() && self.cursor.is_none() && self.malformed == 0
    }

    /// The events with several for one file reduced to the last: one entry
    /// per URL, in the order of each URL's last event.
    ///
    /// URLs are compared as [`PubkyUrl`]s, by the user's key bytes and the
    /// path, so the two spellings of a key name one file. One sweep makes
    /// several events (`running`, then `done`), and the last says what
    /// happened to the file in the end: a `PUT` after a `DEL` is a file that
    /// exists again, a `DEL` after a `PUT` one that is gone.
    // The result borrows from `self`: each `&FeedEvent` points into
    // `self.events`, so nothing is cloned. The compiler infers the lifetime
    // (one reference in, references out), and the caller cannot drop the
    // page while it still holds the result.
    pub fn deduped(&self) -> Vec<&FeedEvent> {
        // Walk from the end, keeping each URL the first time it is seen:
        // that is its last event. `HashSet::insert` returns `false` when the
        // URL is already there, so one lookup both checks and records it,
        // and the whole walk is linear in the number of events.
        //
        // `HashSet`'s default hasher is keyed with random numbers per process,
        // so a homeserver cannot choose URLs that all land in one bucket and
        // turn this quadratic. The set holds references, so it copies no URL,
        // and its capacity is at most the page's own event count.
        let mut seen: HashSet<&PubkyUrl> = HashSet::with_capacity(self.events.len());
        let mut last_first = Vec::new();
        for event in self.events.iter().rev() {
            if seen.insert(&event.url) {
                last_first.push(event);
            }
        }
        last_first.reverse();
        last_first
    }

    /// The sweep records the page names, as `pull` needs them: each
    /// `/pub/sweepky/sweeps/<id>.json` URL as a [`SweepRef`] with its last
    /// operation, [deduplicated](Self::deduped), in the order of each
    /// sweep's last event.
    ///
    /// Every other URL is dropped: the sweep's `.age` package (fetched once
    /// its record says `done`), every other Sweepky file and every other
    /// app's. A path counts only when [`SweepRef::from_url`] reads it, which
    /// is exactly the path a sweep record has. A `PUT` is a record to
    /// re-fetch from the sweeper's own homeserver; a `DEL`, a sweep that is
    /// gone.
    // `(FeedOp, SweepRef)` is two `Copy` values, so the result owns them and
    // does not borrow from the page.
    pub fn sweep_records(&self) -> Vec<(FeedOp, SweepRef)> {
        self.deduped()
            .into_iter()
            // `filter_map` keeps the `Some`s and drops the `None`s:
            // `from_url` gives `None` for any URL that is not a sweep
            // record's, and `map` pairs a `Some` with its operation.
            .filter_map(|event| SweepRef::from_url(&event.url).map(|sweep| (event.op, sweep)))
            .collect()
    }
}

/// Reads one page of a homeserver's `/events/` feed.
///
/// In pubky-core 0.16.2 (`format_events_feed` in
/// `pubky-homeserver/src/client_server/routes/events.rs`) a page is plain
/// text: one line per event, `PUT pubky://<z32><path>` or
/// `DEL pubky://<z32><path>`, then `cursor: <event id>` when there were any
/// events, joined with `\n` and no trailing newline. A page with no events is
/// the empty string, which means the reader is caught up. 01 adds that the
/// cursor line must not be assumed last, so here it may come anywhere.
///
/// The feed is a hint from a homeserver we do not control, listing every
/// app's files, so the parse is strict about each line and tolerant of the
/// page: a line that is not exactly an event or a cursor is skipped and
/// counted in [`FeedPage::malformed`], and never stops the rest of the page
/// from being read. The rules, P1a's choice where 01 is silent:
///
/// - The body is bytes, at most [`MAX_FEED_BODY_BYTES`]; a longer one is
///   refused whole with [`FeedError::TooLarge`] before any line is read. That
///   is the only error.
/// - Lines end at `\n`, and one `\r` before it is dropped, so `\r\n` endings
///   read the same. An empty line is skipped and not counted, so a trailing
///   newline, or a body of nothing but newlines, is not an error.
/// - A line longer than [`MAX_FEED_LINE_BYTES`], or not UTF-8, is malformed.
/// - An event line is `PUT` or `DEL`, in upper case, one space, then a URL
///   [`PubkyUrl`] accepts, which leaves no room for a second space or a
///   trailing word.
/// - A cursor line is `cursor: ` then an [`EventCursor`] in canonical decimal.
///   The first valid one wins; any later cursor line is malformed, even one
///   with the same number.
///
/// It runs in time linear in the body, never panics, and keeps nothing but
/// the events and the cursor.
// Bytes, not `&str`: a line that is not UTF-8 then spoils only itself, where
// decoding the whole body first would lose every line with it. Splitting the
// bytes at `\n` is safe because in UTF-8 the byte 0x0A only ever means
// newline; it never occurs inside a multi-byte character. A caller holding a
// `&str` passes `body.as_bytes()`.
pub fn parse_feed(body: &[u8]) -> Result<FeedPage, FeedError> {
    if body.len() > MAX_FEED_BODY_BYTES {
        return Err(FeedError::TooLarge {
            limit: MAX_FEED_BODY_BYTES,
            len: body.len(),
        });
    }
    let mut page = FeedPage {
        events: Vec::new(),
        cursor: None,
        malformed: 0,
    };
    // `split` yields the pieces between `\n` bytes, as subslices of `body`
    // found by the standard library, so no offset is computed here. An empty
    // body yields one empty piece, and a trailing `\n` an empty last piece.
    for line in body.split(|&byte| byte == b'\n') {
        match parse_line(line) {
            Line::Empty => {}
            Line::Event(event) => page.events.push(event),
            // A match guard: this arm applies only while no cursor has been
            // kept, so the first valid one wins and the next arm counts any
            // later one.
            Line::Cursor(found) if page.cursor.is_none() => page.cursor = Some(found),
            // `+= 1` cannot overflow, which would panic in a debug build:
            // there are at most as many lines as the body has bytes, plus
            // one, and the cap above keeps that far below `usize::MAX`.
            Line::Cursor(_) | Line::Malformed => page.malformed += 1,
        }
    }
    Ok(page)
}

/// What one feed line is.
enum Line {
    /// Nothing, or only the `\r` of a `\r\n` ending.
    Empty,
    /// A `PUT` or `DEL` line.
    Event(FeedEvent),
    /// A `cursor:` line.
    Cursor(EventCursor),
    /// Anything else.
    Malformed,
}

/// Reads one line, without its `\n`.
fn parse_line(line: &[u8]) -> Line {
    // `strip_suffix` gives the line without one trailing `\r`, or `None`
    // when it does not end in one; `unwrap_or` then keeps the line as it
    // was. (`unwrap_or` supplies a fallback, so unlike `unwrap` it cannot
    // panic.)
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if line.is_empty() {
        return Line::Empty;
    }
    // Checked before decoding, so an overlong line costs nothing more.
    if line.len() > MAX_FEED_LINE_BYTES {
        return Line::Malformed;
    }
    // `let ... else` binds the value when the pattern matches and runs the
    // `else` block, which must leave the function, when it does not.
    let Ok(line) = std::str::from_utf8(line) else {
        return Line::Malformed;
    };
    if let Some(value) = line.strip_prefix(CURSOR_PREFIX) {
        // `EventCursor`'s parse accepts canonical decimal only, so an empty
        // value, a sign, a space or a leading zero is malformed. `map_or`
        // gives the first value for an `Err` and calls the function on an
        // `Ok`, here the variant itself, used as a function.
        return value.parse().map_or(Line::Malformed, Line::Cursor);
    }
    parse_event(line).map_or(Line::Malformed, Line::Event)
}

/// Reads an event line, `PUT <url>` or `DEL <url>`, or gives `None` when the
/// line is not one.
fn parse_event(line: &str) -> Option<FeedEvent> {
    // `?` on an `Option` returns `None` from the function at once, the way it
    // returns an `Err` from one that gives a `Result`. The operation is
    // everything before the first space, so `PUT` with no URL has no space
    // and stops here.
    let (op, url) = line.split_once(' ')?;
    let op = match op {
        "PUT" => FeedOp::Put,
        "DEL" => FeedOp::Del,
        _ => return None,
    };
    // `PubkyUrl`'s parse checks the scheme, the host as a pubky and the
    // path, and refuses whitespace, so a second space or a trailing word
    // fails here. `ok()` turns its `Result` into an `Option`, dropping the
    // error: the caller only counts the line.
    let url = url.parse().ok()?;
    Some(FeedEvent { op, url })
}

#[cfg(test)]
mod tests {
    use super::{
        FeedError, FeedEvent, FeedOp, FeedPage, MAX_FEED_BODY_BYTES, MAX_FEED_LINE_BYTES,
        parse_feed,
    };
    use crate::ids::EventCursor;
    use crate::pubky::Pubky;
    use crate::url::{PubkyUrl, SweepRef};

    /// The local testnet homeserver's key (pubky-testnet 0.16.2), standing in
    /// for one user.
    const ALICE: &str = "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo";
    /// Another user, roster member B in fixtures/trust-labels.json.
    const BOB: &str = "btyoe954e99wb6sp7csdipt9ki8ca3iyus1tfi3171zqdixb5csy";
    /// Two sweep ids from fixtures/trust-labels.json.
    const ID1: &str = "0035G87EK4XFE";
    const ID2: &str = "0035JREYBXX7T";

    fn url(text: &str) -> PubkyUrl {
        text.parse().unwrap()
    }

    fn event(op: FeedOp, text: &str) -> FeedEvent {
        FeedEvent { op, url: url(text) }
    }

    fn sweep(user: &str, id: &str) -> SweepRef {
        format!("pubky://{user}/pub/sweepky/sweeps/{id}.json")
            .parse()
            .unwrap()
    }

    fn parse(body: &str) -> FeedPage {
        parse_feed(body.as_bytes()).unwrap()
    }

    /// The event lines of `upstream_body`, in order.
    fn upstream_event_lines() -> Vec<String> {
        vec![
            format!("PUT pubky://{ALICE}/pub/sweepky/sweeps/{ID1}.json"),
            format!("DEL pubky://{BOB}/pub/other.app/posts/1"),
            format!("PUT pubky://{ALICE}/pub/sweepky/sweeps/{ID1}.age"),
        ]
    }

    /// Three event lines and a cursor, joined as pubky-core 0.16.2's
    /// `format_events_feed` joins them: with `\n` and no trailing newline.
    fn upstream_body() -> String {
        let mut lines = upstream_event_lines();
        lines.push("cursor: 42".to_owned());
        lines.join("\n")
    }

    /// The events `upstream_event_lines` parse to.
    fn upstream_events() -> Vec<FeedEvent> {
        vec![
            event(
                FeedOp::Put,
                &format!("pubky://{ALICE}/pub/sweepky/sweeps/{ID1}.json"),
            ),
            event(FeedOp::Del, &format!("pubky://{BOB}/pub/other.app/posts/1")),
            event(
                FeedOp::Put,
                &format!("pubky://{ALICE}/pub/sweepky/sweeps/{ID1}.age"),
            ),
        ]
    }

    // Done when: feed parsing.
    #[test]
    fn put_and_del_lines_parse_in_order_into_typed_urls() {
        let page = parse(&upstream_body());
        assert_eq!(page.events(), upstream_events().as_slice());
        assert_eq!(page.cursor(), Some(EventCursor::new(42)));
        assert_eq!(page.malformed(), 0);
        assert!(!page.is_caught_up());

        // The URL is typed: its key and path are read, not kept as text.
        let first = page.events().first().unwrap();
        assert_eq!(first.op, FeedOp::Put);
        assert_eq!(first.url.user(), ALICE.parse::<Pubky>().unwrap());
        assert_eq!(first.url.path(), format!("/pub/sweepky/sweeps/{ID1}.json"));
    }

    // Done when: feed parsing.
    #[test]
    fn a_pubky_prefixed_host_reads_as_the_raw_one() {
        // The SDK's `pubky<z32>` spelling of the host.
        let page = parse(&format!(
            "DEL pubky://pubky{BOB}/pub/other.app/posts/1\ncursor: 7"
        ));
        assert_eq!(
            page.events(),
            [event(
                FeedOp::Del,
                &format!("pubky://{BOB}/pub/other.app/posts/1")
            )]
        );
    }

    // Done when: the empty body.
    #[test]
    fn an_empty_body_is_caught_up() {
        for body in ["", "\n", "\n\n\n", "\r\n", "\r\n\r\n"] {
            let page = parse(body);
            assert!(page.events().is_empty(), "{body:?}");
            assert_eq!(page.cursor(), None, "{body:?}");
            assert_eq!(page.malformed(), 0, "{body:?}");
            assert!(page.is_caught_up(), "{body:?}");
        }
    }

    // Done when: the empty body (and what does not count as one).
    #[test]
    fn a_lone_cursor_or_a_malformed_line_is_not_caught_up() {
        assert!(!parse("cursor: 9").is_caught_up());
        // A body whose every line is malformed says something, but nothing
        // usable.
        let garbage = parse("garbage");
        assert!(garbage.events().is_empty());
        assert_eq!(garbage.cursor(), None);
        assert_eq!(garbage.malformed(), 1);
        assert!(!garbage.is_caught_up());
    }

    // Done when: the cursor line out of order.
    #[test]
    fn the_cursor_line_may_come_anywhere() {
        let expected = parse(&upstream_body());
        let events = upstream_event_lines();
        for at in 0..=events.len() {
            let mut lines = events.clone();
            lines.insert(at, "cursor: 42".to_owned());
            let page = parse(&lines.join("\n"));
            assert_eq!(page, expected, "cursor at line {at}");
        }
    }

    // Done when: the cursor line out of order (more than one of them).
    #[test]
    fn the_first_valid_cursor_line_wins() {
        // A second cursor line is counted as malformed.
        let events = upstream_event_lines().join("\n");
        let two = parse(&format!("cursor: 5\n{events}\ncursor: 9"));
        assert_eq!(two.events(), upstream_events().as_slice());
        assert_eq!(two.cursor(), Some(EventCursor::new(5)));
        assert_eq!(two.malformed(), 1);
        // Even when the second is the same number.
        let same = parse("cursor: 5\ncursor: 5");
        assert_eq!(same.cursor(), Some(EventCursor::new(5)));
        assert_eq!(same.malformed(), 1);
        // An invalid cursor line is malformed and does not count as the first.
        let after_bad = parse("cursor: abc\ncursor: 7");
        assert_eq!(after_bad.cursor(), Some(EventCursor::new(7)));
        assert_eq!(after_bad.malformed(), 1);
    }

    /// One line of each malformed kind, as bytes so that some can be invalid
    /// UTF-8.
    fn malformed_lines() -> Vec<Vec<u8>> {
        let path = format!("/pub/sweepky/sweeps/{ID1}.json");
        let too_long = format!("PUT pubky://{ALICE}/{}", "x".repeat(MAX_FEED_LINE_BYTES));
        // Two-byte characters, so the cap falls inside one of them.
        let too_long_multibyte = format!(
            "PUT pubky://{ALICE}/{}",
            "\u{e9}".repeat(MAX_FEED_LINE_BYTES / 2)
        );
        for line in [&too_long, &too_long_multibyte] {
            assert!(line.len() > MAX_FEED_LINE_BYTES);
        }
        [
            // Unknown or misspelled operations.
            format!("PATCH pubky://{ALICE}{path}"),
            format!("put pubky://{ALICE}{path}"),
            format!("Put pubky://{ALICE}{path}"),
            format!("DELETE pubky://{ALICE}{path}"),
            // A missing URL.
            "PUT".to_owned(),
            "PUT ".to_owned(),
            "DEL".to_owned(),
            // Another scheme.
            format!("PUT https://{ALICE}{path}"),
            format!("PUT {ALICE}{path}"),
            // A bad pubky host.
            format!("PUT pubky://example.com{path}"),
            format!("PUT pubky://{}{path}", ALICE.to_uppercase()),
            format!("PUT pubky://{}{path}", &ALICE[..51]),
            format!("PUT pubky://{path}"),
            // Extra or misplaced spaces.
            format!("PUT  pubky://{ALICE}{path}"),
            format!(" PUT pubky://{ALICE}{path}"),
            format!("PUT pubky://{ALICE}{path} "),
            format!("PUT pubky://{ALICE}{path} extra"),
            "   ".to_owned(),
            "\t".to_owned(),
            // Non-ASCII garbage and control characters.
            "\u{fffd}\u{202e}\u{e9}\u{2603}".to_owned(),
            format!("PUT pubky://{ALICE}/pub/other.app/\u{202e}txt"),
            format!("PUT pubky://{ALICE}/pub/other.app/a\rb"),
            "\0".to_owned(),
            "\u{1b}[31mred".to_owned(),
            // Lines over the cap.
            too_long,
            too_long_multibyte,
            // Bad cursor lines.
            "cursor: abc".to_owned(),
            "cursor:".to_owned(),
            "cursor: ".to_owned(),
            "cursor: 007".to_owned(),
            "cursor: 0042".to_owned(),
            "cursor: -1".to_owned(),
            "cursor: +1".to_owned(),
            "cursor:  42".to_owned(),
            "cursor: 42 ".to_owned(),
            "cursor:42".to_owned(),
            "Cursor: 42".to_owned(),
            "cursor: 18446744073709551616".to_owned(),
        ]
        .into_iter()
        .map(String::into_bytes)
        // Bytes that are not UTF-8 at all.
        .chain([
            b"\xff\xfe\xfd".to_vec(),
            [
                b"PUT pubky://".as_slice(),
                ALICE.as_bytes(),
                b"/pub/other.app/\xc3".as_slice(),
            ]
            .concat(),
        ])
        .collect()
    }

    // Done when: malformed lines.
    #[test]
    fn malformed_lines_are_skipped_and_counted() {
        // The first two upstream lines, a PUT and a DEL, and their events.
        let lines = upstream_event_lines();
        let events = upstream_events();
        let expected = &events[..2];
        let (put, del, cursor): (&[u8], &[u8], &[u8]) =
            (lines[0].as_bytes(), lines[1].as_bytes(), b"cursor: 3");
        let malformed = malformed_lines();
        for bad in &malformed {
            let bad = bad.as_slice();
            // Between two good lines, then first and last.
            let bodies = [
                [put, bad, del, cursor].join(&b'\n'),
                [bad, put, del, cursor].join(&b'\n'),
                [put, del, cursor, bad].join(&b'\n'),
            ];
            for body in &bodies {
                let page = parse_feed(body).unwrap();
                let shown = String::from_utf8_lossy(bad);
                assert_eq!(page.events(), expected, "{shown:?}");
                assert_eq!(page.cursor(), Some(EventCursor::new(3)), "{shown:?}");
                assert_eq!(page.malformed(), 1, "{shown:?}");
            }
        }

        // All of them in one body, each counted once.
        let mut body = [put, b"\n".as_slice()].concat();
        for bad in &malformed {
            body.extend_from_slice(bad);
            body.push(b'\n');
        }
        body.extend_from_slice(del);
        let page = parse_feed(&body).unwrap();
        assert_eq!(page.events(), expected);
        assert_eq!(page.cursor(), None);
        assert_eq!(page.malformed(), malformed.len());
    }

    // Done when: malformed lines (CRLF is tolerated, not malformed).
    #[test]
    fn crlf_line_endings_are_tolerated() {
        let crlf = parse(&(upstream_body().replace('\n', "\r\n") + "\r\n"));
        assert_eq!(crlf, parse(&upstream_body()));
        assert_eq!(crlf.malformed(), 0);
    }

    // Done when: duplicate URIs.
    #[test]
    fn several_events_for_one_uri_dedupe_to_the_last() {
        let a = format!("pubky://{ALICE}/pub/sweepky/sweeps/{ID1}.json");
        let b = format!("pubky://{BOB}/pub/other.app/posts/1");
        let c = format!("pubky://{BOB}/pub/sweepky/sweeps/{ID2}.json");

        // PUT, PUT, DEL of one URI is a DEL.
        let page = parse(&format!("PUT {a}\nPUT {a}\nDEL {a}\ncursor: 3"));
        assert_eq!(page.events().len(), 3);
        assert_eq!(page.deduped(), [&event(FeedOp::Del, &a)]);

        // DEL then PUT is a PUT.
        let page = parse(&format!("DEL {a}\nPUT {a}\ncursor: 2"));
        assert_eq!(page.deduped(), [&event(FeedOp::Put, &a)]);

        // One entry per URI, in the order of each URI's last event. The key's
        // spelling does not matter: `pubky<z32>` is the same user.
        let page = parse(&format!(
            "PUT {a}\nPUT {b}\nPUT {c}\nDEL pubky://pubky{ALICE}/pub/sweepky/sweeps/{ID1}.json\nPUT {b}\ncursor: 5"
        ));
        assert_eq!(
            page.deduped(),
            [
                &event(FeedOp::Put, &c),
                &event(FeedOp::Del, &a),
                &event(FeedOp::Put, &b),
            ]
        );
        // The page itself keeps every event as it came.
        assert_eq!(page.events().len(), 5);
    }

    // Done when: feed parsing (picking out the sweep records `pull` needs).
    #[test]
    fn sweep_records_keeps_only_sweep_record_urls() {
        let body = [
            format!("PUT pubky://{ALICE}/pub/sweepky/sweeps/{ID1}.json"),
            // The package beside it, and every other Sweepky file.
            format!("PUT pubky://{ALICE}/pub/sweepky/sweeps/{ID1}.age"),
            format!("PUT pubky://{ALICE}/pub/sweepky/bounties/{ID1}.json"),
            format!("PUT pubky://{ALICE}/pub/sweepky/bounties/{ID1}.discovered.json"),
            format!("PUT pubky://{ALICE}/pub/sweepky/circle.json"),
            format!("PUT pubky://{ALICE}/pub/sweepky/keys/laptop-1.json"),
            // Paths that only look like a sweep record.
            format!("PUT pubky://{ALICE}/pub/sweepky/sweeps/{ID1}.json.bak"),
            format!("PUT pubky://{ALICE}/pub/sweepky/sweeps/x/{ID1}.json"),
            format!("PUT pubky://{ALICE}/pub/sweepky/sweeps/../sweeps/{ID1}.json"),
            format!(
                "PUT pubky://{ALICE}/pub/sweepky/sweeps/{}.json",
                ID1.to_lowercase()
            ),
            // Another app's file of the same name.
            format!("PUT pubky://{ALICE}/pub/other.app/sweeps/{ID1}.json"),
            format!("DEL pubky://{BOB}/pub/sweepky/sweeps/{ID2}.json"),
            // The first sweep again: deduped to its last event.
            format!("PUT pubky://pubky{ALICE}/pub/sweepky/sweeps/{ID1}.json"),
            "cursor: 99".to_owned(),
        ]
        .join("\n");
        let page = parse(&body);
        assert_eq!(page.malformed(), 0);
        assert_eq!(
            page.sweep_records(),
            [
                (FeedOp::Del, sweep(BOB, ID2)),
                (FeedOp::Put, sweep(ALICE, ID1)),
            ]
        );
        assert!(parse("").sweep_records().is_empty());
    }

    // Invariant: the whole body is bounded.
    #[test]
    fn a_body_over_the_cap_is_too_large() {
        let over = vec![b'\n'; MAX_FEED_BODY_BYTES + 1];
        assert_eq!(
            parse_feed(&over),
            Err(FeedError::TooLarge {
                limit: MAX_FEED_BODY_BYTES,
                len: MAX_FEED_BODY_BYTES + 1,
            })
        );
        // Exactly at the cap is read.
        let at = vec![b'\n'; MAX_FEED_BODY_BYTES];
        assert!(parse_feed(&at).unwrap().is_caught_up());
    }
}
