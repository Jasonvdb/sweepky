//! A homeserver's public events: [`parse_feed`] reads one page of its
//! `/events/` feed into a [`FeedPage`], and [`parse_event_stream`] one
//! non-live `/events-stream` answer into a [`StreamPage`].
//!
//! The formats and the reading rules are on the two functions, because this
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

/// The longest line read, in bytes, not counting its `\n` or `\r\n`: 4096.
/// A longer line is malformed, in the `/events/` feed and in an
/// `/events-stream` answer alike.
///
/// Well above the longest line [`PubkyUrl`] accepts, so it never refuses a
/// valid event; it bounds the work on one line before the line is even
/// decoded. P1a's choice; 01 sets none.
pub const MAX_FEED_LINE_BYTES: usize = 4096;

/// The longest `/events-stream` answer read, in bytes: 64 KiB.
///
/// `post --open` asks for one event (`limit=1`), which the homeserver sends
/// in at most about 1.2 KB: the `event:` line, the URL (under 1100 bytes, the
/// most [`PubkyUrl`] accepts), the cursor and a 44-character content hash.
/// The cap leaves room for keep-alive comments and a few dozen such events,
/// and bounds what one answer can make the parse do. P2c's choice; 01 sets
/// none.
pub const MAX_EVENT_STREAM_BODY_BYTES: usize = 64 * 1024;

/// What starts a cursor line.
const CURSOR_PREFIX: &str = "cursor: ";

/// Why a feed page or an `/events-stream` answer could not be read at all. A
/// malformed line or event is not an error: it is skipped and counted in
/// [`FeedPage::malformed`] or [`StreamPage::malformed`].
///
/// Like [`RecordError`](crate::RecordError), it holds numbers only, never
/// text from the homeserver.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FeedError {
    /// The body is longer than its cap, [`MAX_FEED_BODY_BYTES`] for
    /// [`parse_feed`] or [`MAX_EVENT_STREAM_BODY_BYTES`] for
    /// [`parse_event_stream`], so no line of it was read.
    #[error("events body is {len} bytes, over the {limit}-byte limit")]
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

/// One event of a homeserver's `/events-stream` answer, as
/// [`parse_event_stream`] read it: an operation on one file, and the event's
/// id.
// Any operation, checked URL and cursor make a valid event, so the fields can
// be public, as `FeedEvent`'s are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamEvent {
    /// What happened to the file.
    pub op: FeedOp,
    /// The file's URL, of any app, as in [`FeedEvent::url`].
    pub url: PubkyUrl,
    /// The event's id. A homeserver numbers its events once for both
    /// endpoints, so its `/events/?cursor=<id>` lists the events after this
    /// one.
    pub cursor: EventCursor,
}

/// One non-live `/events-stream` answer, as [`parse_event_stream`] read it.
///
/// Like a [`FeedPage`], it is a hint from that homeserver: its events say
/// which files changed and where in its history, not what they hold.
// Private fields and no other constructor, as for `FeedPage`, so `malformed`
// always counts what the parse skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamPage {
    events: Vec<StreamEvent>,
    malformed: usize,
}

impl StreamPage {
    /// Every event, in the order the answer gave them: newest first when the
    /// request said `reverse=true`, oldest first otherwise.
    pub fn events(&self) -> &[StreamEvent] {
        &self.events
    }

    /// How many events were skipped as malformed. Comments and blank lines
    /// are not counted.
    ///
    /// A count, not the events: they are the homeserver's text, and this
    /// crate never hands it back for display.
    pub const fn malformed(&self) -> usize {
        self.malformed
    }

    /// Keeps the event `pending` holds, or counts it as malformed. Lines that
    /// were only comments make no event and are dropped.
    fn end_event(&mut self, pending: PendingEvent) {
        if !pending.started {
            return;
        }
        match pending.into_event() {
            Some(event) => self.events.push(event),
            // Cannot overflow, as in `parse_feed`: there is at most one event
            // per line, and the cap keeps that far below `usize::MAX`.
            None => self.malformed += 1,
        }
    }
}

/// Reads one non-live answer of a homeserver's `/events-stream` endpoint,
/// such as the one to `?user=<owner>&reverse=true&limit=1&path=<dir>`, whose
/// one event is the owner's latest under `<dir>`.
///
/// In pubky-core 0.16.2 (`feed_stream` in
/// `pubky-homeserver/src/client_server/routes/events.rs`, and `to_sse_data`
/// in `persistence/files/events/events_entity.rs`) the answer is Server-Sent
/// Events as axum 0.8.9 writes them. An event is an `event: PUT` or
/// `event: DEL` line, then `data: pubky://<z32><path>`,
/// `data: cursor: <event id>` and, for a PUT only,
/// `data: content_hash: <base64>`, then a blank line. While the stream is
/// idle the homeserver sends axum's default keep-alive, the empty comment
/// `:`. A non-live answer ends after its last event.
///
/// The answer is a hint from a homeserver we do not control, so, as in
/// [`parse_feed`], the parse is strict about each event and tolerant of the
/// answer: an event that is not exactly right is skipped and counted in
/// [`StreamPage::malformed`], and never stops the rest from being read. The
/// rules, P2c's choice where 01 is silent (two of them depart from the SSE
/// standard, and say why):
///
/// - The body is bytes, at most [`MAX_EVENT_STREAM_BODY_BYTES`]; a longer one
///   is refused whole with [`FeedError::TooLarge`] before any line is read.
///   That is the only error.
/// - Lines end at `\n`, and one `\r` before it is dropped, so `\r\n` endings
///   read the same. A lone `\r` does not end a line, though SSE says it does:
///   the homeserver never sends one, so it stays inside its line, where no
///   field accepts it.
/// - A blank line ends an event, and so does the end of the body. (SSE drops
///   an event the stream ends in the middle of. Keeping it trusts the
///   homeserver no further: a body cut inside a cursor line reads as a
///   smaller cursor, and the homeserver can send any cursor it likes anyway.)
/// - A line that starts with `:` is a comment, and is skipped. Lines that are
///   only comments make no event and are not counted.
/// - Any other line is a field, split as SSE splits it: the name before the
///   first `:`, and the value after it without one leading space; a line with
///   no `:` is all name, with an empty value.
///   - `event` is `PUT` or `DEL`, in upper case, once. A missing one (SSE's
///     default type is `message`), any other, or a second, is malformed.
///   - The first `data` line is the file's URL, which [`PubkyUrl`] must
///     accept.
///   - A later `data` line that starts with `cursor:` is the event's id:
///     `cursor: ` then an [`EventCursor`] in canonical decimal, once, as in
///     [`parse_feed`]. A missing one, any other spelling, or a second, even
///     with the same number, is malformed.
///   - Every other later `data` line is skipped unread, `content_hash:` among
///     them: Sweepky does not use the hash, so a DEL needs none and a PUT's
///     is not checked. So is every other field (`id`, `retry`, and names
///     this build does not know), as SSE says.
/// - A line longer than [`MAX_FEED_LINE_BYTES`], a comment included, or a
///   field line that is not UTF-8, makes its event malformed.
///
/// It runs in time linear in the body, never panics, and keeps nothing of an
/// event but its operation, URL and cursor: once an event is malformed, its
/// remaining lines are skipped unread.
// Bytes, not `&str`, for the reason `parse_feed` gives: a line that is not
// UTF-8 then spoils only its own event.
pub fn parse_event_stream(body: &[u8]) -> Result<StreamPage, FeedError> {
    if body.len() > MAX_EVENT_STREAM_BODY_BYTES {
        return Err(FeedError::TooLarge {
            limit: MAX_EVENT_STREAM_BODY_BYTES,
            len: body.len(),
        });
    }
    let mut page = StreamPage {
        events: Vec::new(),
        malformed: 0,
    };
    let mut pending = PendingEvent::default();
    for line in body.split(|&byte| byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            // `mem::take` moves the event read so far out of `pending` and
            // leaves an empty one (its `Default`) in its place, so the next
            // line starts the next event with nothing copied.
            page.end_event(std::mem::take(&mut pending));
        } else {
            pending.read_line(line);
        }
    }
    // The end of the body ends the last event too.
    page.end_event(pending);
    Ok(page)
}

/// What [`parse_event_stream`] has read of the event in progress: the lines
/// since the last blank line.
// `derive(Default)` gives the empty one: `false` for each `bool` and `None`
// for each `Option`.
#[derive(Default)]
struct PendingEvent {
    /// Whether a line other than a comment was read, so that the lines make
    /// an event to keep or count rather than a keep-alive.
    started: bool,
    /// Whether a line already made the event malformed.
    malformed: bool,
    op: Option<FeedOp>,
    url: Option<PubkyUrl>,
    cursor: Option<EventCursor>,
}

impl PendingEvent {
    /// Reads one line that is not blank, without its line ending.
    fn read_line(&mut self, line: &[u8]) {
        // Checked first, so a line over the cap is malformed whatever it
        // holds, a comment included, and costs nothing more.
        if line.len() > MAX_FEED_LINE_BYTES {
            self.started = true;
            self.malformed = true;
            return;
        }
        // A comment, the homeserver's keep-alive among them.
        if line.starts_with(b":") {
            return;
        }
        self.started = true;
        // Once malformed, the event stays so, and `&&` stops before reading
        // its later lines at all: the work per line stays small however many
        // follow.
        if !self.malformed && self.read_field(line).is_none() {
            self.malformed = true;
        }
    }

    /// Reads one field line into the event, or gives `None` when the line
    /// makes the event malformed.
    // `Option<()>` is a yes or a no that `?` can pass on: each `?` below
    // returns `None` at once when its check fails, as in `parse_event`.
    fn read_field(&mut self, line: &[u8]) -> Option<()> {
        let (name, value) = split_field(std::str::from_utf8(line).ok()?);
        // A match guard (`if ...`) lets an arm apply only when its test holds,
        // so a `data` line goes to the first of the two `data` arms whose test
        // it passes, or else to the last arm.
        match name {
            "event" => {
                let op = match value {
                    "PUT" => FeedOp::Put,
                    "DEL" => FeedOp::Del,
                    _ => return None,
                };
                set_once(&mut self.op, op)
            }
            // The first data line. Had an earlier one failed as a URL, the
            // event would be malformed and this line never read, so `url` is
            // empty only here.
            "data" if self.url.is_none() => {
                self.url = Some(value.parse().ok()?);
                Some(())
            }
            // Every line that starts `cursor:` is the cursor's, so a
            // misspelled one is malformed rather than skipped as unknown.
            "data" if value.starts_with("cursor:") => {
                let cursor = value.strip_prefix(CURSOR_PREFIX)?.parse().ok()?;
                set_once(&mut self.cursor, cursor)
            }
            // `content_hash:`, unknown data, `id`, `retry` and unknown fields.
            _ => Some(()),
        }
    }

    /// The event, or `None` when it is malformed or lacks its type, its URL
    /// or its cursor.
    // `self`, not `&self`: the event takes the URL out of the pending one,
    // which is used up, so nothing is cloned.
    fn into_event(self) -> Option<StreamEvent> {
        if self.malformed {
            return None;
        }
        Some(StreamEvent {
            op: self.op?,
            url: self.url?,
            cursor: self.cursor?,
        })
    }
}

/// Splits a field line as SSE does: the name before the first `:`, and the
/// value after it without one leading space. A line with no `:` is all name,
/// with an empty value.
// Both halves borrow from `line`, so nothing is copied. With one reference
// in, the compiler gives the references out its lifetime.
fn split_field(line: &str) -> (&str, &str) {
    match line.split_once(':') {
        Some((name, value)) => (name, value.strip_prefix(' ').unwrap_or(value)),
        None => (line, ""),
    }
}

/// Puts `value` in an empty `slot`, or gives `None` when the slot already
/// holds one: the check for a field that may come only once.
fn set_once<T>(slot: &mut Option<T>, value: T) -> Option<()> {
    if slot.is_some() {
        return None;
    }
    *slot = Some(value);
    Some(())
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{
        FeedError, FeedEvent, FeedOp, FeedPage, MAX_EVENT_STREAM_BODY_BYTES, MAX_FEED_BODY_BYTES,
        MAX_FEED_LINE_BYTES, StreamEvent, StreamPage, parse_event_stream, parse_feed,
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

    // The `/events-stream` answer `post --open` reads its starting cursor
    // from.

    /// A PUT's content hash as the homeserver writes it, the base64 of a
    /// 32-byte BLAKE3 digest: the example in pubky-homeserver 0.16.2's
    /// `feed_stream` docs. The parse never reads it.
    const HASH: &str = "r0NJufX5oaagQE3qNtzJSZvLJcmtwRK3zJqTyuQfMmI=";

    /// axum 0.8.9's default keep-alive (`Event::DEFAULT_KEEP_ALIVE`), an
    /// empty comment, which the homeserver sends while a stream is idle.
    const KEEP_ALIVE: &str = ":\n\n";

    /// One event as pubky-homeserver 0.16.2 sends it: its `to_sse_data` joins
    /// the URL, `cursor: <id>` and, for a PUT, `content_hash: <base64>` with
    /// `\n`, and axum 0.8.9's SSE `Event` writes `event: <type>`, then each of
    /// those lines after `data: `, then a blank line.
    fn wire_event(op: &str, url: &str, cursor: u64, hash: Option<&str>) -> String {
        let mut event = format!("event: {op}\ndata: {url}\ndata: cursor: {cursor}\n");
        if let Some(hash) = hash {
            event.push_str(&format!("data: content_hash: {hash}\n"));
        }
        event.push('\n');
        event
    }

    /// The owner's bounty record, the file `post --open` asks about.
    fn bounty_url() -> String {
        format!("pubky://{ALICE}/pub/sweepky/bounties/{ID1}.json")
    }

    fn other_url() -> String {
        format!("pubky://{BOB}/pub/other.app/posts/1")
    }

    /// The answer to `post --open`'s request: the bounty's PUT alone.
    fn put_answer() -> String {
        wire_event("PUT", &bounty_url(), 42, Some(HASH))
    }

    /// The event `put_answer` parses to.
    fn put_event() -> StreamEvent {
        stream_event(FeedOp::Put, &bounty_url(), 42)
    }

    /// `put_answer` and then a DEL with no hash: two events, newest first, as
    /// `reverse=true` sends them.
    fn two_event_answer() -> String {
        put_answer() + &wire_event("DEL", &other_url(), 41, None)
    }

    /// The events `two_event_answer` parses to.
    fn two_events() -> [StreamEvent; 2] {
        [put_event(), stream_event(FeedOp::Del, &other_url(), 41)]
    }

    fn stream_event(op: FeedOp, text: &str, cursor: u64) -> StreamEvent {
        StreamEvent {
            op,
            url: url(text),
            cursor: EventCursor::new(cursor),
        }
    }

    fn parse_stream(body: &str) -> StreamPage {
        parse_event_stream(body.as_bytes()).unwrap()
    }

    // Task: a PUT with its URL, cursor and content hash parses, and so does a
    // DEL without a hash.
    #[test]
    fn a_put_with_its_hash_and_a_del_without_one_parse() {
        let page = parse_stream(&put_answer());
        assert_eq!(page.events(), [put_event()]);
        assert_eq!(page.malformed(), 0);
        // The URL is typed, as in the feed.
        let put = page.events().first().unwrap();
        assert_eq!(put.url.user(), ALICE.parse::<Pubky>().unwrap());
        assert_eq!(put.url.path(), format!("/pub/sweepky/bounties/{ID1}.json"));

        // Events keep the order the answer gave them.
        let page = parse_stream(&two_event_answer());
        assert_eq!(page.events(), two_events());
        assert_eq!(page.malformed(), 0);

        // With no event under the path asked about, the answer is empty.
        let empty = parse_stream("");
        assert!(empty.events().is_empty());
        assert_eq!(empty.malformed(), 0);
    }

    // Task: keep-alives, `\r\n`, a last event with no blank line after it
    // and unknown `data:` prefixes are tolerated.
    #[test]
    fn keep_alives_crlf_an_unended_last_event_and_unknown_data_are_tolerated() {
        let event = put_answer();
        // Without the blank line that ends the event, then without the
        // newline that ends its last line too.
        let unended = event.strip_suffix('\n').unwrap();
        let unterminated = unended.strip_suffix('\n').unwrap();
        // A field line of exactly the line cap is still read.
        let at_line_cap = format!("future: {}", "x".repeat(MAX_FEED_LINE_BYTES - 8));
        assert_eq!(at_line_cap.len(), MAX_FEED_LINE_BYTES);
        let bodies = [
            (
                "keep-alives around it",
                format!("{KEEP_ALIVE}{event}{KEEP_ALIVE}{KEEP_ALIVE}"),
            ),
            ("other comments", format!(":\n:ok\n: x: y\n\n{event}")),
            (
                "a comment inside the event",
                event.replacen("data: cursor", ": ping\ndata: cursor", 1),
            ),
            (
                "CRLF line endings",
                format!("{KEEP_ALIVE}{event}").replace('\n', "\r\n"),
            ),
            ("no blank line after the last event", unended.to_owned()),
            ("no newline after the last line", unterminated.to_owned()),
            ("extra blank lines", format!("\n\n\r\n{event}\n\n")),
            (
                "an unknown data prefix",
                event.replacen("data: cursor", "data: future: 1\ndata: cursor", 1),
            ),
            (
                "unknown data after the hash",
                format!("{unended}data: future: 1\n\n"),
            ),
            (
                "a hash that is not base64, which is never read",
                event.replace(HASH, "not base64"),
            ),
            (
                "no space after a field's colon",
                event
                    .replace("event: ", "event:")
                    .replace("data: ", "data:"),
            ),
            (
                "SSE fields Sweepky does not read",
                event.replacen(
                    "event: PUT\n",
                    "event: PUT\nid: 7\nretry: 1000\nfuture\n",
                    1,
                ),
            ),
            (
                "a field line at the line cap",
                event.replacen("event: PUT\n", &format!("event: PUT\n{at_line_cap}\n"), 1),
            ),
        ];
        for (what, body) in &bodies {
            let page = parse_stream(body);
            assert_eq!(page.events(), [put_event()], "{what}");
            assert_eq!(page.malformed(), 0, "{what}");
        }

        // Keep-alives alone are no event, and nothing malformed either.
        for body in [KEEP_ALIVE, ":", ": \n\n", ": \r\n\r\n", "\n\n", "\r\n"] {
            let page = parse_stream(body);
            assert!(page.events().is_empty(), "{body:?}");
            assert_eq!(page.malformed(), 0, "{body:?}");
        }
    }

    /// One malformed event of each kind, without the blank line that ends
    /// it, as bytes so that some can be invalid UTF-8.
    fn malformed_events() -> Vec<Vec<u8>> {
        let url = bounty_url();
        // A DEL of `url` whose cursor line holds `cursor`.
        let with_cursor = |cursor: &str| format!("event: DEL\ndata: {url}\ndata: cursor: {cursor}");
        // An event of `url` with cursor 1 and `kind` as its type.
        let with_type = |kind: &str| format!("event: {kind}\ndata: {url}\ndata: cursor: 1");
        // A PUT of `text` as its URL, with cursor 1.
        let with_url = |text: &str| format!("event: PUT\ndata: {text}\ndata: cursor: 1");
        let long = "x".repeat(MAX_FEED_LINE_BYTES);
        let mut events = vec![
            // No URL: no data line, an empty first one, or the cursor first.
            "event: PUT".to_owned(),
            format!("event: DEL\ndata:\ndata: {url}\ndata: cursor: 1"),
            "event: DEL\ndata: cursor: 1".to_owned(),
            format!("event: DEL\ndata: cursor: 1\ndata: {url}"),
            // No cursor, two, or the same one twice.
            format!("event: DEL\ndata: {url}"),
            format!("{}\ndata: cursor: 2", with_cursor("1")),
            format!("{}\ndata: cursor: 1", with_cursor("1")),
            // A cursor line with no space after its colon, alone or beside a
            // good one.
            format!("event: DEL\ndata: {url}\ndata: cursor:1"),
            format!("{}\ndata: cursor:2", with_cursor("1")),
            // A missing type (SSE's default is `message`), or two.
            format!("data: {url}\ndata: cursor: 1"),
            format!("event: PUT\n{}", with_type("PUT")),
            format!("event: DEL\n{}", with_type("PUT")),
            // Lines that are no field Sweepky reads, and nothing else.
            "garbage".to_owned(),
            "\u{1b}[31mred".to_owned(),
            "\0".to_owned(),
            // Lines over the cap, even a comment's or an unknown field's.
            format!("event: PUT\ndata: pubky://{ALICE}/{long}\ndata: cursor: 1"),
            format!("{}\n:{long}", with_cursor("1")),
            format!("{}\nfuture: {long}", with_cursor("1")),
            // A lone `\r` does not end a line, so here the type swallows the
            // URL line.
            format!("event: PUT\rdata: {url}\ndata: cursor: 1"),
        ];
        // Cursors that are not canonical decimal.
        let cursors = [
            "",
            " 1",
            "1 ",
            "007",
            "+1",
            "-1",
            "0x1",
            "abc",
            "18446744073709551616",
        ];
        events.extend(cursors.map(with_cursor));
        // Types other than `PUT` and `DEL`.
        let kinds = [
            "PATCH", "put", "Put", "DELETE", "message", "", "PUT ", "PUT\0",
        ];
        events.extend(kinds.map(with_type));
        // URLs `PubkyUrl` refuses.
        let urls = [
            format!("https://{ALICE}/pub/x"),
            format!("pubky://{}/pub/x", ALICE.to_uppercase()),
            "pubky://example.com/pub/x".to_owned(),
            format!("pubky://{ALICE}"),
            format!(" pubky://{ALICE}/pub/x"),
            format!("pubky://{ALICE}/pub/a b"),
            format!("pubky://{ALICE}/pub/a?b"),
            format!("pubky://{ALICE}/pub/\u{1b}[2J"),
            format!("pubky://{ALICE}/pub/\u{202e}txt"),
        ];
        events.extend(urls.iter().map(String::as_str).map(with_url));
        let mut events: Vec<Vec<u8>> = events.into_iter().map(String::into_bytes).collect();
        // Text that is not UTF-8.
        let url = url.as_bytes();
        events.extend([
            [
                b"event: PUT\xff\ndata: ".as_slice(),
                url,
                b"\ndata: cursor: 1",
            ]
            .concat(),
            [
                b"event: PUT\ndata: pubky://".as_slice(),
                ALICE.as_bytes(),
                b"/pub/\xc3\ndata: cursor: 1",
            ]
            .concat(),
            [
                b"event: PUT\ndata: ".as_slice(),
                url,
                b"\ndata: cursor: 1\nfuture: \xff",
            ]
            .concat(),
            b"\xff\xfe\xfd".to_vec(),
        ]);
        events
    }

    // Task: malformed events are skipped and counted, never fatal.
    #[test]
    fn malformed_events_are_skipped_and_counted() {
        let put = put_answer().into_bytes();
        let del = wire_event("DEL", &other_url(), 41, None).into_bytes();
        let (put, del, blank): (&[u8], &[u8], &[u8]) = (&put, &del, b"\n\n");
        let malformed = malformed_events();
        for bad in &malformed {
            let bad = bad.as_slice();
            let shown = String::from_utf8_lossy(bad);
            // Between two good events, first, and last with no blank line
            // after it.
            let bodies = [
                [put, bad, blank, del].concat(),
                [bad, blank, put, del].concat(),
                [put, del, bad].concat(),
            ];
            for body in &bodies {
                let page = parse_event_stream(body).unwrap();
                assert_eq!(page.events(), two_events(), "{shown:?}");
                assert_eq!(page.malformed(), 1, "{shown:?}");
            }
        }

        // All of them in one body, each counted once.
        let mut body = put.to_vec();
        for bad in &malformed {
            body.extend_from_slice(bad);
            body.extend_from_slice(blank);
        }
        body.extend_from_slice(del);
        let page = parse_event_stream(&body).unwrap();
        assert_eq!(page.events(), two_events());
        assert_eq!(page.malformed(), malformed.len());
    }

    // Task and invariant: the body is bounded, and the error quotes none of
    // it.
    #[test]
    fn a_body_over_its_cap_is_refused_whole_and_quoted_nowhere() {
        // A valid answer, then comments past the cap: none of it is read.
        let mut over = put_answer();
        while over.len() <= MAX_EVENT_STREAM_BODY_BYTES {
            over.push_str(":MARKER\n");
        }
        let error = parse_event_stream(over.as_bytes()).unwrap_err();
        assert_eq!(
            error,
            FeedError::TooLarge {
                limit: MAX_EVENT_STREAM_BODY_BYTES,
                len: over.len(),
            }
        );
        // Numbers only: neither the message nor `Debug` quotes the body.
        for text in [error.to_string(), format!("{error:?}")] {
            assert!(!text.contains("MARKER"), "{text}");
            assert!(!text.contains(ALICE), "{text}");
        }

        // Exactly at the cap is read.
        let mut at = put_answer();
        at.push_str(&"\n".repeat(MAX_EVENT_STREAM_BODY_BYTES - at.len()));
        assert_eq!(parse_stream(&at).events(), [put_event()]);
    }

    // Invariant: a hostile body never panics, and its parse is linear.
    #[test]
    fn hostile_bodies_never_panic_and_parse_in_linear_time() {
        let cap = MAX_EVENT_STREAM_BODY_BYTES;
        // `unit` repeated as many whole times as fit in the cap.
        let repeated = |unit: &[u8]| unit.repeat(cap / unit.len());
        let event = put_answer();
        let unended = event.strip_suffix('\n').unwrap();
        let url_line = format!("data: {}\n", bounty_url());
        // Each body, with how many events and malformed events it holds.
        let cases: Vec<(&str, Vec<u8>, usize, usize)> = vec![
            ("one line as long as the body cap", vec![b'a'; cap], 0, 1),
            (
                "one data line as long as the body cap",
                [
                    b"event: PUT\ndata: ".as_slice(),
                    vec![b'x'; cap - 17].as_slice(),
                ]
                .concat(),
                0,
                1,
            ),
            ("one comment as long as the body cap", vec![b':'; cap], 0, 1),
            ("NUL bytes", vec![0; cap], 0, 1),
            ("bare CRs", vec![b'\r'; cap], 0, 1),
            ("NUL lines", repeated(b"\0\n"), 0, 1),
            (
                "ESC sequences",
                repeated(b"\x1b[2J\x1b]0;title\x07\n"),
                0,
                1,
            ),
            ("invalid UTF-8", repeated(b"\xff\xfe\xc3\n"), 0, 1),
            ("blank lines", repeated(b"\n"), 0, 0),
            ("CRLF blank lines", repeated(b"\r\n"), 0, 0),
            ("keep-alives", repeated(KEEP_ALIVE.as_bytes()), 0, 0),
            ("one event of type lines", repeated(b"event: PUT\n"), 0, 1),
            (
                "one event of cursor lines",
                repeated(b"data: cursor: 1\n"),
                0,
                1,
            ),
            (
                "one event of URL lines",
                repeated(url_line.as_bytes()),
                0,
                1,
            ),
            (
                "one event with many unknown data lines",
                [
                    unended.as_bytes(),
                    b"data: x\n".repeat((cap - unended.len()) / 8).as_slice(),
                ]
                .concat(),
                1,
                0,
            ),
            (
                "events with no data",
                repeated(b"event: PUT\n\n"),
                0,
                cap / 12,
            ),
            (
                "valid events",
                repeated(event.as_bytes()),
                cap / event.len(),
                0,
            ),
        ];
        for (what, body, events, malformed) in &cases {
            assert!(body.len() <= cap, "{what}");
            let started = Instant::now();
            let page = parse_event_stream(body).unwrap();
            let elapsed = started.elapsed();
            assert_eq!(page.events().len(), *events, "{what}");
            assert_eq!(page.malformed(), *malformed, "{what}");
            // Linear work on 64 KiB takes milliseconds, even in a debug
            // build; work quadratic in the body would take seconds.
            assert!(elapsed < Duration::from_secs(1), "{what}: {elapsed:?}");
        }

        // Bodies stitched at random from the pieces the format is made of:
        // whatever comes out, the parse returns, and every event or
        // malformed event took at least one line.
        let url = bounty_url();
        let pieces: [&[u8]; 16] = [
            b"event: ",
            b"data: ",
            b"cursor: ",
            b"PUT",
            b"DEL",
            b"1",
            b"007",
            b":",
            b" ",
            b"\n",
            b"\r",
            b"\r\n",
            b"\0",
            b"\x1b[",
            b"\xff",
            url.as_bytes(),
        ];
        let mut state: u64 = 0x2545_f491_4f6c_dd1d;
        for _ in 0..1000 {
            let mut body = Vec::new();
            for _ in 0..64 {
                // xorshift64: deterministic, and enough to mix the pieces.
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                body.extend_from_slice(pieces[(state % 16) as usize]);
            }
            let page = parse_event_stream(&body).unwrap();
            let lines = body.split(|&byte| byte == b'\n').count();
            assert!(page.events().len() + page.malformed() <= lines);
        }
    }
}
