//! The loopback server of the Pubky Ring sign-in: a small HTTP/1.1 server
//! on `127.0.0.1` that serves the sign-in page for one login flow (03, "How
//! the Ring sign-in looks").
//!
//! [`LoopbackServer::bind`] opens it on a random port, with a random secret
//! path and a fresh CSP nonce, and renders the page for them
//! ([`render_page`]). [`LoopbackServer::serve`] then answers:
//!
//! - `GET /<path>`: the page, as `text/html`;
//! - `GET /<path>/status`: the flow's [`SignInStatus`] word, as
//!   `text/plain`, which the page's script asks for about once a second;
//! - anything else: a refusal whose body is fixed text, never anything from
//!   the request. Another path is 404, another Host 421, another method
//!   405, a head that does not parse 400 and one over [`MAX_HEAD_BYTES`]
//!   431.
//!
//! **Hygiene.** It listens on `127.0.0.1` only, an address written as a
//! number, so no name is looked up; port 0 lets the system pick a free
//! port. The path is 32 bytes from the SDK's CSPRNG, held in `Zeroizing`
//! buffers, compared in constant time and never logged or written to disk:
//! it is what keeps other local pages and processes off the page, which
//! holds the relay channel's secret. Every resource is bounded: at most
//! [`MAX_CONNECTIONS`] connections at once (the rest wait in the system's
//! listen backlog), a [`MAX_HEAD_BYTES`] cap on a request's head, a
//! per-connection timeout, a short linger and the flow's deadline. A server
//! serves one flow and stops for good: `serve` takes it by value.
//!
//! **When it stops.** The page's status can only flip if the page is still
//! served after the flow ends, so once the status is final (anything but
//! `waiting`) the server lingers until that status has been served once,
//! or until [`Limits::linger`] passes with no one asking. It always stops
//! at the flow's deadline, and a connection still open then is closed.
//!
//! **Known limit.** Any local user or process can connect to `127.0.0.1`;
//! the random path is the defence against them. The Host check stops a web
//! page that rebinds its own name to `127.0.0.1` (DNS rebinding): its
//! requests carry its own name as the Host, so they are refused.

use std::borrow::Cow;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use pubky::Keypair;
use sweepky_core::Zeroizing;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep_until, timeout};

use super::page::{SignInStatus, render_page};
use crate::identity::hex_digit;

/// The most connections served at once. A browser opens one for the page
/// and one per status poll, and may open a spare it never uses (a
/// "speculative preconnect"), so four is plenty; more wait in the listen
/// backlog until a slot frees.
pub(crate) const MAX_CONNECTIONS: usize = 4;

/// The most bytes read of a request's head, the request line and headers
/// up to and including the blank line that ends them. A browser's GET is
/// well under 2 KiB.
pub(crate) const MAX_HEAD_BYTES: usize = 8 * 1024;

/// What follows the page's path in the status path.
const STATUS_SUFFIX: &str = "/status";

/// How long the accept loop pauses after the system refuses an accept (out
/// of file descriptors, say), so a lasting failure does not spin a core.
const ACCEPT_RETRY: Duration = Duration::from_millis(100);

/// The blank line that ends a request's head.
const END_OF_HEAD: &[u8] = b"\r\n\r\n";

/// The content type of the page.
const HTML: &str = "text/html; charset=utf-8";

/// The content type of every other answer: the status word and the
/// refusals.
const TEXT: &str = "text/plain; charset=utf-8";

/// The time limits of one server. Tests pass short ones; the login flow
/// passes [`Limits::DEFAULT`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    /// How long one connection may take, from its accept to the end of its
    /// answer: the request's head must arrive in this time, and the answer
    /// must be written in it too.
    pub(crate) connection_timeout: Duration,
    /// How long the server stays up after the status turns final when no
    /// one asks for it.
    pub(crate) linger: Duration,
}

impl Limits {
    /// Five seconds for each.
    pub(crate) const DEFAULT: Self = Self {
        connection_timeout: Duration::from_secs(5),
        linger: Duration::from_secs(5),
    };
}

/// The server for one sign-in flow, bound and not yet serving.
///
/// No `Debug`: it holds the page's URL, whose path is a secret.
pub(crate) struct LoopbackServer {
    listener: TcpListener,
    /// `http://127.0.0.1:<port>/<path>`, which `login` opens in the browser.
    page_url: Zeroizing<String>,
    /// What every connection task needs, behind an `Arc` (a shared,
    /// reference-counted pointer): each task gets a cheap clone of the
    /// pointer, and the last one dropped frees the `Site`, so no task has to
    /// borrow from the server, which a spawned task could not do.
    site: Arc<Site>,
}

/// What the server answers with, made once at bind.
struct Site {
    /// `127.0.0.1:<port>`, the one Host header answered.
    host: String,
    /// `/<path>`, the page's request target. A secret.
    page_target: Zeroizing<String>,
    /// `/<path>/status`. A secret.
    status_target: Zeroizing<String>,
    /// The whole answer to the page's GET, head and page. It holds the
    /// authorization URL, so it is wiped when dropped too.
    page_answer: Zeroizing<Vec<u8>>,
    /// The Content-Security-Policy every answer carries.
    csp: String,
}

impl LoopbackServer {
    /// Opens the server for the authorization URL `link`: a random port on
    /// `127.0.0.1`, a random path and nonce, and the page rendered for them.
    ///
    /// Errors (no port free, a link too long for a QR code) are fixed text
    /// that quotes neither the link nor the path.
    pub(crate) async fn bind(link: &str) -> anyhow::Result<Self> {
        // A `SocketAddr` built from the address itself, never a host name:
        // nothing is looked up, so nothing can resolve to another address.
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .context("could not open a port on 127.0.0.1 for the Pubky Ring sign-in page")?;
        let port = listener
            .local_addr()
            .context("could not read the port of the Pubky Ring sign-in page")?
            .port();
        let host = format!("{}:{port}", Ipv4Addr::LOCALHOST);
        let path = random_hex();
        // The nonce is no secret once the page is out, but it must be one
        // no one could guess before: it is what lets the page's own script
        // and style run while any other would not.
        let nonce = random_hex();
        // `concat` adds up the parts' lengths and allocates once, so each
        // secret string is built in a buffer of its exact size: no growth,
        // which would copy the path into a new buffer and free the old one
        // unwiped.
        let page_target = Zeroizing::new(["/", path.as_str()].concat());
        let status_target = Zeroizing::new([page_target.as_str(), STATUS_SUFFIX].concat());
        let page_url = Zeroizing::new(["http://", host.as_str(), page_target.as_str()].concat());
        let csp = content_security_policy(&nonce);
        // Best effort: `render_page` builds its string by growing it, and
        // the SDK hands the link over unwiped (see `page`), so copies of
        // both may stay in freed memory. The page is wiped from here on.
        let page = Zeroizing::new(render_page(link, &status_target, &nonce)?);
        // Moving the `Vec` into `Zeroizing` moves only its pointer, length
        // and capacity; the bytes stay where they are, so no copy is left.
        let page_answer = Zeroizing::new(Answer::ok(HTML, &page).to_bytes(&csp));
        Ok(Self {
            listener,
            page_url,
            site: Arc::new(Site {
                host,
                page_target,
                status_target,
                page_answer,
                csp,
            }),
        })
    }

    /// The page's URL, `http://127.0.0.1:<port>/<path>`. Its path is the
    /// secret that keeps others off the page: open it in the browser, and
    /// never log it or write it to disk.
    pub(crate) fn url(&self) -> &str {
        &self.page_url
    }

    /// Serves the page and the status until the flow is over: `status`
    /// carries the flow's [`SignInStatus`], and `deadline` is the flow's
    /// own. Returns once the final status has been served, `limits.linger`
    /// after it turned final, at `deadline`, or as soon as the status can
    /// no longer change while it is still `waiting` (its sender dropped),
    /// whichever comes first. Every connection still open is closed before
    /// it returns.
    ///
    /// It takes `self` by value: the server moves in here and is gone
    /// afterwards, so the compiler refuses a second `serve` of it. One
    /// server, one flow.
    ///
    /// Nothing here can fail the login: a connection that goes wrong only
    /// ends that connection, so this returns nothing.
    pub(crate) async fn serve(
        self,
        mut status: watch::Receiver<SignInStatus>,
        deadline: Instant,
        limits: Limits,
    ) {
        // Take the server apart. Serving needs only `listener` and `site`,
        // so the URL is dropped, and so wiped, now; left in the pattern
        // unnamed, it would live on to the end of this function.
        let Self {
            listener,
            page_url,
            site,
        } = self;
        drop(page_url);
        // Every connection runs as its own task in this set, so a slow one
        // never holds up the others. Dropping a `JoinSet` aborts its tasks,
        // so even a caller that drops this future half-way leaves none.
        let mut connections = JoinSet::new();
        let mut stop_at = deadline;
        let mut lingering = false;
        let mut watching = true;
        loop {
            // `borrow` locks the value for reading; `*` copies it out (the
            // status is `Copy`), and the lock is released at the end of the
            // statement. Holding it longer would block the sender.
            if !lingering && is_final(*status.borrow()) {
                lingering = true;
                stop_at = capped_after(limits.linger, deadline);
            }
            // `select!` waits on every branch at once and runs the first
            // that is ready; the others are dropped, which is safe for each
            // of these (tokio documents them as cancel-safe: dropping one
            // loses nothing). A branch with `if` is skipped when it is false.
            tokio::select! {
                () = sleep_until(stop_at) => break,
                accepted = listener.accept(), if connections.len() < MAX_CONNECTIONS => {
                    match accepted {
                        Ok((stream, _peer)) => {
                            connections.spawn(serve_connection(
                                stream,
                                Arc::clone(&site),
                                status.clone(),
                                limits.connection_timeout,
                            ));
                        }
                        Err(_) => sleep_until(capped_after(ACCEPT_RETRY, stop_at)).await,
                    }
                }
                Some(finished) = connections.join_next(), if !connections.is_empty() => {
                    // `Err` is a task that panicked or was aborted; it served
                    // nothing. `flatten` turns the `Option<Option<_>>` into
                    // one `Option`.
                    if finished.ok().flatten().is_some_and(is_final) {
                        break;
                    }
                }
                changed = status.changed(), if watching => {
                    if changed.is_err() {
                        // The sender is gone, so the status is what it is for
                        // good. Still waiting, the flow can never end: stop.
                        watching = false;
                        if !is_final(*status.borrow()) {
                            break;
                        }
                    }
                }
            }
        }
        // Abort every connection still open and wait until each task has
        // stopped, which drops (and so closes) its connection.
        connections.shutdown().await;
    }
}

/// Whether `status` ends the flow: everything but `waiting`.
fn is_final(status: SignInStatus) -> bool {
    status != SignInStatus::Waiting
}

/// The instant `duration` from now, or `cap` if that is sooner. `Instant +
/// Duration` panics when the sum overflows; `checked_add` is `None` instead.
fn capped_after(duration: Duration, cap: Instant) -> Instant {
    Instant::now()
        .checked_add(duration)
        .map_or(cap, |at| at.min(cap))
}

/// 32 bytes from the SDK's CSPRNG as 64 lower-case hex digits.
///
/// pubky re-exports no random-bytes function, but a new keypair's secret is
/// exactly 32 bytes from the operating system's CSPRNG (pkarr's
/// `Keypair::random` fills its seed with `getrandom`). The keypair itself
/// is dropped at once.
fn random_hex() -> Zeroizing<String> {
    let bytes = Zeroizing::new(Keypair::random().secret());
    let mut hex = Zeroizing::new(String::with_capacity(2 * bytes.len()));
    // `bytes.iter()` goes through `Zeroizing`'s `Deref` to the array.
    // `hex_digit` writes a digit without a branch or a table lookup on the
    // secret value, and the string has its full size already, so no push
    // makes it grow.
    for &byte in bytes.iter() {
        hex.push(char::from(hex_digit(byte >> 4)));
        hex.push(char::from(hex_digit(byte & 0x0f)));
    }
    hex
}

/// The policy every answer carries: nothing is allowed (`default-src
/// 'none'`) but the page's own nonced script and style, and fetches of its
/// own origin, which the status poll needs; `base-uri`, `form-action` and
/// `frame-ancestors`, which `default-src` does not cover, are `'none'` too,
/// so the page can be neither re-based nor submitted nor framed.
fn content_security_policy(nonce: &str) -> String {
    format!(
        "default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; \
         connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    )
}

/// One HTTP answer, before it is written out.
///
/// `'a` is how long the body is borrowed for: a refusal's body is a
/// constant, borrowed for the whole program (`'static`), and the page's is
/// borrowed from the page string while its bytes are made.
struct Answer<'a> {
    /// The status line's code and reason, such as `200 OK`.
    status: &'static str,
    content_type: &'static str,
    /// Header lines this answer needs beyond those every answer carries,
    /// each ending in `\r\n`.
    extra_headers: &'static str,
    body: &'a str,
}

impl<'a> Answer<'a> {
    /// A `200 OK` answer of `body`.
    const fn ok(content_type: &'static str, body: &'a str) -> Self {
        Self {
            status: "200 OK",
            content_type,
            extra_headers: "",
            body,
        }
    }

    /// The whole answer, head and body, in one buffer of its exact size, so
    /// it goes out in one write.
    ///
    /// Every answer carries the same hygiene headers: `no-store` keeps the
    /// page (it holds the relay channel's secret) out of the browser's disk
    /// cache, `no-referrer` keeps the path out of any request the page could
    /// cause, `nosniff` and `DENY` stop content sniffing and framing, and
    /// `Connection: close` ends the connection after the one answer, so each
    /// connection serves exactly one request.
    fn to_bytes(&self, csp: &str) -> Vec<u8> {
        let head = format!(
            "HTTP/1.1 {status}\r\n\
             Content-Type: {content_type}\r\n\
             Content-Length: {length}\r\n\
             Cache-Control: no-store\r\n\
             Referrer-Policy: no-referrer\r\n\
             X-Content-Type-Options: nosniff\r\n\
             X-Frame-Options: DENY\r\n\
             Content-Security-Policy: {csp}\r\n\
             {extra_headers}\
             Connection: close\r\n\r\n",
            status = self.status,
            content_type = self.content_type,
            length = self.body.len(),
            extra_headers = self.extra_headers,
        );
        [head.as_bytes(), self.body.as_bytes()].concat()
    }
}

impl Answer<'static> {
    /// A refusal: `status` with `body`, fixed text.
    const fn refusal(status: &'static str, body: &'static str) -> Self {
        Self {
            status,
            content_type: TEXT,
            extra_headers: "",
            body,
        }
    }
}

const BAD_REQUEST: Answer<'static> = Answer::refusal("400 Bad Request", "bad request\n");

const NOT_FOUND: Answer<'static> = Answer::refusal("404 Not Found", "not found\n");

/// HTTP requires a 405 to say which methods are allowed. `..` fills the
/// other fields from the refusal (struct update syntax).
const NOT_GET: Answer<'static> = Answer {
    extra_headers: "Allow: GET\r\n",
    ..Answer::refusal("405 Method Not Allowed", "only GET is served here\n")
};

const WRONG_HOST: Answer<'static> = Answer::refusal(
    "421 Misdirected Request",
    "this server answers only for its own 127.0.0.1 address\n",
);

const HEAD_TOO_LARGE: Answer<'static> = Answer::refusal(
    "431 Request Header Fields Too Large",
    "request head too large\n",
);

/// What one request gets.
enum Route {
    Page,
    Status,
    Refused(Answer<'static>),
}

/// Answers the one request on `stream` within `limit`, and returns the
/// status word it served, if it served the status.
///
/// `timeout` drops the inner future when time runs out, which ends the
/// read or the write wherever it was; the stream is dropped (closed) when
/// this function returns.
async fn serve_connection(
    mut stream: TcpStream,
    site: Arc<Site>,
    status: watch::Receiver<SignInStatus>,
    limit: Duration,
) -> Option<SignInStatus> {
    timeout(limit, answer_request(&mut stream, &site, &status))
        .await
        .ok()
        .flatten()
}

/// Reads one request's head from `stream`, writes its answer and ends the
/// connection. Returns the status word served, if any; a connection that
/// closes or fails on the way gets nothing, and serves nothing.
async fn answer_request(
    stream: &mut TcpStream,
    site: &Site,
    status: &watch::Receiver<SignInStatus>,
) -> Option<SignInStatus> {
    // The head holds the request's path, which is the secret one when the
    // request is right, so it is read into a wiped buffer of fixed size.
    let mut buffer = Zeroizing::new(vec![0_u8; MAX_HEAD_BYTES]);
    let route = match read_head(stream, &mut buffer).await {
        Ok(head) => route(head, site),
        Err(HeadError::TooLarge) => Route::Refused(HEAD_TOO_LARGE),
        Err(HeadError::Closed) => return None,
    };
    // A `Cow` ("clone on write") is either borrowed or owned: the page's
    // answer was made once, at bind, and is only borrowed here, while the
    // status and the refusals are made for this request and owned.
    let (bytes, served) = match route {
        Route::Page => (Cow::Borrowed(site.page_answer.as_slice()), None),
        Route::Status => {
            let word = *status.borrow();
            let bytes = Answer::ok(TEXT, word.word()).to_bytes(&site.csp);
            (Cow::Owned(bytes), Some(word))
        }
        Route::Refused(refusal) => (Cow::Owned(refusal.to_bytes(&site.csp)), None),
    };
    // Only an answer that went out whole counts as served.
    send(stream, &bytes).await.ok()?;
    served
}

/// Writes `bytes` and closes this side of the connection, so the browser
/// sees the end of the answer at once.
async fn send(stream: &mut TcpStream, bytes: &[u8]) -> std::io::Result<()> {
    stream.write_all(bytes).await?;
    stream.shutdown().await
}

/// Why a head could not be read.
enum HeadError {
    /// The buffer filled up before the head ended.
    TooLarge,
    /// The connection ended or failed before the head did.
    Closed,
}

/// Reads from `stream` into `buffer` until the blank line that ends a
/// request's head, and returns the head without that line.
///
/// The returned slice borrows from `buffer`: the lifetime `'b` ties the
/// two, so the compiler keeps `buffer` alive and unchanged while the head
/// is in use. Bytes after the blank line (a body, which a GET has none of)
/// are ignored.
async fn read_head<'b>(
    stream: &mut TcpStream,
    buffer: &'b mut [u8],
) -> Result<&'b [u8], HeadError> {
    let mut filled = 0;
    let end = loop {
        // `get_mut(filled..)` is the free part of the buffer, without an
        // index that could panic; `filled` never passes the buffer's length,
        // so it is always `Some`, and empty once the buffer is full.
        let free = buffer.get_mut(filled..).unwrap_or_default();
        if free.is_empty() {
            return Err(HeadError::TooLarge);
        }
        let read = stream.read(free).await.map_err(|_| HeadError::Closed)?;
        if read == 0 {
            return Err(HeadError::Closed);
        }
        // The blank line may straddle the last read, so the search starts
        // three bytes back; earlier bytes were searched already. `read` is
        // at most the free length, so `filled` stays within the buffer.
        let searched_from = filled.saturating_sub(END_OF_HEAD.len() - 1);
        filled += read;
        let fresh = buffer.get(searched_from..filled).unwrap_or_default();
        if let Some(at) = fresh
            .windows(END_OF_HEAD.len())
            .position(|window| window == END_OF_HEAD)
        {
            break searched_from + at;
        }
    };
    Ok(buffer.get(..end).unwrap_or_default())
}

/// Which answer the request whose head is `head` gets.
fn route(head: &[u8], site: &Site) -> Route {
    let Some(request) = parse_head(head) else {
        return Route::Refused(BAD_REQUEST);
    };
    if request.method != "GET" {
        return Route::Refused(NOT_GET);
    }
    // The Host is public, so a plain comparison. A page elsewhere that
    // rebinds its name to 127.0.0.1 sends its own name here.
    if request.host != Some(site.host.as_str()) {
        return Route::Refused(WRONG_HOST);
    }
    // Both comparisons always run, each in constant time.
    let target = request.target.as_bytes();
    let is_page = constant_time_eq(target, site.page_target.as_bytes());
    let is_status = constant_time_eq(target, site.status_target.as_bytes());
    match (is_page, is_status) {
        (true, _) => Route::Page,
        (_, true) => Route::Status,
        _ => Route::Refused(NOT_FOUND),
    }
}

/// The parts of a request this server looks at, borrowed from its head.
struct Request<'a> {
    method: &'a str,
    target: &'a str,
    /// The one Host header's value, if there is one.
    host: Option<&'a str>,
}

/// `head`, the request line and headers without the blank line, parsed,
/// or `None` when it is not a well-formed HTTP/1.1 request head with at
/// most one Host header.
///
/// Arbitrary bytes come in here, from anything that can connect, so it
/// never indexes: every step is a `split` or a check that returns `None`.
fn parse_head(head: &[u8]) -> Option<Request<'_>> {
    // A browser sends ASCII; anything that is not UTF-8 is refused whole.
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    // `split` always yields at least one piece, so this is the request line.
    let mut parts = lines.next()?.split(' ');
    // Exactly three parts, the last `HTTP/1.1`: a tuple of the first four
    // `next()`s matched in one pattern, the fourth required to be `None`.
    let (Some(method), Some(target), Some("HTTP/1.1"), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    if !is_token(method) || target.is_empty() {
        return None;
    }
    let mut host = None;
    for line in lines {
        let (name, value) = line.split_once(':')?;
        if !is_token(name) {
            return None;
        }
        // `replace` stores the new value and hands back the old one: a
        // second Host header is refused rather than one of them picked.
        if name.eq_ignore_ascii_case("host")
            && host.replace(value.trim_matches([' ', '\t'])).is_some()
        {
            return None;
        }
    }
    Some(Request {
        method,
        target,
        host,
    })
}

/// Whether `text` is an HTTP token, as a method and a header name must be:
/// one or more letters, digits or ``!#$%&'*+-.^_`|~``. Spaces are not, so a
/// header line folded onto the next, or with a space before its colon, is
/// refused.
fn is_token(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// Whether `a` and `b` are the same bytes, compared in constant time once
/// their lengths match.
///
/// The length is public (every path is 64 hex digits), so it is checked
/// first. Then every byte pair is XORed (zero only where they are equal)
/// and the results ORed into one value, looked at once at the end, so the
/// time taken does not depend on where the first difference is: an early
/// exit would tell a local attacker, by timing many guesses, how much of a
/// guess was right. Neither Rust nor LLVM promises that this compiles
/// without a branch; `black_box` asks the optimiser not to reason about
/// the value, which is a best effort, not a guarantee. (The `subtle` crate
/// does the same with more care; it is not among the pinned crates.)
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let difference = a
        .iter()
        .zip(b)
        .fold(0_u8, |acc, (x, y)| std::hint::black_box(acc | (x ^ y)));
    difference == 0
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::sync::watch;
    use tokio::task::JoinHandle;
    use tokio::time::{Instant, sleep, timeout};
    use url::Url;

    use super::{
        Limits, LoopbackServer, MAX_CONNECTIONS, MAX_HEAD_BYTES, NOT_FOUND, constant_time_eq,
        parse_head, random_hex,
    };
    use crate::ring::page::{SignInStatus, render_page};
    use crate::test_support::contains_bytes;

    /// A synthetic grant link shaped like the SDK's, with made-up values.
    const LINK: &str = "pubkyauth://signin_grant?caps=/pub/sweepky/:rw\
        &relay=http://localhost:15412/inbox&cid=sweepky-cli\
        &secret=c3ludGhldGljLXJlbGF5LWNoYW5uZWwtc2VjcmV0LTAx";

    /// Short limits, so a test of a timeout takes a fraction of a second.
    const FAST: Limits = Limits {
        connection_timeout: Duration::from_millis(400),
        linger: Duration::from_millis(300),
    };

    /// How long a test waits for anything before it fails.
    const PATIENCE: Duration = Duration::from_secs(5);

    /// A server serving in its own task, and the handles a test drives it
    /// with.
    struct Running {
        /// The page's URL, as `bind` gave it.
        url: Url,
        addr: SocketAddr,
        /// `127.0.0.1:<port>`, the Host header a browser sends.
        host: String,
        status: watch::Sender<SignInStatus>,
        server: JoinHandle<()>,
    }

    impl Running {
        /// The page's request target, `/<path>`.
        fn page(&self) -> &str {
            self.url.path()
        }
    }

    /// Binds a server for [`LINK`] and serves it with `limits` until
    /// `run_for` from now.
    async fn start(limits: Limits, run_for: Duration) -> Running {
        let server = LoopbackServer::bind(LINK).await.expect("a server");
        let url = Url::parse(server.url()).expect("a URL");
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, url.port().expect("a port")));
        let host = format!("127.0.0.1:{}", addr.port());
        let (status, watched) = watch::channel(SignInStatus::Waiting);
        let deadline = Instant::now() + run_for;
        let server = tokio::spawn(server.serve(watched, deadline, limits));
        Running {
            url,
            addr,
            host,
            status,
            server,
        }
    }

    /// An HTTP answer, as the test client read it.
    struct Reply {
        status: u16,
        /// Each header's lower-case name and its value, in order.
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl Reply {
        /// The value of the one header called `name` (lower case).
        fn header(&self, name: &str) -> Option<&str> {
            let mut values = self.headers.iter().filter(|(key, _)| key == name);
            let value = values.next().map(|(_, value)| value.as_str());
            assert!(values.next().is_none(), "two {name} headers");
            value
        }

        fn text(&self) -> &str {
            std::str::from_utf8(&self.body).expect("UTF-8")
        }
    }

    /// Sends `request` on a new connection and reads the answer to the end
    /// of the connection.
    async fn exchange(addr: SocketAddr, request: &[u8]) -> Reply {
        let mut stream = TcpStream::connect(addr).await.expect("a connection");
        stream.write_all(request).await.expect("the request sent");
        let mut raw = Vec::new();
        timeout(PATIENCE, stream.read_to_end(&mut raw))
            .await
            .expect("an answer in time")
            .expect("the answer read");
        parse_reply(&raw)
    }

    /// A browser's GET of `target` on `running`.
    async fn get(running: &Running, target: &str) -> Reply {
        let request = format!("GET {target} HTTP/1.1\r\nHost: {}\r\n\r\n", running.host);
        exchange(running.addr, request.as_bytes()).await
    }

    fn parse_reply(raw: &[u8]) -> Reply {
        let end = raw
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("a whole head");
        let head = std::str::from_utf8(&raw[..end]).expect("an ASCII head");
        let mut lines = head.split("\r\n");
        let status_line = lines.next().expect("a status line");
        let status = status_line
            .strip_prefix("HTTP/1.1 ")
            .and_then(|rest| rest.get(..3))
            .expect("HTTP/1.1 and a code")
            .parse()
            .expect("a numeric code");
        let headers = lines
            .map(|line| {
                let (name, value) = line.split_once(':').expect("a header");
                (name.to_ascii_lowercase(), value.trim().to_owned())
            })
            .collect();
        let body = raw[end + 4..].to_vec();
        Reply {
            status,
            headers,
            body,
        }
    }

    /// The headers every answer carries, whatever it is.
    fn assert_hygiene_headers(reply: &Reply) {
        for (name, value) in [
            ("cache-control", "no-store"),
            ("referrer-policy", "no-referrer"),
            ("x-content-type-options", "nosniff"),
            ("x-frame-options", "DENY"),
            ("connection", "close"),
        ] {
            assert_eq!(reply.header(name), Some(value), "{name}");
        }
        assert!(reply.header("content-security-policy").is_some());
    }

    /// A Content-Security-Policy header as its directives: each name, in
    /// lower case, and its values.
    fn directives(policy: &str) -> BTreeMap<String, Vec<String>> {
        let mut parsed = BTreeMap::new();
        for directive in policy.split(';').map(str::trim).filter(|d| !d.is_empty()) {
            let mut words = directive.split_ascii_whitespace();
            let name = words.next().expect("a name").to_ascii_lowercase();
            let values = words.map(str::to_owned).collect();
            assert!(parsed.insert(name, values).is_none(), "{directive} twice");
        }
        parsed
    }

    /// The value of the one `attribute="..."` in `page`, given as
    /// `attribute="`.
    fn attribute<'a>(page: &'a str, opening: &str) -> &'a str {
        assert_eq!(page.matches(opening).count(), 1, "{opening}");
        let (_, rest) = page.split_once(opening).expect("the attribute");
        rest.split_once('"').expect("its closing quote").0
    }

    /// The nonce a policy names in `script-src`.
    fn policy_nonce(policy: &str) -> String {
        let directives = directives(policy);
        let [source] = directives["script-src"].as_slice() else {
            panic!("one script source: {policy}");
        };
        source
            .strip_prefix("'nonce-")
            .and_then(|rest| rest.strip_suffix('\''))
            .expect("a nonce source")
            .to_owned()
    }

    fn is_lower_hex(text: &str) -> bool {
        text.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }

    #[tokio::test]
    async fn bind_gives_a_loopback_url_with_a_fresh_random_path_and_nonce() {
        let first = LoopbackServer::bind(LINK).await.expect("a server");
        let second = LoopbackServer::bind(LINK).await.expect("a server");
        let mut seen = Vec::new();
        for server in [&first, &second] {
            let url = Url::parse(server.url()).expect("a URL");
            assert_eq!(url.scheme(), "http");
            assert_eq!(url.host_str(), Some("127.0.0.1"));
            let port = url.port().expect("a port");
            assert_ne!(port, 0);
            let bound = server.listener.local_addr().expect("an address");
            assert_eq!(bound, SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
            assert_eq!(url.query(), None);
            // At least 32 random characters: 64 hex digits, 256 bits.
            let path = url.path().strip_prefix('/').expect("absolute").to_owned();
            assert!(path.len() >= 32 && is_lower_hex(&path), "{path}");
            // At least 128 random bits, in characters a CSP nonce allows.
            let nonce = policy_nonce(&server.site.csp);
            assert!(nonce.len() >= 32 && is_lower_hex(&nonce), "{nonce}");
            seen.push((path, nonce));
        }
        assert_ne!(seen[0].0, seen[1].0, "two binds share a path");
        assert_ne!(seen[0].1, seen[1].1, "two binds share a nonce");
    }

    #[tokio::test]
    async fn the_page_is_served_as_html_with_the_hygiene_headers() {
        let running = start(Limits::DEFAULT, PATIENCE).await;
        let reply = get(&running, running.page()).await;
        assert_eq!(reply.status, 200);
        assert_eq!(
            reply.header("content-type"),
            Some("text/html; charset=utf-8")
        );
        assert_hygiene_headers(&reply);
        // Exactly the page `render_page` writes for this flow.
        let nonce = policy_nonce(reply.header("content-security-policy").expect("a CSP"));
        let status_path = format!("{}/status", running.page());
        let page = render_page(LINK, &status_path, &nonce).expect("a page");
        assert_eq!(reply.text(), page);
        assert_eq!(
            reply.header("content-length"),
            Some(page.len().to_string().as_str())
        );
    }

    #[tokio::test]
    async fn the_csp_is_strict_and_names_the_nonce_on_the_page() {
        let running = start(Limits::DEFAULT, PATIENCE).await;
        let reply = get(&running, running.page()).await;
        let policy = reply.header("content-security-policy").expect("a CSP");
        let directives = directives(policy);
        for (name, value) in [
            ("default-src", "'none'"),
            ("connect-src", "'self'"),
            ("base-uri", "'none'"),
            ("form-action", "'none'"),
            ("frame-ancestors", "'none'"),
        ] {
            assert_eq!(
                directives.get(name),
                Some(&vec![value.to_owned()]),
                "{name}"
            );
        }
        // The page's one script and one style carry the nonce the policy
        // names, and the policy allows nothing else for either.
        let page = reply.text();
        let script_nonce = attribute(page, r#"<script nonce=""#);
        let style_nonce = attribute(page, r#"<style nonce=""#);
        assert_eq!(script_nonce, style_nonce);
        let source = vec![format!("'nonce-{script_nonce}'")];
        assert_eq!(directives.get("script-src"), Some(&source));
        assert_eq!(directives.get("style-src"), Some(&source));
        for never in ["'unsafe-inline'", "'unsafe-eval'"] {
            assert!(!policy.contains(never), "{policy}");
        }
    }

    // Done when (06, login options): the status flips to "approved".
    #[tokio::test]
    async fn the_status_path_on_the_page_answers_waiting_then_approved() {
        let running = start(Limits::DEFAULT, PATIENCE).await;
        let page = get(&running, running.page()).await;
        // Resolved against the page's URL as a browser's fetch resolves
        // it. A relative path would land on `/status`, not the flow's.
        let status_path = attribute(page.text(), r#"data-status=""#);
        let status_url = running.url.join(status_path).expect("a URL");
        assert_eq!(status_url.origin(), running.url.origin());
        assert_eq!(status_url.path(), format!("{}/status", running.page()));

        let waiting = get(&running, status_url.path()).await;
        assert_eq!(waiting.status, 200);
        assert_eq!(
            waiting.header("content-type"),
            Some("text/plain; charset=utf-8")
        );
        assert_hygiene_headers(&waiting);
        assert_eq!(waiting.text(), "waiting");

        running
            .status
            .send(SignInStatus::Approved)
            .expect("the server watches");
        let approved = get(&running, status_url.path()).await;
        assert_eq!(approved.status, 200);
        assert_eq!(approved.text(), "approved");
    }

    // Done when (06, login options): a wrong loopback path gets 404.
    #[tokio::test]
    async fn wrong_paths_get_a_fixed_404_that_echoes_nothing() {
        let running = start(Limits::DEFAULT, PATIENCE).await;
        let page = running.page().to_owned();
        let prefix = page.get(..page.len() - 1).expect("a prefix").to_owned();
        for target in [
            format!("/{}", &*random_hex()),
            prefix,
            format!("{page}x"),
            format!("{page}/"),
            format!("{page}?syntheticmarker=1"),
            format!("{page}/status?syntheticmarker=1"),
            format!("{page}/statusx"),
            page.to_ascii_uppercase(),
            "/".to_owned(),
            "/status".to_owned(),
            "/favicon.ico".to_owned(),
            "*".to_owned(),
            format!("http://{}{page}", running.host),
        ] {
            let reply = get(&running, &target).await;
            assert_eq!(reply.status, 404, "{target}");
            assert_eq!(reply.text(), NOT_FOUND.body, "{target}");
            assert_hygiene_headers(&reply);
        }
        assert_eq!(get(&running, &page).await.status, 200);
    }

    #[tokio::test]
    async fn bad_requests_end_their_connection_and_the_next_one_is_served() {
        let running = start(FAST, PATIENCE).await;
        let page = running.page().to_owned();
        let host = running.host.clone();
        let port = running.addr.port();
        let mut over_cap = format!("GET {page} HTTP/1.1\r\nHost: {host}\r\nX-Pad: ").into_bytes();
        over_cap.resize(MAX_HEAD_BYTES, b'a');
        let cases: Vec<(&str, Vec<u8>, u16)> = vec![
            (
                "another host",
                format!("GET {page} HTTP/1.1\r\nHost: rebound.example:{port}\r\n\r\n").into(),
                421,
            ),
            (
                "the host without the port",
                format!("GET {page} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").into(),
                421,
            ),
            (
                "no host",
                format!("GET {page} HTTP/1.1\r\nAccept: */*\r\n\r\n").into(),
                421,
            ),
            (
                "two hosts",
                format!("GET {page} HTTP/1.1\r\nHost: {host}\r\nHost: {host}\r\n\r\n").into(),
                400,
            ),
            (
                "POST",
                format!("POST {page} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\n\r\n").into(),
                405,
            ),
            (
                "HEAD",
                format!("HEAD {page} HTTP/1.1\r\nHost: {host}\r\n\r\n").into(),
                405,
            ),
            (
                "a malformed request line",
                format!("GET{page}\r\nHost: {host}\r\n\r\n").into(),
                400,
            ),
            (
                "another HTTP version",
                format!("GET {page} HTTP/1.0\r\nHost: {host}\r\n\r\n").into(),
                400,
            ),
            (
                "a header without a colon",
                format!("GET {page} HTTP/1.1\r\nHost: {host}\r\nbroken\r\n\r\n").into(),
                400,
            ),
            (
                "bytes that are not UTF-8",
                [
                    format!("GET {page}").as_bytes(),
                    b"\xff\xfe",
                    format!(" HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes(),
                ]
                .concat(),
                400,
            ),
            ("a head over the cap", over_cap, 431),
        ];
        for (what, request, code) in cases {
            let reply = exchange(running.addr, &request).await;
            assert_eq!(reply.status, code, "{what}");
            assert_hygiene_headers(&reply);
            // Fixed text: nothing of the request comes back.
            assert!(!contains_bytes(&reply.body, page.as_bytes()), "{what}");
            assert!(!contains_bytes(&reply.body, b"rebound"), "{what}");
            if code == 405 {
                assert_eq!(reply.header("allow"), Some("GET"));
            }
            assert_eq!(get(&running, &page).await.status, 200, "after {what}");
        }

        // A client that sends nothing is cut off at the per-connection
        // timeout, with no answer.
        let mut silent = TcpStream::connect(running.addr)
            .await
            .expect("a connection");
        let started = Instant::now();
        let mut rest = Vec::new();
        timeout(PATIENCE, silent.read_to_end(&mut rest))
            .await
            .expect("closed in time")
            .expect("closed cleanly");
        assert!(rest.is_empty());
        let took = started.elapsed();
        assert!(
            took + Duration::from_millis(50) >= FAST.connection_timeout,
            "{took:?}"
        );
        assert_eq!(get(&running, &page).await.status, 200, "after silence");
    }

    #[tokio::test]
    async fn an_idle_connection_does_not_delay_the_page() {
        let limits = Limits {
            connection_timeout: Duration::from_secs(3),
            ..FAST
        };
        let running = start(limits, PATIENCE).await;
        // A browser's speculative preconnect: opened, and nothing sent.
        let _idle = TcpStream::connect(running.addr)
            .await
            .expect("a connection");
        sleep(Duration::from_millis(50)).await;
        let started = Instant::now();
        assert_eq!(get(&running, running.page()).await.status, 200);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn connections_past_the_bound_wait_for_a_free_slot() {
        let limits = Limits {
            connection_timeout: Duration::from_millis(600),
            ..FAST
        };
        let running = start(limits, PATIENCE).await;
        let mut idle = Vec::new();
        for _ in 0..MAX_CONNECTIONS {
            idle.push(
                TcpStream::connect(running.addr)
                    .await
                    .expect("a connection"),
            );
        }
        // Long enough for the server to take every idle one.
        sleep(Duration::from_millis(100)).await;
        let started = Instant::now();
        // This one waits in the listen backlog until an idle connection
        // times out and frees its slot, then it is served.
        assert_eq!(get(&running, running.page()).await.status, 200);
        assert!(
            started.elapsed() >= Duration::from_millis(250),
            "{:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn a_final_status_stops_the_server_once_it_has_been_served() {
        let limits = Limits {
            linger: PATIENCE,
            ..FAST
        };
        let mut running = start(limits, PATIENCE * 2).await;
        running
            .status
            .send(SignInStatus::Approved)
            .expect("the server watches");
        let status_path = format!("{}/status", running.page());
        assert_eq!(get(&running, &status_path).await.text(), "approved");
        timeout(Duration::from_secs(1), &mut running.server)
            .await
            .expect("stopped once the status was served")
            .expect("no panic");
    }

    #[tokio::test]
    async fn a_final_status_nobody_asks_for_stops_the_server_after_the_linger() {
        let running = start(FAST, PATIENCE).await;
        let started = Instant::now();
        running
            .status
            .send(SignInStatus::Refused)
            .expect("the server watches");
        timeout(PATIENCE, running.server)
            .await
            .expect("stopped after the linger")
            .expect("no panic");
        let took = started.elapsed();
        assert!(took >= FAST.linger, "{took:?}");
        assert!(took < Duration::from_secs(2), "{took:?}");
    }

    #[tokio::test]
    async fn the_deadline_stops_the_server_waiting_or_lingering() {
        let run_for = Duration::from_millis(500);
        // Still waiting.
        let started = Instant::now();
        let running = start(FAST, run_for).await;
        timeout(PATIENCE, running.server)
            .await
            .expect("stopped at the deadline")
            .expect("no panic");
        let took = started.elapsed();
        assert!(took >= run_for && took < Duration::from_secs(2), "{took:?}");

        // Final, with a linger that would outlast the deadline.
        let limits = Limits {
            linger: PATIENCE * 2,
            ..FAST
        };
        let started = Instant::now();
        let running = start(limits, run_for).await;
        running
            .status
            .send(SignInStatus::Expired)
            .expect("the server watches");
        timeout(PATIENCE, running.server)
            .await
            .expect("stopped at the deadline")
            .expect("no panic");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn no_connection_is_left_open_once_the_server_stops() {
        let limits = Limits {
            connection_timeout: PATIENCE * 6,
            ..FAST
        };
        let running = start(limits, Duration::from_millis(500)).await;
        let mut idle = TcpStream::connect(running.addr)
            .await
            .expect("a connection");
        timeout(PATIENCE, running.server)
            .await
            .expect("stopped at the deadline")
            .expect("no panic");
        // The idle connection's task stopped with the server, and closed
        // the connection on its way out, long before its own timeout.
        let mut rest = Vec::new();
        timeout(Duration::from_secs(1), idle.read_to_end(&mut rest))
            .await
            .expect("closed with the server")
            .expect("closed cleanly");
        assert!(rest.is_empty());
    }

    #[test]
    fn the_comparison_is_equal_only_for_the_same_bytes() {
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"/0a1b", b"/0a1b"));
        for other in [&b"/0a1c"[..], b"/1a1b", b"/0a1", b"/0a1b2", b""] {
            assert!(!constant_time_eq(b"/0a1b", other), "{other:?}");
        }
    }

    #[test]
    fn parsing_never_panics_on_arbitrary_bytes() {
        let valid = b"GET /0a1b/status HTTP/1.1\r\nHost: 127.0.0.1:8\r\nAccept: */*";
        let parsed = parse_head(valid).expect("a request");
        assert_eq!(
            (parsed.method, parsed.target, parsed.host),
            ("GET", "/0a1b/status", Some("127.0.0.1:8"))
        );
        // Every cut of a valid head.
        for end in 0..=valid.len() {
            let _ = parse_head(&valid[..end]);
        }
        // And many short runs of the bytes a head is made of, with some
        // that are not UTF-8, from a fixed xorshift sequence.
        let alphabet = b"GET /:\r\n \tHhOoSsTt1.\xff\xc3\x80";
        let mut state: u32 = 0x9e37_79b9;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state
        };
        for _ in 0..20_000 {
            let len = next() as usize % 48;
            let bytes: Vec<u8> = (0..len)
                .map(|_| alphabet[next() as usize % alphabet.len()])
                .collect();
            let _ = parse_head(&bytes);
        }
    }
}
