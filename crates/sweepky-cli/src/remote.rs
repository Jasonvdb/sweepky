//! Reading other people's records and directories, and what a refused write
//! means: the network helpers every command shares.
//!
//! - [`get_public`] reads one public file of any owner, and [`get_own`] one of
//!   the signed-in user's own; a 404 is `None`, "no such record".
//! - [`list_dir`] lists one directory of an owner, page by page, into the
//!   Sweepky files it holds; a 404 is an empty directory.
//! - [`get_unredirected`], the one anonymous `GET` Sweepky sends itself:
//!   `get_public`'s, each listing page's and each of GitHub's (in
//!   `targets::github`).
//! - [`write_refusal`] turns the two answers a homeserver gives a write it
//!   will not take, 403 and 507, into the message `login` aborts with, and
//!   [`request_error`] turns every other SDK error into a message.
//! - [`pubky_of`] and [`public_key_of`] convert between core's `Pubky` and
//!   the SDK's `PublicKey`, the owner these helpers take, so the commands
//!   share one conversion.
//!
//! The rules, and why:
//!
//! - **Every body is capped before it is buffered.** A homeserver is someone
//!   else's machine and can answer with an endless body. [`read_capped`]
//!   refuses a `Content-Length` over the cap before reading a byte, then
//!   reads chunk by chunk and stops at the chunk that would cross it, so
//!   nothing past the cap is ever copied in. The caller names the cap: a
//!   record is read with [`MAX_RECORD_BYTES`](sweepky_core::MAX_RECORD_BYTES)
//!   and then parsed with that record's `from_json`, core's capped,
//!   version-first parse, which is the only record parser. The SDK's own
//!   `text()`, `bytes()` and `get_json` read a whole body with no cap, and
//!   are never used on remote data.
//! - **Listings are bounded by line, by page and in total.** The SDK's
//!   `list(..).send()` is not used: in pubky 0.16.2
//!   (`actors/storage/list.rs`) it reads the whole answer with
//!   `resp.bytes()`, whatever its size, and decodes it with
//!   `String::from_utf8_lossy`, which quietly replaces bytes that are not
//!   UTF-8; its `.limit()` bounds only what an honest server sends. So
//!   [`list_dir`] sends its own `GET` of the directory, on the same anonymous
//!   path the SDK's public storage uses, reads each page through
//!   [`read_capped`], and parses it with [`ListingParser`], which refuses a
//!   line over [`MAX_LISTING_LINE_BYTES`], a line that is not UTF-8 or not a
//!   resource URL, a page with more entries than were asked for, and a
//!   listing past [`ListLimits`]' entry and page counts.
//! - **A redirected answer is refused, never used.** The SDK's HTTP client
//!   follows redirects to any host and scheme (pubky 0.16.2 sets no
//!   `redirect::Policy`, so reqwest's default of up to 10 applies), and a
//!   homeserver or GitHub is someone else's machine. So every request
//!   Sweepky sends itself goes through [`get_unredirected`], which keeps the
//!   URL the request went to and refuses the answer when reqwest reports
//!   another one ([`check_not_redirected`]): before its status is looked at,
//!   so a redirected 404 is not an empty directory either, and before a
//!   byte of its body is read. reqwest has still sent the redirected request
//!   by then, possibly to a host inside the sweeper's network; the guard
//!   refuses its answer, it cannot stop the request. The SDK's own requests
//!   (sign-up, sign-in, sign-out and a session's reads and writes, so
//!   [`get_own`] too) are not Sweepky's to guard and still follow redirects.
//! - **Entries are checked, not trusted.** An entry of another owner, or
//!   outside the directory asked for, is skipped and counted, and so is one
//!   [`SweepkyPath::parse`] does not accept, such as a `keys/` file whose
//!   name is not a valid device id. Owners are compared as keys, by their
//!   bytes (`PublicKey`'s `==`), never as strings.
//! - **Errors never quote the server or the URL.** A homeserver's error body
//!   is a stranger's text, and an SDK transport error's `Display` includes
//!   the request URL. So every message built here is fixed text, the HTTP
//!   status (whose wording comes from the `http` crate, not the server) and
//!   the owner key and path the caller asked for. Text inside a record goes
//!   through [`crate::display`]'s sanitiser before it is printed.

use std::fmt;

use anyhow::{Context as _, anyhow, bail};
// `pubky` re-exports `reqwest`'s `Method` and `StatusCode`, so this crate
// needs no `reqwest` dependency of its own. The response type the SDK hands
// back is `reqwest`'s and cannot be named here, which is why the read loop
// takes a closure rather than a response (see `read_capped`).
use pubky::errors::RequestError;
use pubky::{Method, Pubky, PubkyHttpClient, PubkyResource, PubkySession, PublicKey, StatusCode};
use sweepky_core::Zeroizing;
use sweepky_core::paths::SweepkyPath;
use url::Url;

/// What `login` aborts with when its first key write gets a 403: the
/// homeserver will not let this identity write under `/pub/sweepky/`.
///
/// On production that is a signup token from free IP verification, which
/// allows only Paykit's and Bitkit's paths (06, "Production homeserver").
pub(crate) const WRITE_FORBIDDEN: &str = "the homeserver refused the write (HTTP 403): this \
     identity's signup token does not allow `/pub/sweepky/`; use a dedicated identity";

/// What `login` aborts with when its first key write gets a 507: the
/// identity's storage quota is used up.
pub(crate) const QUOTA_FULL: &str =
    "the homeserver refused the write (HTTP 507): storage quota full; use a dedicated identity";

/// The HTTP status of an SDK error that is a homeserver's answer, or `None`
/// for any other error (a transport failure, a pkarr lookup, a bad URL).
///
/// The SDK reports every non-2xx answer as `RequestError::Server`, so that is
/// the one variant with a status.
pub(crate) fn status_of(error: &pubky::Error) -> Option<StatusCode> {
    match error {
        // `..` skips the `message` field: it is the server's own text, and
        // nothing here ever looks at it. `*status` copies the `StatusCode`
        // out of the borrowed error, which `Copy` allows.
        pubky::Error::Request(RequestError::Server { status, .. }) => Some(*status),
        _ => None,
    }
}

/// The message for a write the homeserver refused with 403 or 507, the two
/// refusals `login`'s capability probe explains, or `None` for any other
/// error. The message is fixed text: none of the server's words.
pub(crate) fn write_refusal(error: &pubky::Error) -> Option<&'static str> {
    // `?` on an `Option` returns `None` at once when there is no status.
    match status_of(error)? {
        StatusCode::FORBIDDEN => Some(WRITE_FORBIDDEN),
        StatusCode::INSUFFICIENT_STORAGE => Some(QUOTA_FULL),
        _ => None,
    }
}

/// A failed write as the message to abort with: [`write_refusal`]'s for a
/// 403 or 507, [`request_error`]'s for anything else.
pub(crate) fn write_error(error: &pubky::Error) -> anyhow::Error {
    match write_refusal(error) {
        // `Error::msg` makes an error of a plain message; `anyhow!` would do
        // the same, but reads as if it formatted something.
        Some(message) => anyhow::Error::msg(message),
        None => request_error(error),
    }
}

/// An SDK error as a message that quotes nothing it holds: the status for a
/// homeserver's answer, "network error" for a transport failure, a fixed
/// sentence for the rest.
///
/// The SDK's own `Display` would print a server's error body, which is a
/// stranger's text, and a transport error's request URL.
pub(crate) fn request_error(error: &pubky::Error) -> anyhow::Error {
    // No `_ =>` arm: if a later SDK adds a variant, the build stops here
    // until someone decides what it may print.
    let message = match error {
        pubky::Error::Request(RequestError::Server { status, .. }) => return status_error(*status),
        pubky::Error::Request(RequestError::Transport(transport)) => {
            // Only the error's kind and status are read, never its text.
            let what = if transport.is_timeout() {
                "network error (timed out)"
            } else if transport.is_connect() {
                "network error (could not connect)"
            } else {
                "network error"
            };
            return match transport.status() {
                Some(status) => anyhow!("{what}: HTTP {status}"),
                None => anyhow::Error::msg(what),
            };
        }
        pubky::Error::Request(RequestError::Validation { .. }) => {
            "the Pubky SDK refused the request as invalid"
        }
        pubky::Error::Request(RequestError::DecodeJson { .. }) => {
            "the homeserver's answer could not be decoded"
        }
        pubky::Error::Pkarr(_) => "could not resolve the homeserver through pkarr",
        pubky::Error::Parse(_) => "could not build the request URL",
        pubky::Error::Authentication(_) => "the homeserver did not accept the session",
        pubky::Error::Build(_) => "could not build the Pubky HTTP client",
    };
    anyhow::Error::msg(message)
}

/// A homeserver's non-2xx answer as "the homeserver answered 500 Internal
/// Server Error": the status and the `http` crate's standard reason for it,
/// never the server's own words.
fn status_error(status: StatusCode) -> anyhow::Error {
    anyhow!("the homeserver answered {status}")
}

/// A body over its cap: the homeserver said, or sent, more than the caller
/// reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BodyTooLarge {
    /// The cap that applied, in bytes.
    pub(crate) cap: usize,
}

impl fmt::Display for BodyTooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the server's answer is over the {}-byte limit", self.cap)
    }
}

// An empty impl: `Error`'s methods all have defaults. Implementing it (with
// `Display` and `Debug` above) is what lets `?` turn a `BodyTooLarge` into an
// `anyhow::Error`.
impl std::error::Error for BodyTooLarge {}

/// The buffer a body of unknown length starts with: 8 KiB, or the cap when
/// that is smaller.
const INITIAL_CAPACITY: usize = 8 * 1024;

/// A response body collected up to a cap, as [`read_capped`] reads it.
///
/// A pure type, so the cap is tested without a network. It never holds more
/// than `cap` bytes, and never asks for a buffer larger than `cap` either.
///
/// The bytes live in a `Zeroizing` buffer, wiped when it is dropped, the
/// crate's one buffer type for file and network bodies. When it has to grow,
/// it moves into a new, larger buffer and the old one is dropped, so wiped;
/// a `Vec` growing by itself would free its old memory unwiped. (The network
/// stack's own buffers are not ours to wipe; nothing read here is secret
/// today, so this is hygiene, not a guarantee.)
pub(crate) struct CappedBody {
    buf: Zeroizing<Vec<u8>>,
    cap: usize,
}

impl CappedBody {
    /// A new, empty body, or [`BodyTooLarge`] when the `Content-Length`
    /// (`None` when the answer gave none) is already over `cap`. Nothing of
    /// that size is allocated: the check comes first.
    pub(crate) fn new(content_length: Option<u64>, cap: usize) -> Result<Self, BodyTooLarge> {
        let too_large = BodyTooLarge { cap };
        let initial = match content_length {
            Some(claimed) => {
                // `try_from` fails for a length a 32-bit `usize` cannot hold,
                // which is over any cap anyway.
                let claimed = usize::try_from(claimed).map_err(|_| too_large)?;
                if claimed > cap {
                    return Err(too_large);
                }
                claimed
            }
            None => INITIAL_CAPACITY.min(cap),
        };
        Ok(Self {
            buf: Zeroizing::new(Vec::with_capacity(initial)),
            cap,
        })
    }

    /// Appends `chunk`, or refuses it with [`BodyTooLarge`] when it would
    /// take the body past the cap. A refused chunk is not copied in at all,
    /// and the caller stops reading: the body is abandoned.
    ///
    /// A lying `Content-Length` changes nothing: the cap holds whatever the
    /// header said.
    pub(crate) fn push(&mut self, chunk: &[u8]) -> Result<(), BodyTooLarge> {
        // `checked_add` is `None` on overflow, and `filter` turns a total over
        // the cap into `None` too, so one `ok_or` covers both.
        let needed = self
            .buf
            .len()
            .checked_add(chunk.len())
            .filter(|&total| total <= self.cap)
            .ok_or(BodyTooLarge { cap: self.cap })?;
        if needed > self.buf.capacity() {
            // Double, as `Vec` would, but never past the cap.
            let grown = needed
                .max(self.buf.capacity().saturating_mul(2))
                .min(self.cap);
            let mut bigger = Zeroizing::new(Vec::with_capacity(grown));
            bigger.extend_from_slice(&self.buf);
            // Assigning drops the old buffer, and `Zeroizing`'s `Drop` wipes
            // it, spare capacity included, before the memory is freed.
            self.buf = bigger;
        }
        // There is room now, so this copies without reallocating.
        self.buf.extend_from_slice(chunk);
        Ok(())
    }

    /// How many bytes the body holds so far.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.buf.len()
    }

    /// The whole body. Takes `self` by value: the body is handed over, and
    /// nothing can be pushed to it afterwards.
    pub(crate) fn finish(self) -> Zeroizing<Vec<u8>> {
        self.buf
    }
}

/// Reads a whole response body of at most `cap` bytes: refuses a
/// `content_length` over the cap before reading anything, then calls
/// `next_chunk` until it gives `None`, and stops at the first chunk that
/// would cross the cap, without asking for another.
///
/// Callers pass `response.content_length()` and
/// `async || response.chunk().await`. The response is `reqwest`'s type,
/// which this crate cannot name without depending on `reqwest` itself, so
/// the loop takes the one method it needs as a closure instead. The chunk
/// type `C` and the error `E` are left generic for the same reason, and
/// tests pass a list of chunks.
// `AsyncFnMut` is the async form of `FnMut`: a closure that can be called
// more than once and may change what it captured (here, the response it
// reads from). Unlike a plain closure that returns a future, the future it
// returns may borrow what the closure captured, which `response.chunk()`
// needs, because it borrows the response mutably. `E: Into<pubky::Error>`
// accepts `reqwest`'s error, which the SDK converts into its own.
pub(crate) async fn read_capped<C, E>(
    content_length: Option<u64>,
    cap: usize,
    mut next_chunk: impl AsyncFnMut() -> Result<Option<C>, E>,
) -> anyhow::Result<Zeroizing<Vec<u8>>>
where
    C: AsRef<[u8]>,
    E: Into<pubky::Error>,
{
    let mut body = CappedBody::new(content_length, cap)?;
    // `while let` runs while the pattern matches: here, while the source
    // hands back `Some(chunk)`. `?` leaves the loop and the function on an
    // error, so after a refusal no further chunk is asked for.
    while let Some(chunk) = next_chunk()
        .await
        .map_err(|error| request_error(&error.into()))?
    {
        body.push(chunk.as_ref())?;
    }
    Ok(body.finish())
}

/// `Ok(None)` for a 404, which for a record means "there is no such
/// record", `Ok(Some(..))` for an answer, and every other error as it was.
fn absent_on_not_found<T>(result: pubky::Result<T>) -> pubky::Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        // A match guard: this arm applies only when the condition holds.
        Err(error) if status_of(&error) == Some(StatusCode::NOT_FOUND) => Ok(None),
        Err(error) => Err(error),
    }
}

/// The SDK's key as core's `Pubky`: the same 32 bytes.
//
// Core's `Pubky` is written out in full in these two functions: in this
// module the bare name `Pubky` is the SDK's client, imported above.
pub(crate) fn pubky_of(key: &PublicKey) -> sweepky_core::Pubky {
    sweepky_core::Pubky::from_bytes(key.to_bytes())
}

/// Core's `Pubky` as the SDK's key, the owner every helper here takes; the
/// SDK checks it is a valid Ed25519 point.
pub(crate) fn public_key_of(pubky: &sweepky_core::Pubky) -> anyhow::Result<PublicKey> {
    PublicKey::try_from_z32(&pubky.to_string())
        .map_err(|_| anyhow!("{pubky} is not a valid public key"))
}

/// Reads `path` of `owner`'s public storage, at most `cap` bytes, or `None`
/// when there is no such file (a 404).
///
/// No session: the owner's homeserver is resolved through pkarr and asked
/// anonymously, with the request the SDK's public storage sends (a `GET` of
/// the resource's transport URL), sent through [`get_unredirected`] so a
/// redirected answer is refused. The owner and path go in as the SDK's
/// `PubkyResource`, so no URL is put together from strings here. Parse a
/// record with its type's `from_json` and pass
/// [`MAX_RECORD_BYTES`](sweepky_core::MAX_RECORD_BYTES) as `cap`.
///
/// `path` appears in the error message, so pass one built by
/// [`sweepky_core::paths`], never a stranger's text.
pub(crate) async fn get_public(
    pubky: &Pubky,
    owner: &PublicKey,
    path: &str,
    cap: usize,
) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
    // An `async` block is a future that runs the code inside when awaited;
    // `?` inside it returns from the block, not from `get_public`, so the
    // context below is added to every error the block can give.
    async {
        // `clone` because the resource keeps its own copy of the key; a
        // `PublicKey` holds no heap data, so the copy is cheap.
        let resource = PubkyResource::new(owner.clone(), path).map_err(|e| request_error(&e))?;
        let url = resource.to_transport_url().map_err(|e| request_error(&e))?;
        // A 404 is `None`, "no such record", as for a listing page.
        get_unredirected(pubky.client(), url, &[], cap, page_status).await
    }
    .await
    .with_context(|| format!("could not read {path} of {}", owner.z32()))
}

/// Reads `path` of the signed-in user's own storage through `session`, at
/// most `cap` bytes, or `None` when there is no such file. As for
/// [`get_public`], `path` appears in the error message.
pub(crate) async fn get_own(
    session: &PubkySession,
    path: &str,
    cap: usize,
) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
    async {
        let answer = session.storage().get(path).await;
        let Some(mut response) = absent_on_not_found(answer).map_err(|e| request_error(&e))? else {
            return Ok(None);
        };
        let body = read_capped(response.content_length(), cap, async || {
            response.chunk().await
        })
        .await?;
        anyhow::Ok(Some(body))
    }
    .await
    .with_context(|| format!("could not read your {path}"))
}

/// The longest listing line read, in bytes, not counting its `\n` or
/// `\r\n`: 4096, as for the events feed. A longer line is refused.
///
/// A Sweepky entry is under 250 bytes even in the longer `https://` form
/// (two 52-character keys, `/pub/sweepky/keys/` and a 64-character device
/// id), so this never refuses one of ours; it bounds the work on one line
/// before it is decoded. P2a's choice.
pub(crate) const MAX_LISTING_LINE_BYTES: usize = 4096;

/// The most entries a homeserver sends on one listing page, whatever
/// `limit=` asks for: 1000 (`DEFAULT_MAX_LIST_LIMIT` in pubky-homeserver
/// 0.16.2's `constants.rs`).
const MAX_PAGE_SIZE: u16 = 1000;

/// How much of a directory [`list_dir`] reads. P2a's choice; 01 sets none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ListLimits {
    /// Entries asked for per page, sent as `limit=`: 1 to 1000. The
    /// homeserver's own default is 100. A page with fewer entries is the
    /// last, and one with more breaks the protocol and is refused. Above
    /// 1000 the homeserver would quietly send 1000, which would read as a
    /// short last page and cut the listing off, so [`list_dir`] refuses it.
    pub(crate) page_size: u16,
    /// The most entries read across all pages; one more is refused.
    pub(crate) max_entries: usize,
    /// The most pages read; one more is refused.
    pub(crate) max_pages: usize,
}

impl ListLimits {
    /// 100 entries a page, at most 1000 entries in 11 pages: room for an
    /// owner's device keys many times over. Ten full pages take 1000
    /// entries, and the eleventh is the empty page that says the listing is
    /// over.
    pub(crate) const DEFAULT: Self = Self {
        page_size: 100,
        max_entries: 1000,
        max_pages: 11,
    };

    /// Whether `page_size` is one the homeserver honours: 1 to
    /// [`MAX_PAGE_SIZE`]. `const`, so the check below runs at compile time.
    const fn page_size_is_honoured(&self) -> bool {
        self.page_size >= 1 && self.page_size <= MAX_PAGE_SIZE
    }

    /// The most bytes one page may have: `page_size` lines of
    /// [`MAX_LISTING_LINE_BYTES`] plus `\r\n` each. Blank lines count
    /// against it too, so padding cannot stretch a page.
    pub(crate) fn max_page_bytes(&self) -> usize {
        usize::from(self.page_size).saturating_mul(MAX_LISTING_LINE_BYTES.saturating_add(2))
    }
}

// A compile-time check (a failed `assert!` in a `const` is a build error, not
// a panic at run time): the default limits are ones `list_dir` accepts.
const _: () = assert!(ListLimits::DEFAULT.page_size_is_honoured());

/// What [`list_dir`] found in a directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Listing {
    /// The Sweepky files in the directory, in the order the homeserver
    /// listed them.
    pub(crate) entries: Vec<SweepkyPath>,
    /// How many entries were skipped: another owner's, outside the
    /// directory, or not a Sweepky file. A count, never the names, which
    /// are the homeserver's text.
    pub(crate) skipped: usize,
}

/// Why a listing was refused. Fixed text only: none of the listing's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListingError {
    /// A page is over [`ListLimits::max_page_bytes`].
    PageTooLarge,
    /// A line is over [`MAX_LISTING_LINE_BYTES`].
    LineTooLong,
    /// A line is not UTF-8.
    NotUtf8,
    /// A line is not a `pubky://` or `https://` resource URL.
    NotAResource,
    /// A page has more entries than [`ListLimits::page_size`] asked for.
    PageOverLimit,
    /// The pages together have more than [`ListLimits::max_entries`].
    TooManyEntries,
    /// The listing runs past [`ListLimits::max_pages`].
    TooManyPages,
    /// A full page names no entry of this owner in this directory, so there
    /// is nothing to continue from.
    NoCursor,
}

impl fmt::Display for ListingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // No `_ =>` arm, so a new variant does not build without a message.
        match self {
            Self::PageTooLarge => f.write_str("a page of the listing is over its byte limit"),
            Self::LineTooLong => write!(
                f,
                "a line of the listing is over {MAX_LISTING_LINE_BYTES} bytes"
            ),
            Self::NotUtf8 => f.write_str("a line of the listing is not UTF-8"),
            Self::NotAResource => {
                f.write_str("a line of the listing is not a pubky:// or https:// URL")
            }
            Self::PageOverLimit => {
                f.write_str("a page of the listing has more entries than were asked for")
            }
            Self::TooManyEntries => f.write_str("the listing has more entries than Sweepky reads"),
            Self::TooManyPages => f.write_str("the listing runs to more pages than Sweepky reads"),
            Self::NoCursor => {
                f.write_str("a full page of the listing names no entry to continue from")
            }
        }
    }
}

impl std::error::Error for ListingError {}

/// Reads the pages of one directory's listing, one [`page`](Self::page) at
/// a time, into a [`Listing`]. Pure: [`list_dir`] does the network.
///
/// A page is plain text, one entry per line. The 0.16.2 homeserver writes
/// `pubky://<owner>/<path>` lines joined with `\n` (`list` in
/// `client_server/routes/tenants/read.rs`); the SDK also reads the
/// `https://_pubky.<owner>/storage/<owner>/<path>` transport form, so both
/// are read here. Only those two forms: not the SDK's `pubky<owner>/<path>`.
// `'a` is a lifetime: the parser borrows the directory (it does not copy
// it), and the compiler makes sure the directory outlives the parser.
pub(crate) struct ListingParser<'a> {
    directory: &'a PubkyResource,
    limits: ListLimits,
    listing: Listing,
    entries_read: usize,
    pages_read: usize,
}

impl<'a> ListingParser<'a> {
    /// A parser for `directory`, whose path ends with `/`.
    pub(crate) fn new(directory: &'a PubkyResource, limits: ListLimits) -> Self {
        Self {
            directory,
            limits,
            listing: Listing::default(),
            entries_read: 0,
            pages_read: 0,
        }
    }

    /// Reads one page, and gives the entry to ask for the next page after
    /// (its cursor), or `None` when this page was the last: one with fewer
    /// entries than [`ListLimits::page_size`].
    ///
    /// The rules, P2a's choice:
    ///
    /// - The page is refused whole if it is over the byte cap or past the
    ///   page count, and any line that breaks the protocol refuses it: one
    ///   over [`MAX_LISTING_LINE_BYTES`], one that is not UTF-8 (never
    ///   decoded lossily), one that is not a resource URL. So is a page with
    ///   more entries than asked for, or one past the entry count.
    /// - Lines end at `\n`, one `\r` before it is dropped, and the line is
    ///   trimmed, as the SDK does. Blank lines are skipped and not counted.
    /// - An entry of another owner, or not inside the directory, is skipped
    ///   and counted, and so is one that [`SweepkyPath::parse`] does not
    ///   accept.
    /// - The cursor is the last entry of this owner inside the directory,
    ///   Sweepky file or not. A full page with none has no cursor, and is
    ///   refused.
    pub(crate) fn page(&mut self, body: &[u8]) -> Result<Option<PubkyResource>, ListingError> {
        self.pages_read = self.pages_read.saturating_add(1);
        if self.pages_read > self.limits.max_pages {
            return Err(ListingError::TooManyPages);
        }
        if body.len() > self.limits.max_page_bytes() {
            return Err(ListingError::PageTooLarge);
        }
        let page_size = usize::from(self.limits.page_size);
        let mut on_page: usize = 0;
        let mut last = None;
        // Bytes, split at `\n`, as core's feed parser does: in UTF-8 the
        // byte 0x0A only ever means newline, so splitting first is safe, and
        // each line is decoded (strictly) on its own.
        for raw_line in body.split(|&byte| byte == b'\n') {
            // `let ... else`: go on with the line's text, or to the next
            // line when this one is blank.
            let Some(line) = decode_line(raw_line)? else {
                continue;
            };
            // Both counts are bounded by the checks right after them, so
            // they stay far below `usize::MAX`.
            on_page = on_page.saturating_add(1);
            self.entries_read = self.entries_read.saturating_add(1);
            if on_page > page_size {
                return Err(ListingError::PageOverLimit);
            }
            if self.entries_read > self.limits.max_entries {
                return Err(ListingError::TooManyEntries);
            }
            let entry = parse_entry(line).ok_or(ListingError::NotAResource)?;
            if self.is_inside(&entry) {
                self.add(&entry);
                last = Some(entry);
            } else {
                self.skip();
            }
        }
        // `on_page == 0` matters only for a `page_size` of 0, which
        // `list_dir` never sends: an empty page still ends the listing.
        if on_page < page_size || on_page == 0 {
            return Ok(None);
        }
        // A full page: the next one starts after its last entry, so a full
        // page without one cannot go on.
        let cursor = last.ok_or(ListingError::NoCursor)?;
        Ok(Some(cursor))
    }

    /// Adds `entry`, one inside the directory, to the listing, or counts it
    /// as skipped when [`SweepkyPath::parse`] does not accept it.
    fn add(&mut self, entry: &PubkyResource) {
        match SweepkyPath::parse(entry.path.as_str()) {
            Some(path) => self.listing.entries.push(path),
            None => self.skip(),
        }
    }

    /// Counts one entry as skipped.
    fn skip(&mut self) {
        self.listing.skipped = self.listing.skipped.saturating_add(1);
    }

    /// Whether `entry` is this owner's and strictly inside the directory.
    fn is_inside(&self, entry: &PubkyResource) -> bool {
        // `PublicKey`'s `==` compares the key bytes, never a spelling. The
        // SDK's `ResourcePath` has already refused `.`, `..` and `//`
        // segments, so a plain prefix test on the path is sound.
        entry.owner == self.directory.owner
            && entry
                .path
                .as_str()
                .strip_prefix(self.directory.path.as_str())
                .is_some_and(|rest| !rest.is_empty())
    }

    /// Everything read so far.
    pub(crate) fn finish(self) -> Listing {
        self.listing
    }
}

/// One listing line, split off at `\n`, as its trimmed text, or `None` when
/// it is blank. One `\r` at its end is dropped first. A line over
/// [`MAX_LISTING_LINE_BYTES`] is refused before it is decoded, and one that
/// is not UTF-8 is refused rather than decoded lossily.
// The `&str` borrows from `raw_line`: with one reference in, the compiler
// gives the one out the same lifetime, so none needs writing.
fn decode_line(raw_line: &[u8]) -> Result<Option<&str>, ListingError> {
    let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
    if line.len() > MAX_LISTING_LINE_BYTES {
        return Err(ListingError::LineTooLong);
    }
    let line = std::str::from_utf8(line)
        .map_err(|_| ListingError::NotUtf8)?
        .trim();
    // `then_some` is `Some(line)` when the condition holds, else `None`.
    Ok((!line.is_empty()).then_some(line))
}

/// One listing line as a resource, or `None` when it is neither form.
fn parse_entry(line: &str) -> Option<PubkyResource> {
    // `.ok()` drops the SDK's error, whose message can quote the line.
    if line.starts_with("pubky://") {
        line.parse().ok()
    } else if line.starts_with("https://") {
        PubkyResource::from_transport_url(&Url::parse(line).ok()?).ok()
    } else {
        None
    }
}

/// What an answer's status says to do with its body, as the
/// `read_status` of [`get_unredirected`] decides it: named for the listing
/// page it was first written for, it serves every answer that function
/// reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PageStatus {
    /// 2xx: read the body.
    Read,
    /// 404: there is nothing to read. For a listing, the directory is
    /// empty, or does not exist, which for a homeserver is the same (it
    /// answers 404 "Directory Not Found" for a directory with nothing in
    /// it); for a record, there is no such record.
    Empty,
}

/// What `status` means for a homeserver's answer, a listing page or a
/// record, or an error naming the status alone for anything but 2xx and
/// 404. It is given the status alone, so it cannot read an error answer's
/// body.
fn page_status(status: StatusCode) -> anyhow::Result<PageStatus> {
    if status == StatusCode::NOT_FOUND {
        Ok(PageStatus::Empty)
    } else if status.is_success() {
        Ok(PageStatus::Read)
    } else {
        Err(status_error(status))
    }
}

/// The URL of one listing page: the directory's transport URL, then
/// `limit=<page_size>` and, after the first page, `cursor=` the last entry's
/// `pubky://` URL.
fn page_url(
    directory: &PubkyResource,
    page_size: u16,
    cursor: Option<&PubkyResource>,
) -> anyhow::Result<Url> {
    let mut url = directory
        .to_transport_url()
        .map_err(|e| request_error(&e))?;
    // `query_pairs_mut` lends out a writer for the URL's query that
    // percent-encodes every key and value, so a cursor cannot add a
    // parameter of its own. The braces end that loan, which borrows `url`
    // mutably, so that `url` can be returned after it.
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("limit", &page_size.to_string());
        if let Some(last) = cursor {
            query.append_pair("cursor", &last.to_pubky_url());
        }
    }
    Ok(url)
}

/// Lists `dir` (a path ending with `/`, such as
/// [`paths::KEYS_DIR`](sweepky_core::paths::KEYS_DIR)) of `owner`'s public
/// storage, page by page, within `limits`. A 404 is an empty directory.
///
/// Each page is an anonymous `GET` of the directory's transport URL, the
/// same request the SDK's public storage sends, read through
/// [`read_capped`] with [`ListLimits::max_page_bytes`] and parsed by a
/// [`ListingParser`]. Paging stops at a short page, an empty one or a 404.
/// `limits.page_size` must be 1 to 1000.
///
/// `dir` appears in the error message, so pass one of
/// [`sweepky_core::paths`]' directories, never a stranger's text.
pub(crate) async fn list_dir(
    pubky: &Pubky,
    owner: &PublicKey,
    dir: &str,
    limits: ListLimits,
) -> anyhow::Result<Listing> {
    async {
        if !limits.page_size_is_honoured() {
            bail!(
                "a listing page holds 1 to {MAX_PAGE_SIZE} entries, not {}",
                limits.page_size
            );
        }
        // `clone` because the resource keeps its own copy of the key; a
        // `PublicKey` holds no heap data, so the copy is cheap.
        let directory = PubkyResource::new(owner.clone(), dir).map_err(|e| request_error(&e))?;
        if !directory.path.as_str().ends_with('/') {
            bail!("not a directory: a listing's path ends with `/`");
        }
        let mut parser = ListingParser::new(&directory, limits);
        let mut cursor: Option<PubkyResource> = None;
        loop {
            let url = page_url(&directory, limits.page_size, cursor.as_ref())?;
            let Some(body) = fetch_page(pubky, url, limits.max_page_bytes()).await? else {
                break;
            };
            match parser.page(&body)? {
                Some(last) => cursor = Some(last),
                None => break,
            }
        }
        anyhow::Ok(parser.finish())
    }
    .await
    .with_context(|| format!("could not list {dir} of {}", owner.z32()))
}

/// One listing page: an anonymous `GET` of `url` through
/// [`get_unredirected`], its body read with `cap`, or `None` for a 404. Any
/// other non-2xx answer is an error naming the status, and its body is
/// never read.
async fn fetch_page(
    pubky: &Pubky,
    url: Url,
    cap: usize,
) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
    get_unredirected(pubky.client(), url, &[], cap, page_status).await
}

/// What a request that ended at another URL than the one it was sent to is
/// refused with. Fixed text: neither URL, which a server chose.
const REDIRECTED: &str =
    "the server answered through a redirect, which Sweepky refuses: nothing in the answer was used";

/// Sends an anonymous `GET` of `url` through `client`, the SDK's HTTP
/// client, with `headers` added, and reads its body, at most `cap` bytes,
/// through [`read_capped`]: the one way Sweepky sends a request itself.
///
/// In order, so that nothing is used that should not be:
///
/// 1. The answer is refused when it came through a redirect
///    ([`check_not_redirected`]), whatever its status.
/// 2. `read_status` is given the status alone and decides: read the body
///    ([`PageStatus::Read`]), hand back `None` ([`PageStatus::Empty`]), or
///    fail. An error answer's body is never read.
/// 3. The body is read under the cap.
///
/// Every error is fixed text, the status, or [`request_error`]'s: never the
/// server's words or a URL.
pub(crate) async fn get_unredirected(
    client: &PubkyHttpClient,
    url: Url,
    headers: &[(&'static str, &'static str)],
    cap: usize,
    read_status: impl FnOnce(StatusCode) -> anyhow::Result<PageStatus>,
) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
    // `request_async` is the SDK's own way to address a URL: it resolves a
    // Pubky host through pkarr and may rewrite the URL (an ICANN domain in
    // place of the key, or a legacy homeserver's path). The URL to compare
    // with is therefore the one in the request it builds, not `url`.
    let mut builder = client
        .request_async(Method::GET, url)
        .await
        .map_err(|e| request_error(&e))?;
    // `&(name, value)` takes each pair apart, copying out its two
    // `&'static str`s; `header` consumes the builder and hands it back.
    for &(name, value) in headers {
        builder = builder.header(name, value);
    }
    // `build_split` takes the builder apart into its client and the
    // finished request, so the request's URL can be kept before
    // `execute` sends it. (`send` would do both in one step, and keep no
    // URL to compare with.) Both fail with `reqwest`'s error; `.into()`
    // makes it the SDK's, whose variants `request_error` knows.
    let (http, request) = builder.build_split();
    let request = request.map_err(|e| request_error(&e.into()))?;
    let sent = request.url().clone();
    let mut response = http
        .execute(request)
        .await
        .map_err(|e| request_error(&e.into()))?;
    check_not_redirected(&sent, response.url())?;
    if read_status(response.status())? == PageStatus::Empty {
        return Ok(None);
    }
    // `content_length()` is read first, while nothing borrows the
    // response; the closure then borrows it mutably for the reads.
    let body = read_capped(response.content_length(), cap, async || {
        response.chunk().await
    })
    .await?;
    Ok(Some(body))
}

/// Refuses an answer whose URL, `received`, is not `sent`, the URL its
/// request went to: [`REDIRECTED`] for another scheme, host, port, path or
/// query. Pure, so the tests check it without a network.
///
/// reqwest follows a redirect by itself and reports the URL of the last
/// request it made as the answer's, so any difference means the answer
/// came from a request Sweepky did not choose to send. With no redirect
/// that URL is the one sent, parsed again from its text, so the parts are
/// compared rather than the text, and `port_or_known_default` reads
/// `https://h/` and `https://h:443/` as the one port they are.
pub(crate) fn check_not_redirected(sent: &Url, received: &Url) -> anyhow::Result<()> {
    let same = sent.scheme() == received.scheme()
        && sent.host() == received.host()
        && sent.port_or_known_default() == received.port_or_known_default()
        && sent.path() == received.path()
        && sent.query() == received.query();
    if !same {
        bail!(REDIRECTED);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use pubky::errors::RequestError;
    use pubky::{Keypair, PubkyResource, PublicKey, StatusCode};
    use sweepky_core::DeviceId;
    use sweepky_core::paths::{self, SweepkyPath};

    use super::{
        BodyTooLarge, CappedBody, ListLimits, ListingError, ListingParser, MAX_LISTING_LINE_BYTES,
        PageStatus, QUOTA_FULL, WRITE_FORBIDDEN, absent_on_not_found, check_not_redirected,
        page_status, page_url, read_capped, request_error, status_of, write_error, write_refusal,
    };

    /// What the server text in these tests tries to do: move the cursor, set
    /// a colour, start a new line that looks like Sweepky's own output.
    const HOSTILE: &str = "\u{1b}[2J\u{1b}[31mpwned\nerror: everything is fine\r\n\u{9b}0m";

    /// The error the SDK returns for a non-2xx answer.
    fn server(status: StatusCode) -> pubky::Error {
        RequestError::Server {
            status,
            message: HOSTILE.to_owned(),
        }
        .into()
    }

    /// An error that is not an HTTP answer at all.
    fn not_an_answer() -> pubky::Error {
        RequestError::Validation {
            message: HOSTILE.to_owned(),
        }
        .into()
    }

    fn device(name: &str) -> SweepkyPath {
        SweepkyPath::Key(name.parse::<DeviceId>().expect("a valid device id"))
    }

    fn keys_dir(owner: &PublicKey) -> PubkyResource {
        PubkyResource::new(owner.clone(), paths::KEYS_DIR).expect("a valid directory")
    }

    /// The listing line the 0.16.2 homeserver writes for `path`.
    fn pubky_line(owner: &PublicKey, path: &str) -> String {
        format!("pubky://{}{path}", owner.z32())
    }

    /// The same entry in the SDK's `https://` transport form.
    fn https_line(owner: &PublicKey, path: &str) -> String {
        let z32 = owner.z32();
        format!("https://_pubky.{z32}/storage/{z32}{path}")
    }

    #[test]
    fn status_403_maps_to_signup_token_message() {
        let message = write_refusal(&server(StatusCode::FORBIDDEN)).expect("403 is mapped");
        assert!(
            message.contains(
                "this identity's signup token does not allow `/pub/sweepky/`; use a dedicated \
                 identity"
            ),
            "{message}"
        );
        assert_eq!(message, WRITE_FORBIDDEN);
        // None of the server's text, and no control character at all.
        assert!(!message.contains("pwned"), "{message}");
        assert!(!message.chars().any(char::is_control), "{message:?}");
    }

    #[test]
    fn status_507_maps_to_quota_message() {
        let message =
            write_refusal(&server(StatusCode::INSUFFICIENT_STORAGE)).expect("507 is mapped");
        assert!(message.contains("storage quota full"), "{message}");
        assert!(message.contains("use a dedicated identity"), "{message}");
        assert_eq!(message, QUOTA_FULL);
        assert!(!message.contains("pwned"), "{message}");
        assert!(!message.chars().any(char::is_control), "{message:?}");
    }

    #[test]
    fn other_statuses_and_transport_errors_are_not_mapped() {
        for status in [
            StatusCode::UNAUTHORIZED,
            StatusCode::NOT_FOUND,
            StatusCode::PAYLOAD_TOO_LARGE,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            assert_eq!(write_refusal(&server(status)), None, "{status}");
            assert_eq!(status_of(&server(status)), Some(status));
        }
        assert_eq!(write_refusal(&not_an_answer()), None);
        assert_eq!(status_of(&not_an_answer()), None);
    }

    #[test]
    fn error_messages_never_quote_the_server() {
        // A refused write aborts with its fixed message, any other answer
        // with its status alone, and an error that is not an answer with a
        // fixed sentence: never the server's text.
        let shown = |error: anyhow::Error| format!("{error:#}");
        assert_eq!(
            shown(write_error(&server(StatusCode::FORBIDDEN))),
            WRITE_FORBIDDEN
        );
        assert_eq!(
            shown(write_error(&server(StatusCode::INSUFFICIENT_STORAGE))),
            QUOTA_FULL
        );
        assert_eq!(
            shown(write_error(&server(StatusCode::INTERNAL_SERVER_ERROR))),
            "the homeserver answered 500 Internal Server Error"
        );
        for error in [server(StatusCode::NOT_FOUND), not_an_answer()] {
            let message = shown(request_error(&error));
            assert!(!message.contains("pwned"), "{message}");
            assert!(!message.chars().any(char::is_control), "{message:?}");
        }
    }

    /// The cap the body tests read with.
    const CAP: usize = 10;

    #[test]
    fn capped_body_refuses_over_limit() {
        // A Content-Length over the cap is refused before a byte is read,
        // whatever its size, so no buffer of that size is ever allocated.
        for claimed in [CAP as u64 + 1, u64::MAX] {
            assert_eq!(
                CappedBody::new(Some(claimed), CAP).err(),
                Some(BodyTooLarge { cap: CAP })
            );
        }

        // Up to the cap, with or without a Content-Length, is read whole.
        let mut exact = CappedBody::new(Some(CAP as u64), CAP).expect("at the cap");
        exact.push(b"01234").expect("fits");
        exact.push(b"56789").expect("fits");
        assert_eq!(exact.finish().as_slice(), b"0123456789");

        // Streamed chunks that add up past the cap are refused at the chunk
        // that would cross it, which is never copied in.
        let mut streamed = CappedBody::new(None, CAP).expect("no length given");
        for _ in 0..3 {
            streamed.push(b"abc").expect("9 bytes fit");
        }
        assert_eq!(streamed.push(b"abc"), Err(BodyTooLarge { cap: CAP }));
        assert_eq!(streamed.len(), 9);

        // A Content-Length that lies low does not lift the cap either.
        let mut liar = CappedBody::new(Some(2), CAP).expect("claims 2 bytes");
        liar.push(&[0; CAP]).expect("10 bytes fit");
        assert_eq!(liar.push(b"x"), Err(BodyTooLarge { cap: CAP }));
    }

    #[tokio::test]
    async fn read_capped_stops_asking_at_the_refusal() {
        // The read loop stops asking for chunks at the refusal: a server
        // that streams forever is read only until it crosses the cap.
        let mut chunks: VecDeque<&[u8]> = VecDeque::from(vec![&b"abcd"[..]; 100]);
        let result = read_capped(None, CAP, async || {
            Ok::<_, pubky::Error>(chunks.pop_front())
        })
        .await;
        assert!(result.is_err());
        assert_eq!(chunks.len(), 100 - 3, "read past the refusal");

        let mut chunks: VecDeque<&[u8]> = VecDeque::from(vec![&b"abcde"[..], &b"fghij"[..]]);
        let body = read_capped(Some(10), CAP, async || {
            Ok::<_, pubky::Error>(chunks.pop_front())
        })
        .await
        .expect("at the cap");
        assert_eq!(body.as_slice(), b"abcdefghij");
    }

    #[test]
    fn not_found_is_absent_or_empty() {
        // A record GET: 404 is "no such record", not an error.
        assert!(matches!(
            absent_on_not_found::<u8>(Err(server(StatusCode::NOT_FOUND))),
            Ok(None)
        ));
        assert!(matches!(absent_on_not_found(Ok(7_u8)), Ok(Some(7))));
        // Every other error passes through as it was.
        for status in [
            StatusCode::FORBIDDEN,
            StatusCode::GONE,
            StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            let error = absent_on_not_found::<u8>(Err(server(status))).expect_err("passes through");
            assert_eq!(status_of(&error), Some(status));
        }
        let error = absent_on_not_found::<u8>(Err(not_an_answer())).expect_err("passes through");
        assert_eq!(status_of(&error), None);

        // A listing: 404 is an empty directory, 2xx a page to read, anything
        // else an error that names the status only.
        assert_eq!(
            page_status(StatusCode::NOT_FOUND).ok(),
            Some(PageStatus::Empty)
        );
        assert_eq!(page_status(StatusCode::OK).ok(), Some(PageStatus::Read));
        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::FORBIDDEN,
            StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            let error = page_status(status).expect_err("an error");
            assert_eq!(
                format!("{error:#}"),
                format!("the homeserver answered {status}")
            );
        }
        // An empty listing has no entries, and nothing skipped.
        let owner = Keypair::random().public_key();
        let dir = keys_dir(&owner);
        let listing = ListingParser::new(&dir, ListLimits::DEFAULT).finish();
        assert!(listing.entries.is_empty());
        assert_eq!(listing.skipped, 0);
    }

    /// Limits small enough to cross in a test: 4 entries a page, 6 in all,
    /// in at most 3 pages.
    const SMALL: ListLimits = ListLimits {
        page_size: 4,
        max_entries: 6,
        max_pages: 3,
    };

    /// The listing line for `keys/<name>.json` of `owner`.
    fn key_line(owner: &PublicKey, name: &str) -> String {
        pubky_line(owner, &format!("{}{name}.json", paths::KEYS_DIR))
    }

    /// A listing page of one [`key_line`] per name.
    fn key_page(owner: &PublicKey, names: &[&str]) -> String {
        names
            .iter()
            .map(|name| key_line(owner, name))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn listing_parser_reads_both_line_forms() {
        let owner = Keypair::random().public_key();
        let dir = keys_dir(&owner);

        // Both line forms parse, blank lines (with or without `\r`) are
        // ignored, and a short page ends the listing.
        let body = format!(
            "\n{}\r\n\n   \n{}\n",
            pubky_line(&owner, "/pub/sweepky/keys/laptop-1.json"),
            https_line(&owner, "/pub/sweepky/keys/desk.json"),
        );
        let mut parser = ListingParser::new(&dir, SMALL);
        assert_eq!(
            parser.page(body.as_bytes()).ok(),
            Some(None),
            "a short page"
        );
        let listing = parser.finish();
        assert_eq!(listing.entries, [device("laptop-1"), device("desk")]);
        assert_eq!(listing.skipped, 0);
    }

    #[test]
    fn listing_parser_skips_and_counts_entries_it_does_not_keep() {
        let owner = Keypair::random().public_key();
        let stranger = Keypair::random().public_key();
        let dir = keys_dir(&owner);

        // Another owner's entries, entries outside the directory and names
        // that are not a Sweepky file are skipped and counted, not fatal.
        let body = [
            pubky_line(&stranger, "/pub/sweepky/keys/laptop-1.json"),
            pubky_line(&owner, "/pub/sweepky/bounties/0035G87EK4XFE.json"),
            pubky_line(&owner, "/pub/sweepky/keys/-not-a-device.json"),
            pubky_line(&owner, "/pub/sweepky/keys/sub/x.json"),
        ]
        .join("\n");
        let mut parser = ListingParser::new(&dir, SMALL);
        let next = parser
            .page(body.as_bytes())
            .expect("a full page")
            .expect("a full page has a next page");
        // The cursor is the last entry of this owner in this directory.
        assert_eq!(
            next.to_pubky_url(),
            pubky_line(&owner, "/pub/sweepky/keys/sub/x.json")
        );
        assert_eq!(parser.page(b"").ok(), Some(None), "an empty page ends it");
        let listing = parser.finish();
        assert!(listing.entries.is_empty());
        assert_eq!(listing.skipped, 4);
    }

    #[test]
    fn listing_parser_refuses_malformed_lines() {
        let owner = Keypair::random().public_key();
        let dir = keys_dir(&owner);

        // A line over the line cap is refused, before it is decoded.
        let long = key_line(&owner, &"a".repeat(MAX_LISTING_LINE_BYTES));
        assert_eq!(
            ListingParser::new(&dir, SMALL).page(long.as_bytes()).err(),
            Some(ListingError::LineTooLong)
        );

        // Invalid UTF-8 is refused, never decoded lossily.
        let mut not_utf8 = pubky_line(&owner, "/pub/sweepky/keys/caf").into_bytes();
        not_utf8.extend_from_slice(b"\xe9.json");
        assert_eq!(
            ListingParser::new(&dir, SMALL).page(&not_utf8).err(),
            Some(ListingError::NotUtf8)
        );

        // A line that is not a resource URL at all is refused too.
        for junk in [
            "hello",
            "pubky://not-a-key/pub/sweepky/keys/a.json",
            "ftp://x/y",
        ] {
            assert_eq!(
                ListingParser::new(&dir, SMALL).page(junk.as_bytes()).err(),
                Some(ListingError::NotAResource),
                "{junk}"
            );
        }
    }

    #[test]
    fn listing_parser_is_bounded_and_strict() {
        let owner = Keypair::random().public_key();
        let dir = keys_dir(&owner);

        // More entries than `max_entries`, across pages, is refused.
        let mut parser = ListingParser::new(&dir, SMALL);
        assert!(matches!(
            parser.page(key_page(&owner, &["a", "b", "c", "d"]).as_bytes()),
            Ok(Some(_))
        ));
        assert_eq!(
            parser
                .page(key_page(&owner, &["e", "f", "g", "h"]).as_bytes())
                .err(),
            Some(ListingError::TooManyEntries)
        );

        // More pages than `max_pages` is refused, even when each is small.
        let one_a_page = ListLimits {
            page_size: 1,
            max_entries: 100,
            max_pages: 3,
        };
        let mut parser = ListingParser::new(&dir, one_a_page);
        for name in ["a", "b", "c"] {
            assert!(
                matches!(parser.page(key_line(&owner, name).as_bytes()), Ok(Some(_))),
                "{name}"
            );
        }
        assert_eq!(parser.page(b"").err(), Some(ListingError::TooManyPages));

        // A page with more entries than were asked for breaks the protocol.
        let over = key_page(&owner, &["a", "b", "c", "d", "e"]);
        assert_eq!(
            ListingParser::new(&dir, one_a_page)
                .page(over.as_bytes())
                .err(),
            Some(ListingError::PageOverLimit)
        );

        // A page over the byte cap is refused whole, blank lines and all.
        let padded = "\n".repeat(SMALL.max_page_bytes() + 1);
        assert_eq!(
            ListingParser::new(&dir, SMALL)
                .page(padded.as_bytes())
                .err(),
            Some(ListingError::PageTooLarge)
        );
    }

    #[test]
    fn listing_parser_refuses_a_full_page_with_no_cursor() {
        let owner = Keypair::random().public_key();
        let stranger = Keypair::random().public_key();
        let dir = keys_dir(&owner);

        // A full page with no entry of this owner in this directory gives
        // no cursor to go on from.
        let foreign = key_page(&stranger, &["a", "b", "c", "d"]);
        assert_eq!(
            ListingParser::new(&dir, SMALL)
                .page(foreign.as_bytes())
                .err(),
            Some(ListingError::NoCursor)
        );
    }

    #[test]
    fn the_redirect_guard_accepts_only_the_url_that_was_sent() {
        let owner = Keypair::random().public_key();
        let listing = page_url(&keys_dir(&owner), 100, None).expect("a URL");
        let github =
            url::Url::parse("https://api.github.com/repos/org/name/pulls/42").expect("a URL");
        for sent in [listing, github] {
            // The URL that was sent, as reqwest reports it back: parsed
            // again from its text, and with https's own port written out.
            let reparsed = url::Url::parse(sent.as_str()).expect("a URL");
            let mut default_port = sent.clone();
            default_port.set_port(Some(443)).expect("a port");
            for received in [&sent, &reparsed, &default_port] {
                assert!(check_not_redirected(&sent, received).is_ok(), "{received}");
            }
            // Any other scheme, host, port, path or query: the answer came
            // from a request reqwest made after a redirect.
            let changed = |change: fn(&mut url::Url)| {
                let mut url = sent.clone();
                change(&mut url);
                url
            };
            for (what, received) in [
                (
                    "scheme",
                    changed(|url| url.set_scheme("http").expect("http")),
                ),
                (
                    "host",
                    changed(|url| url.set_host(Some("internal.example")).expect("a host")),
                ),
                (
                    "port",
                    changed(|url| url.set_port(Some(8443)).expect("a port")),
                ),
                ("path", changed(|url| url.set_path("/elsewhere"))),
                ("query", changed(|url| url.set_query(Some("limit=1")))),
            ] {
                let error = check_not_redirected(&sent, &received).expect_err(what);
                let message = format!("{error:#}");
                assert!(message.contains("redirect"), "{what}: {message}");
                // Neither URL is quoted.
                assert!(!message.contains("internal.example"), "{what}: {message}");
                assert!(!message.contains("/elsewhere"), "{what}: {message}");
                assert!(!message.contains(&owner.z32()), "{what}: {message}");
                assert!(!message.contains("api.github.com"), "{what}: {message}");
            }
        }
    }

    #[test]
    fn listing_url_carries_limit_and_cursor() {
        let owner = Keypair::random().public_key();
        let dir = keys_dir(&owner);
        let base = dir.to_transport_url().expect("a transport URL");
        let pairs = |url: &url::Url| -> Vec<(String, String)> {
            url.query_pairs()
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect()
        };

        // The first page: the directory's transport URL plus `limit` alone.
        let first = page_url(&dir, 50, None).expect("a URL");
        let mut without_query = first.clone();
        without_query.set_query(None);
        assert_eq!(without_query, base);
        assert_eq!(pairs(&first), [("limit".to_owned(), "50".to_owned())]);

        // Later pages add the last entry's `pubky://` URL as the cursor.
        let last = PubkyResource::new(owner.clone(), "/pub/sweepky/keys/laptop-1.json")
            .expect("a valid entry");
        let next = page_url(&dir, 50, Some(&last)).expect("a URL");
        let mut without_query = next.clone();
        without_query.set_query(None);
        assert_eq!(without_query, base);
        assert_eq!(
            pairs(&next),
            [
                ("limit".to_owned(), "50".to_owned()),
                (
                    "cursor".to_owned(),
                    pubky_line(&owner, "/pub/sweepky/keys/laptop-1.json")
                ),
            ]
        );
    }
}
