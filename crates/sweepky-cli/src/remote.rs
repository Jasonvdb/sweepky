//! Reading other people's records and directories, and what a refused write
//! means: the network helpers every command shares.
//!
//! - [`get_public`] reads one public file of any owner, and [`get_own`] one of
//!   the signed-in user's own; a 404 is `None`, "no such record".
//!   [`get_public_if_changed`] reads a record again only if it changed since
//!   the [`ETag`] its last answer gave (`If-None-Match`, so an unchanged one
//!   costs a 304), and [`get_package`] reads a sweep's `.age`.
//! - [`list_dir`] lists one directory of an owner, page by page, into the
//!   Sweepky files it holds; a 404 is an empty directory.
//!   [`list_dir_newest_first`] lists it newest first and stops at the newest
//!   record id already seen there ([`ListOrder`]).
//! - [`get_unredirected`], the one anonymous `GET` Sweepky sends itself:
//!   that of every function above but `get_own`, and each of GitHub's (in
//!   `targets::github`).
//! - [`write_refusal`] turns the two answers a homeserver gives a write it
//!   will not take, 403 and 507, into the message `login` aborts with, and
//!   [`request_error`] turns every other SDK error into a message.
//!   [`upload_error`] says what a failed upload of a sweep package means:
//!   413, 429 and 507 in `submit`'s own words, anything else as for a write.
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
//!   record is read with [`MAX_RECORD_BYTES`] and then parsed with that
//!   record's `from_json`, core's capped, version-first parse, which is the
//!   only record parser; a sweep package with [`MAX_CIPHERTEXT_BYTES`], the
//!   most core's `decrypt` accepts. The SDK's own
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
//!   listing past [`ListLimits`]' entry and page counts, in either order.
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
//!   through [`crate::display`]'s sanitiser before it is printed. An
//!   [`ETag`] is the server's text too: it is checked, kept and sent back,
//!   and never printed.

use std::fmt;

use anyhow::{Context as _, anyhow, bail};
// `pubky` re-exports `reqwest`'s `Method` and `StatusCode`, so this crate
// needs no `reqwest` dependency of its own. The response type the SDK hands
// back is `reqwest`'s and cannot be named here, which is why the read loop
// takes a closure rather than a response (see `read_capped`).
use pubky::errors::RequestError;
use pubky::{Method, Pubky, PubkyHttpClient, PubkyResource, PubkySession, PublicKey, StatusCode};
use serde::{Deserialize, Serialize};
use sweepky_core::paths::{self, SweepkyPath};
use sweepky_core::{MAX_CIPHERTEXT_BYTES, MAX_RECORD_BYTES, RecordId, Zeroizing};
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

/// What `submit` says when the homeserver answers its upload of a sweep
/// package with a 413: the package, which the padding has made at most 32
/// MiB, is more than this homeserver takes in one write.
pub(crate) const PACKAGE_TOO_LARGE: &str = "the homeserver refused the upload (HTTP 413): the \
     package is too large for this homeserver";

/// What `submit` says when the homeserver answers its upload with a 429:
/// it throttles this user's writes for now (06, "Production homeserver": a
/// throttled write gets a 429 with `Retry-After`).
pub(crate) const RATE_LIMITED: &str =
    "the homeserver refused the upload (HTTP 429): rate limited; try again later";

/// What `submit` says when the homeserver answers its upload with a 507:
/// this identity's storage has no room for the package.
pub(crate) const UPLOAD_QUOTA_FULL: &str = "the homeserver refused the upload (HTTP 507): storage quota full, so there is no room for \
     the package";

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

/// A failed upload of a sweep package as the message to stop with:
/// [`PACKAGE_TOO_LARGE`], [`RATE_LIMITED`] and [`UPLOAD_QUOTA_FULL`] for
/// 413, 429 and 507, and [`write_error`]'s for anything else. Fixed text
/// and the status, never the server's words. Which of these leave the
/// sweep to be submitted again is `submit`'s decision, made from
/// [`status_of`].
pub(crate) fn upload_error(error: &pubky::Error) -> anyhow::Error {
    let message = match status_of(error) {
        Some(StatusCode::PAYLOAD_TOO_LARGE) => PACKAGE_TOO_LARGE,
        Some(StatusCode::TOO_MANY_REQUESTS) => RATE_LIMITED,
        Some(StatusCode::INSUFFICIENT_STORAGE) => UPLOAD_QUOTA_FULL,
        _ => return write_error(error),
    };
    anyhow::Error::msg(message)
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
/// [`MAX_RECORD_BYTES`] as `cap`.
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
    async { fetch_public(pubky, public_url(owner, path)?, cap).await }
        .await
        .with_context(|| could_not_read(path, owner))
}

/// The transport URL of `path` of `owner`'s public storage, the URL the
/// SDK's public storage sends its `GET` to, made by the SDK's
/// `PubkyResource`, so no URL is put together from strings here.
fn public_url(owner: &PublicKey, path: &str) -> anyhow::Result<Url> {
    // `clone` because the resource keeps its own copy of the key; a
    // `PublicKey` holds no heap data, so the copy is cheap.
    let resource = PubkyResource::new(owner.clone(), path).map_err(|e| request_error(&e))?;
    resource.to_transport_url().map_err(|e| request_error(&e))
}

/// What a failed read of `path` of `owner` says first: the path and the
/// key the caller asked for, never a URL.
fn could_not_read(path: &str, owner: &PublicKey) -> String {
    format!("could not read {path} of {}", owner.z32())
}

/// The longest `ETag` kept, in bytes: 128. The 0.16.2 homeserver's is 46, a
/// quoted base64 of the file's 32-byte content hash
/// (`client_server/routes/tenants/read.rs`). A longer one counts as none,
/// so a server cannot make Sweepky keep or send back more than this.
pub(crate) const MAX_ETAG_BYTES: usize = 128;

/// A record's entity tag, as a homeserver's `ETag` header gave it, kept to
/// send back in `If-None-Match` so that an unchanged record costs a 304.
///
/// It is the server's text, so it is checked before it is kept (see
/// [`ETag::parse`]) and never printed: no `Display`, and a `Debug` that
/// gives its length alone. Two tags are compared exactly, as the homeserver
/// compares them; nothing about a tag is secret, so no constant-time
/// comparison is needed.
///
/// It is kept between runs in `pull`'s poll state, so it is `Serialize`,
/// written as its text, and `Deserialize`, read back through
/// [`ETag::parse`]'s check (`try_from = "String"` reads a string, then
/// calls the `TryFrom<String>` below), so a tag from that file is held to
/// the same rule as one from a server.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub(crate) struct ETag(String);

impl ETag {
    /// `value`, the bytes of an `ETag` header, as a tag, or `None` when it
    /// cannot be one Sweepky sends back: empty, over [`MAX_ETAG_BYTES`], or
    /// holding anything but visible ASCII (`!` to `~`: no space, no control
    /// character, nothing past 0x7E). `None` is as if the answer gave no
    /// tag, so the next read of the record is a plain `GET`.
    pub(crate) fn parse(value: &[u8]) -> Option<Self> {
        let usable = !value.is_empty()
            && value.len() <= MAX_ETAG_BYTES
            && value.iter().all(u8::is_ascii_graphic);
        if !usable {
            return None;
        }
        // Visible ASCII is valid UTF-8, so this cannot fail; `.ok()?` keeps
        // even that case from panicking.
        let text = std::str::from_utf8(value).ok()?;
        Some(Self(text.to_owned()))
    }

    /// The tag as it came, to send back in `If-None-Match`.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// So `#[serde(try_from = "String")]` can run [`ETag::parse`]. The error is
/// fixed text: it never quotes the tag.
impl TryFrom<String> for ETag {
    type Error = &'static str;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(text.as_bytes()).ok_or("is not an entity tag Sweepky sends back")
    }
}

impl fmt::Debug for ETag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ETag({} bytes)", self.0.len())
    }
}

/// What [`get_public_if_changed`] found.
pub(crate) enum Conditional {
    /// A 304: the record is unchanged since the tag that was sent. No body
    /// was read.
    NotModified,
    /// A 404: there is no such record, or no longer.
    Absent,
    /// A 2xx: the record as it is now, at most
    /// [`MAX_RECORD_BYTES`], and the tag to send next time, when the
    /// answer gave one [`ETag::parse`] accepts.
    // Outside the tests nothing reads the fields yet, so the compiler would
    // warn. `expect` (not `allow`) silences that only while it is true:
    // `pull`, the first reader, must remove it.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "pull, the first reader, comes in a later step")
    )]
    Changed {
        /// The record's bytes.
        body: Zeroizing<Vec<u8>>,
        /// Its tag now.
        etag: Option<ETag>,
    },
}

/// Reads `path` of `owner`'s public storage again, a record of at most
/// [`MAX_RECORD_BYTES`], unless it is unchanged since `etag`, the tag its
/// last answer gave. The tag goes out as `If-None-Match`, so an unchanged
/// record costs a 304 and no body: 01 ("Circle") re-fetches only records
/// that can still change, open bounties and `running` sweeps, this way.
///
/// Without a tag nothing is compared: no `If-None-Match` goes out, and a
/// 304 is refused like any status but 2xx and 404. As for [`get_public`],
/// `path` appears in the error message; the tag never does.
pub(crate) async fn get_public_if_changed(
    pubky: &Pubky,
    owner: &PublicKey,
    path: &str,
    etag: Option<&ETag>,
) -> anyhow::Result<Conditional> {
    async { fetch_if_changed(pubky, public_url(owner, path)?, etag).await }
        .await
        .with_context(|| could_not_read(path, owner))
}

/// The conditional `GET` of [`get_public_if_changed`], of `url`.
async fn fetch_if_changed(
    pubky: &Pubky,
    url: Url,
    etag: Option<&ETag>,
) -> anyhow::Result<Conditional> {
    // The one header, borrowing the tag's text, or none. `as_slice` makes a
    // slice of length 1 or 0 of the `Option` without allocating.
    let if_none_match = etag.map(|tag| ("if-none-match", tag.as_str()));
    // Two functions with the same signature: the `if` makes both plain `fn`
    // pointers, one type, so either can be passed on.
    let read_status = if etag.is_some() {
        conditional_status
    } else {
        page_status
    };
    let answer = get_unredirected(
        pubky.client(),
        url,
        if_none_match.as_slice(),
        MAX_RECORD_BYTES,
        read_status,
    )
    .await?;
    Ok(match answer {
        Answer::Body { body, etag } => Conditional::Changed { body, etag },
        Answer::Empty => Conditional::Absent,
        Answer::NotModified => Conditional::NotModified,
    })
}

/// Reads the encrypted package of sweep `id` of `sweeper`,
/// `sweeps/<id>.age`, at most [`MAX_CIPHERTEXT_BYTES`], or `None` when
/// there is none (a 404).
pub(crate) async fn get_package(
    pubky: &Pubky,
    sweeper: &PublicKey,
    id: RecordId,
) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
    let path = paths::sweep_package(id);
    async { fetch_package(pubky, public_url(sweeper, &path)?).await }
        .await
        .with_context(|| could_not_read(&path, sweeper))
}

/// The `GET` of [`get_package`], of `url`: [`fetch_public`] under
/// [`MAX_CIPHERTEXT_BYTES`], the most core's `decrypt` accepts at all (the
/// longest header it reads, a 32 MiB package and age's framing of it), so
/// nothing larger is ever buffered.
async fn fetch_package(pubky: &Pubky, url: Url) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
    fetch_public(pubky, url, MAX_CIPHERTEXT_BYTES).await
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

/// Which way a directory is listed, and where a newest-first listing
/// stops.
///
/// A homeserver lists in its paths' byte order, and record ids are
/// timestamps that sort as they were made (01), so oldest first is the
/// order they were written in, and `reverse=true` turns it round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListOrder {
    /// Oldest first, the homeserver's own order, and the whole directory:
    /// [`list_dir`].
    OldestFirst,
    /// Newest first, stopping at the first file of a record whose id is at
    /// or below `seen`, the newest id already seen in this directory, or
    /// the whole directory when `seen` is `None`:
    /// [`list_dir_newest_first`].
    ///
    /// P2c's reading of 01's "paging by cursor until an id already seen".
    /// Every file named by a record id counts: `<id>.json`,
    /// `<id>.discovered.json` and `<id>.age` all stop the listing, so a
    /// file added later under an id already seen (a sweep's `.age`) is not
    /// listed again; the record's re-read finds it. A writer can name a
    /// record with an old id, which then stays unlisted: listings are
    /// hints, as the feed is, and bounded either way.
    NewestFirst {
        /// The newest record id already seen in the directory.
        seen: Option<RecordId>,
    },
}

impl ListOrder {
    /// Whether a listing in this order stops at `entry`, before keeping
    /// it: in a newest-first one, at a file of a record whose id is at or
    /// below the one already seen. A file with no record id (`circle.json`,
    /// a `keys/` record) never stops one.
    pub(crate) fn stops_at(self, entry: &SweepkyPath) -> bool {
        match self {
            Self::OldestFirst | Self::NewestFirst { seen: None } => false,
            Self::NewestFirst { seen: Some(seen) } => {
                record_id_of(entry).is_some_and(|id| id <= seen)
            }
        }
    }
}

/// The record id in `entry`'s name, if it has one.
fn record_id_of(entry: &SweepkyPath) -> Option<RecordId> {
    // No `_ =>` arm, so a new kind of file does not build until someone
    // decides whether its name carries an id.
    match entry {
        SweepkyPath::Bounty(id)
        | SweepkyPath::Discovered(id)
        | SweepkyPath::SweepRecord(id)
        | SweepkyPath::SweepPackage(id) => Some(*id),
        SweepkyPath::Circle | SweepkyPath::Key(_) => None,
    }
}

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
    order: ListOrder,
    listing: Listing,
    entries_read: usize,
    pages_read: usize,
}

impl<'a> ListingParser<'a> {
    /// A parser for an oldest-first listing of `directory`, whose path ends
    /// with `/`: the tests' shorthand for [`in_order`](Self::in_order).
    #[cfg(test)]
    pub(crate) fn new(directory: &'a PubkyResource, limits: ListLimits) -> Self {
        Self::in_order(directory, limits, ListOrder::OldestFirst)
    }

    /// A parser for a listing of `directory`, whose path ends with `/`, in
    /// `order`.
    pub(crate) fn in_order(
        directory: &'a PubkyResource,
        limits: ListLimits,
        order: ListOrder,
    ) -> Self {
        Self {
            directory,
            limits,
            order,
            listing: Listing::default(),
            entries_read: 0,
            pages_read: 0,
        }
    }

    /// Reads one page, and gives the entry to ask for the next page after
    /// (its cursor), or `None` when this page was the last: one with fewer
    /// entries than [`ListLimits::page_size`], or one where a newest-first
    /// listing reached a record already seen ([`ListOrder::stops_at`]).
    ///
    /// The rules, P2a's choice, and the stop P2c's:
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
    /// - A newest-first listing stops at the first Sweepky file inside the
    ///   directory that [`ListOrder::stops_at`]: neither it nor anything
    ///   after it is kept, and the page is the last however full it is. The
    ///   rest of the page is still read under every rule above, so a stop
    ///   on the first line does not let the page break the protocol.
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
        let mut stopped = false;
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
            // Past the stop, each line is still checked above, and nothing
            // more is kept.
            if stopped {
                continue;
            }
            if !self.is_inside(&entry) {
                self.skip();
                continue;
            }
            // A match guard (`if` after the pattern): this arm applies only
            // to a Sweepky file the order stops at.
            match SweepkyPath::parse(entry.path.as_str()) {
                Some(path) if self.order.stops_at(&path) => stopped = true,
                Some(path) => self.listing.entries.push(path),
                None => self.skip(),
            }
            last = Some(entry);
        }
        // `on_page == 0` matters only for a `page_size` of 0, which
        // `list_dir` never sends: an empty page still ends the listing.
        if stopped || on_page < page_size || on_page == 0 {
            return Ok(None);
        }
        // A full page: the next one starts after its last entry, so a full
        // page without one cannot go on.
        let cursor = last.ok_or(ListingError::NoCursor)?;
        Ok(Some(cursor))
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
    /// 304: the record is unchanged since the tag sent in `If-None-Match`,
    /// and the answer has no body. Only [`conditional_status`] gives it.
    NotModified,
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

/// What `status` means for a conditional `GET`, one that sent a tag in
/// `If-None-Match`: a 304 is "unchanged", and anything else is as for
/// [`page_status`].
fn conditional_status(status: StatusCode) -> anyhow::Result<PageStatus> {
    if status == StatusCode::NOT_MODIFIED {
        Ok(PageStatus::NotModified)
    } else {
        page_status(status)
    }
}

/// The URL of one listing page: the directory's transport URL, then
/// `limit=<page_size>`, `reverse=true` for a newest-first listing and,
/// after the first page, `cursor=` the last entry's `pubky://` URL.
fn page_url(
    directory: &PubkyResource,
    page_size: u16,
    order: ListOrder,
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
        if matches!(order, ListOrder::NewestFirst { .. }) {
            query.append_pair("reverse", "true");
        }
        if let Some(last) = cursor {
            query.append_pair("cursor", &last.to_pubky_url());
        }
    }
    Ok(url)
}

/// Lists `dir` (a path ending with `/`, such as
/// [`paths::KEYS_DIR`]) of `owner`'s public
/// storage, oldest first, page by page, within `limits`. A 404 is an empty
/// directory.
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
    list_in_order(pubky, owner, dir, limits, ListOrder::OldestFirst).await
}

/// Lists `dir` of `owner`'s public storage as [`list_dir`] does, but newest
/// first (`reverse=true`), and stops at `seen`, the newest record id
/// already seen there: the first file of a record at or below it ends the
/// listing, and the page after it is never asked for
/// ([`ListOrder::NewestFirst`]). `None` lists the whole directory, newest
/// first. The same limits hold, and a 404 is an empty directory.
pub(crate) async fn list_dir_newest_first(
    pubky: &Pubky,
    owner: &PublicKey,
    dir: &str,
    limits: ListLimits,
    seen: Option<RecordId>,
) -> anyhow::Result<Listing> {
    list_in_order(pubky, owner, dir, limits, ListOrder::NewestFirst { seen }).await
}

/// [`list_dir`] and [`list_dir_newest_first`]: the checks on `limits` and
/// `dir`, then [`read_listing`] with each page fetched by [`fetch_public`].
async fn list_in_order(
    pubky: &Pubky,
    owner: &PublicKey,
    dir: &str,
    limits: ListLimits,
    order: ListOrder,
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
        let cap = limits.max_page_bytes();
        read_listing(&directory, limits, order, async |url| {
            fetch_public(pubky, url, cap).await
        })
        .await
    }
    .await
    .with_context(|| format!("could not list {dir} of {}", owner.z32()))
}

/// Pages through the listing of `directory` in `order`: asks `fetch_page`
/// for each page's URL, which gives the body or `None` for a 404, and
/// parses it with a [`ListingParser`], until a 404, a short or empty page,
/// or a newest-first listing's stop.
///
/// The fetch is a closure, as `read_capped`'s chunks are, so the tests page
/// through fake pages with no network. `AsyncFnMut`: called once a page,
/// and free to change what it captured.
async fn read_listing(
    directory: &PubkyResource,
    limits: ListLimits,
    order: ListOrder,
    mut fetch_page: impl AsyncFnMut(Url) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>>,
) -> anyhow::Result<Listing> {
    let mut parser = ListingParser::in_order(directory, limits, order);
    let mut cursor: Option<PubkyResource> = None;
    loop {
        let url = page_url(directory, limits.page_size, order, cursor.as_ref())?;
        let Some(body) = fetch_page(url).await? else {
            break;
        };
        match parser.page(&body)? {
            Some(last) => cursor = Some(last),
            None => break,
        }
    }
    Ok(parser.finish())
}

/// An anonymous `GET` of `url` through [`get_unredirected`], its body read
/// with `cap`, or `None` for a 404: a record, a listing page or a package.
/// Any other non-2xx answer is an error naming the status, and its body is
/// never read.
async fn fetch_public(
    pubky: &Pubky,
    url: Url,
    cap: usize,
) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
    get_unredirected(pubky.client(), url, &[], cap, page_status)
        .await?
        .into_body()
}

/// What a request that ended at another URL than the one it was sent to is
/// refused with. Fixed text: neither URL, which a server chose.
const REDIRECTED: &str =
    "the server answered through a redirect, which Sweepky refuses: nothing in the answer was used";

/// What [`Answer::into_body`] refuses a 304 with: only a `GET` that sent a
/// tag expects one.
const UNASKED_NOT_MODIFIED: &str =
    "the server answered 304 Not Modified to a request that compared nothing";

/// What [`get_unredirected`] hands back, as its `read_status` decided.
pub(crate) enum Answer {
    /// [`PageStatus::Read`]: the body, at most the cap, and the answer's
    /// [`ETag`] when it gave one that [`ETag::parse`] accepts.
    Body {
        /// The bytes of the answer.
        body: Zeroizing<Vec<u8>>,
        /// Its tag, if usable.
        etag: Option<ETag>,
    },
    /// [`PageStatus::Empty`]: a 404, and nothing read.
    Empty,
    /// [`PageStatus::NotModified`]: a 304, and nothing read.
    NotModified,
}

impl Answer {
    /// The body, or `None` for a 404: what a `GET` that sent no tag wants.
    /// Such a `GET`'s `read_status` never gives [`PageStatus::NotModified`],
    /// but should one, the 304 is refused rather than read as "no record".
    pub(crate) fn into_body(self) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
        match self {
            // `..` leaves the tag out: a plain `GET` has no use for it.
            Self::Body { body, .. } => Ok(Some(body)),
            Self::Empty => Ok(None),
            Self::NotModified => bail!(UNASKED_NOT_MODIFIED),
        }
    }
}

/// Sends an anonymous `GET` of `url` through `client`, the SDK's HTTP
/// client, with `headers` added, and reads its body, at most `cap` bytes,
/// through [`read_capped`]: the one way Sweepky sends a request itself.
///
/// In order, so that nothing is used that should not be:
///
/// 1. The answer is refused when it came through a redirect
///    ([`check_not_redirected`]), whatever its status.
/// 2. `read_status` is given the status alone and decides: read the body
///    ([`PageStatus::Read`]), hand back [`Answer::Empty`] for a 404 or
///    [`Answer::NotModified`] for a 304 (each with nothing read), or fail.
///    An error answer's body is never read.
/// 3. The `ETag` header is checked ([`ETag::parse`]) and the body read
///    under the cap.
///
/// Every error is fixed text, the status, or [`request_error`]'s: never the
/// server's words, a URL or a header.
pub(crate) async fn get_unredirected(
    client: &PubkyHttpClient,
    url: Url,
    headers: &[(&str, &str)],
    cap: usize,
    read_status: impl FnOnce(StatusCode) -> anyhow::Result<PageStatus>,
) -> anyhow::Result<Answer> {
    // `request_async` is the SDK's own way to address a URL: it resolves a
    // Pubky host through pkarr and may rewrite the URL (an ICANN domain in
    // place of the key, or a legacy homeserver's path). The URL to compare
    // with is therefore the one in the request it builds, not `url`.
    let mut builder = client
        .request_async(Method::GET, url)
        .await
        .map_err(|e| request_error(&e))?;
    // `&(name, value)` takes each pair apart, copying out its two `&str`s
    // (a shared reference is `Copy`); `header` consumes the builder and
    // hands it back. The values may borrow from the caller, such as an
    // `If-None-Match` tag: reqwest copies each into a header of its own
    // here, so nothing has to outlive this call.
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
    match read_status(response.status())? {
        PageStatus::Read => {}
        PageStatus::Empty => return Ok(Answer::Empty),
        PageStatus::NotModified => return Ok(Answer::NotModified),
    }
    // `parse` copies the header's bytes out, so the borrow of the response
    // ends here, before the reads below borrow it mutably.
    let etag = response
        .headers()
        .get("etag")
        .and_then(|value| ETag::parse(value.as_bytes()));
    // `content_length()` is read first, while nothing borrows the
    // response; the closure then borrows it mutably for the reads.
    let body = read_capped(response.content_length(), cap, async || {
        response.chunk().await
    })
    .await?;
    Ok(Answer::Body { body, etag })
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
    use sweepky_core::paths::{self, SweepkyPath};
    use sweepky_core::{DeviceId, MAX_CIPHERTEXT_BYTES, MAX_RECORD_BYTES, Zeroizing};

    use super::{
        BodyTooLarge, CappedBody, Conditional, ETag, ListLimits, ListOrder, Listing, ListingError,
        ListingParser, MAX_ETAG_BYTES, MAX_LISTING_LINE_BYTES, PACKAGE_TOO_LARGE, PageStatus,
        QUOTA_FULL, RATE_LIMITED, REDIRECTED, UPLOAD_QUOTA_FULL, WRITE_FORBIDDEN,
        absent_on_not_found, check_not_redirected, conditional_status, fetch_if_changed,
        fetch_package, page_status, page_url, read_capped, read_listing, request_error, status_of,
        upload_error, write_error, write_refusal,
    };
    use crate::test_support::{Canned, LocalHttp, canned, offline_network, record_id};

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

    #[test]
    fn an_upload_s_413_429_and_507_say_what_they_mean_for_the_package() {
        let shown = |status| format!("{:#}", upload_error(&server(status)));
        assert_eq!(shown(StatusCode::PAYLOAD_TOO_LARGE), PACKAGE_TOO_LARGE);
        assert!(PACKAGE_TOO_LARGE.contains("the package is too large for this homeserver"));
        assert_eq!(shown(StatusCode::TOO_MANY_REQUESTS), RATE_LIMITED);
        assert!(RATE_LIMITED.contains("rate limited; try again later"));
        assert_eq!(shown(StatusCode::INSUFFICIENT_STORAGE), UPLOAD_QUOTA_FULL);
        assert!(UPLOAD_QUOTA_FULL.contains("storage quota full"));
        // Anything else as for any write: a 403's message, the status alone,
        // or a fixed sentence for an error that is not an answer.
        assert_eq!(shown(StatusCode::FORBIDDEN), WRITE_FORBIDDEN);
        assert_eq!(
            shown(StatusCode::BAD_GATEWAY),
            "the homeserver answered 502 Bad Gateway"
        );
        for message in [
            shown(StatusCode::PAYLOAD_TOO_LARGE),
            format!("{:#}", upload_error(&not_an_answer())),
        ] {
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
        let listing =
            page_url(&keys_dir(&owner), 100, ListOrder::OldestFirst, None).expect("a URL");
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

    /// The decoded query of `url`, pair by pair, in order.
    fn query_pairs(url: &url::Url) -> Vec<(String, String)> {
        url.query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect()
    }

    /// `(key, value)` as the owned pair [`query_pairs`] gives.
    fn pair(key: &str, value: &str) -> (String, String) {
        (key.to_owned(), value.to_owned())
    }

    #[test]
    fn listing_url_carries_limit_and_cursor() {
        let owner = Keypair::random().public_key();
        let dir = keys_dir(&owner);
        let base = dir.to_transport_url().expect("a transport URL");

        // The first page: the directory's transport URL plus `limit` alone.
        let first = page_url(&dir, 50, ListOrder::OldestFirst, None).expect("a URL");
        let mut without_query = first.clone();
        without_query.set_query(None);
        assert_eq!(without_query, base);
        assert_eq!(query_pairs(&first), [pair("limit", "50")]);

        // Later pages add the last entry's `pubky://` URL as the cursor.
        let last = PubkyResource::new(owner.clone(), "/pub/sweepky/keys/laptop-1.json")
            .expect("a valid entry");
        let next = page_url(&dir, 50, ListOrder::OldestFirst, Some(&last)).expect("a URL");
        let mut without_query = next.clone();
        without_query.set_query(None);
        assert_eq!(without_query, base);
        assert_eq!(
            query_pairs(&next),
            [
                pair("limit", "50"),
                pair(
                    "cursor",
                    &pubky_line(&owner, "/pub/sweepky/keys/laptop-1.json")
                ),
            ]
        );
    }

    #[test]
    fn a_newest_first_listing_url_adds_reverse_beside_limit_and_cursor() {
        let owner = Keypair::random().public_key();
        let dir = keys_dir(&owner);
        let base = dir.to_transport_url().expect("a transport URL");
        let newest_first = ListOrder::NewestFirst { seen: None };
        let cursor_line = pubky_line(&owner, "/pub/sweepky/keys/laptop-1.json");
        let last = PubkyResource::new(owner.clone(), "/pub/sweepky/keys/laptop-1.json")
            .expect("a valid entry");

        let first = page_url(&dir, 50, newest_first, None).expect("a URL");
        assert_eq!(
            query_pairs(&first),
            [pair("limit", "50"), pair("reverse", "true")]
        );
        let next = page_url(&dir, 50, newest_first, Some(&last)).expect("a URL");
        let mut without_query = next.clone();
        without_query.set_query(None);
        assert_eq!(without_query, base);
        assert_eq!(
            query_pairs(&next),
            [
                pair("limit", "50"),
                pair("reverse", "true"),
                pair("cursor", &cursor_line),
            ]
        );
        // The cursor goes out percent-encoded, so it cannot add a parameter
        // of its own.
        let query = next.query().expect("a query");
        assert!(
            query.starts_with("limit=50&reverse=true&cursor=pubky%3A%2F%2F"),
            "{query}"
        );
    }

    /// The listing line for `bounties/<id>.json`, where `<id>` is
    /// `record_id(n)`: a larger `n` is a newer bounty.
    fn bounty_line(owner: &PublicKey, n: u64) -> String {
        pubky_line(owner, &paths::bounty(record_id(n)))
    }

    /// The listing line for that bounty's `<id>.discovered.json`.
    fn discovered_line(owner: &PublicKey, n: u64) -> String {
        pubky_line(owner, &paths::discovered(record_id(n)))
    }

    fn bounties_dir(owner: &PublicKey) -> PubkyResource {
        PubkyResource::new(owner.clone(), paths::BOUNTIES_DIR).expect("a valid directory")
    }

    /// The listing [`read_listing`] makes of `pages`, handed out one per
    /// request, whatever URL it asks for, and then a 404; and the URLs it
    /// asked for.
    async fn list_fake_pages(
        dir: &PubkyResource,
        limits: ListLimits,
        order: ListOrder,
        pages: &[String],
    ) -> (anyhow::Result<Listing>, Vec<url::Url>) {
        let mut served = pages.iter();
        let mut asked = Vec::new();
        let listing = read_listing(dir, limits, order, async |url| {
            asked.push(url);
            Ok(served
                .next()
                .map(|page| Zeroizing::new(page.clone().into_bytes())))
        })
        .await;
        (listing, asked)
    }

    #[tokio::test]
    async fn a_newest_first_listing_stops_at_the_newest_id_already_seen() {
        let owner = Keypair::random().public_key();
        let dir = bounties_dir(&owner);
        let two_a_page = ListLimits {
            page_size: 2,
            max_entries: 100,
            max_pages: 10,
        };
        let bounty = |n| SweepkyPath::Bounty(record_id(n));
        // Newest first, two entries a page, as the homeserver sends them
        // with `reverse=true`: a bounty's record sorts after its
        // `.discovered.json`, so it comes first.
        let pages = [
            [bounty_line(&owner, 5), discovered_line(&owner, 5)].join("\n"),
            [bounty_line(&owner, 4), bounty_line(&owner, 3)].join("\n"),
            [bounty_line(&owner, 2), bounty_line(&owner, 1)].join("\n"),
        ];

        // Bounty 3 is the newest already seen: the listing stops at it, and
        // the third page is never asked for.
        let seen_3 = ListOrder::NewestFirst {
            seen: Some(record_id(3)),
        };
        let (listing, asked) = list_fake_pages(&dir, two_a_page, seen_3, &pages).await;
        let listing = listing.expect("listed");
        assert_eq!(
            listing.entries,
            [bounty(5), SweepkyPath::Discovered(record_id(5)), bounty(4)]
        );
        assert_eq!(listing.skipped, 0);
        assert_eq!(asked.len(), 2, "asked past the stop: {asked:?}");
        // Every page asks for newest first, and the second starts after the
        // last entry of the first.
        assert!(
            asked
                .iter()
                .all(|url| query_pairs(url).contains(&pair("reverse", "true"))),
            "{asked:?}"
        );
        assert!(
            query_pairs(&asked[1]).contains(&pair("cursor", &discovered_line(&owner, 5))),
            "{asked:?}"
        );

        // A stop on the first line keeps nothing and asks for nothing more.
        let seen_5 = ListOrder::NewestFirst {
            seen: Some(record_id(5)),
        };
        let (listing, asked) = list_fake_pages(&dir, two_a_page, seen_5, &pages).await;
        assert!(listing.expect("listed").entries.is_empty());
        assert_eq!(asked.len(), 1);

        // With nothing seen yet, the whole directory is read, newest first,
        // up to the 404 after the last page.
        let nothing_seen = ListOrder::NewestFirst { seen: None };
        let (listing, asked) = list_fake_pages(&dir, two_a_page, nothing_seen, &pages).await;
        assert_eq!(
            listing.expect("listed").entries,
            [
                bounty(5),
                SweepkyPath::Discovered(record_id(5)),
                bounty(4),
                bounty(3),
                bounty(2),
                bounty(1)
            ]
        );
        assert_eq!(asked.len(), 4);

        // A 404 on the first page is an empty directory, not an error.
        let (listing, asked) = list_fake_pages(&dir, two_a_page, seen_3, &[]).await;
        assert_eq!(listing.expect("an empty listing"), Listing::default());
        assert_eq!(asked.len(), 1);
    }

    #[test]
    fn a_newest_first_listing_keeps_the_listing_limits() {
        let owner = Keypair::random().public_key();
        let dir = bounties_dir(&owner);
        let seen = |n| ListOrder::NewestFirst {
            seen: Some(record_id(n)),
        };

        // More entries than were asked for is refused, even when the stop is
        // on the first line: the rest of the page is still read and checked.
        let over: Vec<String> = (1..=5).rev().map(|n| bounty_line(&owner, n)).collect();
        assert_eq!(
            ListingParser::in_order(&dir, SMALL, seen(5))
                .page(over.join("\n").as_bytes())
                .err(),
            Some(ListingError::PageOverLimit)
        );

        // So is a line over the line cap, after the stop or before it.
        let long = pubky_line(
            &owner,
            &format!(
                "{}{}.json",
                paths::BOUNTIES_DIR,
                "a".repeat(MAX_LISTING_LINE_BYTES)
            ),
        );
        for body in [
            [bounty_line(&owner, 3), long.clone()].join("\n"),
            [long.clone(), bounty_line(&owner, 3)].join("\n"),
        ] {
            assert_eq!(
                ListingParser::in_order(&dir, SMALL, seen(3))
                    .page(body.as_bytes())
                    .err(),
                Some(ListingError::LineTooLong)
            );
        }

        // And a listing past `max_pages`, while nothing it holds was seen.
        let one_a_page = ListLimits {
            page_size: 1,
            max_entries: 100,
            max_pages: 3,
        };
        let mut parser = ListingParser::in_order(&dir, one_a_page, seen(1));
        for n in [9, 8, 7] {
            assert!(
                matches!(parser.page(bounty_line(&owner, n).as_bytes()), Ok(Some(_))),
                "{n}"
            );
        }
        assert_eq!(
            parser.page(bounty_line(&owner, 6).as_bytes()).err(),
            Some(ListingError::TooManyPages)
        );
    }

    #[test]
    fn an_etag_is_kept_only_when_it_is_short_visible_ascii() {
        let longest = [b'a'; MAX_ETAG_BYTES];
        for usable in [&b"\"tag-1\""[..], b"W/\"x\"", &longest] {
            let tag = ETag::parse(usable).expect("a usable tag");
            assert_eq!(tag.as_str().as_bytes(), usable);
        }
        // Empty, over the cap, a space, a control character, an escape
        // sequence, DEL or anything past ASCII counts as no tag at all.
        let too_long = [b'a'; MAX_ETAG_BYTES + 1];
        for unusable in [
            &b""[..],
            &too_long,
            b"\"a b\"",
            b"\"a\tb\"",
            b"\"\x1b[31m\"",
            b"\"\x7f\"",
            b"\"caf\xc3\xa9\"",
        ] {
            assert!(ETag::parse(unusable).is_none(), "{unusable:?}");
        }
        // Its `Debug` gives the length alone, never the server's text.
        let tag = ETag::parse(b"\"pwned\"").expect("a usable tag");
        assert_eq!(format!("{tag:?}"), "ETag(7 bytes)");
    }

    #[test]
    fn a_conditional_get_reads_304_as_unchanged() {
        assert_eq!(
            conditional_status(StatusCode::NOT_MODIFIED).ok(),
            Some(PageStatus::NotModified)
        );
        assert_eq!(
            conditional_status(StatusCode::NOT_FOUND).ok(),
            Some(PageStatus::Empty)
        );
        assert_eq!(
            conditional_status(StatusCode::OK).ok(),
            Some(PageStatus::Read)
        );
        let error = conditional_status(StatusCode::INTERNAL_SERVER_ERROR).expect_err("an error");
        assert_eq!(
            format!("{error:#}"),
            "the homeserver answered 500 Internal Server Error"
        );
        // A GET that sent no tag still reads a 304 as an error.
        assert!(page_status(StatusCode::NOT_MODIFIED).is_err());
    }

    /// The tag the local server's records carry.
    const TAG: &str = "\"tag-1\"";

    /// A 200 whose `Content-Length` is one byte over a package's cap, with
    /// no body behind it.
    fn claims_over_the_package_cap() -> Canned {
        Canned::Bytes(
            format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                MAX_CIPHERTEXT_BYTES + 1
            )
            .into_bytes(),
        )
    }

    #[tokio::test]
    async fn a_conditional_get_maps_304_404_and_2xx() {
        let long_tag = "a".repeat(MAX_ETAG_BYTES + 1);
        let server = LocalHttp::start(vec![
            ("/same", canned("304 Not Modified", &[("etag", TAG)], b"")),
            ("/gone", canned("404 Not Found", &[], HOSTILE.as_bytes())),
            (
                "/new",
                canned("200 OK", &[("etag", "\"tag-2\"")], b"{\"a\":1}"),
            ),
            ("/no-tag", canned("200 OK", &[], b"{}")),
            (
                "/spaced-tag",
                canned("200 OK", &[("etag", "\"a b\"")], b"{}"),
            ),
            ("/long-tag", canned("200 OK", &[("etag", &long_tag)], b"{}")),
            (
                "/broken",
                canned(
                    "500 Internal Server Error",
                    &[("etag", TAG)],
                    HOSTILE.as_bytes(),
                ),
            ),
        ])
        .await;
        let network = offline_network();
        let pubky = network.pubky();
        let tag = ETag::parse(TAG.as_bytes()).expect("a usable tag");

        // A 304 to the tag sent in If-None-Match: unchanged, no body read.
        let same = fetch_if_changed(pubky, server.url("/same"), Some(&tag))
            .await
            .expect("an answer");
        assert!(matches!(same, Conditional::NotModified));
        let heads = server.heads();
        assert!(
            heads[0].contains(&format!("\r\nif-none-match: {TAG}\r\n")),
            "{heads:?}"
        );

        // A 404: there is no such record any more.
        let gone = fetch_if_changed(pubky, server.url("/gone"), Some(&tag))
            .await
            .expect("an answer");
        assert!(matches!(gone, Conditional::Absent));

        // A 2xx: the record as it is now, and the tag to send next time.
        let Conditional::Changed { body, etag } =
            fetch_if_changed(pubky, server.url("/new"), Some(&tag))
                .await
                .expect("an answer")
        else {
            panic!("a 200 is a change");
        };
        assert_eq!(body.as_slice(), b"{\"a\":1}");
        assert_eq!(etag.as_ref().map(ETag::as_str), Some("\"tag-2\""));

        // An ETag that is missing, not visible ASCII or over the cap counts
        // as none.
        for path in ["/no-tag", "/spaced-tag", "/long-tag"] {
            let Conditional::Changed { etag, .. } =
                fetch_if_changed(pubky, server.url(path), Some(&tag))
                    .await
                    .expect("an answer")
            else {
                panic!("{path}: a 200 is a change");
            };
            assert!(etag.is_none(), "{path}: {etag:?}");
        }

        // Without a tag nothing is compared: no If-None-Match goes out, and a
        // 304 is refused like any status but 2xx and 404.
        let error = fetch_if_changed(pubky, server.url("/same"), None)
            .await
            .err()
            .expect("a 304 to an unconditional GET is refused");
        assert_eq!(
            format!("{error:#}"),
            "the homeserver answered 304 Not Modified"
        );
        let heads = server.heads();
        let last = heads.last().expect("a request");
        assert!(!last.contains("if-none-match"), "{last}");

        // Any other answer is its status alone: never the tag sent or got,
        // and never the server's text.
        let error = fetch_if_changed(pubky, server.url("/broken"), Some(&tag))
            .await
            .err()
            .expect("a 500 is refused");
        let message = format!("{error:#}");
        assert_eq!(message, "the homeserver answered 500 Internal Server Error");
        assert!(!message.contains("tag-1"), "{message}");
        assert!(!message.contains("pwned"), "{message}");
    }

    #[tokio::test]
    async fn a_redirected_conditional_or_package_answer_is_refused_before_its_status_or_body() {
        let moved = |to: &str| canned("302 Found", &[("location", to)], b"");
        let server = LocalHttp::start(vec![
            ("/same", canned("304 Not Modified", &[("etag", TAG)], b"")),
            ("/gone", canned("404 Not Found", &[], b"")),
            (
                "/broken",
                canned("500 Internal Server Error", &[], HOSTILE.as_bytes()),
            ),
            ("/record", canned("200 OK", &[("etag", TAG)], b"{}")),
            ("/huge", claims_over_the_package_cap()),
            ("/to/same", moved("/same")),
            ("/to/gone", moved("/gone")),
            ("/to/broken", moved("/broken")),
            ("/to/record", moved("/record")),
            ("/to/huge", moved("/huge")),
        ])
        .await;
        let network = offline_network();
        let pubky = network.pubky();
        let tag = ETag::parse(TAG.as_bytes()).expect("a usable tag");

        // Whatever the answer at the end of the redirect says, it is refused
        // unread: a 304 is not "unchanged", a 404 not "absent", a 500 not its
        // status and a 200 not a body.
        for to in ["/to/same", "/to/gone", "/to/broken", "/to/record"] {
            let error = fetch_if_changed(pubky, server.url(to), Some(&tag))
                .await
                .err()
                .expect("a redirected answer is refused");
            assert_eq!(format!("{error:#}"), REDIRECTED, "{to}");
        }
        // A package's too: one over the cap is not even measured.
        for to in ["/to/huge", "/to/gone", "/to/broken"] {
            let error = fetch_package(pubky, server.url(to))
                .await
                .expect_err("a redirected answer is refused");
            assert_eq!(format!("{error:#}"), REDIRECTED, "{to}");
        }
        // reqwest did follow each redirect: the guard refused the answer, it
        // could not stop the request.
        let heads = server.heads();
        for target in ["/same", "/gone", "/broken", "/record", "/huge"] {
            let request_line = format!("GET {target} HTTP/1.1\r\n");
            assert!(
                heads.iter().any(|head| head.starts_with(&request_line)),
                "{target}: {heads:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_package_get_refuses_more_than_max_ciphertext_bytes_before_buffering() {
        let two_mib = vec![b'x'; 2 * 1024 * 1024];
        let server = LocalHttp::start(vec![
            ("/claims-too-much", claims_over_the_package_cap()),
            ("/endless", Canned::Endless),
            ("/two-mib", canned("200 OK", &[], &two_mib)),
        ])
        .await;
        let network = offline_network();
        let pubky = network.pubky();

        // A Content-Length over the cap is refused before a byte is read,
        // and a body with no length at the chunk that would cross the cap.
        for path in ["/claims-too-much", "/endless"] {
            let error = fetch_package(pubky, server.url(path))
                .await
                .expect_err("over the cap");
            assert_eq!(
                error.downcast_ref::<BodyTooLarge>(),
                Some(&BodyTooLarge {
                    cap: MAX_CIPHERTEXT_BYTES
                }),
                "{path}: {error:#}"
            );
        }

        // A package may be larger than a record, and is read whole.
        assert!(two_mib.len() > MAX_RECORD_BYTES);
        let package = fetch_package(pubky, server.url("/two-mib"))
            .await
            .expect("read")
            .expect("there");
        assert_eq!(package.as_slice(), two_mib.as_slice());

        // A 404 is no package, not an error.
        let missing = fetch_package(pubky, server.url("/missing"))
            .await
            .expect("a 404 is no error");
        assert!(missing.is_none());
    }
}
