//! `pubky://` URLs: [`PubkyUrl`] for a file of any app, and [`BountyRef`]
//! and [`SweepRef`] for the two Sweepky records other records point at.
//!
//! A `pubky://` URL names a file by its owner's key and its path, as in
//! `pubky://<z32>/pub/sweepky/bounties/<id>.json`. The host is a [`Pubky`] in
//! either of its spellings, raw z-base32 or the SDK's `pubky<z32>`; records
//! always write the raw form (01's rule). So
//! `pubky://pubky<z32>/pub/sweepky/bounties/<id>.json` reads as the same
//! bounty and is written back as `pubky://<z32>/pub/sweepky/bounties/<id>.json`.
//!
//! These URLs arrive in records and events feeds that strangers' homeservers
//! serve. Parsing walks them with `strip_prefix` and `split_once` and checks
//! each part with a validated type, never by slicing at a byte offset, and
//! returns an error for anything malformed rather than panicking.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize, Serializer};

use crate::error::RecordError;
use crate::ids::RecordId;
use crate::names::reorders_text;
use crate::paths::SweepkyPath;
use crate::pubky::Pubky;

/// The one scheme accepted, in lower case only.
const SCHEME: &str = "pubky://";

/// A `pubky://` URL of any app's file: a user's key and a path.
///
/// What the homeserver's `/events/` feed and directory listings carry, for
/// every app, so this type takes any path that is well formed; to find out
/// whether it is one of Sweepky's files, call
/// [`sweepky_path`](Self::sweepky_path).
///
/// Parsing accepts `pubky://`, then a host that is a [`Pubky`] in either
/// form, then a path of at most [`MAX_PATH_LEN`](Self::MAX_PATH_LEN) bytes
/// that starts with `/` and has no `?` or `#` (so no query or fragment), no
/// whitespace, no control character and none of the characters that reorder
/// printed text (U+061C, U+200E, U+200F, U+202A to U+202E and U+2066 to
/// U+2069). Any other path is kept exactly as written: `..`, `//` and `%` are
/// allowed here, because another app's paths are not this crate's to judge.
/// Those limits are P1a's choice; 01 sets none.
///
/// [`Display`](fmt::Display) writes the host in raw form. Equality compares
/// the key by its bytes and the path as a string, so the two spellings of
/// one URL are equal.
// The fields are private, so the only ways to make a `PubkyUrl` are the
// parse below and `PubkyUrl::sweepky`, and a value always holds a checked
// path. `Pubky` is `Copy`, and `String` is not, so the struct as a whole is
// `Clone` only.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PubkyUrl {
    user: Pubky,
    path: String,
}

impl PubkyUrl {
    /// The longest path accepted, in bytes: 1024.
    pub const MAX_PATH_LEN: usize = 1024;

    /// The URL of one of Sweepky's own files. It cannot fail: a
    /// [`SweepkyPath`] always writes a valid path.
    pub fn sweepky(user: Pubky, path: &SweepkyPath) -> Self {
        Self {
            user,
            path: path.to_path(),
        }
    }

    /// The key of the user whose file this is.
    // Returns a copy, not a reference: `Pubky` is `Copy`, 32 bytes.
    pub const fn user(&self) -> Pubky {
        self.user
    }

    /// The path, starting with `/`, exactly as written.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Which Sweepky file this is, or `None` when the path is not exactly
    /// one of them. See [`SweepkyPath::parse`].
    pub fn sweepky_path(&self) -> Option<SweepkyPath> {
        SweepkyPath::parse(&self.path)
    }
}

impl FromStr for PubkyUrl {
    type Err = RecordError;

    fn from_str(value: &str) -> Result<Self, RecordError> {
        let invalid = |reason| RecordError::Invalid {
            field: "pubky url",
            reason,
        };
        // `ok_or` turns the `None` of a missing prefix into our error, and `?`
        // returns it. Comparing the scheme exactly refuses `https://`,
        // `PUBKY://`, `pubky:/` and a URL with no scheme at all.
        let rest = value
            .strip_prefix(SCHEME)
            .ok_or(invalid("does not start with pubky://"))?;
        // Split at the first `/`: the host before it, the path after it.
        // `split_once` drops the `/` itself, so `tail` is the path without its
        // leading `/`. A URL without one has no path.
        let (host, tail) = rest
            .split_once('/')
            .ok_or(invalid("has no path after the host"))?;
        // The `Pubky` parse checks length, alphabet and canonical form, which
        // refuses an empty host, a DNS name, a port (`:6286`), a user
        // (`user@`) and upper case alike. Its own error names the key rather
        // than the URL, so it is replaced with one that names the URL.
        let user: Pubky = host
            .parse()
            .map_err(|_| invalid("has a host that is not a pubky, raw or pubky-prefixed"))?;
        // `check_path` returns only the reason, and `map_err` hands it to
        // `invalid` to wrap. Checked before the path is copied, so a huge
        // input is never copied.
        check_path(tail).map_err(invalid)?;
        Ok(Self {
            user,
            path: format!("/{tail}"),
        })
    }
}

/// So a `String` converts with the same checks.
impl TryFrom<String> for PubkyUrl {
    type Error = RecordError;

    fn try_from(value: String) -> Result<Self, RecordError> {
        value.parse()
    }
}

/// Writes `pubky://<raw z32><path>`.
impl fmt::Display for PubkyUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{SCHEME}{}{}", self.user, self.path)
    }
}

/// Checks a [`PubkyUrl`]'s path, given as `tail`, the path without its
/// leading `/`. The error is the reason alone, for the caller to wrap.
fn check_path(tail: &str) -> Result<(), &'static str> {
    // `tail` plus the `/` must fit in `MAX_PATH_LEN`. `len()` is in bytes, the
    // unit of the limit, so a multi-byte character counts in full.
    if tail.len() >= PubkyUrl::MAX_PATH_LEN {
        return Err("has a path longer than 1024 bytes");
    }
    // An array of `char`s as a pattern matches any one of them.
    if tail.contains(['?', '#']) {
        return Err("has a query or fragment ('?' or '#')");
    }
    // `chars()` decodes whole characters, so a check never lands inside a
    // multi-byte sequence.
    if tail.chars().any(is_forbidden_in_path) {
        return Err(
            "has whitespace, a control character or a character that reorders text in its path",
        );
    }
    Ok(())
}

/// Whether `c` may not appear in a [`PubkyUrl`]'s path, apart from `?` and
/// `#`, which are checked on their own.
fn is_forbidden_in_path(c: char) -> bool {
    // `is_whitespace` is Unicode's White_Space, which includes the no-break
    // space and the line and paragraph separators as well as ASCII's.
    // `is_control` is the Cc category: C0, DEL and C1, so NUL, newline and
    // the escape that starts a terminal sequence. `reorders_text` is the
    // list of bidirectional controls `RepoPath` refuses too.
    c.is_whitespace() || c.is_control() || reorders_text(c)
}

/// A pointer to a bounty record, `pubky://<owner>/pub/sweepky/bounties/<id>.json`,
/// as a sweep record's and a manifest's `bounty` field holds it.
///
/// Serialized as that URL, with the owner in raw form. Parsing and
/// deserializing accept the owner in either form, and refuse any other URL,
/// including the bounty's own `.discovered.json` and a sweep's URL. Two refs
/// are equal when the owner's key bytes and the id are, so the spelling of
/// the key never matters.
// Any key and any id make a valid ref, so the fields can be public: there is
// nothing for a constructor to check. `Copy` is fine for 40 bytes of public
// data. `try_from = "String"` makes deserializing read a string and call
// `TryFrom<String>` below, rather than expect a JSON object with `owner`
// and `id` fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct BountyRef {
    /// The bounty's owner, whose homeserver holds the record.
    pub owner: Pubky,
    /// The bounty's id, the `<id>` in its file name.
    pub id: RecordId,
}

impl BountyRef {
    /// The bounty `url` points at, or `None` when its path is not exactly a
    /// bounty record's.
    pub fn from_url(url: &PubkyUrl) -> Option<Self> {
        // `?` returns `None` early when the path is no Sweepky file at all;
        // the `match` then keeps the one kind this type names.
        match url.sweepky_path()? {
            SweepkyPath::Bounty(id) => Some(Self {
                owner: url.user(),
                id,
            }),
            _ => None,
        }
    }

    /// The bounty record's URL, with the owner in raw form.
    pub fn url(&self) -> PubkyUrl {
        PubkyUrl::sweepky(self.owner, &SweepkyPath::Bounty(self.id))
    }
}

/// A pointer to a sweep record, `pubky://<sweeper>/pub/sweepky/sweeps/<id>.json`,
/// as a discovered-sweeps file lists it.
///
/// Serialized as that URL, with the sweeper in raw form. Parsing and
/// deserializing accept the sweeper in either form, and refuse any other URL,
/// including the sweep's `.age` package and a bounty's URL; the package's URL
/// comes from [`package_url`](Self::package_url). Equality works as for
/// [`BountyRef`].
// Public fields, `Copy` and `try_from` for the same reasons as `BountyRef`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(try_from = "String")]
pub struct SweepRef {
    /// The sweeper, whose homeserver holds the record and the package.
    pub sweeper: Pubky,
    /// The sweep's id, the `<id>` in its file names.
    pub id: RecordId,
}

impl SweepRef {
    /// The sweep `url` points at, or `None` when its path is not exactly a
    /// sweep record's. A package's `.age` URL gives `None` too.
    pub fn from_url(url: &PubkyUrl) -> Option<Self> {
        match url.sweepky_path()? {
            SweepkyPath::SweepRecord(id) => Some(Self {
                sweeper: url.user(),
                id,
            }),
            _ => None,
        }
    }

    /// The sweep record's URL, with the sweeper in raw form.
    pub fn url(&self) -> PubkyUrl {
        PubkyUrl::sweepky(self.sweeper, &SweepkyPath::SweepRecord(self.id))
    }

    /// The URL of the sweep's encrypted package, `sweeps/<id>.age`, beside
    /// the record.
    pub fn package_url(&self) -> PubkyUrl {
        PubkyUrl::sweepky(self.sweeper, &SweepkyPath::SweepPackage(self.id))
    }
}

/// Writes what [`BountyRef`] and [`SweepRef`] share: `FromStr`,
/// `TryFrom<String>`, `Display` and `Serialize`, all through the type's own
/// `from_url` and `url`. One macro keeps the two types' parsing identical, so
/// a fix to one cannot miss the other.
///
/// `$field` names the type in its errors, and `$reason` says what URL it
/// expects. Both are literals, so they stay `&'static str` and an error never
/// quotes the input.
macro_rules! record_ref {
    ($name:ident, $field:literal, $reason:literal) => {
        impl FromStr for $name {
            type Err = RecordError;

            /// Accepts the record's `pubky://` URL, with the key in either
            /// form.
            fn from_str(value: &str) -> Result<Self, RecordError> {
                // A malformed URL keeps `PubkyUrl`'s own, more specific error;
                // a well-formed URL of another file gets this type's.
                let url: PubkyUrl = value.parse()?;
                Self::from_url(&url).ok_or(RecordError::Invalid {
                    field: $field,
                    reason: $reason,
                })
            }
        }

        /// So `#[serde(try_from = "String")]` can call the same checks.
        impl TryFrom<String> for $name {
            type Error = RecordError;

            fn try_from(value: String) -> Result<Self, RecordError> {
                value.parse()
            }
        }

        /// Writes the record's URL, with the key in raw form.
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.url(), f)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                // `collect_str` writes the `Display` output as a JSON string,
                // so the stored form and the printed form are one and the
                // same.
                serializer.collect_str(self)
            }
        }
    };
}

record_ref!(
    BountyRef,
    "bounty url",
    "is not a bounty record's URL, pubky://<owner>/pub/sweepky/bounties/<id>.json"
);
record_ref!(
    SweepRef,
    "sweep url",
    "is not a sweep record's URL, pubky://<sweeper>/pub/sweepky/sweeps/<id>.json"
);

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{BountyRef, PubkyUrl, SweepRef};
    use crate::error::RecordError;
    use crate::ids::RecordId;
    use crate::paths::SweepkyPath;
    use crate::pubky::Pubky;

    /// The local testnet homeserver's key (pubky-testnet 0.16.2).
    const TESTNET: &str = "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo";
    /// A bounty id from fixtures/trust-labels.json.
    const ID: &str = "0035G87EK4XFE";

    fn testnet() -> Pubky {
        TESTNET.parse().unwrap()
    }

    fn id() -> RecordId {
        ID.parse().unwrap()
    }

    fn json(text: &str) -> String {
        serde_json::to_string(text).unwrap()
    }

    fn bounty_url(host: &str) -> String {
        format!("pubky://{host}/pub/sweepky/bounties/{ID}.json")
    }

    fn sweep_url(host: &str) -> String {
        format!("pubky://{host}/pub/sweepky/sweeps/{ID}.json")
    }

    #[test]
    fn a_bounty_url_in_either_pubky_form_is_one_bounty_ref() {
        let raw = bounty_url(TESTNET);
        let prefixed = bounty_url(&format!("pubky{TESTNET}"));
        let from_raw: BountyRef = raw.parse().unwrap();
        let from_prefixed: BountyRef = prefixed.parse().unwrap();

        assert_eq!(from_raw, from_prefixed);
        assert_eq!(
            from_raw,
            BountyRef {
                owner: testnet(),
                id: id()
            }
        );
        // Equal values hash alike, so the two spellings are one set entry.
        assert_eq!(HashSet::from([from_raw, from_prefixed]).len(), 1);
        assert_eq!(BountyRef::try_from(prefixed.clone()).unwrap(), from_raw);

        for bounty in [from_raw, from_prefixed] {
            // Written back in the raw form, whichever form was read.
            assert_eq!(bounty.to_string(), raw);
            assert_eq!(serde_json::to_string(&bounty).unwrap(), json(&raw));
            let url = bounty.url();
            assert_eq!(url.to_string(), raw);
            assert_eq!(BountyRef::from_url(&url), Some(bounty));
        }
        for text in [&raw, &prefixed] {
            assert_eq!(
                serde_json::from_str::<BountyRef>(&json(text)).unwrap(),
                from_raw
            );
        }
    }

    #[test]
    fn a_sweep_url_in_either_pubky_form_is_one_sweep_ref() {
        let raw = sweep_url(TESTNET);
        let prefixed = sweep_url(&format!("pubky{TESTNET}"));
        let from_raw: SweepRef = raw.parse().unwrap();
        let from_prefixed: SweepRef = prefixed.parse().unwrap();

        assert_eq!(from_raw, from_prefixed);
        assert_eq!(
            from_raw,
            SweepRef {
                sweeper: testnet(),
                id: id()
            }
        );
        assert_eq!(HashSet::from([from_raw, from_prefixed]).len(), 1);
        assert_eq!(SweepRef::try_from(prefixed.clone()).unwrap(), from_raw);

        for sweep in [from_raw, from_prefixed] {
            assert_eq!(sweep.to_string(), raw);
            assert_eq!(serde_json::to_string(&sweep).unwrap(), json(&raw));
            let url = sweep.url();
            assert_eq!(url.to_string(), raw);
            assert_eq!(SweepRef::from_url(&url), Some(sweep));
        }
        for text in [&raw, &prefixed] {
            assert_eq!(
                serde_json::from_str::<SweepRef>(&json(text)).unwrap(),
                from_raw
            );
        }
    }

    #[test]
    fn a_sweep_ref_names_its_package_too() {
        let sweep = SweepRef {
            sweeper: testnet(),
            id: id(),
        };
        let package = sweep.package_url();
        assert_eq!(
            package.to_string(),
            format!("pubky://{TESTNET}/pub/sweepky/sweeps/{ID}.age")
        );
        assert_eq!(package.user(), testnet());
        assert_eq!(
            package.sweepky_path(),
            Some(SweepkyPath::SweepPackage(id()))
        );
        // The package is not a sweep record.
        assert_eq!(SweepRef::from_url(&package), None);
    }

    #[test]
    fn a_ref_of_one_kind_is_not_a_ref_of_the_other() {
        let bounty = bounty_url(TESTNET);
        let sweep = sweep_url(TESTNET);
        assert_ref_rejected::<SweepRef>(&bounty, "sweep url");
        assert_ref_rejected::<BountyRef>(&sweep, "bounty url");
        let parsed_bounty: PubkyUrl = bounty.parse().unwrap();
        let parsed_sweep: PubkyUrl = sweep.parse().unwrap();
        assert_eq!(SweepRef::from_url(&parsed_bounty), None);
        assert_eq!(BountyRef::from_url(&parsed_sweep), None);
    }

    #[test]
    fn other_files_under_sweepky_are_not_record_refs() {
        let not_refs = [
            format!("pubky://{TESTNET}/pub/sweepky/bounties/{ID}.discovered.json"),
            format!("pubky://{TESTNET}/pub/sweepky/sweeps/{ID}.age"),
            format!("pubky://{TESTNET}/pub/sweepky/circle.json"),
            format!("pubky://{TESTNET}/pub/sweepky/keys/laptop-1.json"),
            format!("pubky://{TESTNET}/pub/sweepky/bounties/../sweeps/{ID}.json"),
            format!("pubky://{TESTNET}/pub/other.app/bounties/{ID}.json"),
        ];
        for text in &not_refs {
            // Each is a well-formed URL, just not a bounty or a sweep record.
            let url: PubkyUrl = text.parse().unwrap();
            assert_eq!(BountyRef::from_url(&url), None, "{text}");
            assert_eq!(SweepRef::from_url(&url), None, "{text}");
            assert_ref_rejected::<BountyRef>(text, "bounty url");
            assert_ref_rejected::<SweepRef>(text, "sweep url");
        }
    }

    /// Asserts that parsing `text` as a `T`, from a `&str`, a `String` and a
    /// JSON string, fails with an `Invalid` error for `field`.
    fn assert_ref_rejected<T>(text: &str, field: &str)
    where
        T: std::str::FromStr<Err = RecordError>
            + TryFrom<String, Error = RecordError>
            + serde::de::DeserializeOwned
            + std::fmt::Debug,
    {
        match text.parse::<T>() {
            Err(RecordError::Invalid { field: found, .. }) => assert_eq!(found, field, "{text:?}"),
            other => panic!("{text:?} gave {other:?}"),
        }
        assert!(T::try_from(text.to_owned()).is_err(), "{text:?}");
        assert!(serde_json::from_str::<T>(&json(text)).is_err(), "{text:?}");
    }

    #[test]
    fn a_generic_url_holds_any_app_path() {
        // What the events feed carries for other apps.
        let raw = format!("pubky://{TESTNET}/pub/other.app/x");
        let url: PubkyUrl = raw.parse().unwrap();
        assert_eq!(url.user(), testnet());
        assert_eq!(url.path(), "/pub/other.app/x");
        assert_eq!(url.to_string(), raw);
        assert_eq!(url.sweepky_path(), None);

        let prefixed: PubkyUrl = format!("pubky://pubky{TESTNET}/pub/other.app/x")
            .parse()
            .unwrap();
        assert_eq!(prefixed, url);
        assert_eq!(prefixed.to_string(), raw);
        assert_eq!(PubkyUrl::try_from(raw.clone()).unwrap(), url);

        // Classification is strict even when the URL itself is fine.
        let traversal: PubkyUrl = format!("pubky://{TESTNET}/pub/sweepky/bounties/../keys/a.json")
            .parse()
            .unwrap();
        assert_eq!(traversal.sweepky_path(), None);

        for path in [
            "/",
            "/pub/other.app/caf\u{e9}",
            "/pub/other.app/a%20b",
            "/pub/other.app//x",
        ] {
            let text = format!("pubky://{TESTNET}{path}");
            let url: PubkyUrl = text.parse().unwrap();
            assert_eq!(url.path(), path);
            assert_eq!(url.to_string(), text);
        }
    }

    #[test]
    fn a_generic_url_classifies_sweepky_paths() {
        let url: PubkyUrl = bounty_url(TESTNET).parse().unwrap();
        assert_eq!(url.sweepky_path(), Some(SweepkyPath::Bounty(id())));
        let built = PubkyUrl::sweepky(testnet(), &SweepkyPath::Bounty(id()));
        assert_eq!(built, url);
        assert_eq!(built.path(), "/pub/sweepky/bounties/0035G87EK4XFE.json");
    }

    #[test]
    fn a_path_may_be_1024_bytes_and_no_longer() {
        let longest = format!("/{}", "x".repeat(PubkyUrl::MAX_PATH_LEN - 1));
        let url: PubkyUrl = format!("pubky://{TESTNET}{longest}").parse().unwrap();
        assert_eq!(url.path().len(), 1024);

        let too_long = format!("pubky://{TESTNET}/{}", "x".repeat(PubkyUrl::MAX_PATH_LEN));
        assert_url_rejected(&too_long);
        // Multi-byte characters count as bytes.
        let too_long = format!("pubky://{TESTNET}/{}", "\u{e9}".repeat(512));
        assert_url_rejected(&too_long);
    }

    /// Asserts that `text` is refused as a generic URL, a bounty ref and a
    /// sweep ref, with an `Invalid` error and no panic.
    fn assert_url_rejected(text: &str) {
        match text.parse::<PubkyUrl>() {
            Err(RecordError::Invalid {
                field: "pubky url", ..
            }) => {}
            other => panic!("{text:?} gave {other:?}"),
        }
        assert!(PubkyUrl::try_from(text.to_owned()).is_err(), "{text:?}");
        assert!(text.parse::<BountyRef>().is_err(), "{text:?}");
        assert!(text.parse::<SweepRef>().is_err(), "{text:?}");
        assert!(
            serde_json::from_str::<BountyRef>(&json(text)).is_err(),
            "{text:?}"
        );
        assert!(
            serde_json::from_str::<SweepRef>(&json(text)).is_err(),
            "{text:?}"
        );
    }

    #[test]
    fn malformed_urls_are_rejected_without_panicking() {
        let bounty_path = format!("/pub/sweepky/bounties/{ID}.json");
        let good = bounty_url(TESTNET);
        let malformed = [
            // Another scheme, or none.
            format!("https://{TESTNET}{bounty_path}"),
            format!("http://{TESTNET}{bounty_path}"),
            format!("{TESTNET}{bounty_path}"),
            format!("pubky{TESTNET}{bounty_path}"),
            format!("pubky:{TESTNET}{bounty_path}"),
            format!("pubky:/{TESTNET}{bounty_path}"),
            format!("PUBKY://{TESTNET}{bounty_path}"),
            format!("Pubky://{TESTNET}{bounty_path}"),
            bounty_path.clone(),
            String::new(),
            "pubky://".to_owned(),
            // No path.
            format!("pubky://{TESTNET}"),
            format!("pubky://{TESTNET}?x=1"),
            // A query or a fragment.
            format!("{good}?x=1"),
            format!("{good}?"),
            format!("{good}#x"),
            format!("{good}#"),
            format!("pubky://{TESTNET}/pub/sweepky/bounties?/{ID}.json"),
            // Whitespace.
            format!("{good} "),
            format!(" {good}"),
            format!("{good}\n"),
            format!("{good}\r\n"),
            format!("pubky://{TESTNET}/pub/sweepky/bounties/{ID} .json"),
            format!("pubky://{TESTNET}/pub/other.app/a\tb"),
            format!("pubky://{TESTNET}/pub/other.app/a\u{a0}b"),
            format!("pubky://{TESTNET}/pub/other.app/a\u{3000}b"),
            format!("pubky://{TESTNET}/pub/other.app/a\u{2028}b"),
            // Control characters, including a terminal escape and C1's NEL.
            format!("{good}\0"),
            format!("pubky://{TESTNET}/pub/other.app/a\u{7f}b"),
            format!("pubky://{TESTNET}/pub/other.app/\u{1b}[31mred"),
            format!("pubky://{TESTNET}/pub/other.app/a\u{85}b"),
            // Characters that reorder printed text.
            format!("pubky://{TESTNET}/pub/other.app/a\u{202e}b"),
            format!("pubky://{TESTNET}/pub/other.app/a\u{2066}b"),
            // Bad hosts.
            format!("pubky:///pub/sweepky/bounties/{ID}.json"),
            format!("pubky://example.com{bounty_path}"),
            format!("pubky://{}{bounty_path}", TESTNET.to_uppercase()),
            format!("pubky://{}{bounty_path}", &TESTNET[..51]),
            format!("pubky://{TESTNET}y{bounty_path}"),
            format!("pubky://{TESTNET}:6286{bounty_path}"),
            format!("pubky://user@{TESTNET}{bounty_path}"),
            format!("pubky://{TESTNET}.example.com{bounty_path}"),
            format!("pubky://pk:{TESTNET}{bounty_path}"),
            format!("pubky://pubkypubky{TESTNET}{bounty_path}"),
            format!("pubky://PUBKY{TESTNET}{bounty_path}"),
            format!("pubky://{}\u{e9}{bounty_path}", &TESTNET[..50]),
            format!("pubky://\u{e9}{bounty_path}"),
            format!("pubky:// {TESTNET}{bounty_path}"),
            format!("pubky://{TESTNET}\\pub\\sweepky\\circle.json"),
        ];
        for text in &malformed {
            assert_url_rejected(text);
        }
    }
}
