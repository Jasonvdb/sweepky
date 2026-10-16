//! The paths of Sweepky's files under `/pub/sweepky/`, as 01 lays them out:
//!
//! | Path | Builder | [`SweepkyPath`] variant |
//! |---|---|---|
//! | `/pub/sweepky/circle.json` | [`circle`] | [`Circle`](SweepkyPath::Circle) |
//! | `/pub/sweepky/keys/<deviceId>.json` | [`key`] | [`Key`](SweepkyPath::Key) |
//! | `/pub/sweepky/bounties/<id>.json` | [`bounty`] | [`Bounty`](SweepkyPath::Bounty) |
//! | `/pub/sweepky/bounties/<id>.discovered.json` | [`discovered`] | [`Discovered`](SweepkyPath::Discovered) |
//! | `/pub/sweepky/sweeps/<id>.json` | [`sweep_record`] | [`SweepRecord`](SweepkyPath::SweepRecord) |
//! | `/pub/sweepky/sweeps/<id>.age` | [`sweep_package`] | [`SweepPackage`](SweepkyPath::SweepPackage) |
//!
//! The listing prefixes [`BOUNTIES_DIR`], [`SWEEPS_DIR`] and [`KEYS_DIR`] end
//! in `/`, the form a homeserver lists a directory by.
//!
//! **Building.** Each builder takes a [`RecordId`] or a [`DeviceId`], never a
//! `&str`. Both types are checked when they are made, and neither can hold a
//! `/`, a `.` or anything outside a small ASCII set, so no builder can produce
//! a path outside `/pub/sweepky/` or with an extra segment. The compiler, not
//! a runtime check, keeps an unchecked string out.
//!
//! **Classifying.** [`SweepkyPath::parse`] turns a path back into what it
//! names, and gives `None` for anything else. The paths it sees come from
//! listings and events feeds that other people's homeservers serve, so it is
//! strict: the exact directory, the exact extension and a valid id, with no
//! extra segment, no `..`, no `//` and no trailing `/`. A path it accepts is
//! always exactly the one the builder would write, so `parse` inverts every
//! builder and nothing else.

use crate::ids::RecordId;
use crate::names::DeviceId;

/// The root of every Sweepky file: `/pub/sweepky/`.
pub const ROOT: &str = "/pub/sweepky/";
/// The directory of bounty records and their discovered-sweeps files, for
/// listing: `/pub/sweepky/bounties/`.
pub const BOUNTIES_DIR: &str = "/pub/sweepky/bounties/";
/// The directory of sweep records and sweep packages, for listing:
/// `/pub/sweepky/sweeps/`.
pub const SWEEPS_DIR: &str = "/pub/sweepky/sweeps/";
/// The directory of device keys, for listing: `/pub/sweepky/keys/`.
pub const KEYS_DIR: &str = "/pub/sweepky/keys/";

/// The roster's path. Written out rather than built from [`ROOT`], because
/// `concat!` only joins literals; the tests pin both strings.
const CIRCLE: &str = "/pub/sweepky/circle.json";

/// The extension of every JSON record.
const JSON: &str = ".json";
/// The extension of a bounty's discovered-sweeps file. It ends in [`JSON`]
/// too, so classifying must try it first.
const DISCOVERED: &str = ".discovered.json";
/// The extension of an encrypted sweep package.
const AGE: &str = ".age";

/// The roster's path: `/pub/sweepky/circle.json`.
///
/// A `&'static str`, a reference to text compiled into the program, because
/// this path never changes; call `.to_owned()` for a `String`.
pub fn circle() -> &'static str {
    CIRCLE
}

/// A device key's path: `/pub/sweepky/keys/<deviceId>.json`.
// `&DeviceId` borrows: a `DeviceId` owns a `String`, so taking it by value
// would make every caller give theirs up or clone it.
pub fn key(device: &DeviceId) -> String {
    format!("{KEYS_DIR}{device}{JSON}")
}

/// A bounty record's path: `/pub/sweepky/bounties/<id>.json`.
// `RecordId` is `Copy` (8 bytes), so it is taken by value: copying it costs
// no more than passing a reference, and the caller keeps theirs.
pub fn bounty(id: RecordId) -> String {
    format!("{BOUNTIES_DIR}{id}{JSON}")
}

/// An open bounty's discovered-sweeps file:
/// `/pub/sweepky/bounties/<id>.discovered.json`.
pub fn discovered(id: RecordId) -> String {
    format!("{BOUNTIES_DIR}{id}{DISCOVERED}")
}

/// A sweep record's path: `/pub/sweepky/sweeps/<id>.json`.
pub fn sweep_record(id: RecordId) -> String {
    format!("{SWEEPS_DIR}{id}{JSON}")
}

/// A sweep package's path, the encrypted findings beside the record:
/// `/pub/sweepky/sweeps/<id>.age`.
pub fn sweep_package(id: RecordId) -> String {
    format!("{SWEEPS_DIR}{id}{AGE}")
}

/// One file under `/pub/sweepky/`, classified by its path.
///
/// [`parse`](Self::parse) reads a path and [`to_path`](Self::to_path) writes
/// it back, and the two are exact inverses. Directories, the directories 01
/// reserves for later (`payouts/`, `tags/`, …) and every malformed path have
/// no variant, so they parse to `None`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SweepkyPath {
    /// `circle.json`, the roster.
    Circle,
    /// `keys/<deviceId>.json`, one CLI install's public key.
    Key(DeviceId),
    /// `bounties/<id>.json`, a bounty record.
    Bounty(RecordId),
    /// `bounties/<id>.discovered.json`, an open bounty's discovered sweeps.
    Discovered(RecordId),
    /// `sweeps/<id>.json`, a sweep record.
    SweepRecord(RecordId),
    /// `sweeps/<id>.age`, a sweep's encrypted package.
    SweepPackage(RecordId),
}

impl SweepkyPath {
    /// What `path` names, or `None` when it is not exactly one of the paths
    /// the builders write.
    ///
    /// `path` is the path alone, starting `/pub/sweepky/`, not a `pubky://`
    /// URL; [`PubkyUrl::sweepky_path`](crate::PubkyUrl::sweepky_path)
    /// classifies a URL.
    pub fn parse(path: &str) -> Option<Self> {
        if path == CIRCLE {
            return Some(Self::Circle);
        }
        // `strip_prefix` returns the rest of the string after the prefix, or
        // `None` when the string does not start with it. Like `strip_suffix`
        // and `contains` in the helpers below, it finds the offsets itself,
        // always on a character boundary, so no input can make it panic. A
        // path that starts with none of the three directories falls through
        // to `None`.
        //
        // `?` on an `Option` returns `None` from `parse` at once, the way it
        // returns an `Err` early from a function that gives a `Result`.
        if let Some(name) = path.strip_prefix(BOUNTIES_DIR) {
            return Self::parse_bounties_file(file_name(name)?);
        }
        if let Some(name) = path.strip_prefix(SWEEPS_DIR) {
            return Self::parse_sweeps_file(file_name(name)?);
        }
        if let Some(name) = path.strip_prefix(KEYS_DIR) {
            return Self::parse_keys_file(file_name(name)?);
        }
        None
    }

    /// The path this names, exactly as the matching builder writes it.
    pub fn to_path(&self) -> String {
        // `self` is a reference, so each pattern binds a reference into it:
        // `id` is a `&RecordId` and `device` a `&DeviceId`. `*id` copies the
        // `RecordId` out, which `Copy` allows; `device` is passed on as the
        // reference `key` asks for.
        match self {
            Self::Circle => circle().to_owned(),
            Self::Key(device) => key(device),
            Self::Bounty(id) => bounty(*id),
            Self::Discovered(id) => discovered(*id),
            Self::SweepRecord(id) => sweep_record(*id),
            Self::SweepPackage(id) => sweep_package(*id),
        }
    }

    /// What `name`, a file directly in `bounties/`, names.
    fn parse_bounties_file(name: &str) -> Option<Self> {
        // `.discovered.json` before `.json`: the longer extension ends in the
        // shorter, so trying `.json` first would leave `<id>.discovered`,
        // which only fails later as a bad id.
        //
        // `.parse()` runs `RecordId`'s check (length, alphabet, canonical
        // form), and `.ok()` turns its `Result` into an `Option`, dropping the
        // error: here a bad id just means "not one of ours". The compiler
        // infers which type to parse from the variant `map` wraps it in.
        if let Some(id) = name.strip_suffix(DISCOVERED) {
            return id.parse().ok().map(Self::Discovered);
        }
        name.strip_suffix(JSON)?.parse().ok().map(Self::Bounty)
    }

    /// What `name`, a file directly in `sweeps/`, names.
    fn parse_sweeps_file(name: &str) -> Option<Self> {
        if let Some(id) = name.strip_suffix(JSON) {
            return id.parse().ok().map(Self::SweepRecord);
        }
        name.strip_suffix(AGE)?.parse().ok().map(Self::SweepPackage)
    }

    /// What `name`, a file directly in `keys/`, names.
    fn parse_keys_file(name: &str) -> Option<Self> {
        // Here the variant holds a `DeviceId`, so its check runs.
        name.strip_suffix(JSON)?.parse().ok().map(Self::Key)
    }
}

/// `name` when it is a single file name, with no further `/`. That one check
/// refuses an extra segment, a `..` that climbs into a sibling directory, a
/// `//` and a trailing `/`, since each puts a `/` after the directory's own.
///
/// [`RecordId`] and [`DeviceId`] refuse a `/` as well, so this is a second
/// line: it keeps "one file directly in the directory" true here even if an
/// id type's alphabet ever grows.
fn file_name(name: &str) -> Option<&str> {
    // The `&str` that comes back borrows from the caller's `name`, so no text
    // is copied. The compiler infers the lifetime: one reference in, one out.
    if name.contains('/') { None } else { Some(name) }
}

#[cfg(test)]
mod tests {
    use pubky_timestamp::Timestamp;

    use super::{
        BOUNTIES_DIR, KEYS_DIR, ROOT, SWEEPS_DIR, SweepkyPath, bounty, circle, discovered, key,
        sweep_package, sweep_record,
    };
    use crate::ids::RecordId;
    use crate::names::DeviceId;

    /// A bounty id from fixtures/trust-labels.json.
    const ID: &str = "0035G87EK4XFE";

    fn id() -> RecordId {
        ID.parse().unwrap()
    }

    fn device(value: &str) -> DeviceId {
        value.parse().unwrap()
    }

    #[test]
    fn the_builders_return_exactly_01s_paths() {
        assert_eq!(circle(), "/pub/sweepky/circle.json");
        assert_eq!(key(&device("laptop-1")), "/pub/sweepky/keys/laptop-1.json");
        assert_eq!(bounty(id()), "/pub/sweepky/bounties/0035G87EK4XFE.json");
        assert_eq!(
            discovered(id()),
            "/pub/sweepky/bounties/0035G87EK4XFE.discovered.json"
        );
        assert_eq!(sweep_record(id()), "/pub/sweepky/sweeps/0035G87EK4XFE.json");
        assert_eq!(sweep_package(id()), "/pub/sweepky/sweeps/0035G87EK4XFE.age");
    }

    #[test]
    fn the_listing_prefixes_are_directories_with_a_trailing_slash() {
        assert_eq!(ROOT, "/pub/sweepky/");
        assert_eq!(BOUNTIES_DIR, "/pub/sweepky/bounties/");
        assert_eq!(SWEEPS_DIR, "/pub/sweepky/sweeps/");
        assert_eq!(KEYS_DIR, "/pub/sweepky/keys/");
    }

    /// One of every kind of path, with ids at both ends of their range.
    fn every_kind_of_path() -> Vec<SweepkyPath> {
        let ids = [0, 1, u64::MAX].map(|micros| RecordId::from_timestamp(Timestamp::from(micros)));
        let mut paths = vec![SweepkyPath::Circle];
        for id in ids.into_iter().chain([id()]) {
            paths.extend([
                SweepkyPath::Bounty(id),
                SweepkyPath::Discovered(id),
                SweepkyPath::SweepRecord(id),
                SweepkyPath::SweepPackage(id),
            ]);
        }
        // `web-<id>` is the browser key name 05 reserves.
        let longest = "d".repeat(DeviceId::MAX_LEN);
        for name in ["a", "9", "laptop-1", "web-0035G87EK4XFE", "A_b-c", &longest] {
            paths.push(SweepkyPath::Key(device(name)));
        }
        paths
    }

    #[test]
    fn parse_inverts_every_builder() {
        for path in every_kind_of_path() {
            let text = path.to_path();
            assert!(text.starts_with(ROOT), "{text}");
            assert_eq!(SweepkyPath::parse(&text).as_ref(), Some(&path), "{text}");
        }
    }

    #[test]
    fn to_path_is_the_builder_for_each_kind() {
        let laptop = device("laptop-1");
        assert_eq!(SweepkyPath::Circle.to_path(), circle());
        assert_eq!(SweepkyPath::Key(laptop.clone()).to_path(), key(&laptop));
        assert_eq!(SweepkyPath::Bounty(id()).to_path(), bounty(id()));
        assert_eq!(SweepkyPath::Discovered(id()).to_path(), discovered(id()));
        assert_eq!(SweepkyPath::SweepRecord(id()).to_path(), sweep_record(id()));
        assert_eq!(
            SweepkyPath::SweepPackage(id()).to_path(),
            sweep_package(id())
        );
    }

    #[test]
    fn anything_else_is_not_a_sweepky_path() {
        let too_long_device = format!(
            "/pub/sweepky/keys/{}.json",
            "d".repeat(DeviceId::MAX_LEN + 1)
        );
        let rejected = [
            // Not under /pub/sweepky/.
            "",
            "/",
            "/pub/other.app/x",
            "/pub/pubky.app/posts/0035G87EK4XFE",
            "/pub/sweepky",
            "/pub/sweepky/",
            "/pub/sweepkyx/circle.json",
            "/priv/sweepky/circle.json",
            "pub/sweepky/circle.json",
            "/PUB/SWEEPKY/circle.json",
            "/pub/sweepky/Circle.json",
            // A full URL is not a path.
            "pubky://8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo/pub/sweepky/circle.json",
            // Directories, and the reserved ones 01 leaves empty in v1.
            "/pub/sweepky/bounties",
            "/pub/sweepky/bounties/",
            "/pub/sweepky/sweeps/",
            "/pub/sweepky/keys/",
            "/pub/sweepky/payouts/0035G87EK4XFE.json",
            "/pub/sweepky/tags/0035G87EK4XFE.json",
            // Wrong extensions.
            "/pub/sweepky/circle.age",
            "/pub/sweepky/bounties/0035G87EK4XFE",
            "/pub/sweepky/bounties/0035G87EK4XFE.age",
            "/pub/sweepky/bounties/0035G87EK4XFE.JSON",
            "/pub/sweepky/bounties/0035G87EK4XFE.json.json",
            "/pub/sweepky/bounties/0035G87EK4XFE.discovered.age",
            "/pub/sweepky/bounties/0035G87EK4XFE.discovered",
            "/pub/sweepky/sweeps/0035G87EK4XFE",
            "/pub/sweepky/sweeps/0035G87EK4XFE.discovered.json",
            "/pub/sweepky/sweeps/0035G87EK4XFE.json.age",
            "/pub/sweepky/sweeps/0035G87EK4XFE.age.json",
            "/pub/sweepky/keys/laptop-1.age",
            "/pub/sweepky/keys/laptop-1",
            "/pub/sweepky/keys/laptop-1.discovered.json",
            // Lower-case, short, long and non-canonical record ids.
            "/pub/sweepky/bounties/0035g87ek4xfe.json",
            "/pub/sweepky/bounties/0035G87EK4XF.json",
            "/pub/sweepky/bounties/0035G87EK4XFEE.json",
            "/pub/sweepky/bounties/0035G87EK4XFF.json",
            "/pub/sweepky/bounties/.json",
            "/pub/sweepky/bounties/.discovered.json",
            "/pub/sweepky/bounties/0035g87ek4xfe.discovered.json",
            "/pub/sweepky/sweeps/0035g87ek4xfe.json",
            "/pub/sweepky/sweeps/0035G87EK4XF.age",
            "/pub/sweepky/sweeps/laptop-1.json",
            // Bad device ids.
            "/pub/sweepky/keys/.json",
            "/pub/sweepky/keys/-laptop.json",
            "/pub/sweepky/keys/_laptop.json",
            "/pub/sweepky/keys/lap top.json",
            "/pub/sweepky/keys/lap.top.json",
            "/pub/sweepky/keys/caf\u{e9}.json",
            &too_long_device,
            // Extra segments, traversal, `//` and a trailing `/`.
            "/pub/sweepky/bounties/x/0035G87EK4XFE.json",
            "/pub/sweepky/sweeps/0035G87EK4XFE/findings.json",
            "/pub/sweepky/bounties/0035G87EK4XFE.json/extra",
            "/pub/sweepky/bounties/../keys/a.json",
            "/pub/sweepky/keys/../bounties/0035G87EK4XFE.json",
            "/pub/sweepky/../sweepky/circle.json",
            "/pub/sweepky/./circle.json",
            "/pub/sweepky/bounties/./0035G87EK4XFE.json",
            "//pub/sweepky/circle.json",
            "/pub//sweepky/circle.json",
            "/pub/sweepky//circle.json",
            "/pub/sweepky//bounties/0035G87EK4XFE.json",
            "/pub/sweepky/bounties//0035G87EK4XFE.json",
            "/pub/sweepky/circle.json/",
            "/pub/sweepky/bounties/0035G87EK4XFE.json/",
            "/pub/sweepky/keys/laptop-1.json/",
            // Other separators, escapes, a query and a fragment.
            "/pub/sweepky/bounties\\0035G87EK4XFE.json",
            "/pub/sweepky/bounties%2F0035G87EK4XFE.json",
            "/pub/sweepky/circle.json?x=1",
            "/pub/sweepky/circle.json#x",
            // Whitespace, control and multi-byte characters.
            " /pub/sweepky/circle.json",
            "/pub/sweepky/circle.json\n",
            "/pub/sweepky/bounties/0035G87EK4XFE.json\0",
            "/pub/sweepky/bounties/0035G87EK4XF\u{c9}.json",
            "/pub/sweepky/\u{e9}",
            "/pub/sweepky/\u{e9}/circle.json",
        ];
        for path in rejected {
            assert_eq!(SweepkyPath::parse(path), None, "{path:?}");
        }
    }
}
