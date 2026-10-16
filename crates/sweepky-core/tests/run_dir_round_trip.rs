//! The two synthetic run directories under `fixtures/`, taken through the
//! whole pipeline a sweep goes through and back: build the package from the
//! directory's files, pad and encrypt it ([`seal_package`]), decrypt, parse
//! and bind it ([`open_package`]), then split it back into files
//! ([`SweepPackage::into_files`]).
//!
//! - `fixtures/cloudflare/` is the Cloudflare-shaped run directory: P1a's
//!   `findings.json` in Cloudflare's format, plus `REPORT.md` and
//!   `coverage-ledger.json`. Sweeper B submits it.
//! - `fixtures/common/` is a common-format run directory: a hand-written
//!   `findings.json`, `REPORT.md`, `notes/triage.md`, and `capture.bin`, the
//!   one file that is not text. The stranger C submits it.
//!
//! Both are sealed to the owner A and to the sweeper, and each of the two
//! opens it. The pubkys are A, B and S3 (C here) from
//! `fixtures/trust-labels.json`; the age keys are generated at run time, so no
//! secret key is written in this file. `fixtures/README.md` describes what
//! the fixtures hold and why.
//!
//! **No run-time I/O.** Every fixture is compiled into the test binary with
//! `include_bytes!`, which reads the file while the test compiles and puts its
//! bytes in the binary as a `&'static [u8; N]`. So this test, unlike
//! `cctv_age.rs`, opens no file when it runs, and nothing here touches the
//! network.
//!
//! **Public API only.** A file under `tests/` is an integration test: Cargo
//! compiles it as a separate crate that links sweepky-core like any other
//! user, so it can call only what the crate exports. That it gets through the
//! pipeline shows the API is enough for `submit` (P2b) and `pull` (P2c).

use serde_json::{Value, json};
use sweepky_core::{
    AttachmentPath, BuiltPackage, DeviceIdentity, FINDINGS_FILE, Finding, Findings, FindingsSource,
    KnownLocationKind, Location, Manifest, PackageFiles, SkipReason, Sweep, SweepFile,
    SweepPackage, SweepRef, open_package, parse_audit_findings, seal_package, to_cloudflare,
};

/// One file of a fixture run directory: its path inside the directory, `/`
/// between components, as the CLI's walk reports it, and its bytes.
struct FixtureFile {
    path: &'static str,
    // `include_bytes!` gives a `&'static [u8; N]`, a reference to an array
    // whose length is part of its type. Storing it as a slice, `&[u8]`, lets
    // files of different lengths share this one field type; the array
    // coerces to the slice where each constant below is built.
    bytes: &'static [u8],
}

/// `fixtures/cloudflare/findings.json`, P1a's Cloudflare fixture, unchanged.
const CLOUDFLARE_FINDINGS: &[u8] = include_bytes!("../../../fixtures/cloudflare/findings.json");
/// `fixtures/common/findings.json`.
const COMMON_FINDINGS: &[u8] = include_bytes!("../../../fixtures/common/findings.json");
/// `fixtures/common/capture.bin`, the one fixture file that is not UTF-8.
const CAPTURE_BIN: &[u8] = include_bytes!("../../../fixtures/common/capture.bin");

/// Every file of `fixtures/cloudflare/`. Nothing lists the directory at run
/// time, so a file added there is part of this test only once it is added
/// here.
const CLOUDFLARE_RUN_DIR: &[FixtureFile] = &[
    FixtureFile {
        path: FINDINGS_FILE,
        bytes: CLOUDFLARE_FINDINGS,
    },
    FixtureFile {
        path: "REPORT.md",
        bytes: include_bytes!("../../../fixtures/cloudflare/REPORT.md"),
    },
    FixtureFile {
        path: "coverage-ledger.json",
        bytes: include_bytes!("../../../fixtures/cloudflare/coverage-ledger.json"),
    },
];

/// Every file of `fixtures/common/`, likewise.
const COMMON_RUN_DIR: &[FixtureFile] = &[
    FixtureFile {
        path: FINDINGS_FILE,
        bytes: COMMON_FINDINGS,
    },
    FixtureFile {
        path: "REPORT.md",
        bytes: include_bytes!("../../../fixtures/common/REPORT.md"),
    },
    FixtureFile {
        path: "notes/triage.md",
        bytes: include_bytes!("../../../fixtures/common/notes/triage.md"),
    },
    FixtureFile {
        path: "capture.bin",
        bytes: CAPTURE_BIN,
    },
];

/// A, the bounty's owner: the roster's admin in `fixtures/trust-labels.json`.
const OWNER: &str = "ybymzxgk1zd3a7dm3i15gcuq7ewqkbimft6r1n8oc9o6uay8mqfo";
/// A's bounty both sweeps cover: a synthetic id of 12 October 2026.
const BOUNTY_ID: &str = "0035V87C84EHJ";
/// The bounty's one target, which both sweeps cover.
const TARGET_ID: &str = "t1";
/// The commit [`TARGET_ID`] is pinned at: M, `main`'s tip in
/// `fixtures/target-repo.git`. Every location the fixtures name holds the
/// code its finding describes there.
const TARGET_REV: &str = "791991b2e79a7fe8371635dc377b9cc620032465";

/// One fixture sweep: who swept, under which sweep record, with which
/// playbook, and when.
struct SweepCase {
    sweeper: &'static str,
    sweep_id: &'static str,
    playbook: &'static str,
    started_at: &'static str,
    finished_at: &'static str,
}

/// B, a circle member, submits the Cloudflare-shaped run directory.
const CLOUDFLARE_SWEEP: SweepCase = SweepCase {
    sweeper: "btyoe954e99wb6sp7csdipt9ki8ca3iyus1tfi3171zqdixb5csy",
    sweep_id: "0035VDF0PFF72",
    playbook: "cloudflare/security-audit@c1c8a8c",
    started_at: "2026-10-13T10:00:00Z",
    finished_at: "2026-10-13T11:20:00Z",
};

/// C, a stranger (S3 in `fixtures/trust-labels.json`), submits the
/// common-format run directory.
const COMMON_SWEEP: SweepCase = SweepCase {
    sweeper: "qwujy4epafpmfei7bxn8fccfm1shzqp516sbenxi7qr6gua4n77o",
    sweep_id: "0035VE9TZVPAA",
    playbook: "careful-review",
    started_at: "2026-10-13T14:00:00Z",
    finished_at: "2026-10-13T14:45:00Z",
};

impl SweepCase {
    /// The manifest `submit` would write: this sweeper, A's bounty, and
    /// [`TARGET_ID`] at [`TARGET_REV`].
    fn manifest(&self) -> Manifest {
        // A manifest has no `from_json` (it is never a file by itself), so
        // the test reads one through its public `Deserialize`.
        serde_json::from_value(json!({
            "sweeper": self.sweeper,
            "bounty": bounty_url(),
            "targets": [TARGET_ID],
            // A `json!` key may be any expression that converts into a
            // `String`, so this key is the constant's value, "t1", not
            // the text `TARGET_ID` (as it would be in JavaScript).
            "targetShas": { TARGET_ID: TARGET_REV },
            "playbook": self.playbook,
            "startedAt": self.started_at,
            "finishedAt": self.finished_at,
        }))
        .unwrap()
    }

    /// The sweep record beside the package, after `submit` flipped it to
    /// `done`. It names no sweeper: its path does.
    fn record(&self) -> Sweep {
        let record = json!({
            "schemaVersion": 1,
            "bounty": bounty_url(),
            "targets": [TARGET_ID],
            "playbook": self.playbook,
            "status": "done",
            "startedAt": self.started_at,
            "finishedAt": self.finished_at,
        });
        Sweep::from_json(record.to_string().as_bytes()).unwrap()
    }

    /// The path the record and the package are fetched from: the sweeper's
    /// own storage.
    fn sweep_ref(&self) -> SweepRef {
        format!(
            "pubky://{}/pub/sweepky/sweeps/{}.json",
            self.sweeper, self.sweep_id
        )
        .parse()
        .unwrap()
    }
}

/// The URL of A's bounty record.
fn bounty_url() -> String {
    format!("pubky://{OWNER}/pub/sweepky/bounties/{BOUNTY_ID}.json")
}

/// The run directory's files as the CLI hands them to
/// [`SweepPackage::build`]. `to_vec` copies each compiled-in slice into a
/// `Vec` the `SweepFile` owns, the way a read gives the CLI a fresh buffer;
/// `SweepFile::new` then moves that `Vec` into a wiped buffer without a
/// second copy.
fn sweep_files(run_dir: &[FixtureFile]) -> Vec<SweepFile> {
    run_dir
        .iter()
        .map(|file| SweepFile::new(file.path, file.bytes.to_vec()))
        .collect()
}

/// Seals `package` to the owner and the sweeper, as `submit` does, opens it
/// with each identity against the sweep's record and path, and returns the
/// owner's copy. Both copies must equal the package that was sealed.
fn seal_and_open(package: &SweepPackage, sweep: &SweepCase) -> SweepPackage {
    // Fresh keys every run: `generate` uses the OS random number generator,
    // so no secret key is ever written into the source.
    let owner = DeviceIdentity::generate();
    let sweeper = DeviceIdentity::generate();
    let sealed = seal_package(package, &[owner.recipient(), sweeper.recipient()]).unwrap();

    let path = sweep.sweep_ref();
    let record = sweep.record();
    let by_owner = open_package(&sealed, &owner, &path, &record).unwrap();
    let by_sweeper = open_package(&sealed, &sweeper, &path, &record).unwrap();
    // `assert!` on `==` rather than `assert_eq!`: a failure then prints the
    // message only, not the package, even though its `Debug` is redacted.
    assert!(by_owner == *package, "the owner's copy differs");
    assert!(by_sweeper == *package, "the sweeper's copy differs");
    by_owner
}

/// What `build` left out, as `(path, reason)`, in input order.
fn skipped(built: &BuiltPackage) -> Vec<(&str, SkipReason)> {
    built
        .skipped
        .iter()
        .map(|file| (file.path.as_str(), file.reason))
        .collect()
}

/// The paths of `files`, in the map's order (byte order: upper case first).
fn paths(files: &PackageFiles) -> Vec<&str> {
    files.iter().map(|(path, _)| path.as_str()).collect()
}

fn attachment_path(value: &str) -> AttachmentPath {
    value.parse().unwrap()
}

/// Whether `bytes` are text: valid UTF-8, the test `SweepPackage::build`
/// applies.
// A function rather than `std::str::from_utf8` called on a fixture constant
// directly: rustc's `invalid_from_utf8` lint reads a compiled-in literal at
// compile time and warns that the call always fails, which CI's
// `-D warnings` would turn into an error. Through a parameter the check runs
// when the test does, where a changed fixture makes it fail.
fn is_text(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok()
}

/// Asserts that every text file of `run_dir` other than `findings.json`
/// came back from the split byte for byte.
fn assert_attachments_unchanged(files: &PackageFiles, run_dir: &[FixtureFile]) {
    for file in run_dir {
        if file.path == FINDINGS_FILE || !is_text(file.bytes) {
            continue;
        }
        assert!(
            files.get(&attachment_path(file.path)) == Some(file.bytes),
            "{} did not come back byte for byte",
            file.path
        );
    }
}

/// The bytes of the split `findings.json`.
fn split_findings(files: &PackageFiles) -> &[u8] {
    files.get(&attachment_path(FINDINGS_FILE)).unwrap()
}

/// Each sink of `finding` as `(file, line, scope)`. Only locations whose
/// `kind` is `sink` count: the owner's CLI groups by the sink.
fn sinks(finding: &Finding) -> Vec<(&str, Option<u64>, Option<&str>)> {
    finding
        .locations
        .iter()
        .filter(|location| is_sink(location))
        .map(|location| {
            (
                location.file.as_str(),
                location.line,
                location.scope.as_deref(),
            )
        })
        .collect()
}

/// Whether `location`'s `kind` is `sink`.
fn is_sink(location: &Location) -> bool {
    // `kind` is an open string, so `as_known` gives `None` for a kind this
    // build does not know, and `and_then` skips a location with no `kind`
    // at all.
    location.kind.as_ref().and_then(|kind| kind.as_known()) == Some(KnownLocationKind::Sink)
}

/// The one finding of `findings` with id `id`.
fn by_id<'a>(findings: &'a Findings, id: &str) -> &'a Finding {
    // Two references come in, so Rust cannot work out on its own which one
    // the result borrows from. `'a` says it is `findings`, not `id`, so the
    // caller may drop `id` while keeping the result.
    let mut matches = findings.findings.iter().filter(|finding| finding.id == id);
    let found = matches.next().unwrap();
    assert!(matches.next().is_none(), "two findings with id {id}");
    found
}

/// `fixtures/common/findings.json`, parsed.
fn common_findings() -> Findings {
    Findings::from_json(COMMON_FINDINGS).unwrap()
}

/// `fixtures/cloudflare/findings.json`, converted under the Cloudflare
/// sweep's playbook, as `build` converts it.
fn cloudflare_findings() -> Findings {
    let playbook = CLOUDFLARE_SWEEP.playbook.parse().unwrap();
    let (findings, _) = parse_audit_findings(CLOUDFLARE_FINDINGS, &playbook).unwrap();
    findings
}

#[test]
fn common_run_dir_round_trips_without_its_non_text_file() {
    let built = SweepPackage::build(COMMON_SWEEP.manifest(), sweep_files(COMMON_RUN_DIR)).unwrap();
    assert_eq!(built.findings_source, FindingsSource::Common);
    // The one file that is not text is reported, with its path as given and
    // the reason, and left out of the package.
    assert_eq!(skipped(&built), [("capture.bin", SkipReason::NotText)]);
    assert_eq!(built.package.attachments.len(), 2);

    let opened = seal_and_open(&built.package, &COMMON_SWEEP);
    let files = opened.into_files().unwrap();
    // `capture.bin` is never packaged, so it never comes back out.
    assert_eq!(
        paths(&files),
        ["REPORT.md", FINDINGS_FILE, "notes/triage.md"]
    );
    assert_attachments_unchanged(&files, COMMON_RUN_DIR);
    // The split findings are pretty-printed by serde_json, so they are
    // compared with the fixture as JSON values, not as bytes.
    let split: Value = serde_json::from_slice(split_findings(&files)).unwrap();
    let fixture: Value = serde_json::from_slice(COMMON_FINDINGS).unwrap();
    assert!(split == fixture, "findings.json is not the fixture's JSON");
}

#[test]
fn cloudflare_run_dir_round_trips() {
    let built =
        SweepPackage::build(CLOUDFLARE_SWEEP.manifest(), sweep_files(CLOUDFLARE_RUN_DIR)).unwrap();
    assert_eq!(built.findings_source, FindingsSource::Cloudflare);
    // Every file is text, so nothing is left out.
    assert!(built.skipped.is_empty(), "skipped {:?}", built.skipped);
    assert_eq!(built.package.attachments.len(), 2);

    let opened = seal_and_open(&built.package, &CLOUDFLARE_SWEEP);
    let files = opened.into_files().unwrap();
    assert_eq!(
        paths(&files),
        ["REPORT.md", "coverage-ledger.json", FINDINGS_FILE]
    );
    assert_attachments_unchanged(&files, CLOUDFLARE_RUN_DIR);

    // The split findings are the fixture as `submit` converts it...
    let split = Findings::from_json(split_findings(&files)).unwrap();
    assert!(split == cloudflare_findings(), "the split findings differ");
    // ...and every Cloudflare record survives inside them, value for value.
    let rebuilt = Value::Array(to_cloudflare(&split).unwrap());
    let fixture: Value = serde_json::from_slice(CLOUDFLARE_FINDINGS).unwrap();
    assert!(rebuilt == fixture, "to_cloudflare is not the fixture");
}

#[test]
fn fixtures_share_one_sink_under_different_ids() {
    // The shared location: one sink, two sweeps, two different ids.
    let expiry_sink = ("src/auth/session.rs", Some(88), Some("fn is_expired"));
    assert_eq!(
        sinks(by_id(&cloudflare_findings(), "auth-expiry-inclusive")),
        [expiry_sink]
    );
    assert_eq!(
        sinks(by_id(&common_findings(), "session-expiry-off-by-one")),
        [expiry_sink]
    );
}

#[test]
fn fixtures_share_one_id_at_unrelated_sinks() {
    // The shared id: one id, two sweeps, unrelated sinks.
    let id = "auth-token-compare-timing";
    assert_eq!(
        sinks(by_id(&common_findings(), id)),
        [("src/http.rs", Some(12), Some("fn header"))]
    );
    assert_eq!(
        sinks(by_id(&cloudflare_findings(), id)),
        [("src/auth/session.rs", Some(120), Some("fn validate"))]
    );
}

#[test]
fn capture_bin_is_not_text() {
    // The non-text file: not valid UTF-8, so `build` must skip it.
    assert!(!is_text(CAPTURE_BIN));
}
