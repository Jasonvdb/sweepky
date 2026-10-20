//! Helpers that the unit tests of several modules share: a private temp
//! directory, the [`Dirs`] under it and the file-mode checks around it, a
//! [`FileSnapshot`] that tells whether a file was written at all, a random
//! public key, a [`Context`] for a test ([`test_context`], on an
//! [`offline_network`] or a testnet's) with a [`SharedBuffer`] that keeps
//! what it writes to standard error, the [`GitEnv`] the tests run git with
//! and the inert fixture repository they run it against, a
//! [`FakeResolver`] in place of DNS and the [`checked_remote`] made
//! through it, a [`FakeHomeservers`] in place of pkarr's homeserver
//! records, a [`RecordingGit`] in place of git, a [`FakeGitHub`] in
//! place of GitHub's API, the fixture source over
//! that repository ([`fixture_targets`]) and the SHAs `fixtures/README.md`
//! records for it, a [`FakeKeyStore`] in place of a homeserver's `keys/`, a
//! [`FakeOwnStorage`] in place of the signed-in user's own storage, a
//! [`FakePublicRecords`] in place of everyone's public storage and its
//! listings, a [`FakeEventsFeed`] in place of a homeserver's events feed and
//! stream, which keeps every request, with [`feed_page`] and
//! [`events_page`], an honest feed's page as a homeserver writes it, and
//! [`stream_event`], one event of a
//! stream answer, a [`LocalHttp`] server on the loopback address for the
//! requests Sweepky sends itself, and the synthetic bounty, circle and
//! sweep records the tests
//! put there, with the snapshot `run` keeps of a sweep's fetch, the
//! passphrase the tests wrap secret files with and a byte search to check
//! a wrapped file shows none of its secret, a compile-time check that a
//! secret type implements none of the traits that would print or copy it,
//! [`stored_findings`], what `pull` stored of a sweep's findings, read
//! back, and for the Ring login a [`RingStandIn`] that approves in-process
//! as Pubky Ring would, the [`RingPage`] it reads the link off, and
//! [`loopback_get`], the raw, capped GET it fetches the page with.
//!
//! Compiled only for `cargo test` (`#[cfg(test)]` on its `mod` line in
//! `lib.rs`), so nothing here reaches the binary, and like any test code it
//! may panic.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, Permissions};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::{self, BufRead, ErrorKind, Write};
use std::net::IpAddr;
// `MetadataExt` adds `.mode()` and `.ino()` to `Metadata`; `PermissionsExt`
// adds `Permissions::from_mode`.
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pubky::errors::RequestError;
use pubky::{
    Capabilities, ClientId, GrantInfo, GrantManager, Keypair, PubkyHttpClient, PubkySession,
    PubkySigner, PublicKey, StatusCode,
};
use pubky_testnet::EphemeralTestnet;
use serde_json::{Value, json};
use sweepky_core::paths::{self, SweepkyPath};
use sweepky_core::{
    Bounty, BountyRef, DeviceId, EventCursor, Findings, GitSha, KnownTarget, MAX_PACKAGE_BYTES,
    Pubky, RecordId, RepoName, SweepRef, TargetId, Timestamp, Zeroizing,
};
use tempfile::TempDir;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::UnboundedReceiver;
use url::Url;

use crate::device::{KeyIds, KeyStore, PublicKeys};
use crate::events::EventsFeed;
use crate::git::{AllowedProtocols, GitCommand, GitFailed, RunGit, git_argv};
use crate::own_storage::OwnStorage;
use crate::pull::resolve::{ResolveHomeserver, Unreachable};
use crate::pull::store::{Placement, StoredCopy, read_stored_findings, stored_sweep_dir};
use crate::records::PublicRecords;
use crate::remote::{Conditional, ETag, ListOrder, Listing, ListingError};
use crate::sweep_state::SweepSnapshot;
use crate::targets::TargetSource;
use crate::targets::fixture::FixtureTargets;
use crate::targets::github::GitHubApi;
use crate::targets::host::{HttpsRemote, ResolveHost};
use crate::{Browser, Context, Dirs, GitEnv, Network, StderrWriter, StdinReader};

/// A fresh private directory to work in, created 0700 (`tempfile` passes
/// `permissions` to the `mkdir` itself; its default would follow the
/// umask, usually 0755). It deletes itself when the `TempDir` is dropped.
pub(crate) fn private_temp() -> TempDir {
    let temp = tempfile::Builder::new()
        .permissions(Permissions::from_mode(0o700))
        .tempdir()
        .expect("temp dir");
    assert_eq!(mode(temp.path()), 0o700);
    temp
}

/// The directories under `home`, as `SWEEPKY_HOME=<home>` gives them.
pub(crate) fn dirs_in(home: &TempDir) -> Dirs {
    Dirs::resolve(None, Some(home.path().as_os_str())).expect("absolute temp dir")
}

/// A fresh public key, made from a random keypair and converted to core's
/// `Pubky` (the same 32 bytes).
pub(crate) fn random_pubky() -> Pubky {
    Pubky::from_bytes(Keypair::random().public_key().to_bytes())
}

/// Where nothing listens: port 1 of the loopback address. Any request sent
/// there fails at once, without leaving the machine.
const NOWHERE: &str = "http://127.0.0.1:1/";

/// A network that reaches nothing, for a test that needs a [`Context`] but
/// no homeserver.
///
/// Its client has no DHT and one pkarr relay, at [`NOWHERE`] (a client with
/// neither cannot be built), so building it contacts nothing and any
/// request it made would fail. Its auth relay and default homeserver are
/// just as unreachable.
pub(crate) fn offline_network() -> Network {
    Network::injected(
        pubky::Pubky::with_client(offline_client()),
        format!("{NOWHERE}inbox"),
        Keypair::random().public_key(),
    )
}

/// The client of an [`offline_network`]: no DHT, and its one pkarr relay
/// at [`NOWHERE`].
fn offline_client() -> PubkyHttpClient {
    PubkyHttpClient::builder()
        .pkarr(|pkarr| {
            pkarr
                .no_dht()
                .relays(&[NOWHERE])
                .expect("a valid relay URL")
        })
        .build()
        .expect("an offline client")
}

/// A writer the test keeps a handle on: the context writes into it, the
/// test reads what was written. `Arc<Mutex<…>>` is shared ownership of one
/// buffer, which both sides lock to use.
#[derive(Clone, Default)]
pub(crate) struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl SharedBuffer {
    /// Everything written so far.
    pub(crate) fn text(&self) -> String {
        String::from_utf8(self.0.lock().expect("lock").clone()).expect("UTF-8")
    }
}

impl Write for SharedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("lock").write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A [`Context`] for a test, and the buffer that keeps what it writes to
/// standard error: `network`, the directories under `home` (as
/// `SWEEPKY_HOME=<home>` gives them), `home` itself as the working
/// directory, `stdin` as standard input, no passphrase, [`test_git_env`]
/// for git, and a fixture source that maps no repository, so no test
/// reaches a repository host by default.
///
/// The fields are public, so a test that needs another working directory
/// sets `ctx.cwd` afterwards, and one that needs targets sets
/// `ctx.targets` to [`fixture_targets`].
pub(crate) fn test_context(
    network: Network,
    home: &TempDir,
    stdin: impl BufRead + Send + 'static,
) -> (Context, SharedBuffer) {
    let stderr = SharedBuffer::default();
    let ctx = Context {
        network,
        dirs: dirs_in(home),
        cwd: home.path().to_path_buf(),
        stdin: StdinReader::new(stdin),
        // A clone of the handle: the context writes into the same buffer
        // the test reads.
        stderr: StderrWriter::new(stderr.clone()),
        passphrase: None,
        git_env: test_git_env(),
        targets: TargetSource::Fixture(FixtureTargets::new([])),
        // No test opens a real browser.
        browser: Browser::None,
    };
    (ctx, stderr)
}

/// What the tests let git see: this test process's `PATH`, so git is found
/// where the developer's or CI's shell finds it, and none of the proxy or
/// CA variables, so a test never depends on the machine's network setup.
/// Test code, so it may read the environment; the library never does.
pub(crate) fn test_git_env() -> GitEnv {
    GitEnv::capture(|name| {
        if name == "PATH" {
            std::env::var_os(name)
        } else {
            None
        }
    })
}

/// `fixtures/target-repo.git`, as an absolute path, after checking that its
/// files are inert: the check `tests/fixture_target_repo.rs` makes before
/// any of its git commands, made again here because a unit test cannot call
/// an integration test's code. Read without git: exactly the minimal
/// `config`, `HEAD` naming `main`, no `hooks/`, the four loose refs and one
/// pack, and no link or special file anywhere. A test that runs git against
/// the fixture gets its path from here, so the check always comes first.
pub(crate) fn inert_target_repo() -> PathBuf {
    // `env!` reads `CARGO_MANIFEST_DIR` when the test is compiled: this
    // crate's directory, whatever directory the test later runs in.
    let dir = fs::canonicalize(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/target-repo.git"),
    )
    .expect("the fixture repository");
    let read = |name: &str| fs::read_to_string(dir.join(name)).expect("a fixture file");
    assert_eq!(
        read("config"),
        "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = true\n",
        "the fixture's config must be exactly the minimal one"
    );
    assert_eq!(read("HEAD"), "ref: refs/heads/main\n");
    assert_eq!(
        fs::symlink_metadata(dir.join("hooks"))
            .map_err(|error| error.kind())
            .err(),
        Some(ErrorKind::NotFound),
        "the fixture must not have a hooks entry"
    );
    let (packs, others): (BTreeSet<String>, BTreeSet<String>) = regular_files_under(&dir)
        .into_iter()
        .partition(|path| path.starts_with("objects/pack/"));
    let expected: BTreeSet<String> = [
        "HEAD",
        "config",
        "refs/heads/main",
        "refs/heads/topic",
        "refs/pull/1/head",
        "refs/tags/v0.1.0",
    ]
    .map(String::from)
    .into();
    assert_eq!(others, expected, "only these files outside objects/pack/");
    let names: Vec<&str> = packs
        .iter()
        .filter_map(|path| path.strip_prefix("objects/pack/pack-"))
        .collect();
    // One `pack-<sha>.pack` and its `.idx`: two names, one SHA.
    let shas: BTreeSet<&str> = names
        .iter()
        .filter_map(|name| name.strip_suffix(".pack").or(name.strip_suffix(".idx")))
        .collect();
    assert_eq!(
        (packs.len(), names.len(), shas.len()),
        (2, 2, 1),
        "exactly one pack and its index: {packs:?}"
    );
    dir
}

/// The synthetic name the fixture source serves `fixtures/target-repo.git`
/// under in the tests.
const FIXTURE_REPO: &str = "example.invalid/sweepky/target-repo";

/// [`FIXTURE_REPO`], parsed.
pub(crate) fn fixture_repo() -> RepoName {
    FIXTURE_REPO.parse().expect("a repo name")
}

/// The fixture source with [`FIXTURE_REPO`] mapped to the inert fixture
/// repository ([`inert_target_repo`], so its check comes first).
pub(crate) fn fixture_targets() -> FixtureTargets {
    FixtureTargets::new([(fixture_repo(), inert_target_repo())])
}

/// The SHAs `fixtures/README.md` records in its `target-repo.git` section,
/// by name: the commits R, A, T1, B, F1, F2 and M, and the tag object
/// `v0.1.0`. It reads every table row of the form ``| name | `<sha>` |
/// …``, as `tests/fixture_target_repo.rs` does, so the README stays the
/// one place the SHAs are written; a unit test cannot call an integration
/// test's code, so the reader is written again here.
pub(crate) fn recorded_fixture_shas() -> BTreeMap<String, GitSha> {
    let readme =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/README.md"))
            .expect("fixtures/README.md");
    let section = readme
        .split("\n## ")
        .find(|section| section.starts_with("`target-repo.git`"))
        .expect("fixtures/README.md has a `target-repo.git` section");
    let mut shas = BTreeMap::new();
    for line in section.lines() {
        // "| R | `abc…` | none | …" splits on '|' into
        // ["", " R ", " `abc…` ", …]; a slice pattern takes the second
        // and third cells of a row that has them.
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        let &[_, name, sha, ..] = cells.as_slice() else {
            continue;
        };
        let Some(sha) = sha.strip_prefix('`').and_then(|sha| sha.strip_suffix('`')) else {
            continue;
        };
        // A SHA: the other backticked cells in the section are ref names.
        if let Ok(sha) = sha.parse::<GitSha>() {
            let previous = shas.insert(name.trim_matches('`').to_owned(), sha);
            assert!(previous.is_none(), "the README records {name} twice");
        }
    }
    shas
}

/// Every regular file under `dir`, `/`-separated and relative to it.
/// Panics on a symlink or anything else that is neither a file nor a
/// directory, because git would follow a link out of the fixture.
fn regular_files_under(dir: &Path) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    // A stack of directories still to list, relative to `dir`.
    let mut pending = vec![String::new()];
    while let Some(relative) = pending.pop() {
        for entry in fs::read_dir(dir.join(&relative)).expect("a listing") {
            let entry = entry.expect("an entry");
            let name = entry.file_name().into_string().expect("a UTF-8 name");
            let path = if relative.is_empty() {
                name
            } else {
                format!("{relative}/{name}")
            };
            // `DirEntry::file_type` does not follow a link.
            let kind = entry.file_type().expect("a file type");
            if kind.is_dir() {
                pending.push(path);
            } else {
                assert!(kind.is_file(), "{path} is not a plain file");
                found.insert(path);
            }
        }
    }
    found
}

/// The passphrase the tests wrap secret files with, through
/// `Passphrase::for_tests`. Synthetic, like every secret in this crate's
/// tests.
pub(crate) const TEST_PASSPHRASE: &str = "synthetic correct horse battery";

/// Whether `needle` appears anywhere in `haystack`: how a test checks that a
/// wrapped file holds none of its secret in the clear. `windows` takes the
/// window length from `needle`, so no length is counted by hand.
pub(crate) fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// What the [`FakeKeyStore`] answers a write it refuses with: the server's
/// own words, which a test checks never reach a message.
pub(crate) const FAKE_SERVER_TEXT: &str = "fake homeserver: tenant quota and path policy say no";

/// What a [`FakeKeyStore`] fails a read with, in the fixed words a failed
/// request gets from `remote`.
pub(crate) const FAKE_READ_FAILURE: &str = "the homeserver answered 500 Internal Server Error";

/// One call a [`FakeKeyStore`] was asked to make, with what it was asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KeyStoreCall {
    /// [`KeyStore::get_own_key`] of this id.
    GetOwnKey(DeviceId),
    /// [`KeyStore::put_key`] of this id, refused or not.
    PutKey(DeviceId),
    /// [`PublicKeys::list_key_ids`] of this owner.
    ListKeyIds(PublicKey),
    /// [`PublicKeys::get_key`] of this id. The owner is not logged: the
    /// fake holds one owner's records.
    GetKey(DeviceId),
}

/// A [`KeyStore`] (and so a [`PublicKeys`]) in memory, in place of a
/// homeserver: one owner's `keys/` records by device id, every call it was
/// asked to make, in order, and, if set, the status it refuses every write
/// with. Its listing holds every record's id, and every id it was told to
/// list without a record, in id order, and skips none.
///
/// The methods take `&self`, as the trait's do, yet the fake has to change
/// what it holds. A `Mutex` gives that "interior mutability": it hands out
/// `&mut` access to one caller at a time, checked at run time.
#[derive(Default)]
pub(crate) struct FakeKeyStore {
    records: Mutex<BTreeMap<DeviceId, Vec<u8>>>,
    /// Ids the listing names although no record is behind them.
    listed_only: Mutex<BTreeSet<DeviceId>>,
    /// Ids whose public read fails, as a request to a homeserver can.
    failing_reads: Mutex<BTreeSet<DeviceId>>,
    /// Whether the listing fails, as a request to a homeserver can.
    failing_listings: Mutex<bool>,
    calls: Mutex<Vec<KeyStoreCall>>,
    refuse_puts_with: Option<StatusCode>,
}

impl FakeKeyStore {
    /// A store that refuses every write with `status` and the text
    /// [`FAKE_SERVER_TEXT`], as the SDK reports a homeserver's non-2xx answer.
    pub(crate) fn refusing_puts(status: StatusCode) -> Self {
        Self {
            refuse_puts_with: Some(status),
            ..Self::default()
        }
    }

    /// Every call so far, in order.
    pub(crate) fn calls(&self) -> Vec<KeyStoreCall> {
        self.calls.lock().expect("lock").clone()
    }

    /// The record the store holds as `keys/<id>.json`, if any. Not a call:
    /// it is the test looking at the homeserver, so it is not logged.
    pub(crate) fn record(&self, id: &DeviceId) -> Option<Vec<u8>> {
        self.records.lock().expect("lock").get(id).cloned()
    }

    /// Puts `record` in place as `keys/<id>.json`, as someone writing to the
    /// homeserver behind this install's back would. Not logged either.
    pub(crate) fn set_record(&self, id: &DeviceId, record: Vec<u8>) {
        self.records
            .lock()
            .expect("lock")
            .insert(id.clone(), record);
    }

    /// Deletes `keys/<id>.json`, as someone could behind this install's
    /// back. Not logged either.
    pub(crate) fn remove_record(&self, id: &DeviceId) {
        self.records.lock().expect("lock").remove(id);
    }

    /// Lists `id` with no record behind it, as a record deleted between
    /// the listing and its read is. Not logged either.
    pub(crate) fn list_without_record(&self, id: &DeviceId) {
        self.listed_only.lock().expect("lock").insert(id.clone());
    }

    /// Fails every public read of `keys/<id>.json` with
    /// [`FAKE_READ_FAILURE`], as a request to a homeserver can fail. Not
    /// logged either.
    pub(crate) fn fail_reads_of(&self, id: &DeviceId) {
        self.failing_reads.lock().expect("lock").insert(id.clone());
    }

    /// Fails every listing of `keys/` with [`FAKE_READ_FAILURE`], as a
    /// request to a homeserver can fail. Not logged either.
    pub(crate) fn fail_listings(&self) {
        *self.failing_listings.lock().expect("lock") = true;
    }

    fn log(&self, call: KeyStoreCall) {
        self.calls.lock().expect("lock").push(call);
    }
}

impl PublicKeys for FakeKeyStore {
    async fn list_key_ids(&self, owner: &PublicKey) -> anyhow::Result<KeyIds> {
        self.log(KeyStoreCall::ListKeyIds(owner.clone()));
        if *self.failing_listings.lock().expect("lock") {
            anyhow::bail!(FAKE_READ_FAILURE);
        }
        let records = self.records.lock().expect("lock");
        let listed_only = self.listed_only.lock().expect("lock");
        // Collected into a set first, so the ids come out in order, once.
        let ids: BTreeSet<DeviceId> = records.keys().chain(listed_only.iter()).cloned().collect();
        Ok(KeyIds {
            ids: ids.into_iter().collect(),
            skipped: 0,
        })
    }

    async fn get_key(
        &self,
        _owner: &PublicKey,
        id: &DeviceId,
    ) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
        self.log(KeyStoreCall::GetKey(id.clone()));
        if self.failing_reads.lock().expect("lock").contains(id) {
            anyhow::bail!(FAKE_READ_FAILURE);
        }
        Ok(self.record(id).map(Zeroizing::new))
    }
}

impl KeyStore for FakeKeyStore {
    async fn get_own_key(&self, id: &DeviceId) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
        self.log(KeyStoreCall::GetOwnKey(id.clone()));
        Ok(self.record(id).map(Zeroizing::new))
    }

    async fn put_key(&self, id: &DeviceId, record: Vec<u8>) -> pubky::Result<()> {
        self.log(KeyStoreCall::PutKey(id.clone()));
        if let Some(status) = self.refuse_puts_with {
            return Err(pubky::Error::from(RequestError::Server {
                status,
                message: FAKE_SERVER_TEXT.to_owned(),
            }));
        }
        self.set_record(id, record);
        Ok(())
    }
}

/// How a [`FakeOwnStorage`] fails the write of one path.
#[derive(Clone)]
enum PutFailure {
    /// The homeserver answers with this status and its own text.
    Status {
        status: StatusCode,
        server_text: String,
    },
    /// The request never gets an answer: a transport error, such as a
    /// connection refused.
    Transport,
}

/// An [`OwnStorage`] in memory, in place of the signed-in user's own
/// storage: the files by path, every path it was asked to write, in order,
/// and the paths whose write it fails, each with how. It hands a file back
/// whole: the caps are the real storage's business. The `Mutex`es are
/// there for the same reason as in [`FakeKeyStore`]; the failures sit
/// behind one too, so a test can lift them between two runs of a command.
#[derive(Default)]
pub(crate) struct FakeOwnStorage {
    files: Mutex<BTreeMap<String, Vec<u8>>>,
    puts: Mutex<Vec<String>>,
    failures: Mutex<BTreeMap<String, PutFailure>>,
}

impl FakeOwnStorage {
    /// A storage that refuses a write of `path` with `status` and
    /// `server_text`, as the SDK reports a homeserver's non-2xx answer, and
    /// takes every other write.
    pub(crate) fn refusing(path: &str, status: StatusCode, server_text: &str) -> Self {
        let storage = Self::default();
        storage.refuse(path, status, server_text);
        storage
    }

    /// Refuses every write of `path` from now on with `status` and
    /// `server_text`.
    pub(crate) fn refuse(&self, path: &str, status: StatusCode, server_text: &str) {
        let failure = PutFailure::Status {
            status,
            server_text: server_text.to_owned(),
        };
        self.fail(path, failure);
    }

    /// Fails every write of `path` from now on with a transport error, as
    /// when the homeserver cannot be reached.
    pub(crate) fn fail_transport(&self, path: &str) {
        self.fail(path, PutFailure::Transport);
    }

    fn fail(&self, path: &str, failure: PutFailure) {
        self.failures
            .lock()
            .expect("lock")
            .insert(path.to_owned(), failure);
    }

    /// Takes every write from now on, as a homeserver that has recovered.
    pub(crate) fn stop_failing(&self) {
        self.failures.lock().expect("lock").clear();
    }

    /// Puts `bytes` in place at `path`, as an earlier command wrote them.
    /// Not logged as a write.
    pub(crate) fn insert(&self, path: &str, bytes: Vec<u8>) {
        self.files
            .lock()
            .expect("lock")
            .insert(path.to_owned(), bytes);
    }

    /// Every path asked to be written so far, refused or not, in order.
    pub(crate) fn puts(&self) -> Vec<String> {
        self.puts.lock().expect("lock").clone()
    }
}

/// A transport error as the SDK reports one: a request to [`NOWHERE`],
/// where nothing listens, so the connection is refused at once without
/// leaving the machine. reqwest's error type has no public constructor, so
/// a real failed request is the way to get one.
async fn transport_error() -> pubky::Error {
    let refused = offline_client()
        .request(pubky::Method::PUT, &NOWHERE)
        .send()
        .await
        .expect_err("nothing listens there");
    pubky::Error::from(RequestError::Transport(refused))
}

impl OwnStorage for FakeOwnStorage {
    async fn put(&self, path: &str, bytes: Vec<u8>) -> pubky::Result<()> {
        self.puts.lock().expect("lock").push(path.to_owned());
        // `cloned` copies the failure out, so the lock's guard, a temporary,
        // is released at the end of this statement: a guard must not be
        // held across the `.await` below.
        let failure = self.failures.lock().expect("lock").get(path).cloned();
        match failure {
            None => {}
            Some(PutFailure::Status {
                status,
                server_text,
            }) => {
                return Err(pubky::Error::from(RequestError::Server {
                    status,
                    message: server_text,
                }));
            }
            Some(PutFailure::Transport) => return Err(transport_error().await),
        }
        self.files
            .lock()
            .expect("lock")
            .insert(path.to_owned(), bytes);
        Ok(())
    }

    async fn get_own(&self, path: &str) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(self
            .files
            .lock()
            .expect("lock")
            .get(path)
            .map(|bytes| Zeroizing::new(bytes.clone())))
    }
}

/// A [`PublicRecords`] in memory, in place of everyone's homeservers: files
/// by owner and path, the directories whose listing it refuses, and every
/// request it was asked, in order: a read by its path, a listing by its
/// directory, which ends with `/`. It hands a file back whole, whatever its
/// size, and lists a directory whole, in path order or the reverse, newest
/// first, where it stops as the real listing does
/// ([`ListOrder::stops_at`]): the caps and the listing limits are the real
/// reader's business, and the record parsers check the cap again
/// themselves. A conditional read compares the tag sent with a hash of the
/// file's bytes, as a homeserver compares its content hash. The `Mutex` is
/// there for the same reason as in [`FakeKeyStore`].
#[derive(Default)]
pub(crate) struct FakePublicRecords {
    files: BTreeMap<(Pubky, String), Vec<u8>>,
    broken_listings: BTreeSet<(Pubky, String)>,
    asked: Mutex<Vec<(Pubky, String)>>,
    /// Every conditional read, with the tag it sent.
    conditional: Mutex<Vec<(Pubky, String, Option<ETag>)>>,
}

impl FakePublicRecords {
    /// The same fake, holding `bytes` at `path` of `owner`'s storage too.
    // It takes `self` by value and hands it back, so a test builds one in a
    // chain: `FakePublicRecords::default().with_file(..).with_file(..)`.
    pub(crate) fn with_file(mut self, owner: Pubky, path: &str, bytes: Vec<u8>) -> Self {
        self.files.insert((owner, path.to_owned()), bytes);
        self
    }

    /// The same fake, with nothing at `path` of `owner`'s storage any more,
    /// as after its owner deleted it.
    pub(crate) fn without_file(mut self, owner: Pubky, path: &str) -> Self {
        self.files.remove(&(owner, path.to_owned()));
        self
    }

    /// The owner, the path and the tag sent of every conditional read so
    /// far, in order. Each is in [`asked`](Self::asked) too.
    pub(crate) fn conditional_asked(&self) -> Vec<(Pubky, String, Option<ETag>)> {
        self.conditional.lock().expect("lock").clone()
    }

    /// The same fake, holding `record` as JSON at `path` of `owner`'s
    /// storage too.
    pub(crate) fn with_record(self, owner: Pubky, path: &str, record: &Value) -> Self {
        self.with_file(owner, path, json_bytes(record))
    }

    /// The same fake, refusing the listing of `dir` of `owner`'s storage as
    /// the real reader refuses one that breaks the protocol: a page with
    /// more entries than were asked for.
    pub(crate) fn with_broken_listing(mut self, owner: Pubky, dir: &str) -> Self {
        self.broken_listings.insert((owner, dir.to_owned()));
        self
    }

    /// The owner and path of every request so far, in order.
    pub(crate) fn asked(&self) -> Vec<(Pubky, String)> {
        self.asked.lock().expect("lock").clone()
    }

    /// The file at `path` of `owner`'s storage, if any, with the request
    /// kept in [`asked`](Self::asked).
    fn file(&self, owner: Pubky, path: &str) -> Option<&Vec<u8>> {
        let key = (owner, path.to_owned());
        let found = self.files.get(&key);
        self.asked.lock().expect("lock").push(key);
        found
    }

    /// The listing of `dir` of `owner`'s storage in `order`, with the
    /// request kept in [`asked`](Self::asked).
    fn listing(&self, owner: Pubky, dir: &str, order: ListOrder) -> anyhow::Result<Listing> {
        let key = (owner, dir.to_owned());
        let broken = self.broken_listings.contains(&key);
        self.asked.lock().expect("lock").push(key);
        if broken {
            return Err(anyhow::Error::new(ListingError::PageOverLimit)
                .context(format!("could not list {dir} of {owner}")));
        }
        // The Sweepky files in `dir`, as the real listing keeps them: the
        // map's order is the paths' byte order, a homeserver's order too.
        let in_dir = self
            .files
            .keys()
            .filter(|(file_owner, path)| *file_owner == owner && path.starts_with(dir))
            .filter_map(|(_, path)| SweepkyPath::parse(path));
        let entries = match order {
            ListOrder::OldestFirst => in_dir.collect(),
            ListOrder::NewestFirst { .. } => in_dir
                .rev()
                .take_while(|entry| !order.stops_at(entry))
                .collect(),
        };
        Ok(Listing {
            entries,
            skipped: 0,
        })
    }
}

/// The tag [`FakePublicRecords`] gives a file: a hash of its bytes, quoted
/// as a homeserver quotes its content hash, so it changes when they do.
/// std's `DefaultHasher` is enough for a fake; it is no content hash to
/// rely on.
fn content_tag(bytes: &[u8]) -> ETag {
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    ETag::parse(format!("\"{:016x}\"", hasher.finish()).as_bytes()).expect("a usable tag")
}

impl PublicRecords for FakePublicRecords {
    async fn get_record(
        &self,
        owner: Pubky,
        path: &str,
    ) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(self
            .file(owner, path)
            .map(|bytes| Zeroizing::new(bytes.clone())))
    }

    async fn list(&self, owner: Pubky, dir: &str) -> anyhow::Result<Listing> {
        self.listing(owner, dir, ListOrder::OldestFirst)
    }

    async fn list_newest_first(
        &self,
        owner: Pubky,
        dir: &str,
        seen: Option<RecordId>,
    ) -> anyhow::Result<Listing> {
        self.listing(owner, dir, ListOrder::NewestFirst { seen })
    }

    async fn get_record_if_changed(
        &self,
        owner: Pubky,
        path: &str,
        etag: Option<&ETag>,
    ) -> anyhow::Result<Conditional> {
        self.conditional
            .lock()
            .expect("lock")
            .push((owner, path.to_owned(), etag.cloned()));
        let Some(bytes) = self.file(owner, path) else {
            return Ok(Conditional::Absent);
        };
        let now = content_tag(bytes);
        if etag == Some(&now) {
            return Ok(Conditional::NotModified);
        }
        Ok(Conditional::Changed {
            body: Zeroizing::new(bytes.clone()),
            etag: Some(now),
        })
    }

    async fn get_package(&self, sweep: SweepRef) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(self
            .file(sweep.sweeper, &paths::sweep_package(sweep.id))
            .map(|bytes| Zeroizing::new(bytes.clone())))
    }
}

/// What a [`FakeEventsFeed`] answers a page request with: the body for the
/// cursor and the limit asked, or an error. `Box<dyn Fn ..>` is "any
/// function of this shape", chosen by each test, closures that capture
/// their own data included.
type FeedAnswer = Box<dyn Fn(EventCursor, u16) -> anyhow::Result<Vec<u8>>>;

/// What a [`FakeEventsFeed`] answers a stream request with: the body for
/// the homeserver, the owner and the path asked, or an error.
type StreamAnswer = Box<dyn Fn(Pubky, Pubky, &SweepkyPath) -> anyhow::Result<Vec<u8>>>;

/// One stream request a [`FakeEventsFeed`] was sent: the homeserver asked,
/// and the owner and the path of the file whose latest event it asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StreamRequest {
    pub(crate) homeserver: Pubky,
    pub(crate) owner: Pubky,
    pub(crate) path: SweepkyPath,
}

/// An [`EventsFeed`] in memory, in place of a homeserver's `/events/` and
/// `/events-stream`: each page is what its function answers for the cursor
/// and the limit asked, whatever the homeserver, and each stream answer
/// what its other function answers for the request. It keeps every page
/// request, with its homeserver, and every stream request, in order. The
/// parse and the checks are `EventsFeed`'s provided methods', so they run
/// on these bodies as on a homeserver's; the caps are the real reader's.
/// The `Mutex`es are there for the same reason as in [`FakeKeyStore`].
pub(crate) struct FakeEventsFeed {
    pages: FeedAnswer,
    stream: StreamAnswer,
    asked: Mutex<Vec<(Pubky, EventCursor, u16)>>,
    streams_asked: Mutex<Vec<StreamRequest>>,
}

impl FakeEventsFeed {
    /// A feed whose pages `answer` gives, and whose stream answer is empty.
    // `'static`: the boxed function may outlive this call, so whatever it
    // captures must be owned (`move`d in), not borrowed.
    pub(crate) fn answering(
        answer: impl Fn(EventCursor, u16) -> anyhow::Result<Vec<u8>> + 'static,
    ) -> Self {
        Self {
            pages: Box::new(answer),
            stream: Box::new(|_, _, _| Ok(Vec::new())),
            asked: Mutex::new(Vec::new()),
            streams_asked: Mutex::new(Vec::new()),
        }
    }

    /// An honest feed of public events with the ids `ids`, in increasing
    /// order: each page as [`feed_page`] writes it.
    pub(crate) fn of_ids(ids: &[u64]) -> Self {
        let ids = ids.to_vec();
        Self::answering(move |cursor, limit| Ok(feed_page(&ids, cursor, limit)))
    }

    /// An honest feed of `events`, each an id and its line, in increasing
    /// order of id: each page as [`events_page`] writes it.
    pub(crate) fn of_events(events: Vec<(u64, String)>) -> Self {
        Self::answering(move |cursor, limit| Ok(events_page(&events, cursor, limit)))
    }

    /// The same fake, answering every stream request with `body`.
    pub(crate) fn with_stream(self, body: &[u8]) -> Self {
        let body = body.to_vec();
        self.with_stream_answer(move |_, _, _| Ok(body.clone()))
    }

    /// The same fake, answering each stream request with what `answer`
    /// gives for its homeserver, owner and path.
    pub(crate) fn with_stream_answer(
        mut self,
        answer: impl Fn(Pubky, Pubky, &SweepkyPath) -> anyhow::Result<Vec<u8>> + 'static,
    ) -> Self {
        self.stream = Box::new(answer);
        self
    }

    /// The cursor and the limit of every page request so far, in order.
    pub(crate) fn asked(&self) -> Vec<(EventCursor, u16)> {
        self.asked
            .lock()
            .expect("lock")
            .iter()
            .map(|&(_, cursor, limit)| (cursor, limit))
            .collect()
    }

    /// Every homeserver a page was asked of so far, once each.
    pub(crate) fn homeservers_asked(&self) -> BTreeSet<Pubky> {
        self.asked
            .lock()
            .expect("lock")
            .iter()
            .map(|&(homeserver, _, _)| homeserver)
            .collect()
    }

    /// Every stream request so far, in order.
    pub(crate) fn streams_asked(&self) -> Vec<StreamRequest> {
        self.streams_asked.lock().expect("lock").clone()
    }
}

impl EventsFeed for FakeEventsFeed {
    async fn feed_body(
        &self,
        homeserver: Pubky,
        cursor: EventCursor,
        limit: u16,
    ) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        self.asked
            .lock()
            .expect("lock")
            .push((homeserver, cursor, limit));
        (self.pages)(cursor, limit).map(Zeroizing::new)
    }

    async fn stream_body(
        &self,
        homeserver: Pubky,
        owner: Pubky,
        path: &SweepkyPath,
    ) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        self.streams_asked
            .lock()
            .expect("lock")
            .push(StreamRequest {
                homeserver,
                owner,
                path: path.clone(),
            });
        (self.stream)(homeserver, owner, path).map(Zeroizing::new)
    }
}

/// One event of an `/events-stream` answer, as pubky-homeserver 0.16.2
/// writes it: its type, the file's URL, its cursor and, for a PUT, a
/// content hash, then a blank line.
pub(crate) fn stream_event(op: &str, url: &str, cursor: u64) -> String {
    let hash = if op == "PUT" {
        "data: content_hash: r0NJufX5oaagQE3qNtzJSZvLJcmtwRK3zJqTyuQfMmI=\n"
    } else {
        ""
    };
    format!("event: {op}\ndata: {url}\ndata: cursor: {cursor}\n{hash}\n")
}

/// One page of an honest feed of public events with the ids `ids`, in
/// increasing order, as [`events_page`] writes it: a `PUT` of a file of
/// another app for each.
pub(crate) fn feed_page(ids: &[u64], cursor: EventCursor, limit: u16) -> Vec<u8> {
    let user = Pubky::from_bytes([7; 32]);
    // Only the events the page holds get a line written, so a long feed
    // costs each page no more than its own lines.
    let after: Vec<(u64, String)> = ids
        .iter()
        .filter(|&&id| id > cursor.id())
        .take(usize::from(limit))
        .map(|&id| (id, format!("PUT pubky://{user}/pub/example.app/{id}.json")))
        .collect();
    events_page(&after, cursor, limit)
}

/// One page of an honest feed of `events`, each an id and its line (`PUT
/// pubky://…` or `DEL pubky://…`), in increasing order of id, as
/// `format_events_feed` in pubky-homeserver 0.16.2 writes it: the lines of
/// the first `limit` events after `cursor`, then `cursor: <the last one's
/// id>`, joined with `\n`; the empty body when no event comes after
/// `cursor`.
pub(crate) fn events_page(events: &[(u64, String)], cursor: EventCursor, limit: u16) -> Vec<u8> {
    let after: Vec<&(u64, String)> = events
        .iter()
        .filter(|(id, _)| *id > cursor.id())
        .take(usize::from(limit))
        .collect();
    let Some((last, _)) = after.last() else {
        return Vec::new();
    };
    let mut lines: Vec<&str> = after.iter().map(|(_, line)| line.as_str()).collect();
    let cursor_line = format!("cursor: {last}");
    lines.push(&cursor_line);
    lines.join("\n").into_bytes()
}

/// What a [`LocalHttp`] server answers a path with.
pub(crate) enum Canned {
    /// These bytes, as they go on the wire: the status line, the headers, a
    /// blank line and the body ([`canned`] writes them). The connection
    /// closes after them.
    Bytes(Vec<u8>),
    /// A 200 with no length, whose body is zero bytes sent until the client
    /// hangs up or [`ENDLESS_LIMIT`] bytes have gone out: a server that
    /// streams forever.
    Endless,
}

/// The most a [`Canned::Endless`] body sends, so that a client that never
/// stops reading still ends the test: 64 MiB, twice the largest cap
/// Sweepky reads with.
const ENDLESS_LIMIT: usize = 64 * 1024 * 1024;

/// An HTTP/1.1 answer of `status` (such as `"302 Found"`), `headers` and
/// `body`, with a `content-length` of the body's.
pub(crate) fn canned(status: &str, headers: &[(&str, &str)], body: &[u8]) -> Canned {
    let header_lines: String = headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .collect();
    let head = format!(
        "HTTP/1.1 {status}\r\n{header_lines}content-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(body);
    Canned::Bytes(bytes)
}

/// An HTTP/1.1 server on the loopback address, for the tests of the
/// requests Sweepky sends itself where a fake would skip the code under
/// test: what reqwest does with a redirect, a 304 or a body over a cap. It
/// answers each request with the [`Canned`] answer for its path (the query
/// is ignored), any other path with a 404, and keeps the head of every
/// request it read, in order. Dropping it stops it.
pub(crate) struct LocalHttp {
    base: url::Url,
    heads: Arc<Mutex<Vec<String>>>,
    server: tokio::task::JoinHandle<()>,
}

impl LocalHttp {
    /// A server on a free port of 127.0.0.1, answering `routes`: each a
    /// path and its answer.
    pub(crate) async fn start(routes: Vec<(&'static str, Canned)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a free loopback port");
        let address = listener.local_addr().expect("its address");
        let base = url::Url::parse(&format!("http://{address}/")).expect("a URL");
        // `Arc` because every connection's task reads the routes and writes
        // the heads, and each task must own what it uses.
        let routes: Arc<BTreeMap<&'static str, Canned>> = Arc::new(routes.into_iter().collect());
        let heads = Arc::new(Mutex::new(Vec::new()));
        let server = tokio::spawn({
            let heads = Arc::clone(&heads);
            async move {
                // A task per connection, so a client that keeps one open
                // does not hold up the next.
                while let Ok((stream, _)) = listener.accept().await {
                    tokio::spawn(answer(stream, Arc::clone(&routes), Arc::clone(&heads)));
                }
            }
        });
        Self {
            base,
            heads,
            server,
        }
    }

    /// The URL of `path` on this server.
    pub(crate) fn url(&self, path: &str) -> url::Url {
        self.base.join(path).expect("a URL")
    }

    /// The head of every request so far, its request line and headers, as
    /// it arrived, in order.
    pub(crate) fn heads(&self) -> Vec<String> {
        self.heads.lock().expect("lock").clone()
    }
}

impl Drop for LocalHttp {
    // Stops accepting; each connection's task ends once its answer is out.
    fn drop(&mut self) {
        self.server.abort();
    }
}

/// Reads one request's head from `stream`, keeps it in `heads`, and writes
/// the answer `routes` has for its path.
async fn answer(
    mut stream: TcpStream,
    routes: Arc<BTreeMap<&'static str, Canned>>,
    heads: Arc<Mutex<Vec<String>>>,
) {
    // `AsyncReadExt` and `AsyncWriteExt` add `.read`, `.write_all` and
    // `.shutdown` to the socket. Imported here, not for the whole module,
    // where tokio's `write` would clash with `std::io::Write`'s on
    // `SharedBuffer`.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // A GET has no body, so its head is the whole request. 16 KiB is far
    // more than reqwest sends.
    let mut head = Vec::new();
    let mut buf = [0_u8; 1024];
    while !head.windows(4).any(|end| end == b"\r\n\r\n") && head.len() < 16 * 1024 {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(read) => head.extend_from_slice(&buf[..read]),
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    // `GET /path?query HTTP/1.1`: the path, without its query.
    let path = head
        .split(' ')
        .nth(1)
        .and_then(|target| target.split('?').next())
        .unwrap_or_default()
        .to_owned();
    heads.lock().expect("lock").push(head);
    // A write fails once the client has hung up, which is how an endless
    // body ends, so the results are dropped.
    match routes.get(path.as_str()) {
        Some(Canned::Bytes(bytes)) => {
            let _ = stream.write_all(bytes).await;
        }
        Some(Canned::Endless) => {
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n")
                .await;
            let zeros = [0_u8; 64 * 1024];
            let mut sent = 0;
            while sent < ENDLESS_LIMIT && stream.write_all(&zeros).await.is_ok() {
                sent += zeros.len();
            }
        }
        None => {
            let _ = stream
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                )
                .await;
        }
    }
    let _ = stream.shutdown().await;
}

/// A word the tests plant in a stranger's text, where serde_json's own
/// message or a careless format string would repeat it: no message may.
pub(crate) const PLANTED: &str = "PLANTED-7f3a";

/// A full lower-case SHA-1 for the targets of a synthetic bounty.
pub(crate) const SYNTHETIC_SHA: &str = "1111111111111111111111111111111111111111";

/// The record id of a synthetic bounty or sweep.
pub(crate) fn bounty_id() -> RecordId {
    "0035G87EK4XFE".parse().expect("a record id")
}

/// The record id of timestamp `n`: ids order as their timestamps do, so a
/// test makes an older record with a smaller `n`.
pub(crate) fn record_id(n: u64) -> RecordId {
    RecordId::from_timestamp(Timestamp::from(n))
}

/// The bytes of `value`, as a homeserver would hand them back.
pub(crate) fn json_bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("JSON")
}

/// A repo target `id` of the whole of `github.com/org/name` at
/// [`SYNTHETIC_SHA`], as a bounty's `targets` holds it.
pub(crate) fn repo_target_json(id: &str) -> Value {
    json!({ "id": id, "kind": "repo", "repo": "github.com/org/name", "rev": SYNTHETIC_SHA })
}

/// The head of the pull request [`pr_target_json`] gives: the commit a
/// sweep of it reviews, unlike its base, [`SYNTHETIC_SHA`].
pub(crate) const SYNTHETIC_HEAD: &str = "2222222222222222222222222222222222222222";

/// A pull request target `id`, number 7 of `github.com/org/name`, with
/// base [`SYNTHETIC_SHA`] and head [`SYNTHETIC_HEAD`], as a bounty's
/// `targets` holds it.
pub(crate) fn pr_target_json(id: &str) -> Value {
    json!({
        "id": id,
        "kind": "pr",
        "repo": "github.com/org/name",
        "number": 7,
        "base": SYNTHETIC_SHA,
        "head": SYNTHETIC_HEAD,
        "mergeBase": "3333333333333333333333333333333333333333",
    })
}

/// A bounty record as `post` writes it, with `targets`: status `open`,
/// closed to strangers, no playbook suggested.
pub(crate) fn bounty_json(targets: Value) -> Value {
    json!({
        "schemaVersion": 1,
        "title": "Auth before the release",
        "focus": "security",
        "brief": "Look at the session handling.",
        "playbook": { "required": false },
        "targets": targets,
        "open": false,
        "reward": null,
        "status": "open",
        "credits": [],
        "createdAt": "2026-10-19T08:00:00Z",
        "doneAt": null,
    })
}

/// A sweep record of `targets` of `bounty`, with `status`, as `run` writes
/// one.
pub(crate) fn sweep_json(bounty: BountyRef, targets: &[&str], status: &str) -> Value {
    json!({
        "schemaVersion": 1,
        "bounty": bounty.to_string(),
        "targets": targets,
        "playbook": "cloudflare/security-audit@c1c8a8c",
        "status": status,
        "startedAt": "2026-10-19T09:00:00Z",
    })
}

/// [`sweep_json`] as `submit` leaves it: done, with its `finishedAt`.
pub(crate) fn done_record(bounty: BountyRef, targets: &[&str]) -> Value {
    let mut record = sweep_json(bounty, targets, "done");
    record["finishedAt"] = json!("2026-10-19T10:00:00Z");
    record
}

/// A sweep package as `submit` builds one, of `sweeper`'s sweep of
/// `bounty` at `shas` (target id to commit), its targets the keys of
/// `shas`, with [`PLANTED`] in its one finding and its one attachment, so
/// a test can check that nothing printed holds sealed content.
pub(crate) fn package_json(sweeper: Pubky, bounty: BountyRef, shas: Value) -> Value {
    let targets: Vec<&String> = shas.as_object().expect("an object").keys().collect();
    json!({
        "schemaVersion": 1,
        "manifest": {
            "sweeper": sweeper.to_string(),
            "bounty": bounty.to_string(),
            "targets": targets,
            "targetShas": shas,
            "playbook": "careful-review",
            "startedAt": "2026-10-19T09:00:00Z",
            "finishedAt": "2026-10-19T10:00:00Z",
        },
        "findings": {
            "schemaVersion": 1,
            "playbook": "careful-review",
            "findings": [{
                "id": "session-expiry-off-by-one",
                "title": PLANTED,
                "severity": null,
                "confidence": null,
                "status": "needs_validation",
                "locations": [{ "file": "src/auth/session.rs", "line": 88 }],
                "description": PLANTED,
            }],
        },
        "attachments": { "REPORT.md": PLANTED },
    })
}

/// A SHA no synthetic target pins, for a revision rewritten after a fetch.
pub(crate) const UNPINNED_SHA: &str = "4444444444444444444444444444444444444444";

/// [`bounty_json`] of `targets`, read by core.
pub(crate) fn bounty_of(targets: Value) -> Bounty {
    Bounty::from_json(&json_bytes(&bounty_json(targets))).expect("a bounty")
}

/// A random sweeper's sweep and a random owner's bounty, unrelated so far.
pub(crate) fn random_sweep_and_bounty() -> (SweepRef, BountyRef) {
    let sweep = SweepRef {
        sweeper: random_pubky(),
        id: record_id(7),
    };
    let bounty = BountyRef {
        owner: random_pubky(),
        id: bounty_id(),
    };
    (sweep, bounty)
}

/// The snapshot `run` keeps of `sweep`, a fetch of the targets `ids` of
/// `bounty`, read from `at`: each checked out at its reviewed commit.
pub(crate) fn snapshot_of(
    sweep: SweepRef,
    at: BountyRef,
    bounty: &Bounty,
    ids: &[&str],
) -> SweepSnapshot {
    let fetched: Vec<(TargetId, KnownTarget)> = ids
        .iter()
        .map(|id| {
            let target = bounty
                .targets
                .iter()
                .find(|target| target.id().as_str() == *id)
                .expect("a target of the bounty");
            let known = target.known().expect("well formed").expect("a known kind");
            (target.id().clone(), known)
        })
        .collect();
    SweepSnapshot::new(sweep, at, fetched.iter().map(|(id, target)| (id, target)))
}

/// A `circle.json` that `admin` keeps, listing `members` and no labels.
pub(crate) fn circle_json(admin: Pubky, members: &[Pubky]) -> Value {
    let members: Vec<Value> = members
        .iter()
        .map(|member| json!({ "pubky": member.to_string() }))
        .collect();
    json!({
        "schemaVersion": 1,
        "name": "Friends",
        "admin": admin.to_string(),
        "members": members,
    })
}

/// The compact copy `pull` stored of the findings of `sweep` of `bounty`,
/// read back within the package's cap: the side it was stored on, as its
/// directory shows, and the findings, or `None` when it was not stored.
pub(crate) fn stored_findings(
    dirs: &Dirs,
    bounty: BountyRef,
    sweep: SweepRef,
) -> anyhow::Result<Option<(Placement, Findings)>> {
    let Some(dir) = stored_sweep_dir(dirs, bounty, sweep)? else {
        return Ok(None);
    };
    let placement = if dir.starts_with(dirs.pulled_untrusted_dir(&bounty.id)) {
        Placement::Untrusted
    } else {
        Placement::Trusted
    };
    Ok(
        match read_stored_findings(dirs, bounty, sweep, MAX_PACKAGE_BYTES)? {
            None => None,
            Some(StoredCopy::Read { findings, .. }) => Some((placement, findings)),
            Some(StoredCopy::OverCap { len }) => panic!("a copy over the cap, of {len} bytes"),
        },
    )
}

/// What a [`FakeResolver`] that fails gives as its error: words that a
/// test checks never reach a message.
pub(crate) const FAKE_LOOKUP_TEXT: &str = "fake resolver: SERVFAIL for lookup-marker.example";

/// A [`ResolveHost`] in place of DNS: it answers every host with the same
/// addresses, or fails every lookup with [`FAKE_LOOKUP_TEXT`], and keeps
/// every host it was asked for, in order. The `Mutex` is there for the
/// same reason as in [`FakeKeyStore`].
pub(crate) struct FakeResolver {
    /// `None` fails every lookup.
    answer: Option<Vec<IpAddr>>,
    asked: Mutex<Vec<String>>,
}

impl FakeResolver {
    /// Answers every host with `addresses`, each parsed from its text; an
    /// empty list is a host with no address.
    pub(crate) fn answering(addresses: &[&str]) -> Self {
        let answer = addresses
            .iter()
            .map(|text| text.parse().expect("an IP address"))
            .collect();
        Self {
            answer: Some(answer),
            asked: Mutex::default(),
        }
    }

    /// Fails every lookup.
    pub(crate) fn failing() -> Self {
        Self {
            answer: None,
            asked: Mutex::default(),
        }
    }

    /// Every host asked for so far, in order.
    pub(crate) fn asked(&self) -> Vec<String> {
        self.asked.lock().expect("lock").clone()
    }
}

impl ResolveHost for FakeResolver {
    async fn resolve(&self, host: &str) -> anyhow::Result<Vec<IpAddr>> {
        self.asked.lock().expect("lock").push(host.to_owned());
        self.answer
            .clone()
            .ok_or_else(|| anyhow::anyhow!(FAKE_LOOKUP_TEXT))
    }
}

/// The homeserver every key is at in a [`FakeHomeservers`] that was given
/// no answers for it.
pub(crate) const FAKE_HOMESERVER: Pubky = Pubky::from_bytes([9; 32]);

/// How a [`FakeHomeservers`] answers one lookup of a key.
#[derive(Debug, Clone, Copy)]
pub(crate) enum FakeLookup {
    /// The key's pkarr record names this homeserver.
    At(Pubky),
    /// The key has no pkarr record, or one that names no homeserver.
    NoRecord,
    /// The lookup fails.
    Fails,
}

/// A [`ResolveHomeserver`] in place of pkarr: each key's lookups are
/// answered in the order a test gave, the last one again for every lookup
/// after it, and a key given no answers is at [`FAKE_HOMESERVER`]. It keeps
/// every key it was asked for, in order. The `Mutex` is there for the same
/// reason as in [`FakeKeyStore`].
#[derive(Default)]
pub(crate) struct FakeHomeservers {
    answers: BTreeMap<Pubky, Vec<FakeLookup>>,
    asked: Mutex<Vec<Pubky>>,
}

impl FakeHomeservers {
    /// The same fake, answering the lookups of `user` with `answers`, in
    /// order.
    pub(crate) fn with_answers(mut self, user: Pubky, answers: &[FakeLookup]) -> Self {
        self.answers.insert(user, answers.to_vec());
        self
    }

    /// Every key looked up so far, in order.
    pub(crate) fn asked(&self) -> Vec<Pubky> {
        self.asked.lock().expect("lock").clone()
    }

    /// How many times `user` was looked up so far.
    pub(crate) fn times_asked(&self, user: Pubky) -> usize {
        self.asked().iter().filter(|&&asked| asked == user).count()
    }
}

impl ResolveHomeserver for FakeHomeservers {
    async fn homeserver_of(&self, user: Pubky) -> Result<Pubky, Unreachable> {
        let earlier = self.times_asked(user);
        self.asked.lock().expect("lock").push(user);
        let answer = match self.answers.get(&user) {
            None => FakeLookup::At(FAKE_HOMESERVER),
            // The answer for this lookup, or the last one once they run out.
            Some(answers) => *answers
                .get(earlier)
                .or(answers.last())
                .expect("at least one answer"),
        };
        match answer {
            FakeLookup::At(homeserver) => Ok(homeserver),
            FakeLookup::NoRecord => Err(Unreachable::NoHomeserver),
            FakeLookup::Fails => Err(Unreachable::LookupFailed),
        }
    }
}

/// A [`RunGit`] in place of git: it records the argv git would have been
/// started with, through [`git_argv`] and the protocols it was made with,
/// and answers every run with the same scripted exit status and output.
/// Exit status 0 hands back `stdout`; any other is a [`GitFailed`] with
/// that code and `stderr`, as the real runner gives. A command whose argv
/// [`git_argv`] refuses is not recorded, as the real runner would start no
/// git for it. The `Mutex` is there for the same reason as in
/// [`FakeKeyStore`].
pub(crate) struct RecordingGit {
    protocols: AllowedProtocols,
    code: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    argv: Mutex<Vec<Vec<String>>>,
}

impl RecordingGit {
    /// Answers every run with success and `stdout`.
    pub(crate) fn succeeding(protocols: AllowedProtocols, stdout: &[u8]) -> Self {
        Self::answering(protocols, 0, stdout, b"")
    }

    /// Answers every run with exit status `code` and `stderr`.
    pub(crate) fn failing(protocols: AllowedProtocols, code: i32, stderr: &[u8]) -> Self {
        Self::answering(protocols, code, b"", stderr)
    }

    fn answering(protocols: AllowedProtocols, code: i32, stdout: &[u8], stderr: &[u8]) -> Self {
        Self {
            protocols,
            code,
            stdout: stdout.to_vec(),
            stderr: stderr.to_vec(),
            argv: Mutex::default(),
        }
    }

    /// The argv of every run so far, in order.
    pub(crate) fn argv(&self) -> Vec<Vec<String>> {
        self.argv.lock().expect("lock").clone()
    }
}

impl RunGit for RecordingGit {
    async fn run(&self, command: &GitCommand) -> anyhow::Result<Vec<u8>> {
        let argv = git_argv(command, self.protocols)?;
        self.argv.lock().expect("lock").push(argv);
        if self.code == 0 {
            Ok(self.stdout.clone())
        } else {
            Err(GitFailed::for_tests(command, self.code, self.stderr.clone()).into())
        }
    }
}

/// A [`GitHubApi`] in place of GitHub: it answers each URL it was given a
/// body for with that body, as a 2xx answer, and every other URL as a 404
/// (`None`), and keeps every URL it was asked for, in order. It hands the
/// body back whole, whatever the cap: the parsers check the cap again
/// themselves. The `Mutex` is there for the same reason as in
/// [`FakeKeyStore`].
pub(crate) struct FakeGitHub {
    answers: BTreeMap<String, Vec<u8>>,
    asked: Mutex<Vec<String>>,
}

impl FakeGitHub {
    /// Answers each `(url, body)` of `answers`; an empty list answers
    /// every URL with a 404.
    pub(crate) fn answering(answers: &[(&str, &[u8])]) -> Self {
        Self {
            answers: answers
                .iter()
                .map(|&(url, body)| (url.to_owned(), body.to_vec()))
                .collect(),
            asked: Mutex::default(),
        }
    }

    /// Every URL asked for so far, in order.
    pub(crate) fn asked(&self) -> Vec<String> {
        self.asked.lock().expect("lock").clone()
    }
}

impl GitHubApi for FakeGitHub {
    async fn get(&self, url: url::Url, _cap: usize) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
        self.asked.lock().expect("lock").push(url.to_string());
        Ok(self
            .answers
            .get(url.as_str())
            .map(|body| Zeroizing::new(body.clone())))
    }
}

/// The https remote of `repo`, made the one way there is, through the host
/// policy, with a [`FakeResolver`] that answers one public address.
pub(crate) async fn checked_remote(repo: &str) -> HttpsRemote {
    let repo = repo.parse().expect("a repo name");
    HttpsRemote::for_repo(&repo, &FakeResolver::answering(&["140.82.112.3"]))
        .await
        .expect("a public host")
}

/// The permission bits of whatever is at `path`, not following a link.
///
/// `& 0o777` keeps the permission bits and drops the file-type bits that
/// `st_mode` also carries.
pub(crate) fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).expect("exists").mode() & 0o777
}

/// Sets the permission bits of `path` to `mode`.
pub(crate) fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, Permissions::from_mode(mode)).expect("chmod");
}

/// What a file holds at one moment, and which inode holds it.
///
/// `private_fs` writes a file by renaming a new one over it, so a file
/// written again has a new inode even when its bytes are the same: two equal
/// snapshots mean the file was not written at all in between.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FileSnapshot {
    bytes: Vec<u8>,
    inode: u64,
}

impl FileSnapshot {
    /// The file at `path` now, or `None` when there is nothing there. Any
    /// other error fails the test, so an unreadable file is never mistaken
    /// for a missing one.
    pub(crate) fn of(path: &Path) -> Option<Self> {
        let meta = match fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == ErrorKind::NotFound => return None,
            Err(error) => panic!("could not stat {}: {error}", path.display()),
        };
        Some(Self {
            bytes: fs::read(path).expect("readable"),
            inode: meta.ino(),
        })
    }
}

/// Fails to compile when `$type` implements any of the listed traits. A test
/// states what a secret type must never implement with
/// `crate::test_support::assert_not_impl_any!(Type: Trait, …);`.
///
/// A copy of `sweepky-core`'s test-only macro of the same name, which is
/// `pub(crate)` there and so cannot be used from this crate; like that one,
/// it is the trick behind `static_assertions::assert_not_impl_any!`, written
/// out so no dependency is needed for it. A local trait has a blanket impl
/// for every type with the parameter `()`, and one more blanket impl per
/// listed trait, each with its own private parameter type, for the types
/// that implement that trait. `<$type as AmbiguousIfImpl<_>>` asks the
/// compiler to infer the parameter. If `$type` implements none of the listed
/// traits, only the `()` impl applies and inference succeeds; if it
/// implements one, two impls apply, inference is ambiguous, and the crate
/// does not compile. So the check happens at compile time, and the test that
/// holds it has nothing left to do when it runs.
///
/// For `Deserialize`, list `serde::de::DeserializeOwned`: it is implemented
/// for every type that is `Deserialize` for every lifetime, which is what
/// `#[derive(Deserialize)]` gives.
macro_rules! assert_not_impl_any {
    ($type:ty: $($trait_path:path),+ $(,)?) => {
        // `const _` is an unnamed constant: it exists only to make the
        // compiler type-check the closure below. The closure is never called.
        const _: fn() = || {
            trait AmbiguousIfImpl<A> {
                fn some_item() {}
            }
            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
            $({
                // Never constructed: it only gives this impl a parameter type
                // of its own.
                #[allow(dead_code)]
                struct Invalid;
                impl<T: ?Sized + $trait_path> AmbiguousIfImpl<Invalid> for T {}
            })+
            let _ = <$type as AmbiguousIfImpl<_>>::some_item;
        };
    };
}

// A `macro_rules!` macro is visible only further down this file unless it is
// re-exported. This `use` gives it the path
// `crate::test_support::assert_not_impl_any` for test modules anywhere in the
// crate.
pub(crate) use assert_not_impl_any;

/// The most bytes [`loopback_get`] reads of one answer. The sign-in page,
/// with its QR code as an SVG, is well under this.
const MAX_LOOPBACK_ANSWER: u64 = 1024 * 1024;

/// How long [`loopback_get`] waits for one answer.
const LOOPBACK_WAIT: Duration = Duration::from_secs(10);

/// A plain `GET` of `url` on the loopback address, as a browser would send
/// it, over a raw `TcpStream`: the answer's status code and its body, read
/// to at most [`MAX_LOOPBACK_ANSWER`] bytes within [`LOOPBACK_WAIT`].
///
/// `Err` when nothing answers (the server has stopped). It refuses any URL
/// that is not `http://127.0.0.1:<port>/...`, so a test cannot send it
/// anywhere else by mistake.
pub(crate) async fn loopback_get(url: &Url) -> io::Result<(u16, String)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    assert_eq!(url.scheme(), "http", "{url}");
    assert_eq!(url.host_str(), Some("127.0.0.1"), "{url}");
    let port = url.port().expect("the loopback URL names its port");
    let target = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_owned(),
    };
    let exchange = async {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await?;
        let request =
            format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await?;
        let mut raw = Vec::new();
        // `take` caps the read: past the cap it reads as the end of input.
        stream
            .take(MAX_LOOPBACK_ANSWER)
            .read_to_end(&mut raw)
            .await?;
        Ok::<_, io::Error>(raw)
    };
    let raw = tokio::time::timeout(LOOPBACK_WAIT, exchange)
        .await
        .map_err(|_| io::Error::from(ErrorKind::TimedOut))??;
    let text = String::from_utf8(raw).expect("a UTF-8 answer");
    let (head, body) = text.split_once("\r\n\r\n").expect("a head and a body");
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("a status line");
    Ok((status, body.to_owned()))
}

/// The Pubky Ring sign-in page as a test playing Ring sees it: fetched from
/// the URL `login` handed to [`Browser::Notify`], with the authorization
/// link and the status URL read off it.
pub(crate) struct RingPage {
    /// The page's URL, a secret path on `127.0.0.1`.
    pub(crate) url: Url,
    /// The page's HTML.
    pub(crate) html: String,
    /// The `pubkyauth://` link, un-escaped from the page's `auth-link`.
    pub(crate) link: String,
    /// The status URL: the page's `data-status` joined to the page's URL,
    /// as the page's script resolves it.
    pub(crate) status_url: Url,
}

impl RingPage {
    /// Waits for the page URL on `urls`, fetches the page and reads the
    /// link and the status URL off it.
    pub(crate) async fn open(urls: &mut UnboundedReceiver<Url>) -> Self {
        let url = tokio::time::timeout(LOOPBACK_WAIT, urls.recv())
            .await
            .expect("login hands over the page URL in time")
            .expect("login hands over the page URL");
        let (status, html) = loopback_get(&url).await.expect("the page answers");
        assert_eq!(status, 200, "{html}");
        let link = html_unescape(between(&html, r#"<code id="auth-link">"#, "</code>"));
        let status_path = html_unescape(between(&html, r#"data-status=""#, r#"""#));
        let status_url = url.join(&status_path).expect("a status URL");
        Self {
            url,
            html,
            link,
            status_url,
        }
    }

    /// The status word the page's status URL answers with now.
    pub(crate) async fn status(&self) -> String {
        let (code, word) = loopback_get(&self.status_url)
            .await
            .expect("the status answers");
        assert_eq!(code, 200, "{word}");
        word
    }

    /// Asks the status about every 100 ms until it is no longer `waiting`,
    /// and returns that final word.
    pub(crate) async fn final_status(&self) -> String {
        for _ in 0..300 {
            let word = self.status().await;
            if word != "waiting" {
                return word;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("the status stayed `waiting` for 30 s");
    }
}

/// The text of `html` between the first `start` and the next `end` after it.
fn between<'a>(html: &'a str, start: &str, end: &str) -> &'a str {
    let (_, rest) = html.split_once(start).expect("the start marker");
    let (inside, _) = rest.split_once(end).expect("the end marker");
    inside
}

/// The page's HTML escapes undone (`ring::page::html_escape`'s five), with
/// `&amp;` last so that an escaped entity is not unescaped twice.
fn html_unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

/// An in-process stand-in for Pubky Ring: a keypair signed up on a testnet
/// homeserver, which approves a sign-in link as Ring would
/// (`PubkySigner::approve_auth`), and a root session of its own, which
/// lists the identity's grants the way Ring's grant list does.
///
/// No `Debug`: it holds a signer and a session.
pub(crate) struct RingStandIn {
    signer: PubkySigner,
    root: PubkySession,
}

impl RingStandIn {
    /// A fresh identity signed up on `testnet`'s homeserver, signed in with
    /// its root key under the client id `ring-stand-in`.
    pub(crate) async fn sign_up(testnet: &EphemeralTestnet) -> Self {
        let signer = testnet.sdk().expect("client").signer(Keypair::random());
        signer
            .signup(&testnet.homeserver_app().public_key(), None)
            .await
            .expect("signs up");
        let root = signer
            .signin(ClientId::new("ring-stand-in").expect("a client id"))
            .await
            .expect("signs in");
        Self { signer, root }
    }

    /// The identity's public key.
    pub(crate) fn public_key(&self) -> PublicKey {
        self.root.public_key()
    }

    /// Approves `page`'s link in full, as Ring's approve button does.
    pub(crate) async fn approve(&self, page: &RingPage) {
        self.signer
            .approve_auth(&page.link)
            .await
            .expect("approves");
    }

    /// Approves `page`'s link with `capabilities` only, as a Ring that
    /// narrows a request would.
    pub(crate) async fn approve_with(&self, page: &RingPage, capabilities: &Capabilities) {
        self.signer
            .approve_auth_with_capabilities(&page.link, capabilities)
            .await
            .expect("approves");
    }

    /// The identity's active grants made for `client_id`, from the
    /// homeserver's grant list (`GrantManager::list`, which needs this root
    /// session).
    pub(crate) async fn active_grants_for(&self, client_id: &str) -> Vec<GrantInfo> {
        GrantManager::new(&self.root)
            .list()
            .await
            .expect("lists the grants")
            .into_iter()
            .filter(|grant| grant.client_id == client_id)
            .collect()
    }
}
