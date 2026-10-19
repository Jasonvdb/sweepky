//! Helpers that the unit tests of several modules share: a private temp
//! directory, the [`Dirs`] under it and the file-mode checks around it, a
//! [`FileSnapshot`] that tells whether a file was written at all, a random
//! public key, a [`Context`] for a test ([`test_context`], on an
//! [`offline_network`] or a testnet's) with a [`SharedBuffer`] that keeps
//! what it writes to standard error, the [`GitEnv`] the tests run git with
//! and the inert fixture repository they run it against, a
//! [`FakeResolver`] in place of DNS and the [`checked_remote`] made
//! through it, a [`RecordingGit`] in place of git, a [`FakeGitHub`] in
//! place of GitHub's API, the fixture source over
//! that repository ([`fixture_targets`]) and the SHAs `fixtures/README.md`
//! records for it, a [`FakeKeyStore`] in place of a homeserver's `keys/`, a
//! [`FakeOwnStorage`] in place of the signed-in user's own storage, a
//! [`FakePublicRecords`] in place of everyone's public storage and the
//! synthetic bounty and circle records the tests put there, the
//! passphrase the tests wrap secret files with and a byte search to check
//! a wrapped file shows none of its secret, and a compile-time check that a
//! secret type implements none of the traits that would print or copy it.
//!
//! Compiled only for `cargo test` (`#[cfg(test)]` on its `mod` line in
//! `lib.rs`), so nothing here reaches the binary, and like any test code it
//! may panic.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, Permissions};
use std::io::{self, BufRead, ErrorKind, Write};
use std::net::IpAddr;
// `MetadataExt` adds `.mode()` and `.ino()` to `Metadata`; `PermissionsExt`
// adds `Permissions::from_mode`.
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use pubky::errors::RequestError;
use pubky::{Keypair, PubkyHttpClient, PublicKey, StatusCode};
use serde_json::{Value, json};
use sweepky_core::{DeviceId, GitSha, Pubky, RecordId, RepoName, Zeroizing};
use tempfile::TempDir;

use crate::device::{KeyIds, KeyStore, PublicKeys};
use crate::git::{AllowedProtocols, GitCommand, GitFailed, RunGit, git_argv};
use crate::own_storage::OwnStorage;
use crate::records::PublicRecords;
use crate::targets::TargetSource;
use crate::targets::fixture::FixtureTargets;
use crate::targets::github::GitHubApi;
use crate::targets::host::{HttpsRemote, ResolveHost};
use crate::{Context, Dirs, GitEnv, Network, StderrWriter, StdinReader};

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
    let client = PubkyHttpClient::builder()
        .pkarr(|pkarr| {
            pkarr
                .no_dht()
                .relays(&[NOWHERE])
                .expect("a valid relay URL")
        })
        .build()
        .expect("an offline client");
    Network::injected(
        pubky::Pubky::with_client(client),
        format!("{NOWHERE}inbox"),
        Keypair::random().public_key(),
    )
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
/// with. Its listing holds every record's id, in id order, and skips none.
///
/// The methods take `&self`, as the trait's do, yet the fake has to change
/// what it holds. A `Mutex` gives that "interior mutability": it hands out
/// `&mut` access to one caller at a time, checked at run time.
#[derive(Default)]
pub(crate) struct FakeKeyStore {
    records: Mutex<BTreeMap<DeviceId, Vec<u8>>>,
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

    fn log(&self, call: KeyStoreCall) {
        self.calls.lock().expect("lock").push(call);
    }
}

impl PublicKeys for FakeKeyStore {
    async fn list_key_ids(&self, owner: &PublicKey) -> anyhow::Result<KeyIds> {
        self.log(KeyStoreCall::ListKeyIds(owner.clone()));
        let records = self.records.lock().expect("lock");
        Ok(KeyIds {
            ids: records.keys().cloned().collect(),
            skipped: 0,
        })
    }

    async fn get_key(
        &self,
        _owner: &PublicKey,
        id: &DeviceId,
    ) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
        self.log(KeyStoreCall::GetKey(id.clone()));
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

/// A write a [`FakeOwnStorage`] refuses: the path, and the status and
/// server text it answers with.
struct RefusedPut {
    path: String,
    status: StatusCode,
    server_text: String,
}

/// An [`OwnStorage`] in memory, in place of the signed-in user's own
/// storage: the files by path, every path it was asked to write, in order,
/// and, if set, the one path whose write it refuses. It hands a file back
/// whole: the caps are the real storage's business. The `Mutex`es are
/// there for the same reason as in [`FakeKeyStore`].
#[derive(Default)]
pub(crate) struct FakeOwnStorage {
    files: Mutex<BTreeMap<String, Vec<u8>>>,
    puts: Mutex<Vec<String>>,
    refused: Option<RefusedPut>,
}

impl FakeOwnStorage {
    /// A storage that refuses a write of `path` with `status` and
    /// `server_text`, as the SDK reports a homeserver's non-2xx answer, and
    /// takes every other write.
    pub(crate) fn refusing(path: &str, status: StatusCode, server_text: &str) -> Self {
        Self {
            refused: Some(RefusedPut {
                path: path.to_owned(),
                status,
                server_text: server_text.to_owned(),
            }),
            ..Self::default()
        }
    }

    /// Every path asked to be written so far, refused or not, in order.
    pub(crate) fn puts(&self) -> Vec<String> {
        self.puts.lock().expect("lock").clone()
    }
}

impl OwnStorage for FakeOwnStorage {
    async fn put(&self, path: &str, bytes: Vec<u8>) -> pubky::Result<()> {
        self.puts.lock().expect("lock").push(path.to_owned());
        if let Some(refused) = self.refused.as_ref().filter(|refused| refused.path == path) {
            return Err(pubky::Error::from(RequestError::Server {
                status: refused.status,
                message: refused.server_text.clone(),
            }));
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
/// by owner and path, and every read it was asked for, in order. It hands
/// a file back whole, whatever its size: the cap is the real reader's
/// business, and the record parsers check it again themselves. The
/// `Mutex` is there for the same reason as in [`FakeKeyStore`].
#[derive(Default)]
pub(crate) struct FakePublicRecords {
    files: BTreeMap<(Pubky, String), Vec<u8>>,
    asked: Mutex<Vec<(Pubky, String)>>,
}

impl FakePublicRecords {
    /// The same fake, holding `bytes` at `path` of `owner`'s storage too.
    // It takes `self` by value and hands it back, so a test builds one in a
    // chain: `FakePublicRecords::default().with_file(..).with_file(..)`.
    pub(crate) fn with_file(mut self, owner: Pubky, path: &str, bytes: Vec<u8>) -> Self {
        self.files.insert((owner, path.to_owned()), bytes);
        self
    }

    /// The owner and path of every read so far, in order.
    pub(crate) fn asked(&self) -> Vec<(Pubky, String)> {
        self.asked.lock().expect("lock").clone()
    }
}

impl PublicRecords for FakePublicRecords {
    async fn get_record(
        &self,
        owner: Pubky,
        path: &str,
    ) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
        let key = (owner, path.to_owned());
        let found = self
            .files
            .get(&key)
            .map(|bytes| Zeroizing::new(bytes.clone()));
        self.asked.lock().expect("lock").push(key);
        Ok(found)
    }
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

/// The bytes of `value`, as a homeserver would hand them back.
pub(crate) fn json_bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("JSON")
}

/// A repo target `id` of the whole of `github.com/org/name` at
/// [`SYNTHETIC_SHA`], as a bounty's `targets` holds it.
pub(crate) fn repo_target_json(id: &str) -> Value {
    json!({ "id": id, "kind": "repo", "repo": "github.com/org/name", "rev": SYNTHETIC_SHA })
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
