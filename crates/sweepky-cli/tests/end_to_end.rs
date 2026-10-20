//! The end-to-end test from `docs/plan/06-verification-and-limits.md`, run
//! against a local `EphemeralTestnet` with every command going through the
//! library's `run`, exactly as the binary does, but with the testnet's
//! client injected so nothing reaches production.
//!
//! There is one test function and it is built up phase by phase: P2a's
//! steps use the throwaway identity `throwaway` (not A, B or C, because
//! `logout` deletes the identity it runs on), and P2b to P2d add their steps
//! for A, B and C after these, without reordering them. Each identity has a
//! `SWEEPKY_HOME`, and so a `Context`, of its own, as on separate machines.
//!
//! It needs Postgres for the testnet's homeserver, through
//! `TEST_PUBKY_CONNECTION_STRING`. `#[pubky_testnet::test]` drops the test
//! databases when the test ends, even when it fails, but not when the
//! process aborts, as on a stack overflow: then a `pubky_test_*` database is
//! left behind to drop by hand.

use std::fs;
use std::io::{self, BufRead, Cursor, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use clap::Parser;
use pubky::{ClientId, Keypair, Method, PublicKey};
use pubky_testnet::EphemeralTestnet;
use serde_json::{Value, json};
use sweepky_cli::{
    CLIENT_ID, Cli, Context, Dirs, FixtureTargets, GitEnv, Network, Report, StderrWriter,
    StdinReader, TargetSource, run,
};
use sweepky_core::paths::{self, SweepkyPath};
use sweepky_core::{
    Bounty, BountyRef, Circle, DeviceIdentity, DeviceKey, Discovered, EventCursor, FeedEvent,
    FeedOp, Findings, GitSha, KnownBountyStatus, KnownSweepStatus, KnownTarget,
    MAX_CIPHERTEXT_BYTES, MAX_FEED_BODY_BYTES, MAX_RECORD_BYTES, Playbook, Pubky, PubkyUrl,
    RecordId, RepoName, RepoPath, SecretString, Sweep, SweepRef, Zeroizing, open_package,
    parse_audit_findings, parse_feed,
};
use url::Url;

/// What the context writes to standard error, kept where the test can read
/// it. `Arc<Mutex<…>>` is one buffer with two owners, the context and the
/// test, each locking it to use it.
#[derive(Clone, Default)]
struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

impl SharedBuffer {
    fn text(&self) -> String {
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

/// Runs `sweepky <args>` against `ctx`.
async fn sweepky(ctx: &Context, args: &[&str]) -> anyhow::Result<Report> {
    let cli = Cli::try_parse_from(std::iter::once("sweepky").chain(args.iter().copied()))
        .expect("the arguments parse");
    // `Box::pin` moves `run`'s future, about 10 KiB because it can hold any
    // command's state, onto the heap, and this one holds a pointer to it. A
    // debug build gives each call to this function in the test's one long
    // body a stack slot of its own, sized for the future it returns, so
    // unboxed the test thread's 2 MiB stack overflowed once P2c's steps were
    // added.
    Box::pin(run(cli, ctx)).await
}

/// The permission bits of `path`.
fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).expect("exists").mode() & 0o777
}

/// The JSON in `path`.
fn json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).expect("readable")).expect("JSON")
}

/// Asserts that nothing is at `path`, not even a dangling symlink:
/// `symlink_metadata` is `lstat`, which does not follow a link.
fn assert_gone(path: &Path) {
    assert_eq!(
        fs::symlink_metadata(path)
            .map_err(|error| error.kind())
            .err(),
        Some(io::ErrorKind::NotFound),
        "{} is still there",
        path.display()
    );
}

/// The body of an anonymous `GET` of `path` under `user`, through a fresh
/// client, read as the CLI reads one: the `Content-Length` and then every
/// chunk are checked against `cap`, so the test never holds more than that.
async fn get_capped(
    testnet: &EphemeralTestnet,
    user: &PublicKey,
    path: &str,
    cap: usize,
) -> Vec<u8> {
    let mut response = testnet
        .sdk()
        .expect("client")
        .public_storage()
        .get((user, path))
        .await
        .expect("the path is public");
    if let Some(length) = response.content_length() {
        assert!(
            usize::try_from(length).expect("fits") <= cap,
            "{path}: over the cap"
        );
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.expect("the body reads") {
        body.extend_from_slice(&chunk);
        assert!(body.len() <= cap, "{path}: over the cap");
    }
    body
}

/// The entries of `user`'s `keys/`, from one anonymous `GET` of the
/// directory: the request `remote::list_dir` sends, which this test cannot
/// call because the module is private to the crate. The `GET` leaves out
/// the CLI's `limit=100`, which is the homeserver's default page anyway
/// (`DEFAULT_LIST_LIMIT` in pubky-homeserver 0.16.2). The body is read
/// under the cap of such a page. The homeserver answers one URL per line,
/// `pubky://<owner>/pub/sweepky/keys/<id>.json`.
async fn list_keys(testnet: &EphemeralTestnet, user: &PublicKey) -> Vec<String> {
    // The CLI's `ListLimits::DEFAULT` page: 100 lines of at most
    // `MAX_LISTING_LINE_BYTES`, each with its `\r\n`.
    const PAGE_ENTRIES: usize = 100;
    const MAX_LINE_BYTES: usize = 4096;
    const CAP: usize = PAGE_ENTRIES * (MAX_LINE_BYTES + "\r\n".len());
    let body = get_capped(testnet, user, "/pub/sweepky/keys/", CAP).await;
    String::from_utf8(body)
        .expect("UTF-8")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(str::to_owned)
        .collect()
}

/// Signs in as the identity whose Sweepky key file is `key_file`, with its
/// root key, writes `record` at `path`, and signs out: what another install
/// of the same identity, an operator of its homeserver or anyone holding its
/// credentials can do behind this install's back.
async fn publish_as(testnet: &EphemeralTestnet, key_file: &Path, path: &str, record: &Value) {
    let signer = testnet
        .sdk()
        .expect("client")
        .signer(Keypair::from_secret(&identity_seed(key_file)));
    let session = signer
        .signin(ClientId::new(CLIENT_ID).expect("a valid client id"))
        .await
        .expect("signs in");
    session
        .storage()
        .put(path, serde_json::to_vec(record).expect("JSON"))
        .await
        .expect("writes");
    // `signout` hands the session back with the error; only the error is
    // kept, so a failure never prints the session.
    session
        .signout()
        .await
        .map_err(|(error, _session)| error)
        .expect("signs out");
}

/// The 32-byte root seed in the Sweepky key file `key_file`.
///
/// The library keeps its reader of that file private, so the test reads
/// Sweepky's documented format itself: the line `sweepky-identity/v1`, then
/// the seed as 64 lower-case hex digits and a newline. The bytes stay in
/// buffers that wipe themselves.
fn identity_seed(key_file: &Path) -> Zeroizing<[u8; 32]> {
    let file = Zeroizing::new(fs::read(key_file).expect("readable"));
    let hex = file
        .strip_prefix(b"sweepky-identity/v1\n")
        .and_then(|rest| rest.strip_suffix(b"\n"))
        .expect("a v1 identity file");
    assert_eq!(hex.len(), 64, "a 32-byte seed");
    // `as_chunks::<2>()` views the digits as pairs typed `[u8; 2]`, each one
    // byte of the seed, plus a remainder, which is empty because 64 is even.
    let (pairs, _remainder) = hex.as_chunks::<2>();
    let mut seed = Zeroizing::new([0_u8; 32]);
    for (byte, pair) in seed.iter_mut().zip(pairs) {
        let digits = std::str::from_utf8(pair).expect("hex digits");
        *byte = u8::from_str_radix(digits, 16).expect("hex digits");
    }
    seed
}

/// Copies the Sweepky identity file `key_file` into `identities`, another
/// install's `identities/`, as an owner on `--identity` carries the
/// identity to a second machine: test setup for A's second install, not an
/// import path, since `login` still refuses recovery files and raw keys.
///
/// The directory, and any parent missing, is made 0700 and the copy is
/// created 0600, so the secret is never readable by anyone else, not even
/// for a moment: a `chmod` after the write would leave such a moment. The
/// bytes stay in a buffer that wipes itself.
fn copy_identity_file(key_file: &Path, identities: &Path) {
    // `DirBuilderExt` and `OpenOptionsExt` are Unix extension traits: in
    // scope, they add `mode`, the permission bits to create with, which the
    // umask can only narrow.
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(identities)
        .expect("identities/");
    let secret = Zeroizing::new(fs::read(key_file).expect("readable"));
    let copy = identities.join(key_file.file_name().expect("a file name"));
    // `create_new` refuses anything already at the name, a link included,
    // rather than writing through it.
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(copy)
        .expect("a new file")
        .write_all(&secret)
        .expect("written");
}

/// The synthetic name the fixture source serves `fixtures/target-repo.git`
/// under: a host under `example.invalid`, which no resolver answers.
const FIXTURE_REPO: &str = "example.invalid/sweepky/target-repo";

/// The fixture source the test's targets come from: [`FIXTURE_REPO`] mapped
/// to `fixtures/target-repo.git`, whose files `tests/fixture_target_repo.rs`
/// checks are inert. `env!` reads `CARGO_MANIFEST_DIR` when the test is
/// compiled, so the path holds whatever directory the test runs in.
fn fixture_targets() -> TargetSource {
    let repo: RepoName = FIXTURE_REPO.parse().expect("a repo name");
    let path = fs::canonicalize(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/target-repo.git"),
    )
    .expect("the fixture repository");
    TargetSource::Fixture(FixtureTargets::new([(repo, path)]))
}

/// The SHA `fixtures/README.md` records for `name`, a commit of the
/// fixture repository (R, A, B, M, F2, …), in a row of the form
/// ``| name | `<sha>` | …`` of its `target-repo.git` section. A test binary
/// cannot call `tests/fixture_target_repo.rs`'s own reader, so this is a
/// small one of its own; the README stays the one place the SHAs are
/// written.
fn recorded_sha(name: &str) -> GitSha {
    let readme =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/README.md"))
            .expect("fixtures/README.md");
    let section = readme
        .split("\n## ")
        .find(|section| section.starts_with("`target-repo.git`"))
        .expect("fixtures/README.md has a `target-repo.git` section");
    let row = format!("| {name} | `");
    section
        .lines()
        .find_map(|line| line.strip_prefix(row.as_str()))
        .and_then(|rest| rest.split('`').next())
        .expect("the README records the commit")
        .parse()
        .expect("a SHA")
}

/// A context for one identity: the testnet's client injected, `home` as
/// its `SWEEPKY_HOME` and working directory, `stdin` as its standard input,
/// and the buffer that keeps what it writes to standard error.
fn context(
    testnet: &EphemeralTestnet,
    home: &Path,
    stdin: impl BufRead + Send + 'static,
) -> (Context, SharedBuffer) {
    // `local_url()` ends with `/`, so this is `http://localhost:<port>/inbox`.
    let relay = format!("{}inbox", testnet.http_relay().local_url());
    let stderr = SharedBuffer::default();
    let ctx = Context {
        network: Network::injected(
            testnet.sdk().expect("client"),
            relay,
            testnet.homeserver_app().public_key(),
        ),
        dirs: Dirs::resolve(None, Some(home.as_os_str())).expect("absolute"),
        cwd: home.to_path_buf(),
        stdin: StdinReader::new(stdin),
        // A clone of the handle: the context writes into the buffer the
        // test reads.
        stderr: StderrWriter::new(stderr.clone()),
        // No --passphrase-file: the secret files are written plain, as the
        // test reads them.
        passphrase: None,
        // git is found through this test's PATH, and sees none of the
        // proxy or CA variables: the targets come from the fixture
        // repository on this disk.
        git_env: GitEnv::capture(|name| {
            if name == "PATH" {
                std::env::var_os(name)
            } else {
                None
            }
        }),
        // Targets from the fixture repository, so nothing reaches a real
        // repository host.
        targets: fixture_targets(),
    };
    (ctx, stderr)
}

/// The playbook B's sweeps name: the pinned Cloudflare skill.
const PLAYBOOK: &str = "cloudflare/security-audit@c1c8a8c";

/// The playbook C's sweep names: the one `fixtures/common/findings.json`
/// names, which fits 01's pattern for a sweep record's `playbook`.
const COMMON_PLAYBOOK: &str = "careful-review";

/// The three files of `fixtures/cloudflare/`, the synthetic run directory
/// of a Cloudflare-format sweep.
const CLOUDFLARE_FILES: [&str; 3] = ["REPORT.md", "coverage-ledger.json", "findings.json"];

/// The four files of `fixtures/common/`, the synthetic run directory of a
/// common-format sweep. `capture.bin` is not text, so `submit` leaves it
/// out of the package.
const COMMON_FILES: [&str; 4] = [
    "REPORT.md",
    "capture.bin",
    "findings.json",
    "notes/triage.md",
];

/// `fixtures/<dir>/<name>`, a file of one of the synthetic run directories.
fn run_dir_fixture(dir: &str, name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(dir)
        .join(name)
}

/// `fixtures/cloudflare/<name>`.
fn cloudflare_fixture(name: &str) -> PathBuf {
    run_dir_fixture("cloudflare", name)
}

/// The device key of the install whose directories are `dirs`, read from
/// its plain `device.key` (the test passes no `--passphrase-file`): the
/// age identity string alone, which goes straight into a `SecretString`.
fn device_identity(dirs: &Dirs) -> DeviceIdentity {
    let bytes = Zeroizing::new(fs::read(dirs.device_key_file()).expect("device.key"));
    let text = std::str::from_utf8(&bytes).expect("UTF-8");
    DeviceIdentity::from_secret(&SecretString::from(text)).expect("an age identity")
}

/// The pubky `ctx`'s install is logged in as, from its `login.json`.
fn logged_in(ctx: &Context) -> Pubky {
    json(&ctx.dirs.login_file())["pubky"]
        .as_str()
        .expect("a pubky")
        .parse()
        .expect("a pubky")
}

/// The ids of the sweep directories in `sweeps`, a project's `sweeps/`:
/// none before the project's first `run` makes the directory.
fn sweep_ids(sweeps: &Path) -> Vec<RecordId> {
    let entries = match fs::read_dir(sweeps) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Vec::new(),
        entries => entries.expect("sweeps/"),
    };
    entries
        .map(|entry| {
            let name = entry.expect("an entry").file_name();
            name.to_str().expect("UTF-8").parse().expect("a record id")
        })
        .collect()
}

/// Has `ctx` run `bounty` once more in its project, whose `sweeps/` is
/// `sweeps`, and fills the new sweep's `audit/` with `files` of the run
/// directory `fixtures/<dir>/`, as the playbook would leave them. Returns
/// the new sweep's id.
async fn fixture_sweep(
    ctx: &Context,
    bounty: &BountyRef,
    sweeps: &Path,
    dir: &str,
    files: &[&str],
) -> RecordId {
    let before = sweep_ids(sweeps);
    sweepky(ctx, &["run", &bounty.to_string()])
        .await
        .expect("the bounty runs");
    let id = sweep_ids(sweeps)
        .into_iter()
        .find(|id| !before.contains(id))
        .expect("a new sweep directory");
    let audit = sweeps.join(id.to_string()).join("audit");
    // `&name` copies each `&str` out of the borrowed slice.
    for &name in files {
        let copy = audit.join(name);
        // `create_dir_all` makes `audit/` and the directory a file sits in
        // below it, such as `notes/`. `parent` is `None` only for a path
        // with nothing above it, which a file under `audit/` is not.
        fs::create_dir_all(copy.parent().expect("a directory")).expect("audit/");
        fs::copy(run_dir_fixture(dir, name), copy).expect("copy");
    }
    id
}

/// [`fixture_sweep`] from `fixtures/cloudflare/`, as Cloudflare's skill
/// would leave it.
async fn cloudflare_sweep(ctx: &Context, bounty: &BountyRef, sweeps: &Path) -> RecordId {
    fixture_sweep(ctx, bounty, sweeps, "cloudflare", &CLOUDFLARE_FILES).await
}

/// `user`'s sweep record `id`, read anonymously within the record cap.
async fn read_sweep(testnet: &EphemeralTestnet, user: &PublicKey, id: RecordId) -> Sweep {
    let record = get_capped(testnet, user, &paths::sweep_record(id), MAX_RECORD_BYTES).await;
    Sweep::from_json(&record).expect("a sweep record")
}

/// `user`'s record at `path` as JSON, read anonymously within the record
/// cap.
async fn read_json(testnet: &EphemeralTestnet, user: &PublicKey, path: &str) -> Value {
    serde_json::from_slice(&get_capped(testnet, user, path, MAX_RECORD_BYTES).await).expect("JSON")
}

/// `owner`'s `bounties/<id>.discovered.json`, read anonymously within the
/// record cap and parsed by core, as `pull` reads it.
async fn read_discovered(
    testnet: &EphemeralTestnet,
    owner: &PublicKey,
    id: RecordId,
) -> Discovered {
    let record = get_capped(testnet, owner, &paths::discovered(id), MAX_RECORD_BYTES).await;
    Discovered::from_json(&record).expect("a discovered-sweeps record")
}

/// The cursor the install whose directories are `dirs` keeps for `owner`
/// on `homeserver`, in its `feed-cursors.json`: where its next `pull` reads
/// that homeserver's events feed from. Read from the file's documented
/// shape, `{owners: {<owner>: {cursors: {<homeserver>: "<event id>"}}}}`,
/// as the library keeps its reader private.
fn feed_cursor(dirs: &Dirs, owner: Pubky, homeserver: Pubky) -> EventCursor {
    json(&dirs.data().join("feed-cursors.json"))["owners"][owner.to_string()]["cursors"]
        [homeserver.to_string()]
    .as_str()
    .expect("a cursor")
    .parse()
    .expect("an event id")
}

/// The events of the testnet homeserver's `/events/` feed after `cursor`,
/// from one anonymous `GET` through a fresh client: the request `pull`
/// sends, which this test cannot call because the module is private to the
/// crate. The body is read as [`get_capped`] reads one, under core's feed
/// cap, and parsed by core. The test's homeserver holds far fewer events
/// than the one page of 1000 asked for.
async fn events_after(testnet: &EphemeralTestnet, cursor: EventCursor) -> Vec<FeedEvent> {
    const PAGE: usize = 1000;
    let homeserver = testnet.homeserver_app().public_key();
    let url = Url::parse(&format!(
        "https://{}/events/?cursor={cursor}&limit={PAGE}",
        homeserver.z32()
    ))
    .expect("a URL");
    // `request_async` resolves the homeserver's key through pkarr, as the
    // CLI's own requests do.
    let mut response = testnet
        .client()
        .expect("client")
        .request_async(Method::GET, url)
        .await
        .expect("a request")
        .send()
        .await
        .expect("an answer");
    assert!(response.status().is_success(), "{}", response.status());
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.expect("the body reads") {
        body.extend_from_slice(&chunk);
        assert!(
            body.len() <= MAX_FEED_BODY_BYTES,
            "the feed is over the cap"
        );
    }
    let page = parse_feed(&body).expect("a feed page");
    assert!(page.events().len() < PAGE, "one page holds every event");
    page.events().to_vec()
}

/// Where the finding with id `id` is in `findings`.
fn index_of(findings: &Findings, id: &str) -> usize {
    findings
        .findings
        .iter()
        .position(|finding| finding.id == id)
        .expect("a finding with the id")
}

/// The one group of `groups`, a `groups.json`, whose members hold finding
/// `index` of `sweep`.
fn group_of(groups: &Value, sweep: SweepRef, index: usize) -> &Value {
    let url = sweep.to_string();
    let mut holding = groups["groups"]
        .as_array()
        .expect("groups")
        .iter()
        .filter(|group| {
            group["members"]
                .as_array()
                .expect("members")
                .iter()
                .any(|member| member["sweep"] == url && member["index"] == index)
        });
    let group = holding.next().expect("a group holds the finding");
    assert!(holding.next().is_none(), "two groups hold the finding");
    group
}

/// Whether anyone can see `user`'s package of the sweep `id`.
async fn package_exists(testnet: &EphemeralTestnet, user: &PublicKey, id: RecordId) -> bool {
    testnet
        .sdk()
        .expect("client")
        .public_storage()
        .exists((user, paths::sweep_package(id).as_str()))
        .await
        .expect("the path is public")
}

/// A signup token in a form the homeserver rejects (400) before it looks at
/// anything else, so a `login` that sent a signup with it would fail. Passed
/// where `login` must not sign up, it proves that no signup was sent.
const TRIPWIRE_TOKEN: &str = "not-a-signup-code";

// `multi_thread`: tokio's runtime with worker threads, the kind
// `#[tokio::main]` builds for the binary, rather than `#[tokio::test]`'s
// default of one thread, so the two `submit`s P2b runs at once run as they
// would in the binary.
#[tokio::test(flavor = "multi_thread")]
#[pubky_testnet::test]
async fn end_to_end() {
    let testnet = EphemeralTestnet::builder()
        .with_http_relay()
        .build()
        .await
        .expect("the testnet starts");
    let homeserver = testnet.homeserver_app().public_key();

    // SWEEPKY_HOME for the throwaway identity: a fresh directory that
    // deletes itself. An empty standard input: P2a's commands ask nothing,
    // and a question would read the end of the input, which is no.
    let home = tempfile::tempdir().expect("temp dir");
    let (ctx, stderr) = context(&testnet, home.path(), io::empty());
    // The test looks at the files through the context's own `Dirs`.
    let dirs = &ctx.dirs;

    // ----- P2a: the throwaway identity -----

    // `login --identity throwaway` creates the identity, signs it up on the
    // testnet's homeserver and logs in.
    let report = sweepky(&ctx, &["login", "--identity", "throwaway"])
        .await
        .expect("the first login");
    assert!(report.text().contains("Signed up"), "{}", report.text());
    assert_eq!(stderr.text(), "", "nothing to warn about on a testnet");

    let config = dirs.config();
    let key_file = config.join("identities/throwaway.key");
    let details_file = config.join("identities/throwaway.json");
    let details = json(&details_file);
    assert_eq!(details["name"], "throwaway");
    assert_eq!(details["homeserver"], homeserver.z32());
    assert_eq!(details["signedUp"], true);
    let pubky = details["pubky"].as_str().expect("a pubky").to_owned();

    // Its pkarr record names the testnet's homeserver, as a fresh client
    // with nothing cached resolves it.
    let user = PublicKey::try_from_z32(&pubky).expect("a key");
    let resolved = testnet
        .sdk()
        .expect("client")
        .get_homeserver_of(&user)
        .await
        .expect("pkarr resolves");
    assert_eq!(resolved, Some(homeserver.clone()));

    // The secret is in a 0600 file in a 0700 config directory, and so is
    // everything else login wrote.
    assert_eq!(mode(config), 0o700);
    assert_eq!(mode(&config.join("identities")), 0o700);
    assert_eq!(mode(&key_file), 0o600);
    assert_eq!(mode(&details_file), 0o600);
    assert_eq!(mode(&dirs.login_file()), 0o600);
    assert_eq!(mode(&dirs.credential_lock_file()), 0o600);
    let login = json(&dirs.login_file());
    assert_eq!(login["kind"], "identity");
    assert_eq!(login["name"], "throwaway");
    assert_eq!(login["pubky"], pubky.as_str());

    // The shared tail: this install's device key, in a 0600 file that holds
    // the identity string alone, published as `keys/<deviceId>.json`, the
    // write that proves the identity may write under `/pub/sweepky/`.
    let device_id = login["deviceId"].as_str().expect("a device id").to_owned();
    let device_key_file = dirs.device_key_file();
    assert_eq!(mode(&device_key_file), 0o600);
    // Kept to compare with after the later logins, in a buffer that wipes
    // itself when the test ends.
    let device_key_bytes = Zeroizing::new(fs::read(&device_key_file).expect("readable"));
    assert_eq!(
        device_key_bytes.len(),
        74,
        "the identity string and nothing else"
    );
    let secret = SecretString::from(String::from_utf8(device_key_bytes.to_vec()).expect("UTF-8"));
    let device = DeviceIdentity::from_secret(&secret).expect("an age identity");

    // Anyone can read the record, anonymously, and it is read as the CLI
    // reads every record: never more than MAX_RECORD_BYTES.
    let path = format!("/pub/sweepky/keys/{device_id}.json");
    let record = get_capped(&testnet, &user, &path, MAX_RECORD_BYTES).await;
    let key = DeviceKey::from_json(&record).expect("a device key record");
    assert_eq!(key.revoked_at, None);
    assert_eq!(key.label, "sweepky-cli");
    assert_eq!(key.recipient, device.recipient().to_string());
    assert_eq!(
        key.encryption_recipient().expect("usable"),
        device.recipient()
    );

    // installs.json lists the id under this owner, with the key it
    // published, and the report says to back the config directory up.
    let install_entry = json!([{
        "deviceId": device_id,
        "recipient": device.recipient().to_string(),
    }]);
    assert_eq!(mode(&dirs.installs_file()), 0o600);
    assert_eq!(
        json(&dirs.installs_file())["owners"][pubky.as_str()],
        install_entry
    );
    let reminder = format!("Back up {}", config.display());
    assert!(report.text().contains(&reminder), "{}", report.text());

    // A second `login --identity throwaway` reuses the identity and does not
    // sign up again: the tripwire token would make a signup fail.
    let report = sweepky(
        &ctx,
        &[
            "login",
            "--identity",
            "throwaway",
            "--signup-token",
            TRIPWIRE_TOKEN,
        ],
    )
    .await
    .expect("the second login");
    assert!(!report.text().contains("Signed up"), "{}", report.text());
    assert!(report.text().contains("still unspent"), "{}", report.text());
    assert_eq!(json(&details_file), details, "the details are unchanged");
    // It reuses this install's device key too, after reading its record
    // back: the same id in login.json, the same secret in device.key, and
    // still one key under the identity's keys/.
    assert!(
        report.text().contains("Reusing this install's device key"),
        "{}",
        report.text()
    );
    assert_eq!(json(&dirs.login_file())["deviceId"], device_id.as_str());
    // `assert!` rather than `assert_eq!`, which would print both secrets if
    // it failed.
    assert!(
        *Zeroizing::new(fs::read(&device_key_file).expect("readable")) == *device_key_bytes,
        "device.key was rewritten"
    );
    assert_eq!(
        list_keys(&testnet, &user).await,
        [format!("pubky://{pubky}/pub/sweepky/keys/{device_id}.json")]
    );

    // The key file alone, as P2c's second install copies it: login rebuilds
    // the details from the key and the pkarr record, without a signup.
    fs::remove_file(&details_file).expect("remove the details");
    sweepky(
        &ctx,
        &[
            "login",
            "--identity",
            "throwaway",
            "--signup-token",
            TRIPWIRE_TOKEN,
        ],
    )
    .await
    .expect("a login with the key file alone");
    assert_eq!(json(&details_file), details, "the details are rebuilt");

    // Details that say the signup never went through, as after a crash
    // between the signup and the details' rewrite: login signs up again, the
    // homeserver answers 409 (the account exists), and that counts as done.
    let mut not_recorded = details.clone();
    not_recorded["signedUp"] = Value::Bool(false);
    fs::write(
        &details_file,
        serde_json::to_vec(&not_recorded).expect("JSON"),
    )
    .expect("write");
    let report = sweepky(&ctx, &["login", "--identity", "throwaway"])
        .await
        .expect("a login after an unrecorded signup");
    assert!(
        report.text().contains("Already signed up"),
        "{}",
        report.text()
    );
    assert_eq!(json(&details_file)["signedUp"], true);
    assert_eq!(stderr.text(), "", "no warning on the way");

    // None of the logins after the first made another device key: login.json
    // still names the first one, and it is the only install of this owner.
    assert_eq!(json(&dirs.login_file())["deviceId"], device_id.as_str());
    assert_eq!(
        json(&dirs.installs_file())["owners"][pubky.as_str()],
        install_entry
    );

    // `keys list` lists this install's key, in use, and raises no alarm.
    let own_line = format!("keys/{device_id}.json: this install; in use");
    let report = sweepky(&ctx, &["keys", "list"]).await.expect("keys list");
    let text = report.text();
    assert!(text.contains(&own_line), "{text}");
    assert!(!text.contains("alarm"), "{text}");

    // This install's own record rewritten with another valid, unrevoked
    // key, by someone holding the identity's credentials: the id is known,
    // so only the comparison with the key installs.json records for it
    // tells. `keys list` raises the alarm and no longer shows the key in
    // use, without printing either key. The original record then goes back,
    // so the steps below find this install's key as login published it.
    let original: Value = serde_json::from_slice(&record).expect("JSON");
    let intruder = DeviceIdentity::generate();
    let mut rewritten = original.clone();
    rewritten["recipient"] = json!(intruder.recipient().to_string());
    publish_as(&testnet, &key_file, &path, &rewritten).await;
    let report = sweepky(&ctx, &["keys", "list"]).await.expect("keys list");
    let text = report.text();
    assert!(
        text.contains(&format!(
            "alarm: keys/{device_id}.json, this install's own device key record, does not hold \
             this install's key"
        )),
        "{text}"
    );
    assert!(!text.contains(&own_line), "{text}");
    for recipient in [intruder.recipient(), device.recipient()] {
        assert!(!text.contains(&recipient.to_string()), "{text}");
    }
    publish_as(&testnet, &key_file, &path, &original).await;
    let report = sweepky(&ctx, &["keys", "list"]).await.expect("keys list");
    assert!(report.text().contains(&own_line), "{}", report.text());

    // A second key under the throwaway's keys/, written with the identity's
    // own root key, standing in for another install or an operator. It
    // carries a field this build does not know, which `keys revoke` keeps.
    let other_id = "another-install";
    let other_path = format!("/pub/sweepky/keys/{other_id}.json");
    let other_key = DeviceIdentity::generate();
    let other_record = json!({
        "schemaVersion": 1,
        "alg": "age-x25519",
        "recipient": other_key.recipient().to_string(),
        "label": "another install",
        "createdAt": "2026-10-16T09:41:07Z",
        "revokedAt": null,
        "addedLater": { "kept": true },
    });
    publish_as(&testnet, &key_file, &other_path, &other_record).await;

    // Logging in again keeps this install's key and id, and the report
    // raises the alarm for the new id, with the fix.
    let report = sweepky(&ctx, &["login", "--identity", "throwaway"])
        .await
        .expect("a login with an unknown key under keys/");
    let text = report.text();
    assert!(text.contains("Reusing this install's device key"), "{text}");
    assert!(
        text.contains(&format!("alarm: keys/{other_id}.json")),
        "{text}"
    );
    assert!(
        text.contains(&format!("`sweepky keys revoke {other_id}`")),
        "{text}"
    );
    assert!(
        !text.contains(&format!("alarm: keys/{device_id}.json")),
        "{text}"
    );
    assert_eq!(json(&dirs.login_file())["deviceId"], device_id.as_str());

    // `keys list` lists both and flags the new one as unknown, without ever
    // printing a recipient.
    let report = sweepky(&ctx, &["keys", "list"]).await.expect("keys list");
    let text = report.text();
    assert!(text.contains(&own_line), "{text}");
    assert!(
        text.contains(&format!("keys/{other_id}.json: UNKNOWN")),
        "{text}"
    );
    assert!(
        text.contains(&format!("alarm: keys/{other_id}.json")),
        "{text}"
    );
    for recipient in [other_key.recipient(), device.recipient()] {
        assert!(!text.contains(&recipient.to_string()), "{text}");
    }

    // `keys revoke` sets the new key's revokedAt and keeps every other
    // field, the unknown one included; this install's key stays in use.
    let report = sweepky(&ctx, &["keys", "revoke", other_id])
        .await
        .expect("keys revoke");
    let text = report.text();
    assert!(
        text.contains(&format!("Revoked keys/{other_id}.json")),
        "{text}"
    );
    let revoked_bytes = get_capped(&testnet, &user, &other_path, MAX_RECORD_BYTES).await;
    let revoked = DeviceKey::from_json(&revoked_bytes).expect("a device key record");
    let revoked_at = revoked.revoked_at.expect("revokedAt is set");
    let mut expected = other_record;
    expected["revokedAt"] = json!(revoked_at.as_str());
    assert_eq!(
        serde_json::from_slice::<Value>(&revoked_bytes).expect("JSON"),
        expected
    );
    let own = get_capped(&testnet, &user, &path, MAX_RECORD_BYTES).await;
    let own = DeviceKey::from_json(&own).expect("a device key record");
    assert_eq!(
        own.revoked_at, None,
        "this install's key is left for logout"
    );

    // Revoked, the unknown key is settled: still marked unknown, no alarm.
    let report = sweepky(&ctx, &["keys", "list"]).await.expect("keys list");
    let text = report.text();
    assert!(
        text.contains(&format!(
            "keys/{other_id}.json: UNKNOWN: not created by this owner's installs here; revoked {}",
            revoked_at.as_str()
        )),
        "{text}"
    );
    assert!(!text.contains("alarm"), "{text}");
    assert_eq!(stderr.text(), "", "nothing on standard error");

    // `circle create` makes the throwaway's circle, with the throwaway as
    // its admin and its first member.
    let report = sweepky(&ctx, &["circle", "create", "Throwaway circle"])
        .await
        .expect("circle create");
    assert!(
        report
            .text()
            .contains("Created the circle Throwaway circle"),
        "{}",
        report.text()
    );

    // `circle add` of a synthetic member, a key made for this run and used
    // nowhere else, given in the SDK's `pubky<z32>` spelling.
    let member = Keypair::random().public_key();
    let member_z32 = member.z32();
    let report = sweepky(
        &ctx,
        &[
            "circle",
            "add",
            &member.to_string(),
            "--label",
            "synthetic member",
        ],
    )
    .await
    .expect("circle add");
    assert!(
        report.text().contains(&format!("Added {member_z32}")),
        "{}",
        report.text()
    );

    // Anyone can read the roster, and it lists the admin in `members` as
    // well as in `admin`, then the member with its label.
    let roster = get_capped(
        &testnet,
        &user,
        "/pub/sweepky/circle.json",
        MAX_RECORD_BYTES,
    )
    .await;
    let circle = Circle::from_json(&roster).expect("a circle record");
    let admin: Pubky = pubky.parse().expect("a pubky");
    let added: Pubky = member_z32.parse().expect("a pubky");
    assert_eq!(circle.name, "Throwaway circle");
    assert_eq!(circle.admin, admin);
    let listed: Vec<(Pubky, Option<&str>)> = circle
        .members
        .iter()
        .map(|entry| (entry.pubky, entry.label.as_deref()))
        .collect();
    assert_eq!(listed, [(admin, None), (added, Some("synthetic member"))]);

    // `circle show`, with no argument, shows this identity's circle: the
    // admin and the member.
    let report = sweepky(&ctx, &["circle", "show"])
        .await
        .expect("circle show");
    let text = report.text();
    assert!(text.contains(&format!("Admin: {pubky}\n")), "{text}");
    assert!(text.contains(&format!("  {pubky} (admin)\n")), "{text}");
    assert!(
        text.contains(&format!("  {member_z32}, label synthetic member\n")),
        "{text}"
    );

    // `circle remove`, given the raw z-base32 spelling this time: the key is
    // the same member, compared by its bytes. `circle show <admin>` then
    // lists the admin only.
    let report = sweepky(&ctx, &["circle", "remove", &member_z32])
        .await
        .expect("circle remove");
    assert!(
        report.text().contains(&format!("Removed {member_z32}")),
        "{}",
        report.text()
    );
    let report = sweepky(&ctx, &["circle", "show", &pubky])
        .await
        .expect("circle show of the admin");
    let text = report.text();
    assert!(text.contains("Members (1):\n"), "{text}");
    assert!(text.contains(&format!("  {pubky} (admin)\n")), "{text}");
    assert!(!text.contains(&member_z32), "{text}");
    assert_eq!(stderr.text(), "", "nothing on standard error");

    // `logout`, the last of P2a's steps: it revokes this install's key while
    // its session is live, signs out, forgets the identity and deletes this
    // install's files.
    let report = sweepky(&ctx, &["logout"]).await.expect("logout");
    let text = report.text();
    assert!(
        text.contains(&format!("Revoked keys/{device_id}.json")),
        "{text}"
    );
    // Anyone reading the record now sees it revoked, with the same key in
    // it: sweepers no longer encrypt to it.
    let own = get_capped(&testnet, &user, &path, MAX_RECORD_BYTES).await;
    let own = DeviceKey::from_json(&own).expect("a device key record");
    assert!(
        own.revoked_at.is_some(),
        "logout revoked this install's key"
    );
    assert_eq!(own.recipient, device.recipient().to_string());
    // The throwaway identity is forgotten and this install's files are gone;
    // the lock file stays, as it always does.
    for gone in [
        &key_file,
        &details_file,
        &device_key_file,
        &dirs.login_file(),
    ] {
        assert_gone(gone);
    }
    assert_eq!(
        json(&dirs.installs_file())["owners"].get(pubky.as_str()),
        None,
        "the owner's install entry is gone"
    );
    assert_eq!(mode(&dirs.credential_lock_file()), 0o600);
    // Logged out: a command that needs the login says so.
    let err = sweepky(&ctx, &["keys", "revoke", "x"])
        .await
        .expect_err("no login any more");
    assert!(format!("{err:#}").contains("not logged in"), "{err:#}");
    assert_eq!(stderr.text(), "", "nothing on standard error");

    // ----- P2b: A posts a closed bounty for a circle that holds B -----

    // A, the owner, and B, a member of A's circle, each with a SWEEPKY_HOME
    // of their own. A answers yes to the one question `post` asks; B is
    // asked nothing. `mut`: P2c gives A's standard input a second answer.
    let a_home = tempfile::tempdir().expect("temp dir");
    let (mut a, a_stderr) = context(&testnet, a_home.path(), Cursor::new(b"y\n".to_vec()));
    let b_home = tempfile::tempdir().expect("temp dir");
    // `mut`: B's working directory becomes its project before `run`.
    let (mut b, b_stderr) = context(&testnet, b_home.path(), io::empty());
    sweepky(&a, &["login", "--identity", "a"])
        .await
        .expect("A logs in");
    sweepky(&b, &["login", "--identity", "b"])
        .await
        .expect("B logs in");
    let a_pubky = logged_in(&a);
    let b_pubky = logged_in(&b);
    let a_user = PublicKey::try_from_z32(&a_pubky.to_string()).expect("a key");

    // A's circle, with B in it, as anyone reads it.
    sweepky(&a, &["circle", "create", "A's circle"])
        .await
        .expect("circle create");
    sweepky(&a, &["circle", "add", &b_pubky.to_string(), "--label", "B"])
        .await
        .expect("circle add");
    let roster = get_capped(
        &testnet,
        &a_user,
        "/pub/sweepky/circle.json",
        MAX_RECORD_BYTES,
    )
    .await;
    let roster = Circle::from_json(&roster).expect("a circle record");
    assert_eq!(roster.admin, a_pubky);
    assert!(roster.is_in_roster(b_pubky));

    // The draft A's agent would write, in a file of its own: one target of
    // each kind in the fixture repository.
    const TITLE: &str = "Session handling in the fixture repository";
    const BRIEF: &str = "Look at how sessions expire and are revoked.\n\n- `session.rs`\n";
    let drafts = tempfile::tempdir().expect("temp dir");
    let draft = drafts.path().join("bounty.json");
    let draft_json = json!({
        "title": TITLE,
        "brief": BRIEF,
        "playbook": "cloudflare/security-audit@c1c8a8c",
        "targets": [
            { "kind": "repo", "repo": FIXTURE_REPO, "ref": "main", "paths": ["src/auth/"] },
            { "kind": "commit", "repo": FIXTURE_REPO, "ref": "main" },
            { "kind": "pr", "repo": FIXTURE_REPO, "number": 1 },
        ],
    });
    fs::write(&draft, serde_json::to_vec(&draft_json).expect("JSON")).expect("written");

    let report = sweepky(&a, &["post", draft.to_str().expect("a UTF-8 path")])
        .await
        .expect("A posts the bounty");

    // A was shown the bounty and asked once; B, nothing.
    let shown = a_stderr.text();
    assert!(shown.contains(&format!("  Title: {TITLE}\n")), "{shown}");
    assert_eq!(shown.matches("[y/N] ").count(), 1, "{shown}");
    assert_eq!(b_stderr.text(), "", "B is asked nothing");
    // The report's last line is the bounty's URL, under A's own pubky.
    let url = report.text().lines().last().expect("a report");
    let posted: BountyRef = url.parse().expect("a bounty URL");
    assert_eq!(posted.owner, a_pubky);

    // Anyone can read the bounty, closed and open for sweeps, every target
    // pinned to the fixture's SHAs: the repo at M narrowed to `src/auth/`,
    // the commit M, and pull request 1 based on M with head F2, the two
    // meeting at B.
    let record = get_capped(
        &testnet,
        &a_user,
        &paths::bounty(posted.id),
        MAX_RECORD_BYTES,
    )
    .await;
    let bounty = Bounty::from_json(&record).expect("a bounty record");
    assert!(!bounty.open, "a closed bounty");
    assert_eq!(bounty.status().as_known(), Some(KnownBountyStatus::Open));
    assert_eq!(
        (bounty.title.as_str(), bounty.brief.as_str()),
        (TITLE, BRIEF)
    );
    let targets: Vec<KnownTarget> = bounty
        .targets
        .iter()
        .map(|target| target.known().expect("well formed").expect("a known kind"))
        .collect();
    let [
        KnownTarget::Repo(narrowed),
        KnownTarget::Commit(commit),
        KnownTarget::Pr(pr),
    ] = targets.as_slice()
    else {
        panic!("a repo, a commit and a pr target: {targets:?}");
    };
    let (m, f2, b_sha) = (recorded_sha("M"), recorded_sha("F2"), recorded_sha("B"));
    assert_eq!(narrowed.rev(), &m);
    assert_eq!(
        narrowed
            .paths()
            .map(|paths| paths.iter().map(RepoPath::as_str).collect::<Vec<_>>()),
        Some(vec!["src/auth/"])
    );
    assert_eq!(commit.rev(), &m);
    assert_eq!(pr.number().get(), 1);
    assert_eq!((pr.base(), pr.head(), pr.merge_base()), (&m, &f2, &b_sha));

    // ----- P2b: B runs A's bounty in an init project -----

    // B's project, made by the minimal `init`; B then works in it, as
    // `run` must be run in the project's own directory.
    let b_projects = tempfile::tempdir().expect("temp dir");
    let project = b_projects.path().join("project");
    sweepky(&b, &["init", project.to_str().expect("a UTF-8 path")])
        .await
        .expect("B's init");
    b.cwd = project.clone();

    let report = sweepky(&b, &["run", &posted.to_string()])
        .await
        .expect("B runs A's bounty");

    // B was shown why it may run the bounty, and the report says what to
    // run next. One sweep directory, named by the sweep's id.
    let shown = b_stderr.text();
    assert!(shown.contains(&format!("Bounty {posted}\n")), "{shown}");
    assert!(
        shown.contains("Closed: you are in its owner's circle"),
        "{shown}"
    );
    let sweeps = project.join("sweeps");
    let ids: Vec<String> = fs::read_dir(&sweeps)
        .expect("sweeps/")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .into_string()
                .expect("UTF-8")
        })
        .collect();
    let [id] = ids.as_slice() else {
        panic!("one sweep directory: {ids:?}");
    };
    let sweep = SweepRef {
        sweeper: b_pubky,
        id: id.parse::<RecordId>().expect("a record id"),
    };
    let text = report.text();
    for next in [
        "claude --setting-sources project,local".to_owned(),
        "/sweepky".to_owned(),
        format!("sweepky submit --run-dir sweeps/{id}"),
    ] {
        assert!(text.contains(&next), "{next} not in {text}");
    }

    // Anyone can read B's sweep record: running, for A's bounty, with all
    // three targets, and the placeholder playbook, since B's `init`
    // recorded none.
    let b_user = PublicKey::try_from_z32(&b_pubky.to_string()).expect("a key");
    let record = get_capped(
        &testnet,
        &b_user,
        &paths::sweep_record(sweep.id),
        MAX_RECORD_BYTES,
    )
    .await;
    let record = Sweep::from_json(&record).expect("a sweep record");
    assert_eq!(record.status.as_known(), Some(KnownSweepStatus::Running));
    assert_eq!(record.bounty, posted);
    let target_ids: Vec<&str> = record.targets.iter().map(|id| id.as_str()).collect();
    assert_eq!(target_ids, ["t1", "t2", "t3"]);
    assert_eq!(record.playbook.as_str(), "unspecified");
    assert_eq!(record.finished_at, None);

    // Each target holds its pinned commit, checked out detached, so
    // `.git/HEAD` is the SHA itself: the repo and the commit target at M,
    // the pull request at its head F2.
    // The fixture's planted agent files are gone from each, and scope.json
    // lists them for that target.
    let planted = [
        ".claude/",
        ".mcp.json",
        "AGENTS.md",
        "CLAUDE.local.md",
        "CLAUDE.md",
        "src/auth/CLAUDE.md",
    ];
    let sweep_dir = sweeps.join(id);
    let scope = json(&sweep_dir.join("scope.json"));
    for (index, (tid, commit)) in [("t1", &m), ("t2", &m), ("t3", &f2)]
        .into_iter()
        .enumerate()
    {
        let target = sweep_dir.join("target").join(tid);
        assert_eq!(
            fs::read_to_string(target.join(".git/HEAD")).expect("HEAD"),
            format!("{commit}\n"),
            "{tid}"
        );
        assert_eq!(scope["targets"][index]["id"], tid);
        assert_eq!(scope["targets"][index]["stripped"], json!(planted), "{tid}");
        for relative in planted {
            assert_gone(&target.join(relative));
        }
    }

    // The per-sweep marker names the sweep and the bounty.
    let marker = json(&sweep_dir.join(".sweepky/sweep.json"));
    assert_eq!(marker["sweep"], sweep.to_string());
    assert_eq!(marker["bounty"], posted.to_string());
    assert_eq!(marker["targets"], json!(["t1", "t2", "t3"]));

    // What B fetched, kept under B's data directory, out of the agent's
    // reach, 0600: what B's submit takes the manifest's commits from.
    let snapshot_file = b.dirs.data().join(format!("sweeps/{id}.json"));
    assert_eq!(mode(&snapshot_file), 0o600);

    // ----- P2b: B submits a Cloudflare-format sweep -----

    // What the agent leaves, Cloudflare's skill having written its output
    // into audit/: the synthetic Cloudflare run directory.
    let audit = sweep_dir.join("audit");
    fs::create_dir(&audit).expect("audit/");
    for name in CLOUDFLARE_FILES {
        fs::copy(cloudflare_fixture(name), audit.join(name)).expect("copy");
    }
    let submit_args = [
        "submit",
        "--run-dir",
        &format!("sweeps/{id}"),
        "--playbook",
        PLAYBOOK,
    ];

    // A rewrites t1's pinned revision, M, to F2 after B fetched it, with
    // A's own root key, as A's homeserver could too. B's submit refuses:
    // its manifest would say F2 was swept. Nothing is published, and the
    // snapshot stays for the next try.
    let as_posted: Value = serde_json::from_slice(
        &get_capped(
            &testnet,
            &a_user,
            &paths::bounty(posted.id),
            MAX_RECORD_BYTES,
        )
        .await,
    )
    .expect("JSON");
    let mut rewritten = as_posted.clone();
    rewritten["targets"][0]["rev"] = json!(f2.as_str());
    let a_key_file = a.dirs.config().join("identities/a.key");
    publish_as(&testnet, &a_key_file, &paths::bounty(posted.id), &rewritten).await;
    let error = sweepky(&b, &submit_args)
        .await
        .expect_err("the bounty changed since the run");
    let message = format!("{error:#}");
    assert!(
        message.contains("the bounty's targets changed since this sweep was run"),
        "{message}"
    );
    assert!(!package_exists(&testnet, &b_user, sweep.id).await);
    assert_eq!(
        read_sweep(&testnet, &b_user, sweep.id)
            .await
            .status
            .as_known(),
        Some(KnownSweepStatus::Running)
    );
    assert_eq!(mode(&snapshot_file), 0o600);

    // A puts the bounty back as posted, and B's submit goes through.
    publish_as(&testnet, &a_key_file, &paths::bounty(posted.id), &as_posted).await;
    let report = sweepky(&b, &submit_args)
        .await
        .expect("B submits the sweep");
    assert!(
        report.text().contains(&sweep.to_string()),
        "{}",
        report.text()
    );
    // B was shown the conversion and the packaged files, and asked
    // nothing: this is B's first submit to A, so A's keys are pinned
    // without a word.
    let shown = b_stderr.text();
    assert!(shown.contains("Cloudflare's format"), "{shown}");
    for name in CLOUDFLARE_FILES {
        assert!(shown.contains(&format!("  audit/{name} (")), "{shown}");
    }
    assert!(!shown.contains("[y/N]"), "{shown}");

    // Anyone can read B's sweep record: done, finished, with the playbook
    // given.
    let record = get_capped(
        &testnet,
        &b_user,
        &paths::sweep_record(sweep.id),
        MAX_RECORD_BYTES,
    )
    .await;
    let record = Sweep::from_json(&record).expect("a sweep record");
    assert_eq!(record.status.as_known(), Some(KnownSweepStatus::Done));
    assert!(record.finished_at.is_some());
    assert_eq!(record.playbook.as_str(), PLAYBOOK);

    // Anyone can download the package, within the cap a reader applies;
    // A's device key opens it, and its findings are the fixture's,
    // converted.
    let sealed = get_capped(
        &testnet,
        &b_user,
        &paths::sweep_package(sweep.id),
        MAX_CIPHERTEXT_BYTES,
    )
    .await;
    let a_device = device_identity(&a.dirs);
    let package = open_package(&sealed, &a_device, &sweep, &record).expect("A opens B's sweep");
    let playbook: Playbook = PLAYBOOK.parse().expect("a playbook");
    let fixture = fs::read(cloudflare_fixture("findings.json")).expect("the fixture");
    let (expected, _) = parse_audit_findings(&fixture, &playbook).expect("findings");
    // `assert!` rather than `assert_eq!`, so a failure prints no finding.
    assert!(package.findings == expected, "the findings differ");
    assert_eq!(package.manifest.sweeper, b_pubky);
    assert_eq!(package.manifest.bounty, posted);

    // B's pin of A's keys: A's one install, its device id and its key, in
    // a 0600 file.
    let pins_file = b.dirs.config().join("owner-keys.json");
    assert_eq!(mode(&pins_file), 0o600);
    assert_eq!(
        json(&pins_file),
        json!({
            "schemaVersion": 1,
            "owners": {
                a_pubky.to_string(): [{
                    "deviceId": json(&a.dirs.login_file())["deviceId"],
                    "recipient": a_device.recipient().to_string(),
                }],
            },
        })
    );
    // The sweep directory is stamped as submitted, and the snapshot of the
    // fetch is gone, the record being final.
    assert!(sweep_dir.join(".sweepky/submitted").is_file());
    assert_gone(&snapshot_file);

    // ----- P2b: a second run, with links planted in its audit/ -----

    sweepky(&b, &["run", &posted.to_string()])
        .await
        .expect("B runs A's bounty again");
    let run2_id = fs::read_dir(&sweeps)
        .expect("sweeps/")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .into_string()
                .expect("UTF-8")
        })
        .find(|name| name != id)
        .expect("a second sweep directory");
    let run2: RecordId = run2_id.parse().expect("a record id");
    let run2_audit = sweeps.join(&run2_id).join("audit");
    fs::create_dir(&run2_audit).expect("audit/");
    fs::copy(
        cloudflare_fixture("findings.json"),
        run2_audit.join("findings.json"),
    )
    .expect("copy");
    // A hard link to B's login.json and a symbolic link to B's device key.
    // The project and B's SWEEPKY_HOME are both under the system's temp
    // directory, so on one filesystem, where a hard link can be made.
    let b_config = b.dirs.config();
    fs::hard_link(
        b_config.join("login.json"),
        run2_audit.join("planted-hard-link"),
    )
    .expect("a hard link");
    symlink(b.dirs.device_key_file(), run2_audit.join("planted-symlink")).expect("a symlink");
    let pins_before = fs::read(&pins_file).expect("the pins");
    let run2_args = [
        "submit",
        "--run-dir",
        &format!("sweeps/{run2_id}"),
        "--playbook",
        PLAYBOOK,
    ];

    // The walk stops at the first entry it refuses, in name order: the
    // hard link, then, once that is gone, the symbolic link.
    for (planted, what) in [
        ("planted-hard-link", "hard links"),
        ("planted-symlink", "a symbolic link"),
    ] {
        let error = sweepky(&b, &run2_args).await.expect_err("refused");
        let message = format!("{error:#}");
        assert!(message.contains(&format!("audit/{planted}")), "{message}");
        assert!(message.contains(what), "{message}");
        fs::remove_file(run2_audit.join(planted)).expect("remove the planted link");
    }

    // Nothing of run 2 reached B's storage, its record still says running,
    // and B's pins are as they were.
    let exists = testnet
        .sdk()
        .expect("client")
        .public_storage()
        .exists((&b_user, paths::sweep_package(run2).as_str()))
        .await
        .expect("the path is public");
    assert!(!exists, "run 2's package was uploaded");
    let record = get_capped(
        &testnet,
        &b_user,
        &paths::sweep_record(run2),
        MAX_RECORD_BYTES,
    )
    .await;
    let record = Sweep::from_json(&record).expect("a sweep record");
    assert_eq!(record.status.as_known(), Some(KnownSweepStatus::Running));
    assert_eq!(fs::read(&pins_file).expect("the pins"), pins_before);

    // ----- P2b: a key added under A's keys/ makes B's next submit warn -----

    // A second key under A's keys/, written with A's own root key, standing
    // in for an operator of A's homeserver or someone holding A's grant.
    // Its identity is made for this run, and its secret is written nowhere.
    let added_id = "added-by-the-test";
    let added_key = DeviceIdentity::generate();
    publish_as(
        &testnet,
        &a.dirs.config().join("identities/a.key"),
        &format!("/pub/sweepky/keys/{added_id}.json"),
        &json!({
            "schemaVersion": 1,
            "alg": "age-x25519",
            "recipient": added_key.recipient().to_string(),
            "label": "added by the test",
            "createdAt": "2026-10-19T09:00:00Z",
            "revokedAt": null,
        }),
    )
    .await;
    let a_recipient = a_device.recipient().to_string();
    let added_recipient = added_key.recipient().to_string();

    // Run 2, its planted links gone, now holds Cloudflare's output.
    for name in CLOUDFLARE_FILES {
        fs::copy(cloudflare_fixture(name), run2_audit.join(name)).expect("copy");
    }

    // Under --no-input, B's submit of run 2 fails on the new key. The
    // warning is the error, which the binary prints on standard error: it
    // names the new record by its device id and holds no key.
    // `String::split_off` keeps what was said from `mark` on.
    let mark = b_stderr.text().len();
    let no_input_args = [&run2_args[..], &["--no-input"]].concat();
    let error = sweepky(&b, &no_input_args)
        .await
        .expect_err("--no-input refuses a new key");
    let message = format!("{error:#}");
    assert!(
        message.contains(&format!("keys/{added_id}.json")),
        "{message}"
    );
    assert!(message.contains("--no-input"), "{message}");
    let shown = b_stderr.text().split_off(mark);
    for recipient in [&a_recipient, &added_recipient] {
        assert!(!message.contains(recipient.as_str()), "{message}");
        assert!(!shown.contains(recipient.as_str()), "{shown}");
    }
    // Nothing was uploaded, the record still says running and the pin is
    // as it was.
    assert!(!package_exists(&testnet, &b_user, run2).await);
    assert_eq!(
        read_sweep(&testnet, &b_user, run2).await.status.as_known(),
        Some(KnownSweepStatus::Running)
    );
    assert_eq!(fs::read(&pins_file).expect("the pins"), pins_before);

    // The same submit answered yes: B is warned and asked once, and goes
    // on. B's context is `mut`, so its standard input can be given the
    // answer.
    b.stdin = StdinReader::new(Cursor::new(b"y\n".to_vec()));
    let mark = b_stderr.text().len();
    sweepky(&b, &run2_args)
        .await
        .expect("B submits run 2 after a yes");
    let shown = b_stderr.text().split_off(mark);
    assert!(
        shown.contains("warning: the bounty's owner has keys"),
        "{shown}"
    );
    assert!(shown.contains(&format!("keys/{added_id}.json")), "{shown}");
    assert_eq!(shown.matches("[y/N] ").count(), 1, "{shown}");
    for recipient in [&a_recipient, &added_recipient] {
        assert!(!shown.contains(recipient.as_str()), "{shown}");
    }
    let record = read_sweep(&testnet, &b_user, run2).await;
    assert_eq!(record.status.as_known(), Some(KnownSweepStatus::Done));
    assert!(package_exists(&testnet, &b_user, run2).await);

    // B's pin, still 0600, now holds both of A's keys, in device-id order.
    assert_eq!(mode(&pins_file), 0o600);
    let a_device_id = json(&a.dirs.login_file())["deviceId"]
        .as_str()
        .expect("a device id")
        .to_owned();
    // The two recipients move into the pairs: this is their last use.
    let mut a_keys = [
        (a_device_id, a_recipient),
        (added_id.to_owned(), added_recipient),
    ];
    a_keys.sort();
    let a_keys: Vec<Value> = a_keys
        .iter()
        .map(|(id, recipient)| json!({ "deviceId": id, "recipient": recipient }))
        .collect();
    assert_eq!(
        json(&pins_file),
        json!({ "schemaVersion": 1, "owners": { a_pubky.to_string(): a_keys } })
    );

    // ----- P2b: two submits of two separate runs, at the same time -----

    // Runs 3 and 4, each holding Cloudflare's output.
    let run3 = cloudflare_sweep(&b, &posted, &sweeps).await;
    let run4 = cloudflare_sweep(&b, &posted, &sweeps).await;
    let (run3_dir, run4_dir) = (format!("sweeps/{run3}"), format!("sweeps/{run4}"));
    let run3_args = ["submit", "--run-dir", &run3_dir, "--playbook", PLAYBOOK];
    let run4_args = ["submit", "--run-dir", &run4_dir, "--playbook", PLAYBOOK];

    // `tokio::join!` polls both submits in this one task until both are
    // done, so each goes on while the other waits on the network or on the
    // writers' lock. Both only borrow B's context (`&b`), and any number of
    // shared borrows can be alive at once. Each takes the lock with its own
    // open of `credential.lock`, so the two exclude each other as two
    // processes would; that the lock serialises them is P2a's lock test.
    let mark = b_stderr.text().len();
    let (third, fourth) = tokio::join!(sweepky(&b, &run3_args), sweepky(&b, &run4_args));
    third.expect("run 3 is submitted");
    fourth.expect("run 4 is submitted");
    // Neither asked a question: A's keys are as pinned.
    let shown = b_stderr.text().split_off(mark);
    assert!(!shown.contains("[y/N]"), "{shown}");
    for run in [run3, run4] {
        let record = read_sweep(&testnet, &b_user, run).await;
        assert_eq!(record.status.as_known(), Some(KnownSweepStatus::Done));
        assert!(package_exists(&testnet, &b_user, run).await);
    }

    // ----- P2c: A posts an open bounty -----

    // The draft of a bounty open to anyone's sweeps, with two targets in
    // the fixture repository: the whole repository at `main`, M, and pull
    // request 1.
    let open_draft = drafts.path().join("open-bounty.json");
    let open_draft_json = json!({
        "title": "Open review of the fixture repository",
        "brief": "Anyone may sweep this one. Look at session expiry and header lookups.\n",
        "targets": [
            { "kind": "repo", "repo": FIXTURE_REPO, "ref": "main" },
            { "kind": "pr", "repo": FIXTURE_REPO, "number": 1 },
        ],
    });
    fs::write(
        &open_draft,
        serde_json::to_vec(&open_draft_json).expect("JSON"),
    )
    .expect("written");

    // A says yes once more, and is shown that the bounty is open.
    a.stdin = StdinReader::new(Cursor::new(b"y\n".to_vec()));
    let mark = a_stderr.text().len();
    let report = sweepky(
        &a,
        &["post", open_draft.to_str().expect("a UTF-8 path"), "--open"],
    )
    .await
    .expect("A posts the open bounty");
    let shown = a_stderr.text().split_off(mark);
    assert!(
        shown.contains("open: sweeps from anyone are read and labelled by trust"),
        "{shown}"
    );
    assert_eq!(shown.matches("[y/N] ").count(), 1, "{shown}");
    let open: BountyRef = report
        .text()
        .lines()
        .last()
        .expect("a report")
        .parse()
        .expect("a bounty URL");
    assert_eq!(open.owner, a_pubky);

    // Anyone can read the bounty, open to anyone's sweeps, with its two
    // targets.
    let record = get_capped(&testnet, &a_user, &paths::bounty(open.id), MAX_RECORD_BYTES).await;
    let record = Bounty::from_json(&record).expect("a bounty record");
    assert!(record.open, "an open bounty");
    assert_eq!(record.status().as_known(), Some(KnownBountyStatus::Open));
    assert_eq!(record.targets.len(), 2);

    // And its discovered.json: no sweep yet, and the starting cursor on the
    // one homeserver the network watches, the testnet's, which is the event
    // of the bounty's PUT. A's own feed-cursors.json holds the same cursor,
    // where A's first pull starts.
    let watched: Pubky = homeserver.z32().parse().expect("a pubky");
    let listed = read_discovered(&testnet, &a_user, open.id).await;
    assert!(listed.sweeps.is_empty(), "{:?}", listed.sweeps);
    assert_eq!(listed.cursors.keys().collect::<Vec<_>>(), [&watched]);
    let start = listed.cursors[&watched];
    assert_eq!(feed_cursor(&a.dirs, a_pubky, watched), start);

    // ----- P2c: C, a stranger, logs in -----

    // C, outside A's circle, with a SWEEPKY_HOME of its own, is asked
    // nothing. `mut`: C's working directory becomes its project before
    // `run`.
    let c_home = tempfile::tempdir().expect("temp dir");
    let (mut c, c_stderr) = context(&testnet, c_home.path(), io::empty());
    sweepky(&c, &["login", "--identity", "c"])
        .await
        .expect("C logs in");
    let c_pubky = logged_in(&c);
    let c_user = PublicKey::try_from_z32(&c_pubky.to_string()).expect("a key");
    assert!(!roster.is_in_roster(c_pubky));

    // ----- P2c: B and C each run the open bounty and submit -----

    // B, in its project, in Cloudflare's format, as before.
    let b_open = SweepRef {
        sweeper: b_pubky,
        id: cloudflare_sweep(&b, &open, &sweeps).await,
    };
    let b_open_dir = format!("sweeps/{}", b_open.id);
    sweepky(
        &b,
        &["submit", "--run-dir", &b_open_dir, "--playbook", PLAYBOOK],
    )
    .await
    .expect("B submits its sweep of the open bounty");

    // C, in an init project of its own, may run the bounty only because it
    // is open, and its agent leaves the common-format run directory.
    let c_projects = tempfile::tempdir().expect("temp dir");
    let c_project = c_projects.path().join("project");
    sweepky(&c, &["init", c_project.to_str().expect("a UTF-8 path")])
        .await
        .expect("C's init");
    c.cwd = c_project.clone();
    let c_sweep = SweepRef {
        sweeper: c_pubky,
        id: fixture_sweep(
            &c,
            &open,
            &c_project.join("sweeps"),
            "common",
            &COMMON_FILES,
        )
        .await,
    };
    let shown = c_stderr.text();
    assert!(
        shown.contains("Open: its owner reads sweeps from anyone, labelled untrusted"),
        "{shown}"
    );
    let c_dir = format!("sweeps/{}", c_sweep.id);
    sweepky(
        &c,
        &["submit", "--run-dir", &c_dir, "--playbook", COMMON_PLAYBOOK],
    )
    .await
    .expect("C submits its sweep");
    // C was told that capture.bin, which is not text, is left out.
    let shown = c_stderr.text();
    assert!(
        shown.contains(
            "warning: audit/capture.bin is left out of the package: it is not UTF-8 text"
        ),
        "{shown}"
    );

    // Both records say done, and anyone can see both packages.
    for (user, sweep) in [(&b_user, b_open), (&c_user, c_sweep)] {
        let record = read_sweep(&testnet, user, sweep.id).await;
        assert_eq!(record.status.as_known(), Some(KnownSweepStatus::Done));
        assert_eq!(record.bounty, open);
        assert!(package_exists(&testnet, user, sweep.id).await);
    }

    // ----- P2c: A pulls -----

    let report = sweepky(&a, &["pull"]).await.expect("A pulls");
    let text = report.text();

    // Where pull stores the open bounty's sweeps: B's among the trusted, C's
    // under untrusted/, each named by its sweeper and its id.
    let bounty_dir = a.dirs.data().join(open.id.to_string());
    let b_stored = bounty_dir.join(format!("{b_pubky}-{}", b_open.id));
    let c_stored = bounty_dir
        .join("untrusted")
        .join(format!("{c_pubky}-{}", c_sweep.id));

    // The report: the feed of the testnet's homeserver read from the
    // starting cursor post --open stored; the open bounty with B's sweep,
    // labelled circle, and C's, found through that feed alone (C is outside
    // the roster and discovered.json listed no sweep), labelled unknown,
    // both stored now, in upload order; where the triage files are; the
    // discovered.json written; and no warning. A's older, closed bounty is
    // reported too, with B's four P2b sweeps, which this test does not look
    // at.
    assert!(!text.contains("warning: "), "{text}");
    for expected in [
        format!(
            "Events feeds:\n  {watched}: read from cursor {start}, from this install's \
             feed-cursors.json\n"
        ),
        format!(
            "Bounty {open} (status open, open to strangers):\n  {b_open}: circle; done; stored \
             now in {}\n  {c_sweep}: unknown; done; stored now in {}\n  groups.json and \
             merged.json are in {}: 2 sweeps grouped, 1 of them the circle's, whose findings \
             alone are merged\n",
            b_stored.display(),
            c_stored.display(),
            bounty_dir.display()
        ),
        format!("Published {}.\n", paths::discovered(open.id)),
    ] {
        assert!(text.contains(&expected), "{expected}\nnot in\n{text}");
    }

    // The key P2b's step added under A's keys/ raises the alarm, by its
    // device id alone: the report prints no recipient, and no finding.
    // `assert!` with fixed text, so a failure prints neither.
    assert!(
        text.contains(&format!(
            "alarm: keys/{added_id}.json is a device key that this owner's installs here did \
             not create."
        )),
        "{text}"
    );
    for recipient in [a_device.recipient(), added_key.recipient()] {
        assert!(
            !text.contains(&recipient.to_string()),
            "the report prints a recipient"
        );
    }
    // B's findings as submit converted them, and C's as written.
    let (b_findings, _) = parse_audit_findings(&fixture, &playbook).expect("findings");
    let c_findings = Findings::from_json(
        &fs::read(run_dir_fixture("common", "findings.json")).expect("the fixture"),
    )
    .expect("findings");
    for finding in b_findings.findings.iter().chain(&c_findings.findings) {
        assert!(
            !text.contains(finding.title.as_str()),
            "the report prints a finding"
        );
    }

    // Each sweep's files are where the report says, owner-only, as its
    // sweeper's agent left them: the attachments byte for byte, beside the
    // pretty findings.json. C's are under untrusted/ and nowhere else, and
    // capture.bin, which submit left out, is not among them.
    for (stored, fixture_dir, attachments) in [
        (
            &b_stored,
            "cloudflare",
            ["REPORT.md", "coverage-ledger.json"],
        ),
        (&c_stored, "common", ["REPORT.md", "notes/triage.md"]),
    ] {
        assert_eq!(mode(stored), 0o700);
        assert!(stored.join("findings.json").is_file());
        for name in attachments {
            let file = stored.join(name);
            assert_eq!(mode(&file), 0o600);
            assert!(
                fs::read(&file).expect("stored")
                    == fs::read(run_dir_fixture(fixture_dir, name)).expect("the fixture"),
                "{name} differs from the fixture"
            );
        }
    }
    assert_gone(&c_stored.join("capture.bin"));
    assert_gone(&bounty_dir.join(format!("{c_pubky}-{}", c_sweep.id)));

    // groups.json labels B circle and trusted, and C unknown and not, with
    // no credits for either yet.
    let groups = json(&bounty_dir.join("groups.json"));
    assert_eq!(
        groups["sweeps"],
        json!([
            {
                "sweep": b_open.to_string(),
                "label": "circle",
                "bounties": 0,
                "owners": 0,
                "trusted": true,
            },
            {
                "sweep": c_sweep.to_string(),
                "label": "unknown",
                "bounties": 0,
                "owners": 0,
                "trusted": false,
            },
        ])
    );
    // The shared location is one group of B's Cloudflare-format finding and
    // C's common-format one, both anchored at its sink, reported by B and C
    // in upload order. The members hold the findings' places, so they are
    // compared with `assert!`.
    let b_expiry = index_of(&b_findings, "auth-expiry-inclusive");
    let c_expiry = index_of(&c_findings, "session-expiry-off-by-one");
    let sink = json!({ "file": "src/auth/session.rs", "line": 88, "scope": "fn is_expired" });
    let shared = group_of(&groups, b_open, b_expiry);
    assert_eq!(
        shared["reportedBy"],
        json!([b_pubky.to_string(), c_pubky.to_string()])
    );
    assert!(
        shared["members"]
            == json!([
                { "sweep": b_open.to_string(), "index": b_expiry, "anchor": sink },
                { "sweep": c_sweep.to_string(), "index": c_expiry, "anchor": sink },
            ]),
        "the shared location's members differ"
    );
    // The two findings with the id auth-token-compare-timing, at unrelated
    // sinks, stay two groups, each reported by its own sweeper alone.
    let shared_id = "auth-token-compare-timing";
    for (sweep, findings) in [(b_open, &b_findings), (c_sweep, &c_findings)] {
        let group = group_of(&groups, sweep, index_of(findings, shared_id));
        assert_eq!(group["reportedBy"], json!([sweep.sweeper.to_string()]));
        assert_eq!(group["members"].as_array().expect("members").len(), 1);
    }

    // merged.json holds every one of B's findings and nothing of C's sweep,
    // not even its URL.
    let merged_path = bounty_dir.join("merged.json");
    let merged = json(&merged_path);
    let mut merged_indexes = Vec::new();
    for group in merged["groups"].as_array().expect("groups") {
        for entry in group["findings"].as_array().expect("findings") {
            assert_eq!(entry["sweep"], json!(b_open.to_string()));
            let index = entry["index"].as_u64().expect("an index");
            merged_indexes.push(usize::try_from(index).expect("fits"));
        }
    }
    merged_indexes.sort_unstable();
    assert_eq!(
        merged_indexes,
        (0..b_findings.findings.len()).collect::<Vec<_>>()
    );
    let merged_text = fs::read_to_string(&merged_path).expect("merged.json");
    assert!(!merged_text.contains(&c_sweep.to_string()));

    // discovered.json now lists C's sweep, and its cursor is the one pull
    // persisted in A's feed-cursors.json, past the starting cursor.
    let persisted = feed_cursor(&a.dirs, a_pubky, watched);
    assert!(persisted > start, "the feed was read past the start");
    let listed = read_discovered(&testnet, &a_user, open.id).await;
    assert_eq!(listed.sweeps, [c_sweep]);
    assert_eq!(listed.cursors.get(&watched), Some(&persisted));

    // ----- P2c: A pulls again after a restart -----

    // A fresh context on A's SWEEPKY_HOME stands in for a restart: only the
    // files carry over. The cursor survives it: pull resumes the testnet's
    // feed where the first pull left it, from this install's
    // feed-cursors.json, and publishes nothing, with no warning.
    let (a_restarted, _) = context(&testnet, a_home.path(), io::empty());
    let report = sweepky(&a_restarted, &["pull"])
        .await
        .expect("A pulls again");
    let text = report.text();
    let resumed = format!(
        "Events feeds:\n  {watched}: read from cursor {persisted}, from this install's \
         feed-cursors.json\n"
    );
    assert!(text.contains(&resumed), "{text}");
    assert!(!text.contains("Published"), "{text}");
    assert!(!text.contains("warning: "), "{text}");
    // discovered.json still lists C once. And the homeserver itself shows
    // that the second pull made no PUT: past the persisted cursor its feed
    // holds one event, the first pull's write of discovered.json.
    assert_eq!(
        read_discovered(&testnet, &a_user, open.id).await.sweeps,
        [c_sweep]
    );
    assert_eq!(
        events_after(&testnet, persisted).await,
        [FeedEvent {
            op: FeedOp::Put,
            url: PubkyUrl::sweepky(a_pubky, &SweepkyPath::Discovered(open.id)),
        }]
    );

    // ----- P2c: A's second install, A2 -----

    // A2, a SWEEPKY_HOME of A's own, as on a second machine. Until P2d moves
    // A to the Ring flow, the test makes it by copying A's Sweepky identity
    // file there, and `login --identity a` reuses it. The key file alone:
    // login rebuilds the details from it and A's pkarr record, with no
    // signup, which the tripwire token proves. It publishes A2's own device
    // key under the id A2's login.json records: unrevoked, holding A2's
    // key.
    let a2_home = tempfile::tempdir().expect("temp dir");
    let (a2, _) = context(&testnet, a2_home.path(), io::empty());
    let a2_identities = a2.dirs.identities_dir();
    copy_identity_file(&a_key_file, &a2_identities);
    assert_eq!(mode(a2.dirs.config()), 0o700);
    assert_eq!(mode(&a2_identities), 0o700);
    assert_eq!(mode(&a2_identities.join("a.key")), 0o600);
    let report = sweepky(
        &a2,
        &["login", "--identity", "a", "--signup-token", TRIPWIRE_TOKEN],
    )
    .await
    .expect("A2 logs in");
    let text = report.text();
    assert!(!text.contains("Signed up"), "{text}");
    assert!(text.contains("still unspent"), "{text}");
    assert_eq!(logged_in(&a2), a_pubky);
    let a2_device_id = json(&a2.dirs.login_file())["deviceId"]
        .as_str()
        .expect("a device id")
        .to_owned();
    assert_ne!(
        json(&a.dirs.login_file())["deviceId"],
        a2_device_id.as_str()
    );
    let a2_device = device_identity(&a2.dirs);
    let a2_record = get_capped(
        &testnet,
        &a_user,
        &format!("/pub/sweepky/keys/{a2_device_id}.json"),
        MAX_RECORD_BYTES,
    )
    .await;
    let a2_key = DeviceKey::from_json(&a2_record).expect("a device key record");
    assert_eq!(a2_key.revoked_at, None);
    // `assert!` rather than `assert_eq!`, so a failure prints neither key.
    assert!(
        a2_key.encryption_recipient().expect("usable") == a2_device.recipient(),
        "A2's key record does not hold A2's key"
    );

    // ----- P2c: A2 pulls, and can open none of the earlier sweeps -----

    // A2 has no feed cursor of its own, so it reads the testnet's feed from
    // the cursor the open bounty's discovered.json gives, the one A1's first
    // pull wrote there. C's events are before it and C is outside the
    // roster, so A2 reaches C's sweep through discovered.json's list alone.
    // Every sweep so far was sealed before A2's key was published: A2
    // refuses B's and C's sweeps of the open bounty for good as not
    // encrypted to its key, and stores no sweep of either bounty.
    let report = sweepky(&a2, &["pull"]).await.expect("A2 pulls");
    let text = report.text();
    let from_discovered = format!(
        "Events feeds:\n  {watched}: read from cursor {persisted}, from the open bounties' \
         discovered.json\n"
    );
    assert!(text.contains(&from_discovered), "{text}");
    for (sweep, label) in [(b_open, "circle"), (c_sweep, "unknown")] {
        for expected in [
            format!("  {sweep}: {label}; done; not stored: refused for good\n"),
            format!(
                "warning: pull skipped {sweep} for good: not encrypted to this install's key \
                 (sealed before this install's key was published, or to another install)\n"
            ),
        ] {
            assert!(text.contains(&expected), "{expected}\nnot in\n{text}");
        }
    }
    for bounty in [posted, open] {
        assert_gone(&a2.dirs.data().join(bounty.id.to_string()));
    }
    // installs.json is each install's own, so A2 alarms on A1's key too;
    // the test asserts the injected key's alarm alone.
    assert!(
        text.contains(&format!(
            "alarm: keys/{added_id}.json is a device key that this owner's installs here did \
             not create."
        )),
        "{text}"
    );

    // ----- P2c: B's third sweep of the open bounty, after A2's login -----

    // B's submit finds A2's key, new since B pinned A's keys, warns of it
    // by its device id alone, asks once and goes on after the yes, sealing
    // the sweep to A2's key with A's others.
    let third = SweepRef {
        sweeper: b_pubky,
        id: cloudflare_sweep(&b, &open, &sweeps).await,
    };
    b.stdin = StdinReader::new(Cursor::new(b"y\n".to_vec()));
    let mark = b_stderr.text().len();
    let third_dir = format!("sweeps/{}", third.id);
    sweepky(
        &b,
        &["submit", "--run-dir", &third_dir, "--playbook", PLAYBOOK],
    )
    .await
    .expect("B submits the third sweep after a yes");
    let shown = b_stderr.text().split_off(mark);
    assert!(
        shown.contains("warning: the bounty's owner has keys"),
        "{shown}"
    );
    assert!(
        shown.contains(&format!("keys/{a2_device_id}.json")),
        "{shown}"
    );
    assert_eq!(shown.matches("[y/N] ").count(), 1, "{shown}");
    assert!(
        !shown.contains(&a2_device.recipient().to_string()),
        "B was shown A2's key"
    );

    // A2's next pull opens the third sweep with A2's key, the second
    // install of A decrypting it, and stores it among the trusted, B being
    // in A's circle, byte for byte as B's agent left it.
    let report = sweepky(&a2, &["pull"]).await.expect("A2 pulls again");
    let text = report.text();
    let third_stored = a2
        .dirs
        .data()
        .join(open.id.to_string())
        .join(format!("{b_pubky}-{}", third.id));
    let expected = format!(
        "  {third}: circle; done; stored now in {}\n",
        third_stored.display()
    );
    assert!(text.contains(&expected), "{expected}\nnot in\n{text}");
    assert!(
        fs::read(third_stored.join("REPORT.md")).expect("stored")
            == fs::read(cloudflare_fixture("REPORT.md")).expect("the fixture"),
        "A2's REPORT.md differs from the fixture"
    );

    // ----- P2c: A marks the open bounty done, on A1 -----

    // Both `done` steps run on A's first install, A1, whose groups, from
    // its last pull, hold B's and C's sweeps. A2 could not open C's sweep,
    // so A2's groups would propose B alone.

    // A newer client of A's, stood in for by A's root key, has written
    // fields this build does not know into the bounty: at the top, in its
    // playbook and in a target. `done` keeps every one.
    let bounty_path = paths::bounty(open.id);
    let mut newer = read_json(&testnet, &a_user, &bounty_path).await;
    newer["addedLater"] = json!({ "kept": true });
    newer["playbook"]["addedLater"] = json!("kept");
    newer["targets"][0]["addedLater"] = json!("kept");
    publish_as(&testnet, &a_key_file, &bounty_path, &newer).await;

    // `done --credit <A>` is refused with its one line, before anything is
    // shown or asked, and the bounty anyone reads is as it was.
    let mark = a_stderr.text().len();
    let error = sweepky(
        &a,
        &["done", &open.to_string(), "--credit", &a_pubky.to_string()],
    )
    .await
    .expect_err("done refuses to credit the owner");
    assert_eq!(
        format!("{error:#}"),
        "--credit names the bounty's owner, who is never credited on their own bounty"
    );
    assert_eq!(a_stderr.text().split_off(mark), "", "done showed nothing");
    assert_eq!(read_json(&testnet, &a_user, &bounty_path).await, newer);

    // `done` with A's yes: it proposes B and C, each labelled as A1's last
    // pull labelled them, asks once, and credits both.
    a.stdin = StdinReader::new(Cursor::new(b"y\n".to_vec()));
    let mark = a_stderr.text().len();
    let report = sweepky(&a, &["done", &open.to_string()])
        .await
        .expect("A marks the bounty done");
    let shown = a_stderr.text().split_off(mark);
    assert!(!shown.contains("warning: "), "{shown}");
    for expected in [
        format!("  {b_pubky}: circle; "),
        format!("  {c_pubky}: unknown; "),
        format!("Credits to write (2):\n  {b_pubky} (proposed)\n  {c_pubky} (proposed)\n"),
    ] {
        assert!(shown.contains(&expected), "{expected}\nnot in\n{shown}");
    }
    assert_eq!(shown.matches("[y/N] ").count(), 1, "{shown}");
    let expected = format!(
        "Marked the bounty done, crediting 2 sweepers:\n{open}\n  {b_pubky}\n  {c_pubky}\n"
    );
    assert!(report.text().contains(&expected), "{}", report.text());

    // The bounty anyone reads is done at the doneAt `done` wrote, crediting
    // exactly B and C, and every other field is as it was, the unknown ones
    // included.
    let marked = read_json(&testnet, &a_user, &bounty_path).await;
    let done_at = marked["doneAt"].as_str().expect("doneAt is set").to_owned();
    let mut expected = newer;
    expected["status"] = json!("done");
    expected["doneAt"] = json!(done_at);
    expected["credits"] = json!([b_pubky.to_string(), c_pubky.to_string()]);
    assert_eq!(marked, expected);

    // ----- P2c: A1 pulls once the bounty is done -----

    // The done bounty credits C, so A1's next pull labels C known: 1
    // credit across 1 owner, A, in its report and in groups.json; C is
    // still outside the circle, so C's sweep stays untrusted.
    let report = sweepky(&a, &["pull"]).await.expect("A pulls after done");
    let text = report.text();
    let expected = format!(
        "  {c_sweep}: known: 1 credit across 1 owner; done; stored in {}\n",
        c_stored.display()
    );
    assert!(text.contains(&expected), "{expected}\nnot in\n{text}");
    let regrouped = json(&bounty_dir.join("groups.json"));
    let c_entry = regrouped["sweeps"]
        .as_array()
        .expect("sweeps")
        .iter()
        .find(|entry| entry["sweep"] == c_sweep.to_string())
        .expect("C's sweep is grouped");
    assert_eq!(
        *c_entry,
        json!({
            "sweep": c_sweep.to_string(),
            "label": "known",
            "bounties": 1,
            "owners": 1,
            "trusted": false,
        })
    );

    // The key the test injected under A's keys/ stays unrevoked: P2d's
    // concurrent `keys revoke` step, after these steps, revokes it.
}
