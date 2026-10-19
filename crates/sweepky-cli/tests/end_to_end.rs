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
//! databases when the test ends, even when it fails.

use std::fs;
use std::io::{self, BufRead, Cursor, Write};
use std::os::unix::fs::{MetadataExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use clap::Parser;
use pubky::{ClientId, Keypair, PublicKey};
use pubky_testnet::EphemeralTestnet;
use serde_json::{Value, json};
use sweepky_cli::{
    CLIENT_ID, Cli, Context, Dirs, FixtureTargets, GitEnv, Network, Report, StderrWriter,
    StdinReader, TargetSource, run,
};
use sweepky_core::{
    Bounty, BountyRef, Circle, DeviceIdentity, DeviceKey, GitSha, KnownBountyStatus,
    KnownSweepStatus, KnownTarget, MAX_CIPHERTEXT_BYTES, MAX_RECORD_BYTES, Playbook, Pubky,
    RecordId, RepoName, RepoPath, SecretString, Sweep, SweepRef, Zeroizing, open_package,
    parse_audit_findings, paths,
};

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
    run(cli, ctx).await
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

/// The three files of `fixtures/cloudflare/`, the synthetic run directory
/// of a Cloudflare-format sweep.
const CLOUDFLARE_FILES: [&str; 3] = ["REPORT.md", "coverage-ledger.json", "findings.json"];

/// `fixtures/cloudflare/<name>`.
fn cloudflare_fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/cloudflare")
        .join(name)
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

/// The ids of the sweep directories in `sweeps`, a project's `sweeps/`.
fn sweep_ids(sweeps: &Path) -> Vec<RecordId> {
    fs::read_dir(sweeps)
        .expect("sweeps/")
        .map(|entry| {
            let name = entry.expect("an entry").file_name();
            name.to_str().expect("UTF-8").parse().expect("a record id")
        })
        .collect()
}

/// Has `ctx` run `bounty` once more in its project, whose `sweeps/` is
/// `sweeps`, and fills the new sweep's `audit/` from `fixtures/cloudflare/`,
/// as Cloudflare's skill would leave it. Returns the new sweep's id.
async fn cloudflare_sweep(ctx: &Context, bounty: &BountyRef, sweeps: &Path) -> RecordId {
    let before = sweep_ids(sweeps);
    sweepky(ctx, &["run", &bounty.to_string()])
        .await
        .expect("the bounty runs");
    let id = sweep_ids(sweeps)
        .into_iter()
        .find(|id| !before.contains(id))
        .expect("a new sweep directory");
    let audit = sweeps.join(id.to_string()).join("audit");
    fs::create_dir(&audit).expect("audit/");
    for name in CLOUDFLARE_FILES {
        fs::copy(cloudflare_fixture(name), audit.join(name)).expect("copy");
    }
    id
}

/// `user`'s sweep record `id`, read anonymously within the record cap.
async fn read_sweep(testnet: &EphemeralTestnet, user: &PublicKey, id: RecordId) -> Sweep {
    let record = get_capped(testnet, user, &paths::sweep_record(id), MAX_RECORD_BYTES).await;
    Sweep::from_json(&record).expect("a sweep record")
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
    // asked nothing.
    let a_home = tempfile::tempdir().expect("temp dir");
    let (a, a_stderr) = context(&testnet, a_home.path(), Cursor::new(b"y\n".to_vec()));
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
}
