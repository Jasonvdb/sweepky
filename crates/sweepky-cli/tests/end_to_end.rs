//! The end-to-end test from `docs/plan/06-verification-and-limits.md`, run
//! against a local `EphemeralTestnet` with every command going through the
//! library's `run`, exactly as the binary does, but with the testnet's
//! client injected so nothing reaches production.
//!
//! There is one test function and it is built up phase by phase: P2a's
//! steps use the throwaway identity `throwaway` (not A, B or C, because
//! `logout` deletes the identity it runs on), and P2b to P2d add their steps
//! for A, B and C after these, without reordering them.
//!
//! It needs Postgres for the testnet's homeserver, through
//! `TEST_PUBKY_CONNECTION_STRING`. `#[pubky_testnet::test]` drops the test
//! databases when the test ends, even when it fails.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::{Arc, Mutex};

use clap::Parser;
use pubky::{ClientId, Keypair, PublicKey};
use pubky_testnet::EphemeralTestnet;
use serde_json::{Value, json};
use sweepky_cli::{CLIENT_ID, Cli, Context, Dirs, Network, Report, StderrWriter, run};
use sweepky_core::{DeviceIdentity, DeviceKey, MAX_RECORD_BYTES, SecretString, Zeroizing};

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
    let mut seed = Zeroizing::new([0_u8; 32]);
    for (byte, pair) in seed.iter_mut().zip(hex.chunks_exact(2)) {
        let digits = std::str::from_utf8(pair).expect("hex digits");
        *byte = u8::from_str_radix(digits, 16).expect("hex digits");
    }
    seed
}

/// A signup token in a form the homeserver rejects (400) before it looks at
/// anything else, so a `login` that sent a signup with it would fail. Passed
/// where `login` must not sign up, it proves that no signup was sent.
const TRIPWIRE_TOKEN: &str = "not-a-signup-code";

#[tokio::test]
#[pubky_testnet::test]
async fn end_to_end() {
    let testnet = EphemeralTestnet::builder()
        .with_http_relay()
        .build()
        .await
        .expect("the testnet starts");
    let homeserver = testnet.homeserver_app().public_key();
    // `local_url()` ends with `/`, so this is `http://localhost:<port>/inbox`.
    let relay = format!("{}inbox", testnet.http_relay().local_url());

    // SWEEPKY_HOME for this test: a fresh directory that deletes itself.
    let home = tempfile::tempdir().expect("temp dir");
    let stderr = SharedBuffer::default();
    let ctx = Context {
        network: Network::injected(testnet.sdk().expect("client"), relay, homeserver.clone()),
        dirs: Dirs::resolve(None, Some(home.path().as_os_str())).expect("absolute"),
        stderr: StderrWriter::new(stderr.clone()),
    };
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

    // installs.json lists the id under this owner, and the report says to
    // back the config directory up.
    assert_eq!(mode(&dirs.installs_file()), 0o600);
    assert_eq!(
        json(&dirs.installs_file())["owners"][pubky.as_str()],
        json!([device_id])
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
        json!([device_id])
    );

    // `keys list` lists this install's key, in use, and raises no alarm.
    let own_line = format!("keys/{device_id}.json: this install; in use");
    let report = sweepky(&ctx, &["keys", "list"]).await.expect("keys list");
    let text = report.text();
    assert!(text.contains(&own_line), "{text}");
    assert!(!text.contains("alarm"), "{text}");

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
}
