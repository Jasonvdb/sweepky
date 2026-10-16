//! Which Pubky network the CLI talks to, and the identifiers it presents there.
//!
//! Three kinds of network ([`NetworkKind`]):
//!
//! - **Production**, the default: the SDK's mainline client, Pubky's public
//!   HTTP relay and Synonym's homeserver.
//! - **Testnet**, under `--testnet` or `SWEEPKY_TESTNET`: the local
//!   `pubky-testnet` on its fixed ports.
//! - **Injected**: a client, relay and homeserver a caller hands in, which is
//!   how the end-to-end test runs every command against an `EphemeralTestnet`
//!   on random ports.
//!
//! The data (relay URL, default homeserver, watch list) lives in
//! [`NetworkSettings`], apart from the client in [`Network`], so it can be
//! checked without building a client. Building a production client starts a
//! DHT node that contacts public bootstrap servers, and no test may do that.

use std::ffi::OsStr;

use anyhow::{Context as _, bail};
use pubky::{Pubky, PublicKey};

/// The client id Sweepky presents when it asks for a grant.
///
/// Ring shows it as the app's name. It never changes between releases,
/// because a saved session is compared against it. The SDK accepts any
/// non-empty string up to 253 characters (`pubky::ClientId::new`).
pub const CLIENT_ID: &str = "sweepky-cli";

/// The one capability Sweepky asks for: read and write under `/pub/sweepky/`.
///
/// The trailing `/` matters. `/pub/sweepky/` is a directory scope and covers
/// every path inside it; `/pub/sweepky` without it is a file scope that covers
/// only a file of that exact name, so a grant for it could write no record.
/// `rw` is read then write. The first code that requests it is the Ring login
/// (P2d); `login --identity` signs in with the identity's own root key.
pub const SWEEPKY_CAPABILITY: &str = "/pub/sweepky/:rw";

/// The production homeserver's public key (`homeserver.pubky.app`), raw
/// z-base32.
///
/// From `PRODUCTION_HOMESERVER` in `src/utils/constants.ts` of
/// `pubky/pubky-ring` at commit `5ad21e22dd37c11817bd6aa7026b4990b35e1f89`,
/// the default homeserver Ring signs people up on. `pubky/pubky-nexus` names
/// the same key as "Synonym homeserver pubky" (`[watcher] homeserver` in
/// `nexusd/default.config.toml` at `8641d38a1ddbb8435dfda4d892ca954eef6ba314`).
pub const PRODUCTION_HOMESERVER: &str = "8um71us3fyw6h8wbcxb5ar3rwusy1a6u49956ikzojg3gcwd1dty";

/// The local testnet's homeserver key, raw z-base32. `pubky-testnet` derives
/// it from an all-zero secret, so it is the same on every machine.
pub const TESTNET_HOMESERVER: &str = "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo";

/// The local testnet's HTTP relay inbox: `pubky-testnet` serves its relay on
/// the fixed port 15412.
pub const TESTNET_RELAY_URL: &str = "http://localhost:15412/inbox";

/// Which network a [`Network`] talks to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkKind {
    /// The public Pubky network, the default.
    Production,
    /// The local `pubky-testnet` on its fixed ports.
    Testnet,
    /// A client, relay and homeserver the caller handed in.
    Injected,
}

/// Picks production or the testnet from the `--testnet` flag and the value of
/// `SWEEPKY_TESTNET` (`None` when it is unset).
///
/// The flag, or the variable set to exactly `1` or `true`, selects the
/// testnet; unset, `0`, `false` or empty is production. Any other value (`yes`,
/// `TRUE`, ` 1`, a value that is not UTF-8) is an error, with or without the
/// flag, because a typo must never quietly send a test run to production.
///
/// Pure: `main.rs` reads the variable and passes its value in, so this is
/// tested without touching the process environment.
pub fn select_kind(testnet_flag: bool, env_value: Option<&OsStr>) -> anyhow::Result<NetworkKind> {
    // The variable is checked first, flag or no flag, so a bad value is an
    // error even under `--testnet`.
    let env_testnet = env_selects_testnet(env_value)?;
    Ok(if testnet_flag || env_testnet {
        NetworkKind::Testnet
    } else {
        NetworkKind::Production
    })
}

/// Whether `SWEEPKY_TESTNET`'s value (`None` when unset) asks for the testnet,
/// or an error for a value [`select_kind`] does not know.
fn env_selects_testnet(env_value: Option<&OsStr>) -> anyhow::Result<bool> {
    let Some(value) = env_value else {
        return Ok(false);
    };
    // `OsStr::to_str` gives `None` for a value that is not valid UTF-8, which
    // falls through to the error arm with every other unknown value.
    match value.to_str() {
        Some("1" | "true") => Ok(true),
        Some("" | "0" | "false") => Ok(false),
        // `{value:?}` quotes the value and escapes control characters, so
        // whatever the variable holds prints as one readable token.
        _ => bail!(
            "SWEEPKY_TESTNET must be 1 or true for the testnet, or 0, false or empty for \
             production; it is {value:?}"
        ),
    }
}

/// What a network is, apart from its client: the auth relay, the default
/// homeserver and the open-bounty watch list.
///
/// Plain data, so it can be built and checked without a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkSettings {
    kind: NetworkKind,
    relay_url: String,
    default_homeserver: PublicKey,
    watch_list: Vec<PublicKey>,
}

impl NetworkSettings {
    /// Production's settings.
    pub fn production() -> anyhow::Result<Self> {
        // The SDK's own relay constant, so a release that moves the relay
        // moves us with it (a unit test pins today's value).
        Self::built_in(
            NetworkKind::Production,
            pubky::DEFAULT_HTTP_RELAY_INBOX,
            PRODUCTION_HOMESERVER,
        )
    }

    /// The local testnet's settings.
    pub fn testnet() -> anyhow::Result<Self> {
        Self::built_in(NetworkKind::Testnet, TESTNET_RELAY_URL, TESTNET_HOMESERVER)
    }

    /// Settings for a relay and homeserver the caller supplies.
    pub fn injected(relay_url: String, default_homeserver: PublicKey) -> Self {
        Self::new(NetworkKind::Injected, relay_url, default_homeserver)
    }

    /// Production's or the testnet's settings, from our own constants.
    fn built_in(kind: NetworkKind, relay_url: &str, homeserver: &str) -> anyhow::Result<Self> {
        // Our own constants, so this cannot fail in practice; it returns an
        // error rather than panicking anyway, as everything here does.
        // `try_from_z32` accepts only the raw form, not `pubky<z32>`.
        let homeserver = PublicKey::try_from_z32(homeserver)
            .with_context(|| format!("built-in homeserver key for {kind:?} does not parse"))?;
        Ok(Self::new(kind, relay_url.to_owned(), homeserver))
    }

    /// The one constructor, so every kind gets the same watch-list rule: by
    /// default the watch list is the default homeserver alone.
    fn new(kind: NetworkKind, relay_url: String, default_homeserver: PublicKey) -> Self {
        Self {
            kind,
            relay_url,
            // `clone` because the key is stored twice, once in each field. A
            // `PublicKey` holds no heap data, so the copy is cheap.
            watch_list: vec![default_homeserver.clone()],
            default_homeserver,
        }
    }

    /// Which kind of network these settings are for.
    pub fn kind(&self) -> NetworkKind {
        self.kind
    }

    /// The HTTP relay inbox the grant flow posts its approval through.
    pub fn relay_url(&self) -> &str {
        &self.relay_url
    }

    /// The homeserver `login --identity` signs up on when none is named.
    pub fn default_homeserver(&self) -> &PublicKey {
        &self.default_homeserver
    }

    /// The homeservers whose public events feed `pull` follows for open
    /// bounties.
    ///
    /// Returning `&[PublicKey]` rather than `&Vec<PublicKey>` lends out just
    /// the elements, which is all a reader needs.
    pub fn watch_list(&self) -> &[PublicKey] {
        &self.watch_list
    }
}

/// A Pubky client together with the [`NetworkSettings`] it is used with.
#[derive(Debug, Clone)]
pub struct Network {
    pubky: Pubky,
    settings: NetworkSettings,
}

impl Network {
    /// The production network: the SDK's mainline client and production's
    /// settings.
    ///
    /// Building the client can fail (TLS or DHT setup), so this returns a
    /// `Result`. No test calls it: it starts a DHT node that contacts public
    /// bootstrap servers.
    pub fn production() -> anyhow::Result<Self> {
        Ok(Self {
            pubky: Pubky::new().context("could not build the Pubky client")?,
            settings: NetworkSettings::production()?,
        })
    }

    /// The local testnet: `Pubky::testnet()`, which bootstraps from
    /// `localhost:6881` and resolves through the pkarr relay on
    /// `localhost:15411`, and the testnet's settings.
    pub fn testnet() -> anyhow::Result<Self> {
        Ok(Self {
            pubky: Pubky::testnet().context("could not build the Pubky testnet client")?,
            settings: NetworkSettings::testnet()?,
        })
    }

    /// A network made of what the caller hands in, as the end-to-end test does
    /// with an `EphemeralTestnet`'s client, relay and homeserver.
    ///
    /// It takes `pubky` by value: the network owns its client from here on.
    pub fn injected(pubky: Pubky, relay_url: String, default_homeserver: PublicKey) -> Self {
        Self {
            pubky,
            settings: NetworkSettings::injected(relay_url, default_homeserver),
        }
    }

    /// The network of a kind [`select_kind`] returned: production or the
    /// testnet. An injected network is built with [`Network::injected`]
    /// instead, so asking for one here is an error.
    pub fn for_kind(kind: NetworkKind) -> anyhow::Result<Self> {
        match kind {
            NetworkKind::Production => Self::production(),
            NetworkKind::Testnet => Self::testnet(),
            NetworkKind::Injected => {
                bail!("an injected network needs its client: use Network::injected")
            }
        }
    }

    /// The Pubky client.
    pub fn pubky(&self) -> &Pubky {
        &self.pubky
    }

    /// The kind, relay, default homeserver and watch list.
    pub fn settings(&self) -> &NetworkSettings {
        &self.settings
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::str::FromStr;

    use pubky::{Capability, ClientId, Keypair, StoragePath};

    use super::{CLIENT_ID, NetworkKind, NetworkSettings, SWEEPKY_CAPABILITY, select_kind};

    fn path(p: &str) -> StoragePath {
        StoragePath::new(p).expect("test path is valid")
    }

    /// `SWEEPKY_TESTNET` set to `value`, as `main.rs` would pass it in.
    fn env(value: &'static str) -> Option<&'static OsStr> {
        Some(OsStr::new(value))
    }

    #[test]
    fn requested_capability_is_exactly_pub_sweepky_rw() {
        assert_eq!(SWEEPKY_CAPABILITY, "/pub/sweepky/:rw");

        let cap = Capability::from_str(SWEEPKY_CAPABILITY).expect("the constant parses");
        assert_eq!(cap.scope().as_str(), "/pub/sweepky/");
        assert!(
            cap.scope().is_directory(),
            "a trailing `/` is a directory scope"
        );
        assert_eq!(
            cap,
            Capability::read_write("/pub/sweepky/").expect("valid scope"),
            "read and write, nothing else"
        );
        assert_eq!(
            cap.to_string(),
            SWEEPKY_CAPABILITY,
            "Display writes it back"
        );

        assert!(cap.scope_covers_path(&path("/pub/sweepky/keys/x.json")));
        assert!(!cap.scope_covers_path(&path("/pub/sweepky.json")));
        assert!(!cap.scope_covers_path(&path("/pub/sweepkyx/a")));

        // Without the trailing slash the same text is a file scope: it covers
        // the one path `/pub/sweepky` and nothing under it.
        let file = Capability::from_str("/pub/sweepky:rw").expect("parses");
        assert!(file.scope().is_file());
        assert!(!file.scope_covers_path(&path("/pub/sweepky/keys/x.json")));
    }

    #[test]
    fn client_id_is_sweepky_cli() {
        assert_eq!(CLIENT_ID, "sweepky-cli");
        let id = ClientId::new(CLIENT_ID).expect("the SDK accepts it");
        assert_eq!(id.as_str(), CLIENT_ID);
    }

    #[test]
    fn flag_or_variable_selects_the_testnet() {
        // The flag alone, or the variable set to 1 or true, selects the testnet.
        assert_eq!(select_kind(true, None).ok(), Some(NetworkKind::Testnet));
        assert_eq!(
            select_kind(false, env("1")).ok(),
            Some(NetworkKind::Testnet)
        );
        assert_eq!(
            select_kind(false, env("true")).ok(),
            Some(NetworkKind::Testnet)
        );
        assert_eq!(select_kind(true, env("1")).ok(), Some(NetworkKind::Testnet));
        assert_eq!(select_kind(true, env("0")).ok(), Some(NetworkKind::Testnet));
    }

    #[test]
    fn production_without_flag_or_testnet_value() {
        // Unset, 0, false or empty, with no flag, is production.
        for value in [None, env("0"), env("false"), env("")] {
            assert_eq!(
                select_kind(false, value).ok(),
                Some(NetworkKind::Production),
                "{value:?}"
            );
        }
    }

    #[test]
    fn unknown_variable_value_is_an_error() {
        // Anything else is an error, with or without the flag: a typo never
        // falls back to production.
        for bad in ["yes", "TRUE", "True", "2", " 1", "1 ", "on", "testnet"] {
            assert!(select_kind(false, env(bad)).is_err(), "{bad:?}");
            assert!(
                select_kind(true, env(bad)).is_err(),
                "{bad:?} with the flag"
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let not_utf8 = OsStr::from_bytes(b"\xff");
            assert!(select_kind(false, Some(not_utf8)).is_err());
        }
    }

    #[test]
    fn built_in_settings_are_the_recorded_values() {
        let testnet = NetworkSettings::testnet().expect("built in");
        assert_eq!(testnet.kind(), NetworkKind::Testnet);
        assert_eq!(testnet.relay_url(), "http://localhost:15412/inbox");
        // `z32()` is the raw z-base32 form, without the `pubky` prefix.
        assert_eq!(
            testnet.default_homeserver().z32(),
            "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo"
        );

        let production = NetworkSettings::production().expect("built in");
        assert_eq!(production.kind(), NetworkKind::Production);
        assert_eq!(production.relay_url(), pubky::DEFAULT_HTTP_RELAY_INBOX);
        assert_eq!(production.relay_url(), "https://httprelay.pubky.app/inbox");
        assert_eq!(
            production.default_homeserver().z32(),
            "8um71us3fyw6h8wbcxb5ar3rwusy1a6u49956ikzojg3gcwd1dty"
        );
    }

    #[test]
    fn every_kind_watches_its_default_homeserver_alone() {
        let homeserver = Keypair::random().public_key();
        let injected =
            NetworkSettings::injected("http://127.0.0.1:1/inbox".to_owned(), homeserver.clone());
        assert_eq!(injected.kind(), NetworkKind::Injected);
        assert_eq!(injected.relay_url(), "http://127.0.0.1:1/inbox");
        assert_eq!(injected.default_homeserver(), &homeserver);

        for settings in [
            NetworkSettings::testnet().expect("built in"),
            NetworkSettings::production().expect("built in"),
            injected,
        ] {
            assert_eq!(
                settings.watch_list(),
                [settings.default_homeserver().clone()],
                "{:?}",
                settings.kind()
            );
        }
    }
}
