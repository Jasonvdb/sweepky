//! Where each key's homeserver is, as `pull` asks it once a run: the
//! [`ResolveHomeserver`] seam, its real implementation [`PkarrHomeservers`]
//! over the SDK's `Pubky::get_homeserver_of`, and [`Homeservers`], the cache
//! of one run in front of it. The tests use `test_support::FakeHomeservers`.
//!
//! **Why look a key up at all**, when every read of its storage goes to
//! `https://_pubky.<key>/…` and the SDK resolves that itself, through pkarr,
//! with its own 60-second cache over pkarr's? Because the lookup is the gate
//! before any request: a key whose pkarr record names no homeserver is
//! skipped with one warning, instead of failing each of its reads, and the
//! steps that check or use the homeserver itself (the host policy, the feed)
//! learn which it is.
//!
//! **Once a run.** 01 ("Circle") says to resolve each member once, cache it,
//! and resolve it again hourly or on failure. `pull` is one short process,
//! so its cache lasts the run: one lookup per key, and one more after a read
//! of that key failed ([`Homeservers::after_failed_read`]), so that a key
//! whose record is gone since is skipped for the rest of the run. Hourly
//! lookups are for a poller that keeps running, such as the board. A cache
//! kept on disk would save no lookup: the SDK resolves each read again
//! anyway.
//!
//! **Errors quote nothing.** A key that cannot be reached is an
//! [`Unreachable`], whose text is fixed; the resolver's own error is
//! dropped.

use std::collections::HashMap;
use std::fmt;

use sweepky_core::Pubky;

use crate::remote::{pubky_of, public_key_of, request_error};

/// Where a key's homeserver is looked up: the seam between `pull` and
/// pkarr.
///
/// A trait so that the tests can answer as they like, with no network. As
/// with `targets::host::ResolveHost`, the method is an `async fn`, so callers
/// take `&impl ResolveHomeserver` (or a type parameter) rather than
/// `&dyn ResolveHomeserver`.
pub(crate) trait ResolveHomeserver {
    /// The homeserver `user`'s pkarr record names, or `None` when there is
    /// no record or it names none. An error's text is never shown
    /// ([`Homeservers`] replaces it with fixed text).
    async fn homeserver_of(&self, user: Pubky) -> anyhow::Result<Option<Pubky>>;
}

/// The real [`ResolveHomeserver`]: the SDK's `get_homeserver_of`, which
/// reads the key's pkarr record through the client's relays and DHT, from
/// pkarr's cache first. It borrows the client, which is what the `'a`
/// says.
pub(crate) struct PkarrHomeservers<'a> {
    pubky: &'a pubky::Pubky,
}

impl<'a> PkarrHomeservers<'a> {
    /// A resolver on `pubky`'s client.
    pub(crate) fn new(pubky: &'a pubky::Pubky) -> Self {
        Self { pubky }
    }
}

impl ResolveHomeserver for PkarrHomeservers<'_> {
    async fn homeserver_of(&self, user: Pubky) -> anyhow::Result<Option<Pubky>> {
        let key = public_key_of(&user)?;
        let found = self
            .pubky
            .get_homeserver_of(&key)
            .await
            // `request_error` keeps the kind of fault and drops the SDK's
            // text.
            .map_err(|error| request_error(&error))?;
        // `as_ref` lends the key inside the `Option` to `pubky_of`, which
        // takes a reference.
        Ok(found.as_ref().map(pubky_of))
    }
}

/// Why a key's storage cannot be read this run. Fixed text, so a warning
/// can name the key and say why without quoting pkarr or a relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unreachable {
    /// The key has no pkarr record, or its record names no homeserver.
    NoHomeserver,
    /// The lookup itself failed: no relay answered, or the record could not
    /// be read.
    LookupFailed,
}

impl fmt::Display for Unreachable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoHomeserver => "its pkarr record names no homeserver",
            Self::LookupFailed => "its pkarr record could not be looked up",
        })
    }
}

/// What one lookup of a key found: its homeserver, or why there is none.
// `Result` is `Copy` when both its sides are, as `Pubky` and `Unreachable`
// are, so a cached answer is handed out by value.
type Found = Result<Pubky, Unreachable>;

/// One key's lookups this run.
struct Lookup {
    /// What the last lookup found.
    found: Found,
    /// Whether the key was looked up again after a failed read.
    again: bool,
}

/// The homeservers of the keys one run reads, each looked up through `R` the
/// first time it is asked for and kept for the run, and looked up once more
/// after a read of it failed.
///
/// `pull`'s steps share one, so a key is looked up once a run whichever step
/// reads it first. It borrows the resolver (`'a`), so the caller keeps it.
pub(crate) struct Homeservers<'a, R> {
    resolver: &'a R,
    lookups: HashMap<Pubky, Lookup>,
}

impl<'a, R: ResolveHomeserver> Homeservers<'a, R> {
    /// An empty cache in front of `resolver`, for one run.
    pub(crate) fn new(resolver: &'a R) -> Self {
        Self {
            resolver,
            lookups: HashMap::new(),
        }
    }

    /// The homeserver of `user`, looked up the first time it is asked for
    /// in this run, or why its storage cannot be read. A failed lookup is
    /// kept for the run like a found one, so a key that cannot be reached
    /// costs one lookup, not one per read.
    pub(crate) async fn resolve(&mut self, user: Pubky) -> Found {
        if let Some(lookup) = self.lookups.get(&user) {
            return lookup.found;
        }
        let found = self.look_up(user).await;
        self.lookups.insert(
            user,
            Lookup {
                found,
                again: false,
            },
        );
        found
    }

    /// The homeserver of `user` after one of its reads failed: looked up
    /// again the first time this is asked in the run, so a key whose record
    /// changed or went is seen to have, and as [`resolve`](Self::resolve)
    /// gives it after that. So a run looks a key up twice at most.
    pub(crate) async fn after_failed_read(&mut self, user: Pubky) -> Found {
        // Looked up again already, or never yet: as `resolve` gives it.
        // `is_some_and` is false for a key not in the map.
        let first_failure = self.lookups.get(&user).is_some_and(|lookup| !lookup.again);
        if !first_failure {
            return self.resolve(user).await;
        }
        let found = self.look_up(user).await;
        self.lookups.insert(user, Lookup { found, again: true });
        found
    }

    /// What the resolver says of `user` now, kept nowhere.
    async fn look_up(&self, user: Pubky) -> Found {
        match self.resolver.homeserver_of(user).await {
            Ok(Some(homeserver)) => Ok(homeserver),
            Ok(None) => Err(Unreachable::NoHomeserver),
            // The error is dropped rather than kept as a cause: its text is
            // the resolver's.
            Err(_) => Err(Unreachable::LookupFailed),
        }
    }
}

#[cfg(test)]
mod tests {
    use pubky::{ClientId, Keypair};
    use pubky_testnet::EphemeralTestnet;

    use super::{Homeservers, PkarrHomeservers, Unreachable};
    use crate::CLIENT_ID;
    use crate::remote::pubky_of;
    use crate::test_support::{
        FAKE_HOMESERVER, FAKE_LOOKUP_TEXT, FakeHomeservers, FakeLookup, random_pubky,
    };

    #[tokio::test]
    async fn a_key_is_looked_up_once_a_run_and_once_more_after_a_failed_read() {
        let (user, moved_to, other) = (random_pubky(), random_pubky(), random_pubky());
        let resolver = FakeHomeservers::default().with_answers(
            user,
            &[FakeLookup::At(FAKE_HOMESERVER), FakeLookup::At(moved_to)],
        );
        let mut homeservers = Homeservers::new(&resolver);

        // Asked twice, looked up once: the first answer is kept for the run.
        assert_eq!(homeservers.resolve(user).await, Ok(FAKE_HOMESERVER));
        assert_eq!(homeservers.resolve(user).await, Ok(FAKE_HOMESERVER));
        assert_eq!(resolver.times_asked(user), 1);

        // After a failed read, looked up once more, and that answer is kept.
        assert_eq!(homeservers.after_failed_read(user).await, Ok(moved_to));
        assert_eq!(homeservers.after_failed_read(user).await, Ok(moved_to));
        assert_eq!(homeservers.resolve(user).await, Ok(moved_to));
        assert_eq!(resolver.times_asked(user), 2);

        // A failed read of a key not looked up yet is its first lookup.
        assert_eq!(
            homeservers.after_failed_read(other).await,
            Ok(FAKE_HOMESERVER)
        );
        assert_eq!(homeservers.resolve(other).await, Ok(FAKE_HOMESERVER));
        assert_eq!(resolver.asked(), [user, user, other]);
    }

    #[tokio::test]
    async fn no_record_and_a_failed_lookup_are_unreachable_in_fixed_text() {
        let (gone, failing) = (random_pubky(), random_pubky());
        let resolver = FakeHomeservers::default()
            .with_answers(gone, &[FakeLookup::NoRecord])
            .with_answers(failing, &[FakeLookup::Fails]);
        let mut homeservers = Homeservers::new(&resolver);

        assert_eq!(
            homeservers.resolve(gone).await,
            Err(Unreachable::NoHomeserver)
        );
        assert_eq!(
            homeservers.resolve(failing).await,
            Err(Unreachable::LookupFailed)
        );
        // A failed lookup is kept for the run too, not tried again at once.
        assert_eq!(
            homeservers.resolve(failing).await,
            Err(Unreachable::LookupFailed)
        );
        assert_eq!(resolver.asked(), [gone, failing]);
        for why in [Unreachable::NoHomeserver, Unreachable::LookupFailed] {
            let shown = why.to_string();
            assert!(shown.contains("pkarr"), "{shown}");
            assert!(!shown.contains(FAKE_LOOKUP_TEXT), "{shown}");
        }
    }

    #[tokio::test]
    #[pubky_testnet::test]
    async fn on_a_testnet_a_signed_up_key_is_at_its_homeserver_and_a_new_key_nowhere() {
        let testnet = EphemeralTestnet::builder()
            .build()
            .await
            .expect("testnet starts");
        let pubky = testnet.sdk().expect("client");
        let homeserver = testnet.homeserver_app().public_key();
        let signer = pubky.signer(Keypair::random());
        signer.signup(&homeserver, None).await.expect("signs up");
        // Signed in only so that the identity is as `login` leaves one.
        signer
            .signin(ClientId::new(CLIENT_ID).expect("a valid client id"))
            .await
            .expect("signs in");
        let user = pubky_of(&signer.public_key());

        let resolver = PkarrHomeservers::new(&pubky);
        let mut homeservers = Homeservers::new(&resolver);
        assert_eq!(homeservers.resolve(user).await, Ok(pubky_of(&homeserver)));
        assert_eq!(
            homeservers.resolve(random_pubky()).await,
            Err(Unreachable::NoHomeserver)
        );
    }
}
