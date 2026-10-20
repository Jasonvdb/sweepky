//! Where each key's homeserver is, as `pull` asks it once a run: the
//! [`ResolveHomeserver`] seam, its real implementation [`PkarrHomeservers`]
//! over the SDK's `Pubky::get_homeserver_of`, [`CheckedHomeservers`], which
//! puts the host policy in front of a resolver on production, and
//! [`Homeservers`], the cache of one run in front of either. The tests use
//! `test_support::FakeHomeservers`.
//!
//! **Why look a key up at all**, when every read of its storage goes to
//! `https://_pubky.<key>/…` and the SDK resolves that itself, through pkarr,
//! with its own 60-second cache over pkarr's? Because the lookup is the gate
//! before any request: a key whose pkarr record names no homeserver, or a
//! homeserver the host policy refuses, is skipped with one warning, instead
//! of failing each of its reads, and the steps that use the homeserver
//! itself (the feed) learn which it is.
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
//! **The host policy** (P2b's carry-forward: reuse it for anything that
//! contacts a stranger-named host). A key's pkarr record names its
//! homeserver, and the homeserver's own record names where it is, so whoever
//! holds a key, a stranger or a circle member, chooses where `pull` connects
//! to read it. On production, [`CheckedHomeservers`] passes a key other than
//! the owner's only once the records the SDK's own pkarr client reads
//! ([`PkarrRecords`]) show that:
//!
//! 1. every `_pubky` record of the key names that one homeserver, as the
//!    SDK's signup writes it: the SDK's requests use every such record, not
//!    only the first, which is the one `get_homeserver_of` gives;
//! 2. the homeserver's record gives somewhere to reach it, an HTTPS or SVCB
//!    record whose target is a domain, or `.` beside an A or AAAA record;
//!    with none, or no record at all, the key is unreachable, as one with no
//!    homeserver is; and
//! 3. every A and AAAA record in it is public (`targets::host::is_public`),
//!    every domain it targets passes `check_host` through the
//!    `ResolveHost` seam, at most [`MAX_HOMESERVER_DOMAINS`] of them, and no
//!    target points on to another pkarr key, which the SDK would follow and
//!    the policy does not.
//!
//! A homeserver's verdict is kept for the run, so one that many keys share,
//! such as the production homeserver, is checked once. The owner, and the
//! homeserver `login.json` records for them, are never checked: the owner
//! chose it. Nor is anything on the testnet or an injected network, whose
//! homeservers are on loopback by design. The check fails closed: whatever
//! it cannot classify refuses the key.
//!
//! **The check is advisory.** The SDK resolves pkarr and DNS again inside
//! each request, so a stranger who answers differently the second time
//! (DNS rebinding, or a pkarr record republished once pkarr's cache of it
//! expires) is not caught. The reads it guards are capped GETs sent through
//! `remote::get_unredirected`, which refuses a redirected answer, though
//! reqwest has followed the redirect by then (P2b's redirect limit).
//!
//! **Errors quote nothing.** A key that cannot be reached is an
//! [`Unreachable`], whose text is fixed and holds nothing of the resolver's,
//! a relay's or a record's.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Mutex, MutexGuard, PoisonError};

use pubky::pkarr::dns::rdata::{HTTPS, RData};
use pubky::pkarr::{ResolvePolicy, SignedPacket};
use sweepky_core::Pubky;

use crate::network::NetworkKind;
use crate::remote::{pubky_of, public_key_of};
use crate::state::LoginState;
use crate::targets::host::{ResolveHost, check_host, is_public};

/// The most domains a homeserver's pkarr record may target for the host
/// policy to check it. pubky-homeserver writes one, its ICANN domain, for
/// browsers. Each costs a DNS lookup, which has no timeout but the system
/// resolver's, so a stranger's record cannot make one run wait on many.
pub(crate) const MAX_HOMESERVER_DOMAINS: usize = 4;

/// Where a key's homeserver is looked up: the seam between `pull` and
/// pkarr.
///
/// A trait so that the tests can answer as they like, with no network. As
/// with `targets::host::ResolveHost`, the method is an `async fn`, so callers
/// take `&impl ResolveHomeserver` (or a type parameter) rather than
/// `&dyn ResolveHomeserver`.
pub(crate) trait ResolveHomeserver {
    /// The homeserver `user`'s pkarr record names, or why its storage cannot
    /// be read. [`Unreachable`] is fixed text with no room for the
    /// resolver's, so nothing a relay or a record said reaches a warning.
    async fn homeserver_of(&self, user: Pubky) -> Result<Pubky, Unreachable>;
}

/// Where a key's own signed pkarr record is read for the host policy: the
/// seam between [`CheckedHomeservers`] and pkarr, so that the tests can
/// answer with records they sign themselves.
pub(crate) trait PkarrRecords {
    /// `key`'s signed pkarr record, or `None` when it has none or it could
    /// not be read: the policy refuses alike whatever went wrong, so the
    /// error, whose text is pkarr's, is dropped here.
    async fn record_of(&self, key: Pubky) -> Option<SignedPacket>;
}

/// The real [`ResolveHomeserver`] and [`PkarrRecords`]: the SDK's
/// `get_homeserver_of`, and its pkarr client (`PubkyHttpClient::pkarr`),
/// which read a key's record through the client's relays and DHT, from
/// pkarr's cache first. It borrows the client, which is what the `'a` says.
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
    async fn homeserver_of(&self, user: Pubky) -> Result<Pubky, Unreachable> {
        let key = public_key_of(&user).map_err(|_| Unreachable::LookupFailed)?;
        match self.pubky.get_homeserver_of(&key).await {
            // `pubky_of` takes a reference, so `&` lends it the key.
            Ok(Some(homeserver)) => Ok(pubky_of(&homeserver)),
            Ok(None) => Err(Unreachable::NoHomeserver),
            // The SDK's error is dropped: its text is the resolver's.
            Err(_) => Err(Unreachable::LookupFailed),
        }
    }
}

impl PkarrRecords for PkarrHomeservers<'_> {
    async fn record_of(&self, key: Pubky) -> Option<SignedPacket> {
        let key = public_key_of(&key).ok()?;
        // `CacheFirst` is the policy the SDK resolves with before each
        // request, from the same client's cache, so while pkarr keeps a
        // record this reads what the SDK's next request will. `as_inner`
        // lends the pkarr key that the SDK's key wraps.
        self.pubky
            .client()
            .pkarr()
            .resolve(key.as_inner(), ResolvePolicy::CacheFirst)
            .await
            .ok()
    }
}

/// Why a key's storage cannot be read this run. Fixed text, so a warning
/// can name the key and say why without quoting pkarr, a relay or a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unreachable {
    /// The key has no pkarr record, or its record names no homeserver.
    NoHomeserver,
    /// The lookup itself failed: no relay answered, or the record could not
    /// be read.
    LookupFailed,
    /// The host policy found no record of the key's homeserver, or one that
    /// gives nowhere to reach it.
    HomeserverNotFound,
    /// The host policy refused the key: its records lead to an address that
    /// is not public, or to one the policy could not classify.
    NotPublic,
}

impl fmt::Display for Unreachable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoHomeserver => "its pkarr record names no homeserver",
            Self::LookupFailed => "its pkarr record could not be looked up",
            Self::HomeserverNotFound => {
                "its homeserver's pkarr record could not be found or names no address"
            }
            Self::NotPublic => {
                "its pkarr records lead to an address that is not public (loopback, private, \
                 link-local or otherwise reserved) or that Sweepky could not check, so Sweepky \
                 did not contact it"
            }
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
        let found = self.resolver.homeserver_of(user).await;
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
        let found = self.resolver.homeserver_of(user).await;
        self.lookups.insert(user, Lookup { found, again: true });
        found
    }
}

/// The host policy's verdict on one homeserver: it passed, or why not.
type Verdict = Result<(), Unreachable>;

/// A [`ResolveHomeserver`] that puts the host policy (see the module docs)
/// in front of another: `R` says where a key's homeserver is, `P` reads the
/// pkarr records the policy checks, and `D` looks up the domains they
/// target. On a network other than production it is `R` alone.
///
/// It is itself a [`ResolveHomeserver`], so a [`Homeservers`] cache, and the
/// roster poll through it, take it as they take `R`: a refused key is
/// skipped there like one with no homeserver, with one warning that names
/// it.
pub(crate) struct CheckedHomeservers<'a, R, P, D> {
    resolver: &'a R,
    records: &'a P,
    hosts: &'a D,
    /// The owner, never checked.
    owner: Pubky,
    /// The homeserver the owner's login records, never checked for anyone.
    owner_homeserver: Pubky,
    /// Whether the policy applies: on production only.
    checks: bool,
    /// Each homeserver's verdict this run. `homeserver_of` takes `&self`, as
    /// the trait says, yet this map grows; a `Mutex` gives that "interior
    /// mutability", one caller at a time, checked at run time.
    verdicts: Mutex<HashMap<Pubky, Verdict>>,
}

impl<'a, R, P, D> CheckedHomeservers<'a, R, P, D> {
    /// The policy for the owner `login` records, through `records` and
    /// `hosts`, in front of `resolver`, on a network of `kind`.
    pub(crate) fn new(
        resolver: &'a R,
        records: &'a P,
        hosts: &'a D,
        login: &LoginState,
        kind: NetworkKind,
    ) -> Self {
        Self {
            resolver,
            records,
            hosts,
            owner: login.pubky,
            owner_homeserver: login.homeserver,
            checks: policy_applies(kind),
            verdicts: Mutex::default(),
        }
    }

    /// The verdicts so far, locked. A lock poisoned by a panic elsewhere
    /// still holds a whole map (each `insert` happened or did not), so it
    /// is taken as it is rather than panicking in turn.
    fn verdicts(&self) -> MutexGuard<'_, HashMap<Pubky, Verdict>> {
        self.verdicts.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl<R: ResolveHomeserver, P: PkarrRecords, D: ResolveHost> ResolveHomeserver
    for CheckedHomeservers<'_, R, P, D>
{
    async fn homeserver_of(&self, user: Pubky) -> Result<Pubky, Unreachable> {
        let homeserver = self.resolver.homeserver_of(user).await?;
        if self.checks && user != self.owner {
            self.check_key(user, homeserver).await?;
            if homeserver != self.owner_homeserver {
                self.check_homeserver(homeserver).await?;
            }
        }
        Ok(homeserver)
    }
}

impl<R, P: PkarrRecords, D: ResolveHost> CheckedHomeservers<'_, R, P, D> {
    /// Step 1 of the module docs: `user`'s own record names `homeserver`
    /// alone. Read at each lookup of the key, from pkarr's cache.
    async fn check_key(&self, user: Pubky, homeserver: Pubky) -> Verdict {
        // `None` when pkarr lost the record it gave a moment ago: refused,
        // as a lookup that failed. `ok_or` turns the `Option` into a
        // `Result`, so that `?` can return the reason.
        let record = self
            .records
            .record_of(user)
            .await
            .ok_or(Unreachable::LookupFailed)?;
        if names_only(&record, homeserver) {
            Ok(())
        } else {
            Err(Unreachable::NotPublic)
        }
    }

    /// Steps 2 and 3: `homeserver`'s verdict, checked the first time it is
    /// asked for in this run and kept for the rest of it.
    async fn check_homeserver(&self, homeserver: Pubky) -> Verdict {
        // The guard `verdicts()` returns is dropped at the end of each
        // statement that takes it, so the lock is never held across an
        // `.await`. Held there, it would block whoever asked next, and since
        // a std guard is not `Send`, the future could not move between
        // threads.
        let kept = self.verdicts().get(&homeserver).copied();
        if let Some(verdict) = kept {
            return verdict;
        }
        let verdict = self.verdict_on(homeserver).await;
        self.verdicts().insert(homeserver, verdict);
        verdict
    }

    /// What the policy says of `homeserver` now, kept nowhere.
    async fn verdict_on(&self, homeserver: Pubky) -> Verdict {
        let record = self
            .records
            .record_of(homeserver)
            .await
            .ok_or(Unreachable::HomeserverNotFound)?;
        let endpoints = Endpoints::of(&record)?;
        // The addresses first: they need no lookup.
        if !endpoints.addresses.into_iter().all(is_public) {
            return Err(Unreachable::NotPublic);
        }
        for domain in &endpoints.domains {
            // `check_host` is the target policy's own check: every address
            // the domain resolves to must be public. Its error is fixed text
            // already, dropped for this one.
            check_host(domain, self.hosts)
                .await
                .map_err(|_| Unreachable::NotPublic)?;
        }
        Ok(())
    }
}

/// Whether the host policy applies on a network of `kind`: on production
/// only. The testnet's homeservers are on loopback by design, and an
/// injected network is a testnet a test started.
fn policy_applies(kind: NetworkKind) -> bool {
    // No `_ =>` arm: a kind added later stops the build here until someone
    // decides.
    match kind {
        NetworkKind::Production => true,
        NetworkKind::Testnet | NetworkKind::Injected => false,
    }
}

/// Whether every `_pubky` service record (HTTPS or SVCB) in a key's
/// `record` targets `homeserver`, in the exact form the SDK's signup writes,
/// its raw z-base32.
///
/// Text, compared exactly, unlike a pubky in a record (01 says to compare
/// those by key bytes): pkarr reads a target such as `www.<key>` as that
/// key, but then looks in its record under the name `www`, so any other
/// spelling would be a second place to look.
fn names_only(record: &SignedPacket, homeserver: Pubky) -> bool {
    let expected = homeserver.to_string();
    record
        .resource_records("_pubky")
        .all(|entry| match &entry.rdata {
            // An or-pattern: both arms bind `service` to the same type, the
            // SVCB record an HTTPS record wraps.
            RData::HTTPS(HTTPS(service)) | RData::SVCB(service) => {
                service.target.to_string() == expected
            }
            _ => true,
        })
}

/// Where a homeserver's own pkarr record says it is, for the host policy to
/// check: every A and AAAA record in it, under any name, and each domain an
/// HTTPS or SVCB record targets, once.
struct Endpoints {
    addresses: Vec<IpAddr>,
    domains: BTreeSet<String>,
}

impl Endpoints {
    /// The endpoints of `record`, or why the policy goes no further: a
    /// target that points on to another pkarr key, or more than
    /// [`MAX_HOMESERVER_DOMAINS`] domains, is [`Unreachable::NotPublic`];
    /// a record with nowhere to reach the homeserver is
    /// [`Unreachable::HomeserverNotFound`].
    ///
    /// A record is at most 1000 bytes (pkarr's limit), so the loop is short.
    fn of(record: &SignedPacket) -> Result<Self, Unreachable> {
        let mut addresses = Vec::new();
        let mut domains = BTreeSet::new();
        let mut at_own_addresses = false;
        for entry in record.all_resource_records() {
            match &entry.rdata {
                // A record holds its address as a number, as the wire does.
                RData::A(a) => addresses.push(IpAddr::V4(Ipv4Addr::from(a.address))),
                RData::AAAA(aaaa) => addresses.push(IpAddr::V6(Ipv6Addr::from(aaaa.address))),
                RData::HTTPS(HTTPS(service)) | RData::SVCB(service) => {
                    let target = service.target.to_string();
                    // `.`, the root, prints as nothing: this record's own
                    // A and AAAA records, as pkarr reads it.
                    if target.is_empty() || target == "." {
                        at_own_addresses = true;
                    } else if pubky::pkarr::PublicKey::try_from(target.as_str()).is_ok() {
                        // The same test pkarr makes before it follows a
                        // target to another key's record.
                        return Err(Unreachable::NotPublic);
                    } else {
                        domains.insert(target);
                    }
                }
                _ => {}
            }
        }
        if domains.len() > MAX_HOMESERVER_DOMAINS {
            return Err(Unreachable::NotPublic);
        }
        let reachable = !domains.is_empty() || (at_own_addresses && !addresses.is_empty());
        if !reachable {
            return Err(Unreachable::HomeserverNotFound);
        }
        Ok(Self { addresses, domains })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::Mutex;

    use pubky::pkarr::SignedPacket;
    use pubky::pkarr::dns::Name;
    use pubky::pkarr::dns::rdata::SVCB;
    use pubky::{ClientId, Keypair};
    use pubky_testnet::EphemeralTestnet;
    use sweepky_core::Pubky;
    use sweepky_core::paths;

    use super::{
        CheckedHomeservers, Endpoints, Found, Homeservers, MAX_HOMESERVER_DOMAINS,
        PkarrHomeservers, PkarrRecords, Unreachable, names_only,
    };
    use crate::CLIENT_ID;
    use crate::network::NetworkKind;
    use crate::pull::roster::poll_roster;
    use crate::pull::state::PollState;
    use crate::remote::pubky_of;
    use crate::state::LoginState;
    use crate::targets::host::SystemResolver;
    use crate::test_support::{
        FAKE_HOMESERVER, FakeHomeservers, FakeLookup, FakePublicRecords, FakeResolver, circle_json,
        random_pubky,
    };

    /// The non-public endpoints the policy must refuse: loopback, private,
    /// unique local and link-local, in both families.
    const NOT_PUBLIC_ADDRESSES: &[&str] =
        &["127.0.0.1", "::1", "10.0.0.1", "fd00::1", "169.254.1.1"];

    /// Public addresses, one of each family.
    const PUBLIC_ADDRESSES: &[&str] = &["140.82.112.3", "2606:4700:4700::1111"];

    /// A domain a homeserver's record names; every refusal is checked not
    /// to name it.
    const DOMAIN: &str = "marker-home.example";

    /// A [`PkarrRecords`] in place of pkarr: the records a test signed, by
    /// key, and every key asked for, in order. The `Mutex` is there for the
    /// same reason as in `test_support::FakeKeyStore`.
    #[derive(Default)]
    struct FakeRecords {
        records: HashMap<Pubky, SignedPacket>,
        asked: Mutex<Vec<Pubky>>,
    }

    impl FakeRecords {
        /// The same fake, holding `record` under the key that signed it.
        fn with(mut self, record: SignedPacket) -> Self {
            self.records.insert(signer_of(&record), record);
            self
        }

        /// Every key asked for so far, in order.
        fn asked(&self) -> Vec<Pubky> {
            self.asked.lock().expect("lock").clone()
        }

        /// How many times `key` was asked for so far.
        fn times_asked(&self, key: Pubky) -> usize {
            self.asked().iter().filter(|&&asked| asked == key).count()
        }
    }

    impl PkarrRecords for FakeRecords {
        async fn record_of(&self, key: Pubky) -> Option<SignedPacket> {
            self.asked.lock().expect("lock").push(key);
            self.records.get(&key).cloned()
        }
    }

    /// The key that signed `record`, as core's `Pubky`.
    fn signer_of(record: &SignedPacket) -> Pubky {
        Pubky::from_bytes(record.public_key().to_bytes())
    }

    /// A new key: its keypair, to sign its record with, and the key.
    fn new_key() -> (Keypair, Pubky) {
        let keypair = Keypair::random();
        let key = pubky_of(&keypair.public_key());
        (keypair, key)
    }

    fn name(text: &str) -> Name<'_> {
        Name::new(text).expect("a DNS name")
    }

    /// `user`'s record as the SDK's signup writes it: one `_pubky` HTTPS
    /// record whose target is `homeserver`, raw z-base32.
    fn user_record(user: &Keypair, homeserver: Pubky) -> SignedPacket {
        user_record_naming(user, &[homeserver])
    }

    /// `user`'s record with one `_pubky` HTTPS record for each of
    /// `homeservers`.
    fn user_record_naming(user: &Keypair, homeservers: &[Pubky]) -> SignedPacket {
        let targets: Vec<String> = homeservers.iter().map(ToString::to_string).collect();
        let mut builder = SignedPacket::builder();
        for target in &targets {
            builder = builder.https(name("_pubky"), SVCB::new(0, name(target)), 3600);
        }
        // `&Keypair` (the SDK's) passes as pkarr's: it derefs to the keypair
        // it wraps.
        builder.sign(user).expect("signs")
    }

    /// A homeserver's record as pubky-homeserver writes it: an HTTPS record
    /// whose target is `.` (its own addresses), one HTTPS record for each of
    /// `domains`, and an A or AAAA record for each of `addresses`.
    fn homeserver_record(
        homeserver: &Keypair,
        addresses: &[&str],
        domains: &[&str],
    ) -> SignedPacket {
        let mut builder = SignedPacket::builder().https(name("."), SVCB::new(1, name(".")), 3600);
        for domain in domains {
            builder = builder.https(name("."), SVCB::new(10, name(domain)), 3600);
        }
        for address in addresses {
            builder = builder.address(name("."), address.parse().expect("an address"), 3600);
        }
        builder.sign(homeserver).expect("signs")
    }

    /// The owner's login: their key and the homeserver it records, neither
    /// of which a member in these tests uses unless the test says so.
    fn owner_login() -> LoginState {
        LoginState::identity(
            "owner".parse().expect("a name"),
            random_pubky(),
            random_pubky(),
        )
    }

    /// What one run says of a member on the homeserver whose record is
    /// `home_record`, on a network of `kind`, with DNS answering as `dns`
    /// does; and the keys whose records pkarr was asked for.
    async fn member_on(
        home_record: SignedPacket,
        dns: &FakeResolver,
        kind: NetworkKind,
    ) -> (Found, Vec<Pubky>) {
        let (member_key, member) = new_key();
        let home = signer_of(&home_record);
        let resolver = FakeHomeservers::default().with_answers(member, &[FakeLookup::At(home)]);
        let records = FakeRecords::default()
            .with(user_record(&member_key, home))
            .with(home_record);
        let login = owner_login();
        let checked = CheckedHomeservers::new(&resolver, &records, dns, &login, kind);
        let found = Homeservers::new(&checked).resolve(member).await;
        (found, records.asked())
    }

    /// [`member_on`] a new homeserver whose record names `addresses` and
    /// `domains`, on production.
    async fn on_production(addresses: &[&str], domains: &[&str], dns: &FakeResolver) -> Found {
        let record = homeserver_record(&Keypair::random(), addresses, domains);
        let (found, _) = member_on(record, dns, NetworkKind::Production).await;
        found
    }

    #[tokio::test]
    async fn on_production_a_homeserver_at_an_address_that_is_not_public_is_refused() {
        let dns = FakeResolver::answering(&["8.8.8.8"]);
        for address in NOT_PUBLIC_ADDRESSES {
            // Alone, and beside a public address: one is enough.
            for addresses in [&[*address][..], &[PUBLIC_ADDRESSES[0], address]] {
                assert_eq!(
                    on_production(addresses, &[], &dns).await,
                    Err(Unreachable::NotPublic),
                    "{addresses:?}"
                );
            }
        }
        // Refused before any lookup: the addresses come first.
        assert!(dns.asked().is_empty(), "{:?}", dns.asked());
    }

    #[tokio::test]
    async fn on_production_a_homeserver_whose_domain_resolves_to_a_private_address_is_refused() {
        let dns = FakeResolver::answering(&["192.168.1.1"]);
        assert_eq!(
            on_production(PUBLIC_ADDRESSES, &[DOMAIN], &dns).await,
            Err(Unreachable::NotPublic)
        );
        // Through the host policy's own seam, the domain alone.
        assert_eq!(dns.asked(), [DOMAIN]);
    }

    #[tokio::test]
    async fn on_production_a_homeserver_on_public_addresses_passes() {
        let dns = FakeResolver::answering(&["8.8.8.8", "2001:4860:4860::8888"]);
        let (home_key, home) = new_key();
        let record = homeserver_record(&home_key, PUBLIC_ADDRESSES, &[DOMAIN]);
        let (found, asked) = member_on(record, &dns, NetworkKind::Production).await;
        assert_eq!(found, Ok(home));
        assert_eq!(dns.asked(), [DOMAIN]);
        // The member's own record, then its homeserver's.
        assert_eq!(asked.len(), 2);
        assert_eq!(asked[1], home);
    }

    #[tokio::test]
    async fn on_the_testnet_and_an_injected_network_nothing_is_checked() {
        let dns = FakeResolver::answering(&["127.0.0.1"]);
        for kind in [NetworkKind::Testnet, NetworkKind::Injected] {
            let (home_key, home) = new_key();
            let record = homeserver_record(&home_key, &["127.0.0.1"], &["localhost"]);
            let (found, asked) = member_on(record, &dns, kind).await;
            assert_eq!(found, Ok(home), "{kind:?}");
            assert!(asked.is_empty(), "{kind:?}: {asked:?}");
        }
        assert!(dns.asked().is_empty(), "{:?}", dns.asked());
    }

    #[tokio::test]
    async fn a_homeserver_many_keys_share_is_checked_once_a_run() {
        let (home_key, home) = new_key();
        let ((first_key, first), (second_key, second)) = (new_key(), new_key());
        let resolver = FakeHomeservers::default()
            .with_answers(first, &[FakeLookup::At(home)])
            .with_answers(second, &[FakeLookup::At(home)]);
        let records = FakeRecords::default()
            .with(user_record(&first_key, home))
            .with(user_record(&second_key, home))
            .with(homeserver_record(&home_key, PUBLIC_ADDRESSES, &[DOMAIN]));
        let dns = FakeResolver::answering(&["8.8.8.8"]);
        let login = owner_login();
        let checked =
            CheckedHomeservers::new(&resolver, &records, &dns, &login, NetworkKind::Production);
        let mut homeservers = Homeservers::new(&checked);

        assert_eq!(homeservers.resolve(first).await, Ok(home));
        assert_eq!(homeservers.resolve(second).await, Ok(home));
        // A failed read looks the key up again, but not its homeserver.
        assert_eq!(homeservers.after_failed_read(first).await, Ok(home));
        assert_eq!(records.times_asked(home), 1);
        assert_eq!(dns.asked(), [DOMAIN]);
        // Each key's own record is read at each of its lookups.
        assert_eq!(records.times_asked(first), 2);
        assert_eq!(records.times_asked(second), 1);
    }

    #[tokio::test]
    async fn a_refused_homeserver_stays_refused_for_the_run() {
        let (home_key, home) = new_key();
        let ((first_key, first), (second_key, second)) = (new_key(), new_key());
        let resolver = FakeHomeservers::default()
            .with_answers(first, &[FakeLookup::At(home)])
            .with_answers(second, &[FakeLookup::At(home)]);
        let records = FakeRecords::default()
            .with(user_record(&first_key, home))
            .with(user_record(&second_key, home))
            .with(homeserver_record(&home_key, &[], &[DOMAIN]));
        let dns = FakeResolver::answering(&["10.0.0.1"]);
        let login = owner_login();
        let checked =
            CheckedHomeservers::new(&resolver, &records, &dns, &login, NetworkKind::Production);
        let mut homeservers = Homeservers::new(&checked);

        for key in [first, second] {
            assert_eq!(homeservers.resolve(key).await, Err(Unreachable::NotPublic));
        }
        assert_eq!(records.times_asked(home), 1);
        assert_eq!(dns.asked(), [DOMAIN]);
    }

    #[tokio::test]
    async fn a_homeserver_with_no_record_or_nowhere_to_reach_it_is_unreachable() {
        let dns = FakeResolver::answering(&["8.8.8.8"]);
        let home_key = Keypair::random();
        let no_https = SignedPacket::builder()
            .address(name("."), "8.8.8.8".parse().expect("an address"), 3600)
            .sign(&home_key)
            .expect("signs");
        let cases = [
            (
                "an HTTPS record for its own addresses, and none",
                homeserver_record(&home_key, &[], &[]),
            ),
            ("addresses, and no HTTPS record", no_https),
        ];
        for (what, record) in cases {
            let (found, _) = member_on(record, &dns, NetworkKind::Production).await;
            assert_eq!(found, Err(Unreachable::HomeserverNotFound), "{what}");
        }

        // No record of the homeserver at all.
        let (member_key, member) = new_key();
        let nowhere = random_pubky();
        let resolver = FakeHomeservers::default().with_answers(member, &[FakeLookup::At(nowhere)]);
        let records = FakeRecords::default().with(user_record(&member_key, nowhere));
        let login = owner_login();
        let checked =
            CheckedHomeservers::new(&resolver, &records, &dns, &login, NetworkKind::Production);
        assert_eq!(
            Homeservers::new(&checked).resolve(member).await,
            Err(Unreachable::HomeserverNotFound)
        );
        assert!(dns.asked().is_empty(), "{:?}", dns.asked());
    }

    #[tokio::test]
    async fn the_owner_and_the_homeserver_their_login_records_are_never_checked() {
        let (owner_home_key, owner_home) = new_key();
        let (owner_key, owner) = new_key();
        let (member_key, member) = new_key();
        let resolver = FakeHomeservers::default()
            .with_answers(owner, &[FakeLookup::At(owner_home)])
            .with_answers(member, &[FakeLookup::At(owner_home)]);
        // The owner's homeserver is on a private address, and the owner's
        // own record names a second one too: neither is looked at.
        let records = FakeRecords::default()
            .with(user_record_naming(
                &owner_key,
                &[owner_home, random_pubky()],
            ))
            .with(user_record(&member_key, owner_home))
            .with(homeserver_record(&owner_home_key, &["10.0.0.1"], &[]));
        let dns = FakeResolver::answering(&["10.0.0.1"]);
        let login = LoginState::identity("owner".parse().expect("a name"), owner, owner_home);
        let checked =
            CheckedHomeservers::new(&resolver, &records, &dns, &login, NetworkKind::Production);
        let mut homeservers = Homeservers::new(&checked);

        assert_eq!(homeservers.resolve(owner).await, Ok(owner_home));
        assert_eq!(homeservers.resolve(member).await, Ok(owner_home));
        // The member's own record is read; neither the owner's nor their
        // homeserver's is.
        assert_eq!(records.asked(), [member]);
        assert!(dns.asked().is_empty(), "{:?}", dns.asked());
    }

    #[tokio::test]
    async fn a_key_whose_record_names_a_second_homeserver_is_refused() {
        // The SDK's requests use every `_pubky` record, not only the first
        // `get_homeserver_of` gives, so a public first one cannot cover for
        // a second.
        let (home_key, home) = new_key();
        let (member_key, member) = new_key();
        let resolver = FakeHomeservers::default().with_answers(member, &[FakeLookup::At(home)]);
        let records = FakeRecords::default()
            .with(user_record_naming(&member_key, &[home, random_pubky()]))
            .with(homeserver_record(&home_key, PUBLIC_ADDRESSES, &[]));
        let dns = FakeResolver::answering(&["8.8.8.8"]);
        let login = owner_login();
        let checked =
            CheckedHomeservers::new(&resolver, &records, &dns, &login, NetworkKind::Production);
        assert_eq!(
            Homeservers::new(&checked).resolve(member).await,
            Err(Unreachable::NotPublic)
        );
        assert_eq!(records.asked(), [member]);
    }

    #[tokio::test]
    async fn an_endpoint_the_policy_cannot_classify_refuses_the_key() {
        // A target that points on to another pkarr key, which the SDK would
        // follow and the policy does not.
        let (_, elsewhere) = new_key();
        let onward = elsewhere.to_string();
        let subdomain = format!("www.{elsewhere}");
        for target in [onward.as_str(), subdomain.as_str()] {
            let dns = FakeResolver::answering(&["8.8.8.8"]);
            assert_eq!(
                on_production(PUBLIC_ADDRESSES, &[target], &dns).await,
                Err(Unreachable::NotPublic),
                "{target}"
            );
            assert!(dns.asked().is_empty(), "{:?}", dns.asked());
        }

        // A domain whose lookup fails, or that has no address.
        for dns in [FakeResolver::failing(), FakeResolver::answering(&[])] {
            assert_eq!(
                on_production(PUBLIC_ADDRESSES, &[DOMAIN], &dns).await,
                Err(Unreachable::NotPublic)
            );
        }

        // More domains than the policy looks up: refused before any lookup.
        let domains: Vec<String> = (0..=MAX_HOMESERVER_DOMAINS)
            .map(|n| format!("d{n}.example"))
            .collect();
        let domains: Vec<&str> = domains.iter().map(String::as_str).collect();
        let dns = FakeResolver::answering(&["8.8.8.8"]);
        assert_eq!(
            on_production(PUBLIC_ADDRESSES, &domains, &dns).await,
            Err(Unreachable::NotPublic)
        );
        assert!(dns.asked().is_empty(), "{:?}", dns.asked());
    }

    #[tokio::test]
    async fn a_roster_key_on_a_private_homeserver_is_skipped_with_one_warning_and_never_read() {
        let login = owner_login();
        let owner = login.pubky;
        let ((private_key, private), (public_key, public)) = (new_key(), new_key());
        let ((private_home_key, private_home), (public_home_key, public_home)) =
            (new_key(), new_key());
        let resolver = FakeHomeservers::default()
            .with_answers(private, &[FakeLookup::At(private_home)])
            .with_answers(public, &[FakeLookup::At(public_home)]);
        let records = FakeRecords::default()
            .with(user_record(&private_key, private_home))
            .with(homeserver_record(
                &private_home_key,
                &["10.0.0.1"],
                &[DOMAIN],
            ))
            .with(user_record(&public_key, public_home))
            .with(homeserver_record(&public_home_key, PUBLIC_ADDRESSES, &[]));
        let storage = FakePublicRecords::default().with_record(
            owner,
            paths::circle(),
            &circle_json(owner, &[owner, private, public]),
        );
        let dns = FakeResolver::answering(&["8.8.8.8"]);
        let checked =
            CheckedHomeservers::new(&resolver, &records, &dns, &login, NetworkKind::Production);
        let mut homeservers = Homeservers::new(&checked);
        let found = poll_roster(&storage, &mut homeservers, owner, &mut PollState::default()).await;

        assert_eq!(found.warnings.len(), 1, "{:?}", found.warnings);
        let warning = &found.warnings[0];
        assert!(warning.contains(&private.to_string()), "{warning}");
        assert!(
            warning.ends_with(&Unreachable::NotPublic.to_string()),
            "{warning}"
        );
        for quoted in ["10.0.0.1", DOMAIN, &private_home.to_string()] {
            assert!(!warning.contains(quoted), "{warning}");
        }
        // Nothing of its storage is asked for; the public key's is read.
        let asked = storage.asked();
        assert!(asked.iter().all(|(key, _)| *key != private), "{asked:?}");
        assert!(asked.contains(&(public, paths::BOUNTIES_DIR.to_owned())));
        assert!(asked.contains(&(public, paths::SWEEPS_DIR.to_owned())));
        // Unreachable is not untrusted: it stays in the roster.
        assert!(found.roster.is_in_roster(private));
    }

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
    async fn no_record_and_a_failed_lookup_are_unreachable_and_kept_for_the_run() {
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
    }

    #[tokio::test]
    #[pubky_testnet::test]
    async fn on_a_testnet_a_signed_up_key_is_at_its_homeserver_which_the_policy_refuses() {
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
        let (user, home) = (pubky_of(&signer.public_key()), pubky_of(&homeserver));

        let resolver = PkarrHomeservers::new(&pubky);
        let mut homeservers = Homeservers::new(&resolver);
        assert_eq!(homeservers.resolve(user).await, Ok(home));
        assert_eq!(
            homeservers.resolve(random_pubky()).await,
            Err(Unreachable::NoHomeserver)
        );

        // The records the SDK's pkarr client reads: the user's, as the
        // SDK's signup wrote it, names the homeserver alone, and the
        // homeserver's is on loopback, as a testnet's is by design.
        let user_record = resolver.record_of(user).await.expect("the user's record");
        assert!(names_only(&user_record, home));
        let home_record = resolver.record_of(home).await.expect("its record");
        let endpoints = Endpoints::of(&home_record).expect("somewhere to reach it");
        assert!(
            endpoints.addresses.iter().any(IpAddr::is_loopback),
            "{:?}",
            endpoints.addresses
        );

        // So with the policy on, as on production, the key is refused; on
        // the injected network this test runs on, it is not.
        let login = owner_login();
        let checked = CheckedHomeservers::new(
            &resolver,
            &resolver,
            &SystemResolver,
            &login,
            NetworkKind::Production,
        );
        assert_eq!(
            Homeservers::new(&checked).resolve(user).await,
            Err(Unreachable::NotPublic)
        );
        let unchecked = CheckedHomeservers::new(
            &resolver,
            &resolver,
            &SystemResolver,
            &login,
            NetworkKind::Injected,
        );
        assert_eq!(Homeservers::new(&unchecked).resolve(user).await, Ok(home));
    }
}
