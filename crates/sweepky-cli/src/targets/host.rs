//! The network policy for a target's host. v1 sweeps public repositories
//! only (`docs/plan/00-overview.md`), so before `post` or `run` lets git
//! contact a repository, its host is looked up and every address it
//! resolves to must be public. [`HttpsRemote::for_repo`] is the one way to
//! make the `https://<repo>` remote that git's network commands take
//! (`git::Remote`), and it refuses a host with any address on a loopback,
//! private, link-local or otherwise reserved range. [`check_host`] is that
//! check on its own, which GitHub's API host goes through too before the
//! real source asks it about a pull request.
//!
//! - [`is_public`], the pure address classifier.
//! - [`ResolveHost`], the seam the lookup goes through: [`SystemResolver`]
//!   is the real one, and the tests use `test_support::FakeResolver`.
//! - [`HttpsRemote`], the remote that exists only once its host passed.
//!
//! **What the check cannot close.** git looks the name up again when it
//! connects, so a DNS answer that changes between this check and git's own
//! lookup (DNS rebinding) is not caught: the check stops a host that names
//! an internal address, not someone who controls its DNS and times the
//! change. A redirect to an internal host is stopped by the git runner's
//! `http.followRedirects=false`. With `HTTPS_PROXY` set, git asks the proxy
//! to connect, and the proxy makes a lookup of its own.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context as _, bail};
use sweepky_core::RepoName;

// The refusals, fixed text that names neither the host nor an address: the
// caller says which target, or which service, it was.
const LOOKUP_FAILED: &str = "could not look up the host, so Sweepky did not contact it; check the \
                             network connection and try again";
const NO_ADDRESS: &str = "the host has no address, so Sweepky did not contact it";
const NOT_PUBLIC: &str = "the host resolves to an address that is not public (loopback, private, \
                          link-local or otherwise reserved), so Sweepky refused to contact it; \
                          Sweepky sweeps public repositories only";

/// A real target's repository as git is given it, `https://<repo>`: the
/// only form a network git command takes for a real target, made only
/// once the host policy has passed its host.
///
/// Its field is private and [`HttpsRemote::for_repo`] is its only
/// constructor, so holding one means the check ran. It is a check of one
/// moment: git looks the name up again (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HttpsRemote {
    url: String,
}

impl HttpsRemote {
    /// `https://<repo>`, once `repo`'s host passed [`check_host`].
    pub(crate) async fn for_repo(
        repo: &RepoName,
        resolver: &impl ResolveHost,
    ) -> anyhow::Result<Self> {
        // `RepoName` always has a `/` after its host, so this `context`
        // never fires; it is there because this code never panics.
        let (host, _path) = repo
            .as_str()
            .split_once('/')
            .context("the repository name has no host")?;
        check_host(host, resolver).await?;
        Ok(Self {
            url: format!("https://{repo}"),
        })
    }

    /// The URL as git is given it.
    pub(crate) fn as_str(&self) -> &str {
        &self.url
    }
}

/// Passes `host` once `resolver` has given at least one address for it and
/// every one of them is public.
///
/// Refused, in fixed text that names neither the host nor an address, when
/// the lookup fails, when it gives no address, and when any one address is
/// not public, whatever the others are: git and reqwest connect to
/// whichever address they like, so one private address is enough to reach
/// the sweeper's own network.
pub(crate) async fn check_host(host: &str, resolver: &impl ResolveHost) -> anyhow::Result<()> {
    // The lookup's own error is dropped rather than added as context: its
    // text is the resolver's, and could name the host.
    let Ok(addresses) = resolver.resolve(host).await else {
        bail!(LOOKUP_FAILED);
    };
    // `all` is true for an empty list, so an empty answer is refused before
    // it.
    if addresses.is_empty() {
        bail!(NO_ADDRESS);
    }
    if !addresses.into_iter().all(is_public) {
        bail!(NOT_PUBLIC);
    }
    Ok(())
}

/// Where a host's addresses are looked up: the seam between the host
/// policy and DNS.
///
/// A trait so that the tests can answer with any addresses, or fail, with
/// no network. As with `device::PublicKeys`, the method is an `async fn`,
/// so callers take `&impl ResolveHost` rather than `&dyn ResolveHost`, and
/// the compiler makes one copy of each caller per implementation.
pub(crate) trait ResolveHost {
    /// Every address `host` resolves to. An error's text is never shown
    /// ([`check_host`] replaces it with fixed text).
    async fn resolve(&self, host: &str) -> anyhow::Result<Vec<IpAddr>>;
}

/// The real [`ResolveHost`]: the system resolver, which git's own lookup
/// asks too.
pub(crate) struct SystemResolver;

impl ResolveHost for SystemResolver {
    async fn resolve(&self, host: &str) -> anyhow::Result<Vec<IpAddr>> {
        // `lookup_host` calls the system's `getaddrinfo` on tokio's
        // blocking thread pool, so the runtime is not held up while it
        // waits. It takes a host and a port, and answers with socket
        // addresses; the port, 443 for https, plays no part in the answer.
        // There is no timeout here: the system resolver gives up on its own.
        let addresses = tokio::net::lookup_host((host, 443)).await?;
        Ok(addresses.map(|socket| socket.ip()).collect())
    }
}

/// Whether `address` is public: on the internet at large, not on this
/// machine, its local network or a range set aside for something else.
///
/// Pure, so the tests check it address by address. An IPv6 address that
/// carries an IPv4 one (see [`carried_ipv4`]) is as public as the address
/// it carries.
pub(crate) fn is_public(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_v4(address),
        IpAddr::V6(address) => is_public_v6(address),
    }
}

/// The IPv4 blocks that are not public, each as its first address and its
/// prefix length: `(10.0.0.0, 8)` is 10.0.0.0/8. Every other IPv4 address
/// is public. From IANA's special-purpose address registry, plus multicast.
const NON_PUBLIC_V4: [(Ipv4Addr, u32); 14] = [
    // "This network" (RFC 791), 0.0.0.0 (unspecified) included.
    (Ipv4Addr::new(0, 0, 0, 0), 8),
    // Private (RFC 1918).
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    // Shared address space for carrier-grade NAT (RFC 6598).
    (Ipv4Addr::new(100, 64, 0, 0), 10),
    // Loopback.
    (Ipv4Addr::new(127, 0, 0, 0), 8),
    // Link-local (RFC 3927), where clouds serve instance metadata
    // (169.254.169.254).
    (Ipv4Addr::new(169, 254, 0, 0), 16),
    // Private (RFC 1918).
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    // IETF protocol assignments (RFC 6890).
    (Ipv4Addr::new(192, 0, 0, 0), 24),
    // Documentation, TEST-NET-1 (RFC 5737).
    (Ipv4Addr::new(192, 0, 2, 0), 24),
    // Private (RFC 1918).
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    // Benchmarking (RFC 2544).
    (Ipv4Addr::new(198, 18, 0, 0), 15),
    // Documentation, TEST-NET-2.
    (Ipv4Addr::new(198, 51, 100, 0), 24),
    // Documentation, TEST-NET-3.
    (Ipv4Addr::new(203, 0, 113, 0), 24),
    // Multicast.
    (Ipv4Addr::new(224, 0, 0, 0), 4),
    // Reserved (RFC 1112), the broadcast address 255.255.255.255 included.
    (Ipv4Addr::new(240, 0, 0, 0), 4),
];

/// Global unicast, 2000::/3: every public IPv6 address is in it, so
/// everything outside it is refused at once. That is `::`, `::1`, the
/// deprecated IPv4-compatible `::a.b.c.d`, discard-only `100::/64`, unique
/// local `fc00::/7`, link-local `fe80::/10`, the deprecated site-local
/// `fec0::/10`, multicast `ff00::/8`, and space not yet assigned.
const GLOBAL_UNICAST: (Ipv6Addr, u32) = (Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0), 3);

/// The blocks inside [`GLOBAL_UNICAST`] that are still not public.
const NON_PUBLIC_GLOBAL_V6: [(Ipv6Addr, u32); 3] = [
    // IETF protocol assignments (RFC 2928), Teredo `2001::/32` and
    // benchmarking `2001:2::/48` among them. A few anycast services in it
    // are reachable, but none serves a repository, so the whole block goes.
    (Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 23),
    // Documentation (RFC 3849).
    (Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32),
    // Documentation (RFC 9637).
    (Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0), 20),
];

/// NAT64's well-known prefix (RFC 6052): `64:ff9b::a.b.c.d` reaches the
/// IPv4 host `a.b.c.d` through a translator. An IPv6-only network with
/// DNS64 answers this for a host with no IPv6 address, github.com among
/// them.
const NAT64: (Ipv6Addr, u32) = (Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0), 96);

/// 6to4 (RFC 3056): `2002:aabb:ccdd::/48` reaches the IPv4 host
/// `aa.bb.cc.dd` through a relay.
const SIX_TO_FOUR: (Ipv6Addr, u32) = (Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16);

fn is_public_v4(address: Ipv4Addr) -> bool {
    // `&block` in the closure's argument copies each tuple out of the
    // borrowed array, so `in_v4_block` takes it by value.
    !NON_PUBLIC_V4
        .iter()
        .any(|&block| in_v4_block(address, block))
}

fn is_public_v6(address: Ipv6Addr) -> bool {
    // Checked first, because the mapped and NAT64 forms are outside global
    // unicast, yet reach a public host when they carry a public address.
    if let Some(carried) = carried_ipv4(address) {
        return is_public_v4(carried);
    }
    in_v6_block(address, GLOBAL_UNICAST)
        && !NON_PUBLIC_GLOBAL_V6
            .iter()
            .any(|&block| in_v6_block(address, block))
}

/// The IPv4 address that `address` reaches, when it is one of the three
/// forms that reach an IPv4 host: IPv4-mapped (`::ffff:a.b.c.d`, how a
/// dual-stack socket names an IPv4 peer), NAT64 ([`NAT64`]) and 6to4
/// ([`SIX_TO_FOUR`]). `None` for any other address.
///
/// The deprecated IPv4-compatible form (`::a.b.c.d`) is not one of them:
/// nothing routes it any more, so it is refused as outside global unicast.
fn carried_ipv4(address: Ipv6Addr) -> Option<Ipv4Addr> {
    // Each `let [..] = address.octets()` picks bytes out by their place in
    // the 16-byte array: a pattern of the array's whole shape, so it can
    // never be out of bounds the way an index could.
    if let Some(mapped) = address.to_ipv4_mapped() {
        Some(mapped)
    } else if in_v6_block(address, NAT64) {
        let [.., a, b, c, d] = address.octets();
        Some(Ipv4Addr::new(a, b, c, d))
    } else if in_v6_block(address, SIX_TO_FOUR) {
        let [_, _, a, b, c, d, ..] = address.octets();
        Some(Ipv4Addr::new(a, b, c, d))
    } else {
        None
    }
}

/// Whether `address` is in the block `first/prefix`: whether its first
/// `prefix` bits are those of `first`.
fn in_v4_block(address: Ipv4Addr, (first, prefix): (Ipv4Addr, u32)) -> bool {
    // `rest` has every bit after the prefix set: 0.255.255.255 for a /8.
    // Setting those bits on both sides leaves only the prefix to compare.
    // `checked_shr` is `None` for a shift of 32 or more, where `>>` would
    // panic; then no bit is left over and the whole address is compared.
    let rest = u32::MAX.checked_shr(prefix).unwrap_or(0);
    (address.to_bits() | rest) == (first.to_bits() | rest)
}

/// [`in_v4_block`] for IPv6.
fn in_v6_block(address: Ipv6Addr, (first, prefix): (Ipv6Addr, u32)) -> bool {
    let rest = u128::MAX.checked_shr(prefix).unwrap_or(0);
    (address.to_bits() | rest) == (first.to_bits() | rest)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{
        HttpsRemote, LOOKUP_FAILED, NO_ADDRESS, NOT_PUBLIC, ResolveHost, SystemResolver, is_public,
    };
    use crate::test_support::{FAKE_LOOKUP_TEXT, FakeResolver};

    /// Addresses from every IPv4 block the policy refuses, the first and
    /// the last of a block where its size matters.
    const REFUSED_V4: &[&str] = &[
        // "This network", 0.0.0.0 (unspecified) included.
        "0.0.0.0",
        "0.255.255.255",
        // Private (RFC 1918).
        "10.0.0.0",
        "10.255.255.255",
        "172.16.0.0",
        "172.31.255.255",
        "192.168.0.0",
        "192.168.255.255",
        // Carrier-grade NAT.
        "100.64.0.0",
        "100.127.255.255",
        // Loopback.
        "127.0.0.1",
        "127.255.255.255",
        // Link-local, the cloud metadata address included.
        "169.254.0.0",
        "169.254.169.254",
        // IETF protocol assignments.
        "192.0.0.0",
        "192.0.0.255",
        // Documentation.
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.255",
        // Benchmarking.
        "198.18.0.0",
        "198.19.255.255",
        // Multicast.
        "224.0.0.1",
        "239.255.255.255",
        // Reserved, and the broadcast address.
        "240.0.0.0",
        "255.255.255.254",
        "255.255.255.255",
    ];

    /// Public IPv4 addresses, those just outside each refused block
    /// included, so a block one bit too wide is caught.
    const PUBLIC_V4: &[&str] = &[
        "1.1.1.1",
        "8.8.8.8",
        "140.82.112.3",
        "1.0.0.0",
        "9.255.255.255",
        "11.0.0.0",
        "100.63.255.255",
        "100.128.0.0",
        "126.255.255.255",
        "128.0.0.0",
        "169.253.255.255",
        "169.255.0.0",
        "172.15.255.255",
        "172.32.0.0",
        "191.255.255.255",
        "192.0.1.0",
        "192.0.3.0",
        "192.167.255.255",
        "192.169.0.0",
        "198.17.255.255",
        "198.20.0.0",
        "198.51.99.255",
        "198.51.101.0",
        "203.0.112.255",
        "203.0.114.0",
        "223.255.255.255",
    ];

    /// IPv6 addresses the policy refuses, each carrying no IPv4 address
    /// (those are checked through [`REFUSED_V4`]).
    const REFUSED_V6: &[&str] = &[
        // Unspecified and loopback.
        "::",
        "::1",
        // Discard-only.
        "100::",
        "100::ffff:ffff:ffff:ffff",
        // Unique local.
        "fc00::1",
        "fdff:ffff::1",
        // Link-local.
        "fe80::1",
        "febf:ffff::1",
        // Site-local, deprecated.
        "fec0::1",
        "feff:ffff::1",
        // Multicast.
        "ff00::",
        "ff02::1",
        "ff0e::1",
        // Teredo, inside the IETF protocol assignments 2001::/23.
        "2001::",
        "2001:0:4136:e378:8000:63bf:3fff:fdd2",
        // Benchmarking, and the last of 2001::/23.
        "2001:2::1",
        "2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff",
        // Documentation.
        "2001:db8::",
        "2001:db8:ffff::1",
        "3fff::",
        "3fff:fff:ffff::1",
        // Local-use NAT64 and SRv6 segment ids.
        "64:ff9b:1::1",
        "5f00::1",
        // Just outside global unicast 2000::/3, on either side.
        "1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        "4000::1",
    ];

    /// Public IPv6 addresses, those just outside a refused block included.
    const PUBLIC_V6: &[&str] = &[
        "2606:4700:4700::1111",
        "2001:4860:4860::8888",
        "2a00:1450:4001::1",
        "2000::1",
        "2001:200::1",
        "2001:db7:ffff::1",
        "2001:db9::1",
        "3fff:1000::1",
        "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    ];

    /// A repository on a synthetic host; every refusal is checked not to
    /// name it.
    const REPO: &str = "marker-host.example/org/name";
    const HOST: &str = "marker-host.example";

    fn ipv4(text: &str) -> Ipv4Addr {
        text.parse().expect("an IPv4 address")
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("an IP address")
    }

    /// `64:ff9b::a.b.c.d`, NAT64's form of `address`.
    fn nat64(address: Ipv4Addr) -> Ipv6Addr {
        let [a, b, c, d] = address.octets();
        let (high, low) = (u16::from_be_bytes([a, b]), u16::from_be_bytes([c, d]));
        Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, high, low)
    }

    /// `2002:aabb:ccdd::1`, an address in 6to4's block for `address`.
    fn six_to_four(address: Ipv4Addr) -> Ipv6Addr {
        let [a, b, c, d] = address.octets();
        let (high, low) = (u16::from_be_bytes([a, b]), u16::from_be_bytes([c, d]));
        Ipv6Addr::new(0x2002, high, low, 0, 0, 0, 0, 1)
    }

    #[test]
    fn refused_ipv4_is_not_public_in_any_form() {
        for text in REFUSED_V4 {
            let address = ipv4(text);
            assert!(!is_public(IpAddr::V4(address)), "{text}");
            // The same address carried in IPv6: each form reaches it.
            for (form, carried) in [
                ("IPv4-mapped", address.to_ipv6_mapped()),
                ("IPv4-compatible", address.to_ipv6_compatible()),
                ("NAT64", nat64(address)),
                ("6to4", six_to_four(address)),
            ] {
                assert!(
                    !is_public(IpAddr::V6(carried)),
                    "{text} as {form} ({carried})"
                );
            }
        }
    }

    #[test]
    fn public_ipv4_is_public_directly_mapped_and_through_nat64_and_6to4() {
        for text in PUBLIC_V4 {
            let address = ipv4(text);
            assert!(is_public(IpAddr::V4(address)), "{text}");
            for (form, carried) in [
                ("IPv4-mapped", address.to_ipv6_mapped()),
                ("NAT64", nat64(address)),
                ("6to4", six_to_four(address)),
            ] {
                assert!(
                    is_public(IpAddr::V6(carried)),
                    "{text} as {form} ({carried})"
                );
            }
            // The deprecated IPv4-compatible form reaches nothing, so it
            // is refused even for a public address.
            let compatible = address.to_ipv6_compatible();
            assert!(!is_public(IpAddr::V6(compatible)), "{compatible}");
        }
    }

    #[test]
    fn ipv6_is_public_only_in_global_unicast_outside_its_reserved_blocks() {
        for text in REFUSED_V6 {
            assert!(!is_public(ip(text)), "{text}");
        }
        for text in PUBLIC_V6 {
            assert!(is_public(ip(text)), "{text}");
        }
    }

    async fn remote_for(resolver: &FakeResolver) -> anyhow::Result<HttpsRemote> {
        HttpsRemote::for_repo(&REPO.parse().expect("a repo name"), resolver).await
    }

    #[tokio::test]
    async fn a_host_with_only_public_addresses_gives_its_https_remote() {
        let resolver =
            FakeResolver::answering(&["140.82.112.3", "2606:4700:4700::1111", "64:ff9b::808:808"]);
        let remote = remote_for(&resolver)
            .await
            .expect("every address is public");
        assert_eq!(remote.as_str(), "https://marker-host.example/org/name");
        // The host alone is looked up, never the path.
        assert_eq!(resolver.asked(), [HOST]);
    }

    #[tokio::test]
    async fn a_host_is_refused_for_any_non_public_address_in_fixed_text() {
        let cases: &[(&str, &[&str], &str)] = &[
            (
                "one private address among public ones",
                &["8.8.8.8", "10.0.0.1", "2606:4700:4700::1111"],
                NOT_PUBLIC,
            ),
            ("loopback", &["127.0.0.1"], NOT_PUBLIC),
            (
                "a private address, IPv4-mapped",
                &["::ffff:10.0.0.1"],
                NOT_PUBLIC,
            ),
            ("no address", &[], NO_ADDRESS),
        ];
        for (what, addresses, expected) in cases {
            let error = remote_for(&FakeResolver::answering(addresses))
                .await
                .expect_err(what);
            let message = format!("{error:#}");
            assert_eq!(message, *expected, "{what}");
            assert!(!message.contains(HOST), "{what}: {message}");
            for address in *addresses {
                assert!(!message.contains(address), "{what}: {message}");
            }
        }
        // A failed lookup: fixed text again, and none of the resolver's.
        let error = remote_for(&FakeResolver::failing())
            .await
            .expect_err("the lookup fails");
        let message = format!("{error:#}");
        assert_eq!(message, LOOKUP_FAILED);
        assert!(!message.contains(HOST), "{message}");
        assert!(
            !format!("{error:?}").contains(FAKE_LOOKUP_TEXT),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn the_system_resolver_reads_localhost_as_loopback_only() {
        // `localhost` comes from the hosts file, so no network is needed,
        // and the policy refuses every address it gives.
        let addresses = SystemResolver
            .resolve("localhost")
            .await
            .expect("localhost resolves");
        assert!(!addresses.is_empty());
        assert!(addresses.iter().all(IpAddr::is_loopback), "{addresses:?}");
        assert!(!addresses.into_iter().any(is_public));
    }

    #[test]
    fn a_remote_has_no_way_in_but_the_check() {
        // Checked when the test compiles: no default, string or JSON makes
        // an `HttpsRemote`, so `for_repo` is the only way to get one.
        crate::test_support::assert_not_impl_any!(
            HttpsRemote: Default,
            std::str::FromStr,
            From<String>,
            From<&'static str>,
            serde::de::DeserializeOwned,
        );
    }
}
