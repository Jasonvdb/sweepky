//! Where `post` and `run` get a target's repository from, and the network
//! policy for it. So far:
//!
//! - `host`: the policy for a target's host. The pure address classifier,
//!   the `ResolveHost` seam a lookup goes through, and `HttpsRemote`, the
//!   one form a real target's repository reaches git in, which exists only
//!   for a host whose every address is public.
//! - `fixture`: the fixture source's `LocalRemote`, its repository on this
//!   disk, which only that source can make.
//!
//! The target sources themselves, the fixture one and the real one, come
//! later in P2b.

// Nothing outside the tests calls into this module yet: the target sources,
// later in P2b, are the first callers. As in `git.rs`, `expect` (not
// `allow`) silences the dead-code warning only while it is true, and the
// first caller removes it.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the target sources, later in P2b, are the first callers of the host policy"
    )
)]

pub(crate) mod fixture;
pub(crate) mod host;
