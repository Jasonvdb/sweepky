//! The `sweepky` command-line tool. This is a stub that prints its version; the
//! commands arrive from P2a on.
//!
//! How the crate will be split (see "Rust conventions" in
//! `docs/plan/03-cli-and-skill.md`):
//!
//! - A library entry point (`src/lib.rs`) lands in P2a. It takes the Pubky
//!   client, the relay URL and the default homeserver as arguments, so the
//!   end-to-end test can hand it a local testnet instead of production. This
//!   file then only parses arguments and calls into it.
//! - `anyhow` lives only here, in the binary. A binary just needs a good error
//!   message for the user; `sweepky-core` returns typed `thiserror` errors that
//!   code can `match` on.

/// The binary's version, `version` from Cargo.toml, baked in at compile time.
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    println!("sweepky {VERSION}");
}

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn version_is_major_minor_patch() {
        let parts: Vec<&str> = VERSION.split('.').collect();
        assert_eq!(
            parts.len(),
            3,
            "VERSION {VERSION:?} is not major.minor.patch"
        );
        for part in parts {
            assert!(
                part.parse::<u64>().is_ok(),
                "VERSION {VERSION:?}: {part:?} is not a number"
            );
        }
    }
}
