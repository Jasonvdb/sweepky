//! Sweepky's core library: records, ids, paths, target pinning, trust labels,
//! the events-feed parser, finding groups, age encryption, the package envelope
//! and the manifest. None of it exists yet; P1a and P1b add it.
//!
//! Two rules hold for everything that lands here (see "Rust conventions" in
//! `docs/plan/03-cli-and-skill.md`):
//!
//! - **No network or file I/O.** Functions take values and return values. That
//!   keeps the crate unit-testable without a network or a temp directory, and
//!   lets it compile to WASM later. The CLI owns the network and the disk: for
//!   example, the package envelope is built here from an in-memory list of
//!   files, while the directory walk and its safety rules live in `sweepky-cli`.
//! - **Typed errors with `thiserror`.** A fallible function returns
//!   `Result<T, E>` where `E` is an error enum the caller can `match` on, so the
//!   CLI can react to one case (say, an unknown key) differently from another.
//!   `anyhow` turns every error into a message and loses that, which is fine in
//!   the binary, so it is used only there.

/// This crate's version, `version` from Cargo.toml.
///
/// `env!` reads `CARGO_PKG_VERSION`, which Cargo sets while compiling, so the
/// value is baked in at compile time and cannot drift from the manifest. A
/// missing variable is a compile error, not a runtime one.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn version_is_major_minor_patch() {
        // `assert!` and `assert_eq!` panic when they fail, and a panic is how a
        // test reports a bad value. Library code itself must not panic on bad
        // input.
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
