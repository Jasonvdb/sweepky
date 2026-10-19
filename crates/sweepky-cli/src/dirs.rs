//! Where `sweepky` keeps its files on this machine: the config directory
//! (secrets and this install's own lists) and the data directory (what `pull`
//! saves).
//!
//! | | Default | Under `SWEEPKY_HOME=<dir>` |
//! |---|---|---|
//! | config | `$HOME/.config/sweepky/` | `<dir>/config/` |
//! | data | `$HOME/.local/share/sweepky/` | `<dir>/share/` |
//!
//! The config directory holds, so far:
//!
//! | File | What |
//! |---|---|
//! | `credential.lock` | the writers' lock |
//! | `login.json` | which login this install uses |
//! | `installs.json` | the device ids this owner's own installs created |
//! | `device.key` | this install's age identity |
//! | `identities/<name>.key` | a dedicated identity's secret (`login --identity`) |
//! | `identities/<name>.json` | that identity's public details |
//!
//! Pinned owner keys (P2b) and the data directory's subtrees (P2c) come later.
//! Every file here is written with [`crate::private_fs`]: directories 0700,
//! files 0600.
//!
//! **`XDG_CONFIG_HOME` and `XDG_DATA_HOME` are ignored, on purpose.** The
//! sandbox template `init` writes into a sweeper project denies reads of
//! exactly `~/.config/sweepky` and `~/.local/share/sweepky`
//! (`docs/plan/02-encryption-and-safety.md`). Following an XDG variable could
//! put the secrets somewhere that rule does not name.
//!
//! **`SWEEPKY_HOME` moves both**, so a script can run several identities side
//! by side, each with its own directory. That directory is outside the
//! sandbox's `denyRead` entries, so it has to stay outside any `init` project
//! too (the sandbox blocks reads outside the project's working directory).
//!
//! Resolving the directories is pure: `main.rs` reads `HOME` and
//! `SWEEPKY_HOME` and passes their values in, and nothing here touches the
//! disk. Creating a directory is [`crate::private_fs::ensure_private_dir`]'s
//! job, done by the command that first writes into it.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use anyhow::bail;

use crate::identity::IdentityName;

/// The config and data directories, resolved from `HOME` or `SWEEPKY_HOME`.
///
/// The fields are private and the only constructor is [`Dirs::resolve`], so
/// a `Dirs` always holds two absolute paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dirs {
    config: PathBuf,
    data: PathBuf,
}

impl Dirs {
    /// The directories for the values of `HOME` and `SWEEPKY_HOME` (`None`
    /// when a variable is unset).
    ///
    /// `SWEEPKY_HOME`, when set, decides alone: config in `<dir>/config/`,
    /// data in `<dir>/share/`, and `HOME` is not looked at. Otherwise both are
    /// under `HOME`. The variable used must be a non-empty absolute path; an
    /// empty or relative one is an error, never a fall back to the other,
    /// because a script that set `SWEEPKY_HOME` to keep an identity apart
    /// must not end up writing into the user's own config.
    ///
    /// Takes `&OsStr` rather than `&str`: a Unix path is any bytes, so a
    /// directory whose name is not UTF-8 is still accepted.
    pub fn resolve(home: Option<&OsStr>, sweepky_home: Option<&OsStr>) -> anyhow::Result<Self> {
        if let Some(root) = sweepky_home {
            let root = absolute("SWEEPKY_HOME", root)?;
            return Ok(Self {
                config: root.join("config"),
                data: root.join("share"),
            });
        }
        let Some(home) = home else {
            bail!(
                "HOME is not set, so Sweepky cannot find ~/.config/sweepky; set HOME, or set \
                 SWEEPKY_HOME to an absolute directory for Sweepky's files"
            );
        };
        let home = absolute("HOME", home)?;
        Ok(Self {
            config: home.join(".config").join("sweepky"),
            data: home.join(".local").join("share").join("sweepky"),
        })
    }

    /// The config directory: secrets, this install's lists and the lock.
    ///
    /// Returns `&Path`, a borrowed view of the stored `PathBuf` (as `&str` is
    /// of a `String`), so reading it copies nothing.
    pub fn config(&self) -> &Path {
        &self.config
    }

    /// The data directory: what `pull` saves.
    pub fn data(&self) -> &Path {
        &self.data
    }

    /// `config/credential.lock`, the file the writers' lock is taken on.
    ///
    /// Each helper returns a new `PathBuf`, because `join` builds a new path
    /// rather than pointing into `config`.
    pub fn credential_lock_file(&self) -> PathBuf {
        self.config.join("credential.lock")
    }

    /// `config/login.json`: which login this install uses.
    pub fn login_file(&self) -> PathBuf {
        self.config.join("login.json")
    }

    /// `config/installs.json`: the device ids this owner's own installs
    /// created, which `keys list` and `pull` compare `keys/` against.
    pub fn installs_file(&self) -> PathBuf {
        self.config.join("installs.json")
    }

    /// `config/device.key`: this install's age identity.
    pub fn device_key_file(&self) -> PathBuf {
        self.config.join("device.key")
    }

    /// `config/identities/`, the dedicated identities' directory.
    pub fn identities_dir(&self) -> PathBuf {
        self.config.join("identities")
    }

    /// `config/identities/<name>.key`: a dedicated identity's secret.
    ///
    /// Takes an [`IdentityName`], not a `&str`, so the name has already been
    /// checked to be one plain path segment and cannot climb out of
    /// `identities/`.
    pub fn identity_key_file(&self, name: &IdentityName) -> PathBuf {
        self.identities_dir().join(format!("{name}.key"))
    }

    /// `config/identities/<name>.json`: that identity's public details.
    pub fn identity_file(&self, name: &IdentityName) -> PathBuf {
        self.identities_dir().join(format!("{name}.json"))
    }
}

/// `value` as a path, if it is non-empty and absolute; `variable` names it in
/// the error.
fn absolute(variable: &str, value: &OsStr) -> anyhow::Result<PathBuf> {
    if value.is_empty() {
        bail!("{variable} is set but empty; set it to an absolute directory or unset it");
    }
    let path = Path::new(value);
    if !path.is_absolute() {
        // `{value:?}` quotes the value and escapes anything unprintable.
        bail!("{variable} must be an absolute path; it is {value:?}");
    }
    Ok(path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::path::Path;

    use super::{Dirs, IdentityName};

    /// A variable set to `value`, as `std::env::var_os` would return it.
    fn set_to(value: &str) -> Option<&OsStr> {
        Some(OsStr::new(value))
    }

    #[test]
    fn sweepky_home_overrides_both() {
        // Whatever HOME is, set, unset, empty or relative, it is not looked at
        // when SWEEPKY_HOME is set.
        for home in [set_to("/home/u"), None, set_to(""), set_to("relative")] {
            let dirs = Dirs::resolve(home, set_to("/x")).expect("resolves");
            assert_eq!(dirs.config(), Path::new("/x/config"), "{home:?}");
            assert_eq!(dirs.data(), Path::new("/x/share"), "{home:?}");
        }
    }

    #[test]
    fn defaults_are_under_home_never_xdg() {
        // `resolve` takes no XDG_* value at all: the sandbox template denies
        // reads of exactly these two paths, so they must not move.
        let dirs = Dirs::resolve(set_to("/home/u"), None).expect("resolves");
        assert_eq!(dirs.config(), Path::new("/home/u/.config/sweepky"));
        assert_eq!(dirs.data(), Path::new("/home/u/.local/share/sweepky"));
    }

    #[test]
    fn empty_or_relative_sweepky_home_is_refused_never_falls_back() {
        // SWEEPKY_HOME empty or relative is an error, never a fall back to
        // HOME: a script that meant to keep an identity apart must not touch
        // the user's own config.
        for bad in ["", "x", "./x", "x/y", "~/x"] {
            assert!(
                Dirs::resolve(set_to("/home/u"), set_to(bad)).is_err(),
                "SWEEPKY_HOME={bad:?}"
            );
        }
    }

    #[test]
    fn without_sweepky_home_home_must_be_set_and_absolute() {
        for bad in [None, set_to(""), set_to("home"), set_to("./home")] {
            assert!(Dirs::resolve(bad, None).is_err(), "HOME={bad:?}");
        }
    }

    #[test]
    fn layout_is_the_recorded_one() {
        let dirs = Dirs::resolve(None, set_to("/x")).expect("resolves");
        let name: IdentityName = "throwaway".parse().expect("valid name");
        assert_eq!(
            dirs.credential_lock_file(),
            Path::new("/x/config/credential.lock")
        );
        assert_eq!(dirs.login_file(), Path::new("/x/config/login.json"));
        assert_eq!(dirs.installs_file(), Path::new("/x/config/installs.json"));
        assert_eq!(dirs.device_key_file(), Path::new("/x/config/device.key"));
        assert_eq!(dirs.identities_dir(), Path::new("/x/config/identities"));
        assert_eq!(
            dirs.identity_key_file(&name),
            Path::new("/x/config/identities/throwaway.key")
        );
        assert_eq!(
            dirs.identity_file(&name),
            Path::new("/x/config/identities/throwaway.json")
        );
    }
}
