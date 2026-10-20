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
//! | `pull.lock` | the pull lock: one `pull` at a time on this install |
//! | `login.json` | which login this install uses |
//! | `installs.json` | the device ids this owner's own installs created |
//! | `owner-keys.json` | per bounty owner, the keys `submit` last encrypted a sweep to, pinned (`crate::pins`) |
//! | `device.key` | this install's age identity |
//! | `grant.token` | the Pubky Ring login's grant token, the SDK's exported string, optionally passphrase-wrapped (`crate::ring::token`) |
//! | `identities/<name>.key` | a dedicated identity's secret (`login --identity`) |
//! | `identities/<name>.json` | that identity's public details |
//!
//! The data directory holds, so far:
//!
//! | Entry | What |
//! |---|---|
//! | `git-home-<id>/` | git's `HOME` while one command (`post`, `run`) runs it: new, empty and 0700, removed when the command ends (`crate::git`) |
//! | `staging/<id>/` | the sweep directory `run` builds before it moves it into the project's `sweeps/<id>/`: new and 0700, removed when `run` ends (`run::fetch`) |
//! | `staging/.pull.<pid>.<nanos>.<n>.tmp/` | where `pull` writes one decrypted sweep, and a bounty's directory the first time, before it moves them into place: new and 0700, removed when the store ends (`crate::pull::store`) |
//! | `sweeps/<id>.json` | what `run` fetched for sweep `id`, which `submit` builds the manifest's commits from: written by `run`, removed once the sweep's record says `done` or `aborted` (`crate::sweep_state`) |
//! | `feed-cursors.json` | per owner and watched homeserver, how far `pull` has read its `/events/` feed (`crate::pull`) |
//! | `poll-state.json` | per owner, what `pull`'s roster polling learnt: the newest ids seen, bounty and sweep summaries with their `ETag`s, the strangers' sweeps accepted and the deletions confirmed (`crate::pull`) |
//! | `<id>/` | what `pull` decrypted of the owner's bounty `id`: `owner.json`, the owner check; each trusted sweep in `<sweeper z32>-<sweep id>/`, and each untrusted one in `untrusted/<sweeper z32>-<sweep id>/`, holding the package's files and `.sweepky/findings.json`, a compact copy of its findings (`crate::pull::store`) |
//!
//! A bounty's id is 13 characters of `0-9` and upper-case `A-Z`, and no
//! other name here is, in either case: each is shorter or has a `-` or a
//! `.` in it. So a pulled bounty's directory never takes another entry's
//! name, even on a file system that ignores case. Every directory here is
//! made 0700 and every file 0600, with [`crate::private_fs`] or, for what
//! `pull` stores, through directory handles (`crate::pull::store`); the one
//! exception is what git checks out under `staging/<id>/`, which that 0700
//! directory keeps from other users.
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

use sweepky_core::RecordId;

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

    /// `config/pull.lock`, the file the pull lock is taken on, so that one
    /// `pull` at a time reads and writes its local state (`crate::lock`).
    pub(crate) fn pull_lock_file(&self) -> PathBuf {
        self.config.join("pull.lock")
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

    /// `config/owner-keys.json`: per bounty owner, the device keys `submit`
    /// last encrypted a sweep to, which it compares that owner's `keys/`
    /// with the next time.
    pub(crate) fn owner_keys_file(&self) -> PathBuf {
        self.config.join("owner-keys.json")
    }

    /// `config/device.key`: this install's age identity.
    pub fn device_key_file(&self) -> PathBuf {
        self.config.join("device.key")
    }

    /// `config/grant.token`: the grant token of a Pubky Ring login, the
    /// secret every later command restores its session from.
    pub fn grant_token_file(&self) -> PathBuf {
        self.config.join("grant.token")
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

    /// `data/git-home-<id>/`: git's private `HOME` for one command, with
    /// `id` a new record id, so each command gets a directory of its own.
    /// A [`RecordId`] is 13 characters of `0-9` and `A-Z`, so the name is
    /// one plain path segment.
    pub(crate) fn git_home_dir(&self, id: &RecordId) -> PathBuf {
        self.data.join(format!("git-home-{id}"))
    }

    /// `data/staging/`: where `run` builds each sweep directory, one
    /// `staging/<id>/` per sweep, out of reach of the agent, which can
    /// write only in its project.
    pub(crate) fn staging_dir(&self) -> PathBuf {
        self.data.join("staging")
    }

    /// `data/sweeps/`: what `run` fetched for each sweep not yet finished,
    /// one file per sweep, out of reach of the agent.
    pub(crate) fn sweep_snapshots_dir(&self) -> PathBuf {
        self.data.join("sweeps")
    }

    /// `data/sweeps/<id>.json`: what `run` fetched for sweep `id`. A
    /// [`RecordId`] is one plain path segment, as for
    /// [`git_home_dir`](Self::git_home_dir).
    pub(crate) fn sweep_snapshot_file(&self, id: &RecordId) -> PathBuf {
        self.sweep_snapshots_dir().join(format!("{id}.json"))
    }
}

/// The data directory's files that `pull` keeps (`crate::pull`).
impl Dirs {
    /// `data/feed-cursors.json`: per owner and watched homeserver, how far
    /// `pull` has read that homeserver's `/events/` feed.
    pub(crate) fn feed_cursors_file(&self) -> PathBuf {
        self.data.join("feed-cursors.json")
    }

    /// `data/poll-state.json`: per owner, what `pull`'s roster polling
    /// learnt, which its next run starts from.
    pub(crate) fn poll_state_file(&self) -> PathBuf {
        self.data.join("poll-state.json")
    }

    /// `data/<id>/`: what `pull` decrypted of the owner's bounty `id`, 03's
    /// `~/.local/share/sweepky/<bounty>/`. A [`RecordId`] is 13 characters
    /// of `0-9` and upper-case `A-Z`, so the name is one plain path segment
    /// and never that of another entry here, none of which is 13 such
    /// characters, in either case (the module docs).
    pub(crate) fn pulled_bounty_dir(&self, id: &RecordId) -> PathBuf {
        self.data.join(id.to_string())
    }

    /// `data/<id>/untrusted/`: the strangers' sweeps of bounty `id`, kept
    /// apart from the merged report (02, "Sweeper safety").
    pub(crate) fn pulled_untrusted_dir(&self, id: &RecordId) -> PathBuf {
        self.pulled_bounty_dir(id).join("untrusted")
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
        assert_eq!(dirs.pull_lock_file(), Path::new("/x/config/pull.lock"));
        assert_eq!(dirs.login_file(), Path::new("/x/config/login.json"));
        assert_eq!(dirs.installs_file(), Path::new("/x/config/installs.json"));
        assert_eq!(dirs.device_key_file(), Path::new("/x/config/device.key"));
        assert_eq!(dirs.grant_token_file(), Path::new("/x/config/grant.token"));
        assert_eq!(
            dirs.owner_keys_file(),
            Path::new("/x/config/owner-keys.json")
        );
        assert_eq!(dirs.identities_dir(), Path::new("/x/config/identities"));
        assert_eq!(
            dirs.identity_key_file(&name),
            Path::new("/x/config/identities/throwaway.key")
        );
        assert_eq!(
            dirs.identity_file(&name),
            Path::new("/x/config/identities/throwaway.json")
        );
        let id = "0035G87EK4XFE".parse().expect("valid record id");
        assert_eq!(
            dirs.git_home_dir(&id),
            Path::new("/x/share/git-home-0035G87EK4XFE")
        );
        assert_eq!(dirs.staging_dir(), Path::new("/x/share/staging"));
        assert_eq!(
            dirs.sweep_snapshot_file(&id),
            Path::new("/x/share/sweeps/0035G87EK4XFE.json")
        );
        assert_eq!(
            dirs.feed_cursors_file(),
            Path::new("/x/share/feed-cursors.json")
        );
        assert_eq!(
            dirs.poll_state_file(),
            Path::new("/x/share/poll-state.json")
        );
        assert_eq!(
            dirs.pulled_bounty_dir(&id),
            Path::new("/x/share/0035G87EK4XFE")
        );
        assert_eq!(
            dirs.pulled_untrusted_dir(&id),
            Path::new("/x/share/0035G87EK4XFE/untrusted")
        );
    }
}
