//! `sweepky submit`, the terminal command the human runs after the agent:
//! so far the half that reads the sweep directory, and the check of the
//! bounty owner's keys.
//!
//! The agent wrote that directory after reading untrusted code, so
//! [`collect_sweep`] treats it as hostile (02, "`submit` trusts nothing in
//! the sweep directory"):
//!
//! - `sweep_dir` finds it, from `--run-dir` or by picking the one sweep in
//!   the working directory's project not yet submitted, and checks it: a
//!   real directory directly in the canonical `init` project's real
//!   `sweeps/`, holding the per-sweep marker `run` wrote, which must point
//!   at this login's own sweep of that directory's id.
//! - `walk` then walks it from the handle those checks opened, following
//!   no link, refusing links, hard links, FIFOs, sockets and devices,
//!   skipping `target/` and the agents' `scratch/` directories, within caps
//!   on entries, depth and sizes, and reads `audit/`'s files into
//!   `SweepFile`s, the list `SweepPackage::build` takes.
//!
//! The owner's `keys/` were written by whoever can write there, so
//! `owner_keys` takes from them only the unrevoked records core's
//! `DeviceKey::encryption_recipient` accepts, within caps, and compares
//! that set with the one `owner-keys.json` pins for the owner: first use
//! pins it silently, and a new key is warned of by its device id and asked
//! about (or, under `--no-input`, refused).
//!
//! What follows in P2b's next step, the command itself: the sweep record
//! and the bounty, the package, the encryption, the upload and the `done`
//! flip, the pin written under the writers' lock, and the
//! `.sweepky/submitted` stamp that picking reads.

// Until the command calls `collect_sweep` and `accept_owner_keys`, nothing
// outside the tests does. `expect` (not `allow`) silences the dead-code
// warning only while it is true, so the command's step must remove it;
// `cfg_attr(not(test), …)` applies it to the normal build only, because the
// tests below do call everything. It covers `crate::pins` too: rustc counts
// an item whose dead-code lint is expected as used, and so everything it
// calls, so `pins` needs no expectation of its own (one there would go
// unmet, a warning of its own).
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the submit command, P2b's next step, is the first caller"
    )
)]

mod owner_keys;
mod sweep_dir;
mod walk;

use std::path::Path;

use sweepky_core::Pubky;

use self::sweep_dir::{SweepDir, find_sweep_dir};
use self::walk::{AuditFiles, read_audit};

/// What `submit` takes from a sweep directory before it builds a package.
// No `Debug`: `AuditFiles` has none, as it holds the agent's file names
// and the audit's bytes.
pub(crate) struct CollectedSweep {
    /// The sweep directory, checked, and the sweep its marker points at.
    pub(crate) dir: SweepDir,
    /// `audit/`'s files, read.
    pub(crate) audit: AuditFiles,
}

/// Finds and checks the sweep directory `run_dir` names, relative to `cwd`
/// (without it, the one sweep waiting in the project at `cwd`), for
/// `sweeper`, this login's pubky, then walks it and reads `audit/`'s files.
/// See the module docs; any refusal names the entry, sanitised, and quotes
/// no file.
pub(crate) fn collect_sweep(
    cwd: &Path,
    run_dir: Option<&Path>,
    sweeper: &Pubky,
) -> anyhow::Result<CollectedSweep> {
    let dir = find_sweep_dir(cwd, run_dir, sweeper)?;
    let audit = read_audit(&dir)?;
    Ok(CollectedSweep { dir, audit })
}

/// An `init` project with a whole sweep directory in it, as `run` leaves
/// one, for the tests of this module and the two below it, and a config
/// directory beside it to plant links to.
#[cfg(test)]
mod fixture {
    use std::fs;
    use std::path::{Path, PathBuf};

    use serde_json::json;
    use sweepky_core::{BountyRef, Pubky, RecordId, SweepRef};
    use tempfile::TempDir;

    use super::sweep_dir::{SweepDir, find_sweep_dir};
    use crate::Dirs;
    use crate::private_fs::{ensure_private_dir, write_private_file};
    use crate::test_support::{PLANTED, bounty_id, json_bytes, private_temp, random_pubky};

    /// A common-format `findings.json` with no findings.
    const FINDINGS: &str = "{\"schemaVersion\":1,\"playbook\":\"cloudflare/security-audit@c1c8a8c\",\"findings\":[]}\n";

    /// A project at `<root>/<name>`, made by `init`, with the sweep
    /// directory `sweeps/<id>/` of `sweeper`'s sweep `id`: `target/t1/`,
    /// `scope.json`, `brief.md`, the marker, and `audit/findings.json`.
    pub(in crate::submit) struct SweepFixture {
        root: PathBuf,
        project: PathBuf,
        id: RecordId,
        sweeper: Pubky,
        /// The temp directory `root` is, deleted when dropped; `None` for
        /// a fixture made beside another, whose temp directory holds both.
        _temp: Option<TempDir>,
    }

    impl SweepFixture {
        /// A fixture in a new private temp directory, for a random sweeper.
        pub(in crate::submit) fn new() -> Self {
            let temp = private_temp();
            let mut fixture = Self::make(temp.path(), "p", random_pubky(), bounty_id());
            fixture._temp = Some(temp);
            fixture
        }

        /// A second project, `name`, beside `other`'s, with a sweep
        /// directory of the same id for the same sweeper. `other` must
        /// outlive it, since it owns the temp directory.
        pub(in crate::submit) fn in_temp_with(other: &Self, name: &str) -> Self {
            Self::make(&other.root, name, other.sweeper, other.id)
        }

        fn make(root: &Path, name: &str, sweeper: Pubky, id: RecordId) -> Self {
            let project = root.join(name);
            crate::init::init(&project).expect("init");
            let fixture = Self {
                root: root.to_owned(),
                project,
                id,
                sweeper,
                _temp: None,
            };
            fixture.add_sweep(id);
            fixture
        }

        /// Adds the whole sweep directory `sweeps/<id>/` to the project,
        /// and gives its path.
        pub(in crate::submit) fn add_sweep(&self, id: RecordId) -> PathBuf {
            let dir = self.project.join("sweeps").join(id.to_string());
            fs::create_dir_all(dir.join("target/t1")).expect("mkdir");
            fs::write(dir.join("target/t1/README.md"), "the target\n").expect("write");
            fs::write(dir.join("scope.json"), "{\"schemaVersion\":1}\n").expect("write");
            fs::write(dir.join("brief.md"), "Look at the session handling.\n").expect("write");
            fs::create_dir(dir.join(".sweepky")).expect("mkdir");
            self.write_marker(&dir, &self.marker_bytes(self.sweeper, id));
            fs::create_dir(dir.join("audit")).expect("mkdir");
            fs::write(dir.join("audit/findings.json"), FINDINGS).expect("write");
            dir
        }

        /// A marker as `run` writes one, pointing at `sweeper`'s sweep
        /// `id`.
        pub(in crate::submit) fn marker_bytes(&self, sweeper: Pubky, id: RecordId) -> Vec<u8> {
            let bounty = BountyRef {
                owner: random_pubky(),
                id: bounty_id(),
            };
            json_bytes(&json!({
                "schemaVersion": 1,
                "sweep": SweepRef { sweeper, id }.to_string(),
                "bounty": bounty.to_string(),
                "targets": ["t1"],
            }))
        }

        /// Writes `bytes` as the marker of the sweep directory `dir`.
        pub(in crate::submit) fn write_marker(&self, dir: &Path, bytes: &[u8]) {
            fs::write(dir.join(".sweepky/sweep.json"), bytes).expect("write");
        }

        /// Stamps the sweep directory `dir` as submitted, as the command
        /// will: `.sweepky/submitted`.
        pub(in crate::submit) fn stamp(&self, dir: &Path) {
            fs::write(dir.join(".sweepky/submitted"), "").expect("write");
        }

        /// The sweep directory, checked as `--run-dir sweeps/<id>` from
        /// the project.
        pub(in crate::submit) fn open(&self) -> SweepDir {
            let run_dir = PathBuf::from(format!("sweeps/{}", self.id));
            find_sweep_dir(&self.project, Some(&run_dir), &self.sweeper)
                .unwrap_or_else(|err| panic!("refused: {err:#}"))
        }

        /// The temp directory everything is in.
        pub(in crate::submit) fn temp(&self) -> &Path {
            &self.root
        }

        pub(in crate::submit) fn project(&self) -> &Path {
            &self.project
        }

        /// `<project>/sweeps/<id>`, as made (not canonicalised).
        pub(in crate::submit) fn dir(&self) -> PathBuf {
            self.project.join("sweeps").join(self.id.to_string())
        }

        pub(in crate::submit) fn audit(&self) -> PathBuf {
            self.dir().join("audit")
        }

        pub(in crate::submit) fn id(&self) -> RecordId {
            self.id
        }

        pub(in crate::submit) fn sweeper(&self) -> Pubky {
            self.sweeper
        }

        /// The length of the `findings.json` every sweep directory starts
        /// with.
        pub(in crate::submit) fn findings_len(&self) -> usize {
            FINDINGS.len()
        }
    }

    /// This install's config directory, as `SWEEPKY_HOME=<temp>/home` gives
    /// it, beside a fixture's project, so on the same filesystem and a hard
    /// link can reach it. It holds a `device.key` of synthetic text.
    pub(in crate::submit) struct ConfigDir {
        dirs: Dirs,
    }

    impl ConfigDir {
        pub(in crate::submit) fn new(fixture: &SweepFixture) -> Self {
            let home = fixture.root.join("home");
            let dirs = Dirs::resolve(None, Some(home.as_os_str())).expect("absolute");
            ensure_private_dir(dirs.config()).expect("config dir");
            write_private_file(&dirs.device_key_file(), PLANTED.as_bytes()).expect("device.key");
            Self { dirs }
        }

        pub(in crate::submit) fn path(&self) -> &Path {
            self.dirs.config()
        }

        pub(in crate::submit) fn device_key(&self) -> PathBuf {
            self.dirs.device_key_file()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    use sweepky_core::SweepRef;

    use super::collect_sweep;
    use super::fixture::{ConfigDir, SweepFixture};
    use crate::test_support::PLANTED;

    #[test]
    fn a_whole_sweep_directory_is_collected_with_or_without_run_dir() {
        let fixture = SweepFixture::new();
        let run_dir = PathBuf::from(format!("sweeps/{}", fixture.id()));
        for run_dir in [Some(run_dir.as_path()), None] {
            let collected = collect_sweep(fixture.project(), run_dir, &fixture.sweeper())
                .unwrap_or_else(|err| panic!("refused: {err:#}"));
            assert_eq!(
                collected.dir.sweep(),
                SweepRef {
                    sweeper: fixture.sweeper(),
                    id: fixture.id(),
                }
            );
            let paths: Vec<&str> = collected
                .audit
                .files
                .iter()
                .map(|file| file.path.as_str())
                .collect();
            assert_eq!(paths, ["findings.json"]);
        }
    }

    // 06's check: a run directory holding a planted symlink, or a hard
    // link, to a file in the config directory is refused, and nothing of
    // the file is read or shown.
    #[test]
    fn a_planted_link_or_hard_link_to_the_config_dir_is_refused() {
        // `what` is also what the refusal says of the planted file.
        for what in ["a symbolic link", "hard links"] {
            let fixture = SweepFixture::new();
            let config = ConfigDir::new(&fixture);
            let (key, planted) = (config.device_key(), fixture.audit().join("device.key"));
            if what == "hard links" {
                fs::hard_link(&key, &planted)
            } else {
                symlink(&key, &planted)
            }
            .expect("planted");
            let run_dir = PathBuf::from(format!("sweeps/{}", fixture.id()));

            let err = match collect_sweep(fixture.project(), Some(&run_dir), &fixture.sweeper()) {
                Ok(_) => panic!("{what}: accepted"),
                Err(err) => format!("{err:#}"),
            };

            assert!(err.contains("audit/device.key"), "{what}: {err}");
            assert!(err.contains(what), "{what}: {err}");
            assert!(!err.contains(PLANTED), "{what}: {err}");
        }
    }
}
