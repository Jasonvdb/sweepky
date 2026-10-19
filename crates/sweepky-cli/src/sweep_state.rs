//! What `run` fetched for a sweep, kept where the agent cannot reach it:
//! `<data dir>/sweeps/<id>.json`, one small file per sweep, which `run`
//! writes and `submit` builds the manifest's commits from.
//!
//! **Why.** A sweep's manifest says which commit of each target was
//! audited (`targetShas`), and that must be the commit `run` checked out,
//! not whatever the bounty pins by the time `submit` runs: if the owner,
//! or their homeserver, rewrote a target's pinned revision in between, a
//! manifest built from the bounty would claim an audit of a commit nobody
//! looked at, and a later check against the rewritten bounty would accept
//! it. The project's `scope.json` and marker say what was fetched too, but
//! the agent can rewrite every file in the project; the data directory is
//! one the sandbox denies it (02, "Sandbox template"), so this file is the
//! sweeper's own account of the fetch.
//!
//! Its shape, compact JSON and a newline, as the per-sweep marker:
//!
//! ```json
//! {"schemaVersion":1,"sweep":"pubky://<sweeper>/pub/sweepky/sweeps/<id>.json","bounty":"pubky://<owner>/pub/sweepky/bounties/<id>.json","targets":[{"id":"t1","kind":"repo","repo":"github.com/org/name","rev":"<sha>"}],"reviewedCommits":{"t1":"<sha>"}}
//! ```
//!
//! - `targets` are the bounty's targets `run` fetched, each cut down to
//!   what it pins, in core's own `Target` shape: its id, kind and
//!   repository, and its kind's revisions (a repo or commit target's
//!   `rev`; a pull request's `base`, `head` and `mergeBase`, beside its
//!   `number`, which core's `Target::pr` always writes). A repo target's
//!   `paths` are left out: they narrow the review, not the commit.
//! - `reviewedCommits` maps each to the commit `run` checked out
//!   (`KnownTarget::reviewed_commit`), which `submit` writes as the
//!   manifest's `targetShas`.
//!
//! A local file like `installs.json` and `owner-keys.json`, not one of
//! 01's records: nothing publishes it. It goes through
//! [`crate::private_fs`]: the directory 0700, the file 0600, written whole
//! through a temp file and a rename and never through a link, and read
//! with a 64 KiB cap, a loose or linked file refused. Fields a newer
//! Sweepky adds are kept when it is read.
//!
//! **Its life.** `run` refuses to start a sweep when a file is already
//! there for the new id (ids are fresh, so one there means a clash or
//! tampering), writes it once every target is fetched and before the sweep
//! is placed in the project, and removes it if the run then aborts.
//! `submit` refuses a sweep with none, builds `targetShas` from it,
//! refuses one whose bounty no longer pins what it holds, and removes it
//! once the sweep's record says `done` or `aborted`. While the record says
//! `running` it stays, so a retried `submit` still finds it.

use std::collections::BTreeMap;

use anyhow::{Context as _, bail};
use serde::{Deserialize, Serialize};
use sweepky_core::{
    Bounty, BountyRef, GitSha, KnownTarget, RecordError, RecordId, SchemaVersion, Sweep, SweepRef,
    Target, TargetId, UnknownFields,
};

use crate::Dirs;
use crate::private_fs::{
    ensure_private_dir, lstat, read_private_file, remove_private_file, write_private_file,
};

/// The most Sweepky reads of one snapshot: 64 KiB, the cap its other
/// local files, such as `owner-keys.json`, are read with. A run sweeps at
/// most 32 targets, and the longest pinned target (a pull request with a
/// 256-byte repository and three 64-digit SHA-256 names) and its reviewed
/// commit take under 700 bytes, so a snapshot stays near a third of this.
const MAX_SNAPSHOT_BYTES: usize = 64 * 1024;

/// What `submit` says of a sweep this install holds no snapshot for.
pub(crate) const NO_SNAPSHOT: &str = "this install holds no record of what `sweepky run` fetched \
                                      for this sweep, so submit cannot say which commits were \
                                      swept and sent nothing; run the sweep again with \
                                      `sweepky run`";

/// What `run` fetched for one sweep: the module docs' file.
///
/// Public values only (record URLs, repository names and SHAs), so
/// deriving `Debug` prints nothing secret.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
// The Rust fields are snake_case; the JSON keys camelCase, as in records.
#[serde(rename_all = "camelCase")]
pub(crate) struct SweepSnapshot {
    /// The format's version, 1.
    schema_version: SchemaVersion,
    /// The sweep record this is the fetch of.
    sweep: SweepRef,
    /// The bounty the targets were read from.
    bounty: BountyRef,
    /// Each target fetched, cut down to what it pins ([`pinned`]).
    targets: Vec<Target>,
    /// The commit checked out for each target. A `BTreeMap` writes its
    /// keys in one order, so the file is the same each time.
    reviewed_commits: BTreeMap<TargetId, GitSha>,
    /// Fields a newer Sweepky wrote, kept when the file is read.
    #[serde(flatten)]
    extra: UnknownFields,
}

impl SweepSnapshot {
    /// The snapshot of `sweep`, whose targets `fetched` were read from the
    /// bounty at `bounty` and checked out at their reviewed commits.
    ///
    /// `fetched` is anything that yields pairs of borrowed ids and targets,
    /// such as `run`'s chosen targets mapped to `(&id, &target)`; the
    /// lifetime `'a` says only that both borrows live while this runs.
    pub(crate) fn new<'a>(
        sweep: SweepRef,
        bounty: BountyRef,
        fetched: impl IntoIterator<Item = (&'a TargetId, &'a KnownTarget)>,
    ) -> Self {
        let mut targets = Vec::new();
        let mut reviewed_commits = BTreeMap::new();
        for (id, target) in fetched {
            targets.push(pinned(id, target));
            reviewed_commits.insert(id.clone(), target.reviewed_commit().clone());
        }
        Self {
            schema_version: SchemaVersion::CURRENT,
            sweep,
            bounty,
            targets,
            reviewed_commits,
            extra: UnknownFields::new(),
        }
    }

    /// The manifest's `targetShas` for `record`, the sweep's own public
    /// record, read against `bounty`, the bounty as its owner's storage
    /// serves it now: the commit `run` checked out for each of the
    /// record's targets.
    ///
    /// `None` at the first difference: the record names another bounty
    /// than this snapshot, or one of its targets is missing here or from
    /// `bounty`, is not one this build reads, or no longer pins the same
    /// kind, repository and revisions (and a pull request's number) as
    /// when `run` fetched it. A target's `paths` may change, since they are
    /// not pinned.
    pub(crate) fn target_shas(
        &self,
        record: &Sweep,
        bounty: &Bounty,
    ) -> Option<BTreeMap<TargetId, GitSha>> {
        // `BountyRef`'s `==` compares the owner's key bytes and the id.
        if self.bounty != record.bounty {
            return None;
        }
        record
            .targets
            .iter()
            .map(|id| {
                // `?` on an `Option` returns `None` from the closure at
                // once. Both sides are cut down to their pins before they
                // are compared, so a field either side holds beyond them,
                // such as a repo target's `paths`, plays no part.
                let fetched = pinned_view(find(&self.targets, id)?)?;
                let now = pinned_view(find(&bounty.targets, id)?)?;
                if fetched != now {
                    return None;
                }
                let commit = self.reviewed_commits.get(id)?;
                Some((id.clone(), commit.clone()))
            })
            // `collect` into an `Option` stops at the first `None` and
            // returns it; otherwise it builds the map from the pairs.
            .collect()
    }

    /// Writes the snapshot as `<data dir>/sweeps/<id>.json`, 0600 in a
    /// 0700 directory, made if it is missing. A file already there is
    /// replaced, through a rename that never follows a link: `run` refused
    /// to start the sweep when one was ([`refuse_existing_snapshot`]).
    pub(crate) fn write(&self, dirs: &Dirs) -> anyhow::Result<()> {
        let mut bytes =
            serde_json::to_vec(self).context("could not write the record of what run fetched")?;
        bytes.push(b'\n');
        // Far under the cap for any run (see `MAX_SNAPSHOT_BYTES`), but
        // checked, so the file never holds what `submit` would refuse to
        // read back.
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            bail!("the record of what run fetched would be larger than the 64 KiB submit reads");
        }
        ensure_private_dir(&dirs.sweep_snapshots_dir())?;
        write_private_file(&dirs.sweep_snapshot_file(&self.sweep.id), &bytes)
    }
}

/// Refuses sweep `id`, which `run` has just made, when anything is
/// already at its snapshot's path: ids are fresh, so a file there means
/// two runs got one id, or something else wrote it. Looks only, with
/// `lstat`, so a link there is refused too; the message names the path
/// and quotes nothing of the file.
pub(crate) fn refuse_existing_snapshot(dirs: &Dirs, id: &RecordId) -> anyhow::Result<()> {
    let path = dirs.sweep_snapshot_file(id);
    if lstat(&path)?.is_some() {
        bail!(
            "{} is already there, though this sweep's id is new, so run published and fetched \
             nothing: two runs were given one id, or something else wrote it. Look at it, remove \
             it, and run again",
            path.display()
        );
    }
    Ok(())
}

/// Reads the snapshot of `sweep` from `<data dir>/sweeps/<id>.json`.
///
/// Refused with [`NO_SNAPSHOT`] when there is none, or when the one there
/// is of another sweep with that id (another login's). Through
/// `private_fs`, as every file of Sweepky's own: a link, anything but a
/// regular file, a file another user could read and one over 64 KiB are
/// refused before a byte is read.
pub(crate) fn read_snapshot(dirs: &Dirs, sweep: SweepRef) -> anyhow::Result<SweepSnapshot> {
    let path = dirs.sweep_snapshot_file(&sweep.id);
    let Some(bytes) = read_private_file(&path, MAX_SNAPSHOT_BYTES)? else {
        bail!(NO_SNAPSHOT);
    };
    // serde_json's messages go through core's `RecordError`, which keeps
    // only the kind of fault and where it is, so no message quotes the file.
    let snapshot: SweepSnapshot = serde_json::from_slice(&bytes)
        .map_err(RecordError::from)
        .with_context(|| format!("{} is not a record of what run fetched", path.display()))?;
    // `SweepRef`'s `==` compares the sweeper's key bytes and the id.
    if snapshot.sweep != sweep {
        bail!(NO_SNAPSHOT);
    }
    Ok(snapshot)
}

/// Removes sweep `id`'s snapshot, once its record says `done` or
/// `aborted`, or `run` gave the sweep up.
///
/// Best effort, so a failure is dropped with `let _ =`: `submit` refuses a
/// sweep whose record is final before it looks for a snapshot, and one
/// whose directory never reached the project before that, so a file left
/// behind is never read again. Nothing there counts as success.
pub(crate) fn forget_snapshot(dirs: &Dirs, id: &RecordId) {
    let _ = remove_private_file(&dirs.sweep_snapshot_file(id));
}

/// `target`, under the id `id`, cut down to what it pins: its kind,
/// repository and revisions, written by core's own constructors (which
/// give a pull request its number too, so that is compared as well). The
/// one definition of what a snapshot holds, used both when `run` writes
/// one and when `submit` compares it with the bounty, so the two cannot
/// drift.
fn pinned(id: &TargetId, target: &KnownTarget) -> Target {
    // `clone` copies each checked value out of the borrowed view: short
    // strings. No `_` arm: a kind added to core later does not compile
    // until someone decides what it pins.
    match target {
        KnownTarget::Repo(repo) => Target::repo(
            id.clone(),
            repo.repo().clone(),
            repo.rev().clone(),
            Vec::new(),
        ),
        KnownTarget::Commit(commit) => {
            Target::commit(id.clone(), commit.repo().clone(), commit.rev().clone())
        }
        KnownTarget::Pr(pr) => Target::pr(
            id.clone(),
            pr.repo().clone(),
            pr.number(),
            pr.base().clone(),
            pr.head().clone(),
            pr.merge_base().clone(),
        ),
    }
}

/// [`pinned`] of `target`, read as a known kind first, or `None` when it
/// is not one this build reads or is malformed.
fn pinned_view(target: &Target) -> Option<Target> {
    // `ok()` drops the error of a malformed target, and `flatten` turns the
    // `Option<Option<..>>` left into one `Option`: `None` for either fault,
    // or for a kind this build does not know.
    let known = target.known().ok().flatten()?;
    Some(pinned(target.id(), &known))
}

/// The target of `targets` whose id is `id`.
fn find<'a>(targets: &'a [Target], id: &TargetId) -> Option<&'a Target> {
    targets.iter().find(|target| target.id() == id)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use serde_json::{Value, json};
    use sweepky_core::{Bounty, BountyRef, Sweep, SweepRef};

    use super::{NO_SNAPSHOT, forget_snapshot, read_snapshot, refuse_existing_snapshot};
    use crate::private_fs::write_private_file;
    use crate::test_support::{
        PLANTED, SYNTHETIC_HEAD, SYNTHETIC_SHA, UNPINNED_SHA, bounty_of, chmod, dirs_in,
        json_bytes, mode, pr_target_json, private_temp, random_pubky, random_sweep_and_bounty,
        record_id, repo_target_json, snapshot_of, sweep_json,
    };

    fn record(at: BountyRef, ids: &[&str]) -> Sweep {
        Sweep::from_json(&json_bytes(&sweep_json(at, ids, "running"))).expect("a sweep record")
    }

    /// A repo target narrowed to `src/auth/`, as `post` writes one.
    fn narrowed_repo_target(id: &str) -> Value {
        let mut target = repo_target_json(id);
        target["paths"] = json!(["src/auth/"]);
        target
    }

    #[test]
    fn a_snapshot_is_0600_in_a_0700_dir_holding_each_target_s_pins_and_commit() {
        let home = private_temp();
        let dirs = dirs_in(&home);
        let (sweep, at) = random_sweep_and_bounty();
        let fetched = bounty_of(json!([narrowed_repo_target("t1"), pr_target_json("t2")]));

        snapshot_of(sweep, at, &fetched, &["t1", "t2"])
            .write(&dirs)
            .expect("written");

        let path = dirs.sweep_snapshot_file(&sweep.id);
        assert_eq!(path, dirs.data().join(format!("sweeps/{}.json", sweep.id)));
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(&dirs.sweep_snapshots_dir()), 0o700);
        // The repo target without its paths; the pull request with every
        // revision, and its head as the reviewed commit.
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(&path).expect("read")).expect("JSON"),
            json!({
                "schemaVersion": 1,
                "sweep": sweep.to_string(),
                "bounty": at.to_string(),
                "targets": [repo_target_json("t1"), pr_target_json("t2")],
                "reviewedCommits": { "t1": SYNTHETIC_SHA, "t2": SYNTHETIC_HEAD },
            })
        );
        assert_eq!(
            read_snapshot(&dirs, sweep).expect("read back"),
            snapshot_of(sweep, at, &fetched, &["t1", "t2"])
        );

        // Forgotten, it is gone, and forgetting it again is no error.
        forget_snapshot(&dirs, &sweep.id);
        assert!(fs::symlink_metadata(&path).is_err());
        forget_snapshot(&dirs, &sweep.id);
    }

    #[test]
    fn a_snapshot_already_there_or_a_link_is_refused_by_its_path_alone() {
        let home = private_temp();
        let dirs = dirs_in(&home);
        let (sweep, at) = random_sweep_and_bounty();
        // Nothing there yet: no refusal, and nothing made.
        refuse_existing_snapshot(&dirs, &sweep.id).expect("free");
        assert!(fs::symlink_metadata(dirs.sweep_snapshots_dir()).is_err());

        let fetched = bounty_of(json!([repo_target_json("t1")]));
        snapshot_of(sweep, at, &fetched, &["t1"])
            .write(&dirs)
            .expect("written");
        let path = dirs.sweep_snapshot_file(&sweep.id);
        let message = format!(
            "{:#}",
            refuse_existing_snapshot(&dirs, &sweep.id).expect_err("there")
        );
        assert!(message.contains(&path.display().to_string()), "{message}");
        assert!(message.contains("already there"), "{message}");

        // A dangling link counts as something there.
        fs::remove_file(&path).expect("remove");
        symlink(home.path().join("nowhere"), &path).expect("symlink");
        refuse_existing_snapshot(&dirs, &sweep.id).expect_err("a link");
    }

    #[test]
    fn a_missing_loose_or_foreign_snapshot_is_refused_and_unknown_fields_are_kept() {
        let home = private_temp();
        let dirs = dirs_in(&home);
        let (sweep, at) = random_sweep_and_bounty();
        assert_eq!(
            format!("{:#}", read_snapshot(&dirs, sweep).expect_err("none")),
            NO_SNAPSHOT
        );

        let fetched = bounty_of(json!([repo_target_json("t1")]));
        snapshot_of(sweep, at, &fetched, &["t1"])
            .write(&dirs)
            .expect("written");
        let path = dirs.sweep_snapshot_file(&sweep.id);
        // Loose, as every config file: refused, with the chmod that fixes it.
        chmod(&path, 0o644);
        let message = format!("{:#}", read_snapshot(&dirs, sweep).expect_err("loose"));
        assert!(message.contains("chmod 600"), "{message}");
        chmod(&path, 0o600);

        // Of another login's sweep with this id: not this sweep's.
        let other = SweepRef {
            sweeper: random_pubky(),
            id: sweep.id,
        };
        assert_eq!(
            format!("{:#}", read_snapshot(&dirs, other).expect_err("foreign")),
            NO_SNAPSHOT
        );

        // A field a newer Sweepky wrote is read and kept; a damaged file is
        // refused without quoting it.
        let mut file: Value =
            serde_json::from_slice(&fs::read(&path).expect("read")).expect("JSON");
        file["addedLater"] = json!("kept");
        write_private_file(&path, &json_bytes(&file)).expect("write");
        let read = read_snapshot(&dirs, sweep).expect("read");
        assert_eq!(read.extra.get("addedLater"), Some(&json!("kept")));
        file["reviewedCommits"]["t1"] = json!(PLANTED);
        write_private_file(&path, &json_bytes(&file)).expect("write");
        let message = format!("{:#}", read_snapshot(&dirs, sweep).expect_err("damaged"));
        assert!(
            message.contains("not a record of what run fetched"),
            "{message}"
        );
        assert!(!message.contains(PLANTED), "{message}");
    }

    #[test]
    fn the_commits_come_from_the_snapshot_while_the_bounty_pins_the_same() {
        let (sweep, at) = random_sweep_and_bounty();
        let fetched = bounty_of(json!([narrowed_repo_target("t1"), pr_target_json("t2")]));
        let snapshot = snapshot_of(sweep, at, &fetched, &["t1", "t2"]);
        let swept = record(at, &["t2", "t1"]);
        let shas = |now: &Bounty| {
            snapshot.target_shas(&swept, now).map(|shas| {
                shas.iter()
                    .map(|(id, sha)| (id.to_string(), sha.to_string()))
                    .collect::<Vec<_>>()
            })
        };
        let expected = Some(vec![
            ("t1".to_owned(), SYNTHETIC_SHA.to_owned()),
            ("t2".to_owned(), SYNTHETIC_HEAD.to_owned()),
        ]);

        // The bounty as fetched; with other paths, a target added and a
        // field a newer Sweepky wrote: the same pins, so the same commits.
        assert_eq!(shas(&fetched), expected);
        let mut widened = repo_target_json("t1");
        widened["note"] = json!("kept");
        assert_eq!(
            shas(&bounty_of(json!([
                widened,
                pr_target_json("t2"),
                repo_target_json("t3")
            ]))),
            expected
        );

        // Any pinned revision moved, a kind or repository changed, or a
        // target gone: no commits at all.
        let mut moved_rev = narrowed_repo_target("t1");
        moved_rev["rev"] = json!(UNPINNED_SHA);
        let mut moved_base = pr_target_json("t2");
        moved_base["base"] = json!(UNPINNED_SHA);
        let mut moved_merge_base = pr_target_json("t2");
        moved_merge_base["mergeBase"] = json!(UNPINNED_SHA);
        let mut other_repo = narrowed_repo_target("t1");
        other_repo["repo"] = json!("github.com/org/other");
        let mut as_commit = repo_target_json("t1");
        as_commit["kind"] = json!("commit");
        for changed in [
            json!([moved_rev, pr_target_json("t2")]),
            json!([narrowed_repo_target("t1"), moved_base]),
            json!([narrowed_repo_target("t1"), moved_merge_base]),
            json!([other_repo, pr_target_json("t2")]),
            json!([as_commit, pr_target_json("t2")]),
            json!([narrowed_repo_target("t1")]),
        ] {
            assert_eq!(shas(&bounty_of(changed.clone())), None, "{changed}");
        }

        // A record of another bounty, or naming a target not fetched.
        let elsewhere = BountyRef {
            owner: at.owner,
            id: record_id(1),
        };
        assert_eq!(
            snapshot.target_shas(&record(elsewhere, &["t1"]), &fetched),
            None
        );
        let more = bounty_of(json!([
            repo_target_json("t1"),
            pr_target_json("t2"),
            repo_target_json("t3")
        ]));
        assert_eq!(
            snapshot.target_shas(&record(at, &["t1", "t3"]), &more),
            None
        );
    }
}
