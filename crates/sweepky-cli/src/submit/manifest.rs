//! What `submit` takes from the sweep's own record and from the bounty
//! before it builds a package: the check that the record can still be
//! completed, the playbook the manifest and the `done` record name, and
//! the package's [`Manifest`].
//!
//! **Where each value comes from.** The agent can rewrite every file of the
//! sweep directory, the marker and `scope.json` included, so nothing here
//! is read from there. The sweep record, `sweeps/<id>.json` in this login's
//! own storage, is what `run` published and only this login can write: it
//! names the bounty, the targets and when the sweep started. The commit
//! each target was swept at is the one `run` checked out, from the snapshot
//! it kept in the data directory (`crate::sweep_state`), never the bounty
//! as it reads now: an owner, or their homeserver, may have rewritten a
//! target's pinned revision since, and a manifest that took the new one
//! would claim an audit of a commit nobody looked at. So the bounty, read
//! from its owner's storage, must still pin every target as `run` fetched
//! it, or the sweep is refused. The sweeper is this login, and the sweep
//! finishes now. So a manifest says exactly what the public record says,
//! plus the commits `run` fetched.

use anyhow::bail;
use sweepky_core::{
    Bounty, BountyRef, KnownSweepStatus, Manifest, Playbook, Pubky, RecordTime, Sweep,
    UnknownFields,
};

use crate::run::UNSPECIFIED_PLAYBOOK;
use crate::sweep_state::SweepSnapshot;

/// What `submit` says of a sweep whose record says `done`.
const ALREADY_DONE: &str = "this sweep's record says done: it was submitted already, so submit \
                            sent nothing again";

/// What `submit` says of a sweep whose record says `aborted`, which is
/// final: 01 re-fetches only `running` sweeps and the board shows an
/// aborted one struck, so a package uploaded now would never be read.
pub(super) const ABORTED_IS_FINAL: &str = "this sweep's record says aborted, which is final, so \
                                           nothing more can be submitted for it; start a new \
                                           sweep of the bounty with `sweepky run`";

/// What `submit` says when the record holds the placeholder playbook and
/// no `--playbook` was given.
const PLAYBOOK_NEEDED: &str = "this sweep's record names no playbook yet (`unspecified`, which \
                               `run` writes until `init` records one), so give the one the \
                               agent followed with --playbook, such as \
                               --playbook cloudflare/security-audit@c1c8a8c";

/// What `submit` says when the bounty no longer pins what `run` fetched
/// for the sweep. Fixed text: it quotes neither the bounty nor a target.
pub(super) const TARGETS_CHANGED: &str = "the bounty's targets changed since this sweep was run: \
                                          it no longer pins the commits `sweepky run` fetched, \
                                          so submit sent nothing; run the sweep again with \
                                          `sweepky run`";

/// Refuses `record` unless it says `running`, the one status `submit`
/// completes: `done` was submitted already, `aborted` is final, and a
/// status this build does not know is not one it may change.
pub(super) fn require_running(record: &Sweep) -> anyhow::Result<()> {
    match record.status.as_known() {
        Some(KnownSweepStatus::Running) => Ok(()),
        Some(KnownSweepStatus::Done) => bail!(ALREADY_DONE),
        Some(KnownSweepStatus::Aborted) => bail!(ABORTED_IS_FINAL),
        // The status is a stranger's text in general, so it is not
        // printed, although only this login writes this record.
        None => bail!(
            "this sweep's record has a status this build does not know, so submit leaves it alone"
        ),
    }
}

/// The playbook the manifest and the `done` record name: `flag`, the
/// checked `--playbook`, when it was given; otherwise the record's own,
/// unless that is still `run`'s placeholder, which is refused, asking for
/// the flag. Pure, and run before anything is built or uploaded.
pub(super) fn final_playbook(flag: Option<&Playbook>, record: &Sweep) -> anyhow::Result<Playbook> {
    match flag {
        // `cloned` copies the borrowed playbook out, a short string, so the
        // caller keeps its own.
        Some(flag) => Ok(flag.clone()),
        None if record.playbook.as_str() == UNSPECIFIED_PLAYBOOK => bail!(PLAYBOOK_NEEDED),
        None => Ok(record.playbook.clone()),
    }
}

/// The manifest of `sweeper`'s sweep `record` of the bounty `bounty`, read
/// from `bounty_ref`, of which `fetched` is what `run` fetched: the
/// sweeper, the record's bounty and targets, the commit `run` checked out
/// for each target (a pull request's head), the record's `startedAt`,
/// `playbook`, and `finished_at`.
///
/// Refuses a record that is not `running`, and one that names another
/// bounty than `bounty_ref`. Refuses with [`TARGETS_CHANGED`] when
/// `fetched` is of another bounty, or `bounty` no longer pins one of the
/// record's targets as `run` fetched it: the same kind, repository and
/// revisions (`SweepSnapshot::target_shas`).
pub(super) fn build_manifest(
    sweeper: Pubky,
    record: &Sweep,
    bounty_ref: BountyRef,
    bounty: &Bounty,
    fetched: &SweepSnapshot,
    playbook: Playbook,
    finished_at: RecordTime,
) -> anyhow::Result<Manifest> {
    require_running(record)?;
    // `BountyRef`'s `==` compares the owner's key bytes and the id.
    if record.bounty != bounty_ref {
        bail!("this sweep's record names another bounty than the one read for it");
    }
    // The commits come from `fetched` alone; `bounty` only has to agree.
    let Some(target_shas) = fetched.target_shas(record, bounty) else {
        bail!(TARGETS_CHANGED);
    };
    Ok(Manifest {
        sweeper,
        bounty: record.bounty,
        targets: record.targets.clone(),
        target_shas,
        playbook,
        started_at: record.started_at.clone(),
        finished_at,
        extra: UnknownFields::new(),
    })
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use sweepky_core::{Bounty, BountyRef, Playbook, Sweep, TargetId};

    use super::{
        ABORTED_IS_FINAL, ALREADY_DONE, PLAYBOOK_NEEDED, TARGETS_CHANGED, build_manifest,
        final_playbook,
    };
    use crate::sweep_state::SweepSnapshot;
    use crate::test_support::{
        SYNTHETIC_HEAD, SYNTHETIC_SHA, UNPINNED_SHA, bounty_id, bounty_of, json_bytes,
        pr_target_json, random_pubky, random_sweep_and_bounty, record_id, repo_target_json,
        snapshot_of, sweep_json,
    };

    const PLAYBOOK: &str = "cloudflare/security-audit@c1c8a8c";

    fn record(value: &Value) -> Sweep {
        Sweep::from_json(&json_bytes(value)).expect("a sweep record")
    }

    fn playbook(text: &str) -> Playbook {
        text.parse().expect("a playbook")
    }

    fn ids(ids: &[TargetId]) -> Vec<&str> {
        ids.iter().map(TargetId::as_str).collect()
    }

    #[test]
    fn the_manifest_takes_the_record_s_bounty_and_targets_and_the_fetched_commits() {
        let (sweep, at) = random_sweep_and_bounty();
        // The record names t2 and t1, of the bounty's three targets.
        let swept = record(&sweep_json(at, &["t2", "t1"], "running"));
        let fetched = bounty_of(json!([
            repo_target_json("t1"),
            pr_target_json("t2"),
            repo_target_json("t3"),
        ]));
        let snapshot = snapshot_of(sweep, at, &fetched, &["t2", "t1"]);
        // The bounty as it reads now: the same pins, though t1 is narrowed
        // to paths it was not and t3 is gone.
        let mut narrowed = repo_target_json("t1");
        narrowed["paths"] = json!(["src/auth/"]);
        let now = bounty_of(json!([narrowed, pr_target_json("t2")]));
        let finished_at = "2026-10-19T12:30:00Z".parse().expect("a time");

        let manifest = build_manifest(
            sweep.sweeper,
            &swept,
            at,
            &now,
            &snapshot,
            playbook(PLAYBOOK),
            finished_at,
        )
        .expect("a manifest");

        assert_eq!(manifest.sweeper, sweep.sweeper);
        assert_eq!(manifest.bounty, at);
        assert_eq!(ids(&manifest.targets), ["t2", "t1"]);
        // The snapshot's commit for each target: a repo target's rev, and a
        // pull request's head, never its base or merge base.
        assert_eq!(
            Some(manifest.target_shas.clone()),
            snapshot.target_shas(&swept, &now)
        );
        let shas: Vec<(&str, &str)> = manifest
            .target_shas
            .iter()
            .map(|(id, sha)| (id.as_str(), sha.as_str()))
            .collect();
        assert_eq!(shas, [("t1", SYNTHETIC_SHA), ("t2", SYNTHETIC_HEAD)]);
        assert_eq!(manifest.playbook, playbook(PLAYBOOK));
        assert_eq!(manifest.started_at, swept.started_at);
        assert_eq!(manifest.finished_at.as_str(), "2026-10-19T12:30:00Z");
        assert!(manifest.extra.is_empty());
    }

    #[test]
    fn a_record_not_running_or_of_another_bounty_or_a_bounty_changed_since_run_is_refused() {
        let (sweep, at) = random_sweep_and_bounty();
        let fetched = bounty_of(json!([repo_target_json("t1"), pr_target_json("t2")]));
        let snapshot = snapshot_of(sweep, at, &fetched, &["t1", "t2"]);
        // The manifest of `swept` against `now`, the bounty at `at` as it
        // reads, and `snapshot`, which must be refused: the refusal.
        let attempt = |swept: &Sweep, now: &Bounty, snapshot: &SweepSnapshot| {
            let finished_at = "2026-10-19T12:30:00Z".parse().expect("a time");
            let refused = build_manifest(
                sweep.sweeper,
                swept,
                at,
                now,
                snapshot,
                playbook(PLAYBOOK),
                finished_at,
            );
            format!("{:#}", refused.expect_err("refused"))
        };
        // A record of the bounty at `at` with `status`, against the bounty
        // as fetched.
        let with_status = |status: &str| {
            attempt(
                &record(&sweep_json(at, &["t1"], status)),
                &fetched,
                &snapshot,
            )
        };

        assert_eq!(with_status("done"), ALREADY_DONE);
        assert_eq!(with_status("aborted"), ABORTED_IS_FINAL);
        assert!(ABORTED_IS_FINAL.contains("start a new sweep"));
        let unknown = with_status("paused");
        assert!(unknown.contains("does not know"), "{unknown}");
        assert!(!unknown.contains("paused"), "{unknown}");

        // The record names another bounty than the one read.
        let other = BountyRef {
            owner: at.owner,
            id: record_id(1),
        };
        let elsewhere = record(&sweep_json(other, &["t1"], "running"));
        let message = attempt(&elsewhere, &fetched, &snapshot);
        assert!(message.contains("another bounty"), "{message}");

        // The owner rewrote t1's pinned revision after `run` fetched it:
        // refused, in fixed text that quotes neither revision.
        let running = record(&sweep_json(at, &["t1", "t2"], "running"));
        let mut moved = repo_target_json("t1");
        moved["rev"] = json!(UNPINNED_SHA);
        let rewritten = bounty_of(json!([moved, pr_target_json("t2")]));
        assert_eq!(attempt(&running, &rewritten, &snapshot), TARGETS_CHANGED);
        assert!(
            !TARGETS_CHANGED.contains(UNPINNED_SHA) && !TARGETS_CHANGED.contains(SYNTHETIC_SHA)
        );

        // The bounty lost t2, which the record names.
        let shrunk = bounty_of(json!([repo_target_json("t1")]));
        assert_eq!(attempt(&running, &shrunk, &snapshot), TARGETS_CHANGED);

        // A snapshot of a fetch from another bounty.
        let fetched_elsewhere = snapshot_of(sweep, other, &fetched, &["t1", "t2"]);
        assert_eq!(
            attempt(&running, &fetched, &fetched_elsewhere),
            TARGETS_CHANGED
        );
    }

    #[test]
    fn the_playbook_flag_wins_and_the_placeholder_needs_it() {
        let at = BountyRef {
            owner: random_pubky(),
            id: bounty_id(),
        };
        let mut placeholder = sweep_json(at, &["t1"], "running");
        placeholder["playbook"] = json!("unspecified");
        let placeholder = record(&placeholder);
        let named = record(&sweep_json(at, &["t1"], "running"));
        let flag = playbook("my-own-review");

        // With the flag, the flag, whatever the record names.
        for swept in [&placeholder, &named] {
            assert_eq!(final_playbook(Some(&flag), swept).expect("named"), flag);
        }
        // Without it, the record's own, unless it is the placeholder.
        assert_eq!(
            final_playbook(None, &named).expect("named"),
            playbook(PLAYBOOK)
        );
        let refused = final_playbook(None, &placeholder).expect_err("no playbook");
        assert_eq!(format!("{refused:#}"), PLAYBOOK_NEEDED);
        assert!(PLAYBOOK_NEEDED.contains("--playbook"));
    }
}
