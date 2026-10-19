//! What `submit` takes from the sweep's own record and from the bounty
//! before it builds a package: the check that the record can still be
//! completed, the playbook the manifest and the `done` record name, and
//! the package's [`Manifest`].
//!
//! **Where each value comes from.** The agent can rewrite every file of the
//! sweep directory, the marker and `scope.json` included, so nothing here
//! is read from there. The sweep record, `sweeps/<id>.json` in this login's
//! own storage, is what `run` published and only this login can write: it
//! names the bounty, the targets and when the sweep started. The bounty,
//! read from its owner's storage, pins the commit each target reviews. The
//! sweeper is this login, and the sweep finishes now. So a manifest says
//! exactly what the public record says, plus the commits the owner pinned.

use std::collections::BTreeMap;

use anyhow::{Context as _, anyhow, bail};
use sweepky_core::{
    Bounty, BountyRef, GitSha, KnownSweepStatus, Manifest, Playbook, Pubky, RecordTime, Sweep,
    TargetId, UnknownFields,
};

use crate::run::UNSPECIFIED_PLAYBOOK;

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
/// from `bounty_ref`: the sweeper, the record's bounty and targets, each
/// target's reviewed commit as the bounty pins it (a pull request's head),
/// the record's `startedAt`, `playbook`, and `finished_at`.
///
/// Refuses a record that is not `running`, one that names another bounty
/// than `bounty_ref`, and a bounty with no well-formed target of a kind
/// this build knows under one of the record's target ids. Every refusal
/// names a target by its id alone, a checked value.
pub(super) fn build_manifest(
    sweeper: Pubky,
    record: &Sweep,
    bounty_ref: BountyRef,
    bounty: &Bounty,
    playbook: Playbook,
    finished_at: RecordTime,
) -> anyhow::Result<Manifest> {
    require_running(record)?;
    // `BountyRef`'s `==` compares the owner's key bytes and the id.
    if record.bounty != bounty_ref {
        bail!("this sweep's record names another bounty than the one read for it");
    }
    let target_shas = record
        .targets
        .iter()
        .map(|id| Ok((id.clone(), reviewed_commit(bounty, id)?)))
        // `collect` into a `Result` stops at the first error and returns
        // it; otherwise it builds the map from the pairs.
        .collect::<anyhow::Result<BTreeMap<TargetId, GitSha>>>()?;
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

/// The commit target `id` of `bounty` reviews, `KnownTarget::reviewed_commit`:
/// a pull request's head, or a repo or commit target's `rev`.
fn reviewed_commit(bounty: &Bounty, id: &TargetId) -> anyhow::Result<GitSha> {
    let target = bounty
        .targets
        .iter()
        .find(|target| target.id() == id)
        .ok_or_else(|| {
            anyhow!(
                "the bounty has no target {id}, which this sweep's record names, so submit cannot \
                 say which commit was swept"
            )
        })?;
    // core's `TargetError` is fixed text that quotes no field.
    let known = target
        .known()
        .with_context(|| format!("target {id} of the bounty is not well formed"))?
        .ok_or_else(|| {
            anyhow!("target {id} of the bounty is of a kind this build does not know")
        })?;
    Ok(known.reviewed_commit().clone())
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use sweepky_core::{Bounty, BountyRef, Playbook, Sweep, TargetId};

    use super::{ABORTED_IS_FINAL, ALREADY_DONE, PLAYBOOK_NEEDED, build_manifest, final_playbook};
    use crate::test_support::{
        SYNTHETIC_HEAD, SYNTHETIC_SHA, bounty_id, bounty_json, json_bytes, pr_target_json,
        random_pubky, record_id, repo_target_json, sweep_json,
    };

    const PLAYBOOK: &str = "cloudflare/security-audit@c1c8a8c";

    fn bounty(targets: Value) -> Bounty {
        Bounty::from_json(&json_bytes(&bounty_json(targets))).expect("a bounty")
    }

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
    fn the_manifest_takes_the_record_s_bounty_and_targets_and_the_bounty_s_commits() {
        let (sweeper, owner) = (random_pubky(), random_pubky());
        let at = BountyRef {
            owner,
            id: bounty_id(),
        };
        // The record names t2 and t1, of the bounty's three targets.
        let swept = record(&sweep_json(at, &["t2", "t1"], "running"));
        let bounty = bounty(json!([
            repo_target_json("t1"),
            pr_target_json("t2"),
            repo_target_json("t3"),
        ]));
        let finished_at = "2026-10-19T12:30:00Z".parse().expect("a time");

        let manifest = build_manifest(
            sweeper,
            &swept,
            at,
            &bounty,
            playbook(PLAYBOOK),
            finished_at,
        )
        .expect("a manifest");

        assert_eq!(manifest.sweeper, sweeper);
        assert_eq!(manifest.bounty, at);
        assert_eq!(ids(&manifest.targets), ["t2", "t1"]);
        // Each target's reviewed commit: a repo target's rev, and a pull
        // request's head, never its base or merge base.
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
    fn a_record_not_running_or_of_another_bounty_or_a_missing_target_is_refused() {
        let owner = random_pubky();
        let at = BountyRef {
            owner,
            id: bounty_id(),
        };
        let bounty = bounty(json!([repo_target_json("t1")]));
        let attempt = |swept: &Sweep, at: BountyRef| {
            let finished_at = "2026-10-19T12:30:00Z".parse().expect("a time");
            let refused = build_manifest(
                random_pubky(),
                swept,
                at,
                &bounty,
                playbook(PLAYBOOK),
                finished_at,
            );
            format!("{:#}", refused.expect_err("refused"))
        };

        assert_eq!(
            attempt(&record(&sweep_json(at, &["t1"], "done")), at),
            ALREADY_DONE
        );
        assert_eq!(
            attempt(&record(&sweep_json(at, &["t1"], "aborted")), at),
            ABORTED_IS_FINAL
        );
        assert!(ABORTED_IS_FINAL.contains("start a new sweep"));
        let unknown = attempt(&record(&sweep_json(at, &["t1"], "paused")), at);
        assert!(unknown.contains("does not know"), "{unknown}");
        assert!(!unknown.contains("paused"), "{unknown}");

        // The record names another bounty than the one read.
        let other = BountyRef {
            owner,
            id: record_id(1),
        };
        let message = attempt(&record(&sweep_json(other, &["t1"], "running")), at);
        assert!(message.contains("another bounty"), "{message}");

        // The bounty has no target t2, which the record names.
        let message = attempt(&record(&sweep_json(at, &["t1", "t2"], "running")), at);
        assert!(message.contains("no target t2"), "{message}");
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
