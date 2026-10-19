//! `post`, for a bounty that is not `--open`: the half that reads the
//! bounty draft and builds the bounty from it.
//!
//! - `draft`: the draft file an owner or their agent writes (title,
//!   focus, brief, a suggested playbook and the targets, unpinned), read
//!   with a cap and checked as strictly as a stranger's record.
//! - [`prepare_bounty`]: checks every target against the target policy,
//!   pins each one through the context's target source, and builds the
//!   core `Bounty` that `post` publishes, with the warnings it shows
//!   first.
//!
//! The other half, later in P2b, shows the title and the brief for the
//! owner to confirm, and only then writes the bounty.

// Nothing calls into this module yet outside its tests: the `post` command,
// later in P2b, is the first caller. As in `targets/mod.rs`, `expect` (not
// `allow`) silences the dead-code warning only while it is true, and that
// caller removes it.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the post command, later in P2b, is the first caller"
    )
)]

pub(crate) mod draft;

use anyhow::Context as _;
use sweepky_core::{Bounty, RecordTime, Target};

use self::draft::{BountyDraft, UnpinnedKind, UnpinnedTarget};
use crate::git::RunGit;
use crate::targets::github::GitHubApi;
use crate::targets::{PullRequest, TargetResolver};

/// A bounty ready for `post` to publish, and what `post` warns of before
/// it asks the owner to confirm.
#[derive(Debug)]
pub(crate) struct PreparedBounty {
    /// The bounty, every target pinned to full SHAs.
    pub(crate) bounty: Bounty,
    /// One line for each thing worth saying first, such as a repo target
    /// that sweeps the whole repository. Fixed text that names targets by
    /// their place in the draft.
    pub(crate) warnings: Vec<String>,
}

/// Pins every target of `draft` through `source` and builds the bounty
/// `post` publishes, posted at `created_at`.
///
/// First every target goes through the source's policy, which needs no
/// network, so a draft with one target the source refuses is refused
/// before git or GitHub is asked anything. Then each target is pinned in
/// turn, with `git` and, for a pull request, `github`: the caller passes
/// the source's own runner (`TargetResolver::git_runner`) and the SDK's
/// HTTP client, the tests a recording git or the fixture repository and a
/// fake GitHub. A repository that is not anonymously readable, or any
/// other failure, fails the whole draft, and no bounty is built.
///
/// Errors name the target by its place in the draft, `targets[0]`.
// `&impl TargetResolver` and the others: one copy of this function per
// combination of types it is called with, as with `RunGit`. The traits
// have `async fn`s, so they cannot be `dyn` (see `TargetResolver`).
pub(crate) async fn prepare_bounty(
    draft: BountyDraft,
    source: &impl TargetResolver,
    git: &impl RunGit,
    github: &impl GitHubApi,
    created_at: RecordTime,
) -> anyhow::Result<PreparedBounty> {
    for (index, target) in draft.targets().iter().enumerate() {
        source
            .check_policy(target.kind.known(), &target.repo)
            .with_context(|| format!("targets[{index}] is refused"))?;
    }
    let mut pinned = Vec::with_capacity(draft.targets().len());
    for (index, target) in draft.targets().iter().enumerate() {
        let target = pin_target(target, source, git, github)
            .await
            .with_context(|| format!("could not pin targets[{index}]"))?;
        pinned.push(target);
    }
    // Read before `into_bounty`, which uses the draft up.
    let warnings = draft.warnings();
    Ok(PreparedBounty {
        bounty: draft.into_bounty(pinned, created_at),
        warnings,
    })
}

/// `target` pinned through `source`: a repo or commit target's ref
/// resolved to a full SHA, or a pull request's base, head and merge base.
/// Only checked types reach the source.
async fn pin_target(
    target: &UnpinnedTarget,
    source: &impl TargetResolver,
    git: &impl RunGit,
    github: &impl GitHubApi,
) -> anyhow::Result<Target> {
    let UnpinnedTarget { id, repo, kind } = target;
    // A `Target` owns its values, so each `clone` copies a short checked
    // string out of the draft, which keeps its own until `into_bounty`.
    // `number` is `Copy`: `*number` copies the number out of the borrow.
    let pinned = match kind {
        UnpinnedKind::Repo { rev, paths } => {
            let sha = source.resolve_rev(git, repo, rev).await?;
            Target::repo(id.clone(), repo.clone(), sha, paths.clone())
        }
        UnpinnedKind::Commit { rev } => {
            let sha = source.resolve_rev(git, repo, rev).await?;
            Target::commit(id.clone(), repo.clone(), sha)
        }
        UnpinnedKind::Pr { number } => {
            let PullRequest {
                base,
                head,
                merge_base,
            } = source.pull_request(git, github, repo, *number).await?;
            Target::pr(id.clone(), repo.clone(), *number, base, head, merge_base)
        }
    };
    Ok(pinned)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use sweepky_core::{Bounty, GitSha, KnownTarget, RecordTime};

    use super::draft::BountyDraft;
    use super::{PreparedBounty, prepare_bounty};
    use crate::targets::fixture::FixtureTargets;
    use crate::targets::rev::NOT_ANONYMOUSLY_READABLE;
    use crate::targets::{TargetResolver, TargetSource};
    use crate::test_support::{
        FakeGitHub, RecordingGit, dirs_in, fixture_repo, fixture_targets, private_temp,
        recorded_fixture_shas, test_git_env,
    };

    const TITLE: &str = "Auth and session handling";
    const BRIEF: &str = "Look at how sessions expire.\n\n- tokens\n- cookies\n";
    const PLAYBOOK: &str = "cloudflare/security-audit@c1c8a8c";
    const CREATED_AT: &str = "2026-10-19T12:00:00Z";

    /// A draft whose targets are `targets`.
    fn draft(targets: Value) -> BountyDraft {
        let draft = json!({
            "title": TITLE,
            "brief": BRIEF,
            "playbook": PLAYBOOK,
            "targets": targets,
        });
        BountyDraft::parse(draft.to_string().as_bytes()).expect("a valid draft")
    }

    fn created_at() -> RecordTime {
        CREATED_AT.parse().expect("a time")
    }

    /// `draft` pinned through `source`, with `git`, and with a GitHub that
    /// answers nothing, which the fixture source never asks.
    async fn prepare(
        draft: BountyDraft,
        source: &TargetSource,
        git: &impl crate::git::RunGit,
    ) -> anyhow::Result<PreparedBounty> {
        let github = FakeGitHub::answering(&[]);
        let prepared = prepare_bounty(draft, source, git, &github, created_at()).await;
        assert_eq!(github.asked(), Vec::<String>::new());
        prepared
    }

    #[tokio::test]
    async fn the_fixture_source_pins_each_kind_into_an_open_bounty() {
        let shas = recorded_fixture_shas();
        let sha = |name: &str| -> &GitSha { &shas[name] };
        let repo = fixture_repo();
        let source = TargetSource::Fixture(fixture_targets());
        let temp = private_temp();
        let git = source
            .git_runner(&dirs_in(&temp), &test_git_env())
            .expect("a runner");
        let draft = draft(json!([
            { "kind": "repo", "repo": repo, "ref": "main", "paths": ["src/auth/"] },
            { "kind": "commit", "repo": repo, "ref": "main" },
            { "kind": "pr", "repo": repo, "number": 1 },
        ]));

        let prepared = prepare(draft, &source, &git).await.expect("pinned");

        assert_eq!(prepared.warnings, Vec::<String>::new());
        // `main` is M, the fixture's merge commit, for the repo and the
        // commit target alike; pull request 1 is based on M, its head is
        // F2 and the two meet at B. Open, closed to strangers, nobody
        // credited, no reward and not done.
        let expected = json!({
            "schemaVersion": 1,
            "title": TITLE,
            "focus": "security",
            "brief": BRIEF,
            "playbook": { "suggested": PLAYBOOK, "required": false },
            "targets": [
                { "id": "t1", "kind": "repo", "repo": repo, "rev": sha("M"), "paths": ["src/auth/"] },
                { "id": "t2", "kind": "commit", "repo": repo, "rev": sha("M") },
                {
                    "id": "t3", "kind": "pr", "repo": repo, "number": 1,
                    "base": sha("M"), "head": sha("F2"), "mergeBase": sha("B"),
                },
            ],
            "open": false,
            "reward": null,
            "status": "open",
            "credits": [],
            "createdAt": CREATED_AT,
            "doneAt": null,
        });
        let written = serde_json::to_vec(&prepared.bounty).expect("serialises");
        assert_eq!(
            serde_json::from_slice::<Value>(&written).expect("JSON"),
            expected
        );

        // Read back as any Sweepky reads a bounty, each target through
        // `Target::known`, the view `run` uses.
        let read = Bounty::from_json(&written).expect("reads back");
        assert_eq!(read, prepared.bounty);
        let known: Vec<KnownTarget> = read
            .targets
            .iter()
            .map(|target| target.known().expect("well formed").expect("a known kind"))
            .collect();
        let [
            KnownTarget::Repo(narrowed),
            KnownTarget::Commit(commit),
            KnownTarget::Pr(pr),
        ] = known.as_slice()
        else {
            panic!("a repo, a commit and a pr target: {known:?}");
        };
        assert_eq!(narrowed.rev(), sha("M"));
        assert_eq!(commit.rev(), sha("M"));
        assert_eq!(
            (pr.base(), pr.head(), pr.merge_base()),
            (sha("M"), sha("F2"), sha("B"))
        );
    }

    #[tokio::test]
    async fn a_repository_that_is_not_anonymously_readable_builds_no_bounty() {
        // The fixture's name mapped to an empty directory: git cannot list
        // it, as it cannot list a private repository.
        let empty = private_temp();
        let source = TargetSource::Fixture(FixtureTargets::new([(
            fixture_repo(),
            empty.path().to_path_buf(),
        )]));
        let temp = private_temp();
        let git = source
            .git_runner(&dirs_in(&temp), &test_git_env())
            .expect("a runner");
        let draft = draft(json!([{ "kind": "repo", "repo": fixture_repo(), "ref": "main" }]));

        // An `Err`, so there is no bounty to publish.
        let error = prepare(draft, &source, &git).await.expect_err("refused");
        let message = format!("{error:#}");
        assert!(message.contains("targets[0]"), "{message}");
        assert!(message.contains(NOT_ANONYMOUSLY_READABLE), "{message}");
    }

    #[tokio::test]
    async fn every_target_passes_the_policy_before_git_runs() {
        // The second target's repository is one the source does not serve:
        // refused before the first target is pinned.
        let source = TargetSource::Fixture(fixture_targets());
        let git = RecordingGit::succeeding(source.protocols(), b"");
        let draft = draft(json!([
            { "kind": "repo", "repo": fixture_repo(), "ref": "main" },
            { "kind": "commit", "repo": "example.invalid/sweepky/elsewhere", "ref": "main" },
        ]));

        let error = prepare(draft, &source, &git).await.expect_err("refused");
        assert!(format!("{error:#}").contains("targets[1]"), "{error:#}");
        assert_eq!(git.argv(), Vec::<Vec<String>>::new());
    }

    #[tokio::test]
    async fn a_whole_repository_target_is_pinned_with_its_warning() {
        let source = TargetSource::Fixture(fixture_targets());
        let head = "b".repeat(40);
        let listing = format!("{head}\tHEAD\n");
        let git = RecordingGit::succeeding(source.protocols(), listing.as_bytes());
        let draft = draft(json!([{ "kind": "repo", "repo": fixture_repo(), "ref": "HEAD" }]));

        let prepared = prepare(draft, &source, &git).await.expect("pinned");

        let [warning] = prepared.warnings.as_slice() else {
            panic!("one warning: {:?}", prepared.warnings);
        };
        assert!(warning.contains("5-hour plan window"), "{warning}");
        // No paths: the whole repository, written with no `paths` key.
        assert_eq!(
            serde_json::to_value(&prepared.bounty.targets).expect("JSON"),
            json!([{ "id": "t1", "kind": "repo", "repo": fixture_repo(), "rev": head }])
        );
    }
}
