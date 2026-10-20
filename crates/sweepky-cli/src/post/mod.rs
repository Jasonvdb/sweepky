//! `post <draft> [--open]`: the draft read and checked, every target
//! pinned, the bounty shown to the owner, and, once they say yes, published
//! as `/pub/sweepky/bounties/<id>.json`, closed to strangers' sweeps unless
//! `--open`.
//!
//! - `draft`: the draft file an owner or their agent writes (title,
//!   focus, brief, a suggested playbook and the targets, unpinned), read
//!   with a cap and checked as strictly as a stranger's record.
//! - [`prepare_bounty`]: checks every target against the target policy,
//!   pins each one through the context's target source, and builds the
//!   core `Bounty` that `post` publishes, with the warnings it shows
//!   first. `--open` changes the record's `open` field and nothing else.
//! - `open`: what `post --open` does after the yes, in place of step 4
//!   below: the starting cursors found, and the bounty published with its
//!   discovered-sweeps file, `bounties/<id>.discovered.json`.
//! - [`post`], the command, in this order:
//!   1. read the draft, take `createdAt` from the clock, and pin every
//!      target;
//!   2. write the bounty as compact JSON, and refuse it when it is over
//!      `MAX_RECORD_BYTES`, which no Sweepky would read back;
//!   3. show the warnings and the bounty on standard error ([`preview`])
//!      and ask whether to publish it. Anything but `y` or `yes` publishes
//!      nothing, and so does `--no-input`, which fails instead of asking;
//!   4. only then make the bounty's id from the clock and, under the
//!      writers' lock with a fresh session (`session::with_writer_session`:
//!      an identity session is signed out afterwards, a Ring one only
//!      dropped), PUT the record through
//!      [`OwnStorage`] ([`publish`]), and report its `pubky://` URL. An
//!      open bounty goes through `open` instead, which searches before it
//!      takes the lock and writes its discovered-sweeps file after the
//!      bounty.
//!
//! **Why the question comes before the lock.** The lock serialises every
//! writing command on this install, and a person may take minutes to
//! answer, so no other command waits on them and no session is open
//! meanwhile. The lock covers the sign-in or restore, the PUT and the sign-out alone
//! (for `--open`, see `open` for the little more it covers).
//!
//! **Agent-written text is sanitised on its way to the terminal.** The
//! draft's checks already refuse public text the sanitiser would change,
//! but the preview still prints every string a draft wrote (the title,
//! focus, playbook, brief, target ids, repositories and paths) through
//! `display::sanitize` or `sanitize_multiline`: a path is held to core's
//! lexical rules only, and the preview takes a bounty, which nothing
//! makes a draft check first.

pub(crate) mod draft;
mod open;

use std::path::Path;

use anyhow::{Context as _, bail};
use sweepky_core::paths;
use sweepky_core::{
    Bounty, BountyPlaybook, BountyRef, KnownTarget, MAX_RECORD_BYTES, RecordId, RecordTime,
    RepoName, RepoPath, Target, TargetId,
};

use self::draft::{
    BountyDraft, MAX_BRIEF_BYTES, MAX_FOCUS_CHARS, MAX_PLAYBOOK_CHARS, MAX_TITLE_CHARS,
    UnpinnedKind, UnpinnedTarget, read_draft,
};
use crate::display::{sanitize, sanitize_multiline};
use crate::git::RunGit;
use crate::own_storage::{OwnStorage, SessionStorage};
use crate::prompt::{Prompting, confirm};
use crate::remote::write_error;
use crate::session::with_writer_session;
use crate::targets::github::GitHubApi;
use crate::targets::{PullRequest, TargetResolver};
use crate::{Context, Report, clock};

/// What `post` asks before it publishes.
const PUBLISH_QUESTION: &str = "Publish this bounty, where anyone can read it?";

/// What `post` says when it publishes nothing: in its report when the
/// owner does not say yes, and in front of the error under `--no-input`.
const NOTHING_POSTED: &str = "nothing was posted";

/// The line the preview and the report both give for a bounty that is
/// not `--open`.
const CLOSED: &str = "closed: sweeps from outside your circle are not read";

/// The line the preview and the report both give for a bounty that is
/// `--open`.
const OPEN: &str = "open: sweeps from anyone are read and labelled by trust";

/// [`OPEN`] or [`CLOSED`], as the bounty's `open` field says.
fn reach(open: bool) -> &'static str {
    if open { OPEN } else { CLOSED }
}

/// Runs `post <draft> [--open]`: reads the bounty draft at `draft`, pins
/// its targets, shows the bounty and asks whether to publish it, and only
/// on a yes writes `bounties/<id>.json` under the writers' lock with a
/// fresh session; with `open`, the bounty takes anyone's sweeps, and the
/// `open` module writes its discovered-sweeps file too. `prompting` is the
/// global `--no-input`, under which the question fails, so nothing is
/// posted or searched. See the module docs for the order and why.
pub(crate) async fn post(
    ctx: &Context,
    prompting: Prompting,
    draft: &Path,
    open: bool,
) -> anyhow::Result<Report> {
    let prepared = pin_draft(ctx, draft, open).await?;
    let record = bounty_bytes(&prepared.bounty)?;
    ctx.stderr.write_flushed(&preview(&prepared)?)?;
    // `context` puts the words in front of `--no-input`'s error, so both
    // ways of not saying yes tell the owner that nothing was posted.
    if !confirm(ctx, prompting, PUBLISH_QUESTION).context(NOTHING_POSTED)? {
        return Ok(Report::new(format!(
            "Not confirmed, so {NOTHING_POSTED}.\n"
        )));
    }
    let posted = if open {
        open::publish_signed_in(ctx, record).await?
    } else {
        publish_signed_in(ctx, record).await?
    };
    // A `BountyRef` prints as its `pubky://` URL, the raw z-base32 owner
    // and the id, which need no sanitising. It ends its line, so it can be
    // copied whole.
    Ok(Report::new(format!(
        "Posted the bounty, {}:\n{posted}\n",
        reach(open)
    )))
}

/// The draft at `path`, read and checked, its targets pinned through the
/// context's target source into the bounty `post` publishes, posted now,
/// and open to anyone's sweeps when `open`.
async fn pin_draft(ctx: &Context, path: &Path, open: bool) -> anyhow::Result<PreparedBounty> {
    let draft = read_draft(path)?;
    let created_at = clock::now()?;
    // The runner is dropped when this function returns, which removes its
    // private HOME before `post` asks its question and waits on a person.
    let git = ctx.targets.git_runner(&ctx.dirs, &ctx.git_env)?;
    // The SDK's HTTP client is the GitHub API a pull request target is
    // read through.
    let github = ctx.network.pubky().client();
    prepare_bounty(draft, open, &ctx.targets, &git, github, created_at).await
}

/// `bounty` as it is published: compact JSON, refused when it would be
/// over [`MAX_RECORD_BYTES`], which no Sweepky reads a record past. A draft
/// within its own caps can still build a longer bounty (the pinned SHAs
/// and the fields `post` adds), so `post` checks this before it asks, and
/// so before any session.
fn bounty_bytes(bounty: &Bounty) -> anyhow::Result<Vec<u8>> {
    let bytes = serde_json::to_vec(bounty).context("could not write the bounty record")?;
    if bytes.len() > MAX_RECORD_BYTES {
        bail!(
            "the bounty would be {} bytes, over the {MAX_RECORD_BYTES} bytes Sweepky reads a \
             record up to, so {NOTHING_POSTED}; shorten the brief or the paths",
            bytes.len()
        );
    }
    Ok(bytes)
}

/// Publishes `record` under a new bounty id, under the writers' lock with
/// a fresh session (an identity's signed out afterwards, a Ring one only
/// dropped), and gives the bounty's address.
async fn publish_signed_in(ctx: &Context, record: Vec<u8>) -> anyhow::Result<BountyRef> {
    // From the clock, which `new_record_id` checks first, so a clock before
    // 1970 is an error here rather than a panic.
    let id = clock::new_record_id()?;
    // `async move` moves `record` into the closure, which `publish` then
    // consumes; `id` is `Copy`, so the closure gets a copy. The closure
    // only borrows the session, so `with_writer_session` still ends it
    // afterwards, whatever `publish` returned.
    with_writer_session(ctx, async move |signed| {
        publish(&SessionStorage::new(signed), id, record).await?;
        Ok(BountyRef {
            owner: signed.login().pubky,
            id,
        })
    })
    .await
}

/// Writes `record`, the bytes [`bounty_bytes`] gave, as the signed-in
/// user's `bounties/<id>.json`. A refusal is mapped by `write_error`: 403
/// and 507 to their messages, anything else to fixed text and the status,
/// never the server's words.
async fn publish(storage: &impl OwnStorage, id: RecordId, record: Vec<u8>) -> anyhow::Result<()> {
    let path = paths::bounty(id);
    storage
        .put(&path, record)
        .await
        .map_err(|error| write_error(&error).context(format!("could not write {path}")))
}

/// What `post` shows before it asks: each warning, then the bounty as it
/// is about to be published: the title, focus and suggested playbook,
/// every target with its pinned SHAs, and the brief, each of its lines
/// behind a `| ` gutter so that none can pass for a line of Sweepky's own.
///
/// Every string from the draft goes through the sanitiser, with room for
/// the longest text the draft allows, so nothing a check let through is
/// cut. The warnings are fixed text that names targets by place, and the
/// SHAs and the pull request number are checked values, so those print as
/// they are.
fn preview(prepared: &PreparedBounty) -> anyhow::Result<String> {
    // Taking the struct apart borrows each field and names them all, so a
    // field added later does not compile until it is shown here or left
    // out on purpose.
    let PreparedBounty { bounty, warnings } = prepared;
    // `collect` builds one `String` from the `String` each line gives.
    let mut text: String = warnings
        .iter()
        .map(|warning| format!("warning: {warning}\n"))
        .collect();
    text.push_str(&format!(
        "The bounty to post, {}.\n  Title: {}\n  Focus: {}\n  Playbook: {}\n  \
         Targets ({}):\n",
        reach(bounty.open),
        sanitize(&bounty.title, MAX_TITLE_CHARS),
        sanitize(bounty.focus.as_str(), MAX_FOCUS_CHARS),
        shown_playbook(&bounty.playbook),
        bounty.targets.len()
    ));
    for (index, target) in bounty.targets.iter().enumerate() {
        text.push_str(&target_lines(index, target)?);
    }
    text.push_str("  Brief:\n");
    // A brief's characters are at most its bytes, so `MAX_BRIEF_BYTES`
    // shows the whole of any brief the draft allows. `lines()` splits at
    // the newlines the multi-line sanitiser keeps; every other control,
    // `\r` among them, is an escape by then.
    text.extend(
        sanitize_multiline(&bounty.brief, MAX_BRIEF_BYTES)
            .lines()
            .map(|line| format!("  | {line}\n")),
    );
    Ok(text)
}

/// The suggested playbook as the preview shows it, sanitised, or that
/// there is none.
fn shown_playbook(playbook: &BountyPlaybook) -> String {
    match &playbook.suggested {
        Some(suggested) => format!(
            "{} (suggested, not required)",
            sanitize(suggested, MAX_PLAYBOOK_CHARS)
        ),
        None => "none suggested".to_owned(),
    }
}

/// The preview's lines for `target`, the one at `index`: its id, its kind,
/// its repository and every SHA it is pinned to, a pull request's three on
/// lines of their own, and a repo target's paths ([`path_lines`]).
fn target_lines(index: usize, target: &Target) -> anyhow::Result<String> {
    let id = sanitize(target.id().as_str(), TargetId::MAX_LEN);
    // `post` built every target itself from checked parts, so each is of a
    // known kind with well-formed fields; `known` checks that again rather
    // than assume it, and a target it refuses is not shown half-read.
    let Ok(Some(known)) = target.known() else {
        bail!("targets[{index}] is not a target this build can show, so {NOTHING_POSTED}");
    };
    let lines = match known {
        KnownTarget::Repo(repo) => format!(
            "    {id}: repo {} at {}\n{}",
            shown_repo(repo.repo()),
            repo.rev(),
            path_lines(repo.paths())
        ),
        KnownTarget::Commit(commit) => format!(
            "    {id}: commit {} in {}\n",
            commit.rev(),
            shown_repo(commit.repo())
        ),
        KnownTarget::Pr(pr) => format!(
            "    {id}: pull request {} of {}\n      base {}\n      head {}\n      merge base {}\n",
            pr.number(),
            shown_repo(pr.repo()),
            pr.base(),
            pr.head(),
            pr.merge_base()
        ),
    };
    Ok(lines)
}

/// A repo target's paths as the preview shows them, sanitised, one a line,
/// or that it is the whole repository (`None`, as core reads no `paths`).
fn path_lines(paths: Option<&[RepoPath]>) -> String {
    match paths {
        Some(paths) => paths
            .iter()
            .map(|path| {
                format!(
                    "      path {}\n",
                    sanitize(path.as_str(), RepoPath::MAX_LEN)
                )
            })
            .collect(),
        None => "      the whole repository\n".to_owned(),
    }
}

/// `repo` as the preview shows it: through the sanitiser, like every other
/// string a draft wrote.
fn shown_repo(repo: &RepoName) -> String {
    sanitize(repo.as_str(), RepoName::MAX_LEN)
}

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
/// `post` publishes, posted at `created_at`, and open to anyone's sweeps
/// when `open` (`--open`): that field alone differs.
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
    open: bool,
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
    let mut bounty = draft.into_bounty(pinned, created_at);
    bounty.open = open;
    Ok(PreparedBounty { bounty, warnings })
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
    use std::fs;
    use std::io::Cursor;
    use std::path::PathBuf;

    use pubky::StatusCode;
    use serde_json::{Value, json};
    use sweepky_core::{
        Bounty, GitSha, KnownTarget, MAX_RECORD_BYTES, RecordTime, RepoPath, Target,
    };
    use tempfile::TempDir;

    use super::draft::BountyDraft;
    use super::{
        CLOSED, NOTHING_POSTED, OPEN, PUBLISH_QUESTION, PreparedBounty, bounty_bytes, post,
        prepare_bounty, preview, publish,
    };
    use crate::Context;
    use crate::clock;
    use crate::own_storage::OwnStorage;
    use crate::prompt::Prompting;
    use crate::remote::{QUOTA_FULL, WRITE_FORBIDDEN};
    use crate::session::NOT_LOGGED_IN;
    use crate::targets::fixture::FixtureTargets;
    use crate::targets::rev::NOT_ANONYMOUSLY_READABLE;
    use crate::targets::{TargetResolver, TargetSource};
    use crate::test_support::{
        FakeGitHub, FakeOwnStorage, RecordingGit, SharedBuffer, dirs_in, fixture_repo,
        fixture_targets, offline_network, private_temp, recorded_fixture_shas, test_context,
        test_git_env,
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
    /// answers nothing, which the fixture source never asks, into a bounty
    /// open to anyone's sweeps when `open`.
    async fn prepare(
        draft: BountyDraft,
        open: bool,
        source: &TargetSource,
        git: &impl crate::git::RunGit,
    ) -> anyhow::Result<PreparedBounty> {
        let github = FakeGitHub::answering(&[]);
        let prepared = prepare_bounty(draft, open, source, git, &github, created_at()).await;
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

        let prepared = prepare(draft, false, &source, &git).await.expect("pinned");

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
    async fn open_changes_the_record_s_open_field_alone() {
        let source = TargetSource::Fixture(fixture_targets());
        let temp = private_temp();
        let git = source
            .git_runner(&dirs_in(&temp), &test_git_env())
            .expect("a runner");
        let repo = fixture_repo();
        let targets = json!([
            { "kind": "repo", "repo": repo, "ref": "main", "paths": ["src/auth/"] },
            { "kind": "pr", "repo": repo, "number": 1 },
        ]);
        let closed = prepare(draft(targets.clone()), false, &source, &git)
            .await
            .expect("pinned");
        let open = prepare(draft(targets), true, &source, &git)
            .await
            .expect("pinned");

        // Read back as any Sweepky reads a bounty: open, and otherwise the
        // record a closed post writes, field for field.
        let written = bounty_bytes(&open.bounty).expect("within the cap");
        assert!(Bounty::from_json(&written).expect("reads back").open);
        let mut expected: Value =
            serde_json::from_slice(&bounty_bytes(&closed.bounty).expect("within the cap"))
                .expect("JSON");
        assert_eq!(expected["open"], json!(false));
        expected["open"] = json!(true);
        assert_eq!(
            serde_json::from_slice::<Value>(&written).expect("JSON"),
            expected
        );
        assert_eq!(open.warnings, closed.warnings);
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
        let error = prepare(draft, false, &source, &git)
            .await
            .expect_err("refused");
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

        let error = prepare(draft, false, &source, &git)
            .await
            .expect_err("refused");
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

        let prepared = prepare(draft, false, &source, &git).await.expect("pinned");

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

    // ----- The command: the preview, the question and the write -----

    /// A context for `post` on a network that reaches nothing, whose
    /// standard input holds `answer`, with the fixture repository as its
    /// target source and no login, so any sign-in would fail with
    /// [`NOT_LOGGED_IN`]. The `TempDir` is its `SWEEPKY_HOME`, which lives
    /// as long as the test keeps it.
    fn post_context(answer: &'static [u8]) -> (TempDir, Context, SharedBuffer) {
        let home = private_temp();
        let (mut ctx, stderr) = test_context(offline_network(), &home, Cursor::new(answer));
        ctx.targets = TargetSource::Fixture(fixture_targets());
        (home, ctx, stderr)
    }

    /// `draft` written to `draft.json` in `home`, for `post` to read.
    fn draft_file(home: &TempDir, draft: &[u8]) -> PathBuf {
        let path = home.path().join("draft.json");
        fs::write(&path, draft).expect("written");
        path
    }

    /// A draft with one target of each kind in the fixture repository.
    fn fixture_draft() -> Vec<u8> {
        let repo = fixture_repo();
        json!({
            "title": TITLE,
            "brief": BRIEF,
            "playbook": PLAYBOOK,
            "targets": [
                { "kind": "repo", "repo": repo, "ref": "main", "paths": ["src/auth/"] },
                { "kind": "commit", "repo": repo, "ref": "main" },
                { "kind": "pr", "repo": repo, "number": 1 },
            ],
        })
        .to_string()
        .into_bytes()
    }

    /// A draft of one repo target whose paths, and then its brief, bring it
    /// to 64 bytes under the record cap. It is within every cap the draft
    /// itself has, while the bounty built from it, with its pinned SHA, its
    /// id and the fields `post` adds, is over.
    fn draft_near_the_cap() -> Vec<u8> {
        let size = |draft: &Value| draft.to_string().len();
        let wanted = MAX_RECORD_BYTES - 64;
        let path = format!("src/{}", "a".repeat(RepoPath::MAX_LEN - "src/".len()));
        let mut draft = json!({
            "title": TITLE,
            "brief": "b",
            "targets": [{ "kind": "repo", "repo": fixture_repo(), "ref": "main", "paths": [path] }],
        });
        // Each path after the first adds itself, its two quotes and a comma.
        let more = (wanted - size(&draft)) / (path.len() + 3);
        draft["targets"][0]["paths"] = Value::from(vec![path; 1 + more]);
        let short = wanted - size(&draft);
        draft["brief"] = Value::from("b".repeat(1 + short));
        assert_eq!(size(&draft), wanted);
        draft.to_string().into_bytes()
    }

    /// A bounty of one repo target, pinned by hand rather than by git.
    fn a_bounty() -> Bounty {
        let draft = draft(json!([{ "kind": "repo", "repo": fixture_repo(), "ref": "main" }]));
        let sha: GitSha = "b".repeat(40).parse().expect("a SHA");
        let target = Target::repo(
            "t1".parse().expect("an id"),
            fixture_repo(),
            sha,
            Vec::new(),
        );
        draft.into_bounty(vec![target], created_at())
    }

    #[tokio::test]
    async fn anything_but_yes_posts_nothing_searches_nothing_and_opens_no_session() {
        // `n`, an empty line and the end of the input are each a no, for a
        // closed bounty and an open one alike.
        for open in [false, true] {
            for answer in [&b"n\n"[..], b"\n", b""] {
                let (home, ctx, _stderr) = post_context(answer);
                let draft = draft_file(&home, &fixture_draft());

                let report = post(&ctx, Prompting::Allowed, &draft, open)
                    .await
                    .expect("a no is not an error");

                // Had `post` signed in or searched a feed, it would have
                // failed: this context has no login, and its network
                // reaches nothing.
                assert!(report.text().contains(NOTHING_POSTED), "{}", report.text());
                // The writers' lock file is made by the first command that
                // takes the lock, so none was taken; no cursor was stored.
                assert!(!ctx.dirs.credential_lock_file().exists());
                assert!(!ctx.dirs.feed_cursors_file().exists());
            }
        }
    }

    #[tokio::test]
    async fn no_input_fails_instead_of_asking_and_posts_nothing() {
        for open in [false, true] {
            // A yes waits on standard input, and is never read.
            let (home, ctx, stderr) = post_context(b"y\n");
            let draft = draft_file(&home, &fixture_draft());

            let error = post(&ctx, Prompting::Forbidden, &draft, open)
                .await
                .expect_err("no question under --no-input");

            let message = format!("{error:#}");
            assert!(message.contains(NOTHING_POSTED), "{message}");
            assert!(message.contains("--no-input"), "{message}");
            assert!(!message.contains(NOT_LOGGED_IN), "{message}");
            assert!(!stderr.text().contains("[y/N]"), "{}", stderr.text());
            assert!(!ctx.dirs.credential_lock_file().exists());
            assert!(!ctx.dirs.feed_cursors_file().exists());
        }
    }

    #[tokio::test]
    async fn an_open_post_with_no_login_reads_it_after_the_yes_and_searches_nothing() {
        let (home, ctx, stderr) = post_context(b"y\n");
        let draft = draft_file(&home, &fixture_draft());

        let error = post(&ctx, Prompting::Allowed, &draft, true)
            .await
            .expect_err("no login");

        // NOT_LOGGED_IN, not a network error: had `post` searched the watch
        // list's homeserver first, this context's network, which reaches
        // nothing, would have failed it.
        let message = format!("{error:#}");
        assert!(message.contains(NOT_LOGGED_IN), "{message}");
        assert!(message.contains(NOTHING_POSTED), "{message}");
        // Asked and answered, then no search announced, no lock taken and
        // no cursor stored.
        let shown = stderr.text();
        assert!(
            shown.ends_with(&format!("{PUBLISH_QUESTION} [y/N] ")),
            "{shown}"
        );
        assert!(!ctx.dirs.credential_lock_file().exists());
        assert!(!ctx.dirs.feed_cursors_file().exists());
    }

    #[tokio::test]
    async fn the_preview_says_whether_the_bounty_is_open_before_the_question() {
        for (open, reach) in [(false, CLOSED), (true, OPEN)] {
            let (home, ctx, stderr) = post_context(b"n\n");
            let draft = draft_file(&home, &fixture_draft());

            post(&ctx, Prompting::Allowed, &draft, open)
                .await
                .expect("a no is not an error");

            let shown = stderr.text();
            assert!(
                shown.contains(&format!("The bounty to post, {reach}.\n")),
                "{shown}"
            );
            assert!(
                shown.ends_with(&format!("{PUBLISH_QUESTION} [y/N] ")),
                "{shown}"
            );
        }
    }

    #[tokio::test]
    async fn the_bounty_is_shown_with_every_pinned_sha_before_the_question() {
        let shas = recorded_fixture_shas();
        let sha = |name: &str| shas[name].to_string();
        let repo = fixture_repo();
        let (home, ctx, stderr) = post_context(b"n\n");
        let draft = draft_file(&home, &fixture_draft());

        post(&ctx, Prompting::Allowed, &draft, false)
            .await
            .expect("a no is not an error");

        // The title, focus and playbook, every target with its pinned
        // SHAs (main is M; pull request 1 is based on M, its head F2, the
        // two meeting at B), the brief behind its gutter, and then the
        // question.
        let shown = stderr.text();
        for line in [
            format!("  Title: {TITLE}\n"),
            "  Focus: security\n".to_owned(),
            format!("  Playbook: {PLAYBOOK} (suggested, not required)\n"),
            format!(
                "    t1: repo {repo} at {}\n      path src/auth/\n",
                sha("M")
            ),
            format!("    t2: commit {} in {repo}\n", sha("M")),
            format!(
                "    t3: pull request 1 of {repo}\n      base {}\n      head {}\n      \
                 merge base {}\n",
                sha("M"),
                sha("F2"),
                sha("B")
            ),
            "  Brief:\n  | Look at how sessions expire.\n  | \n  | - tokens\n".to_owned(),
        ] {
            assert!(shown.contains(&line), "{line:?} not in {shown}");
        }
        assert!(
            shown.ends_with(&format!("{PUBLISH_QUESTION} [y/N] ")),
            "{shown}"
        );
    }

    #[tokio::test]
    async fn a_bounty_over_the_record_cap_is_refused_before_the_question() {
        let draft = draft_near_the_cap();
        BountyDraft::parse(&draft).expect("the draft itself is within its caps");
        for open in [false, true] {
            let (home, ctx, stderr) = post_context(b"y\n");
            let path = draft_file(&home, &draft);

            let error = post(&ctx, Prompting::Allowed, &path, open)
                .await
                .expect_err("refused");

            // The cap's own message, not NOT_LOGGED_IN, which a sign-in or
            // the login read after the yes on standard input would have
            // given.
            let message = format!("{error:#}");
            assert!(
                message.contains(&format!("over the {MAX_RECORD_BYTES} bytes")),
                "{message}"
            );
            assert!(message.contains(NOTHING_POSTED), "{message}");
            // Nothing shown, nothing asked and no lock taken.
            assert_eq!(stderr.text(), "");
            assert!(!ctx.dirs.credential_lock_file().exists());
        }
    }

    #[test]
    fn the_preview_sanitises_every_string_a_draft_wrote() {
        // A bounty no draft check saw: an ESC sequence, a BEL or a carriage
        // return in every string that can hold one, and a zero-width space
        // in the path, which core's lexical check lets through. A target
        // id and a repository name have no room for any of them.
        let hostile = json!({
            "schemaVersion": 1,
            "title": "title \u{1b}[2J",
            "focus": "focus \u{1b}]0;x\u{7}",
            "brief": "one \u{1b}[31m\r\ntwo\n",
            "playbook": { "suggested": "playbook \u{1b}[1m", "required": false },
            "targets": [{
                "id": "t1", "kind": "repo", "repo": "example.invalid/org/name",
                "rev": "a".repeat(40), "paths": ["src/\u{200b}auth/"],
            }],
            "open": false,
            "reward": null,
            "status": "open",
            "credits": [],
            "createdAt": CREATED_AT,
            "doneAt": null,
        });
        let bounty = Bounty::from_json(hostile.to_string().as_bytes()).expect("core reads it");
        let prepared = PreparedBounty {
            bounty,
            warnings: Vec::new(),
        };

        let shown = preview(&prepared).expect("a preview");

        for raw in ['\u{1b}', '\u{7}', '\r', '\u{200b}'] {
            assert!(
                !shown.contains(raw),
                "{raw:?} reached the terminal: {shown:?}"
            );
        }
        for escaped in [
            "  Title: title \\u{1b}[2J\n",
            "  Focus: focus \\u{1b}]0;x\\u{7}\n",
            "  Playbook: playbook \\u{1b}[1m (suggested, not required)\n",
            "      path src/\\u{200b}auth/\n",
            "  | one \\u{1b}[31m\\u{d}\n  | two\n",
        ] {
            assert!(shown.contains(escaped), "{escaped:?} not in {shown:?}");
        }
    }

    #[tokio::test]
    async fn the_bounty_is_put_at_its_path_as_compact_json_that_reads_back_equal() {
        let bounty = a_bounty();
        let id = clock::new_record_id().expect("an id");
        let storage = FakeOwnStorage::default();

        let record = bounty_bytes(&bounty).expect("within the cap");
        publish(&storage, id, record).await.expect("written");

        let path = format!("/pub/sweepky/bounties/{id}.json");
        assert_eq!(storage.puts(), [path.as_str()]);
        let stored = storage
            .get_own(&path)
            .await
            .expect("reads")
            .expect("written");
        // Compact: a JSON string holds no raw newline, so any newline would
        // be layout.
        assert!(stored.len() <= MAX_RECORD_BYTES);
        assert!(!stored.contains(&b'\n'));
        assert_eq!(Bounty::from_json(&stored).expect("core reads it"), bounty);
    }

    #[tokio::test]
    async fn a_refused_write_gives_the_fixed_message_never_the_servers_text() {
        const SERVER_TEXT: &str = "MARKER-5e7v: tenant over quota, path policy says no";
        let id = clock::new_record_id().expect("an id");
        let path = format!("/pub/sweepky/bounties/{id}.json");
        for (status, fixed) in [
            (StatusCode::INSUFFICIENT_STORAGE, QUOTA_FULL),
            (StatusCode::FORBIDDEN, WRITE_FORBIDDEN),
        ] {
            let storage = FakeOwnStorage::refusing(&path, status, SERVER_TEXT);
            let record = bounty_bytes(&a_bounty()).expect("within the cap");

            let error = publish(&storage, id, record).await.expect_err("refused");

            let message = format!("{error:#}");
            assert!(message.contains(fixed), "{message}");
            assert!(!message.contains("MARKER-5e7v"), "{message}");
            assert_eq!(storage.puts(), [path.as_str()]);
            assert!(storage.get_own(&path).await.expect("reads").is_none());
        }
    }
}
