//! `run`'s fetching half: each chosen target fetched into
//! `./sweeps/<id>/target/<tid>/` by its exact SHA, its agent-instruction
//! files stripped, and `scope.json` and `brief.md` written beside them.
//!
//! - [`SweepPaths`]: every path of one sweep, built from the project's own
//!   path, the sweep's `RecordId` and each `TargetId`, which core holds to a
//!   single path segment of ASCII letters, digits, `-` and `_`. Nothing a
//!   repository or a record wrote as text, a `RepoPath` above all, is ever
//!   joined onto them; a target's paths go into `scope.json` as data.
//! - [`check_sweep_dir`]: the check `run` makes before it publishes
//!   anything: `sweeps/` must be a real directory or absent, never a link,
//!   and `sweeps/<id>/` must not exist.
//! - [`fetch_sweep`]: the fetch itself, which makes the same check again
//!   before git runs and removes the half-made sweep directory if any step
//!   fails. Flipping the public record to `aborted` is the run command's
//!   job, not this module's.
//!
//! **The git steps for one target**, every one through the hardened runner
//! (`crate::git`: argv only, no config or credentials of the user's, hooks,
//! submodules, LFS and symlinks off), in the target's own new directory:
//!
//! 1. `git init --quiet --template=`: an empty repository; the empty
//!    template copies in no hooks or other files.
//! 2. `git config core.symlinks false`: the runner already passes this on
//!    every run, and the copy keeps it too, so a `git checkout` the agent
//!    runs there later writes a link as a plain file as well.
//! 3. `git fetch <remote> --depth=2 --no-tags --no-recurse-submodules
//!    --quiet <sha>…`: the URL is passed as it is, so no remote is
//!    configured, and only the pinned commits come, each by its full SHA,
//!    with one generation of parents: depth 2 for every kind, so a commit
//!    target's parents are there to diff against.
//! 4. `git checkout --quiet --detach <sha>`: the reviewed commit
//!    (`KnownTarget::reviewed_commit`), every link in its tree written as a
//!    plain file holding the link's text, so no link can point the agent
//!    outside the copy.
//! 5. For a commit target, `git rev-list --parents --max-count=1 <sha>`:
//!    the parents of the commit as fetched, which tell a merge (core's
//!    `CommitShape`) from an ordinary or root commit.
//!
//! **Which remote.** [`TargetResolver::fetch_remote`] names it: for the real
//! source the `https://<repo>` remote whose host the policy checked, for a
//! pull request the base repository's. A pull request's head is fetched by
//! its pinned SHA from that base repository, where `refs/pull/<n>/head`
//! makes it reachable (that is how 01's "from the base repo's
//! `refs/pull/<n>/head`" is read), together with its merge base; never
//! from the fork.
//!
//! **A commit no longer served.** git's standard error, which carries a
//! server's words, is never shown; it is matched against git's own phrase
//! for a commit a server will not hand over, and that failure is the fixed
//! "the pinned commit … is no longer served" (01: `run` aborts rather than
//! fall back to a branch tip). Any other failure keeps the runner's fixed exit
//! status text.

use std::fs::{self, DirBuilder};
use std::io::ErrorKind;
// `DirBuilderExt` adds `.mode()` to `DirBuilder`, a Unix-only extension.
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, anyhow, bail};
use sweepky_core::{
    CommitShape, GitSha, KnownTarget, KnownTargetKind, RecordId, RepoName, SweepRef, TargetId,
    TargetScope,
};

use super::CheckedBounty;
use super::scope_file::{ScopeTarget, scope_json, write_new_file};
use super::select::ChosenTarget;
use super::strip::strip_agent_files;
use crate::git::{GitCommand, GitFailed, Limits, LocalSubcommand, Remote, RunGit, STDERR_CAP};
use crate::private_fs::{lstat, refuse_unless_dir};
use crate::targets::{TargetRemote, TargetResolver};

/// The quick local steps' limits (`init`, `config`, `rev-list`): a minute,
/// and 64 KiB of output, room for `rev-list`'s one line of a commit with
/// over 1500 parents.
const LOCAL_LIMITS: Limits = Limits {
    timeout: Duration::from_secs(60),
    stdout_cap: 64 * 1024,
    stderr_cap: STDERR_CAP,
};

/// `checkout`'s limits: it writes the whole tree, so it gets as long as the
/// fetch, 10 minutes. `--quiet`, so it writes almost nothing.
const CHECKOUT_LIMITS: Limits = Limits {
    timeout: Duration::from_secs(10 * 60),
    // `..LOCAL_LIMITS` takes every field not named from that constant.
    ..LOCAL_LIMITS
};

/// git's words, in every protocol version, when a server does not have a
/// commit asked for by SHA, or no ref of its reaches it:
/// `upload-pack: not our ref <sha>` (GitHub and the `file` transport alike,
/// checked against both on 2026-10-19). Matched, never shown. A server
/// that takes no request by SHA at all says something else, and gets the
/// general message: its commit may well still be there.
const NOT_OUR_REF: &str = "not our ref";

/// The check `run` makes before it publishes anything: that sweep `id` can
/// go in `<project>/sweeps/<id>/`. `sweeps` must be absent or a real
/// directory, not a link, and `sweeps/<id>` must not exist. Creates
/// nothing; [`fetch_sweep`] checks again before git runs.
pub(crate) fn check_sweep_dir(project: &Path, id: RecordId) -> anyhow::Result<()> {
    SweepPaths::new(project, id)?.check_free()
}

/// What [`fetch_sweep`] made: the sweep directory, and each target as
/// `scope.json` lists it.
#[derive(Debug)]
pub(crate) struct FetchedSweep {
    /// `<project>/sweeps/<id>`.
    pub(crate) dir: PathBuf,
    /// In the bounty's order. The `stripped` names are the repository's,
    /// so anything that prints one sanitises it first.
    pub(crate) targets: Vec<ScopeTarget>,
}

/// Fetches every target of `checked` into `<project>/sweeps/<id>/` for
/// `sweep`, through `git` and `source`, and writes `scope.json` and
/// `brief.md` there. On any failure the sweep directory is removed again,
/// and nothing else under `sweeps/` is touched.
pub(crate) async fn fetch_sweep(
    git: &impl RunGit,
    source: &impl TargetResolver,
    project: &Path,
    sweep: SweepRef,
    checked: &CheckedBounty,
) -> anyhow::Result<FetchedSweep> {
    let paths = SweepPaths::new(project, sweep.id)?;
    paths.check_free()?;
    let half_made = paths.claim()?;
    let mut targets = Vec::with_capacity(checked.targets.len());
    for chosen in &checked.targets {
        let target = fetch_target(git, source, &paths, chosen)
            .await
            .with_context(|| format!("could not fetch target {}", chosen.id))?;
        targets.push(target);
    }
    let output = dir_text(&paths.audit())?;
    let scope = scope_json(sweep, checked, &output, &targets)?;
    write_new_file(&paths.root.join("scope.json"), &scope)?;
    // The brief as the owner wrote it, byte for byte: the agent reads it as
    // a file, and nothing here prints it.
    write_new_file(
        &paths.root.join("brief.md"),
        checked.bounty.brief.as_bytes(),
    )?;
    half_made.keep();
    Ok(FetchedSweep {
        dir: paths.root,
        targets,
    })
}

/// Fetches `chosen` into its directory under `paths`, checks it out,
/// strips it, and describes it for `scope.json`.
async fn fetch_target(
    git: &impl RunGit,
    source: &impl TargetResolver,
    paths: &SweepPaths,
    chosen: &ChosenTarget,
) -> anyhow::Result<ScopeTarget> {
    let plan = FetchPlan::of(&chosen.target);
    let remote = source.fetch_remote(plan.kind, plan.repo).await?;
    let dir = paths.target(&chosen.id);
    fs::create_dir(&dir).with_context(|| format!("could not create {}", dir.display()))?;
    make_repository(git, &dir).await?;
    git.run(&plan.fetch_command(git_remote(&remote)).in_dir(&dir))
        .await
        .map_err(|error| fetch_error(error, &plan))?;
    check_out(git, &dir, plan.checkout).await?;
    let stripped = strip_agent_files(&dir)?;
    Ok(ScopeTarget {
        id: chosen.id.clone(),
        kind: plan.kind.into(),
        path: dir_text(&dir)?,
        scope: scope_of(git, &dir, &chosen.target).await?,
        stripped,
    })
}

/// `git init --quiet --template=` in `dir`, then `git config core.symlinks
/// false`, so the copy keeps writing links as plain files.
async fn make_repository(git: &impl RunGit, dir: &Path) -> anyhow::Result<()> {
    let init = GitCommand::local(LocalSubcommand::Init, LOCAL_LIMITS)
        .flag("--quiet")
        .flag("--template=");
    git.run(&init.in_dir(dir))
        .await
        .context("could not make the target's repository")?;
    let config = GitCommand::local(LocalSubcommand::Config, LOCAL_LIMITS)
        .operand("core.symlinks")
        .operand("false");
    git.run(&config.in_dir(dir))
        .await
        .context("could not set up the target's repository")?;
    Ok(())
}

/// `git checkout --quiet --detach <commit>` in `dir`, with the runner's
/// `core.symlinks=false`.
async fn check_out(git: &impl RunGit, dir: &Path, commit: &GitSha) -> anyhow::Result<()> {
    let checkout = GitCommand::local(LocalSubcommand::Checkout, CHECKOUT_LIMITS)
        .flag("--quiet")
        .flag("--detach")
        .operand(commit.as_str());
    git.run(&checkout.in_dir(dir))
        .await
        .context("could not check out the pinned commit")?;
    Ok(())
}

/// What to review of `target`, fetched into `dir`: core's scope for its
/// kind, a commit's from its parents as fetched.
async fn scope_of(
    git: &impl RunGit,
    dir: &Path,
    target: &KnownTarget,
) -> anyhow::Result<TargetScope> {
    // No `_` arm: a kind added to core later does not compile until someone
    // decides how it is scoped.
    Ok(match target {
        KnownTarget::Pr(pr) => pr.scope(),
        KnownTarget::Commit(commit) => commit.scope(commit_shape(git, dir, commit.rev()).await?),
        KnownTarget::Repo(repo) => repo.scope(),
    })
}

/// Every path of one sweep under the project: `<project>/sweeps/<id>/` and
/// what `run` puts in it.
///
/// Built from the project's own path, the sweep's id and each target's id
/// alone. The project's path is checked to be absolute and UTF-8 when this
/// is made, so `scope.json` can name every path under it as text.
#[derive(Debug)]
struct SweepPaths {
    /// `<project>/sweeps`.
    sweeps: PathBuf,
    /// `<project>/sweeps/<id>`.
    root: PathBuf,
}

impl SweepPaths {
    /// The paths of sweep `id` in the project at `project`.
    fn new(project: &Path, id: RecordId) -> anyhow::Result<Self> {
        if !project.is_absolute() {
            bail!(
                "{} is not an absolute path, so scope.json could not name the paths under it",
                project.display()
            );
        }
        if project.to_str().is_none() {
            bail!(
                "{} is not UTF-8, so scope.json could not name the paths under it; run the sweep \
                 in a project whose path is",
                project.display()
            );
        }
        let sweeps = project.join("sweeps");
        let root = sweeps.join(id.to_string());
        Ok(Self { sweeps, root })
    }

    /// `<project>/sweeps/<id>/target`, which holds one directory per target.
    fn targets(&self) -> PathBuf {
        self.root.join("target")
    }

    /// `<project>/sweeps/<id>/target/<tid>`.
    fn target(&self, id: &TargetId) -> PathBuf {
        self.targets().join(id.as_str())
    }

    /// `<project>/sweeps/<id>/audit`, the playbook's output directory, which
    /// `run` names in `scope.json` and does not make.
    fn audit(&self) -> PathBuf {
        self.root.join("audit")
    }

    /// Refuses a `sweeps` that is a link or anything but a directory, and a
    /// sweep directory that is already there. Looks only, with `lstat`, so
    /// no link is followed; creates nothing.
    fn check_free(&self) -> anyhow::Result<()> {
        if let Some(seen) = lstat(&self.sweeps)? {
            refuse_unless_dir(&self.sweeps, &seen)?;
        }
        if lstat(&self.root)?.is_some() {
            bail!(
                "{} is already there; run makes a new directory for every sweep and never \
                 writes into one that exists",
                self.root.display()
            );
        }
        Ok(())
    }

    /// Makes `sweeps/` if need be, then `sweeps/<id>/`, 0700, and its
    /// `target/`. The guard handed back removes `sweeps/<id>/` again, with
    /// all it holds, unless it is kept.
    fn claim(&self) -> anyhow::Result<HalfMade<'_>> {
        self.ensure_sweeps()?;
        // Not `recursive`: the `mkdir` fails if anything at all is there, a
        // link included, so the directory is this run's alone. 0700, so no
        // other user of the machine can read the audit the agent writes
        // into it before `submit` encrypts it.
        DirBuilder::new()
            .mode(0o700)
            .create(&self.root)
            .with_context(|| {
                format!(
                    "could not create {}; run makes a new directory for every sweep",
                    self.root.display()
                )
            })?;
        // From here the directory is this run's: if the next step fails,
        // `half_made` is dropped on the way out and removes it.
        let half_made = HalfMade {
            path: &self.root,
            kept: false,
        };
        let targets = self.targets();
        fs::create_dir(&targets)
            .with_context(|| format!("could not create {}", targets.display()))?;
        Ok(half_made)
    }

    /// Makes `sweeps/` unless something is there, then refuses whatever is
    /// there, made just now or before, unless it is a real directory, so a
    /// sweep is never made through a link.
    fn ensure_sweeps(&self) -> anyhow::Result<()> {
        match fs::create_dir(&self.sweeps) {
            Ok(()) => {}
            Err(err) if err.kind() == ErrorKind::AlreadyExists => {}
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("could not create {}", self.sweeps.display()));
            }
        }
        let seen = lstat(&self.sweeps)?
            .with_context(|| format!("{} went away; try again", self.sweeps.display()))?;
        refuse_unless_dir(&self.sweeps, &seen)
    }
}

/// A sweep directory `run` is still filling. Dropped before
/// [`HalfMade::keep`], whether a step failed, returned early with `?`, or
/// the command was cancelled, it removes the directory and all it holds, so
/// no half-made sweep is left for `submit` to find.
///
/// It borrows the path (the lifetime `'a`) from the [`SweepPaths`] it came
/// from, so it cannot outlive them.
struct HalfMade<'a> {
    path: &'a Path,
    kept: bool,
}

impl HalfMade<'_> {
    /// The sweep is whole: keep it. Takes `self` by value, so the guard is
    /// used up here and its `drop`, which runs at the end of this call,
    /// finds `kept` set.
    fn keep(mut self) {
        self.kept = true;
    }
}

/// Best effort: `drop` cannot return an error, and a directory left behind
/// has no marker, so `submit` refuses it. std's `remove_dir_all` never
/// follows a link inside it. A process killed outright (`kill -9`) runs no
/// `drop`, and leaves the directory behind.
impl Drop for HalfMade<'_> {
    fn drop(&mut self) {
        if !self.kept {
            let _ = fs::remove_dir_all(self.path);
        }
    }
}

/// What `run` fetches for one target: from which repository, which commits,
/// and the one it checks out. Pure, so a test checks it without git.
#[derive(Debug, PartialEq, Eq)]
struct FetchPlan<'a> {
    kind: KnownTargetKind,
    /// The repository fetched from: a pull request's base repository,
    /// never its fork.
    repo: &'a RepoName,
    /// The commits fetched, each by its full SHA.
    commits: Vec<&'a GitSha>,
    /// The commit checked out, the one the sweep reviews.
    checkout: &'a GitSha,
}

impl<'a> FetchPlan<'a> {
    /// The plan for `target`. It borrows every value from `target` (the
    /// lifetime `'a`), so it copies no SHA.
    fn of(target: &'a KnownTarget) -> Self {
        let (kind, repo, commits) = match target {
            // The head, and the merge base the scope's diff starts at,
            // which a depth-2 history of the head need not hold.
            KnownTarget::Pr(pr) => (
                KnownTargetKind::Pr,
                pr.repo(),
                vec![pr.head(), pr.merge_base()],
            ),
            KnownTarget::Commit(commit) => {
                (KnownTargetKind::Commit, commit.repo(), vec![commit.rev()])
            }
            KnownTarget::Repo(repo) => (KnownTargetKind::Repo, repo.repo(), vec![repo.rev()]),
        };
        Self {
            kind,
            repo,
            commits,
            checkout: target.reviewed_commit(),
        }
    }

    /// `git fetch <remote> --depth=2 --no-tags --no-recurse-submodules
    /// --quiet <sha>…`, from `remote` alone.
    fn fetch_command(&self, remote: Remote<'_>) -> GitCommand {
        let command = GitCommand::fetch(remote)
            .flag("--depth=2")
            .flag("--no-tags")
            .flag("--no-recurse-submodules")
            .flag("--quiet");
        // `fold` threads the command through one `operand` call per SHA,
        // since each call takes the command by value and hands it back.
        self.commits
            .iter()
            .fold(command, |command, sha| command.operand(sha.as_str()))
    }
}

/// The borrowed form of `remote` that git's network commands take.
fn git_remote(remote: &TargetRemote) -> Remote<'_> {
    match remote {
        TargetRemote::Https(https) => Remote::Https(https),
        TargetRemote::Local(local) => Remote::Local(local),
    }
}

/// The error a failed fetch for `plan` becomes: the fixed "no longer
/// served" when git says a server would not hand over one of its commits,
/// else `error` with context. Neither carries anything git wrote.
fn fetch_error(error: anyhow::Error, plan: &FetchPlan<'_>) -> anyhow::Error {
    // `downcast_ref` finds the `GitFailed` the runner returned, if git ran
    // and failed; a timeout or a cap is another error, which gets the
    // general context.
    let unserved = error.downcast_ref::<GitFailed>().and_then(|failed| {
        plan.commits
            .iter()
            .find(|sha| failed.stderr_mentions(&format!("{NOT_OUR_REF} {sha}")))
    });
    match unserved {
        // A new error, so the `GitFailed`, and git's words with it, is
        // dropped here.
        Some(sha) => anyhow!(
            "the pinned commit {sha} is no longer served by its repository (a force-push can \
             take a commit away), so run stops rather than sweep another one"
        ),
        None => error.context(
            "git could not fetch the pinned commits: the repository may no longer serve them, or \
             may be out of reach",
        ),
    }
}

/// Whether `commit`, fetched in the repository at `dir`, is a merge: its
/// parents counted by `git rev-list --parents --max-count=1`. Depth 2 means
/// they are there to count; a root commit has none.
async fn commit_shape(
    git: &impl RunGit,
    dir: &Path,
    commit: &GitSha,
) -> anyhow::Result<CommitShape> {
    let command = GitCommand::local(LocalSubcommand::RevList, LOCAL_LIMITS)
        .flag("--parents")
        .flag("--max-count=1")
        .operand(commit.as_str())
        .in_dir(dir);
    let output = git
        .run(&command)
        .await
        .context("could not count the pinned commit's parents")?;
    Ok(match parent_count(&output, commit)? {
        0 | 1 => CommitShape::Ordinary,
        _ => CommitShape::Merge,
    })
}

/// What [`parent_count`] says of output it does not read.
const NOT_PARENTS_LINE: &str =
    "git rev-list printed something other than the commit and its parents";

/// How many parents `commit` has, from `rev-list --parents`'s one line:
/// `commit`, then each parent, a space before each, and a newline. Anything
/// else is an error that quotes none of it. The runner caps the output at
/// [`LOCAL_LIMITS`], and nothing here indexes, so no output can make this
/// panic.
fn parent_count(output: &[u8], commit: &GitSha) -> anyhow::Result<usize> {
    let line = output
        .strip_suffix(b"\n")
        .and_then(|line| std::str::from_utf8(line).ok())
        .context(NOT_PARENTS_LINE)?;
    let mut shas = line.split(' ');
    if shas.next() != Some(commit.as_str()) {
        bail!(NOT_PARENTS_LINE);
    }
    let mut parents = 0;
    for parent in shas {
        // A full lower-case SHA-1, as the repository was fetched with.
        if parent.len() != GitSha::SHA1_LEN || parent.parse::<GitSha>().is_err() {
            bail!(NOT_PARENTS_LINE);
        }
        parents += 1;
    }
    Ok(parents)
}

/// `path` as `scope.json` writes a directory: UTF-8, with a trailing `/`.
fn dir_text(path: &Path) -> anyhow::Result<String> {
    path.to_str()
        .map(|text| format!("{text}/"))
        .with_context(|| format!("{} is not UTF-8", path.display()))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::OsStr;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::Duration;

    use serde_json::{Value, json};
    use sweepky_core::{
        Bounty, BountyRef, GitSha, KnownTargetKind, RepoName, SweepRef, Target, TargetId,
    };
    use tempfile::TempDir;

    use super::{
        FetchPlan, FetchedSweep, NOT_PARENTS_LINE, SweepPaths, check_sweep_dir, fetch_sweep,
        parent_count,
    };
    use crate::git::{
        AllowedProtocols, GitCommand, GitFailed, GitRunner, Limits, LocalSubcommand, Remote,
        RunGit, git_argv,
    };
    use crate::run::CheckedBounty;
    use crate::run::select::{Acceptance, ChosenTargets, choose_targets};
    use crate::targets::fixture::{FixtureTargets, LocalRemote};
    use crate::targets::{TargetResolver, TargetSource};
    use crate::test_support::{
        PLANTED, RecordingGit, SYNTHETIC_SHA, bounty_id, bounty_json, dirs_in, fixture_repo,
        fixture_targets, inert_target_repo, json_bytes, mode, private_temp, random_pubky,
        recorded_fixture_shas, test_git_env,
    };

    /// The brief of the tests' bounty: markdown with a CRLF, a non-ASCII
    /// letter and a right-to-left override, which must reach `brief.md` as
    /// they are.
    const BRIEF: &str =
        "# Auth\r\nLook at `src/auth/`, caf\u{e9} \u{202e}rtl\u{202c}.\n\n- no secrets\n";

    /// The playbook the tests' bounty suggests.
    const SUGGESTED: &str = "cloudflare/security-audit@c1c8a8c";

    /// The six agent-instruction files the fixture's root commit plants, as
    /// `strip_agent_files` lists them, and so in every commit.
    const PLANTED_AGENT_FILES: [&str; 6] = [
        ".claude/",
        ".mcp.json",
        "AGENTS.md",
        "CLAUDE.local.md",
        "CLAUDE.md",
        "src/auth/CLAUDE.md",
    ];

    /// Limits for the git commands the tests run to look at a copy.
    const LOOK: Limits = Limits {
        timeout: Duration::from_secs(30),
        stdout_cap: 64 * 1024,
        stderr_cap: 64 * 1024,
    };

    /// The fixture's SHAs, by the names `fixtures/README.md` gives them.
    struct Shas(BTreeMap<String, GitSha>);

    impl Shas {
        fn read() -> Self {
            Self(recorded_fixture_shas())
        }

        fn get(&self, name: &str) -> &str {
            self.0
                .get(name)
                .unwrap_or_else(|| panic!("the README records {name}"))
                .as_str()
        }
    }

    /// The bounty `run` would have checked, with `targets` chosen through
    /// `source`'s policy as `select` chooses them.
    fn checked(targets: Value, source: &impl TargetResolver) -> CheckedBounty {
        let mut value = bounty_json(targets);
        value["brief"] = json!(BRIEF);
        value["playbook"] = json!({ "suggested": SUGGESTED, "required": false });
        let bounty = Bounty::from_json(&json_bytes(&value)).expect("a bounty");
        let ChosenTargets { targets, warnings } =
            choose_targets(&bounty, None, source).expect("chosen");
        CheckedBounty {
            bounty_ref: BountyRef {
                owner: random_pubky(),
                id: bounty_id(),
            },
            bounty,
            acceptance: Acceptance::Open,
            targets,
            warnings,
        }
    }

    /// One target of each kind in the fixture repository: the repository at
    /// M narrowed to `src/auth/`, the merge commit M, the root commit R,
    /// and pull request 1 (base M, head F2, merge base B).
    fn fixture_bounty_targets(shas: &Shas) -> Value {
        let repo = fixture_repo().to_string();
        json!([
            { "id": "t1", "kind": "repo", "repo": repo, "rev": shas.get("M"), "paths": ["src/auth/"] },
            { "id": "t2", "kind": "commit", "repo": repo, "rev": shas.get("M") },
            { "id": "t3", "kind": "commit", "repo": repo, "rev": shas.get("R") },
            {
                "id": "t4", "kind": "pr", "repo": repo, "number": 1,
                "base": shas.get("M"), "head": shas.get("F2"), "mergeBase": shas.get("B"),
            },
        ])
    }

    /// A sweep of the fixture's four targets, fetched through the real
    /// runner. The fields are in drop order: the runner, whose private
    /// `HOME` lives under `home`, goes before `home`.
    struct Fetched {
        git: GitRunner,
        _home: TempDir,
        project: TempDir,
        sweep: SweepRef,
        checked: CheckedBounty,
        fetched: FetchedSweep,
        shas: Shas,
    }

    impl Fetched {
        async fn run() -> Self {
            let shas = Shas::read();
            let source = TargetSource::Fixture(fixture_targets());
            let home = private_temp();
            let git = source
                .git_runner(&dirs_in(&home), &test_git_env())
                .expect("a runner");
            let project = private_temp();
            let sweep = SweepRef {
                sweeper: random_pubky(),
                id: bounty_id(),
            };
            let checked = checked(fixture_bounty_targets(&shas), &source);
            let fetched = fetch_sweep(&git, &source, project.path(), sweep, &checked)
                .await
                .unwrap_or_else(|error| panic!("{error:#}"));
            Self {
                git,
                _home: home,
                project,
                sweep,
                checked,
                fetched,
                shas,
            }
        }

        fn sweep_dir(&self) -> PathBuf {
            self.project
                .path()
                .join("sweeps")
                .join(self.sweep.id.to_string())
        }

        fn target(&self, id: &str) -> PathBuf {
            self.sweep_dir().join("target").join(id)
        }

        fn scope(&self) -> Value {
            serde_json::from_slice(&fs::read(self.sweep_dir().join("scope.json")).expect("read"))
                .expect("JSON")
        }

        /// `git <subcommand> <flags> <operands>` in target `id`'s copy.
        async fn git_in(
            &self,
            id: &str,
            subcommand: LocalSubcommand,
            flags: &[&'static str],
            operands: &[&str],
        ) -> anyhow::Result<Vec<u8>> {
            let command = flags
                .iter()
                .fold(GitCommand::local(subcommand, LOOK), |command, flag| {
                    command.flag(flag)
                });
            let command = operands
                .iter()
                .fold(command, |command, operand| command.operand(*operand));
            self.git.run(&command.in_dir(self.target(id))).await
        }

        /// The commit `HEAD` names in target `id`'s copy.
        async fn head(&self, id: &str) -> String {
            let out = self
                .git_in(id, LocalSubcommand::RevParse, &[], &["HEAD"])
                .await
                .expect("rev-parse");
            String::from_utf8(out).expect("UTF-8").trim_end().to_owned()
        }

        /// Whether target `id`'s object store holds commit `name`.
        async fn has_commit(&self, id: &str, name: &str) -> bool {
            let commit = format!("{}^{{commit}}", self.shas.get(name));
            self.git_in(
                id,
                LocalSubcommand::RevParse,
                &["--verify", "--quiet"],
                &[&commit],
            )
            .await
            .is_ok()
        }

        /// The commits `.git/shallow` lists in target `id`'s copy, by name,
        /// or `None` when there is no such file.
        fn shallow(&self, id: &str) -> Option<BTreeSet<String>> {
            let text = fs::read_to_string(self.target(id).join(".git/shallow")).ok()?;
            Some(
                text.lines()
                    .map(|sha| {
                        self.shas
                            .0
                            .iter()
                            .find(|(_, known)| known.as_str() == sha)
                            .map_or_else(|| sha.to_owned(), |(name, _)| name.clone())
                    })
                    .collect(),
            )
        }
    }

    fn names(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|name| (*name).to_owned()).collect()
    }

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|text| (*text).to_owned()).collect()
    }

    #[tokio::test]
    async fn each_kind_is_checked_out_at_its_pinned_commit_and_scoped() {
        let run = Fetched::run().await;
        let shas = &run.shas;
        let (m, r, b, f2) = (shas.get("M"), shas.get("R"), shas.get("B"), shas.get("F2"));
        for (id, commit) in [("t1", m), ("t2", m), ("t3", r), ("t4", f2)] {
            assert_eq!(run.head(id).await, commit, "{id}");
        }
        let scope = run.scope();
        let targets = scope["targets"].as_array().expect("targets");
        let ids: Vec<&str> = targets
            .iter()
            .map(|target| target["id"].as_str().expect("an id"))
            .collect();
        assert_eq!(ids, ["t1", "t2", "t3", "t4"]);

        // The repository at M, narrowed to its paths, with no command.
        assert_eq!(targets[0]["kind"], "repo");
        assert_eq!(targets[0]["scope"]["paths"], json!(["src/auth/"]));
        assert_eq!(targets[0]["scope"].get("command"), None);
        // M is a merge, as its parents in the copy say: the diff against
        // its first parent, and the note that says so.
        assert_eq!(targets[1]["kind"], "commit");
        let first_parent = format!("{m}^1");
        assert_eq!(
            targets[1]["scope"]["command"],
            json!(["git", "diff-tree", "-p", first_parent, m])
        );
        assert!(
            targets[1]["scope"]["notes"][0]
                .as_str()
                .expect("a note")
                .contains("first parent"),
            "{}",
            targets[1]["scope"]
        );
        // R, the root, has no parent.
        assert_eq!(
            targets[2]["scope"]["command"],
            json!(["git", "diff-tree", "-p", "--root", r])
        );
        assert_eq!(targets[2]["scope"]["notes"], json!([]));
        // Pull request 1: the head checked out, the merge base there too,
        // and the diff from one to the other.
        assert_eq!(targets[3]["kind"], "pr");
        assert!(run.has_commit("t4", "B").await);
        assert_eq!(
            targets[3]["scope"]["command"],
            json!(["git", "diff", b, f2])
        );
        // What `fetch_sweep` hands back is what the file says.
        assert_eq!(run.fetched.dir, run.sweep_dir());
        assert_eq!(run.fetched.targets.len(), 4);
    }

    #[tokio::test]
    async fn each_fetch_is_shallow_and_from_the_base_remote_alone() {
        let run = Fetched::run().await;
        // A depth-2 fetch stops one generation past each commit asked for,
        // and git lists those boundary commits in `.git/shallow`: M's
        // parents B and T1; F2's parent F1 and, for the merge base B, A.
        // R has no parent, so its fetch holds the whole history and git
        // writes no such file.
        assert_eq!(run.shallow("t1"), Some(names(&["B", "T1"])));
        assert_eq!(run.shallow("t2"), Some(names(&["B", "T1"])));
        assert_eq!(run.shallow("t3"), None);
        assert_eq!(run.shallow("t4"), Some(names(&["A", "F1"])));
        // So the root is not in the repository target's object store.
        assert!(run.has_commit("t1", "M").await);
        assert!(!run.has_commit("t1", "R").await);
        assert!(!run.has_commit("t4", "R").await);
        for id in ["t1", "t2", "t3", "t4"] {
            // The URL was passed to `fetch` directly: no remote is
            // configured (`--get-regexp` exits 1 when nothing matches).
            let error = run
                .git_in(
                    id,
                    LocalSubcommand::Config,
                    &["--get-regexp"],
                    &["^remote\\."],
                )
                .await
                .expect_err("no remote");
            let failed = error.downcast_ref::<GitFailed>().expect("git ran");
            assert_eq!(failed.code(), Some(1), "{id}: {error:#}");
        }
    }

    #[test]
    fn the_fetch_plan_asks_only_the_base_remote_and_only_for_pinned_commits() {
        let shas = Shas::read();
        let sha = |name: &str| -> GitSha { shas.get(name).parse().expect("a SHA") };
        let id = |text: &str| -> TargetId { text.parse().expect("an id") };
        let repo: RepoName = "github.com/org/name".parse().expect("a repo");
        let pr = Target::pr(
            id("t1"),
            repo.clone(),
            std::num::NonZeroU64::MIN,
            sha("M"),
            sha("F2"),
            sha("B"),
        )
        .known()
        .expect("well formed")
        .expect("known");
        let plan = FetchPlan::of(&pr);
        let (f2, b) = (sha("F2"), sha("B"));
        // The base repository, never the fork; the head and the merge base,
        // never `base`; and the head is what is checked out.
        assert_eq!(
            plan,
            FetchPlan {
                kind: KnownTargetKind::Pr,
                repo: &repo,
                commits: vec![&f2, &b],
                checkout: &f2,
            }
        );
        // `git fetch` with that one URL, the options, and the two SHAs:
        // nothing else, so no other URL is ever contacted.
        let fixture = inert_target_repo();
        let remote = LocalRemote::for_tests(&fixture).expect("an absolute UTF-8 path");
        let argv = git_argv(
            &plan.fetch_command(Remote::Local(&remote)),
            AllowedProtocols::HttpsAndFile,
        )
        .expect("builds");
        let fetch_at = argv.iter().position(|arg| arg == "fetch").expect("a fetch");
        assert_eq!(
            argv[fetch_at..],
            strings(&[
                "fetch",
                remote.as_str(),
                "--depth=2",
                "--no-tags",
                "--no-recurse-submodules",
                "--quiet",
                f2.as_str(),
                b.as_str(),
            ])
        );

        // A commit or repo target fetches and checks out its one commit.
        for target in [
            Target::commit(id("t2"), repo.clone(), sha("R")),
            Target::repo(id("t3"), repo.clone(), sha("R"), Vec::new()),
        ] {
            let known = target.known().expect("well formed").expect("known");
            let plan = FetchPlan::of(&known);
            let r = sha("R");
            assert_eq!(plan.repo, &repo);
            assert_eq!(plan.commits, [&r]);
            assert_eq!(plan.checkout, &r);
        }
    }

    #[tokio::test]
    async fn every_planted_agent_file_is_stripped_and_listed() {
        let run = Fetched::run().await;
        let scope = run.scope();
        for (index, id) in ["t1", "t2", "t3", "t4"].into_iter().enumerate() {
            let target = run.target(id);
            // Each one is gone from the copy, and listed for its target.
            assert_eq!(
                scope["targets"][index]["stripped"],
                json!(PLANTED_AGENT_FILES),
                "{id}"
            );
            for relative in PLANTED_AGENT_FILES {
                assert!(
                    fs::symlink_metadata(target.join(relative)).is_err(),
                    "{id}: {relative} is still there"
                );
            }
            // The ordinary files are there, as git wrote them.
            for relative in [
                "README.md",
                "src/lib.rs",
                "src/http.rs",
                "src/auth/session.rs",
                "src/auth/handler.rs",
            ] {
                assert!(target.join(relative).is_file(), "{id}: {relative}");
            }
        }
    }

    #[tokio::test]
    async fn scope_json_and_the_brief_are_written_from_the_bounty() {
        let run = Fetched::run().await;
        let scope = run.scope();
        let dir = run.sweep_dir();
        let dir_text = |path: PathBuf| format!("{}/", path.to_str().expect("UTF-8"));
        assert_eq!(scope["schemaVersion"], 1);
        assert_eq!(scope["sweep"], run.sweep.to_string());
        assert_eq!(scope["bounty"], run.checked.bounty_ref.to_string());
        assert_eq!(scope["focus"], "security");
        assert_eq!(scope["suggestedPlaybook"], SUGGESTED);
        assert_eq!(scope["profile"], "standard");
        // The output directory is absolute, under the sweep, and new: run
        // names it and does not make it.
        let output = dir.join("audit");
        assert_eq!(scope["output"], dir_text(output.clone()));
        assert!(output.is_absolute());
        assert!(fs::symlink_metadata(&output).is_err(), "audit/ was made");
        // Each target's path is its directory, built from the sweep's and
        // the target's ids alone: t1's `src/auth/` is in its scope, not in
        // its path.
        for (index, id) in ["t1", "t2", "t3", "t4"].into_iter().enumerate() {
            assert_eq!(
                scope["targets"][index]["path"],
                dir_text(dir.join("target").join(id))
            );
        }
        // The brief, byte for byte.
        assert_eq!(
            fs::read(dir.join("brief.md")).expect("read"),
            BRIEF.as_bytes()
        );
        // The sweep directory is the sweeper's alone, and holds exactly
        // what run wrote.
        assert_eq!(mode(&dir), 0o700);
        let entries: BTreeSet<String> = fs::read_dir(&dir)
            .expect("list")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .into_string()
                    .expect("UTF-8")
            })
            .collect();
        assert_eq!(entries, names(&["brief.md", "scope.json", "target"]));
    }

    /// Runs `git <args>` in `dir` straight from the test, with no system or
    /// user config, as a repository's author would: the runner has no
    /// `commit`, which `run` never needs.
    fn author_git(dir: &Path, home: &Path, args: &[&str]) -> Vec<u8> {
        let output = Command::new("git")
            .args(args)
            .current_dir(dir)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").expect("PATH"))
            .env("HOME", home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("LC_ALL", "C")
            .output()
            .expect("git runs");
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    #[tokio::test]
    async fn a_link_in_a_target_is_checked_out_as_a_plain_file() {
        // A synthetic repository whose one commit holds three links: one to
        // a file outside it, and two named as agent files, one of them to a
        // directory.
        let author = private_temp();
        let repo_dir = author.path().join("links");
        fs::create_dir(&repo_dir).expect("mkdir");
        author_git(
            &repo_dir,
            author.path(),
            &["init", "--quiet", "--template="],
        );
        fs::write(repo_dir.join("README.md"), "ordinary\n").expect("write");
        symlink("/etc/hosts", repo_dir.join("pointer")).expect("symlink");
        symlink("README.md", repo_dir.join("CLAUDE.md")).expect("symlink");
        symlink("/", repo_dir.join(".claude")).expect("symlink");
        author_git(&repo_dir, author.path(), &["add", "--all"]);
        author_git(
            &repo_dir,
            author.path(),
            &[
                "-c",
                "user.name=Sweepky Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--quiet",
                "--message=links",
            ],
        );
        let head = author_git(&repo_dir, author.path(), &["rev-parse", "HEAD"]);
        let head = String::from_utf8(head)
            .expect("UTF-8")
            .trim_end()
            .to_owned();

        let name: RepoName = "example.invalid/sweepky/links".parse().expect("a repo");
        let source = TargetSource::Fixture(FixtureTargets::new([(name.clone(), repo_dir)]));
        let home = private_temp();
        let git = source
            .git_runner(&dirs_in(&home), &test_git_env())
            .expect("a runner");
        let project = private_temp();
        let sweep = SweepRef {
            sweeper: random_pubky(),
            id: bounty_id(),
        };
        let checked = checked(
            json!([{ "id": "t1", "kind": "repo", "repo": name.to_string(), "rev": head }]),
            &source,
        );
        let fetched = fetch_sweep(&git, &source, project.path(), sweep, &checked)
            .await
            .unwrap_or_else(|error| panic!("{error:#}"));

        let target = fetched.dir.join("target").join("t1");
        // The link outside is a plain file that holds the link's text, so
        // reading it reads nothing outside the copy.
        let pointer = fs::symlink_metadata(target.join("pointer")).expect("there");
        assert!(pointer.is_file(), "{pointer:?}");
        assert_eq!(
            fs::read_to_string(target.join("pointer")).expect("read"),
            "/etc/hosts"
        );
        // The two named as agent files were plain files too, and are gone.
        assert_eq!(
            fetched.targets[0].stripped,
            strings(&[".claude", "CLAUDE.md"])
        );
        assert!(target.join("README.md").is_file());
        // The copy's own config keeps links as plain files for a checkout
        // the agent runs there later.
        let config = GitCommand::local(LocalSubcommand::Config, LOOK)
            .flag("--get")
            .operand("core.symlinks")
            .in_dir(&target);
        assert_eq!(git.run(&config).await.expect("set"), b"false\n");
    }

    #[tokio::test]
    async fn an_unserved_sha_fails_and_removes_the_half_made_sweep_alone() {
        let shas = Shas::read();
        let source = TargetSource::Fixture(fixture_targets());
        let home = private_temp();
        let git = source
            .git_runner(&dirs_in(&home), &test_git_env())
            .expect("a runner");
        let project = private_temp();
        // Another sweep's directory, which nothing may touch.
        let other = project.path().join("sweeps").join("0035G87EK4XFF");
        fs::create_dir_all(&other).expect("mkdir");
        fs::write(other.join("keep.txt"), "another sweep").expect("write");
        let sweep = SweepRef {
            sweeper: random_pubky(),
            id: bounty_id(),
        };
        // t1 fetches; t2's commit, a synthetic SHA, the repository never
        // had: the sweep directory holds a whole target when it fails.
        let repo = fixture_repo().to_string();
        let checked = checked(
            json!([
                { "id": "t1", "kind": "repo", "repo": repo, "rev": shas.get("M") },
                { "id": "t2", "kind": "commit", "repo": repo, "rev": SYNTHETIC_SHA },
            ]),
            &source,
        );
        let error = fetch_sweep(&git, &source, project.path(), sweep, &checked)
            .await
            .expect_err("not served");
        let message = format!("{error:#}");
        assert!(message.contains("target t2"), "{message}");
        assert!(
            message.contains(&format!(
                "the pinned commit {SYNTHETIC_SHA} is no longer served"
            )),
            "{message}"
        );
        // Nothing git wrote reaches the message.
        assert!(!message.contains("our ref"), "{message}");
        assert!(!message.contains("upload-pack"), "{message}");
        // The half-made sweep is gone; the other one is as it was.
        let sweeps = project.path().join("sweeps");
        assert!(fs::symlink_metadata(sweeps.join(sweep.id.to_string())).is_err());
        let left: Vec<String> = fs::read_dir(&sweeps)
            .expect("list")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .into_string()
                    .expect("UTF-8")
            })
            .collect();
        assert_eq!(left, ["0035G87EK4XFF"]);
        assert_eq!(
            fs::read_to_string(other.join("keep.txt")).expect("read"),
            "another sweep"
        );
    }

    #[tokio::test]
    async fn a_linked_or_foreign_sweeps_or_an_existing_sweep_is_refused_before_git_runs() {
        let source = TargetSource::Fixture(fixture_targets());
        let checked = checked(
            json!([{ "id": "t1", "kind": "commit", "repo": fixture_repo().to_string(), "rev": SYNTHETIC_SHA }]),
            &source,
        );
        let sweep = SweepRef {
            sweeper: random_pubky(),
            id: bounty_id(),
        };
        let elsewhere = private_temp();
        // What the refusal says, and a closure that lays the project out.
        // `&dyn Fn` lets four different closures share one array type.
        type Arrange<'a> = &'a dyn Fn(&Path);
        let cases: [(&str, Arrange<'_>); 4] = [
            ("symbolic link", &|project: &Path| {
                symlink(elsewhere.path(), project.join("sweeps")).expect("symlink");
            }),
            ("not a directory", &|project: &Path| {
                fs::write(project.join("sweeps"), PLANTED).expect("write");
            }),
            ("already there", &|project: &Path| {
                let dir = project.join("sweeps").join(sweep.id.to_string());
                fs::create_dir_all(&dir).expect("mkdir");
                fs::write(dir.join("keep.txt"), PLANTED).expect("write");
            }),
            ("already there", &|project: &Path| {
                fs::create_dir(project.join("sweeps")).expect("mkdir");
                symlink(
                    elsewhere.path().join("nowhere"),
                    project.join("sweeps").join(sweep.id.to_string()),
                )
                .expect("symlink");
            }),
        ];
        for (expected, arrange) in cases {
            let project = private_temp();
            arrange(project.path());
            let message = format!(
                "{:#}",
                check_sweep_dir(project.path(), sweep.id).expect_err(expected)
            );
            assert!(message.contains(expected), "{message}");
            // The fetch refuses the same way, before any git runs.
            let git = RecordingGit::succeeding(AllowedProtocols::HttpsAndFile, b"");
            let error = fetch_sweep(&git, &source, project.path(), sweep, &checked)
                .await
                .expect_err(expected);
            assert!(format!("{error:#}").contains(expected), "{error:#}");
            assert_eq!(git.argv(), Vec::<Vec<String>>::new());
        }
        // Nothing was made through the link, and what was there stays.
        assert_eq!(fs::read_dir(elsewhere.path()).expect("list").count(), 0);
        // A project with no `sweeps/` yet, or a real one, passes.
        let project = private_temp();
        check_sweep_dir(project.path(), sweep.id).expect("no sweeps/ yet");
        fs::create_dir(project.path().join("sweeps")).expect("mkdir");
        check_sweep_dir(project.path(), sweep.id).expect("a real sweeps/");
    }

    #[test]
    fn sweep_paths_are_built_from_the_ids_alone() {
        let project = Path::new("/abs/project");
        let paths = SweepPaths::new(project, bounty_id()).expect("paths");
        let root = Path::new("/abs/project/sweeps/0035G87EK4XFE");
        let id: TargetId = "t1".parse().expect("an id");
        assert_eq!(paths.target(&id), root.join("target/t1"));
        assert_eq!(paths.audit(), root.join("audit"));
        // A relative project, or one whose path is not UTF-8, is refused:
        // scope.json names every path under it as text.
        assert!(SweepPaths::new(Path::new("project"), bounty_id()).is_err());
        let not_utf8 = Path::new(OsStr::from_bytes(b"/abs/caf\xe9"));
        assert!(SweepPaths::new(not_utf8, bounty_id()).is_err());
    }

    #[test]
    fn rev_list_s_line_gives_the_parent_count_or_an_unquoted_refusal() {
        let shas = Shas::read();
        let (m, b, t1) = (shas.get("M"), shas.get("B"), shas.get("T1"));
        let commit: GitSha = m.parse().expect("a SHA");
        for (line, parents) in [
            (format!("{m}\n"), 0),
            (format!("{m} {b}\n"), 1),
            (format!("{m} {b} {t1}\n"), 2),
        ] {
            assert_eq!(
                parent_count(line.as_bytes(), &commit).expect(&line),
                parents
            );
        }
        let upper = b.to_ascii_uppercase();
        let refused: Vec<Vec<u8>> = vec![
            Vec::new(),
            m.as_bytes().to_vec(),
            format!("{b} {m}\n").into(),
            format!("{m} {PLANTED}\n").into(),
            format!("{m} {b} \n").into(),
            format!("{m}\t{b}\n").into(),
            format!("{m} {upper}\n").into(),
            format!("{m} {b}\n{m}\n").into(),
            [m.as_bytes(), b" \xff\n"].concat(),
        ];
        for output in refused {
            let message = format!("{:#}", parent_count(&output, &commit).expect_err("refused"));
            assert_eq!(message, NOT_PARENTS_LINE);
        }
    }
}
