//! `run`'s fetching half: each chosen target fetched by its exact SHA, its
//! agent-instruction files stripped, and `scope.json` and `brief.md`
//! written beside them, all in a sweep directory built under the data
//! directory and only then put in the project as `./sweeps/<id>/`.
//!
//! - [`SweepPaths`]: every path of one sweep in the project, built from the
//!   project's own path, the sweep's `RecordId` and each `TargetId`, which
//!   core holds to a single path segment of ASCII letters, digits, `-` and
//!   `_`. Nothing a repository or a record wrote as text, a `RepoPath`
//!   above all, is ever joined onto them; a target's paths go into
//!   `scope.json` as data.
//! - [`check_sweep_dir`]: the check `run` makes before it publishes
//!   anything: `sweeps/` must be a real directory or absent, never a link,
//!   and `sweeps/<id>/` must not exist.
//! - [`fetch_sweep`]: the fetch itself, which makes the same check again
//!   before git runs and then builds the whole sweep directory in a new
//!   staging directory of its own, `<data dir>/staging/<id>/`, removed
//!   again with all it holds whatever happens. [`StagedSweep::place`] puts
//!   the finished directory in the project (`place`). Flipping the public
//!   record to `aborted` when a step fails is the run command's job, not
//!   this module's.
//!
//! **Why stage, and not fetch into the project.** The project is the
//! agent's to write, and a process an earlier, prompt-injected agent
//! session left running there may still be at work (02). git reads a
//! repository's own `.git/config` and `.git/info/attributes` whatever the
//! runner's `-c` settings say, so a filter planted there would run as the
//! user, outside the sandbox, at `git checkout`; and a directory on the way
//! swapped for a link would send git, the strip's removals and the file
//! writes wherever the link points. Under the data directory, which the
//! sandbox keeps the agent from, git's working directory and its `.git`,
//! the strip and every write are out of that process's reach, and the
//! project gets the sweep only once it is whole, through handles that
//! follow no link.
//!
//! **The git steps for one target**, every one through the hardened runner
//! (`crate::git`: argv only, no config or credentials of the user's, hooks,
//! submodules, LFS and symlinks off), in the target's own new directory
//! under the staging directory:
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
use super::place::{already_there, place_sweep};
use super::scope_file::{ScopeTarget, scope_json, write_new_file};
use super::select::ChosenTarget;
use super::strip::strip_agent_files;
use crate::Dirs;
use crate::git::{GitCommand, GitFailed, Limits, LocalSubcommand, Remote, RunGit, STDERR_CAP};
use crate::private_fs::{ensure_private_dir, lstat, refuse_unless_dir};
use crate::targets::{TargetRemote, TargetResolver};

/// The directory of a sweep directory that holds one directory per target.
const TARGETS: &str = "target";

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
/// nothing; [`fetch_sweep`] checks again before git runs, and
/// [`StagedSweep::place`] once more, through handles, as it places.
pub(crate) fn check_sweep_dir(project: &Path, id: RecordId) -> anyhow::Result<()> {
    SweepPaths::new(project, id)?.check_free()
}

/// What [`StagedSweep::place`] put in `<project>/sweeps/<id>/`: each
/// target as `scope.json` lists it.
#[derive(Debug)]
pub(crate) struct FetchedSweep {
    /// In the bounty's order. The `stripped` names are the repository's,
    /// so anything that prints one sanitises it first.
    pub(crate) targets: Vec<ScopeTarget>,
}

/// Fetches every target of `checked` for `sweep` through `git` and
/// `source`, strips each, and writes `scope.json` and `brief.md`, all in a
/// new staging directory under `dirs`' data directory. Nothing is written
/// in the project at `project` yet, whose paths `scope.json` names:
/// [`StagedSweep::place`] puts the sweep there. The staging directory is
/// removed again on any failure here, and once the sweep is placed.
pub(crate) async fn fetch_sweep(
    git: &impl RunGit,
    source: &impl TargetResolver,
    dirs: &Dirs,
    project: &Path,
    sweep: SweepRef,
    checked: &CheckedBounty,
) -> anyhow::Result<StagedSweep> {
    let paths = SweepPaths::new(project, sweep.id)?;
    paths.check_free()?;
    let staging = Staging::create(dirs, sweep.id)?;
    let staged_targets = staging.dir.join(TARGETS);
    fs::create_dir(&staged_targets)
        .with_context(|| format!("could not create {}", staged_targets.display()))?;
    let mut targets = Vec::with_capacity(checked.targets.len());
    for chosen in &checked.targets {
        let target = fetch_target(git, source, &paths, &staged_targets, chosen)
            .await
            .with_context(|| format!("could not fetch target {}", chosen.id))?;
        targets.push(target);
    }
    let output = dir_text(&paths.audit())?;
    let scope = scope_json(sweep, checked, &output, &targets)?;
    write_new_file(&staging.dir.join("scope.json"), &scope)?;
    // The brief as the owner wrote it, byte for byte: the agent reads it as
    // a file, and nothing here prints it.
    write_new_file(
        &staging.dir.join("brief.md"),
        checked.bounty.brief.as_bytes(),
    )?;
    Ok(StagedSweep {
        paths,
        staging,
        targets,
    })
}

/// Fetches `chosen` into its own new directory in `staged_targets`, the
/// staging directory's `target/`, checks it out, strips it, and describes
/// it for `scope.json` by the path it will have in the project, from
/// `paths`.
async fn fetch_target(
    git: &impl RunGit,
    source: &impl TargetResolver,
    paths: &SweepPaths,
    staged_targets: &Path,
    chosen: &ChosenTarget,
) -> anyhow::Result<ScopeTarget> {
    let plan = FetchPlan::of(&chosen.target);
    let remote = source.fetch_remote(plan.kind, plan.repo).await?;
    let dir = staged_targets.join(chosen.id.as_str());
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
        path: dir_text(&paths.target(&chosen.id))?,
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

/// A sweep [`fetch_sweep`] built and has not yet put in the project: its
/// paths there, its staging directory, and each target as `scope.json`
/// lists it.
#[derive(Debug)]
pub(crate) struct StagedSweep {
    paths: SweepPaths,
    staging: Staging,
    targets: Vec<ScopeTarget>,
}

impl StagedSweep {
    /// The staged sweep directory, `<data dir>/staging/<id>`, where the run
    /// command writes the per-sweep marker, last, before it places the
    /// sweep. The data directory is out of the agent's reach, so a path
    /// there is safe to write by.
    pub(crate) fn dir(&self) -> &Path {
        &self.staging.dir
    }

    /// Puts the staged sweep in the project as `<project>/sweeps/<id>/`,
    /// through directory handles that follow no link (`place`), and hands
    /// back what it made. Refused, with nothing written through it, when
    /// `sweeps` is a link or not a directory, or when anything at all is at
    /// `sweeps/<id>`.
    ///
    /// Takes `self` by value: once this returns, placed or refused, the
    /// rest of `self` is dropped, and the staging directory with it.
    pub(crate) fn place(self) -> anyhow::Result<FetchedSweep> {
        place_sweep(&self.staging.parent, &self.paths.project, self.paths.id)?;
        // Moving a field out of `self` is allowed because `StagedSweep`
        // itself has no `Drop`; `self.staging`, left behind, is dropped as
        // the function returns.
        Ok(FetchedSweep {
            targets: self.targets,
        })
    }
}

/// The staging directory of one sweep, `<data dir>/staging/<id>/`: made new
/// and 0700, and removed with all it holds when this is dropped, whether
/// the sweep was placed (moved away, so nothing is left, or copied, so the
/// original goes), a step failed or returned early with `?`, or the
/// command was cancelled.
#[derive(Debug)]
struct Staging {
    /// `<data dir>/staging`, which the sweep is placed from.
    parent: PathBuf,
    /// `<data dir>/staging/<id>`.
    dir: PathBuf,
}

impl Staging {
    /// Makes the staging directory of sweep `id` under `dirs`' data
    /// directory, and `staging/` itself if need be, both 0700.
    fn create(dirs: &Dirs, id: RecordId) -> anyhow::Result<Self> {
        let parent = dirs.staging_dir();
        // Made 0700 with any missing parents, or checked to be a real 0700
        // directory when it is there already.
        ensure_private_dir(&parent)?;
        let dir = parent.join(id.to_string());
        // Not `recursive`: the `mkdir` fails if anything at all is there, a
        // link included, so the directory is this run's alone. 0700, so no
        // other user of the machine reads the checkout, and, once placed,
        // the audit the agent writes before `submit` encrypts it.
        DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .with_context(|| format!("could not create {}", dir.display()))?;
        Ok(Self { parent, dir })
    }
}

/// Best effort: `drop` cannot return an error. The directory is under the
/// data directory, which the agent cannot reach, and std's `remove_dir_all`
/// never follows a link inside it. A process killed outright (`kill -9`)
/// runs no `drop`, and leaves the directory behind.
impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Every path of one sweep in the project: `<project>/sweeps/<id>/` and
/// what `run` puts in it.
///
/// Built from the project's own path, the sweep's id and each target's id
/// alone. The project's path is checked to be absolute and UTF-8 when this
/// is made, so `scope.json` can name every path under it as text.
#[derive(Debug)]
struct SweepPaths {
    /// The project's own directory.
    project: PathBuf,
    /// The sweep's id, its directory's name.
    id: RecordId,
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
        Ok(Self {
            project: project.to_path_buf(),
            id,
            sweeps,
            root,
        })
    }

    /// `<project>/sweeps/<id>/target/<tid>`.
    fn target(&self, id: &TargetId) -> PathBuf {
        self.root.join(TARGETS).join(id.as_str())
    }

    /// `<project>/sweeps/<id>/audit`, the playbook's output directory, which
    /// `run` names in `scope.json` and does not make.
    fn audit(&self) -> PathBuf {
        self.root.join("audit")
    }

    /// Refuses a `sweeps` that is a link or anything but a directory, and a
    /// sweep directory that is already there. Looks only, with `lstat`, so
    /// no link is followed; creates nothing. An early, friendly refusal:
    /// the placement checks again, through handles.
    fn check_free(&self) -> anyhow::Result<()> {
        if let Some(seen) = lstat(&self.sweeps)? {
            refuse_unless_dir(&self.sweeps, &seen)?;
        }
        if lstat(&self.root)?.is_some() {
            bail!(already_there(&self.root.display().to_string()));
        }
        Ok(())
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
    use std::sync::{Mutex, Once};
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
    use crate::Dirs;
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

    /// [`fetch_sweep`], then the placement: the sweep as the run command
    /// makes it, the marker aside.
    async fn fetch_and_place(
        git: &impl RunGit,
        source: &impl TargetResolver,
        dirs: &Dirs,
        project: &Path,
        sweep: SweepRef,
        checked: &CheckedBounty,
    ) -> anyhow::Result<FetchedSweep> {
        fetch_sweep(git, source, dirs, project, sweep, checked)
            .await?
            .place()
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
            let dirs = dirs_in(&home);
            let git = source.git_runner(&dirs, &test_git_env()).expect("a runner");
            let project = private_temp();
            let sweep = SweepRef {
                sweeper: random_pubky(),
                id: bounty_id(),
            };
            let checked = checked(fixture_bounty_targets(&shas), &source);
            let fetched = fetch_and_place(&git, &source, &dirs, project.path(), sweep, &checked)
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
        // What the placement hands back is what the file says.
        assert_eq!(run.fetched.targets.len(), 4);
        for (fetched, listed) in run.fetched.targets.iter().zip(targets) {
            assert_eq!(listed["path"], fetched.path.as_str());
        }
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
        let dirs = dirs_in(&home);
        let git = source.git_runner(&dirs, &test_git_env()).expect("a runner");
        let project = private_temp();
        let sweep = SweepRef {
            sweeper: random_pubky(),
            id: bounty_id(),
        };
        let checked = checked(
            json!([{ "id": "t1", "kind": "repo", "repo": name.to_string(), "rev": head }]),
            &source,
        );
        let fetched = fetch_and_place(&git, &source, &dirs, project.path(), sweep, &checked)
            .await
            .unwrap_or_else(|error| panic!("{error:#}"));

        let target = project
            .path()
            .join("sweeps")
            .join(sweep.id.to_string())
            .join("target/t1");
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
        let dirs = dirs_in(&home);
        let git = source.git_runner(&dirs, &test_git_env()).expect("a runner");
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
        let error = fetch_and_place(&git, &source, &dirs, project.path(), sweep, &checked)
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
        // The half-made sweep is gone from the staging directory and was
        // never in the project; the other one is as it was.
        let staged = dirs.staging_dir().join(sweep.id.to_string());
        assert!(fs::symlink_metadata(staged).is_err());
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
        let home = private_temp();
        let dirs = dirs_in(&home);
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
            let error = fetch_sweep(&git, &source, &dirs, project.path(), sweep, &checked)
                .await
                .expect_err(expected);
            assert!(format!("{error:#}").contains(expected), "{error:#}");
            assert_eq!(git.argv(), Vec::<Vec<String>>::new());
            // Refused before anything was staged, too.
            assert!(fs::symlink_metadata(dirs.staging_dir()).is_err());
        }
        // Nothing was made through the link, and what was there stays.
        assert_eq!(fs::read_dir(elsewhere.path()).expect("list").count(), 0);
        // A project with no `sweeps/` yet, or a real one, passes.
        let project = private_temp();
        check_sweep_dir(project.path(), sweep.id).expect("no sweeps/ yet");
        fs::create_dir(project.path().join("sweeps")).expect("mkdir");
        check_sweep_dir(project.path(), sweep.id).expect("a real sweeps/");
    }

    /// A runner that hands every command to `inner`, noting the directory
    /// each one runs in, and calls `plant` once, before the first: what a
    /// process the agent left running in the project could do while `run`
    /// fetches.
    struct Planting<'a, G> {
        inner: G,
        plant: &'a dyn Fn(),
        planted: Once,
        dirs: Mutex<Vec<PathBuf>>,
    }

    impl<'a, G> Planting<'a, G> {
        fn new(inner: G, plant: &'a dyn Fn()) -> Self {
            Self {
                inner,
                plant,
                planted: Once::new(),
                dirs: Mutex::default(),
            }
        }

        fn dirs(&self) -> Vec<PathBuf> {
            self.dirs.lock().expect("lock").clone()
        }
    }

    impl<G: RunGit> RunGit for Planting<'_, G> {
        async fn run(&self, command: &GitCommand) -> anyhow::Result<Vec<u8>> {
            self.planted.call_once(|| (self.plant)());
            let dir = command.dir().expect("run gives every command a directory");
            self.dirs.lock().expect("lock").push(dir.to_path_buf());
            self.inner.run(command).await
        }
    }

    #[tokio::test]
    async fn git_runs_only_under_the_data_directory_never_in_the_project() {
        let shas = Shas::read();
        let source = TargetSource::Fixture(fixture_targets());
        let home = private_temp();
        let dirs = dirs_in(&home);
        let git = Planting::new(
            source.git_runner(&dirs, &test_git_env()).expect("a runner"),
            &|| {},
        );
        let project = private_temp();
        let sweep = SweepRef {
            sweeper: random_pubky(),
            id: bounty_id(),
        };
        let checked = checked(fixture_bounty_targets(&shas), &source);

        fetch_and_place(&git, &source, &dirs, project.path(), sweep, &checked)
            .await
            .unwrap_or_else(|error| panic!("{error:#}"));

        // init, config, fetch and checkout for each of the four targets,
        // and rev-list for the two commits: each in a directory under the
        // data directory, none in the project the agent can write.
        let ran_in = git.dirs();
        assert_eq!(ran_in.len(), 4 * 4 + 2, "{ran_in:?}");
        for dir in &ran_in {
            assert!(dir.starts_with(dirs.data()), "{}", dir.display());
            assert!(!dir.starts_with(project.path()), "{}", dir.display());
        }
    }

    #[tokio::test]
    async fn a_git_config_planted_in_the_project_during_the_fetch_is_never_read() {
        let shas = Shas::read();
        let source = TargetSource::Fixture(fixture_targets());
        let home = private_temp();
        let dirs = dirs_in(&home);
        let project = private_temp();
        let outside = private_temp();
        let sweep = SweepRef {
            sweeper: random_pubky(),
            id: bounty_id(),
        };
        // While git runs, a filter is planted where the target's `.git`
        // goes in the project: were git to read that repository's own
        // config and attributes, its checkout would run the command.
        let canary = outside.path().join("canary");
        let planted = project
            .path()
            .join("sweeps")
            .join(sweep.id.to_string())
            .join("target/t1/.git");
        let config = format!(
            "[filter \"probe\"]\n\tsmudge = touch {}\n",
            canary.display()
        );
        let plant = || {
            fs::create_dir_all(planted.join("info")).expect("mkdir");
            fs::write(planted.join("config"), &config).expect("write");
            fs::write(planted.join("info/attributes"), "* filter=probe\n").expect("write");
        };
        let git = Planting::new(
            source.git_runner(&dirs, &test_git_env()).expect("a runner"),
            &plant,
        );
        let repo = fixture_repo().to_string();
        let checked = checked(
            json!([{ "id": "t1", "kind": "repo", "repo": repo, "rev": shas.get("M") }]),
            &source,
        );

        let error = fetch_and_place(&git, &source, &dirs, project.path(), sweep, &checked)
            .await
            .expect_err("refused");

        // The filter never ran, and the sweep was not put where something
        // already was: the planted files are as they were.
        assert!(fs::symlink_metadata(&canary).is_err(), "git ran the filter");
        let message = format!("{error:#}");
        assert!(message.contains("already there"), "{message}");
        assert_eq!(
            fs::read_to_string(planted.join("config")).expect("read"),
            config
        );
        assert_eq!(
            fs::read_to_string(planted.join("info/attributes")).expect("read"),
            "* filter=probe\n"
        );
    }

    #[tokio::test]
    async fn a_link_swapped_in_during_the_fetch_is_refused_and_nothing_is_written_through_it() {
        let source = TargetSource::Fixture(fixture_targets());
        let repo = fixture_repo().to_string();
        let checked = checked(
            json!([{ "id": "t1", "kind": "repo", "repo": repo, "rev": SYNTHETIC_SHA }]),
            &source,
        );
        let sweep = SweepRef {
            sweeper: random_pubky(),
            id: bounty_id(),
        };
        let elsewhere = private_temp();
        let sweep_dir = |project: &Path| project.join("sweeps").join(sweep.id.to_string());
        // What the refusal says, and what a process left in the project
        // does once git has started: `sweeps`, the sweep directory or its
        // `target` made a link to a directory elsewhere. The checks before
        // git saw a project with none of them.
        type Plant<'a> = &'a dyn Fn(&Path);
        let cases: [(&str, Plant<'_>); 3] = [
            ("symbolic link", &|project: &Path| {
                symlink(elsewhere.path(), project.join("sweeps")).expect("symlink");
            }),
            ("already there", &|project: &Path| {
                fs::create_dir(project.join("sweeps")).expect("mkdir");
                symlink(elsewhere.path(), sweep_dir(project)).expect("symlink");
            }),
            ("already there", &|project: &Path| {
                fs::create_dir_all(sweep_dir(project)).expect("mkdir");
                symlink(elsewhere.path(), sweep_dir(project).join("target")).expect("symlink");
            }),
        ];
        for (expected, plant) in cases {
            let home = private_temp();
            let dirs = dirs_in(&home);
            let project = private_temp();
            let plant_here = || plant(project.path());
            // git itself is a fake here, which succeeds and writes nothing:
            // the placement is what is tested.
            let git = Planting::new(
                RecordingGit::succeeding(AllowedProtocols::HttpsAndFile, b""),
                &plant_here,
            );

            let error = fetch_and_place(&git, &source, &dirs, project.path(), sweep, &checked)
                .await
                .expect_err(expected);

            let message = format!("{error:#}");
            assert!(message.contains(expected), "{message}");
            assert!(!git.dirs().is_empty(), "git ran");
            // The staged sweep is gone with its guard.
            let staged = dirs.staging_dir().join(sweep.id.to_string());
            assert!(fs::symlink_metadata(staged).is_err(), "{expected}");
        }
        // Nothing was written through any of the links.
        assert_eq!(fs::read_dir(elsewhere.path()).expect("list").count(), 0);
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
