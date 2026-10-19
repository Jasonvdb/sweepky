//! Where `post` and `run` get a target's repository from, and the network
//! policy for it.
//!
//! - [`TargetResolver`], the seam both commands use: it resolves a
//!   revision to a full SHA, peeling annotated tags; gives a pull request's
//!   base, head and merge base; names the remote `run` fetches from; and
//!   applies the target policy. Its methods take the [`RunGit`] to run git
//!   with, so a test can record what git was asked.
//! - [`TargetSource`], what the [`Context`](crate::Context) holds: the real
//!   source in the binary, the fixture source in the tests.
//! - `real`, the real source: repositories on the internet, over https
//!   only, each host checked by the host policy before git contacts it,
//!   with pull requests read from GitHub's API.
//! - `github`, GitHub's unauthenticated REST API: the pull request target
//!   policy (`github.com/<owner>/<name>`), the `GitHubApi` seam the
//!   requests go through, and the parsers of its two answers.
//! - `fixture`, the fixture source: the bare repository under `fixtures/`,
//!   over the `file` transport, for the tests alone.
//! - `rev`, a checked revision and the ls-remote pinning both sources
//!   share, with its one fixed refusal for a repository that is not
//!   anonymously readable.
//! - `host`, the policy for a target's host: the pure address classifier,
//!   the `ResolveHost` seam a lookup goes through, and `HttpsRemote`, the
//!   one form a real target's repository reaches git in, which exists only
//!   for a host whose every address is public.

pub(crate) mod fixture;
pub(crate) mod github;
pub(crate) mod host;
pub(crate) mod real;
pub(crate) mod rev;

use std::num::NonZeroU64;

use sweepky_core::{GitSha, KnownTargetKind, RepoName};

use self::fixture::{FixtureTargets, LocalRemote};
use self::github::GitHubApi;
use self::host::{HttpsRemote, SystemResolver};
use self::real::RealTargets;
use self::rev::RevSpec;
use crate::Dirs;
use crate::git::{AllowedProtocols, GitEnv, GitRunner, RunGit};

/// Where `post` and `run` get targets' repositories from: the seam between
/// those commands and the repository hosts.
///
/// A trait so that the tests can serve targets from the fixture repository
/// and record every git run. As with `git::RunGit`, the methods are
/// `async fn`s, so the trait cannot be a `dyn TargetResolver` (each
/// implementation's futures are a different type, which a `dyn` call could
/// not name); [`TargetSource`] is the enum that picks one at run time
/// instead.
///
/// Every error is fixed text that names neither the repository nor the
/// revision: the caller says which target it was, by its id.
pub(crate) trait TargetResolver {
    /// The transports a git runner for this source must allow:
    /// [`AllowedProtocols::Https`] for the real source, `file` as well for
    /// the fixture source.
    fn protocols(&self) -> AllowedProtocols;

    /// A git runner for one command, under `dirs`' data directory and with
    /// `env`, allowed this source's [`protocols`](Self::protocols) and no
    /// others: the one `post` and `run` hand back to this source's methods.
    fn git_runner(&self, dirs: &Dirs, env: &GitEnv) -> anyhow::Result<GitRunner> {
        GitRunner::new(dirs, env, self.protocols())
    }

    /// Refuses a target of `kind` in `repo` that this source does not
    /// serve. No network: `post` and `run` call it before anything else.
    /// The real source takes a pull request on `github.com` only; the
    /// fixture source takes only the names it maps, of any kind.
    fn check_policy(&self, kind: KnownTargetKind, repo: &RepoName) -> anyhow::Result<()>;

    /// The full SHA `rev` names in `repo`, through `git`: an annotated tag
    /// peeled to the commit it names, and a full SHA as given once the
    /// repository is shown to be readable.
    async fn resolve_rev(
        &self,
        git: &impl RunGit,
        repo: &RepoName,
        rev: &RevSpec,
    ) -> anyhow::Result<GitSha>;

    /// Pull request `number` of `repo`: its base, head and merge base. It
    /// applies [`check_policy`](Self::check_policy) first. The real source
    /// reads them through `github` (the caller passes the SDK's HTTP client,
    /// `ctx.network.pubky().client()`) and checks the head with `git`; the
    /// fixture source never asks `github` anything.
    async fn pull_request(
        &self,
        git: &impl RunGit,
        github: &impl GitHubApi,
        repo: &RepoName,
        number: NonZeroU64,
    ) -> anyhow::Result<PullRequest>;

    /// The remote `run` fetches a target of `kind` in `repo` from. It
    /// applies [`check_policy`](Self::check_policy) first, and the real
    /// source checks the host's addresses before it names an
    /// [`HttpsRemote`].
    // `run`, later in P2b, is the first caller outside the tests, and
    // removes this line. `allow`, not the crate's usual `expect`, because
    // an `expect` here is never met: it marks the method as used, and then
    // `TargetSource`'s own `fetch_remote`, which calls the two sources'
    // ones, really is a use of it. `TargetRemote`, which only this method
    // makes, needs nothing of its own for the same reason.
    #[cfg_attr(not(test), allow(dead_code))]
    async fn fetch_remote(
        &self,
        kind: KnownTargetKind,
        repo: &RepoName,
    ) -> anyhow::Result<TargetRemote>;
}

/// Which `TargetResolver` (a trait private to this crate, so not a link
/// here) a command uses: what the [`Context`](crate::Context) holds.
///
/// An enum rather than a `Box<dyn TargetResolver>`, which an async trait
/// cannot be: each variant is one source, and the enum is a
/// `TargetResolver` itself by passing each call on with a `match`.
pub enum TargetSource {
    /// Real repositories, over https only, each host checked by the system
    /// resolver before git contacts it. The one `main.rs` builds.
    Real,
    /// The fixture source, which allows git's `file` transport; for the
    /// tests alone (see [`FixtureTargets`]).
    #[doc(hidden)]
    Fixture(FixtureTargets),
}

/// The real source as [`TargetSource::Real`] stands for it: the system
/// resolver. A unit struct each, so making it costs nothing.
fn system_targets() -> RealTargets<SystemResolver> {
    RealTargets::new(SystemResolver)
}

impl TargetResolver for TargetSource {
    fn protocols(&self) -> AllowedProtocols {
        match self {
            Self::Real => system_targets().protocols(),
            Self::Fixture(fixture) => fixture.protocols(),
        }
    }

    fn check_policy(&self, kind: KnownTargetKind, repo: &RepoName) -> anyhow::Result<()> {
        match self {
            Self::Real => system_targets().check_policy(kind, repo),
            Self::Fixture(fixture) => fixture.check_policy(kind, repo),
        }
    }

    async fn resolve_rev(
        &self,
        git: &impl RunGit,
        repo: &RepoName,
        rev: &RevSpec,
    ) -> anyhow::Result<GitSha> {
        match self {
            Self::Real => system_targets().resolve_rev(git, repo, rev).await,
            Self::Fixture(fixture) => fixture.resolve_rev(git, repo, rev).await,
        }
    }

    async fn pull_request(
        &self,
        git: &impl RunGit,
        github: &impl GitHubApi,
        repo: &RepoName,
        number: NonZeroU64,
    ) -> anyhow::Result<PullRequest> {
        match self {
            Self::Real => {
                system_targets()
                    .pull_request(git, github, repo, number)
                    .await
            }
            Self::Fixture(fixture) => fixture.pull_request(git, github, repo, number).await,
        }
    }

    async fn fetch_remote(
        &self,
        kind: KnownTargetKind,
        repo: &RepoName,
    ) -> anyhow::Result<TargetRemote> {
        match self {
            Self::Real => system_targets().fetch_remote(kind, repo).await,
            Self::Fixture(fixture) => fixture.fetch_remote(kind, repo).await,
        }
    }
}

/// The remote a target is fetched from, owned: what
/// [`TargetResolver::fetch_remote`] hands `run`, which lends it to git's
/// fetch as a `git::Remote`, the borrowed form git's network commands
/// take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TargetRemote {
    /// A real target, at `https://<repo>`, its host checked.
    Https(HttpsRemote),
    /// A fixture repository on this disk, at `file://<path>`.
    Local(LocalRemote),
}

/// `refs/pull/<number>/head`, the ref a repository host keeps for a pull
/// request's head in the base repository itself: what both sources list
/// the head under, and what `run` fetches it from.
pub(crate) fn pull_head_ref(number: NonZeroU64) -> String {
    format!("refs/pull/{number}/head")
}

/// A pull request as `post` pins it: the commits of a `pr` target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PullRequest {
    /// The tip of the base branch.
    pub(crate) base: GitSha,
    /// The pull request's head commit, the one the sweep reviews.
    pub(crate) head: GitSha,
    /// Where `base` and `head` meet, where the sweep's diff starts.
    pub(crate) merge_base: GitSha,
}
