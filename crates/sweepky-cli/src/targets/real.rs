//! The real target source: repositories on the internet, reached over https
//! only. What `main.rs` builds, as [`TargetSource::Real`].
//!
//! Before git contacts a repository, its host is looked up and every
//! address must be public ([`HttpsRemote::for_repo`]), on the pin path and
//! on the fetch path alike, and git's runner allows the `https` transport
//! alone. A revision is pinned with one anonymous `git ls-remote`
//! (`rev::pin`).
//!
//! Generic over [`ResolveHost`], so the tests answer the host lookup with
//! any addresses and no network, and its methods take any [`RunGit`], so
//! they record git's arguments instead of running it.
//!
//! Pull requests come from GitHub's unauthenticated API, which comes later
//! in P2b; until then [`RealTargets::pull_request`] applies the policy and
//! refuses.
//!
//! [`TargetSource::Real`]: super::TargetSource::Real

use std::num::NonZeroU64;

use anyhow::bail;
use sweepky_core::{GitSha, KnownTargetKind, RepoName};

use super::host::{HttpsRemote, ResolveHost};
use super::rev::{RevSpec, pin};
use super::{PullRequest, TargetRemote, TargetResolver};
use crate::git::{AllowedProtocols, Remote, RunGit};

/// The start of every repository on GitHub: the host, then the `/` a
/// `RepoName` always has after it. So a name starts with this exactly when
/// its host is `github.com`.
const GITHUB: &str = "github.com/";

const PR_NOT_ON_GITHUB: &str = "a pull request target must be on github.com: Sweepky reads pull \
                                requests from GitHub only";
const PR_NOT_BUILT: &str = "Sweepky cannot read pull requests from GitHub yet";

/// The real source, looking hosts up through `R`: [`SystemResolver`] in the
/// binary, a fake in the tests.
///
/// [`SystemResolver`]: super::host::SystemResolver
pub(crate) struct RealTargets<R> {
    resolver: R,
}

impl<R: ResolveHost> RealTargets<R> {
    /// The real source, with `resolver` for its host checks.
    pub(crate) fn new(resolver: R) -> Self {
        Self { resolver }
    }
}

// `impl<R: ResolveHost>`: one implementation for every resolver type. The
// compiler makes a copy of it for each `R` it is used with, so the binary
// holds only the `SystemResolver` one.
impl<R: ResolveHost> TargetResolver for RealTargets<R> {
    fn protocols(&self) -> AllowedProtocols {
        AllowedProtocols::Https
    }

    fn check_policy(&self, kind: KnownTargetKind, repo: &RepoName) -> anyhow::Result<()> {
        if kind == KnownTargetKind::Pr && !repo.as_str().starts_with(GITHUB) {
            bail!(PR_NOT_ON_GITHUB);
        }
        Ok(())
    }

    async fn resolve_rev(
        &self,
        git: &impl RunGit,
        repo: &RepoName,
        rev: &RevSpec,
    ) -> anyhow::Result<GitSha> {
        // The host check comes first: with a non-public address, `?`
        // returns before git is asked anything.
        let remote = HttpsRemote::for_repo(repo, &self.resolver).await?;
        pin(git, Remote::Https(&remote), rev).await
    }

    async fn pull_request(
        &self,
        _git: &impl RunGit,
        repo: &RepoName,
        _number: NonZeroU64,
    ) -> anyhow::Result<PullRequest> {
        self.check_policy(KnownTargetKind::Pr, repo)?;
        bail!(PR_NOT_BUILT)
    }

    async fn fetch_remote(
        &self,
        kind: KnownTargetKind,
        repo: &RepoName,
    ) -> anyhow::Result<TargetRemote> {
        self.check_policy(kind, repo)?;
        let remote = HttpsRemote::for_repo(repo, &self.resolver).await?;
        Ok(TargetRemote::Https(remote))
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use sweepky_core::{KnownTargetKind, RepoName};

    use super::RealTargets;
    use crate::git::AllowedProtocols;
    use crate::targets::rev::NOT_ANONYMOUSLY_READABLE;
    use crate::targets::{TargetRemote, TargetResolver};
    use crate::test_support::{FakeResolver, RecordingGit, checked_remote};

    const REPO: &str = "github.com/org/name";
    const SHA: &str = "6a0e0f6f873af85d97788783fde43f3e3fa83133";

    fn repo(text: &str) -> RepoName {
        text.parse().expect("a repo name")
    }

    /// A real source whose resolver answers one public address.
    fn public() -> RealTargets<FakeResolver> {
        RealTargets::new(FakeResolver::answering(&["140.82.112.3"]))
    }

    #[tokio::test]
    async fn a_host_on_a_non_public_address_is_refused_before_git_runs() {
        for address in ["127.0.0.1", "::ffff:10.0.0.1"] {
            let real = RealTargets::new(FakeResolver::answering(&[address]));
            let git = RecordingGit::succeeding(real.protocols(), b"");
            let repo = repo(REPO);
            for rev in ["main", SHA] {
                let error = real
                    .resolve_rev(&git, &repo, &rev.parse().expect("a rev"))
                    .await
                    .expect_err(address);
                assert!(format!("{error:#}").contains("not public"), "{error:#}");
            }
            // The remote `run` fetches from goes through the same check.
            let error = real
                .fetch_remote(KnownTargetKind::Repo, &repo)
                .await
                .expect_err(address);
            assert!(format!("{error:#}").contains("not public"), "{error:#}");
            assert_eq!(git.argv(), Vec::<Vec<String>>::new(), "{address}");
        }
    }

    #[tokio::test]
    async fn a_failed_ls_remote_is_one_fixed_refusal_that_quotes_nothing_of_git() {
        let real = public();
        // What git and a server could say for a private repository: the
        // server's own `remote:` line among them.
        let git = RecordingGit::failing(
            real.protocols(),
            128,
            b"remote: secret-marker\nfatal: Authentication failed\n",
        );
        for rev in ["main", "HEAD", "refs/tags/v1", SHA] {
            let error = real
                .resolve_rev(&git, &repo(REPO), &rev.parse().expect("a rev"))
                .await
                .expect_err(rev);
            assert_eq!(format!("{error:#}"), NOT_ANONYMOUSLY_READABLE, "{rev}");
            assert!(!format!("{error:?}").contains("secret-marker"), "{error:?}");
        }
        // git did run, once for each.
        assert_eq!(git.argv().len(), 4);
    }

    #[tokio::test]
    async fn the_real_source_speaks_https_alone() {
        let real = public();
        assert_eq!(real.protocols(), AllowedProtocols::Https);
        let listing = format!("{SHA}\trefs/heads/main\n");
        let git = RecordingGit::succeeding(real.protocols(), listing.as_bytes());
        let pinned = real
            .resolve_rev(&git, &repo(REPO), &"main".parse().expect("a rev"))
            .await
            .expect("pins");
        assert_eq!(pinned.as_str(), SHA);
        // One ls-remote, of the https URL, with no file transport allowed,
        // asking for the branch, the tag and the tag's peeled line.
        let argv = git.argv();
        let [argv] = argv.as_slice() else {
            panic!("one git run: {argv:?}");
        };
        assert!(argv.iter().any(|arg| arg == "protocol.https.allow=always"));
        assert!(
            !argv.iter().any(|arg| arg.starts_with("protocol.file")),
            "{argv:?}"
        );
        let subcommand = argv
            .iter()
            .position(|arg| arg == "ls-remote")
            .expect("ls-remote");
        assert_eq!(
            argv.get(subcommand + 1..),
            Some(
                [
                    "https://github.com/org/name",
                    "refs/heads/main",
                    "refs/tags/main",
                    "refs/tags/main^{}",
                ]
                .map(String::from)
                .as_slice()
            )
        );
        // The remote `run` fetches from is the checked https one.
        assert_eq!(
            real.fetch_remote(KnownTargetKind::Commit, &repo(REPO))
                .await
                .expect("a remote"),
            TargetRemote::Https(checked_remote(REPO).await)
        );
    }

    #[tokio::test]
    async fn a_pull_request_target_must_be_on_github_com() {
        let real = public();
        let gitlab = repo("gitlab.com/org/name");
        assert!(real.check_policy(KnownTargetKind::Pr, &repo(REPO)).is_ok());
        for kind in [KnownTargetKind::Repo, KnownTargetKind::Commit] {
            assert!(real.check_policy(kind, &gitlab).is_ok(), "{kind:?}");
        }
        let error = real
            .check_policy(KnownTargetKind::Pr, &gitlab)
            .expect_err("not GitHub");
        assert!(format!("{error:#}").contains("github.com"), "{error:#}");
        assert!(!format!("{error:#}").contains("gitlab"), "{error:#}");
        // The pull request and fetch paths apply it themselves, before any
        // lookup or git run.
        let git = RecordingGit::succeeding(real.protocols(), b"");
        assert!(
            real.pull_request(&git, &gitlab, NonZeroU64::MIN)
                .await
                .is_err()
        );
        assert!(
            real.fetch_remote(KnownTargetKind::Pr, &gitlab)
                .await
                .is_err()
        );
        assert_eq!(git.argv(), Vec::<Vec<String>>::new());
        assert_eq!(real.resolver.asked(), Vec::<String>::new());
    }
}
