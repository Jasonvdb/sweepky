//! The real target source: repositories on the internet, reached over https
//! only. What `main.rs` builds, as [`TargetSource::Real`].
//!
//! Before git contacts a repository, its host is looked up and every
//! address must be public ([`HttpsRemote::for_repo`]), on the pin path and
//! on the fetch path alike, and git's runner allows the `https` transport
//! alone. A revision is pinned with one anonymous `git ls-remote`
//! (`rev::pin`).
//!
//! A pull request is read from GitHub's unauthenticated API (`github`):
//! its base and head from the pull request, checked against the base
//! repository's own `refs/pull/<n>/head` through ls-remote, then their
//! merge base from the compare API. GitHub's API host goes through the host
//! policy too, before the first request.
//!
//! Generic over [`ResolveHost`], so the tests answer the host lookup with
//! any addresses and no network, and its methods take any [`RunGit`] and
//! any [`GitHubApi`], so they record git's arguments and GitHub's URLs
//! instead of contacting either.
//!
//! [`TargetSource::Real`]: super::TargetSource::Real

use std::num::NonZeroU64;

use anyhow::{Context as _, bail};
use sweepky_core::{GitSha, KnownTargetKind, RepoName};

use super::github::{API_HOST, GitHubApi, GitHubRepo, PullShas, read_merge_base, read_pull};
use super::host::{HttpsRemote, ResolveHost, check_host};
use super::rev::{RevSpec, find_ref, list_refs, pin};
use super::{PullRequest, TargetRemote, TargetResolver, pull_head_ref};
use crate::git::{AllowedProtocols, Remote, RunGit};

/// What a head that GitHub's API and the repository's ref disagree on is
/// refused with: a push landed between the two reads.
pub(crate) const PULL_REQUEST_MOVED: &str =
    "the pull request moved while it was being pinned; try again";

/// What a pull request whose head ref the repository does not list is
/// refused with.
pub(crate) const NO_PULL_HEAD: &str = "the repository lists no refs/pull/<n>/head for the pull \
     request, so its head cannot be checked";

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
        if kind == KnownTargetKind::Pr {
            GitHubRepo::of(repo)?;
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
        git: &impl RunGit,
        github: &impl GitHubApi,
        repo: &RepoName,
        number: NonZeroU64,
    ) -> anyhow::Result<PullRequest> {
        // The policy first, with no network: `github.com/<owner>/<name>`.
        let api_repo = GitHubRepo::of(repo)?;
        check_host(API_HOST, &self.resolver)
            .await
            .with_context(|| format!("could not reach GitHub's API at {API_HOST}"))?;
        let PullShas { base, head } = read_pull(github, &api_repo, number).await?;
        self.check_pull_head(git, repo, number, &head).await?;
        let merge_base = read_merge_base(github, &api_repo, &base, &head).await?;
        Ok(PullRequest {
            base,
            head,
            merge_base,
        })
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

impl<R: ResolveHost> RealTargets<R> {
    /// Checks that `head`, the head GitHub's API named for pull request
    /// `number`, is what `repo` itself lists as `refs/pull/<number>/head`:
    /// one anonymous ls-remote of the base repository, after its host
    /// check, so the commit `run` will fetch from that ref is the one
    /// pinned. A head that differs is [`PULL_REQUEST_MOVED`]; none listed
    /// is [`NO_PULL_HEAD`].
    async fn check_pull_head(
        &self,
        git: &impl RunGit,
        repo: &RepoName,
        number: NonZeroU64,
        head: &GitSha,
    ) -> anyhow::Result<()> {
        let remote = HttpsRemote::for_repo(repo, &self.resolver).await?;
        let head_ref = pull_head_ref(number);
        let refs = list_refs(git, Remote::Https(&remote), &[&head_ref]).await?;
        match find_ref(&refs, &head_ref)? {
            // A match guard: this arm applies only when the condition holds.
            // Two SHAs from public places, so a plain `==` leaks nothing.
            Some(listed) if listed == *head => Ok(()),
            Some(_) => bail!(PULL_REQUEST_MOVED),
            None => bail!(NO_PULL_HEAD),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use sweepky_core::{KnownTargetKind, RepoName};

    use super::{NO_PULL_HEAD, PULL_REQUEST_MOVED, RealTargets};
    use crate::git::AllowedProtocols;
    use crate::targets::github::NOT_A_GITHUB_REPO;
    use crate::targets::rev::NOT_ANONYMOUSLY_READABLE;
    use crate::targets::{PullRequest, TargetRemote, TargetResolver};
    use crate::test_support::{FakeGitHub, FakeResolver, RecordingGit, checked_remote};

    const REPO: &str = "github.com/org/name";
    const SHA: &str = "6a0e0f6f873af85d97788783fde43f3e3fa83133";

    /// Synthetic object names for pull request 42: the base tip, the head
    /// GitHub names, a head that moved after it, and the merge base.
    const BASE: &str = "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1";
    const HEAD: &str = "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2";
    const MOVED: &str = "d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4";
    const MERGE_BASE: &str = "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3";

    /// The API URLs the real source asks for pull request 42 of [`REPO`].
    const PULLS_URL: &str = "https://api.github.com/repos/org/name/pulls/42";
    fn compare_url() -> String {
        format!("https://api.github.com/repos/org/name/compare/{BASE}...{HEAD}?per_page=1&page=2")
    }

    fn forty_two() -> NonZeroU64 {
        NonZeroU64::new(42).expect("not zero")
    }

    /// GitHub as the tests script it: pull request 42 with [`BASE`] and
    /// [`HEAD`], and their merge base [`MERGE_BASE`]. Every other URL is a
    /// 404.
    fn github() -> FakeGitHub {
        let pull = format!(r#"{{"base":{{"sha":"{BASE}"}},"head":{{"sha":"{HEAD}"}}}}"#);
        let compare = format!(r#"{{"merge_base_commit":{{"sha":"{MERGE_BASE}"}}}}"#);
        FakeGitHub::answering(&[
            (PULLS_URL, pull.as_bytes()),
            (&compare_url(), compare.as_bytes()),
        ])
    }

    /// What `git ls-remote <repo> refs/pull/42/head` lists when the head
    /// is `head`.
    fn pull_head_listing(head: &str) -> String {
        format!("{head}\trefs/pull/42/head\n")
    }

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
    async fn a_pull_request_target_must_be_github_com_owner_name() {
        let real = public();
        assert!(real.check_policy(KnownTargetKind::Pr, &repo(REPO)).is_ok());
        let git = RecordingGit::succeeding(real.protocols(), b"");
        let github = github();
        for text in [
            "gitlab.com/org/name",
            "github.com/org/name/x",
            "github.com/org/name.git",
        ] {
            let refused = repo(text);
            // Other kinds may be anywhere.
            for kind in [KnownTargetKind::Repo, KnownTargetKind::Commit] {
                assert!(real.check_policy(kind, &refused).is_ok(), "{kind:?} {text}");
            }
            let error = real
                .check_policy(KnownTargetKind::Pr, &refused)
                .expect_err(text);
            assert_eq!(format!("{error:#}"), NOT_A_GITHUB_REPO, "{text}");
            assert!(format!("{error:#}").contains("github.com"), "{error:#}");
            assert!(!format!("{error:#}").contains("gitlab"), "{error:#}");
            // The pull request and fetch paths apply it themselves, before
            // any lookup, git run or request to GitHub.
            let error = real
                .pull_request(&git, &github, &refused, forty_two())
                .await
                .expect_err(text);
            assert_eq!(format!("{error:#}"), NOT_A_GITHUB_REPO, "{text}");
            assert!(
                real.fetch_remote(KnownTargetKind::Pr, &refused)
                    .await
                    .is_err()
            );
        }
        assert_eq!(git.argv(), Vec::<Vec<String>>::new());
        assert_eq!(github.asked(), Vec::<String>::new());
        assert_eq!(real.resolver.asked(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn a_pull_request_is_read_from_github_and_its_head_checked_with_ls_remote() {
        let real = public();
        let github = github();
        let listing = pull_head_listing(HEAD);
        let git = RecordingGit::succeeding(real.protocols(), listing.as_bytes());
        let pinned = real
            .pull_request(&git, &github, &repo(REPO), forty_two())
            .await
            .expect("pins");
        let sha = |text: &str| text.parse().expect("a SHA");
        assert_eq!(
            pinned,
            PullRequest {
                base: sha(BASE),
                head: sha(HEAD),
                merge_base: sha(MERGE_BASE),
            }
        );
        // The pull request, then the compare of its base and head.
        assert_eq!(github.asked(), [PULLS_URL.to_owned(), compare_url()]);
        // Both hosts went through the host policy first: GitHub's API, then
        // the repository's own.
        assert_eq!(real.resolver.asked(), ["api.github.com", "github.com"]);
        // One ls-remote of the base repository's own `refs/pull/42/head`,
        // never of the fork the pull request came from.
        let argv = git.argv();
        let [argv] = argv.as_slice() else {
            panic!("one git run: {argv:?}");
        };
        let subcommand = argv
            .iter()
            .position(|arg| arg == "ls-remote")
            .expect("ls-remote");
        assert_eq!(
            argv.get(subcommand + 1..),
            Some(
                ["https://github.com/org/name", "refs/pull/42/head"]
                    .map(String::from)
                    .as_slice()
            )
        );
    }

    #[tokio::test]
    async fn a_head_that_moved_or_is_not_listed_is_refused() {
        let real = public();
        for (listing, expected) in [
            (pull_head_listing(MOVED), PULL_REQUEST_MOVED),
            (String::new(), NO_PULL_HEAD),
        ] {
            let github = github();
            let git = RecordingGit::succeeding(real.protocols(), listing.as_bytes());
            let error = real
                .pull_request(&git, &github, &repo(REPO), forty_two())
                .await
                .expect_err(expected);
            assert_eq!(format!("{error:#}"), expected);
            // Refused before the merge base is asked for.
            assert_eq!(github.asked(), [PULLS_URL]);
        }
        assert_eq!(
            PULL_REQUEST_MOVED,
            "the pull request moved while it was being pinned; try again"
        );
    }

    #[tokio::test]
    async fn a_pull_request_github_does_not_answer_is_not_found_or_not_public() {
        let real = public();
        // A GitHub that answers 404 to everything, as it does for a
        // private repository.
        let github = FakeGitHub::answering(&[]);
        let git = RecordingGit::succeeding(real.protocols(), b"");
        let error = real
            .pull_request(&git, &github, &repo(REPO), forty_two())
            .await
            .expect_err("a 404");
        assert!(
            format!("{error:#}").contains("not found, or not public"),
            "{error:#}"
        );
        assert_eq!(github.asked(), [PULLS_URL]);
        assert_eq!(git.argv(), Vec::<Vec<String>>::new());
    }

    #[tokio::test]
    async fn github_on_a_non_public_address_is_refused_before_any_request() {
        let real = RealTargets::new(FakeResolver::answering(&["127.0.0.1"]));
        let github = github();
        let git = RecordingGit::succeeding(real.protocols(), b"");
        let error = real
            .pull_request(&git, &github, &repo(REPO), forty_two())
            .await
            .expect_err("not public");
        assert!(format!("{error:#}").contains("not public"), "{error:#}");
        assert!(format!("{error:#}").contains("GitHub's API"), "{error:#}");
        assert_eq!(real.resolver.asked(), ["api.github.com"]);
        assert_eq!(github.asked(), Vec::<String>::new());
        assert_eq!(git.argv(), Vec::<Vec<String>>::new());
    }
}
