//! The fixture source: targets served from the bare repository under
//! `fixtures/` (or any repository on this disk a test maps), so the tests
//! reach no real host. `main.rs` never builds it.
//!
//! - [`FixtureTargets`], the source: each repository name it maps to an
//!   absolute path, pinned through git over the `file` transport.
//! - [`LocalRemote`], its remote, which only this module can make.
//!
//! A pull request `<n>` is the fixture's `refs/pull/<n>/head`, the ref a
//! repository host keeps for one; its base is the commit `HEAD` names, and
//! its merge base comes from `git merge-base`, run read-only in the bare
//! repository itself.

use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, bail};
use sweepky_core::{GitSha, KnownTargetKind, RepoName};

use super::github::GitHubApi;
use super::rev::{RevSpec, find_ref, list_refs, pin};
use super::{PullRequest, TargetRemote, TargetResolver, pull_head_ref};
use crate::git::{
    AllowedProtocols, GitCommand, Limits, LocalSubcommand, Remote, RunGit, STDERR_CAP,
};

const NOT_MAPPED: &str = "the fixture source serves no repository by that name";
const NO_BASE: &str = "the repository has no HEAD, so a pull request in it has no base";
const NO_PULL_REQUEST: &str = "the repository has no pull request by that number";

/// `git merge-base`'s limits: a local command over a tiny repository, which
/// prints one SHA and its newline.
const MERGE_BASE_LIMITS: Limits = Limits {
    timeout: Duration::from_secs(60),
    stdout_cap: 1024,
    stderr_cap: STDERR_CAP,
};

/// The fixture source: repositories on this disk, by name, for the tests.
///
/// **It enables git's `file` transport**
/// ([`AllowedProtocols::HttpsAndFile`]), which the real source never does,
/// so `main.rs` never builds it. It is public, and hidden from the docs,
/// only so that `tests/end_to_end.rs` can put it in its
/// [`Context`](crate::Context). It serves the names it maps and refuses
/// every other, and it allows a pull request on any host it maps, so the
/// fixture's `example.invalid` pull request works.
#[doc(hidden)]
pub struct FixtureTargets {
    /// Each repository name, with the absolute path of its repository.
    repos: BTreeMap<RepoName, PathBuf>,
}

impl FixtureTargets {
    /// A source that serves each `(name, path)` of `repos`: `name` from the
    /// repository at `path`, which must be absolute and UTF-8 (a relative
    /// one is refused when a target is pinned in it). git percent-decodes
    /// a `file://` URL, so a path with a `%` in it names another directory.
    pub fn new(repos: impl IntoIterator<Item = (RepoName, PathBuf)>) -> Self {
        Self {
            repos: repos.into_iter().collect(),
        }
    }

    /// Where `repo` is on this disk, or [`NOT_MAPPED`].
    fn path(&self, repo: &RepoName) -> anyhow::Result<&Path> {
        // `as_path` lends the stored `PathBuf` out as a `&Path`.
        self.repos
            .get(repo)
            .map(PathBuf::as_path)
            .context(NOT_MAPPED)
    }

    /// The `file://` remote of `repo`, or [`NOT_MAPPED`].
    fn remote(&self, repo: &RepoName) -> anyhow::Result<LocalRemote> {
        LocalRemote::new(self.path(repo)?)
    }
}

impl TargetResolver for FixtureTargets {
    fn protocols(&self) -> AllowedProtocols {
        AllowedProtocols::HttpsAndFile
    }

    fn check_policy(&self, _kind: KnownTargetKind, repo: &RepoName) -> anyhow::Result<()> {
        // Any kind, for a name this source maps: no host is contacted.
        self.path(repo).map(|_| ())
    }

    async fn resolve_rev(
        &self,
        git: &impl RunGit,
        repo: &RepoName,
        rev: &RevSpec,
    ) -> anyhow::Result<GitSha> {
        let remote = self.remote(repo)?;
        pin(git, Remote::Local(&remote), rev).await
    }

    /// The fixture's own refs stand in for GitHub, so `_github` is never
    /// asked anything.
    async fn pull_request(
        &self,
        git: &impl RunGit,
        _github: &impl GitHubApi,
        repo: &RepoName,
        number: NonZeroU64,
    ) -> anyhow::Result<PullRequest> {
        let path = self.path(repo)?;
        let remote = LocalRemote::new(path)?;
        let head_ref = pull_head_ref(number);
        let refs = list_refs(git, Remote::Local(&remote), &["HEAD", &head_ref]).await?;
        let base = find_ref(&refs, "HEAD")?.context(NO_BASE)?;
        let head = find_ref(&refs, &head_ref)?.context(NO_PULL_REQUEST)?;
        let merge_base = merge_base(git, path, &base, &head).await?;
        Ok(PullRequest {
            base,
            head,
            merge_base,
        })
    }

    async fn fetch_remote(
        &self,
        _kind: KnownTargetKind,
        repo: &RepoName,
    ) -> anyhow::Result<TargetRemote> {
        Ok(TargetRemote::Local(self.remote(repo)?))
    }
}

/// The merge base of `base` and `head` in the bare repository at
/// `repo_dir`, through `git`: `git merge-base <base> <head>`, which reads
/// the repository and writes nothing. git finds the repository at
/// `repo_dir` itself, so it never searches the directories above.
async fn merge_base(
    git: &impl RunGit,
    repo_dir: &Path,
    base: &GitSha,
    head: &GitSha,
) -> anyhow::Result<GitSha> {
    let command = GitCommand::local(LocalSubcommand::MergeBase, MERGE_BASE_LIMITS)
        .operand(base.as_str())
        .operand(head.as_str())
        .in_dir(repo_dir);
    let output = git
        .run(&command)
        .await
        .context("could not find the pull request's merge base")?;
    parse_sha_line(&output)
}

/// One full SHA-1 and its newline, as `git merge-base` prints it. Anything
/// else is an error that quotes none of it.
fn parse_sha_line(output: &[u8]) -> anyhow::Result<GitSha> {
    // Each step hands on `Some` or stops at `None`: no final newline, bytes
    // that are not UTF-8, the wrong length, or not lower-case hex. Nothing
    // is indexed, so no output can make this panic.
    output
        .strip_suffix(b"\n")
        .and_then(|line| std::str::from_utf8(line).ok())
        .filter(|line| line.len() == GitSha::SHA1_LEN)
        .and_then(|line| line.parse().ok())
        .context("git merge-base printed something other than one full SHA-1")
}

/// A repository on this disk as git is given it, `file://<absolute path>`:
/// the fixture source's remote, and the only one besides
/// [`HttpsRemote`](super::host::HttpsRemote) that git's network commands
/// take (`git::Remote`).
///
/// Its constructor is private to this module, so only the fixture source
/// can make one (the tests of other modules have
/// `LocalRemote::for_tests`). git reaches it only through a runner that
/// allows the `file` transport (`AllowedProtocols::HttpsAndFile`), which
/// the fixture source alone asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalRemote {
    url: String,
}

impl LocalRemote {
    /// `file://<path>`. `path` must be absolute and UTF-8. git
    /// percent-decodes a URL, so a path with a `%` in it would name another
    /// directory; the fixture's has none.
    fn new(path: &Path) -> anyhow::Result<Self> {
        match path.to_str() {
            Some(text) if path.is_absolute() => Ok(Self {
                url: format!("file://{text}"),
            }),
            _ => bail!(
                "{} is not an absolute UTF-8 path, so it cannot be a file:// URL",
                path.display()
            ),
        }
    }

    /// [`LocalRemote::new`], for the tests of other modules that run git
    /// against the fixture, such as the git runner's. `cfg(test)`, so the
    /// binary has no way to call it.
    #[cfg(test)]
    pub(crate) fn for_tests(path: &Path) -> anyhow::Result<Self> {
        Self::new(path)
    }

    /// The URL as git is given it.
    pub(crate) fn as_str(&self) -> &str {
        &self.url
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use sweepky_core::{GitSha, KnownTargetKind, RepoName};

    use super::{FixtureTargets, LocalRemote};
    use crate::git::AllowedProtocols;
    use crate::targets::rev::NOT_ANONYMOUSLY_READABLE;
    use crate::targets::{PullRequest, TargetRemote, TargetResolver, TargetSource};
    use crate::test_support::{
        FakeGitHub, RecordingGit, dirs_in, fixture_repo, fixture_targets, inert_target_repo,
        private_temp, recorded_fixture_shas, test_git_env,
    };

    /// A repository name the fixture source does not map.
    const UNMAPPED: &str = "example.invalid/sweepky/elsewhere";

    fn unmapped() -> RepoName {
        UNMAPPED.parse().expect("a repo name")
    }

    #[tokio::test]
    async fn the_fixture_source_pins_its_refs_and_pull_request_1_through_the_trait() {
        // The SHAs `fixtures/README.md` records, by name.
        let shas = recorded_fixture_shas();
        let sha = |name: &str| -> GitSha {
            shas.get(name)
                .cloned()
                .unwrap_or_else(|| panic!("the README records {name}"))
        };
        // Through `TargetSource`, as a command holds it in its context.
        let source = TargetSource::Fixture(fixture_targets());
        let temp = private_temp();
        let git = source
            .git_runner(&dirs_in(&temp), &test_git_env())
            .expect("a runner");
        let repo = fixture_repo();
        let full_sha = sha("B");
        for (rev, expected) in [
            ("main", "M"),
            ("HEAD", "M"),
            ("topic", "T1"),
            // The commit the annotated tag peels to, not the tag object.
            ("v0.1.0", "A"),
            ("refs/pull/1/head", "F2"),
            (full_sha.as_str(), "B"),
        ] {
            let pinned = source
                .resolve_rev(&git, &repo, &rev.parse().expect("a rev"))
                .await
                .unwrap_or_else(|error| panic!("{rev}: {error:#}"));
            assert_eq!(pinned, sha(expected), "{rev}");
        }
        assert_ne!(sha("A"), sha("v0.1.0"), "the tag object is not its commit");

        let one = NonZeroU64::MIN;
        let github = FakeGitHub::answering(&[]);
        assert_eq!(
            source
                .pull_request(&git, &github, &repo, one)
                .await
                .expect("pull request 1"),
            PullRequest {
                base: sha("M"),
                head: sha("F2"),
                merge_base: sha("B"),
            }
        );
        // From the fixture repository alone: GitHub is never asked.
        assert_eq!(github.asked(), Vec::<String>::new());
        // The fixture's `example.invalid` name passes the pull request
        // policy: the source allows its own mapped names.
        assert!(source.check_policy(KnownTargetKind::Pr, &repo).is_ok());
    }

    #[tokio::test]
    async fn the_fixture_source_refuses_an_unknown_name_and_an_unmapped_repository() {
        let source = TargetSource::Fixture(fixture_targets());
        let temp = private_temp();
        let git = source
            .git_runner(&dirs_in(&temp), &test_git_env())
            .expect("a runner");
        let repo = fixture_repo();
        let one = NonZeroU64::MIN;
        let github = FakeGitHub::answering(&[]);
        // A name the repository does not have, a pull request it does not
        // have, and a repository the source does not map.
        assert!(
            source
                .resolve_rev(&git, &repo, &"no-such-branch".parse().expect("a rev"))
                .await
                .is_err()
        );
        let two = NonZeroU64::new(2).expect("not zero");
        assert!(
            source
                .pull_request(&git, &github, &repo, two)
                .await
                .is_err()
        );
        let elsewhere = unmapped();
        assert!(
            source
                .resolve_rev(&git, &elsewhere, &"main".parse().expect("a rev"))
                .await
                .is_err()
        );
        assert!(
            source
                .pull_request(&git, &github, &elsewhere, one)
                .await
                .is_err()
        );
        assert!(
            source
                .fetch_remote(KnownTargetKind::Repo, &elsewhere)
                .await
                .is_err()
        );
        let error = source
            .check_policy(KnownTargetKind::Repo, &elsewhere)
            .expect_err("not mapped");
        assert!(!format!("{error:#}").contains(UNMAPPED), "{error:#}");
    }

    #[tokio::test]
    async fn an_empty_directory_is_not_anonymously_readable() {
        let empty = private_temp();
        let repo = fixture_repo();
        let source = FixtureTargets::new([(repo.clone(), empty.path().to_path_buf())]);
        let temp = private_temp();
        let git = source
            .git_runner(&dirs_in(&temp), &test_git_env())
            .expect("a runner");
        for rev in ["main", "HEAD"] {
            let error = source
                .resolve_rev(&git, &repo, &rev.parse().expect("a rev"))
                .await
                .expect_err(rev);
            assert_eq!(format!("{error:#}"), NOT_ANONYMOUSLY_READABLE, "{rev}");
        }
        let error = source
            .pull_request(&git, &FakeGitHub::answering(&[]), &repo, NonZeroU64::MIN)
            .await
            .expect_err("no repository");
        assert_eq!(format!("{error:#}"), NOT_ANONYMOUSLY_READABLE);
    }

    #[tokio::test]
    async fn the_fixture_source_asks_for_the_file_protocol_for_its_mapped_paths_only() {
        let path = inert_target_repo();
        let source = fixture_targets();
        assert_eq!(source.protocols(), AllowedProtocols::HttpsAndFile);
        let listing = format!("{}\tHEAD\n", "b".repeat(40));
        let git = RecordingGit::succeeding(source.protocols(), listing.as_bytes());
        source
            .resolve_rev(&git, &fixture_repo(), &"HEAD".parse().expect("a rev"))
            .await
            .expect("pins");
        let url = format!("file://{}", path.to_str().expect("UTF-8"));
        let argv = git.argv();
        let [argv] = argv.as_slice() else {
            panic!("one git run: {argv:?}");
        };
        assert!(argv.iter().any(|arg| arg == "protocol.file.allow=always"));
        assert_eq!(
            argv.get(argv.len() - 3..),
            Some(
                ["ls-remote", url.as_str(), "HEAD"]
                    .map(String::from)
                    .as_slice()
            )
        );
        assert_eq!(
            source
                .fetch_remote(KnownTargetKind::Repo, &fixture_repo())
                .await
                .expect("a remote"),
            TargetRemote::Local(LocalRemote::new(&path).expect("absolute"))
        );
        // An unmapped name never reaches git.
        assert!(
            source
                .resolve_rev(&git, &unmapped(), &"HEAD".parse().expect("a rev"))
                .await
                .is_err()
        );
        assert_eq!(git.argv().len(), 1);
    }

    #[test]
    fn a_local_remote_is_the_file_url_of_an_absolute_path_only() {
        let fixture = inert_target_repo();
        let remote = LocalRemote::for_tests(&fixture).expect("an absolute UTF-8 path");
        assert_eq!(
            remote.as_str(),
            format!("file://{}", fixture.to_str().expect("UTF-8"))
        );
        assert!(LocalRemote::for_tests("relative/path".as_ref()).is_err());
        // Like an `HttpsRemote`, it comes from no string, default or JSON.
        crate::test_support::assert_not_impl_any!(
            LocalRemote: Default,
            std::str::FromStr,
            From<String>,
            From<&'static str>,
            serde::de::DeserializeOwned,
        );
    }
}
