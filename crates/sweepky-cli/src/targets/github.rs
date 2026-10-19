//! GitHub's unauthenticated REST API, where the real source reads a pull
//! request: its base and head from `GET /repos/<owner>/<name>/pulls/<n>`,
//! and their merge base from `GET
//! /repos/<owner>/<name>/compare/<base>...<head>`. Pull requests are read
//! from GitHub only in v1 (`docs/plan/01-records-and-discovery.md`).
//!
//! - [`GitHubRepo`], a pull request target's repository as the API names
//!   it, and the policy that makes one: `github.com/<owner>/<name>`
//!   exactly.
//! - [`GitHubApi`], the seam the requests go through: the SDK's HTTP
//!   client in the binary, `test_support::FakeGitHub` in the tests.
//! - [`read_pull`] and [`read_merge_base`], the two reads, and
//!   [`parse_pull`], [`parse_compare`] and [`answer_status`], the pure
//!   parts they are made of.
//!
//! The rules, and why:
//!
//! - **Anonymous.** No token is sent, so what the API answers is what
//!   anyone may read: a private repository is a 404, which reads as "not
//!   found, or not public". Anonymous requests are limited to 60 an hour
//!   from one address, hence the advice to try again on a 403 or 429.
//! - **Through the guard.** Each request goes through
//!   `remote::get_unredirected`, so an answer that came through a
//!   redirect is refused, an error answer's body is never read, and a body
//!   is read under [`MAX_ANSWER_BYTES`]. The caller checks
//!   [`API_HOST`] against the host policy before the first request.
//! - **Checked, not trusted.** The parsers read only the fields they need,
//!   hold every SHA to a full lower-case SHA-1, never panic, and refuse in
//!   fixed text that quotes nothing of the answer: serde's own error is
//!   dropped, because it can quote a value from the body.
//! - **The base repository, never the fork.** The head is the `head.sha`
//!   the base repository's pull request names, which the real source then
//!   checks against that repository's own `refs/pull/<n>/head`; nothing is
//!   ever read from the repository the pull request came from.

use std::num::NonZeroU64;

use anyhow::{Context as _, anyhow, bail};
use pubky::{PubkyHttpClient, StatusCode};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use sweepky_core::{GitSha, RepoName, Zeroizing};
use url::Url;

use super::rev::is_full_sha1;
use crate::remote::{PageStatus, get_unredirected};

/// GitHub's API host, which the real source checks against the host policy
/// before it sends a request there.
pub(crate) const API_HOST: &str = "api.github.com";

/// The largest answer read: 1 MiB, for both reads. A pull request's answer
/// is a few tens of KiB (its description is at most 65,536 characters),
/// and the compare's is too, because only page 2 of 1 commit a page is
/// asked for, which carries no files (see [`GitHubRepo::compare_url`]).
pub(crate) const MAX_ANSWER_BYTES: usize = 1024 * 1024;

/// The headers every request carries: the media type GitHub's REST API
/// documents and the API version this code was written against. The SDK's
/// client adds its own `User-Agent`, which GitHub requires.
const HEADERS: [(&str, &str); 2] = [
    ("accept", "application/vnd.github+json"),
    ("x-github-api-version", "2022-11-28"),
];

/// What a pull request target anywhere but `github.com/<owner>/<name>` is
/// refused with. Fixed text: it never quotes the name.
pub(crate) const NOT_A_GITHUB_REPO: &str = "a pull request target must be a repository on \
     github.com, named github.com/<owner>/<name> with no further path and no .git: Sweepky reads \
     pull requests from GitHub only";

/// What a 404 from either read becomes: GitHub answers 404 for a private
/// repository as for a missing one, so the two cannot be told apart.
pub(crate) const NOT_FOUND_OR_NOT_PUBLIC: &str = "GitHub's API answered 404 Not Found: not found, \
     or not public (Sweepky sweeps public repositories only)";

/// A pull request target's repository as GitHub's API names it: the owner
/// and the name of `github.com/<owner>/<name>`, borrowed from the
/// [`RepoName`] they came from.
// `'a` is a lifetime: the two `&str`s point into the `RepoName`, so the
// compiler makes sure the name lives at least as long as this does, and
// nothing is copied.
#[derive(Debug)]
pub(crate) struct GitHubRepo<'a> {
    owner: &'a str,
    name: &'a str,
}

impl<'a> GitHubRepo<'a> {
    /// `repo` as GitHub's API names it, or [`NOT_A_GITHUB_REPO`] for
    /// anything but `github.com/<owner>/<name>`: another host, a third path
    /// segment, or a name ending in `.git` in any case, which GitHub serves
    /// as the same repository but `run` would fetch from another URL.
    ///
    /// No network: the policy `check_policy` applies. `RepoName` has
    /// already held each segment to `A-Z a-z 0-9 . _ -`, none empty, `.`
    /// or `..`, so the two segments are safe to put in a URL path as they
    /// are.
    pub(crate) fn of(repo: &'a RepoName) -> anyhow::Result<Self> {
        let Some((owner, name)) = repo
            .as_str()
            .strip_prefix("github.com/")
            .and_then(|path| path.split_once('/'))
        else {
            bail!(NOT_A_GITHUB_REPO);
        };
        if name.contains('/') || name.to_ascii_lowercase().ends_with(".git") {
            bail!(NOT_A_GITHUB_REPO);
        }
        Ok(Self { owner, name })
    }

    /// `https://api.github.com/repos/<owner>/<name>/pulls/<number>`.
    pub(crate) fn pull_url(&self, number: NonZeroU64) -> anyhow::Result<Url> {
        let Self { owner, name } = self;
        api_url(&format!("repos/{owner}/{name}/pulls/{number}"))
    }

    /// `https://api.github.com/repos/<owner>/<name>/compare/<base>...<head>`,
    /// the three-dot comparison whose `merge_base_commit` is the merge base,
    /// asking for page 2 at 1 commit a page.
    ///
    /// Page 1 carries up to 300 changed files with their patches, many MiB
    /// for a large pull request; every later page leaves the files out and
    /// still carries `merge_base_commit` (GitHub's documented paging,
    /// checked against the live API on 2026-10-19), so the answer stays
    /// small whatever the pull request changes.
    pub(crate) fn compare_url(&self, base: &GitSha, head: &GitSha) -> anyhow::Result<Url> {
        let Self { owner, name } = self;
        api_url(&format!(
            "repos/{owner}/{name}/compare/{base}...{head}?per_page=1&page=2"
        ))
    }
}

/// `https://api.github.com/<path>`. Every part is ours or checked, so the
/// parse cannot fail; the error is fixed text all the same.
fn api_url(path: &str) -> anyhow::Result<Url> {
    Url::parse(&format!("https://{API_HOST}/{path}"))
        .map_err(|_| anyhow!("could not build GitHub's API URL"))
}

/// The seam GitHub's API is reached through.
///
/// A trait so that the tests answer with synthetic bodies and no network.
/// As with `git::RunGit`, its method is an `async fn`, so callers take
/// `&impl GitHubApi` rather than `&dyn GitHubApi`.
pub(crate) trait GitHubApi {
    /// The body of the 2xx answer to an anonymous `GET` of `url`, at most
    /// `cap` bytes, or `None` for a 404. Any other status is an error in
    /// fixed text ([`answer_status`]).
    async fn get(&self, url: Url, cap: usize) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>>;
}

/// The real [`GitHubApi`]: the SDK's HTTP client, the one every other
/// request goes through. For an ICANN host such as `api.github.com` it is a
/// plain reqwest client (user agent `pubky.org@0.16.2`), so nothing
/// Pubky-specific changes the request.
// A trait of this crate implemented for the SDK's type: Rust allows it
// because the trait is ours (the "orphan rule" needs one of the two to be).
impl GitHubApi for PubkyHttpClient {
    async fn get(&self, url: Url, cap: usize) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
        get_unredirected(self, url, &HEADERS, cap, answer_status)
            .await?
            .into_body()
    }
}

/// What a status from GitHub's API means, given the status alone, so an
/// error answer's body is never read: 2xx is a body to read, 404 is no
/// answer (which the reads word as [`NOT_FOUND_OR_NOT_PUBLIC`]), 403 and
/// 429 are GitHub's rate limit, and anything else is the status alone.
pub(crate) fn answer_status(status: StatusCode) -> anyhow::Result<PageStatus> {
    // `{status}` below is the code and the `http` crate's standard reason
    // for it, never the server's words. `StatusCode::NOT_FOUND` and the
    // others are constants, which a `match` arm can name as a pattern.
    match status {
        // A match guard: this arm applies only when the condition holds.
        _ if status.is_success() => Ok(PageStatus::Read),
        StatusCode::NOT_FOUND => Ok(PageStatus::Empty),
        StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS => bail!(
            "GitHub's API answered {status}, which for an anonymous request almost always means \
             its rate limit (60 requests an hour from one address) is used up; try again later"
        ),
        _ => bail!("GitHub's API answered {status}"),
    }
}

/// The two commits a pull request's answer names, as [`parse_pull`] reads
/// them.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PullShas {
    /// `base.sha`: the tip of the branch the pull request is into.
    pub(crate) base: GitSha,
    /// `head.sha`: the pull request's head commit.
    pub(crate) head: GitSha,
}

/// The base and head of pull request `number` of `repo`, read through
/// `api` and parsed by [`parse_pull`].
pub(crate) async fn read_pull(
    api: &impl GitHubApi,
    repo: &GitHubRepo<'_>,
    number: NonZeroU64,
) -> anyhow::Result<PullShas> {
    // As in `remote::get_public`: `?` inside the block returns from the
    // block, so the context below is added to every error it gives.
    async { parse_pull(&get_answer(api, repo.pull_url(number)?).await?) }
        .await
        .context("could not read the pull request from GitHub's API")
}

/// The merge base of `base` and `head` in `repo`, read through `api` and
/// parsed by [`parse_compare`].
pub(crate) async fn read_merge_base(
    api: &impl GitHubApi,
    repo: &GitHubRepo<'_>,
    base: &GitSha,
    head: &GitSha,
) -> anyhow::Result<GitSha> {
    async { parse_compare(&get_answer(api, repo.compare_url(base, head)?).await?) }
        .await
        .context("could not read the pull request's merge base from GitHub's API")
}

/// The body of GitHub's answer to `url`, read through `api` under
/// [`MAX_ANSWER_BYTES`], with a 404 as [`NOT_FOUND_OR_NOT_PUBLIC`].
async fn get_answer(api: &impl GitHubApi, url: Url) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    // `Option::context` turns the `None` of a 404 into an error with that
    // text.
    api.get(url, MAX_ANSWER_BYTES)
        .await?
        .context(NOT_FOUND_OR_NOT_PUBLIC)
}

/// The fields [`parse_pull`] reads. serde parses past every other field of
/// the answer and keeps none of it: this is an answer to read, never a
/// record to rewrite, so there is nothing to preserve.
#[derive(Deserialize)]
struct PullAnswer {
    base: CommitRef,
    head: CommitRef,
}

/// The field [`parse_compare`] reads.
#[derive(Deserialize)]
struct CompareAnswer {
    merge_base_commit: CommitRef,
}

/// A commit as both answers name one: its `sha`, as a plain string until
/// [`parse_sha1`] checks it.
#[derive(Deserialize)]
struct CommitRef {
    sha: String,
}

/// Reads `base.sha` and `head.sha` from a pull request's answer.
pub(crate) fn parse_pull(body: &[u8]) -> anyhow::Result<PullShas> {
    const WHAT: &str = "pull request";
    let answer: PullAnswer = parse_answer(body, WHAT)?;
    Ok(PullShas {
        base: parse_sha1(&answer.base.sha, WHAT)?,
        head: parse_sha1(&answer.head.sha, WHAT)?,
    })
}

/// Reads `merge_base_commit.sha` from a compare answer.
pub(crate) fn parse_compare(body: &[u8]) -> anyhow::Result<GitSha> {
    const WHAT: &str = "compare";
    let answer: CompareAnswer = parse_answer(body, WHAT)?;
    parse_sha1(&answer.merge_base_commit.sha, WHAT)
}

/// `body` parsed as `T`, the answer `what` names: refused over
/// [`MAX_ANSWER_BYTES`] before it is parsed, and refused in fixed text when
/// it is not that JSON.
// `T: DeserializeOwned` is "any type serde can build that borrows nothing
// from the body", which `#[derive(Deserialize)]` on a type of owned fields
// gives. serde_json never panics on bad input and stops at 128 levels of
// nesting, so a hostile body cannot overflow the stack either.
fn parse_answer<T: DeserializeOwned>(body: &[u8], what: &str) -> anyhow::Result<T> {
    if body.len() > MAX_ANSWER_BYTES {
        bail!("GitHub's {what} answer is over the {MAX_ANSWER_BYTES}-byte limit");
    }
    // `map_err(|_| …)` drops serde's error, whose text can quote the body.
    serde_json::from_slice(body)
        .map_err(|_| anyhow!("GitHub's {what} answer is not the JSON Sweepky reads"))
}

/// `text` as a full SHA-1, or a refusal that does not quote it.
fn parse_sha1(text: &str, what: &str) -> anyhow::Result<GitSha> {
    // `is_full_sha1` passed, so `parse` cannot fail; its error is replaced
    // all the same, so nothing it says can quote the value.
    if is_full_sha1(text)
        && let Ok(sha) = text.parse()
    {
        return Ok(sha);
    }
    bail!("GitHub's {what} answer has a SHA that is not a full lower-case SHA-1")
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use pubky::StatusCode;
    use serde_json::{Value, json};
    use sweepky_core::{GitSha, RepoName};

    use super::{
        GitHubRepo, MAX_ANSWER_BYTES, NOT_A_GITHUB_REPO, PullShas, answer_status, parse_compare,
        parse_pull,
    };
    use crate::remote::PageStatus;

    /// Synthetic object names: a base tip, a pull request head and their
    /// merge base.
    const BASE: &str = "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1";
    const HEAD: &str = "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2";
    const MERGE_BASE: &str = "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3";

    /// Planted in the free text of every synthetic answer, so a message
    /// that quoted the answer would contain it.
    const MARKER: &str = "QUOTED-MARKER";

    fn sha(text: &str) -> GitSha {
        text.parse().expect("a SHA")
    }

    fn repo(text: &str) -> RepoName {
        text.parse().expect("a repo name")
    }

    /// A pull request answer shaped like GitHub's, with `base` and `head`
    /// as the two commits' `sha` values, whatever their JSON type.
    fn pull_answer(base: Value, head: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "url": "https://api.github.com/repos/org/name/pulls/42",
            "number": 42,
            "state": "open",
            "title": MARKER,
            "body": MARKER,
            "user": { "login": MARKER },
            "base": { "label": "org:main", "ref": "main", "sha": base, "repo": { "full_name": "org/name" } },
            "head": { "label": "fork:topic", "ref": MARKER, "sha": head, "repo": { "full_name": "fork/name" } },
        }))
        .expect("JSON")
    }

    /// A compare answer shaped like GitHub's page 2 of 1, which has no
    /// `files`, with `merge_base` as the merge base commit's `sha`.
    fn compare_answer(merge_base: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "url": "https://api.github.com/repos/org/name/compare/x...y",
            "status": "diverged",
            "ahead_by": 2,
            "behind_by": 1,
            "total_commits": 2,
            "base_commit": { "sha": BASE, "commit": { "message": MARKER } },
            "merge_base_commit": { "sha": merge_base, "commit": { "message": MARKER } },
            "commits": [{ "sha": HEAD, "commit": { "message": MARKER } }],
            "a_field_from_a_later_api": { "anything": [MARKER] },
        }))
        .expect("JSON")
    }

    /// `body` padded with trailing spaces, still valid JSON, to one byte
    /// over the cap.
    fn over_the_cap(mut body: Vec<u8>) -> Vec<u8> {
        body.resize(MAX_ANSWER_BYTES + 1, b' ');
        body
    }

    /// Checks that `error` quotes neither the marker nor any of `values`.
    fn assert_quotes_nothing(error: &anyhow::Error, values: &[&str]) {
        let message = format!("{error:#} {error:?}");
        for value in values.iter().copied().chain([MARKER]) {
            assert!(!message.contains(value), "{value} in {message}");
        }
    }

    #[test]
    fn the_pulls_parser_reads_base_and_head_and_refuses_the_rest_without_quoting() {
        assert_eq!(
            parse_pull(&pull_answer(json!(BASE), json!(HEAD))).expect("parses"),
            PullShas {
                base: sha(BASE),
                head: sha(HEAD),
            }
        );
        let upper = HEAD.to_ascii_uppercase();
        let short = &HEAD[..39];
        let sha256 = "e5".repeat(32);
        let not_hex = "g".repeat(40);
        let padded = format!(" {HEAD}");
        let without_head =
            serde_json::to_vec(&json!({ "base": { "sha": BASE }, "title": MARKER })).expect("JSON");
        let cases: &[(&str, Vec<u8>)] = &[
            ("a missing head", without_head),
            (
                "a SHA of the wrong type",
                pull_answer(json!(BASE), json!(42)),
            ),
            (
                "a commit of the wrong type",
                pull_answer(json!(BASE), json!({ "sha": HEAD })),
            ),
            ("a null SHA", pull_answer(json!(null), json!(HEAD))),
            ("an upper-case SHA", pull_answer(json!(BASE), json!(upper))),
            ("a 39-digit SHA", pull_answer(json!(BASE), json!(short))),
            ("a SHA-256", pull_answer(json!(sha256), json!(HEAD))),
            (
                "a SHA that is not hex",
                pull_answer(json!(BASE), json!(not_hex)),
            ),
            (
                "a SHA with a space",
                pull_answer(json!(BASE), json!(padded)),
            ),
            ("not JSON", format!("<html>{MARKER}</html>").into_bytes()),
            ("an array", format!("[\"{MARKER}\"]").into_bytes()),
            ("an empty body", Vec::new()),
        ];
        for (what, body) in cases {
            let error = parse_pull(body).expect_err(what);
            assert_quotes_nothing(&error, &[&upper, short, &sha256, &not_hex]);
        }
        // Over the cap, valid JSON and all: refused by its size.
        let error = parse_pull(&over_the_cap(pull_answer(json!(BASE), json!(HEAD))))
            .expect_err("over the cap");
        assert!(format!("{error:#}").contains("limit"), "{error:#}");
        assert_quotes_nothing(&error, &[]);
    }

    #[test]
    fn the_compare_parser_reads_the_merge_base_and_ignores_the_rest() {
        assert_eq!(
            parse_compare(&compare_answer(json!(MERGE_BASE))).expect("parses"),
            sha(MERGE_BASE)
        );
        let malformed: &[(&str, Vec<u8>)] = &[
            ("a null merge base", compare_answer(json!(null))),
            ("a merge base of the wrong type", compare_answer(json!(7))),
            (
                "a SHA-256 merge base",
                compare_answer(json!("e5".repeat(32))),
            ),
            (
                "no merge base",
                serde_json::to_vec(&json!({ "base_commit": { "sha": BASE }, "status": MARKER }))
                    .expect("JSON"),
            ),
            (
                "cut short",
                b"{\"merge_base_commit\": {\"sha\": \"c3c3".to_vec(),
            ),
        ];
        for (what, body) in malformed {
            let error = parse_compare(body).expect_err(what);
            assert_quotes_nothing(&error, &[]);
        }
        // A body over the cap is refused before it is parsed: this one is
        // not even JSON, and the refusal is about its size.
        let mut not_json = format!("{{{MARKER}").into_bytes();
        not_json.resize(MAX_ANSWER_BYTES + 1, b'x');
        let error = parse_compare(&not_json).expect_err("over the cap");
        assert!(format!("{error:#}").contains("limit"), "{error:#}");
        assert_quotes_nothing(&error, &[]);
        let error = parse_compare(&over_the_cap(compare_answer(json!(MERGE_BASE))))
            .expect_err("over the cap");
        assert!(format!("{error:#}").contains("limit"), "{error:#}");
    }

    #[test]
    fn a_pull_request_target_is_github_com_owner_name_exactly() {
        for text in [
            "gitlab.com/o/r",
            "github.com/o/r/x",
            "github.com/o/r.git",
            "github.com/o/r.GIT",
            "github.com/o/.git",
            "github.com/o",
            "api.github.com/o/r",
            "www.github.com/o/r",
            "github.com.example/o/r",
        ] {
            let name = repo(text);
            let error = GitHubRepo::of(&name).expect_err(text);
            let message = format!("{error:#}");
            assert_eq!(message, NOT_A_GITHUB_REPO, "{text}");
            assert!(!message.contains("o/r"), "{text}: {message}");
        }

        let name = repo("github.com/org/name");
        let github = GitHubRepo::of(&name).expect("on GitHub");
        let number = NonZeroU64::new(42).expect("not zero");
        assert_eq!(
            github.pull_url(number).expect("a URL").as_str(),
            "https://api.github.com/repos/org/name/pulls/42"
        );
        // Page 2 of 1 per page: the page that carries no files (see
        // `compare_url`).
        assert_eq!(
            github
                .compare_url(&sha(BASE), &sha(HEAD))
                .expect("a URL")
                .as_str(),
            format!(
                "https://api.github.com/repos/org/name/compare/{BASE}...{HEAD}?per_page=1&page=2"
            )
        );
        // The characters a repository name may hold all pass through.
        let dotted = repo("github.com/Org-1/my_repo.rs");
        assert_eq!(
            GitHubRepo::of(&dotted)
                .expect("on GitHub")
                .pull_url(NonZeroU64::MIN)
                .expect("a URL")
                .as_str(),
            "https://api.github.com/repos/Org-1/my_repo.rs/pulls/1"
        );
    }

    #[test]
    fn answer_statuses_map_to_fixed_messages() {
        // The mapping is given the status alone, so it cannot read an
        // error answer's body.
        for status in [StatusCode::OK, StatusCode::NON_AUTHORITATIVE_INFORMATION] {
            assert_eq!(
                answer_status(status).ok(),
                Some(PageStatus::Read),
                "{status}"
            );
        }
        // A 404 is no answer to read, which the caller words as "not
        // found, or not public".
        assert_eq!(
            answer_status(StatusCode::NOT_FOUND).ok(),
            Some(PageStatus::Empty)
        );
        for status in [StatusCode::FORBIDDEN, StatusCode::TOO_MANY_REQUESTS] {
            let message = format!("{:#}", answer_status(status).expect_err("refused"));
            assert!(message.contains("rate limit"), "{message}");
            assert!(message.contains("try again later"), "{message}");
            assert!(message.contains(status.as_str()), "{message}");
        }
        for status in [
            StatusCode::MOVED_PERMANENTLY,
            StatusCode::UNAUTHORIZED,
            StatusCode::UNPROCESSABLE_ENTITY,
            StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            let message = format!("{:#}", answer_status(status).expect_err("refused"));
            assert_eq!(message, format!("GitHub's API answered {status}"));
        }
    }
}
