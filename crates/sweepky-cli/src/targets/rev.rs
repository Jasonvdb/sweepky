//! A revision as `post` is given one, and how it becomes a full SHA.
//!
//! - [`RevSpec`], the checked revision: `HEAD`, a full ref name under
//!   `refs/`, a branch or tag name, or a full 40-character SHA. The check
//!   is git's own rule for a ref name (`git check-ref-format`), tightened
//!   to printable ASCII, and it refuses an abbreviated SHA, so what reaches
//!   git is one exact name and never an option or a pattern.
//! - [`pin`], what a target source calls with its checked remote: one
//!   anonymous `git ls-remote` for the refs the revision could be, then
//!   [`match_rev`], the pure matcher that picks the one SHA and peels an
//!   annotated tag to the commit it names.
//! - [`list_refs`], that ls-remote, with every failed run of git turned
//!   into the one fixed refusal [`NOT_ANONYMOUSLY_READABLE`].
//!
//! **Limits.** ls-remote lists refs, not history. A full SHA is pinned as
//! given once the repository answers `ls-remote <url> HEAD`, which proves it
//! is readable but not that it serves that commit: `run` aborts when its
//! fetch by SHA fails. ls-remote does not say what a tag points at either,
//! so a tag of a tree or a blob pins that object, and `run` fails on it.

use std::str::FromStr;

use anyhow::{Context as _, bail};
use sweepky_core::GitSha;

use crate::git::{GitFailed, Remote, RemoteRef, RunGit, ls_remote};

/// The one refusal for a repository git could not list: whatever git said,
/// its exit status included, becomes this. Credential helpers and the
/// terminal prompt are off in the git runner, so a private repository fails
/// here rather than passing through saved credentials.
pub(crate) const NOT_ANONYMOUSLY_READABLE: &str =
    "the repository is not anonymously readable (Sweepky sweeps public repositories only)";

/// The longest revision accepted: 255 bytes, so its longest ls-remote
/// pattern (`refs/tags/<name>^{}`) and the line that answers it stay well
/// inside the parser's 1024-byte line.
pub(crate) const MAX_REV_BYTES: usize = 255;

/// The fewest hex digits git reads as an abbreviated object name.
const MIN_ABBREVIATED_SHA: usize = 4;

/// The characters git refuses anywhere in a ref name, besides spaces and
/// control characters: `~ ^ :` have meanings in a revision, `? * [` are
/// globs, and `\` is a separator on Windows.
const NOT_IN_A_REF: &[u8] = b"~^:?*[\\";

// The matcher's refusals, fixed text that never names the revision: the
// caller says which target it was, by its id.
const NO_HEAD: &str = "the repository has no HEAD (it may be empty)";
const NO_SUCH_REF: &str = "the repository has no ref by that name";
const NO_BRANCH_OR_TAG: &str = "the repository has no branch or tag by that name";
const AMBIGUOUS: &str = "the name is both a branch and a tag in the repository; give refs/heads/… \
                         for the branch or refs/tags/… for the tag instead";
const LISTED_TWICE: &str = "the repository listed one ref more than once, so Sweepky trusted \
                            neither";

/// A revision to pin, checked by [`RevSpec::from_str`] (`"main".parse()`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RevSpec {
    /// `HEAD`: the tip of the repository's default branch.
    Head,
    /// A full ref name under `refs/`, such as `refs/heads/main` or
    /// `refs/pull/1/head`, matched as written.
    FullRef(String),
    /// A branch or tag name, such as `main` or `v0.1.0`: matched against
    /// `refs/heads/<name>` and `refs/tags/<name>`, and refused when it is
    /// both.
    Name(String),
    /// A full 40-character SHA-1, pinned as given.
    Sha(GitSha),
}

impl FromStr for RevSpec {
    type Err = anyhow::Error;

    /// Checks `value` and sorts it into its kind. The error names the rule
    /// it broke and never quotes it.
    fn from_str(value: &str) -> anyhow::Result<Self> {
        if let Err(reason) = check(value) {
            bail!("the revision {reason}");
        }
        Ok(if value == "HEAD" {
            Self::Head
        } else if value.starts_with("refs/") {
            Self::FullRef(value.to_owned())
        } else if looks_like_sha(value) {
            // `check` passed, so this is exactly 40 lower-case hex
            // characters, which `GitSha` takes; its error is replaced all
            // the same, so nothing it says can quote the value.
            let Ok(sha) = value.parse() else {
                bail!("the revision is not a full SHA");
            };
            Self::Sha(sha)
        } else {
            Self::Name(value.to_owned())
        })
    }
}

/// git's rules for a ref name (`git help check-ref-format`), allowing one
/// level (`main`), plus Sweepky's: at most [`MAX_REV_BYTES`], printable
/// ASCII only, no leading `-`, and no abbreviated SHA. The error is the
/// reason alone, for the caller to wrap.
///
/// It walks the value with `bytes()` and `split`, never by index, so it
/// cannot panic, whatever the value.
fn check(value: &str) -> Result<(), &'static str> {
    if value.is_empty() {
        return Err("is empty");
    }
    if value.len() > MAX_REV_BYTES {
        return Err("is longer than 255 bytes");
    }
    // `is_ascii_graphic` is `!` to `~`: no space, no control character and
    // nothing outside ASCII, so the value prints as what it is.
    if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err("has a space, a control character or a character outside printable ASCII");
    }
    if value.starts_with('-') {
        return Err("starts with '-', which git would read as an option");
    }
    if value.bytes().any(|byte| NOT_IN_A_REF.contains(&byte)) {
        return Err("has one of ~ ^ : ? * [ \\, which git does not allow in a ref name");
    }
    if value.contains("..") {
        return Err("has '..', which git reads as a range");
    }
    if value.contains("@{") || value == "@" {
        return Err("has '@{' or is '@', which git reads as a reflog or HEAD");
    }
    if value.ends_with('.') {
        return Err("ends with '.'");
    }
    check_parts(value)?;
    if looks_like_sha(value) && !is_full_sha1(value) {
        return Err(
            "looks like an abbreviated or upper-case SHA; give the full 40-character SHA in lower \
             case, or the branch or tag as refs/heads/… or refs/tags/…",
        );
    }
    Ok(())
}

/// git's rules for each `/`-separated part of a ref name: none empty (so
/// no leading, trailing or doubled `/`), none starting with `.`, and none
/// ending with `.lock`, the name of git's own lock files.
fn check_parts(value: &str) -> Result<(), &'static str> {
    for part in value.split('/') {
        if part.is_empty() {
            return Err("starts or ends with '/' or has '//'");
        }
        if part.starts_with('.') {
            return Err("has a part that starts with '.'");
        }
        if part.ends_with(".lock") {
            return Err("has a part that ends with '.lock'");
        }
    }
    Ok(())
}

/// Whether git could read `value` as an object name: hex digits only, in
/// either case, at least [`MIN_ABBREVIATED_SHA`] of them.
fn looks_like_sha(value: &str) -> bool {
    value.len() >= MIN_ABBREVIATED_SHA && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Whether `value` is a full SHA-1 as git prints one: core's `GitSha`
/// check (lower-case hex), at SHA-1's 40 characters.
fn is_full_sha1(value: &str) -> bool {
    value.len() == GitSha::SHA1_LEN && value.parse::<GitSha>().is_ok()
}

impl RevSpec {
    /// The patterns `git ls-remote` is given for this revision. git prints
    /// an annotated tag's peeled `^{}` line only when that pattern is asked
    /// for (seen with git 2.50.1), so a tag's is always asked for.
    fn ls_remote_patterns(&self) -> Vec<String> {
        match self {
            // A full SHA needs no ref: listing `HEAD` only proves the
            // repository is readable.
            Self::Head | Self::Sha(_) => vec!["HEAD".to_owned()],
            Self::FullRef(name) => vec![name.clone(), peeled_name(name)],
            Self::Name(name) => {
                let tag = tag_ref(name);
                let peeled_tag = peeled_name(&tag);
                vec![branch_ref(name), tag, peeled_tag]
            }
        }
    }
}

/// The full name of the branch `name`: `refs/heads/<name>`.
fn branch_ref(name: &str) -> String {
    format!("refs/heads/{name}")
}

/// The full name of the tag `name`: `refs/tags/<name>`.
fn tag_ref(name: &str) -> String {
    format!("refs/tags/{name}")
}

/// The name git gives `name`'s peeled line: `<name>^{}`. `{{}}` is a
/// literal `{}` in `format!`.
fn peeled_name(name: &str) -> String {
    format!("{name}^{{}}")
}

/// Pins `rev` in the repository at `remote`: one anonymous ls-remote
/// through `git`, then [`match_rev`]. A failed run of git is
/// [`NOT_ANONYMOUSLY_READABLE`].
pub(crate) async fn pin(
    git: &impl RunGit,
    remote: Remote<'_>,
    rev: &RevSpec,
) -> anyhow::Result<GitSha> {
    let patterns = rev.ls_remote_patterns();
    // `ls_remote` takes `&[&str]`, so each `String` is lent out as a `&str`
    // for as long as `patterns` lives.
    let patterns: Vec<&str> = patterns.iter().map(String::as_str).collect();
    let refs = list_refs(git, remote, &patterns).await?;
    match_rev(rev, &refs)
}

/// The refs of `remote` that match `patterns`, through `git`, as
/// [`ls_remote`] lists them; a run of git that exits with a failure status
/// is [`NOT_ANONYMOUSLY_READABLE`] and nothing else.
///
/// Any other error, a timeout, a cap or a malformed listing, keeps its own
/// fixed text.
pub(crate) async fn list_refs(
    git: &impl RunGit,
    remote: Remote<'_>,
    patterns: &[&str],
) -> anyhow::Result<Vec<RemoteRef>> {
    match ls_remote(git, remote, patterns).await {
        // The `GitFailed` is dropped here, not wrapped, so the standard
        // error it keeps, which may hold a server's `remote:` lines, goes
        // nowhere, not even into the error's `Debug`.
        Err(error) if exited_with_failure(&error) => bail!(NOT_ANONYMOUSLY_READABLE),
        result => result,
    }
}

/// Whether `error` is git's own failure exit. `downcast_ref` finds the
/// typed [`GitFailed`] inside an `anyhow::Error`; a git stopped by a
/// signal has no exit code and keeps its own message.
fn exited_with_failure(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<GitFailed>()
        .is_some_and(|failed| failed.code().is_some())
}

/// The one SHA `rev` names among `refs`, an ls-remote listing: pure, so
/// the tests check it over synthetic listings.
///
/// Names are compared whole, because git matches an ls-remote pattern
/// against the end of a ref's name (`refs/heads/main` also matches
/// `refs/heads/x/main`). A tag resolves to the commit its `^{}` line
/// names, or for a lightweight tag, with no such line, to its own SHA. A
/// name that is both a branch and a tag is refused, and so is a listing
/// that names one ref twice. The errors are fixed text.
pub(crate) fn match_rev(rev: &RevSpec, refs: &[RemoteRef]) -> anyhow::Result<GitSha> {
    match rev {
        RevSpec::Sha(sha) => Ok(sha.clone()),
        // `Option::context` turns a `None` into an error with that text.
        RevSpec::Head => find_ref(refs, "HEAD")?.context(NO_HEAD),
        RevSpec::FullRef(name) => peeled(refs, name)?.context(NO_SUCH_REF),
        RevSpec::Name(name) => {
            let branch = find_ref(refs, &branch_ref(name))?;
            let tag = peeled(refs, &tag_ref(name))?;
            match (branch, tag) {
                (Some(_), Some(_)) => bail!(AMBIGUOUS),
                (Some(sha), None) | (None, Some(sha)) => Ok(sha),
                (None, None) => bail!(NO_BRANCH_OR_TAG),
            }
        }
    }
}

/// The SHA of the ref named exactly `name` in `refs`, or `None`. A listing
/// that names it twice is refused, whichever line would have won.
pub(crate) fn find_ref(refs: &[RemoteRef], name: &str) -> anyhow::Result<Option<GitSha>> {
    let mut named = refs.iter().filter(|remote_ref| remote_ref.name == name);
    let first = named.next();
    if named.next().is_some() {
        bail!(LISTED_TWICE);
    }
    Ok(first.map(|remote_ref| remote_ref.sha.clone()))
}

/// The SHA `name` resolves to once peeled: its `^{}` line's when the
/// listing has one (an annotated tag), else its own. `None` when `name`
/// itself is not listed, so a `^{}` line on its own counts for nothing.
fn peeled(refs: &[RemoteRef], name: &str) -> anyhow::Result<Option<GitSha>> {
    let Some(sha) = find_ref(refs, name)? else {
        return Ok(None);
    };
    Ok(Some(find_ref(refs, &peeled_name(name))?.unwrap_or(sha)))
}

#[cfg(test)]
mod tests {
    use super::{MAX_REV_BYTES, RevSpec, match_rev};
    use crate::git::parse_ls_remote;

    /// Synthetic object names for the matcher: a branch tip, a tag object,
    /// the commit that tag peels to, and a second commit.
    const BRANCH: &str = "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1";
    const TAG_OBJECT: &str = "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2";
    const TAGGED: &str = "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3";
    const OTHER: &str = "d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4";

    fn rev(text: &str) -> RevSpec {
        text.parse()
            .unwrap_or_else(|error| panic!("{text}: {error:#}"))
    }

    /// The SHA `text` resolves to over the synthetic ls-remote `output`.
    fn resolved(text: &str, output: &str) -> anyhow::Result<String> {
        let refs = parse_ls_remote(output.as_bytes()).expect("synthetic output parses");
        match_rev(&rev(text), &refs).map(String::from)
    }

    #[test]
    fn a_rev_spec_is_a_ref_name_git_accepts_or_a_full_sha() {
        assert_eq!(rev("HEAD"), RevSpec::Head);
        assert_eq!(rev("main"), RevSpec::Name("main".to_owned()));
        assert_eq!(rev("release/1.2"), RevSpec::Name("release/1.2".to_owned()));
        assert_eq!(rev("v0.1.0"), RevSpec::Name("v0.1.0".to_owned()));
        assert_eq!(
            rev("refs/heads/main"),
            RevSpec::FullRef("refs/heads/main".to_owned())
        );
        assert_eq!(rev(BRANCH), RevSpec::Sha(BRANCH.parse().expect("a SHA")));
        // Short hex that git would never read as an abbreviation (it takes
        // four digits at least) is a name.
        assert_eq!(rev("abc"), RevSpec::Name("abc".to_owned()));
        // The longest accepted.
        let longest = "x".repeat(MAX_REV_BYTES);
        assert_eq!(rev(&longest), RevSpec::Name(longest.clone()));
    }

    #[test]
    fn a_rev_spec_git_could_misread_is_refused_and_never_quoted() {
        // Each refused value carries `QUOTED`, or is a SHA prefix, so a
        // message that quoted it would contain one or the other.
        let too_long = format!("QUOTED{}", "x".repeat(MAX_REV_BYTES));
        let abbreviated = &BRANCH[..7];
        let upper = BRANCH.to_ascii_uppercase();
        let sha256 = "e5".repeat(32);
        let cases: &[(&str, &str)] = &[
            ("empty", ""),
            ("a leading '-'", "-QUOTED"),
            ("'..'", "QUOTED..main"),
            ("'@{'", "QUOTED@{1}"),
            ("a control character", "QUOTED\x1b[2J"),
            ("a newline", "QUOTED\nmain"),
            ("a space", "QUOTED main"),
            ("a trailing '/'", "QUOTED/"),
            ("a leading '/'", "/QUOTED"),
            ("'//'", "QUOTED//main"),
            ("a trailing '.lock'", "QUOTED.lock"),
            ("a part ending '.lock'", "QUOTED.lock/main"),
            ("a part starting '.'", "QUOTED/.main"),
            ("a trailing '.'", "QUOTED."),
            ("a glob", "QUOTED*"),
            ("a caret", "QUOTED^{}"),
            ("a colon", "QUOTED:main"),
            ("a backslash", "QUOTED\\main"),
            ("not ASCII", "QUOTED\u{e9}"),
            ("more than 255 bytes", &too_long),
            ("an abbreviated SHA", abbreviated),
            ("an upper-case SHA", &upper),
            ("a SHA-256", &sha256),
        ];
        for (what, value) in cases {
            let error = value.parse::<RevSpec>().expect_err(what);
            // Lower case, so an upper-case SHA quoted back is caught too.
            let message = format!("{error:#}").to_lowercase();
            assert!(message.starts_with("the revision "), "{what}: {message}");
            assert!(!message.contains("quoted"), "{what}: {message}");
            assert!(!message.contains(&BRANCH[..4]), "{what}: {message}");
            assert!(!message.contains(&sha256[..8]), "{what}: {message}");
        }
        // `@` alone is git's shorthand for HEAD, never a ref name.
        assert!("@".parse::<RevSpec>().is_err());
        // An abbreviated SHA is pointed at the full SHA or the full ref
        // names instead.
        let error = abbreviated.parse::<RevSpec>().expect_err("abbreviated");
        let message = format!("{error:#}");
        assert!(message.contains("40-character"), "{message}");
        assert!(message.contains("refs/heads/…"), "{message}");
    }

    #[test]
    fn a_name_that_is_both_a_branch_and_a_tag_is_ambiguous() {
        let output = format!(
            "{BRANCH}\trefs/heads/v1\n{TAG_OBJECT}\trefs/tags/v1\n{TAGGED}\trefs/tags/v1^{{}}\n"
        );
        let error = resolved("v1", &output).expect_err("ambiguous");
        let message = format!("{error:#}");
        assert!(message.contains("both a branch and a tag"), "{message}");
        assert!(message.contains("refs/heads/…"), "{message}");
        assert!(message.contains("refs/tags/…"), "{message}");
        assert!(!message.contains("v1"), "{message}");
        // The full names settle it, and the tag still peels.
        assert_eq!(
            resolved("refs/heads/v1", &output).expect("a branch"),
            BRANCH
        );
        assert_eq!(resolved("refs/tags/v1", &output).expect("a tag"), TAGGED);
    }

    #[test]
    fn a_tag_resolves_to_the_commit_it_peels_to() {
        // An annotated tag: the tag object's line, then the `^{}` line
        // with the commit, which is what gets pinned.
        let annotated = format!("{TAG_OBJECT}\trefs/tags/v1\n{TAGGED}\trefs/tags/v1^{{}}\n");
        assert_eq!(resolved("v1", &annotated).expect("a tag"), TAGGED);
        // A lightweight tag names its commit directly and has no `^{}` line.
        let lightweight = format!("{OTHER}\trefs/tags/v1\n");
        assert_eq!(resolved("v1", &lightweight).expect("a tag"), OTHER);
        // A branch, HEAD and a full SHA, which pins as given.
        let listing = format!("{BRANCH}\tHEAD\n{BRANCH}\trefs/heads/main\n");
        assert_eq!(resolved("main", &listing).expect("a branch"), BRANCH);
        assert_eq!(resolved("HEAD", &listing).expect("HEAD"), BRANCH);
        assert_eq!(resolved(OTHER, &listing).expect("a SHA"), OTHER);
    }

    #[test]
    fn the_matcher_compares_whole_names_and_trusts_no_odd_listing() {
        // git matches a pattern against the end of a ref's name, so a
        // server may well list `refs/heads/x/main` for `refs/heads/main`.
        let nested = format!("{OTHER}\trefs/heads/x/main\n");
        assert!(resolved("main", &nested).is_err());
        // Nothing listed: no such name, no HEAD.
        assert!(resolved("main", "").is_err());
        assert!(resolved("HEAD", "").is_err());
        assert!(resolved("refs/heads/main", "").is_err());
        // A peeled line without its tag is no tag.
        let orphan = format!("{TAGGED}\trefs/tags/v1^{{}}\n");
        assert!(resolved("v1", &orphan).is_err());
        // One name listed twice is refused, whichever line would win.
        let twice = format!("{BRANCH}\trefs/heads/main\n{OTHER}\trefs/heads/main\n");
        let error = resolved("main", &twice).expect_err("listed twice");
        assert!(!format!("{error:#}").contains("main"), "{error:#}");
    }
}
