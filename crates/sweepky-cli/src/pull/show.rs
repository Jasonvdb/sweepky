//! The owner's view of the circle's findings: the merged report `pull`
//! writes to `merged.json`, turned into lines to print, each location with a
//! GitHub link at the commit the bounty pinned (P5, Done when 1).
//!
//! [`render_findings`] takes the merged groups alone, which hold trusted
//! (circle) findings only: a stranger's content never reaches it, so it
//! cannot print one, and the `reported by` count is the one place a
//! stranger shows, as a number (01, "Attribution and content are two
//! different steps"; 02, "Untrusted reports are data").
//!
//! **What prints.** Per finding: the bounty's id, the group's place and its
//! `reportedBy` count, the title, the status (and the severity and
//! confidence when given), each location, and the description. The fix is
//! not printed: it is for the owner's agent to read in the file, not for
//! the terminal. Every string a finding holds is an agent's, written after
//! reading untrusted code, so each goes through `display::sanitize` (or
//! `sanitize_multiline` for the description) with a cap of its own.
//!
//! **Links.** A location is linked as
//! `https://github.com/<owner>/<name>/blob/<sha>/<file>#L<line>`, built
//! from the bounty record's pinned target (its repo, and a pull request's
//! `head` or a commit or repo target's `rev`) and from the location's file
//! and line alone; nothing else in a finding is ever put in a link. Which
//! target: a sweep of one target links at it; a sweep of several, which
//! sees its targets side by side, links a file only under `<tid>/` of one
//! of them, that prefix taken off. The file must pass the lexical check in
//! [`link_path`]; each of its segments is then percent-encoded by the `url`
//! crate. A file that fails, a target whose kind this build does not know,
//! or a sweep the caller gives no targets for, prints with no link; a repo
//! not on `github.com` prints [`NO_GITHUB_LINK`].

use sweepky_core::{
    BountyRef, Finding, GitSha, KnownTarget, Location, MergedGroup, RepoName, RepoPath, Target,
    TargetId,
};
use url::Url;

use crate::display::{Layout, first_changed_char, sanitize, sanitize_multiline};

/// What a location of a repo not on github.com prints in place of a link.
pub(crate) const NO_GITHUB_LINK: &str = "(no GitHub link)";

/// How many characters of a title to show.
const MAX_TITLE_CHARS: usize = 200;
/// How many characters of a status, a severity or a confidence to show.
/// Each is one short word when an agent follows the format.
const MAX_WORD_CHARS: usize = 32;
/// How many characters of a location's file to show: [`RepoPath`]'s limit
/// is 512 bytes, so no path that could be linked is cut.
const MAX_FILE_CHARS: usize = 512;
/// How many characters of a description to show. The whole text is in
/// `merged.json`.
const MAX_DESCRIPTION_CHARS: usize = 4000;
/// How many locations of one finding to show; the rest are counted.
const MAX_LOCATIONS_SHOWN: usize = 32;

/// The lines to print for `merged`, the merged groups of `bounty` (from
/// `FindingGroups::merged`, which holds trusted findings only), one block
/// per finding, each ending with an empty line. Empty when there are none.
///
/// `targets` are the bounty record's own. `covered` holds, for each sweep
/// of the `FindingGroups` the groups came from and in its order, the ids of
/// the targets its record says it covered (the poll state's
/// `SweepSummary::targets`); a sweep past its end is treated as covering
/// none, so its locations get no link.
pub(crate) fn render_findings(
    bounty: BountyRef,
    targets: &[Target],
    merged: &[MergedGroup<'_>],
    covered: &[&[TargetId]],
) -> String {
    let mut shown = String::new();
    // `zip(1..)` numbers the groups from 1 as they go, without an index
    // that could be off by one.
    for (group, group_number) in merged.iter().zip(1..) {
        let findings = group.findings();
        for (merged_finding, finding_number) in findings.iter().zip(1..) {
            let heading = format!(
                "bounty {}, group {group_number} of {}, finding {finding_number} of {}, \
                 reported by {}\n",
                bounty.id,
                merged.len(),
                findings.len(),
                group.reported_by().len(),
            );
            shown.push_str(&heading);
            // `get` gives `None` past the end, where `[i]` would panic, and
            // `copied` turns the `Option<&&[TargetId]>` into an
            // `Option<&[TargetId]>`; a missing entry is an empty list.
            let sweep_targets = covered
                .get(merged_finding.member.sweep)
                .copied()
                .unwrap_or_default();
            push_finding(&mut shown, merged_finding.finding, targets, sweep_targets);
            shown.push('\n');
        }
    }
    shown
}

/// Appends `finding`'s lines to `shown`: title, status, locations and
/// description, each sanitised.
fn push_finding(shown: &mut String, finding: &Finding, targets: &[Target], covered: &[TargetId]) {
    shown.push_str(&format!(
        "  title: {}\n",
        sanitize(&finding.title, MAX_TITLE_CHARS)
    ));
    shown.push_str(&status_line(finding));
    for location in finding.locations.iter().take(MAX_LOCATIONS_SHOWN) {
        shown.push_str(&location_line(location, targets, covered));
    }
    // `saturating_sub` is 0 when there are no more, rather than a panic.
    let more = finding.locations.len().saturating_sub(MAX_LOCATIONS_SHOWN);
    if more > 0 {
        shown.push_str(&format!("  and {more} more locations\n"));
    }
    push_description(shown, &finding.description);
}

/// `status: <status>`, then the severity and confidence when given, and a
/// newline. Each is an open string an agent wrote, so each is sanitised.
fn status_line(finding: &Finding) -> String {
    let mut line = format!(
        "  status: {}",
        sanitize(finding.status.as_str(), MAX_WORD_CHARS)
    );
    if let Some(severity) = &finding.severity {
        line.push_str(&format!(
            ", severity: {}",
            sanitize(severity.as_str(), MAX_WORD_CHARS)
        ));
    }
    if let Some(confidence) = &finding.confidence {
        line.push_str(&format!(
            ", confidence: {}",
            sanitize(confidence.as_str(), MAX_WORD_CHARS)
        ));
    }
    line.push('\n');
    line
}

/// Appends `description`, sanitised and indented, unless it is empty.
fn push_description(shown: &mut String, description: &str) {
    if description.is_empty() {
        return;
    }
    shown.push_str("  description:\n");
    // Sanitised first, then split: the sanitiser keeps `\n` alone as a line
    // break (a `\r` is escaped), so each line is indented and none can
    // rewrite another.
    for line in sanitize_multiline(description, MAX_DESCRIPTION_CHARS).lines() {
        shown.push_str(&format!("    {line}\n"));
    }
}

/// `at <file>:<line>`, then the location's link or the no-link note, and a
/// newline.
fn location_line(location: &Location, targets: &[Target], covered: &[TargetId]) -> String {
    let mut line = format!("  at {}", sanitize(&location.file, MAX_FILE_CHARS));
    if let Some(number) = location.line {
        line.push_str(&format!(":{number}"));
    }
    match link(location, targets, covered) {
        Link::Url(url) => {
            line.push(' ');
            line.push_str(&url);
        }
        Link::NotGitHub => {
            line.push(' ');
            line.push_str(NO_GITHUB_LINK);
        }
        Link::None => {}
    }
    line.push('\n');
    line
}

/// What a location gets after its `file:line`.
enum Link {
    /// A GitHub blob URL, ASCII only: the `url` crate percent-encodes
    /// everything else.
    Url(String),
    /// The target's repo is not on github.com.
    NotGitHub,
    /// No link: the file failed the check, or no covered target of a kind
    /// this build knows holds it.
    None,
}

/// The link for `location`, in a sweep that covered the targets `covered`
/// of the bounty's `targets`.
fn link(location: &Location, targets: &[Target], covered: &[TargetId]) -> Link {
    let Some((target, file)) = target_of(&location.file, targets, covered) else {
        return Link::None;
    };
    // `Ok(Some(_))` alone is a target to link at: `Ok(None)` is a kind this
    // build does not know, and `Err` one whose fields fail their checks.
    let Ok(Some(known)) = target.known() else {
        return Link::None;
    };
    let Some(repo) = github_repo(repo_of(&known)) else {
        return Link::NotGitHub;
    };
    let Some(file) = link_path(file) else {
        return Link::None;
    };
    match blob_url(repo, known.reviewed_commit(), file, location.line) {
        Some(url) => Link::Url(url),
        None => Link::None,
    }
}

/// The target `file` is in and the file's path inside it: with one covered
/// target, that target and `file` as written; with several, the one whose
/// `<tid>/` starts `file`, and the rest of `file`. `None` when no covered
/// target is among the bounty's `targets`, or none holds the file.
// The returned `&str` borrows from `file` and the `&Target` from `targets`;
// one lifetime `'a` names both, so the result lives as long as the shorter
// of the two borrows, and nothing is copied.
fn target_of<'a>(
    file: &'a str,
    targets: &'a [Target],
    covered: &[TargetId],
) -> Option<(&'a Target, &'a str)> {
    let find = |id: &TargetId| targets.iter().find(|target| target.id() == id);
    // A slice pattern: `[only]` matches a slice of exactly one element.
    if let [only] = covered {
        return Some((find(only)?, file));
    }
    covered.iter().find_map(|id| {
        // `strip_prefix` gives `None` rather than slicing when the prefix is
        // absent, so this is safe on any string.
        let rest = file.strip_prefix(id.as_str())?.strip_prefix('/')?;
        Some((find(id)?, rest))
    })
}

/// The repo a known target names.
// `match` on a `&KnownTarget` binds each view by reference, so nothing is
// copied. No `_` arm: a kind added later does not compile until someone
// decides which repo it links to.
fn repo_of(target: &KnownTarget) -> &RepoName {
    match target {
        KnownTarget::Pr(pr) => pr.repo(),
        KnownTarget::Commit(commit) => commit.repo(),
        KnownTarget::Repo(repo) => repo.repo(),
    }
}

/// `repo`'s owner and name when it is `github.com/<owner>/<name>`, exactly
/// two segments; else `None`. `RepoName` has already limited each segment
/// to `A-Z`, `a-z`, `0-9`, `.`, `_` and `-`.
fn github_repo(repo: &RepoName) -> Option<(&str, &str)> {
    let path = repo.as_str().strip_prefix("github.com/")?;
    let (owner, name) = path.split_once('/')?;
    // A third segment is no GitHub repository.
    (!name.contains('/')).then_some((owner, name))
}

/// `file` when it may go in a link, else `None`.
///
/// The check is lexical, on the text the agent wrote: core's [`RepoPath`]
/// (relative, no empty, `.` or `..` segment, no backslash, no control or
/// reordering character, at most 512 bytes), and further a file rather
/// than a directory (no trailing `/`), no `?` or `#` (which would end the
/// path in a URL if they were ever left unencoded), and nothing
/// `display::sanitize` would change, such as a zero-width character, so the
/// link names the file the line shows.
fn link_path(file: &str) -> Option<&str> {
    let refused = file.ends_with('/')
        || file.contains(['?', '#'])
        || first_changed_char(file, Layout::OneLine).is_some();
    // `is_err` drops the parse error unread: only whether the path passes
    // matters here.
    if refused || file.parse::<RepoPath>().is_err() {
        return None;
    }
    Some(file)
}

/// `https://github.com/<owner>/<name>/blob/<sha>/<file>`, each of
/// `file`'s `/`-separated segments percent-encoded, with
/// `#L<line>` for a line of 1 or more. `None` only if the `url` crate
/// refuses its own fixed base, which it does not.
fn blob_url(
    (owner, name): (&str, &str),
    sha: &GitSha,
    file: &str,
    line: Option<u64>,
) -> Option<String> {
    let mut url = Url::parse("https://github.com/").ok()?;
    {
        // `path_segments_mut` lends the URL's path out as a list of
        // segments: `push` and `extend` percent-encode each one (a space,
        // `%`, `/` and any non-ASCII byte among them), so a segment can
        // never add a `/`, a query or a fragment. The block ends the loan,
        // which is when the path is written back into `url`.
        let mut path = url.path_segments_mut().ok()?;
        path.pop_if_empty()
            .extend([owner, name, "blob", sha.as_str()])
            .extend(file.split('/'));
    }
    // A line of 0 is no line GitHub can show, so it gets no fragment.
    if let Some(line) = line.filter(|&line| line > 0) {
        url.set_fragment(Some(&format!("L{line}")));
    }
    Some(url.into())
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use sweepky_core::{
        Bounty, BountyRef, Findings, SweepFindings, SweepRef, Target, TargetId, group_findings,
    };

    use super::{NO_GITHUB_LINK, render_findings};
    use crate::display::TRUNCATED;
    use crate::test_support::{
        PLANTED, SYNTHETIC_HEAD, SYNTHETIC_SHA, bounty_json, fixture_repo, json_bytes,
        pr_target_json, random_pubky, record_id, repo_target_json,
    };

    /// `fixtures/common/findings.json`: two findings in the common format,
    /// at `src/auth/session.rs:88` and `src/http.rs:12`.
    const COMMON_FINDINGS: &[u8] = include_bytes!("../../../../fixtures/common/findings.json");

    /// The blob URL prefix of `github.com/org/name` at `sha`.
    fn blob(sha: &str) -> String {
        format!("https://github.com/org/name/blob/{sha}/")
    }

    /// The targets of a bounty whose `targets` are `targets`, read back
    /// from the record as `pull` reads it.
    fn targets(targets: Value) -> Vec<Target> {
        Bounty::from_json(&json_bytes(&bounty_json(targets)))
            .expect("a bounty")
            .targets
    }

    fn ids(ids: &[&str]) -> Vec<TargetId> {
        ids.iter()
            .map(|id| id.parse().expect("a target id"))
            .collect()
    }

    /// A findings document of one finding titled `title`, with one
    /// location at `file` and `line`.
    fn one_finding(title: &str, file: &str, line: Option<u64>) -> Findings {
        let document = json!({
            "schemaVersion": 1,
            "playbook": "careful-review",
            "findings": [{
                "id": "one",
                "title": title,
                "status": "needs_validation",
                "locations": [{ "file": file, "line": line, "kind": "sink" }],
                "description": "",
            }],
        });
        Findings::from_json(&json_bytes(&document)).expect("findings")
    }

    /// What `render_findings` prints for `sweeps` (findings and whether
    /// they are trusted, in upload order) of a bounty with `targets`, each
    /// sweep covering the ids at its index in `covered`.
    fn render(
        targets: &[Target],
        sweeps: Vec<(Findings, bool)>,
        covered: &[Vec<TargetId>],
    ) -> String {
        let bounty = BountyRef {
            owner: random_pubky(),
            id: record_id(1),
        };
        let sweeps = sweeps
            .into_iter()
            .zip(1..)
            .map(|((findings, trusted), n)| SweepFindings {
                sweep: SweepRef {
                    sweeper: random_pubky(),
                    id: record_id(n),
                },
                trusted,
                findings,
            })
            .collect();
        let grouped = group_findings(sweeps);
        let covered: Vec<&[TargetId]> = covered.iter().map(Vec::as_slice).collect();
        render_findings(bounty, targets, &grouped.merged(), &covered)
    }

    /// What is printed for one trusted finding at `file` and `line`, in a
    /// sweep of the one repo target `t1` of `github.com/org/name`.
    fn render_location(file: &str, line: Option<u64>) -> String {
        render(
            &targets(json!([repo_target_json("t1")])),
            vec![(one_finding("t", file, line), true)],
            &[ids(&["t1"])],
        )
    }

    #[test]
    fn every_trusted_finding_prints_its_title_status_and_locations_linked_at_the_pinned_sha() {
        let shown = render(
            &targets(json!([repo_target_json("t1")])),
            vec![(
                Findings::from_json(COMMON_FINDINGS).expect("findings"),
                true,
            )],
            &[ids(&["t1"])],
        );
        let sha = SYNTHETIC_SHA;
        for expected in [
            "A session still counts as valid during its expiry second".to_owned(),
            "Header names looked up with a short-circuiting comparison".to_owned(),
            format!(
                "src/auth/session.rs:88 {}src/auth/session.rs#L88",
                blob(sha)
            ),
            format!("src/http.rs:12 {}src/http.rs#L12", blob(sha)),
            "status: needs_validation".to_owned(),
            "reported by 1".to_owned(),
        ] {
            assert!(
                shown.contains(&expected),
                "missing {expected:?} in:\n{shown}"
            );
        }
        // The description is printed; the fix is not.
        assert!(shown.contains("`Session::is_expired` returns"));
        assert!(!shown.contains("Compare with `>=`"));
    }

    #[test]
    fn a_pr_links_at_its_head_and_a_commit_or_repo_at_its_rev_never_at_a_sha_in_the_text() {
        let in_text = "abcdefabcdefabcdefabcdefabcdefabcdefabcd";
        let title = format!("see https://github.com/org/name/blob/{in_text}/x.rs");
        let pr = render(
            &targets(json!([pr_target_json("t1")])),
            vec![(one_finding(&title, "src/x.rs", Some(3)), true)],
            &[ids(&["t1"])],
        );
        assert!(pr.contains(&format!("src/x.rs:3 {}src/x.rs#L3", blob(SYNTHETIC_HEAD))));
        assert!(
            !pr.contains(&blob(SYNTHETIC_SHA)),
            "a pr's base is never linked"
        );

        let commit = json!({
            "id": "t1", "kind": "commit", "repo": "github.com/org/name", "rev": SYNTHETIC_SHA,
        });
        let shown = render(
            &targets(json!([commit])),
            vec![(one_finding(&title, "src/x.rs", Some(3)), true)],
            &[ids(&["t1"])],
        );
        assert!(shown.contains(&format!("src/x.rs:3 {}src/x.rs#L3", blob(SYNTHETIC_SHA))));
        // The title's own link is printed as text, but never built.
        assert!(!shown.contains(&format!("{in_text}/src")));
    }

    #[test]
    fn a_path_that_fails_the_check_prints_sanitised_with_no_link() {
        for (file, shown_as) in [
            ("/etc/passwd", "/etc/passwd:5"),
            ("../x.rs", "../x.rs:5"),
            ("src/../x.rs", "src/../x.rs:5"),
            ("./x.rs", "./x.rs:5"),
            ("src\\x.rs", "src\\\\x.rs:5"),
            ("src/\u{1b}[2Jx.rs", "src/\\u{1b}[2Jx.rs:5"),
            ("src/\u{202e}x.rs", "src/\\u{202e}x.rs:5"),
            ("src//x.rs", "src//x.rs:5"),
            ("src/", "src/:5"),
            ("", ":5"),
            ("src/x.rs?raw=1", "src/x.rs?raw=1:5"),
            ("src/x.rs#L9", "src/x.rs#L9:5"),
        ] {
            let shown = render_location(file, Some(5));
            assert!(
                shown.contains(&format!("at {shown_as}\n")),
                "{file:?}:\n{shown}"
            );
            assert!(!shown.contains("https://"), "{file:?} got a link:\n{shown}");
        }
    }

    #[test]
    fn path_segments_are_percent_encoded_and_a_line_of_zero_or_none_has_no_fragment() {
        let shown = render_location("src/a b/\u{fc}%.rs", Some(3));
        assert!(
            shown.contains(&format!("{}src/a%20b/%C3%BC%25.rs#L3", blob(SYNTHETIC_SHA))),
            "{shown}"
        );
        let zero = render_location("src/x.rs", Some(0));
        assert!(zero.contains(&format!("at src/x.rs:0 {}src/x.rs\n", blob(SYNTHETIC_SHA))));
        let none = render_location("src/x.rs", None);
        assert!(none.contains(&format!("at src/x.rs {}src/x.rs\n", blob(SYNTHETIC_SHA))));
    }

    #[test]
    fn a_repo_not_on_github_prints_the_fixed_no_link_note() {
        for repo in [
            fixture_repo().to_string(),
            "github.com/org/name/extra".to_owned(),
        ] {
            let target = json!({ "id": "t1", "kind": "repo", "repo": repo, "rev": SYNTHETIC_SHA });
            let shown = render(
                &targets(json!([target])),
                vec![(one_finding("t", "src/x.rs", Some(3)), true)],
                &[ids(&["t1"])],
            );
            assert!(
                shown.contains(&format!("at src/x.rs:3 {NO_GITHUB_LINK}\n")),
                "{shown}"
            );
            assert!(!shown.contains("https://"), "{shown}");
        }
    }

    #[test]
    fn a_sweep_of_several_targets_links_only_files_under_a_covered_target_s_directory() {
        let other = json!({
            "id": "t2", "kind": "repo", "repo": "github.com/org/other", "rev": SYNTHETIC_HEAD,
        });
        let both = targets(json!([repo_target_json("t1"), other]));
        let at = |file: &str, covered: &[&str]| {
            render(
                &both,
                vec![(one_finding("t", file, Some(4)), true)],
                &[ids(covered)],
            )
        };
        let linked = at("t2/src/x.rs", &["t1", "t2"]);
        assert!(linked.contains(&format!(
            "at t2/src/x.rs:4 https://github.com/org/other/blob/{SYNTHETIC_HEAD}/src/x.rs#L4\n"
        )));
        for (file, covered) in [
            ("src/x.rs", &["t1", "t2"][..]),
            ("t3/src/x.rs", &["t1", "t2"][..]),
            ("t2/src/x.rs", &[][..]),
        ] {
            let shown = at(file, covered);
            assert!(!shown.contains("https://"), "{file} {covered:?}:\n{shown}");
        }
        // One covered target of the two: its files are relative to it.
        let one = at("src/x.rs", &["t1"]);
        assert!(one.contains(&format!("{}src/x.rs#L4", blob(SYNTHETIC_SHA))));
        // A sweep the caller has no coverage for gets no link.
        let none = render(
            &both,
            vec![(one_finding("t", "src/x.rs", Some(4)), true)],
            &[],
        );
        assert!(!none.contains("https://"));
    }

    #[test]
    fn hostile_text_is_escaped_and_capped() {
        let title = "a\u{1b}]8;;https://evil\u{7}b\rc\u{202e}d\u{200b}e";
        let document = json!({
            "schemaVersion": 1,
            "playbook": "careful-review",
            "findings": [{
                "id": "x",
                "title": title,
                "status": "needs\u{1b}[2J",
                "severity": "high",
                "confidence": "\u{202e}low",
                "locations": [{ "file": "src/x.rs", "line": 1 }],
                "description": format!("line one\r\n\u{1b}[31m{}", "d".repeat(10_000)),
            }],
        });
        let findings = Findings::from_json(&json_bytes(&document)).expect("findings");
        let shown = render(
            &targets(json!([repo_target_json("t1")])),
            vec![(findings, true)],
            &[ids(&["t1"])],
        );
        for raw in ['\u{1b}', '\r', '\u{202e}', '\u{200b}', '\u{7}'] {
            assert!(!shown.contains(raw), "U+{:04X} survived", u32::from(raw));
        }
        assert!(shown.contains("a\\u{1b}]8;;https://evil\\u{7}b\\u{d}c\\u{202e}d\\u{200b}e"));
        assert!(
            shown.contains("status: needs\\u{1b}[2J, severity: high, confidence: \\u{202e}low")
        );
        assert!(shown.contains("line one\\u{d}"));
        assert!(shown.contains(TRUNCATED), "the description is capped");
        assert!(shown.len() < 10_000, "{} bytes", shown.len());
        let long = render_location(&"x".repeat(2_000), Some(1));
        assert!(long.contains(TRUNCATED), "the file is capped");
    }

    #[test]
    fn a_stranger_s_finding_in_a_shared_group_is_counted_but_never_printed() {
        let common = Findings::from_json(COMMON_FINDINGS).expect("findings");
        // At the place of the fixture's first finding, sink and scope
        // alike, so the two group together.
        let stranger = Findings::from_json(&json_bytes(&json!({
            "schemaVersion": 1,
            "playbook": "careful-review",
            "findings": [{
                "id": "planted",
                "title": PLANTED,
                "status": "confirmed",
                "locations": [{
                    "file": "src/auth/session.rs", "line": 88, "kind": "sink",
                    "scope": "fn is_expired",
                }],
                "description": PLANTED,
            }],
        })))
        .expect("findings");
        let shown = render(
            &targets(json!([repo_target_json("t1")])),
            vec![(common, true), (stranger, false)],
            &[ids(&["t1"]), ids(&["t1"])],
        );
        assert!(!shown.contains(PLANTED), "{shown}");
        assert!(shown.contains("reported by 2"), "{shown}");
        assert!(shown.contains("A session still counts as valid"));
    }
}
