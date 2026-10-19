//! The bounty draft that `post` reads: what an owner, or the owner's agent,
//! wants to post, before any target is pinned.
//!
//! The plan never said how a bounty's title, brief and targets reach
//! `post`, so P2b gives it a file, `post <draft.json>`. A file holds a
//! multi-line markdown brief and several targets, and it keeps that text
//! off the command line, where clap would echo it in a usage error. Its
//! shape, every field but the marked ones required:
//!
//! ```text
//! {
//!   "title": "…",        1 to 200 characters
//!   "focus": "…",        optional, `security` when left out; 1 to 64 characters
//!   "brief": "…",        markdown; 1 character to 256 KiB
//!   "playbook": "…",     optional, the playbook the owner suggests; 1 to 512 characters
//!   "targets": [         1 to 32 of them
//!     {
//!       "id": "t1",      optional: t1, t2, … by position
//!       "kind": "repo",  repo, commit or pr
//!       "repo": "github.com/org/name",
//!       "ref": "main",   repo and commit: a branch, a tag, HEAD, refs/… or a full SHA
//!       "paths": ["src/auth/"],  repo only, optional: the whole repository when left out
//!       "number": 42     pr only
//!     }
//!   ]
//! }
//! ```
//!
//! **The draft is untrusted.** An agent writes it, and that agent may have
//! read untrusted code, so this module checks it as strictly as a
//! stranger's record:
//!
//! - It reads at most [`MAX_RECORD_BYTES`] of the file, the most any
//!   Sweepky reads of a public record, and refuses a longer draft before
//!   parsing any of it.
//! - It reads the JSON with `deny_unknown_fields`, so a field it does not
//!   know is an error rather than something to skip: a misspelt `paths`
//!   would otherwise turn a narrow sweep into a sweep of the whole
//!   repository.
//! - An error names the field (`targets[1].ref`) or the position of the
//!   fault, and never quotes the draft. serde's own messages quote values,
//!   so they go through core's `RecordError`, which keeps only the kind of
//!   fault and where it is, as every record parse does.
//! - Every string that becomes public (the title, the brief, the focus and
//!   the suggested playbook) must be text the terminal sanitiser leaves
//!   unchanged: `display::sanitize` for the one-line fields and
//!   `display::sanitize_multiline` for the brief, which keeps newlines and
//!   tabs. Core checks none of them (a focus and a suggestion are open
//!   strings), and `run` and the board print them, so nothing `post`
//!   publishes can drive a reader's terminal or read differently there. A
//!   backslash is refused too, because the sanitiser doubles it.
//! - Every target field becomes a checked type before it is used
//!   ([`TargetId`], [`RepoName`], `RevSpec`, [`RepoPath`] and a non-zero
//!   number), so git and the target source never see anything else.

use std::fs::File;
use std::num::NonZeroU64;
use std::path::Path;

use anyhow::{Context as _, bail};
use serde::Deserialize;
use sweepky_core::{
    Bounty, BountyPlaybook, Focus, KnownFocus, KnownTargetKind, MAX_RECORD_BYTES, RecordError,
    RecordTime, RepoName, RepoPath, Target, TargetId, TargetKind, UnknownFields,
};

use crate::display::{Layout, TextPosition, first_changed_char};
use crate::private_fs::read_up_to_cap;
use crate::targets::rev::RevSpec;

/// The most characters a bounty's title may have.
pub(crate) const MAX_TITLE_CHARS: usize = 200;

/// The most bytes a bounty's brief may have: 256 KiB, a long document,
/// and a quarter of [`MAX_RECORD_BYTES`], so that even with JSON writing
/// each newline or quote in two bytes it leaves most of the record for the
/// rest of the bounty.
pub(crate) const MAX_BRIEF_BYTES: usize = 256 * 1024;

/// The most characters a bounty's focus may have, as many as a label.
pub(crate) const MAX_FOCUS_CHARS: usize = 64;

/// The most characters a suggested playbook may have: room for a URL.
pub(crate) const MAX_PLAYBOOK_CHARS: usize = 512;

/// The most targets a draft may have. P2b's choice: `post` pins each one
/// with a git run, and a pull request with two of the 60 requests an hour
/// GitHub allows an anonymous address, so an agent-written draft cannot
/// ask for unbounded work.
pub(crate) const MAX_TARGETS: usize = 32;

/// Reads and checks the bounty draft at `path`: at most
/// [`MAX_RECORD_BYTES`] of it, then [`BountyDraft::parse`].
///
/// The path is the caller's own choice, so it is opened as given, a
/// symlink followed; a pipe from process substitution works too. The
/// errors never name it, and the system's errors never quote the file.
pub(crate) fn read_draft(path: &Path) -> anyhow::Result<BountyDraft> {
    let mut file = File::open(path).context("could not open the bounty draft")?;
    // One byte past the cap, so a longer draft is seen to be longer without
    // reading the rest of it. The helper fills a buffer of exactly that
    // size and never grows it; it wipes it on drop too, which a draft does
    // not need, but costs nothing.
    let bytes = read_up_to_cap(&mut file, MAX_RECORD_BYTES + 1)
        .context("could not read the bounty draft")?;
    // `&bytes` is a `&Zeroizing<Vec<u8>>`, read as a `&[u8]` through
    // `Deref`.
    BountyDraft::parse(&bytes)
}

/// A checked bounty draft: every field passed the checks in the module's
/// docs, and no target is pinned yet.
///
/// The fields are private and [`parse`](Self::parse) is the only way to
/// make one, so holding a `BountyDraft` means the checks ran.
#[derive(Debug)]
pub(crate) struct BountyDraft {
    title: String,
    focus: Focus,
    brief: String,
    /// The suggested playbook, if the draft names one.
    playbook: Option<String>,
    targets: Vec<UnpinnedTarget>,
}

impl BountyDraft {
    /// Parses and checks a draft. Refuses `bytes` longer than
    /// [`MAX_RECORD_BYTES`] before looking at any of them, then anything
    /// the module's docs list, each error naming a field or a position and
    /// quoting nothing.
    pub(crate) fn parse(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() > MAX_RECORD_BYTES {
            bail!(
                "the bounty draft is longer than {MAX_RECORD_BYTES} bytes, the most Sweepky reads"
            );
        }
        // `RecordError::from` keeps only the kind of fault and its line and
        // column, and drops serde's message, which can quote the draft.
        let file: DraftFile = serde_json::from_slice(bytes)
            .map_err(RecordError::from)
            .context("the bounty draft is not valid")?;
        file.check()
    }

    /// The targets, in the draft's order.
    // A borrowed slice: the caller reads them, and the draft keeps them.
    pub(crate) fn targets(&self) -> &[UnpinnedTarget] {
        &self.targets
    }

    /// What `post` warns of before it asks: one line for each repo target
    /// with no paths, whose sweep of the whole repository can outlast a
    /// 5-hour plan window (01, "Target kinds").
    pub(crate) fn warnings(&self) -> Vec<String> {
        self.targets
            .iter()
            .enumerate()
            // A match guard (`if …`) inside `matches!`: a repo target, and
            // only when its paths are empty.
            .filter(|(_, target)| {
                matches!(&target.kind, UnpinnedKind::Repo { paths, .. } if paths.is_empty())
            })
            .map(|(index, _)| {
                format!(
                    "targets[{index}] has no paths, so it asks for a sweep of the whole \
                     repository, which can outlast a 5-hour plan window; give it paths to \
                     narrow it"
                )
            })
            .collect()
    }

    /// The bounty `post` publishes: this draft's text with `targets`, its
    /// targets pinned in the same order, posted at `created_at`. Open,
    /// closed to strangers, nobody credited, no reward, and the suggested
    /// playbook never required (`Bounty::new`).
    // `self`, not `&self`: the title, focus, brief and playbook move into
    // the bounty without a copy, and the draft is used up.
    pub(crate) fn into_bounty(self, targets: Vec<Target>, created_at: RecordTime) -> Bounty {
        let playbook = BountyPlaybook {
            suggested: self.playbook,
            required: false,
            extra: UnknownFields::new(),
        };
        Bounty::new(
            self.title, self.focus, self.brief, playbook, targets, created_at,
        )
    }
}

/// One target of a draft, checked and not yet pinned: what `post` asks the
/// target source to pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnpinnedTarget {
    /// The target's id: the draft's, or `t<n>` for the `n`th target.
    pub(crate) id: TargetId,
    /// The repository.
    pub(crate) repo: RepoName,
    /// What to pin in it.
    pub(crate) kind: UnpinnedKind,
}

/// What a target asks to be pinned, by kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UnpinnedKind {
    /// A repository's tree at `rev`, narrowed to `paths`; no paths is the
    /// whole repository, as in `Target::repo`.
    Repo { rev: RevSpec, paths: Vec<RepoPath> },
    /// The commit `rev` names.
    Commit { rev: RevSpec },
    /// Pull request `number`.
    Pr { number: NonZeroU64 },
}

impl UnpinnedKind {
    /// The kind, as core names it.
    pub(crate) fn known(&self) -> KnownTargetKind {
        match self {
            Self::Repo { .. } => KnownTargetKind::Repo,
            Self::Commit { .. } => KnownTargetKind::Commit,
            Self::Pr { .. } => KnownTargetKind::Pr,
        }
    }
}

/// The draft file as JSON gives it, before any check.
///
/// `deny_unknown_fields` makes a key this struct does not name an error.
/// Every field is an `Option`, the required ones too, so that a missing
/// one is refused by name ("the draft has no title") rather than by
/// position; serde reads a missing `Option` field as `None`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftFile {
    title: Option<String>,
    // `Focus` is core's open label, a `String` underneath, which serde
    // reads from any JSON string; it is checked below like the others.
    focus: Option<Focus>,
    brief: Option<String>,
    playbook: Option<String>,
    targets: Option<Vec<TargetEntry>>,
}

/// One entry of the draft's `targets`, as JSON gives it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetEntry {
    id: Option<String>,
    // Core's open `kind`, so an unknown kind is refused below by name
    // rather than by serde by position.
    kind: Option<TargetKind>,
    repo: Option<String>,
    // `ref` is a Rust keyword, so the field is `rev` and serde reads it
    // from the JSON key `ref`.
    #[serde(rename = "ref")]
    rev: Option<String>,
    paths: Option<Vec<String>>,
    number: Option<u64>,
}

impl DraftFile {
    fn check(self) -> anyhow::Result<BountyDraft> {
        // Taking the struct apart moves each field into its own variable,
        // with no copy, and names every field, so one added later does
        // not compile until it is checked here.
        let Self {
            title,
            focus,
            brief,
            playbook,
            targets,
        } = self;
        let title = required(title, "title")?;
        check_one_line("title", &title, MAX_TITLE_CHARS)?;
        let brief = required(brief, "brief")?;
        check_brief(&brief)?;
        // No focus is a security review, the first use case (00).
        let focus = focus.unwrap_or_else(|| KnownFocus::Security.into());
        check_one_line("focus", focus.as_str(), MAX_FOCUS_CHARS)?;
        if let Some(playbook) = &playbook {
            check_one_line("playbook", playbook, MAX_PLAYBOOK_CHARS)?;
        }
        let targets = check_targets(required(targets, "targets")?)?;
        Ok(BountyDraft {
            title,
            focus,
            brief,
            playbook,
            targets,
        })
    }
}

/// `value`, or an error that names the missing `field`.
fn required<T>(value: Option<T>, field: &str) -> anyhow::Result<T> {
    value.with_context(|| format!("the draft has no {field}"))
}

/// Checks `text`, the draft's one-line public `field`: not blank, at most
/// `max_chars` characters, and text `display::sanitize` leaves unchanged.
fn check_one_line(field: &str, text: &str, max_chars: usize) -> anyhow::Result<()> {
    refuse_blank(field, text)?;
    let chars = text.chars().count();
    if chars > max_chars {
        bail!("the draft's {field} is {chars} characters, over the {max_chars}-character limit");
    }
    refuse_changed(field, text, Layout::OneLine)
}

/// Checks the draft's brief: not blank, at most [`MAX_BRIEF_BYTES`], and
/// text `display::sanitize_multiline` leaves unchanged.
fn check_brief(brief: &str) -> anyhow::Result<()> {
    refuse_blank("brief", brief)?;
    if brief.len() > MAX_BRIEF_BYTES {
        bail!(
            "the draft's brief is {} bytes, over the {MAX_BRIEF_BYTES}-byte limit",
            brief.len()
        );
    }
    refuse_changed("brief", brief, Layout::MultiLine)
}

/// Refuses `text` when it is empty or only whitespace: a public field
/// that says nothing.
fn refuse_blank(field: &str, text: &str) -> anyhow::Result<()> {
    if text.trim().is_empty() {
        bail!("the draft's {field} is empty");
    }
    Ok(())
}

/// Refuses `text` when the sanitiser for `layout` would print any of it
/// otherwise than as written, saying where and never what.
fn refuse_changed(field: &str, text: &str, layout: Layout) -> anyhow::Result<()> {
    let Some(TextPosition { line, column }) = first_changed_char(text, layout) else {
        return Ok(());
    };
    let controls = match layout {
        Layout::OneLine => "a control character",
        Layout::MultiLine => "a control character other than newline and tab",
    };
    bail!(
        "the draft's {field} has a character at line {line}, column {column} that would not \
         print as written: a backslash, {controls}, or a bidi, invisible or other formatting \
         character"
    )
}

/// Checks the draft's targets: 1 to [`MAX_TARGETS`] of them, each one
/// whole, and no two ids the same when case is ignored.
fn check_targets(entries: Vec<TargetEntry>) -> anyhow::Result<Vec<UnpinnedTarget>> {
    if entries.is_empty() {
        bail!("the draft's targets list is empty; a bounty needs at least one target");
    }
    if entries.len() > MAX_TARGETS {
        bail!(
            "the draft has {} targets, over the {MAX_TARGETS}-target limit",
            entries.len()
        );
    }
    // Collecting an iterator of `Result`s into a `Result<Vec<_>, _>` stops
    // at the first `Err` and returns it.
    let targets = entries
        .into_iter()
        .enumerate()
        .map(|(index, entry)| entry.check(index))
        .collect::<anyhow::Result<Vec<_>>>()?;
    refuse_case_colliding_ids(&targets)?;
    Ok(targets)
}

impl TargetEntry {
    /// Checks the entry at `index` of the draft's `targets`. Every message
    /// names the target by its place in the list, `targets[0]`, never by
    /// anything the draft wrote.
    fn check(self, index: usize) -> anyhow::Result<UnpinnedTarget> {
        let Self {
            id,
            kind,
            repo,
            rev,
            paths,
            number,
        } = self;
        let id = match id {
            Some(id) => id.parse().with_context(|| format!("targets[{index}].id"))?,
            None => default_id(index)?,
        };
        let kind = kind.with_context(|| format!("targets[{index}] has no kind"))?;
        let repo = repo
            .with_context(|| format!("targets[{index}] has no repo"))?
            .parse()
            .with_context(|| format!("targets[{index}].repo"))?;
        // Each kind takes its own fields and refuses the others', so a
        // draft cannot think it narrowed a commit with paths.
        let kind = match kind.as_known() {
            Some(KnownTargetKind::Repo) => {
                refuse_foreign(number.is_some(), index, "number", KnownTargetKind::Repo)?;
                UnpinnedKind::Repo {
                    rev: checked_rev(rev, index, KnownTargetKind::Repo)?,
                    paths: checked_paths(paths, index)?,
                }
            }
            Some(KnownTargetKind::Commit) => {
                refuse_foreign(paths.is_some(), index, "paths", KnownTargetKind::Commit)?;
                refuse_foreign(number.is_some(), index, "number", KnownTargetKind::Commit)?;
                UnpinnedKind::Commit {
                    rev: checked_rev(rev, index, KnownTargetKind::Commit)?,
                }
            }
            Some(KnownTargetKind::Pr) => {
                refuse_foreign(rev.is_some(), index, "ref", KnownTargetKind::Pr)?;
                refuse_foreign(paths.is_some(), index, "paths", KnownTargetKind::Pr)?;
                UnpinnedKind::Pr {
                    number: checked_number(number, index)?,
                }
            }
            None => bail!("targets[{index}].kind is not repo, commit or pr"),
        };
        Ok(UnpinnedTarget { id, repo, kind })
    }
}

/// The id of the target at `index` when the draft gives none: `t1` for
/// the first, `t2` for the second, and so on.
fn default_id(index: usize) -> anyhow::Result<TargetId> {
    // At most `t32`, always a valid id; `?` still turns the error that
    // cannot happen into an error rather than a panic.
    Ok(format!("t{}", index + 1).parse()?)
}

/// Refuses `field` of `targets[index]` when the draft gave it (`given`):
/// a target of `kind` has no such field.
fn refuse_foreign(
    given: bool,
    index: usize,
    field: &str,
    kind: KnownTargetKind,
) -> anyhow::Result<()> {
    if given {
        bail!(
            "targets[{index}].{field} is not a field of a {} target",
            kind.as_str()
        );
    }
    Ok(())
}

/// The `ref` of `targets[index]`, a target of `kind`, checked.
fn checked_rev(
    rev: Option<String>,
    index: usize,
    kind: KnownTargetKind,
) -> anyhow::Result<RevSpec> {
    let rev = rev.with_context(|| {
        format!(
            "targets[{index}] has no ref; a {} target needs the revision to pin: a branch, a \
             tag, HEAD, a full ref name or a full SHA",
            kind.as_str()
        )
    })?;
    rev.parse().with_context(|| format!("targets[{index}].ref"))
}

/// The `paths` of `targets[index]`, checked: none is the whole
/// repository, an empty list is refused because it would narrow the sweep
/// to nothing.
fn checked_paths(paths: Option<Vec<String>>, index: usize) -> anyhow::Result<Vec<RepoPath>> {
    let Some(paths) = paths else {
        return Ok(Vec::new());
    };
    if paths.is_empty() {
        bail!("targets[{index}].paths is empty; leave it out to sweep the whole repository");
    }
    paths
        .into_iter()
        .enumerate()
        // `try_from` checks each `String` and keeps it, with no copy.
        .map(|(n, path)| {
            RepoPath::try_from(path).with_context(|| format!("targets[{index}].paths[{n}]"))
        })
        .collect()
}

/// The `number` of `targets[index]`, a pull request target, checked.
fn checked_number(number: Option<u64>, index: usize) -> anyhow::Result<NonZeroU64> {
    let number = number.with_context(|| {
        format!("targets[{index}] has no number; a pr target needs the pull request's number")
    })?;
    // `NonZeroU64::new` is `None` for 0, which no pull request is.
    NonZeroU64::new(number).with_context(|| format!("targets[{index}].number must be 1 or more"))
}

/// Refuses two targets whose ids are the same when ASCII case is ignored,
/// such as `t1` and `T1`: `run` makes a directory per target id, and on a
/// case-insensitive filesystem, macOS's default, those are one directory.
fn refuse_case_colliding_ids(targets: &[UnpinnedTarget]) -> anyhow::Result<()> {
    for (later, target) in targets.iter().enumerate() {
        // Only the targets before this one, so each pair is compared once.
        // At most 32 targets, so comparing every pair is cheap.
        let earlier = targets
            .iter()
            .take(later)
            .position(|other| other.id.eq_ignore_ascii_case(&target.id));
        if let Some(earlier) = earlier {
            bail!(
                "targets[{earlier}] and targets[{later}] have the same id when case is ignored, \
                 so they would share one directory on a case-insensitive filesystem; give them \
                 distinct ids"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use serde_json::{Value, json};
    use sweepky_core::{KnownFocus, MAX_RECORD_BYTES, RepoName, RepoPath, TargetId};

    use super::{
        BountyDraft, MAX_BRIEF_BYTES, MAX_FOCUS_CHARS, MAX_PLAYBOOK_CHARS, MAX_TARGETS,
        MAX_TITLE_CHARS, UnpinnedKind, UnpinnedTarget, read_draft,
    };
    use crate::display::{sanitize, sanitize_multiline};
    use crate::test_support::private_temp;

    /// Text planted in a bad draft, which no error may repeat.
    const MARKER: &str = "MARKER-d1a7";
    const REPO: &str = "example.invalid/org/name";
    const TITLE: &str = "Auth and session handling before the 0.15 release";
    const BRIEF: &str = "# What to look for\n\n- session tokens\n\t- their expiry\n";
    const PLAYBOOK: &str = "cloudflare/security-audit@c1c8a8c";

    /// A valid draft with one target of each kind: a repo target with a
    /// ref and paths, a commit target with a ref and a pr target with a
    /// number. No ids and no focus, so both take their defaults.
    fn valid() -> Value {
        json!({
            "title": TITLE,
            "brief": BRIEF,
            "playbook": PLAYBOOK,
            "targets": [
                { "kind": "repo", "repo": REPO, "ref": "main", "paths": ["src/auth/"] },
                { "kind": "commit", "repo": REPO, "ref": "main" },
                { "kind": "pr", "repo": REPO, "number": 1 },
            ],
        })
    }

    fn parse(draft: &Value) -> anyhow::Result<BountyDraft> {
        BountyDraft::parse(draft.to_string().as_bytes())
    }

    /// `draft` with `field` set to `value`.
    fn with(mut draft: Value, field: &str, value: Value) -> Value {
        draft[field] = value;
        draft
    }

    /// `draft` with `field` of its target `index` set to `value`.
    fn with_target(mut draft: Value, index: usize, field: &str, value: Value) -> Value {
        draft["targets"][index][field] = value;
        draft
    }

    /// `draft` without its top-level `field`.
    fn without(mut draft: Value, field: &str) -> Value {
        draft.as_object_mut().expect("an object").remove(field);
        draft
    }

    /// `draft` without `field` of its target `index`.
    fn without_target(mut draft: Value, index: usize, field: &str) -> Value {
        draft["targets"][index]
            .as_object_mut()
            .expect("an object")
            .remove(field);
        draft
    }

    /// The refusal of `draft`, as `main.rs` would print it, after checking
    /// that neither it nor its `Debug` repeats [`MARKER`].
    fn refusal(draft: &Value) -> String {
        let error = parse(draft).expect_err("refused");
        let message = format!("{error:#}");
        assert!(!message.contains(MARKER), "{message}");
        assert!(!format!("{error:?}").contains(MARKER), "{error:?}");
        message
    }

    fn id(text: &str) -> TargetId {
        text.parse().expect("a target id")
    }

    fn repo() -> RepoName {
        REPO.parse().expect("a repo name")
    }

    #[test]
    fn a_valid_draft_with_each_target_kind_parses() {
        let draft = parse(&valid()).expect("a valid draft");
        assert_eq!(draft.title, TITLE);
        assert_eq!(draft.brief, BRIEF);
        // No focus given: `security`, the first use case.
        assert_eq!(draft.focus.as_known(), Some(KnownFocus::Security));
        assert_eq!(draft.playbook.as_deref(), Some(PLAYBOOK));
        let main = || "main".parse().expect("a rev");
        let paths: Vec<RepoPath> = vec!["src/auth/".parse().expect("a path")];
        assert_eq!(
            draft.targets,
            [
                UnpinnedTarget {
                    id: id("t1"),
                    repo: repo(),
                    kind: UnpinnedKind::Repo { rev: main(), paths },
                },
                UnpinnedTarget {
                    id: id("t2"),
                    repo: repo(),
                    kind: UnpinnedKind::Commit { rev: main() },
                },
                UnpinnedTarget {
                    id: id("t3"),
                    repo: repo(),
                    kind: UnpinnedKind::Pr {
                        number: NonZeroU64::MIN,
                    },
                },
            ]
        );
    }

    #[test]
    fn a_draft_that_is_not_the_shape_is_refused_by_position() {
        // An unknown field, at the top or in a target, a value of the wrong
        // type, a repeated field, and bytes that are not JSON: serde's own
        // message would quote the field or the value, so the refusal gives
        // only the kind of fault and where it is.
        let unknown_top = with(valid(), MARKER, json!(1));
        let unknown_in_target = with_target(valid(), 0, MARKER, json!(1));
        let wrong_type = with(valid(), "title", json!([MARKER]));
        let repeated = valid().to_string().replacen(
            "\"title\":",
            &format!("\"title\":\"{MARKER}\",\"title\":"),
            1,
        );
        let truncated = format!(r#"{{"title":"{MARKER}"#);
        let trailing = format!("{} {MARKER}", valid());
        for input in [
            unknown_top.to_string(),
            unknown_in_target.to_string(),
            wrong_type.to_string(),
            repeated,
            truncated,
            trailing,
        ] {
            let error = BountyDraft::parse(input.as_bytes()).expect_err(&input);
            let message = format!("{error:#}");
            assert!(message.contains("line 1, column"), "{message}");
            assert!(!message.contains(MARKER), "{message}");
        }
    }

    #[test]
    fn a_missing_field_is_refused_by_name() {
        for (draft, field) in [
            (without(valid(), "title"), "title"),
            (without(valid(), "brief"), "brief"),
            (without(valid(), "targets"), "targets"),
            (without_target(valid(), 0, "kind"), "targets[0] has no kind"),
            (without_target(valid(), 1, "repo"), "targets[1] has no repo"),
            (without_target(valid(), 0, "ref"), "targets[0] has no ref"),
            (without_target(valid(), 1, "ref"), "targets[1] has no ref"),
            (
                without_target(valid(), 2, "number"),
                "targets[2] has no number",
            ),
        ] {
            let message = refusal(&draft);
            assert!(message.contains(field), "{field}: {message}");
        }
    }

    #[test]
    fn a_bad_target_field_is_refused_by_name_without_quoting_it() {
        for (draft, field) in [
            (
                with_target(valid(), 0, "kind", json!(MARKER)),
                "targets[0].kind",
            ),
            (
                with_target(valid(), 0, "repo", json!(MARKER)),
                "targets[0].repo",
            ),
            (
                with_target(
                    valid(),
                    1,
                    "repo",
                    json!(format!("https://{MARKER}.example/a/b")),
                ),
                "targets[1].repo",
            ),
            (
                with_target(valid(), 0, "ref", json!(format!("{MARKER}..main"))),
                "targets[0].ref",
            ),
            (
                with_target(valid(), 1, "ref", json!(format!("-{MARKER}"))),
                "targets[1].ref",
            ),
            (
                with_target(valid(), 0, "id", json!(format!("-{MARKER}"))),
                "targets[0].id",
            ),
            (
                with_target(valid(), 0, "paths", json!(["src/", format!("../{MARKER}")])),
                "targets[0].paths[1]",
            ),
            (
                with_target(valid(), 2, "number", json!(0)),
                "targets[2].number",
            ),
            // A field that belongs to another kind.
            (
                with_target(valid(), 2, "ref", json!("main")),
                "targets[2].ref",
            ),
            (
                with_target(valid(), 1, "paths", json!(["src/"])),
                "targets[1].paths",
            ),
            (
                with_target(valid(), 0, "number", json!(1)),
                "targets[0].number",
            ),
        ] {
            let message = refusal(&draft);
            assert!(message.contains(field), "{field}: {message}");
        }
    }

    #[test]
    fn a_draft_over_the_record_cap_is_refused_before_parsing() {
        // A valid draft padded with JSON whitespace: at the cap it parses,
        // one byte more is refused.
        let mut bytes = valid().to_string().into_bytes();
        bytes.resize(MAX_RECORD_BYTES, b' ');
        assert!(BountyDraft::parse(&bytes).is_ok());
        bytes.push(b' ');
        let over = format!(
            "{:#}",
            BountyDraft::parse(&bytes).expect_err("over the cap")
        );
        assert!(over.contains(&MAX_RECORD_BYTES.to_string()), "{over}");
        // Not JSON at all: the size check answers, so the parser never ran.
        let junk = vec![b'['; MAX_RECORD_BYTES + 1];
        let error = BountyDraft::parse(&junk).expect_err("over the cap");
        assert_eq!(format!("{error:#}"), over);
    }

    #[test]
    fn read_draft_reads_a_file_up_to_the_cap() {
        let temp = private_temp();
        let path = temp.path().join("draft.json");
        std::fs::write(&path, valid().to_string()).expect("written");
        assert_eq!(read_draft(&path).expect("read").title, TITLE);

        // A file one byte over the cap: refused, as the same bytes are.
        let mut bytes = valid().to_string().into_bytes();
        bytes.resize(MAX_RECORD_BYTES + 1, b' ');
        std::fs::write(&path, &bytes).expect("written");
        let error = read_draft(&path).expect_err("over the cap");
        assert!(
            format!("{error:#}").contains(&MAX_RECORD_BYTES.to_string()),
            "{error:#}"
        );
        // No file there at all.
        assert!(read_draft(&temp.path().join("missing.json")).is_err());
    }

    /// Characters the sanitiser would change in any field: a backslash,
    /// which it doubles, then ESC, CR, a bidi override, a zero-width space,
    /// and a byte-order mark, which it escapes.
    const CHANGED_EVERYWHERE: [char; 6] =
        ['\\', '\u{1b}', '\r', '\u{202e}', '\u{200b}', '\u{feff}'];

    #[test]
    fn the_title_is_1_to_200_characters_the_sanitiser_leaves_unchanged() {
        let accepted = [
            "x".to_owned(),
            "x".repeat(MAX_TITLE_CHARS),
            // Counted in characters, not bytes: 200 of them are 400 bytes.
            "\u{e9}".repeat(MAX_TITLE_CHARS),
            "caf\u{e9} \u{65e5}\u{672c} \u{1f600}".to_owned(),
        ];
        let mut refused = vec![
            String::new(),
            "   ".to_owned(),
            "x".repeat(MAX_TITLE_CHARS + 1),
            // One line: newline and tab are changed here.
            format!("a\n{MARKER}"),
            format!("a\t{MARKER}"),
        ];
        refused.extend(CHANGED_EVERYWHERE.map(|c| format!("a{c}{MARKER}")));
        check_text_field("title", &accepted, &refused, |text| {
            sanitize(text, MAX_TITLE_CHARS) == text
        });
    }

    #[test]
    fn the_brief_is_1_character_to_256_kib_the_multiline_sanitiser_leaves_unchanged() {
        let accepted = [
            "x".to_owned(),
            "x".repeat(MAX_BRIEF_BYTES),
            // Newlines and tabs are what a markdown brief is made of.
            "# Scope\n\n\tsrc/auth/\n- tokens\n".to_owned(),
        ];
        let mut refused = vec![
            String::new(),
            "\n\n".to_owned(),
            "x".repeat(MAX_BRIEF_BYTES + 1),
        ];
        refused.extend(CHANGED_EVERYWHERE.map(|c| format!("line one\nline {c}{MARKER}")));
        check_text_field("brief", &accepted, &refused, |text| {
            sanitize_multiline(text, MAX_BRIEF_BYTES) == text
        });
    }

    #[test]
    fn focus_defaults_to_security_and_is_an_open_label_of_1_to_64_characters() {
        let accepted = [
            "bugs".to_owned(),
            // A label this build does not name is as valid.
            "a11y".to_owned(),
            "x".repeat(MAX_FOCUS_CHARS),
        ];
        let mut refused = vec![
            String::new(),
            "x".repeat(MAX_FOCUS_CHARS + 1),
            format!("a\n{MARKER}"),
        ];
        refused.extend(CHANGED_EVERYWHERE.map(|c| format!("a{c}{MARKER}")));
        check_text_field("focus", &accepted, &refused, |text| {
            sanitize(text, MAX_FOCUS_CHARS) == text
        });
        let draft = parse(&with(valid(), "focus", json!("a11y"))).expect("valid");
        assert_eq!(draft.focus.as_str(), "a11y");
        assert_eq!(draft.focus.as_known(), None);
    }

    #[test]
    fn the_playbook_suggestion_is_optional_and_1_to_512_characters() {
        let accepted = [
            PLAYBOOK.to_owned(),
            // A suggestion may be a URL or a procedure, not only a name.
            "https://example.invalid/our-review-checklist".to_owned(),
            "x".repeat(MAX_PLAYBOOK_CHARS),
        ];
        let mut refused = vec![
            String::new(),
            "x".repeat(MAX_PLAYBOOK_CHARS + 1),
            format!("a\n{MARKER}"),
        ];
        refused.extend(CHANGED_EVERYWHERE.map(|c| format!("a{c}{MARKER}")));
        check_text_field("playbook", &accepted, &refused, |text| {
            sanitize(text, MAX_PLAYBOOK_CHARS) == text
        });
        let draft = parse(&without(valid(), "playbook")).expect("valid");
        assert_eq!(draft.playbook, None);
    }

    /// Checks that the draft's `field` takes every value of `accepted` as
    /// it is and refuses every value of `refused` with a message that names
    /// the field and quotes nothing; and, for every value but the blank and
    /// over-long ones, that the check agrees with `unchanged`, the
    /// sanitiser leaving the value as it is.
    fn check_text_field(
        field: &str,
        accepted: &[String],
        refused: &[String],
        unchanged: impl Fn(&str) -> bool,
    ) {
        for value in accepted {
            let draft = parse(&with(valid(), field, json!(value)))
                .unwrap_or_else(|error| panic!("{field}: {error:#}"));
            let kept = match field {
                "title" => draft.title,
                "brief" => draft.brief,
                "focus" => draft.focus.as_str().to_owned(),
                "playbook" => draft.playbook.expect("a suggestion"),
                _ => unreachable!("a text field"),
            };
            assert_eq!(&kept, value, "{field}");
            assert!(unchanged(value), "{field}: the sanitiser changes it");
        }
        for value in refused {
            let message = refusal(&with(valid(), field, json!(value)));
            assert!(message.contains(field), "{field}: {message}");
            if value.contains(MARKER) {
                assert!(!unchanged(value), "{field}: the sanitiser keeps it");
                // Where the character is, never what it is.
                assert!(message.contains("line "), "{field}: {message}");
            }
        }
    }

    #[test]
    fn target_ids_default_by_position_and_must_differ_ignoring_case() {
        let draft = parse(&with_target(valid(), 1, "id", json!("auth-head"))).expect("valid");
        let ids: Vec<&str> = draft.targets.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, ["t1", "auth-head", "t3"]);

        // `T1` and the default `t1`, or `x` and `X`: one directory on a
        // case-insensitive filesystem.
        let upper = with_target(valid(), 1, "id", json!("T1"));
        let both = with_target(
            with_target(valid(), 0, "id", json!("x")),
            2,
            "id",
            json!("X"),
        );
        for (draft, pair) in [
            (upper, "targets[0] and targets[1]"),
            (both, "targets[0] and targets[2]"),
        ] {
            let message = refusal(&draft);
            assert!(message.contains(pair), "{message}");
        }
    }

    #[test]
    fn the_targets_list_is_1_to_32_targets_and_paths_is_never_empty() {
        let one = json!([{ "kind": "commit", "repo": REPO, "ref": "main" }]);
        assert!(parse(&with(valid(), "targets", one.clone())).is_ok());
        let most = Value::Array(vec![one[0].clone(); MAX_TARGETS]);
        assert!(parse(&with(valid(), "targets", most)).is_ok());

        let too_many = Value::Array(vec![one[0].clone(); MAX_TARGETS + 1]);
        for draft in [
            with(valid(), "targets", json!([])),
            with(valid(), "targets", too_many),
        ] {
            assert!(refusal(&draft).contains("targets"));
        }
        // An empty list would narrow the sweep to nothing; leaving `paths`
        // out is how a draft asks for the whole repository.
        let empty_paths = with_target(valid(), 0, "paths", json!([]));
        assert!(refusal(&empty_paths).contains("targets[0].paths"));
    }

    #[test]
    fn a_repo_target_without_paths_warns_of_the_plan_window() {
        let whole = without_target(valid(), 0, "paths");
        let warnings = parse(&whole).expect("valid").warnings();
        let [warning] = warnings.as_slice() else {
            panic!("one warning: {warnings:?}");
        };
        assert!(warning.contains("targets[0]"), "{warning}");
        assert!(warning.contains("5-hour plan window"), "{warning}");
        // Paths given, and a commit or pr target: nothing to warn of.
        assert_eq!(
            parse(&valid()).expect("valid").warnings(),
            Vec::<String>::new()
        );
    }
}
