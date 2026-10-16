//! [`Target`], one entry of a bounty's `targets`, and the typed views of the
//! kinds this build knows: [`PrTarget`], [`CommitTarget`] and [`RepoTarget`].
//!
//! A target is read in two steps, because 01 asks for two different things:
//!
//! 1. **Reading the bounty** reads each target as a [`Target`]: its `id`, its
//!    open-string `kind`, and every other field kept as raw JSON. That step
//!    fails only when the target is not a JSON object, `id` or `kind` is
//!    missing or not a string, or `id` breaks [`TargetId`]'s limits, so a
//!    kind this build has never heard of, or a known kind with a bad field,
//!    does not reject the bounty. And because the fields are kept as they
//!    were, writing the bounty back (as `sweepky done` does) drops nothing.
//! 2. **Using a target** calls [`Target::known`], which checks the fields of
//!    a known kind and returns its typed view. An unknown kind is `Ok(None)`
//!    and a malformed known one is an `Err`; either way the caller skips that
//!    target and shows a placeholder, as 01 says to do with an unknown kind.
//!
//! The typed views hold only checked values ([`RepoName`], [`GitSha`],
//! [`RepoPath`] and a non-zero pull request number), and their fields are
//! private, so holding one means [`Target::known`] passed. The scope handed
//! to the skill (`scope.rs`) is built from these views alone, never from the
//! raw fields, so text a hostile bounty puts in a target never reaches a git
//! command or the skill's request.

use std::num::NonZeroU64;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::RecordError;
use crate::names::{GitSha, RepoName, RepoPath, TargetId};
use crate::open_enum::open_enum;
use crate::schema::UnknownFields;

open_enum! {
    /// A target's `kind`: what the target points at.
    ///
    /// Open, so a newer client can add a kind (01 defers a `crate` kind)
    /// without breaking this build: such a target still parses, and
    /// [`Target::known`] skips it.
    pub struct TargetKind;

    /// The target kinds this build knows.
    pub enum KnownTargetKind {
        /// A GitHub pull request: [`PrTarget`].
        Pr = "pr",
        /// One commit: [`CommitTarget`].
        Commit = "commit",
        /// A repository's tree at one commit: [`RepoTarget`].
        Repo = "repo",
    }
}

// The JSON keys of the kinds' fields. The constructors write them and
// `Target::known` reads them, so the two cannot drift apart by a typo. A
// module of their own makes each use read `key::REPO`: a key, not a repository.
mod key {
    pub(super) const REPO: &str = "repo";
    pub(super) const NUMBER: &str = "number";
    pub(super) const BASE: &str = "base";
    pub(super) const HEAD: &str = "head";
    pub(super) const MERGE_BASE: &str = "mergeBase";
    pub(super) const REV: &str = "rev";
    pub(super) const PATHS: &str = "paths";
}

/// One entry of a bounty's `targets`: `{id, kind, …}`, where the rest of the
/// fields depend on `kind` (01, "Target kinds and how a sweep is scoped").
///
/// `id` and `kind` are checked when the target is read. Everything else is
/// kept as raw JSON and checked by [`known`](Self::known), so an unknown kind
/// or a malformed known one is skipped rather than failing the bounty, and
/// every field survives a rewrite.
///
/// The fields are private: a `Target` comes from reading a bounty or from
/// [`pr`](Self::pr), [`commit`](Self::commit) or [`repo`](Self::repo), so its
/// raw fields never hold an `id` or a `kind` of their own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    /// The target's id, unique within its bounty.
    id: TargetId,
    /// What the target points at.
    kind: TargetKind,
    /// Every other field, of a known kind or not, as written.
    // `flatten` reads every key other than `id` and `kind` into this map and
    // writes them back beside those two, as each record's `extra` does. Here
    // it holds the kind's own fields too, because which fields a target has
    // depends on `kind`, and a kind this build does not know has fields it
    // cannot name.
    #[serde(flatten)]
    fields: UnknownFields,
}

impl Target {
    /// A pull request target, `{id, kind: "pr", repo, number, base, head,
    /// mergeBase}`.
    ///
    /// `post` reads `head` and `base` from GitHub and stores their merge base
    /// alongside, so the scope is the diff GitHub shows (the three-dot
    /// `base...head`) however far the base branch moves later.
    // Every argument is already a checked type, so building the map cannot
    // fail and this returns `Self`, not a `Result`. `NonZeroU64` is a `u64`
    // the type system knows is not 0, as pull request numbers start at 1.
    pub fn pr(
        id: TargetId,
        repo: RepoName,
        number: NonZeroU64,
        base: GitSha,
        head: GitSha,
        merge_base: GitSha,
    ) -> Self {
        let fields = field_map([
            (key::REPO, Value::String(repo.into())),
            (key::NUMBER, Value::from(number.get())),
            (key::BASE, Value::String(base.into())),
            (key::HEAD, Value::String(head.into())),
            (key::MERGE_BASE, Value::String(merge_base.into())),
        ]);
        Self::with_fields(id, KnownTargetKind::Pr, fields)
    }

    /// A commit target, `{id, kind: "commit", repo, rev}`.
    pub fn commit(id: TargetId, repo: RepoName, rev: GitSha) -> Self {
        let fields = field_map([
            (key::REPO, Value::String(repo.into())),
            (key::REV, Value::String(rev.into())),
        ]);
        Self::with_fields(id, KnownTargetKind::Commit, fields)
    }

    /// A repository target, `{id, kind: "repo", repo, rev, paths?}`.
    ///
    /// `paths` narrows the sweep to those paths. Empty means the whole
    /// repository, and is written with no `paths` key, the form 01 gives it.
    pub fn repo(id: TargetId, repo: RepoName, rev: GitSha, paths: Vec<RepoPath>) -> Self {
        let mut fields = field_map([
            (key::REPO, Value::String(repo.into())),
            (key::REV, Value::String(rev.into())),
        ]);
        if !paths.is_empty() {
            // `into_iter` takes the `Vec` by value, so each `RepoPath` moves
            // into its `Value` without a copy.
            let paths = paths
                .into_iter()
                .map(|path| Value::String(path.into()))
                .collect();
            fields.insert(key::PATHS.to_owned(), Value::Array(paths));
        }
        Self::with_fields(id, KnownTargetKind::Repo, fields)
    }

    fn with_fields(id: TargetId, kind: KnownTargetKind, fields: UnknownFields) -> Self {
        Self {
            id,
            kind: kind.into(),
            fields,
        }
    }

    /// The target's id, unique within its bounty.
    pub fn id(&self) -> &TargetId {
        &self.id
    }

    /// The target's `kind`, exactly as written.
    pub fn kind(&self) -> &TargetKind {
        &self.kind
    }

    /// Checks the fields of a known kind and returns its typed view.
    ///
    /// - `Ok(Some(_))`: a known kind whose fields all pass their checks.
    ///   Fields the kind does not name are ignored here (and still kept in
    ///   the target for a rewrite).
    /// - `Ok(None)`: a kind this build does not know. Skip the target.
    /// - `Err(_)`: a known kind with a field missing, of the wrong JSON type
    ///   or failing its check. Skip the target too: one bad target is not a
    ///   reason to refuse the rest of the bounty.
    ///
    /// Never panics, whatever the fields hold.
    pub fn known(&self) -> Result<Option<KnownTarget>, TargetError> {
        // `let … else`: bind the known kind, or return early for an unknown
        // one.
        let Some(kind) = self.kind.as_known() else {
            return Ok(None);
        };
        let fields = Fields {
            kind,
            map: &self.fields,
        };
        let known = match kind {
            KnownTargetKind::Pr => KnownTarget::Pr(PrTarget {
                repo: fields.checked(key::REPO)?,
                number: fields.number(key::NUMBER)?,
                base: fields.checked(key::BASE)?,
                head: fields.checked(key::HEAD)?,
                merge_base: fields.checked(key::MERGE_BASE)?,
            }),
            KnownTargetKind::Commit => KnownTarget::Commit(CommitTarget {
                repo: fields.checked(key::REPO)?,
                rev: fields.checked(key::REV)?,
            }),
            KnownTargetKind::Repo => KnownTarget::Repo(RepoTarget {
                repo: fields.checked(key::REPO)?,
                rev: fields.checked(key::REV)?,
                paths: fields.optional_paths(key::PATHS)?,
            }),
        };
        Ok(Some(known))
    }
}

/// Builds a target's raw field map from `(key, value)` pairs.
// A const generic, `N`, lets this take an array of any length by value, so
// each `Value` moves into the map without a copy. `serde_json::Map`
// implements `FromIterator`, which is what lets `collect` build one.
fn field_map<const N: usize>(entries: [(&str, Value); N]) -> UnknownFields {
    entries
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
}

/// A target of a kind this build knows, from [`Target::known`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KnownTarget {
    /// A pull request.
    Pr(PrTarget),
    /// One commit.
    Commit(CommitTarget),
    /// A repository's tree at one commit.
    Repo(RepoTarget),
}

/// A checked pull request target: `{repo, number, base, head, mergeBase}`.
///
/// The sweep covers the diff from `mergeBase` to `head`, which is the
/// three-dot `base...head` GitHub shows. `run` fetches `head` from the base
/// repository's `refs/pull/<number>/head`, never from the fork. GitHub only
/// in v1; that rule is the CLI's, not this type's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrTarget {
    repo: RepoName,
    number: NonZeroU64,
    base: GitSha,
    head: GitSha,
    merge_base: GitSha,
}

impl PrTarget {
    /// The base repository, the one the pull request was opened against.
    pub fn repo(&self) -> &RepoName {
        &self.repo
    }

    /// The pull request's number, from 1.
    // `NonZeroU64` is `Copy`, so it is returned by value rather than by
    // reference.
    pub fn number(&self) -> NonZeroU64 {
        self.number
    }

    /// The tip of the base branch when the bounty was posted.
    pub fn base(&self) -> &GitSha {
        &self.base
    }

    /// The pull request's head commit, the one the sweep reviews.
    pub fn head(&self) -> &GitSha {
        &self.head
    }

    /// The merge base of `base` and `head`, where the diff starts.
    pub fn merge_base(&self) -> &GitSha {
        &self.merge_base
    }
}

/// A checked commit target: `{repo, rev}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitTarget {
    repo: RepoName,
    rev: GitSha,
}

impl CommitTarget {
    /// The repository the commit is in.
    pub fn repo(&self) -> &RepoName {
        &self.repo
    }

    /// The commit.
    pub fn rev(&self) -> &GitSha {
        &self.rev
    }
}

/// A checked repository target: `{repo, rev, paths?}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoTarget {
    repo: RepoName,
    rev: GitSha,
    /// `None` for the whole repository, else a non-empty list.
    paths: Option<Vec<RepoPath>>,
}

impl RepoTarget {
    /// The repository.
    pub fn repo(&self) -> &RepoName {
        &self.repo
    }

    /// The commit whose tree the sweep covers.
    pub fn rev(&self) -> &GitSha {
        &self.rev
    }

    /// The paths the sweep is narrowed to, in the order written, or `None`
    /// for the whole repository. Never an empty list.
    // `as_deref` turns `&Option<Vec<RepoPath>>` into `Option<&[RepoPath]>`: a
    // borrowed slice, so the caller can read the paths without a copy and
    // without seeing that they are stored in a `Vec`.
    pub fn paths(&self) -> Option<&[RepoPath]> {
        self.paths.as_deref()
    }
}

/// Why [`Target::known`] could not read a target of a known kind.
///
/// Like [`RecordError`], every variant holds fixed text and checked values,
/// never text from the target, so a stranger's bounty cannot put its own
/// words into the CLI's output.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TargetError {
    /// A field the kind requires is not there.
    // thiserror hands the arguments after the format string to `format!`,
    // and `.kind` there is the variant's field. `KnownTargetKind` has no
    // `Display` of its own, so the message calls `as_str()` for the `{}`.
    #[error("{} target: {field} is missing", .kind.as_str())]
    Missing {
        /// The target's kind.
        kind: KnownTargetKind,
        /// The field's JSON key.
        field: &'static str,
    },
    /// A field holds the wrong kind of JSON value for its kind of target.
    #[error("{} target: {field} is not {expected}", .kind.as_str())]
    Malformed {
        /// The target's kind.
        kind: KnownTargetKind,
        /// The field's JSON key.
        field: &'static str,
        /// What the field should hold.
        expected: &'static str,
    },
    /// A field holds a string its type's check refuses.
    #[error("{} target: {field}: {source}", .kind.as_str())]
    Invalid {
        /// The target's kind.
        kind: KnownTargetKind,
        /// The field's JSON key.
        field: &'static str,
        /// What the check found.
        // A field named `source` is what thiserror reports as the error's
        // cause (`std::error::Error::source`).
        source: RecordError,
    },
}

/// The fields of one target of a known kind, read for [`Target::known`].
///
/// The `'a` says a `Fields` borrows the target's map and cannot outlive it,
/// so reading the fields copies only the values it returns.
struct Fields<'a> {
    kind: KnownTargetKind,
    map: &'a UnknownFields,
}

// `'_` stands for the map's lifetime without naming it: these methods work
// whatever that lifetime is.
impl Fields<'_> {
    /// The field `field`, or [`TargetError::Missing`].
    // No lifetime is written on the returned `&Value`, so Rust ties it to
    // `&self`: shorter than the map's own, but long enough, because each
    // caller checks the value and copies what it needs out at once.
    fn get(&self, field: &'static str) -> Result<&Value, TargetError> {
        self.map.get(field).ok_or(TargetError::Missing {
            kind: self.kind,
            field,
        })
    }

    /// A string field read into a checked type such as [`GitSha`].
    ///
    /// Generic over `T`: any type whose `FromStr` runs its check and fails
    /// with a [`RecordError`], which every checked name in this crate does.
    fn checked<T: FromStr<Err = RecordError>>(
        &self,
        field: &'static str,
    ) -> Result<T, TargetError> {
        let Value::String(text) = self.get(field)? else {
            return Err(self.malformed(field, "a string"));
        };
        self.parse(field, text)
    }

    /// A pull request number: a JSON integer of 1 or more.
    fn number(&self, field: &'static str) -> Result<NonZeroU64, TargetError> {
        // `as_u64` is `None` for anything but a non-negative integer (a
        // string, a float such as `42.0`, a negative number), and
        // `NonZeroU64::new` is `None` for 0. `and_then` chains the two.
        self.get(field)?
            .as_u64()
            .and_then(NonZeroU64::new)
            .ok_or_else(|| self.malformed(field, "a whole number of 1 or more"))
    }

    /// An optional, non-empty list of repository paths. A missing field or
    /// `null` is `None`, the whole repository; an empty list is refused,
    /// because it would narrow the sweep to nothing.
    fn optional_paths(&self, field: &'static str) -> Result<Option<Vec<RepoPath>>, TargetError> {
        let expected = "a non-empty list of strings";
        let items = match self.map.get(field) {
            None | Some(Value::Null) => return Ok(None),
            Some(Value::Array(items)) if !items.is_empty() => items,
            Some(_) => return Err(self.malformed(field, expected)),
        };
        // Collecting an iterator of `Result`s into a `Result<Vec<_>, _>`
        // stops at the first `Err` and returns it, so one bad path fails the
        // list.
        let paths = items
            .iter()
            .map(|item| match item {
                Value::String(text) => self.parse(field, text),
                _ => Err(self.malformed(field, expected)),
            })
            .collect::<Result<Vec<RepoPath>, TargetError>>()?;
        Ok(Some(paths))
    }

    fn parse<T: FromStr<Err = RecordError>>(
        &self,
        field: &'static str,
        text: &str,
    ) -> Result<T, TargetError> {
        text.parse().map_err(|source| TargetError::Invalid {
            kind: self.kind,
            field,
            source,
        })
    }

    fn malformed(&self, field: &'static str, expected: &'static str) -> TargetError {
        TargetError::Malformed {
            kind: self.kind,
            field,
            expected,
        }
    }
}

/// Synthetic values and helpers shared by the tests of this module and of
/// `scope.rs`, so both build their targets the same way.
// `pub(crate)` lets `scope.rs`'s tests import these; `#[cfg(test)]` leaves
// the module, and its `unwrap`s, out of every non-test build.
#[cfg(test)]
pub(crate) mod test_support {
    use std::num::NonZeroU64;

    use super::{CommitTarget, KnownTarget, PrTarget, RepoTarget, Target};
    use crate::names::{GitSha, RepoName, RepoPath, TargetId};

    pub(crate) const REPO: &str = "example.invalid/org/name";
    pub(crate) const BASE: &str = "1111111111111111111111111111111111111111";
    pub(crate) const HEAD: &str = "2222222222222222222222222222222222222222";
    pub(crate) const MERGE_BASE: &str = "3333333333333333333333333333333333333333";
    pub(crate) const REV: &str = "4444444444444444444444444444444444444444";

    pub(crate) fn sha(text: &str) -> GitSha {
        text.parse().unwrap()
    }

    pub(crate) fn id(text: &str) -> TargetId {
        text.parse().unwrap()
    }

    pub(crate) fn repo() -> RepoName {
        REPO.parse().unwrap()
    }

    pub(crate) fn path(text: &str) -> RepoPath {
        text.parse().unwrap()
    }

    /// Pull request 42 of [`REPO`], target `t1`.
    pub(crate) fn sample_pr() -> Target {
        let number = NonZeroU64::new(42).unwrap();
        Target::pr(
            id("t1"),
            repo(),
            number,
            sha(BASE),
            sha(HEAD),
            sha(MERGE_BASE),
        )
    }

    /// Commit [`REV`] of [`REPO`], target `t2`.
    pub(crate) fn sample_commit() -> Target {
        Target::commit(id("t2"), repo(), sha(REV))
    }

    /// [`REPO`] at [`REV`], narrowed to `paths`, target `t3`.
    pub(crate) fn sample_repo(paths: Vec<RepoPath>) -> Target {
        Target::repo(id("t3"), repo(), sha(REV), paths)
    }

    pub(crate) fn known_pr(target: &Target) -> PrTarget {
        match target.known() {
            Ok(Some(KnownTarget::Pr(pr))) => pr,
            other => panic!("expected a pr target, got {other:?}"),
        }
    }

    pub(crate) fn known_commit(target: &Target) -> CommitTarget {
        match target.known() {
            Ok(Some(KnownTarget::Commit(commit))) => commit,
            other => panic!("expected a commit target, got {other:?}"),
        }
    }

    pub(crate) fn known_repo(target: &Target) -> RepoTarget {
        match target.known() {
            Ok(Some(KnownTarget::Repo(repo))) => repo,
            other => panic!("expected a repo target, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::test_support::{
        BASE, HEAD, MERGE_BASE, REPO, REV, id, known_commit, known_pr, known_repo, path, repo,
        sample_commit, sample_pr, sample_repo, sha,
    };
    use super::{KnownTargetKind, Target, TargetError};
    use crate::names::{GitSha, RepoName, RepoPath};

    fn pr_json() -> Value {
        json!({
            "id": "t1",
            "kind": "pr",
            "repo": REPO,
            "number": 42,
            "base": BASE,
            "head": HEAD,
            "mergeBase": MERGE_BASE,
        })
    }

    fn commit_json() -> Value {
        json!({ "id": "t2", "kind": "commit", "repo": REPO, "rev": REV })
    }

    fn repo_json() -> Value {
        json!({
            "id": "t3",
            "kind": "repo",
            "repo": REPO,
            "rev": REV,
            "paths": ["src/auth/", "src/lib.rs"],
        })
    }

    fn whole_repo_json() -> Value {
        json!({ "id": "t4", "kind": "repo", "repo": REPO, "rev": REV })
    }

    fn parse(input: &Value) -> Target {
        serde_json::from_value(input.clone()).unwrap()
    }

    #[test]
    fn known_kinds_round_trip_with_an_unknown_field_kept() {
        for mut input in [pr_json(), commit_json(), repo_json(), whole_repo_json()] {
            // A field a newer client added inside a kind this build knows.
            input["addedLater"] = json!({ "by": "a newer client" });
            let target = parse(&input);
            assert!(target.kind().as_known().is_some(), "{input}");
            assert!(matches!(target.known(), Ok(Some(_))), "{input}");
            assert_eq!(serde_json::to_value(&target).unwrap(), input);
        }
    }

    #[test]
    fn known_reads_each_kind_into_its_typed_view() {
        let pr = known_pr(&parse(&pr_json()));
        assert_eq!(pr.repo().as_str(), REPO);
        assert_eq!(pr.number().get(), 42);
        assert_eq!(pr.base().as_str(), BASE);
        assert_eq!(pr.head().as_str(), HEAD);
        assert_eq!(pr.merge_base().as_str(), MERGE_BASE);

        let commit = known_commit(&parse(&commit_json()));
        assert_eq!(commit.repo().as_str(), REPO);
        assert_eq!(commit.rev().as_str(), REV);

        let narrowed = known_repo(&parse(&repo_json()));
        assert_eq!(narrowed.rev().as_str(), REV);
        assert_eq!(
            narrowed.paths(),
            Some(&[path("src/auth/"), path("src/lib.rs")][..])
        );
        assert_eq!(known_repo(&parse(&whole_repo_json())).paths(), None);
    }

    #[test]
    fn the_constructors_write_what_known_reads_back() {
        let pr = sample_pr();
        assert_eq!(serde_json::to_value(&pr).unwrap(), pr_json());
        assert_eq!(known_pr(&pr).merge_base().as_str(), MERGE_BASE);

        let commit = sample_commit();
        assert_eq!(serde_json::to_value(&commit).unwrap(), commit_json());

        let narrowed = sample_repo(vec![path("src/auth/"), path("src/lib.rs")]);
        assert_eq!(serde_json::to_value(&narrowed).unwrap(), repo_json());

        // No paths means the whole repository, written with no `paths` key.
        let whole = Target::repo(id("t4"), repo(), sha(REV), Vec::new());
        assert_eq!(serde_json::to_value(&whole).unwrap(), whole_repo_json());
        assert_eq!(known_repo(&whole).paths(), None);
    }

    #[test]
    fn an_unknown_kind_round_trips_unchanged_and_is_skipped() {
        // A kind a newer client might add, with fields of its own.
        let input = json!({
            "id": "t5",
            "kind": "crate",
            "name": "serde",
            "version": "1.0.229",
            "checksum": { "sha256": "ab".repeat(32) },
        });
        let target = parse(&input);
        assert_eq!(target.id().as_str(), "t5");
        assert_eq!(target.kind().as_str(), "crate");
        assert_eq!(target.kind().as_known(), None);
        // Skipped, not an error: an error here could reject the whole bounty.
        assert_eq!(target.known(), Ok(None));
        assert_eq!(serde_json::to_value(&target).unwrap(), input);
    }

    #[test]
    fn a_malformed_known_target_parses_but_known_returns_an_error() {
        let with = |mut input: Value, field: &str, value: Value| {
            input[field] = value;
            input
        };
        let without = |mut input: Value, field: &str| {
            input.as_object_mut().unwrap().remove(field);
            input
        };
        // The right length, but upper case, a spelling git never prints.
        let upper_head = "ABCDEF0123".repeat(4);
        let short_base = "1111111";
        let climbing_repo = "example.invalid/org/..";
        let climbing_path = "src/../../etc";
        let cases = [
            (
                without(pr_json(), "mergeBase"),
                TargetError::Missing {
                    kind: KnownTargetKind::Pr,
                    field: "mergeBase",
                },
            ),
            (
                with(pr_json(), "head", json!(upper_head)),
                TargetError::Invalid {
                    kind: KnownTargetKind::Pr,
                    field: "head",
                    source: upper_head.parse::<GitSha>().unwrap_err(),
                },
            ),
            (
                with(pr_json(), "base", json!(short_base)),
                TargetError::Invalid {
                    kind: KnownTargetKind::Pr,
                    field: "base",
                    source: short_base.parse::<GitSha>().unwrap_err(),
                },
            ),
            (
                with(pr_json(), "number", json!(0)),
                TargetError::Malformed {
                    kind: KnownTargetKind::Pr,
                    field: "number",
                    expected: "a whole number of 1 or more",
                },
            ),
            (
                with(pr_json(), "number", json!("42")),
                TargetError::Malformed {
                    kind: KnownTargetKind::Pr,
                    field: "number",
                    expected: "a whole number of 1 or more",
                },
            ),
            (
                with(commit_json(), "repo", json!(climbing_repo)),
                TargetError::Invalid {
                    kind: KnownTargetKind::Commit,
                    field: "repo",
                    source: climbing_repo.parse::<RepoName>().unwrap_err(),
                },
            ),
            (
                with(repo_json(), "paths", json!(["src/", climbing_path])),
                TargetError::Invalid {
                    kind: KnownTargetKind::Repo,
                    field: "paths",
                    source: climbing_path.parse::<RepoPath>().unwrap_err(),
                },
            ),
            (
                // An empty list narrows to nothing. Leaving `paths` out is how
                // a target asks for the whole repository.
                with(repo_json(), "paths", json!([])),
                TargetError::Malformed {
                    kind: KnownTargetKind::Repo,
                    field: "paths",
                    expected: "a non-empty list of strings",
                },
            ),
        ];
        for (input, expected) in cases {
            // The target itself still parses, so the bounty holding it does
            // too; only this target is skipped.
            let target = parse(&input);
            assert_eq!(target.known(), Err(expected), "{input}");
            // And it is still written back as it was read.
            assert_eq!(serde_json::to_value(&target).unwrap(), input);
        }
    }
}
