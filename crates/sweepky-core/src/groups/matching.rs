//! Which findings match: each finding's anchor, and the joins that connect
//! every pair the rule on `group_findings` matches without comparing every
//! pair.

use std::collections::BTreeMap;

use super::disjoint_sets::DisjointSets;
use super::{Entry, LINE_WINDOW};
use crate::findings::{Finding, KnownLocationKind, Location, LocationKind};

/// A finding's anchor, normalised for comparing.
#[derive(Clone, Copy)]
pub(super) struct Anchor<'a> {
    file: &'a str,
    scope: Option<&'a str>,
    line: Option<u64>,
}

impl<'a> Anchor<'a> {
    /// The finding's first sink, or else its first location; `None` when it
    /// has no locations.
    pub(super) fn of(finding: &'a Finding) -> Option<Self> {
        // `first()` is `None` on an empty list, where `[0]` would panic.
        let location = finding
            .locations
            .iter()
            .find(|location| is_sink(location))
            .or_else(|| finding.locations.first())?;
        Some(Self {
            file: comparable_file(&location.file),
            // `as_deref` turns the `&Option<String>` into an `Option<&str>`
            // borrowing the string, without copying it.
            scope: location.scope.as_deref().and_then(comparable_scope),
            line: location.line,
        })
    }

    /// Whether the anchor gives neither a scope nor a line, so location
    /// cannot tell it apart from any other anchor in its file.
    fn has_neither_scope_nor_line(&self) -> bool {
        self.scope.is_none() && self.line.is_none()
    }

    fn has_scope_only(&self) -> bool {
        self.scope.is_some() && self.line.is_none()
    }

    fn has_line_only(&self) -> bool {
        self.scope.is_none() && self.line.is_some()
    }
}

/// Whether `location`'s `kind` is exactly `sink`. An unknown kind, `Sink`
/// among them, is not.
fn is_sink(location: &Location) -> bool {
    location.kind.as_ref().and_then(LocationKind::as_known) == Some(KnownLocationKind::Sink)
}

/// `file` without one leading `./`. `strip_prefix` returns `None` rather than
/// slicing when the prefix is absent, so this is safe on any string.
fn comparable_file(file: &str) -> &str {
    file.strip_prefix("./").unwrap_or(file)
}

/// `scope` with its leading and trailing ASCII whitespace trimmed, or `None`
/// when nothing is left.
fn comparable_scope(scope: &str) -> Option<&str> {
    // `trim_ascii` trims only ASCII whitespace, so a no-break space or any
    // other Unicode space stays part of the scope and is compared as written.
    let trimmed = scope.trim_ascii();
    (!trimmed.is_empty()).then_some(trimmed)
}

/// An anchor and the index of its finding's entry.
type IndexedAnchor<'a> = (usize, Anchor<'a>);

/// A line and the index of its finding's entry, the line first so that
/// sorting orders by line.
type IndexedLine = (u64, usize);

/// Joins every pair of anchors that match by location.
///
/// Anchors in different files never match, so each file's anchors are
/// handled alone.
pub(super) fn join_by_location(entries: &[Entry<'_>], sets: &mut DisjointSets) {
    // The `?` makes the closure return `None` for an entry with no anchor,
    // and `filter_map` skips it.
    let anchors = entries
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| Some((index, entry.anchor?)));
    for in_file in by_file(anchors).values() {
        join_one_file(in_file, sets);
    }
}

/// `anchors` bucketed by file.
// A `BTreeMap` rather than a `HashMap` keeps every step in the same order on
// every run; the groups would come out the same either way, since which pairs
// join does not depend on the order they are found. The `'a` says the map's
// keys borrow the same strings as the anchors, so the map cannot outlive the
// sweeps either.
fn by_file<'a>(
    anchors: impl Iterator<Item = IndexedAnchor<'a>>,
) -> BTreeMap<&'a str, Vec<IndexedAnchor<'a>>> {
    let mut by_file: BTreeMap<&str, Vec<IndexedAnchor<'_>>> = BTreeMap::new();
    for (index, anchor) in anchors {
        by_file
            .entry(anchor.file)
            .or_default()
            .push((index, anchor));
    }
    by_file
}

/// Joins the anchors of one file that match: equal scopes, or lines at most
/// [`LINE_WINDOW`] apart when at least one of the two has no scope.
///
/// Comparing every pair would cost the square of the count, so each kind of
/// match is joined in near-linear time instead: anchors with one scope to
/// each other, the unscoped lines to their neighbours once sorted, and each
/// scoped line to the nearest unscoped line on either side. Two scoped lines
/// are never joined by their lines.
fn join_one_file(anchors: &[IndexedAnchor<'_>], sets: &mut DisjointSets) {
    join_equal_scopes(anchors, sets);
    let (scoped_lines, mut unscoped_lines) = lines_with_and_without_scope(anchors);
    unscoped_lines.sort_unstable();
    join_neighbouring_lines(&unscoped_lines, sets);
    join_to_nearest_lines(&scoped_lines, &unscoped_lines, sets);
}

/// Joins the anchors that give one scope, however far apart their lines.
fn join_equal_scopes(anchors: &[IndexedAnchor<'_>], sets: &mut DisjointSets) {
    let mut first_with_scope: BTreeMap<&str, usize> = BTreeMap::new();
    for &(index, anchor) in anchors {
        if let Some(scope) = anchor.scope {
            // `or_insert` keeps the first index seen for this scope and hands
            // it back for every later one.
            let first = *first_with_scope.entry(scope).or_insert(index);
            sets.union(first, index);
        }
    }
}

/// The anchors' lines: first those of the anchors with a scope, then those of
/// the anchors without one. An anchor with no line is in neither list.
fn lines_with_and_without_scope(
    anchors: &[IndexedAnchor<'_>],
) -> (Vec<IndexedLine>, Vec<IndexedLine>) {
    let mut scoped = Vec::new();
    let mut unscoped = Vec::new();
    for &(index, anchor) in anchors {
        if let Some(line) = anchor.line {
            let list = if anchor.scope.is_some() {
                &mut scoped
            } else {
                &mut unscoped
            };
            list.push((line, index));
        }
    }
    (scoped, unscoped)
}

/// Joins each of the `sorted` lines to the next when they are close enough.
/// That connects every pair within the window, since the sorted lines between
/// two such lines are each close to the next.
fn join_neighbouring_lines(sorted: &[IndexedLine], sets: &mut DisjointSets) {
    // `zip` with the same list one step on pairs each line with the next,
    // with no index arithmetic.
    for (&(line, index), &(next_line, next_index)) in sorted.iter().zip(sorted.iter().skip(1)) {
        if lines_within_window(line, next_line) {
            sets.union(index, next_index);
        }
    }
}

/// Joins each scoped line to the nearest of the `sorted_unscoped` lines on
/// either side, when close enough. Each of those two is already joined to
/// every other unscoped line on its side within the window, so this joins the
/// scoped line to all of them.
fn join_to_nearest_lines(
    scoped: &[IndexedLine],
    sorted_unscoped: &[IndexedLine],
    sets: &mut DisjointSets,
) {
    for &(line, index) in scoped {
        for &(other, other_index) in nearest_on_each_side(sorted_unscoped, line) {
            if lines_within_window(line, other) {
                sets.union(index, other_index);
            }
        }
    }
}

/// The entries of `sorted` nearest to `line`: the last one below it and the
/// first one at or above it, where they exist.
fn nearest_on_each_side(sorted: &[IndexedLine], line: u64) -> impl Iterator<Item = &IndexedLine> {
    // `partition_point` binary-searches the sorted list for the first line at
    // or after `line`; the one before it is the nearest below. `checked_sub`
    // is `None` at 0 instead of wrapping, and `get` is `None` past the end, so
    // neither can panic.
    let at_or_above = sorted.partition_point(|&(other, _)| other < line);
    let below = at_or_above
        .checked_sub(1)
        .and_then(|position| sorted.get(position));
    // `flatten` over the two `Option`s yields only the ones that are `Some`.
    [below, sorted.get(at_or_above)].into_iter().flatten()
}

/// Whether two lines are at most [`LINE_WINDOW`] apart.
fn lines_within_window(line: u64, other: u64) -> bool {
    // `abs_diff` is the distance without a subtraction that could overflow:
    // `0 - u64::MAX` would panic in a debug build and wrap in a release one.
    line.abs_diff(other) <= LINE_WINDOW
}

/// Joins findings with an equal, non-empty id where location cannot decide.
///
/// The pairs to look at are those with one id, so the findings are bucketed
/// by id, and within a bucket the undecided pairs are joined without
/// comparing every pair.
pub(super) fn join_by_id(entries: &[Entry<'_>], sets: &mut DisjointSets) {
    let mut by_id: BTreeMap<&str, Vec<(usize, Option<Anchor<'_>>)>> = BTreeMap::new();
    for (index, entry) in entries.iter().enumerate() {
        // An empty id names nothing, so it gives no hint.
        if !entry.id.is_empty() {
            by_id
                .entry(entry.id)
                .or_default()
                .push((index, entry.anchor));
        }
    }
    for same_id in by_id.values() {
        join_undecided_with_one_id(same_id, sets);
    }
}

/// Joins the findings of one id that location cannot tell apart.
///
/// A finding with no anchor is undecided against every other, so if one is
/// here, they all join. Otherwise only anchors in one file can be undecided.
fn join_undecided_with_one_id(same_id: &[(usize, Option<Anchor<'_>>)], sets: &mut DisjointSets) {
    if same_id.iter().any(|(_, anchor)| anchor.is_none()) {
        join_all(same_id.iter().map(|&(index, _)| index), sets);
        return;
    }
    let anchors = same_id
        .iter()
        .filter_map(|&(index, anchor)| Some((index, anchor?)));
    for in_file in by_file(anchors).values() {
        join_undecided_in_file(in_file, sets);
    }
}

/// Joins the anchors of one file and one id that location cannot tell apart.
///
/// Two kinds of pair are undecided: an anchor with neither a scope nor a
/// line, against every other in the file; and an anchor with a scope but no
/// line, against one with a line but no scope. In every other pair both give
/// a scope or both give a line, and location decides it.
fn join_undecided_in_file(anchors: &[IndexedAnchor<'_>], sets: &mut DisjointSets) {
    if anchors
        .iter()
        .any(|(_, anchor)| anchor.has_neither_scope_nor_line())
    {
        join_all(anchors.iter().map(|&(index, _)| index), sets);
        return;
    }
    let any_scope_only = anchors.iter().any(|(_, anchor)| anchor.has_scope_only());
    let any_line_only = anchors.iter().any(|(_, anchor)| anchor.has_line_only());
    if any_scope_only && any_line_only {
        join_all(
            anchors
                .iter()
                .filter(|(_, anchor)| anchor.has_scope_only() || anchor.has_line_only())
                .map(|&(index, _)| index),
            sets,
        );
    }
}

/// Joins every index `indices` yields into one set.
// `impl Iterator` lets callers pass any iterator of indices without first
// collecting it into a `Vec`.
fn join_all(mut indices: impl Iterator<Item = usize>, sets: &mut DisjointSets) {
    if let Some(first) = indices.next() {
        for index in indices {
            sets.union(first, index);
        }
    }
}
