//! The sets the matching findings are joined into.

/// A union-find over `0..len`: each index starts in a set of its own, and
/// [`union`](Self::union) merges two sets.
///
/// It uses union by size and path halving, so a long run of unions and finds
/// costs close to constant time each. Every lookup is a `get`, so an index out
/// of range is left alone rather than panicking; grouping only passes indices
/// of its entries.
pub(super) struct DisjointSets {
    /// Each index's parent; a root is its own parent.
    parent: Vec<usize>,
    /// For a root, the size of its set.
    size: Vec<usize>,
}

impl DisjointSets {
    /// `len` sets of one index each.
    pub(super) fn new(len: usize) -> Self {
        Self {
            parent: (0..len).collect(),
            size: vec![1; len],
        }
    }

    /// The root of `item`'s set.
    pub(super) fn find(&mut self, mut item: usize) -> usize {
        loop {
            let parent = self.parent.get(item).copied().unwrap_or(item);
            if parent == item {
                return item;
            }
            // Path halving: point `item` at its grandparent and step there,
            // which roughly halves the path for the next find.
            let grandparent = self.parent.get(parent).copied().unwrap_or(parent);
            if let Some(slot) = self.parent.get_mut(item) {
                *slot = grandparent;
            }
            item = grandparent;
        }
    }

    /// Merges the sets of `a` and `b`, hanging the smaller under the larger.
    pub(super) fn union(&mut self, a: usize, b: usize) {
        let (a, b) = (self.find(a), self.find(b));
        if a == b {
            return;
        }
        let size_a = self.size.get(a).copied().unwrap_or(1);
        let size_b = self.size.get(b).copied().unwrap_or(1);
        let (root, child) = if size_a >= size_b { (a, b) } else { (b, a) };
        if let Some(slot) = self.parent.get_mut(child) {
            *slot = root;
        }
        if let Some(slot) = self.size.get_mut(root) {
            // Two disjoint sets of in-memory entries hold fewer than
            // `usize::MAX` between them, so the sum cannot overflow;
            // `saturating_add` says so without a panic path.
            *slot = size_a.saturating_add(size_b);
        }
    }
}
