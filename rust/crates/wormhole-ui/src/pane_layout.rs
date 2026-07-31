//! Recursive pane layout tree — pure state (no GPUI / HWND).
//!
//! [`PaneLayout`] is a binary tree of leaves ([`PaneId`]) and axis-aligned splits
//! with a first-child ratio. Split/merge ops live here; [`crate::WorkspaceState`]
//! owns the tree and keeps the flat pane list in sync.
//!
//! Coarse arrangement ([`PaneArrangement`]) remains a count-derived summary for
//! chrome that still tiles from the flat pane list + global ratios. Layout ticks
//! still flow through [`crate::PaneLayoutSink`] unchanged.

use crate::workspace::PaneId;
use crate::UiError;

/// Inclusive lower bound for a finite split ratio after clamp.
pub const SPLIT_RATIO_MIN: f32 = 0.15;
/// Inclusive upper bound for a finite split ratio after clamp.
pub const SPLIT_RATIO_MAX: f32 = 0.85;
/// Default first-child share when splitting.
pub const SPLIT_RATIO_DEFAULT: f32 = 0.5;

/// Divider orientation for a binary split node.
///
/// Naming matches the existing coarse arrangement: a **vertical** split places
/// panes side-by-side (vertical divider); a **horizontal** split stacks them
/// (horizontal divider).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SplitAxis {
    /// Left | Right
    Vertical,
    /// Top / Bottom
    Horizontal,
}

/// Coarse arrangement summary derived from pane count (chrome / diagnostics).
///
/// Distinct from the recursive [`PaneLayout`] tree — count alone cannot express
/// nested axis choices, but GPUI chrome still uses this for simple tile presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PaneArrangement {
    Single,
    VerticalSplit,
    HorizontalSplit,
    Quad,
}

impl PaneArrangement {
    pub fn for_count(count: usize) -> Self {
        match count {
            0 | 1 => Self::Single,
            2 => Self::VerticalSplit,
            3 => Self::HorizontalSplit,
            _ => Self::Quad,
        }
    }
}

/// Recursive pane layout tree.
#[derive(Debug, Clone, PartialEq)]
pub enum PaneLayout {
    Leaf(PaneId),
    Split {
        axis: SplitAxis,
        /// First-child share of the split axis; always finite and in
        /// [`SPLIT_RATIO_MIN`]..=[`SPLIT_RATIO_MAX`] when constructed via ops.
        ratio: f32,
        first: Box<PaneLayout>,
        second: Box<PaneLayout>,
    },
}

impl PaneLayout {
    pub fn leaf(id: PaneId) -> Self {
        Self::Leaf(id)
    }

    /// Validate + clamp a split ratio. Rejects NaN / ±Inf; clamps finite values.
    pub fn normalize_ratio(ratio: f32) -> Result<f32, UiError> {
        if !ratio.is_finite() {
            return Err(UiError::InvalidSplitRatio);
        }
        Ok(ratio.clamp(SPLIT_RATIO_MIN, SPLIT_RATIO_MAX))
    }

    pub fn is_leaf(&self) -> bool {
        matches!(self, Self::Leaf(_))
    }

    pub fn leaf_count(&self) -> usize {
        match self {
            Self::Leaf(_) => 1,
            Self::Split { first, second, .. } => first.leaf_count() + second.leaf_count(),
        }
    }

    /// Depth-first leaf ids (tree order; may differ from [`crate::WorkspaceState::panes`] insertion order).
    pub fn leaves(&self) -> Vec<PaneId> {
        let mut out = Vec::with_capacity(self.leaf_count());
        self.collect_leaves(&mut out);
        out
    }

    fn collect_leaves(&self, out: &mut Vec<PaneId>) {
        match self {
            Self::Leaf(id) => out.push(*id),
            Self::Split { first, second, .. } => {
                first.collect_leaves(out);
                second.collect_leaves(out);
            }
        }
    }

    pub fn contains(&self, id: PaneId) -> bool {
        match self {
            Self::Leaf(leaf) => *leaf == id,
            Self::Split { first, second, .. } => first.contains(id) || second.contains(id),
        }
    }

    /// Split `target` leaf into `target` + `new_pane` along `axis` at `ratio`.
    ///
    /// `ratio` is normalized (NaN / ±Inf rejected; finite values clamped). The
    /// new leaf is always the **second** child. `new_pane` must not already
    /// appear in the tree (including `new_pane == target`).
    pub fn split(
        &mut self,
        target: PaneId,
        new_pane: PaneId,
        axis: SplitAxis,
        ratio: f32,
    ) -> Result<(), UiError> {
        let ratio = Self::normalize_ratio(ratio)?;
        if self.contains(new_pane) {
            return Err(UiError::DuplicatePane(new_pane.0));
        }
        if !self.split_leaf(target, new_pane, axis, ratio) {
            return Err(UiError::UnknownPane(target.0));
        }
        Ok(())
    }

    fn split_leaf(
        &mut self,
        target: PaneId,
        new_pane: PaneId,
        axis: SplitAxis,
        ratio: f32,
    ) -> bool {
        match self {
            Self::Leaf(id) if *id == target => {
                *self = Self::Split {
                    axis,
                    ratio,
                    first: Box::new(Self::Leaf(target)),
                    second: Box::new(Self::Leaf(new_pane)),
                };
                true
            }
            Self::Leaf(_) => false,
            Self::Split { first, second, .. } => {
                first.split_leaf(target, new_pane, axis, ratio)
                    || second.split_leaf(target, new_pane, axis, ratio)
            }
        }
    }

    /// Remove `target` leaf and promote its sibling (unsplit parent).
    ///
    /// Returns a surviving leaf id as a focus hint. Merging the sole root leaf
    /// returns [`UiError::LastPane`].
    pub fn merge(&mut self, target: PaneId) -> Result<PaneId, UiError> {
        if matches!(self, Self::Leaf(id) if *id == target) {
            return Err(UiError::LastPane);
        }
        if matches!(self, Self::Leaf(_)) {
            return Err(UiError::UnknownPane(target.0));
        }
        match Self::collapse(self, target) {
            Collapse::Done(focus) => Ok(focus),
            Collapse::Replace(sibling) => {
                let focus = sibling.first_leaf();
                *self = sibling;
                Ok(focus)
            }
            Collapse::Missing => Err(UiError::UnknownPane(target.0)),
        }
    }

    /// Collapse `target` out of `node`. `Replace` means replace `node` itself
    /// with the returned sibling subtree.
    fn collapse(node: &mut PaneLayout, target: PaneId) -> Collapse {
        let Self::Split { first, second, .. } = node else {
            return Collapse::Missing;
        };

        if matches!(first.as_ref(), Self::Leaf(id) if *id == target) {
            // Take sibling without cloning; leftover placeholder is dropped by caller.
            return Collapse::Replace(std::mem::replace(
                second.as_mut(),
                PaneLayout::Leaf(PaneId(0)),
            ));
        }
        if matches!(second.as_ref(), Self::Leaf(id) if *id == target) {
            return Collapse::Replace(std::mem::replace(
                first.as_mut(),
                PaneLayout::Leaf(PaneId(0)),
            ));
        }

        match Self::collapse(first, target) {
            Collapse::Missing => {}
            Collapse::Replace(sibling) => {
                let focus = sibling.first_leaf();
                *first.as_mut() = sibling;
                return Collapse::Done(focus);
            }
            Collapse::Done(focus) => return Collapse::Done(focus),
        }

        match Self::collapse(second, target) {
            Collapse::Missing => Collapse::Missing,
            Collapse::Replace(sibling) => {
                let focus = sibling.first_leaf();
                *second.as_mut() = sibling;
                Collapse::Done(focus)
            }
            Collapse::Done(focus) => Collapse::Done(focus),
        }
    }

    pub fn first_leaf(&self) -> PaneId {
        match self {
            Self::Leaf(id) => *id,
            Self::Split { first, .. } => first.first_leaf(),
        }
    }

    /// Set the ratio on the **immediate parent** split of `pane`.
    pub fn set_ratio_for_pane(&mut self, pane: PaneId, ratio: f32) -> Result<(), UiError> {
        let ratio = Self::normalize_ratio(ratio)?;
        if !self.set_parent_ratio(pane, ratio) {
            // Sole leaf has no parent split.
            if matches!(self, Self::Leaf(id) if *id == pane) {
                return Err(UiError::NoSplitForPane(pane.0));
            }
            return Err(UiError::UnknownPane(pane.0));
        }
        Ok(())
    }

    fn set_parent_ratio(&mut self, pane: PaneId, ratio: f32) -> bool {
        match self {
            Self::Leaf(_) => false,
            Self::Split {
                ratio: slot,
                first,
                second,
                ..
            } => {
                if matches!(first.as_ref(), Self::Leaf(id) if *id == pane)
                    || matches!(second.as_ref(), Self::Leaf(id) if *id == pane)
                {
                    *slot = ratio;
                    return true;
                }
                first.set_parent_ratio(pane, ratio) || second.set_parent_ratio(pane, ratio)
            }
        }
    }

    /// Ratio on the immediate parent of `pane`, if any.
    pub fn ratio_for_pane(&self, pane: PaneId) -> Option<f32> {
        self.find_parent_ratio(pane)
    }

    fn find_parent_ratio(&self, pane: PaneId) -> Option<f32> {
        match self {
            Self::Leaf(_) => None,
            Self::Split {
                ratio,
                first,
                second,
                ..
            } => {
                if matches!(first.as_ref(), Self::Leaf(id) if *id == pane)
                    || matches!(second.as_ref(), Self::Leaf(id) if *id == pane)
                {
                    Some(*ratio)
                } else {
                    first
                        .find_parent_ratio(pane)
                        .or_else(|| second.find_parent_ratio(pane))
                }
            }
        }
    }
}

enum Collapse {
    /// Nested collapse finished; `node` already updated in place.
    Done(PaneId),
    /// Caller must replace the current split node with `sibling`.
    Replace(PaneLayout),
    Missing,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_rejects_nan_and_inf() {
        assert_eq!(
            PaneLayout::normalize_ratio(f32::NAN),
            Err(UiError::InvalidSplitRatio)
        );
        assert_eq!(
            PaneLayout::normalize_ratio(f32::INFINITY),
            Err(UiError::InvalidSplitRatio)
        );
        assert_eq!(
            PaneLayout::normalize_ratio(f32::NEG_INFINITY),
            Err(UiError::InvalidSplitRatio)
        );
    }

    #[test]
    fn normalize_clamps_finite() {
        assert_eq!(
            PaneLayout::normalize_ratio(0.0).unwrap(),
            SPLIT_RATIO_MIN
        );
        assert_eq!(
            PaneLayout::normalize_ratio(1.0).unwrap(),
            SPLIT_RATIO_MAX
        );
        assert_eq!(
            PaneLayout::normalize_ratio(SPLIT_RATIO_MIN).unwrap(),
            SPLIT_RATIO_MIN
        );
        assert_eq!(
            PaneLayout::normalize_ratio(SPLIT_RATIO_MAX).unwrap(),
            SPLIT_RATIO_MAX
        );
        assert_eq!(
            PaneLayout::normalize_ratio(0.5).unwrap(),
            SPLIT_RATIO_DEFAULT
        );
        assert_eq!(
            PaneLayout::normalize_ratio(-0.0).unwrap(),
            SPLIT_RATIO_MIN
        );
        assert_eq!(
            PaneLayout::normalize_ratio(f32::from_bits(0x7f80_0001)),
            Err(UiError::InvalidSplitRatio)
        );
    }

    #[test]
    fn split_vertical_then_horizontal() {
        let mut tree = PaneLayout::leaf(PaneId(0));
        tree.split(PaneId(0), PaneId(1), SplitAxis::Vertical, 0.5)
            .unwrap();
        assert_eq!(
            tree,
            PaneLayout::Split {
                axis: SplitAxis::Vertical,
                ratio: 0.5,
                first: Box::new(PaneLayout::Leaf(PaneId(0))),
                second: Box::new(PaneLayout::Leaf(PaneId(1))),
            }
        );

        tree.split(PaneId(1), PaneId(2), SplitAxis::Horizontal, 0.4)
            .unwrap();
        assert_eq!(tree.leaf_count(), 3);
        assert_eq!(tree.leaves(), vec![PaneId(0), PaneId(1), PaneId(2)]);
        assert_eq!(
            tree.ratio_for_pane(PaneId(1)).unwrap(),
            PaneLayout::normalize_ratio(0.4).unwrap()
        );
    }

    #[test]
    fn split_rejects_nan_and_inf_without_mutating() {
        let mut tree = PaneLayout::leaf(PaneId(0));
        let before = tree.clone();
        for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            assert_eq!(
                tree.split(PaneId(0), PaneId(1), SplitAxis::Vertical, bad),
                Err(UiError::InvalidSplitRatio)
            );
            assert_eq!(tree, before);
        }
    }

    #[test]
    fn split_rejects_duplicate_new_pane_without_mutating() {
        let mut tree = PaneLayout::leaf(PaneId(0));
        tree.split(PaneId(0), PaneId(1), SplitAxis::Vertical, 0.5)
            .unwrap();
        let before = tree.clone();
        assert_eq!(
            tree.split(PaneId(1), PaneId(0), SplitAxis::Horizontal, 0.5),
            Err(UiError::DuplicatePane(0))
        );
        assert_eq!(
            tree.split(PaneId(0), PaneId(0), SplitAxis::Horizontal, 0.5),
            Err(UiError::DuplicatePane(0))
        );
        assert_eq!(tree, before);
    }

    #[test]
    fn split_unknown_pane() {
        let mut tree = PaneLayout::leaf(PaneId(0));
        let before = tree.clone();
        assert_eq!(
            tree.split(PaneId(9), PaneId(1), SplitAxis::Vertical, 0.5),
            Err(UiError::UnknownPane(9))
        );
        assert_eq!(tree, before);
    }

    #[test]
    fn merge_collapses_to_sibling() {
        let mut tree = PaneLayout::leaf(PaneId(0));
        tree.split(PaneId(0), PaneId(1), SplitAxis::Vertical, 0.5)
            .unwrap();
        tree.split(PaneId(1), PaneId(2), SplitAxis::Horizontal, 0.5)
            .unwrap();
        let focus = tree.merge(PaneId(2)).unwrap();
        assert_eq!(focus, PaneId(1));
        assert_eq!(tree.leaves(), vec![PaneId(0), PaneId(1)]);
        assert!(matches!(
            tree,
            PaneLayout::Split {
                axis: SplitAxis::Vertical,
                ..
            }
        ));
    }

    #[test]
    fn merge_first_child_promotes_second() {
        let mut tree = PaneLayout::leaf(PaneId(0));
        tree.split(PaneId(0), PaneId(1), SplitAxis::Horizontal, 0.6)
            .unwrap();
        let focus = tree.merge(PaneId(0)).unwrap();
        assert_eq!(focus, PaneId(1));
        assert_eq!(tree, PaneLayout::Leaf(PaneId(1)));
    }

    #[test]
    fn merge_promotes_multi_leaf_sibling_subtree() {
        let mut tree = PaneLayout::leaf(PaneId(0));
        tree.split(PaneId(0), PaneId(1), SplitAxis::Vertical, 0.5)
            .unwrap();
        tree.split(PaneId(0), PaneId(2), SplitAxis::Horizontal, 0.5)
            .unwrap();
        tree.split(PaneId(1), PaneId(3), SplitAxis::Horizontal, 0.5)
            .unwrap();
        // V( H(0,2), H(1,3) ) — merge 0 promotes Leaf(2) into the left slot.
        let focus = tree.merge(PaneId(0)).unwrap();
        assert_eq!(focus, PaneId(2));
        assert_eq!(tree.leaves(), vec![PaneId(2), PaneId(1), PaneId(3)]);
        // Merge the remaining left leaf → promote the whole right subtree.
        let focus = tree.merge(PaneId(2)).unwrap();
        assert_eq!(focus, PaneId(1));
        assert_eq!(tree.leaves(), vec![PaneId(1), PaneId(3)]);
        assert!(matches!(
            tree,
            PaneLayout::Split {
                axis: SplitAxis::Horizontal,
                ..
            }
        ));
    }

    #[test]
    fn merge_unknown_and_last_leave_tree_unchanged() {
        let mut sole = PaneLayout::leaf(PaneId(0));
        assert_eq!(sole.merge(PaneId(0)), Err(UiError::LastPane));
        assert_eq!(sole, PaneLayout::leaf(PaneId(0)));
        assert_eq!(sole.merge(PaneId(9)), Err(UiError::UnknownPane(9)));
        assert_eq!(sole, PaneLayout::leaf(PaneId(0)));

        let mut tree = PaneLayout::leaf(PaneId(0));
        tree.split(PaneId(0), PaneId(1), SplitAxis::Vertical, 0.5)
            .unwrap();
        let before = tree.clone();
        assert_eq!(tree.merge(PaneId(9)), Err(UiError::UnknownPane(9)));
        assert_eq!(tree, before);
    }

    #[test]
    fn set_ratio_clamps_and_rejects_non_finite() {
        let mut tree = PaneLayout::leaf(PaneId(0));
        tree.split(PaneId(0), PaneId(1), SplitAxis::Vertical, 0.5)
            .unwrap();
        tree.set_ratio_for_pane(PaneId(0), 0.01).unwrap();
        assert_eq!(tree.ratio_for_pane(PaneId(0)), Some(SPLIT_RATIO_MIN));
        for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            assert_eq!(
                tree.set_ratio_for_pane(PaneId(1), bad),
                Err(UiError::InvalidSplitRatio)
            );
            assert_eq!(tree.ratio_for_pane(PaneId(1)), Some(SPLIT_RATIO_MIN));
        }
    }

    #[test]
    fn set_ratio_sole_leaf_and_unknown_errors() {
        let mut tree = PaneLayout::leaf(PaneId(0));
        assert_eq!(
            tree.set_ratio_for_pane(PaneId(0), 0.5),
            Err(UiError::NoSplitForPane(0))
        );
        assert_eq!(
            tree.set_ratio_for_pane(PaneId(9), 0.5),
            Err(UiError::UnknownPane(9))
        );
    }

    #[test]
    fn arrangement_for_count() {
        assert_eq!(PaneArrangement::for_count(1), PaneArrangement::Single);
        assert_eq!(PaneArrangement::for_count(2), PaneArrangement::VerticalSplit);
        assert_eq!(PaneArrangement::for_count(3), PaneArrangement::HorizontalSplit);
        assert_eq!(PaneArrangement::for_count(4), PaneArrangement::Quad);
    }
}
