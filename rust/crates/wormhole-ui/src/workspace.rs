use crate::pane_layout::{
    PaneArrangement, PaneLayout, SplitAxis, SPLIT_RATIO_DEFAULT,
};
use crate::UiError;

/// Hard cap matching the migration plan (quad-split max).
pub const MAX_PANES: usize = 4;

/// Stable pane slot id within a workspace (0..MAX_PANES).
///
/// Ids are **not** renumbered on close — closing pane 0 leaves panes `[1, 2]` as
/// `[1, 2]` so tab → pane assignments stay valid for surviving panes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PaneId(pub u8);

impl PaneId {
    pub fn index(self) -> usize {
        self.0 as usize
    }
}

/// Workspace pane set (1..=4) backed by a recursive [`PaneLayout`] tree.
///
/// Pane 0 always exists at construction. The flat `panes` list is the **insertion
/// order** of open slots (append on split, stable relative order on close) and is
/// what chrome / [`crate::PaneLayoutSink`] ticks iterate. That order can diverge
/// from DFS [`PaneLayout::leaves`] after nested splits; the leaf **set** stays
/// equal (`pane_count` == `layout.leaf_count()`).
#[derive(Debug, Clone, PartialEq)]
pub struct WorkspaceState {
    panes: Vec<PaneId>,
    focused: PaneId,
    layout: PaneLayout,
}

impl WorkspaceState {
    pub fn single_pane() -> Self {
        Self {
            panes: vec![PaneId(0)],
            focused: PaneId(0),
            layout: PaneLayout::leaf(PaneId(0)),
        }
    }

    pub fn pane_count(&self) -> usize {
        self.panes.len()
    }

    pub fn panes(&self) -> &[PaneId] {
        &self.panes
    }

    pub fn focused(&self) -> PaneId {
        self.focused
    }

    /// Recursive layout tree (axis + clamped ratios).
    pub fn layout(&self) -> &PaneLayout {
        &self.layout
    }

    /// Coarse count-derived arrangement (chrome tile presets).
    pub fn arrangement(&self) -> PaneArrangement {
        PaneArrangement::for_count(self.panes.len())
    }

    pub fn contains(&self, id: PaneId) -> bool {
        self.panes.contains(&id)
    }

    pub fn focus(&mut self, id: PaneId) -> Result<(), UiError> {
        if !self.panes.contains(&id) {
            return Err(UiError::UnknownPane(id.0));
        }
        self.focused = id;
        Ok(())
    }

    /// Split the focused pane vertically at the default ratio.
    ///
    /// Allocates the lowest free slot in `0..MAX_PANES` so ids stay stable across closes.
    pub fn split(&mut self) -> Result<PaneId, UiError> {
        self.split_directed(self.focused, SplitAxis::Vertical, SPLIT_RATIO_DEFAULT)
    }

    /// Split `target` along `axis` at `ratio` (NaN / ±Inf rejected; finite clamped).
    ///
    /// Allocates the lowest free slot in `0..MAX_PANES`.
    pub fn split_directed(
        &mut self,
        target: PaneId,
        axis: SplitAxis,
        ratio: f32,
    ) -> Result<PaneId, UiError> {
        if self.panes.len() >= MAX_PANES {
            return Err(UiError::PaneLimitReached(MAX_PANES));
        }
        let next = (0..MAX_PANES as u8)
            .map(PaneId)
            .find(|id| !self.panes.contains(id))
            .expect("free pane slot exists when under MAX_PANES");
        self.split_with(target, next, axis, ratio)?;
        Ok(next)
    }

    /// Split `target` introducing caller-owned `new_pane`.
    ///
    /// Fail-closed (state unchanged): pane limit, unknown `target`,
    /// [`UiError::DuplicatePane`] when `new_pane` is already open (including
    /// `new_pane == target`), or non-finite `ratio`.
    pub fn split_with(
        &mut self,
        target: PaneId,
        new_pane: PaneId,
        axis: SplitAxis,
        ratio: f32,
    ) -> Result<(), UiError> {
        if self.panes.len() >= MAX_PANES {
            return Err(UiError::PaneLimitReached(MAX_PANES));
        }
        if !self.panes.contains(&target) {
            return Err(UiError::UnknownPane(target.0));
        }
        // Tree rejects DuplicatePane / InvalidSplitRatio before mutation.
        self.layout.split(target, new_pane, axis, ratio)?;
        // Keep insertion order for chrome slot tiling (not DFS leaf order).
        self.panes.push(new_pane);
        debug_assert_eq!(self.panes.len(), self.layout.leaf_count());
        self.focused = new_pane;
        Ok(())
    }

    /// Merge/remove `id` by collapsing its parent split (same as close for leaves).
    pub fn merge(&mut self, id: PaneId) -> Result<(), UiError> {
        self.close_pane(id)
    }

    pub fn close_pane(&mut self, id: PaneId) -> Result<(), UiError> {
        if self.panes.len() == 1 {
            return Err(UiError::LastPane);
        }
        let idx = self
            .panes
            .iter()
            .position(|p| *p == id)
            .ok_or(UiError::UnknownPane(id.0))?;
        self.layout.merge(id)?;
        self.panes.remove(idx);
        debug_assert_eq!(self.panes.len(), self.layout.leaf_count());
        if self.focused == id {
            // Prefer the pane that slid into the closed index (neighbor).
            let neighbor = idx.min(self.panes.len() - 1);
            self.focused = self.panes[neighbor];
        }
        Ok(())
    }

    /// Set the parent-split ratio for `pane` (NaN / ±Inf rejected; finite clamped).
    pub fn set_split_ratio(&mut self, pane: PaneId, ratio: f32) -> Result<(), UiError> {
        self.layout.set_ratio_for_pane(pane, ratio)
    }

    /// Empty workspace (no panes).
    ///
    /// Unreachable via public split/close (last pane is retained). Exposed for
    /// defensive focus-glue fail-closed paths and unit tests.
    pub fn empty() -> Self {
        Self {
            panes: Vec::new(),
            focused: PaneId(0),
            layout: PaneLayout::leaf(PaneId(0)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pane_layout::SPLIT_RATIO_MIN;

    #[test]
    fn split_up_to_four_then_reject() {
        let mut ws = WorkspaceState::single_pane();
        assert_eq!(ws.split().unwrap(), PaneId(1));
        assert_eq!(ws.arrangement(), PaneArrangement::VerticalSplit);
        assert_eq!(ws.split().unwrap(), PaneId(2));
        assert_eq!(ws.split().unwrap(), PaneId(3));
        assert_eq!(ws.arrangement(), PaneArrangement::Quad);
        assert_eq!(ws.pane_count(), 4);
        assert!(matches!(
            ws.split(),
            Err(UiError::PaneLimitReached(MAX_PANES))
        ));
        assert_eq!(ws.layout().leaf_count(), 4);
    }

    #[test]
    fn cannot_close_last_pane() {
        let mut ws = WorkspaceState::single_pane();
        assert_eq!(ws.close_pane(PaneId(0)), Err(UiError::LastPane));
        ws.split().unwrap();
        ws.close_pane(PaneId(0)).unwrap();
        assert_eq!(ws.pane_count(), 1);
        // Surviving pane keeps its stable id (was 1), not renumbered to 0.
        assert_eq!(ws.panes()[0], PaneId(1));
        assert_eq!(ws.focused(), PaneId(1));
        assert_eq!(ws.layout(), &PaneLayout::leaf(PaneId(1)));
    }

    #[test]
    fn pane_ids_stable_across_close() {
        let mut ws = WorkspaceState::single_pane();
        assert_eq!(ws.split().unwrap(), PaneId(1));
        assert_eq!(ws.split().unwrap(), PaneId(2));
        ws.focus(PaneId(2)).unwrap();
        ws.close_pane(PaneId(0)).unwrap();
        assert_eq!(ws.panes(), &[PaneId(1), PaneId(2)]);
        assert_eq!(ws.focused(), PaneId(2));
        // Re-split reuses the lowest free slot (0), not len().
        assert_eq!(ws.split().unwrap(), PaneId(0));
        assert_eq!(ws.pane_count(), 3);
    }

    #[test]
    fn close_focused_selects_neighbor() {
        let mut ws = WorkspaceState::single_pane();
        ws.split().unwrap();
        ws.split().unwrap();
        ws.focus(PaneId(1)).unwrap();
        ws.close_pane(PaneId(1)).unwrap();
        assert_eq!(ws.panes(), &[PaneId(0), PaneId(2)]);
        assert_eq!(ws.focused(), PaneId(2));
    }

    #[test]
    fn focus_rejects_unknown() {
        let mut ws = WorkspaceState::single_pane();
        assert_eq!(ws.focus(PaneId(3)), Err(UiError::UnknownPane(3)));
    }

    #[test]
    fn empty_workspace_helper_has_zero_panes() {
        let ws = WorkspaceState::empty();
        assert_eq!(ws.pane_count(), 0);
        assert!(ws.panes().is_empty());
    }

    #[test]
    fn directed_horizontal_split_and_merge() {
        let mut ws = WorkspaceState::single_pane();
        let p1 = ws
            .split_directed(PaneId(0), SplitAxis::Horizontal, 0.01)
            .unwrap();
        assert_eq!(p1, PaneId(1));
        assert!(matches!(
            ws.layout(),
            PaneLayout::Split {
                axis: SplitAxis::Horizontal,
                ratio,
                ..
            } if (*ratio - SPLIT_RATIO_MIN).abs() < f32::EPSILON
        ));
        ws.merge(PaneId(1)).unwrap();
        assert_eq!(ws.layout(), &PaneLayout::leaf(PaneId(0)));
        assert_eq!(ws.pane_count(), 1);
    }

    #[test]
    fn split_directed_rejects_non_finite_without_mutating() {
        let mut ws = WorkspaceState::single_pane();
        let before = ws.clone();
        for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            assert_eq!(
                ws.split_directed(PaneId(0), SplitAxis::Vertical, bad),
                Err(UiError::InvalidSplitRatio)
            );
            assert_eq!(ws, before);
        }
    }

    #[test]
    fn set_split_ratio_on_workspace() {
        let mut ws = WorkspaceState::single_pane();
        ws.split().unwrap();
        ws.set_split_ratio(PaneId(0), 0.9).unwrap();
        assert_eq!(
            ws.layout().ratio_for_pane(PaneId(0)),
            Some(crate::pane_layout::SPLIT_RATIO_MAX)
        );
        let ratio = ws.layout().ratio_for_pane(PaneId(0));
        for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            assert_eq!(
                ws.set_split_ratio(PaneId(0), bad),
                Err(UiError::InvalidSplitRatio)
            );
            assert_eq!(ws.layout().ratio_for_pane(PaneId(0)), ratio);
        }
    }

    #[test]
    fn panes_insertion_order_stable_for_broker_when_dfs_diverges() {
        let mut ws = WorkspaceState::single_pane();
        ws.split_directed(PaneId(0), SplitAxis::Vertical, 0.5)
            .unwrap();
        // Nested split of the *first* child → DFS leaves ≠ insertion order.
        ws.split_directed(PaneId(0), SplitAxis::Horizontal, 0.5)
            .unwrap();
        assert_eq!(ws.panes(), &[PaneId(0), PaneId(1), PaneId(2)]);
        assert_eq!(
            ws.layout().leaves(),
            vec![PaneId(0), PaneId(2), PaneId(1)]
        );
        assert_ne!(ws.panes(), ws.layout().leaves().as_slice());

        // Close middle insertion slot — survivors keep relative insertion order.
        ws.close_pane(PaneId(1)).unwrap();
        assert_eq!(ws.panes(), &[PaneId(0), PaneId(2)]);
        let mut sorted_panes: Vec<_> = ws.panes().to_vec();
        let mut sorted_leaves = ws.layout().leaves();
        sorted_panes.sort_by_key(|p| p.0);
        sorted_leaves.sort_by_key(|p| p.0);
        assert_eq!(sorted_panes, sorted_leaves);
        assert_eq!(ws.pane_count(), ws.layout().leaf_count());
    }

    #[test]
    fn close_unknown_and_unfocused_leave_focus() {
        let mut ws = WorkspaceState::single_pane();
        ws.split().unwrap();
        ws.focus(PaneId(0)).unwrap();
        let before = ws.clone();
        assert_eq!(ws.close_pane(PaneId(9)), Err(UiError::UnknownPane(9)));
        assert_eq!(ws, before);

        ws.close_pane(PaneId(1)).unwrap();
        assert_eq!(ws.focused(), PaneId(0));
        assert_eq!(ws.panes(), &[PaneId(0)]);
    }

    #[test]
    fn split_with_duplicate_pane_fail_closed() {
        let mut ws = WorkspaceState::single_pane();
        ws.split().unwrap();
        let before = ws.clone();
        assert_eq!(
            ws.split_with(PaneId(0), PaneId(1), SplitAxis::Vertical, 0.5),
            Err(UiError::DuplicatePane(1))
        );
        assert_eq!(
            ws.split_with(PaneId(0), PaneId(0), SplitAxis::Vertical, 0.5),
            Err(UiError::DuplicatePane(0))
        );
        assert_eq!(ws, before);
    }
}
