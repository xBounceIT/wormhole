//! Pane layout bounds sink for chrome → native surface wiring.
//!
//! GPUI chrome computes physical pane slots each layout pass and notifies a
//! [`PaneLayoutSink`]. The composition root adapts this via
//! `wormhole_surface_win::BrokerPaneLayoutSink` (`--features pane-layout` on
//! that crate); no HWND work lives in `wormhole-ui` itself.
//!
//! Headless / Fake-broker glue can also derive ticks from the recursive
//! [`crate::PaneLayout`] tree via [`physical_updates_for_layout`] (no GPUI).

use crate::pane_layout::{PaneLayout, SplitAxis};
use crate::workspace::{PaneId, WorkspaceState};

/// Physical-pixel bounds for one workspace pane slot.
///
/// Field layout mirrors `wormhole_surface_win::PhysicalBounds` so the app
/// composition root can convert without pulling that crate into `wormhole-ui`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PanePhysicalBounds {
    /// Left edge in physical pixels.
    pub x: i32,
    /// Top edge in physical pixels.
    pub y: i32,
    /// Width in physical pixels (0 = degenerate / hidden).
    pub width: u32,
    /// Height in physical pixels (0 = degenerate / hidden).
    pub height: u32,
    /// DPI of the window at the layout pass (e.g. 96, 144, 192).
    pub dpi: u32,
}

impl PanePhysicalBounds {
    /// True when either axis is zero (skip SetWindowPos / hide surface).
    pub fn is_degenerate(self) -> bool {
        self.width == 0 || self.height == 0
    }
}

/// One pane's layout update for a layout tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PaneLayoutUpdate {
    pub pane: PaneId,
    pub bounds: PanePhysicalBounds,
}

/// Receives pane layout bounds after each chrome layout pass.
///
/// `NativeSurfaceBroker` adapters (e.g. `BrokerPaneLayoutSink` in
/// `wormhole-surface-win`) implement this; chrome only needs the trait object.
pub trait PaneLayoutSink: Send {
    /// Called with the full set of **currently open** panes for this tick.
    /// Closed panes are omitted (not reported as degenerate).
    fn on_pane_layout(&mut self, updates: &[PaneLayoutUpdate]);
}

/// No-op sink (lab / tests without a broker).
#[derive(Debug, Default, Clone, Copy)]
pub struct NopPaneLayoutSink;

impl PaneLayoutSink for NopPaneLayoutSink {
    fn on_pane_layout(&mut self, _updates: &[PaneLayoutUpdate]) {}
}

/// Records layout ticks for unit tests.
#[derive(Debug, Default, Clone)]
pub struct RecordingPaneLayoutSink {
    pub ticks: Vec<Vec<PaneLayoutUpdate>>,
}

impl PaneLayoutSink for RecordingPaneLayoutSink {
    fn on_pane_layout(&mut self, updates: &[PaneLayoutUpdate]) {
        self.ticks.push(updates.to_vec());
    }
}

/// Derive physical pane slots from a recursive [`PaneLayout`] + content rect.
///
/// Walks the tree (DFS leaf order). Split ratios are treated as already
/// normalized by layout ops; non-finite ratios fall back to `0.5`. No splitter
/// gap — chrome drag tiling may insert gaps separately. Identity is by
/// [`PaneId`]; tick order is not required to match
/// [`WorkspaceState::panes`] insertion order.
pub fn physical_updates_for_layout(
    layout: &PaneLayout,
    content: PanePhysicalBounds,
) -> Vec<PaneLayoutUpdate> {
    let mut out = Vec::with_capacity(layout.leaf_count());
    collect_physical_updates(layout, content, &mut out);
    out
}

/// [`physical_updates_for_layout`] using [`WorkspaceState::layout`].
pub fn physical_updates_for_workspace(
    workspace: &WorkspaceState,
    content: PanePhysicalBounds,
) -> Vec<PaneLayoutUpdate> {
    physical_updates_for_layout(workspace.layout(), content)
}

/// Push a full layout tick for the current workspace tree into `sink`.
pub fn notify_workspace_layout(
    workspace: &WorkspaceState,
    sink: &mut impl PaneLayoutSink,
    content: PanePhysicalBounds,
) {
    let updates = physical_updates_for_workspace(workspace, content);
    sink.on_pane_layout(&updates);
}

fn collect_physical_updates(
    layout: &PaneLayout,
    bounds: PanePhysicalBounds,
    out: &mut Vec<PaneLayoutUpdate>,
) {
    match layout {
        PaneLayout::Leaf(pane) => {
            out.push(PaneLayoutUpdate {
                pane: *pane,
                bounds,
            });
        }
        PaneLayout::Split {
            axis,
            ratio,
            first,
            second,
        } => {
            let (a, b) = split_physical_bounds(bounds, *axis, *ratio);
            collect_physical_updates(first, a, out);
            collect_physical_updates(second, b, out);
        }
    }
}

fn split_physical_bounds(
    bounds: PanePhysicalBounds,
    axis: SplitAxis,
    ratio: f32,
) -> (PanePhysicalBounds, PanePhysicalBounds) {
    let ratio = if ratio.is_finite() {
        ratio.clamp(0.0, 1.0)
    } else {
        0.5
    };
    match axis {
        SplitAxis::Vertical => {
            let first_w = ((bounds.width as f64) * f64::from(ratio)).round() as u32;
            let first_w = first_w.min(bounds.width);
            let second_w = bounds.width.saturating_sub(first_w);
            (
                PanePhysicalBounds {
                    x: bounds.x,
                    y: bounds.y,
                    width: first_w,
                    height: bounds.height,
                    dpi: bounds.dpi,
                },
                PanePhysicalBounds {
                    x: bounds.x.saturating_add(first_w as i32),
                    y: bounds.y,
                    width: second_w,
                    height: bounds.height,
                    dpi: bounds.dpi,
                },
            )
        }
        SplitAxis::Horizontal => {
            let first_h = ((bounds.height as f64) * f64::from(ratio)).round() as u32;
            let first_h = first_h.min(bounds.height);
            let second_h = bounds.height.saturating_sub(first_h);
            (
                PanePhysicalBounds {
                    x: bounds.x,
                    y: bounds.y,
                    width: bounds.width,
                    height: first_h,
                    dpi: bounds.dpi,
                },
                PanePhysicalBounds {
                    x: bounds.x,
                    y: bounds.y.saturating_add(first_h as i32),
                    width: bounds.width,
                    height: second_h,
                    dpi: bounds.dpi,
                },
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pane_layout::{PaneLayout, SplitAxis, SPLIT_RATIO_DEFAULT};
    use crate::workspace::WorkspaceState;

    fn content(w: u32, h: u32) -> PanePhysicalBounds {
        PanePhysicalBounds {
            x: 10,
            y: 20,
            width: w,
            height: h,
            dpi: 96,
        }
    }

    #[test]
    fn degenerate_when_axis_zero() {
        assert!(PanePhysicalBounds {
            x: 0,
            y: 0,
            width: 0,
            height: 10,
            dpi: 96
        }
        .is_degenerate());
        assert!(!PanePhysicalBounds {
            x: 1,
            y: 2,
            width: 3,
            height: 4,
            dpi: 96
        }
        .is_degenerate());
    }

    #[test]
    fn recording_sink_captures_ticks() {
        let mut sink = RecordingPaneLayoutSink::default();
        let u = PaneLayoutUpdate {
            pane: PaneId(0),
            bounds: PanePhysicalBounds {
                x: 0,
                y: 0,
                width: 100,
                height: 50,
                dpi: 96,
            },
        };
        sink.on_pane_layout(&[u]);
        assert_eq!(sink.ticks.len(), 1);
        assert_eq!(sink.ticks[0][0].pane, PaneId(0));
    }

    #[test]
    fn physical_updates_single_pane_fills_content() {
        let ws = WorkspaceState::single_pane();
        let updates = physical_updates_for_workspace(&ws, content(800, 600));
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].pane, PaneId(0));
        assert_eq!(updates[0].bounds, content(800, 600));
    }

    #[test]
    fn physical_updates_vertical_split_halves_width() {
        let mut ws = WorkspaceState::single_pane();
        ws.split_directed(PaneId(0), SplitAxis::Vertical, SPLIT_RATIO_DEFAULT)
            .unwrap();
        let updates = physical_updates_for_workspace(&ws, content(1000, 400));
        assert_eq!(updates.len(), 2);
        let by_id = |id: u8| updates.iter().find(|u| u.pane == PaneId(id)).unwrap();
        assert_eq!(by_id(0).bounds.width, 500);
        assert_eq!(by_id(1).bounds.width, 500);
        assert_eq!(by_id(0).bounds.x, 10);
        assert_eq!(by_id(1).bounds.x, 510);
        assert_eq!(by_id(0).bounds.height, 400);
        assert_eq!(by_id(1).bounds.height, 400);
    }

    #[test]
    fn physical_updates_horizontal_split_halves_height() {
        let mut layout = PaneLayout::leaf(PaneId(0));
        layout
            .split(PaneId(0), PaneId(1), SplitAxis::Horizontal, 0.5)
            .unwrap();
        let updates = physical_updates_for_layout(&layout, content(200, 100));
        assert_eq!(updates[0].bounds.height, 50);
        assert_eq!(updates[1].bounds.height, 50);
        assert_eq!(updates[1].bounds.y, 70);
    }

    #[test]
    fn notify_workspace_layout_records_tick() {
        let mut ws = WorkspaceState::single_pane();
        ws.split().unwrap();
        let mut sink = RecordingPaneLayoutSink::default();
        notify_workspace_layout(&ws, &mut sink, content(100, 100));
        assert_eq!(sink.ticks.len(), 1);
        assert_eq!(sink.ticks[0].len(), 2);
    }

    #[test]
    fn physical_updates_nested_split_and_odd_width() {
        let mut ws = WorkspaceState::single_pane();
        ws.split_directed(PaneId(0), SplitAxis::Vertical, 0.5)
            .unwrap();
        ws.split_directed(PaneId(0), SplitAxis::Horizontal, SPLIT_RATIO_DEFAULT)
            .unwrap();
        // DFS leaves can diverge from insertion order after nesting.
        assert_ne!(
            ws.panes().to_vec(),
            ws.layout().leaves(),
            "precondition: insertion vs DFS diverge"
        );
        let updates = physical_updates_for_workspace(&ws, content(1001, 400));
        assert_eq!(updates.len(), 3);
        let ids: std::collections::HashSet<_> = updates.iter().map(|u| u.pane).collect();
        assert_eq!(ids.len(), 3);
        for p in ws.panes() {
            assert!(ids.contains(p));
        }
        // 1001 * 0.5 rounds to 501 + 500.
        let by_id = |id: u8| updates.iter().find(|u| u.pane == PaneId(id)).unwrap();
        assert_eq!(by_id(0).bounds.width + by_id(1).bounds.width, 1001);
        // Pane 0 was split horizontally inside the first column.
        assert_eq!(by_id(0).bounds.height + by_id(2).bounds.height, 400);
        assert_eq!(by_id(0).bounds.width, by_id(2).bounds.width);
    }

    #[test]
    fn physical_updates_clamped_ratio_min_column() {
        let mut ws = WorkspaceState::single_pane();
        ws.split_directed(PaneId(0), SplitAxis::Vertical, 0.0)
            .unwrap(); // clamped to SPLIT_RATIO_MIN (0.15)
        let updates = physical_updates_for_workspace(&ws, content(1000, 100));
        let by_id = |id: u8| updates.iter().find(|u| u.pane == PaneId(id)).unwrap();
        assert_eq!(by_id(0).bounds.width, 150);
        assert_eq!(by_id(1).bounds.width, 850);
    }

    #[test]
    fn physical_updates_propagates_dpi_and_origin() {
        let mut ws = WorkspaceState::single_pane();
        ws.split_directed(PaneId(0), SplitAxis::Vertical, 0.5)
            .unwrap();
        let content = PanePhysicalBounds {
            x: 100,
            y: 50,
            width: 400,
            height: 300,
            dpi: 144,
        };
        let updates = physical_updates_for_workspace(&ws, content);
        assert!(updates.iter().all(|u| u.bounds.dpi == 144));
        assert_eq!(updates[0].bounds.x, 100);
        assert_eq!(updates[1].bounds.x, 300);
        assert_eq!(updates[0].bounds.y, 50);
        assert_eq!(updates[1].bounds.y, 50);
    }

    #[test]
    fn non_finite_ratio_in_tree_literal_falls_back_half() {
        // Ops reject NaN; a hand-built node still must not panic the walk.
        let layout = PaneLayout::Split {
            axis: SplitAxis::Vertical,
            ratio: f32::NAN,
            first: Box::new(PaneLayout::leaf(PaneId(0))),
            second: Box::new(PaneLayout::leaf(PaneId(1))),
        };
        let updates = physical_updates_for_layout(&layout, content(100, 50));
        assert_eq!(updates[0].bounds.width, 50);
        assert_eq!(updates[1].bounds.width, 50);
    }
}
