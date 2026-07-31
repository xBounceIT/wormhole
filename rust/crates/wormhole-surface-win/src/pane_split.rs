//! Pane split/merge → [`BrokerPaneLayoutSink`] layout-tick glue (Fake broker).
//!
//! Enabled with `--features pane-layout`. After a successful
//! [`WorkspaceState`] split/merge, emits one [`PaneLayoutSink::on_pane_layout`]
//! tick derived from the recursive layout tree + caller content rect. Failed
//! ops leave workspace + sink unchanged (fail-closed) and reuse
//! [`wormhole_ui::UiError`] (`DuplicatePane`, `UnknownPane`, `PaneLimitReached`,
//! `InvalidSplitRatio`, `LastPane`, …).
//!
//! [`merge_and_notify_bound`] also [`BrokerPaneLayoutSink::unbind`]s the closed
//! pane so the next split cannot reuse that [`PaneId`] against a stale surface.
//! The unbound [`merge_and_notify`] helper only omit-hides via the tick — broker
//! callers must unbind themselves or use the `_bound` entry point.
//! Does **not** rewrite [`super::pane_layout::BrokerPaneLayoutSink`] tick
//! internals or drive GPUI chrome.

use wormhole_ui::{
    notify_workspace_layout, PaneId, PaneLayoutSink, PanePhysicalBounds, SplitAxis, UiError,
    WorkspaceState,
};

use crate::pane_layout::BrokerPaneLayoutSink;
use crate::NativeSurfaceBroker;

/// Split `target` (auto-allocate pane id), then notify `sink`.
///
/// On [`Err`], neither the workspace nor the sink is mutated.
pub fn split_and_notify(
    workspace: &mut WorkspaceState,
    sink: &mut impl PaneLayoutSink,
    target: PaneId,
    axis: SplitAxis,
    ratio: f32,
    content: PanePhysicalBounds,
) -> Result<PaneId, UiError> {
    let new_pane = workspace.split_directed(target, axis, ratio)?;
    notify_workspace_layout(workspace, sink, content);
    Ok(new_pane)
}

/// Split the focused pane vertically at the default ratio, then notify `sink`.
pub fn split_focused_and_notify(
    workspace: &mut WorkspaceState,
    sink: &mut impl PaneLayoutSink,
    content: PanePhysicalBounds,
) -> Result<PaneId, UiError> {
    let new_pane = workspace.split()?;
    notify_workspace_layout(workspace, sink, content);
    Ok(new_pane)
}

/// Split introducing caller-owned `new_pane`, then notify `sink`.
///
/// Fail-closed on [`UiError::DuplicatePane`] (and other [`UiError`] variants)
/// without emitting a layout tick.
pub fn split_with_and_notify(
    workspace: &mut WorkspaceState,
    sink: &mut impl PaneLayoutSink,
    target: PaneId,
    new_pane: PaneId,
    axis: SplitAxis,
    ratio: f32,
    content: PanePhysicalBounds,
) -> Result<(), UiError> {
    workspace.split_with(target, new_pane, axis, ratio)?;
    notify_workspace_layout(workspace, sink, content);
    Ok(())
}

/// Merge/close `pane`, then notify `sink` (omitted pane → hide via sink).
///
/// On [`Err`] ([`UiError::LastPane`] / [`UiError::UnknownPane`]), state + sink
/// unchanged.
///
/// When driving a [`BrokerPaneLayoutSink`], prefer [`merge_and_notify_bound`]:
/// omit-hide alone leaves the `PaneId` binding, and the next split may reuse
/// that id (lowest free slot) against the stale surface. Callers using this
/// unbound helper with a broker sink must [`BrokerPaneLayoutSink::unbind`] the
/// closed pane themselves before id reuse.
pub fn merge_and_notify(
    workspace: &mut WorkspaceState,
    sink: &mut impl PaneLayoutSink,
    pane: PaneId,
    content: PanePhysicalBounds,
) -> Result<(), UiError> {
    workspace.merge(pane)?;
    notify_workspace_layout(workspace, sink, content);
    Ok(())
}

/// [`split_and_notify`] against a [`BrokerPaneLayoutSink`] (Fake / stub broker).
pub fn split_and_notify_bound<B: NativeSurfaceBroker + Send>(
    workspace: &mut WorkspaceState,
    sink: &mut BrokerPaneLayoutSink<B>,
    target: PaneId,
    axis: SplitAxis,
    ratio: f32,
    content: PanePhysicalBounds,
) -> Result<PaneId, UiError> {
    split_and_notify(workspace, sink, target, axis, ratio, content)
}

/// Merge/close `pane` against a [`BrokerPaneLayoutSink`], drop its binding, then
/// notify survivors.
///
/// Unbind runs only after a successful merge so fail-closed errors leave
/// bindings untouched. Dropping the binding prevents PaneId reuse (lowest free
/// slot) from laying out the previous surface under the recycled id.
pub fn merge_and_notify_bound<B: NativeSurfaceBroker + Send>(
    workspace: &mut WorkspaceState,
    sink: &mut BrokerPaneLayoutSink<B>,
    pane: PaneId,
    content: PanePhysicalBounds,
) -> Result<(), UiError> {
    workspace.merge(pane)?;
    // Soft no-op when unbound; hide + drop mapping when present.
    sink.unbind(pane);
    notify_workspace_layout(workspace, sink, content);
    Ok(())
}

/// Re-emit the current workspace tree as a layout tick (resize / rebind path).
pub fn notify_bound_layout<B: NativeSurfaceBroker + Send>(
    workspace: &WorkspaceState,
    sink: &mut BrokerPaneLayoutSink<B>,
    content: PanePhysicalBounds,
) {
    notify_workspace_layout(workspace, sink, content);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounds::SurfaceVisibility;
    use crate::kinds::SurfaceKind;
    use crate::{OwnerHwnd, StubNativeSurfaceBroker};
    use wormhole_ui::{RecordingPaneLayoutSink, SPLIT_RATIO_DEFAULT, MAX_PANES};

    fn content(w: u32, h: u32) -> PanePhysicalBounds {
        PanePhysicalBounds {
            x: 0,
            y: 0,
            width: w,
            height: h,
            dpi: 96,
        }
    }

    #[test]
    fn split_emits_layout_tick_to_recording_sink() {
        let mut ws = WorkspaceState::single_pane();
        let mut sink = RecordingPaneLayoutSink::default();
        let new_pane = split_and_notify(
            &mut ws,
            &mut sink,
            PaneId(0),
            SplitAxis::Vertical,
            SPLIT_RATIO_DEFAULT,
            content(800, 600),
        )
        .expect("split");
        assert_eq!(new_pane, PaneId(1));
        assert_eq!(ws.pane_count(), 2);
        assert_eq!(sink.ticks.len(), 1);
        assert_eq!(sink.ticks[0].len(), 2);
    }

    #[test]
    fn split_reaches_fake_broker_via_bound_sink() {
        let mut broker = StubNativeSurfaceBroker::new();
        let web = broker
            .register(OwnerHwnd(0x10), SurfaceKind::WebView2)
            .expect("register");
        let mut sink = BrokerPaneLayoutSink::new(broker);
        sink.bind(PaneId(0), web);

        let mut ws = WorkspaceState::single_pane();
        split_and_notify_bound(
            &mut ws,
            &mut sink,
            PaneId(0),
            SplitAxis::Vertical,
            0.5,
            content(1000, 500),
        )
        .expect("split");

        let u = sink.broker().last_update(web.id).expect("pane 0 layout");
        assert_eq!(u.visibility, SurfaceVisibility::Visible);
        assert_eq!(u.bounds.width, 500);
        assert_eq!(u.bounds.height, 500);
    }

    #[test]
    fn merge_omits_closed_pane_and_hides_bound_surface() {
        let mut broker = StubNativeSurfaceBroker::new();
        let a = broker
            .register(OwnerHwnd(1), SurfaceKind::WebView2)
            .unwrap();
        let b = broker
            .register(OwnerHwnd(1), SurfaceKind::RdpActiveX)
            .unwrap();
        let mut sink = BrokerPaneLayoutSink::new(broker);
        sink.bind(PaneId(0), a);
        sink.bind(PaneId(1), b);

        let mut ws = WorkspaceState::single_pane();
        split_focused_and_notify(&mut ws, &mut sink, content(200, 200)).unwrap();
        assert_eq!(
            sink.broker().last_update(b.id).unwrap().visibility,
            SurfaceVisibility::Visible
        );

        merge_and_notify_bound(&mut ws, &mut sink, PaneId(1), content(200, 200)).unwrap();
        assert_eq!(ws.pane_count(), 1);
        assert!(sink.binding(PaneId(1)).is_none(), "closed pane must unbind");
        assert_eq!(
            sink.broker().last_update(b.id).unwrap().visibility,
            SurfaceVisibility::Hidden
        );
        assert_eq!(
            sink.broker().last_update(a.id).unwrap().visibility,
            SurfaceVisibility::Visible
        );
        assert_eq!(sink.broker().last_update(a.id).unwrap().bounds.width, 200);
    }

    #[test]
    fn merge_bound_unbinds_so_pane_id_reuse_does_not_resurrect_surface() {
        let mut broker = StubNativeSurfaceBroker::new();
        let a = broker
            .register(OwnerHwnd(1), SurfaceKind::WebView2)
            .unwrap();
        let old_second = broker
            .register(OwnerHwnd(1), SurfaceKind::RdpActiveX)
            .unwrap();
        let mut sink = BrokerPaneLayoutSink::new(broker);
        sink.bind(PaneId(0), a);
        sink.bind(PaneId(1), old_second);

        let mut ws = WorkspaceState::single_pane();
        split_focused_and_notify(&mut ws, &mut sink, content(400, 200)).unwrap();
        merge_and_notify_bound(&mut ws, &mut sink, PaneId(1), content(400, 200)).unwrap();

        // Lowest free slot reuses PaneId(1); without unbind this would push onto old_second.
        let reused = split_and_notify_bound(
            &mut ws,
            &mut sink,
            PaneId(0),
            SplitAxis::Vertical,
            0.5,
            content(400, 200),
        )
        .unwrap();
        assert_eq!(reused, PaneId(1));
        assert!(sink.binding(PaneId(1)).is_none());
        assert_eq!(
            sink.broker().last_update(old_second.id).unwrap().visibility,
            SurfaceVisibility::Hidden
        );
        // Survivor still laid out; recycled id has no binding → no resurrect.
        assert_eq!(
            sink.broker().last_update(a.id).unwrap().visibility,
            SurfaceVisibility::Visible
        );
        assert_eq!(sink.broker().last_update(a.id).unwrap().bounds.width, 200);
    }

    #[test]
    fn merge_unknown_pane_fail_closed_no_tick() {
        let mut ws = WorkspaceState::single_pane();
        ws.split().unwrap();
        let mut sink = RecordingPaneLayoutSink::default();
        let before = ws.clone();
        assert_eq!(
            merge_and_notify(&mut ws, &mut sink, PaneId(9), content(10, 10)),
            Err(UiError::UnknownPane(9))
        );
        assert_eq!(ws, before);
        assert!(sink.ticks.is_empty());
    }

    #[test]
    fn merge_bound_fail_closed_preserves_binding() {
        let mut sink = BrokerPaneLayoutSink::new(StubNativeSurfaceBroker::new());
        let handle = sink
            .register_and_bind(PaneId(0), OwnerHwnd(1), SurfaceKind::WebView2)
            .unwrap();
        let mut ws = WorkspaceState::single_pane();
        assert_eq!(
            merge_and_notify_bound(&mut ws, &mut sink, PaneId(0), content(10, 10)),
            Err(UiError::LastPane)
        );
        assert_eq!(sink.binding(PaneId(0)).map(|h| h.id), Some(handle.id));
        assert!(sink.broker().last_update(handle.id).is_none());
    }

    #[test]
    fn split_with_and_notify_emits_tick_on_success() {
        let mut ws = WorkspaceState::single_pane();
        let mut sink = RecordingPaneLayoutSink::default();
        split_with_and_notify(
            &mut ws,
            &mut sink,
            PaneId(0),
            PaneId(3),
            SplitAxis::Horizontal,
            0.5,
            content(100, 200),
        )
        .expect("split_with");
        assert_eq!(ws.panes(), &[PaneId(0), PaneId(3)]);
        assert_eq!(sink.ticks.len(), 1);
        assert_eq!(sink.ticks[0].len(), 2);
        assert_eq!(sink.ticks[0][0].bounds.height, 100);
        assert_eq!(sink.ticks[0][1].bounds.height, 100);
    }

    #[test]
    fn duplicate_pane_fail_closed_no_tick() {
        let mut ws = WorkspaceState::single_pane();
        ws.split().unwrap();
        let mut sink = RecordingPaneLayoutSink::default();
        let before = ws.clone();
        assert_eq!(
            split_with_and_notify(
                &mut ws,
                &mut sink,
                PaneId(0),
                PaneId(1),
                SplitAxis::Vertical,
                0.5,
                content(100, 100),
            ),
            Err(UiError::DuplicatePane(1))
        );
        assert_eq!(ws, before);
        assert!(sink.ticks.is_empty());
    }

    #[test]
    fn invalid_ratio_fail_closed_no_tick() {
        let mut ws = WorkspaceState::single_pane();
        let mut sink = RecordingPaneLayoutSink::default();
        let before = ws.clone();
        for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            assert_eq!(
                split_and_notify(
                    &mut ws,
                    &mut sink,
                    PaneId(0),
                    SplitAxis::Vertical,
                    bad,
                    content(100, 100),
                ),
                Err(UiError::InvalidSplitRatio)
            );
            assert_eq!(ws, before);
        }
        assert!(sink.ticks.is_empty());
    }

    #[test]
    fn unknown_target_and_pane_limit_fail_closed() {
        let mut ws = WorkspaceState::single_pane();
        let mut sink = RecordingPaneLayoutSink::default();
        assert_eq!(
            split_and_notify(
                &mut ws,
                &mut sink,
                PaneId(9),
                SplitAxis::Vertical,
                0.5,
                content(10, 10),
            ),
            Err(UiError::UnknownPane(9))
        );
        assert_eq!(ws.pane_count(), 1);
        assert!(sink.ticks.is_empty());

        for _ in 0..(MAX_PANES - 1) {
            split_focused_and_notify(&mut ws, &mut sink, content(10, 10)).unwrap();
        }
        let ticks_before = sink.ticks.len();
        let before = ws.clone();
        assert_eq!(
            split_focused_and_notify(&mut ws, &mut sink, content(10, 10)),
            Err(UiError::PaneLimitReached(MAX_PANES))
        );
        assert_eq!(ws, before);
        assert_eq!(sink.ticks.len(), ticks_before);
    }

    #[test]
    fn merge_last_pane_fail_closed_no_tick() {
        let mut ws = WorkspaceState::single_pane();
        let mut sink = RecordingPaneLayoutSink::default();
        assert_eq!(
            merge_and_notify(&mut ws, &mut sink, PaneId(0), content(10, 10)),
            Err(UiError::LastPane)
        );
        assert_eq!(ws.pane_count(), 1);
        assert!(sink.ticks.is_empty());
    }

    #[test]
    fn notify_bound_layout_without_mutation() {
        let mut sink = BrokerPaneLayoutSink::new(StubNativeSurfaceBroker::new());
        let handle = sink
            .register_and_bind(PaneId(0), OwnerHwnd(1), SurfaceKind::WebView2)
            .unwrap();
        let ws = WorkspaceState::single_pane();
        notify_bound_layout(&ws, &mut sink, content(64, 48));
        let u = sink.broker().last_update(handle.id).unwrap();
        assert_eq!(u.bounds.width, 64);
        assert_eq!(u.bounds.height, 48);
    }
}
