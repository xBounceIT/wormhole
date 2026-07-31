//! Pane focus glue: [`WorkspaceState`] ↔ [`FocusCycle`] (no GPUI chrome).
//!
//! Enabled with `--features pane-layout`. Activating or cycling a workspace pane
//! updates shell focus state and syncs [`FocusCycle`] to the pane's binding
//! (bound surface, or chrome sentinel when unbound), building a [`FocusRequest`]
//! for [`crate::FocusBroker`] when the cycle/broker target actually changes —
//! same "request only, broker applies" contract as [`FocusCycle`]. Does **not**
//! call Win32, rewrite [`super::pane_layout::BrokerPaneLayoutSink`] ticks, or
//! drive GPUI.

use wormhole_ui::{PaneId, WorkspaceState};

use crate::broker::SurfaceHandle;
use crate::focus::{
    FocusCycle, FocusCycleDirection, FocusCycleSlot, FocusReason, FocusRequest,
};
use crate::pane_layout::BrokerPaneLayoutSink;
use crate::NativeSurfaceBroker;

/// Outcome of [`activate_pane`] / [`cycle_pane_focus`].
///
/// Callers that receive [`Self::request`] should pass it to
/// [`crate::FocusBroker::request_focus`] — this glue never applies focus itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaneFocusNotify {
    /// Pane that is (or remains) focused after the call.
    pub pane: PaneId,
    /// Whether [`WorkspaceState::focused`] changed.
    pub changed: bool,
    /// Focus request when [`FocusCycle`] / broker target needs a handoff; `None`
    /// when already synced (idempotent workspace + matching cycle) or when
    /// moving among unbound panes while already on the chrome sentinel.
    pub request: Option<FocusRequest>,
}

/// Errors from pane focus glue (fail-closed; workspace / cycle left unchanged).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaneFocusError {
    /// No open panes — activate / cycle refuse to invent a focus target.
    EmptyLayout,
    /// Named pane is not in the workspace.
    UnknownPane(PaneId),
}

impl std::fmt::Display for PaneFocusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyLayout => write!(f, "cannot focus panes in an empty workspace"),
            Self::UnknownPane(id) => write!(f, "pane {} is not in the workspace", id.0),
        }
    }
}

impl std::error::Error for PaneFocusError {}

/// Activate `pane` in `workspace` and sync [`FocusCycle`] to its binding.
///
/// - **Empty layout** → [`PaneFocusError::EmptyLayout`] (state unchanged).
/// - **Unknown pane** → [`PaneFocusError::UnknownPane`] (state unchanged).
/// - **Already focused** → `changed: false`; still refreshes the cycle when the
///   binding drifted (rebind / late bind) or was never synced, emitting a
///   [`FocusRequest`] only when the broker target changes.
/// - **Focus moves** + bound surface → insert/refresh ring membership, set current,
///   return [`FocusRequest`].
/// - **Focus moves** + unbound → workspace focus updates; cycle falls back to
///   chrome (emits chrome [`FocusRequest`] when leaving a surface slot).
pub fn activate_pane(
    workspace: &mut WorkspaceState,
    cycle: &mut FocusCycle,
    resolve_surface: impl Fn(PaneId) -> Option<SurfaceHandle>,
    pane: PaneId,
    reason: FocusReason,
) -> Result<PaneFocusNotify, PaneFocusError> {
    if workspace.pane_count() == 0 {
        return Err(PaneFocusError::EmptyLayout);
    }
    if !workspace.contains(pane) {
        return Err(PaneFocusError::UnknownPane(pane));
    }
    let changed = workspace.focused() != pane;
    if changed {
        // `contains` already checked — focus only fails on unknown pane.
        workspace
            .focus(pane)
            .expect("pane present after contains check");
    }

    let request = sync_cycle_for_pane(cycle, resolve_surface(pane), reason);
    Ok(PaneFocusNotify {
        pane,
        changed,
        request,
    })
}

/// Cycle workspace pane focus in insertion order (`Next` / `Prev`), then sync.
///
/// Empty layout fail-closes. A single-pane workspace wraps onto itself
/// (`changed: false`); a bound pane still syncs [`FocusCycle`] on first wrap.
pub fn cycle_pane_focus(
    workspace: &mut WorkspaceState,
    cycle: &mut FocusCycle,
    resolve_surface: impl Fn(PaneId) -> Option<SurfaceHandle>,
    dir: FocusCycleDirection,
    reason: FocusReason,
) -> Result<PaneFocusNotify, PaneFocusError> {
    if workspace.pane_count() == 0 {
        return Err(PaneFocusError::EmptyLayout);
    }
    let panes = workspace.panes();
    let len = panes.len();
    debug_assert!(len >= 1);
    let idx = panes
        .iter()
        .position(|p| *p == workspace.focused())
        .unwrap_or(0);
    let next_idx = match dir {
        FocusCycleDirection::Next => (idx + 1) % len,
        FocusCycleDirection::Prev => (idx + len - 1) % len,
    };
    let next = panes[next_idx];
    activate_pane(workspace, cycle, resolve_surface, next, reason)
}

/// [`activate_pane`] using [`BrokerPaneLayoutSink::binding`] as the surface resolver.
pub fn activate_pane_bound<B: NativeSurfaceBroker>(
    workspace: &mut WorkspaceState,
    cycle: &mut FocusCycle,
    sink: &BrokerPaneLayoutSink<B>,
    pane: PaneId,
    reason: FocusReason,
) -> Result<PaneFocusNotify, PaneFocusError> {
    activate_pane(workspace, cycle, |id| sink.binding(id), pane, reason)
}

/// [`cycle_pane_focus`] using [`BrokerPaneLayoutSink::binding`] as the surface resolver.
pub fn cycle_pane_focus_bound<B: NativeSurfaceBroker>(
    workspace: &mut WorkspaceState,
    cycle: &mut FocusCycle,
    sink: &BrokerPaneLayoutSink<B>,
    dir: FocusCycleDirection,
    reason: FocusReason,
) -> Result<PaneFocusNotify, PaneFocusError> {
    cycle_pane_focus(workspace, cycle, |id| sink.binding(id), dir, reason)
}

/// Align [`FocusCycle`] with the focused pane's binding; emit a request only when
/// the broker target ([`FocusRequest`] owner / hwnd) changes.
fn sync_cycle_for_pane(
    cycle: &mut FocusCycle,
    surface: Option<SurfaceHandle>,
    reason: FocusReason,
) -> Option<FocusRequest> {
    let before = cycle.request_for_current(reason);
    match surface {
        Some(handle) => {
            cycle.insert_surface(handle);
            // insert_surface makes membership guaranteed; set_current cannot UnknownSurface.
            cycle
                .set_current(FocusCycleSlot::Surface(handle))
                .expect("surface just inserted into focus cycle");
        }
        None => {
            // Unbound pane → chrome sentinel (clears stale surface current).
            cycle
                .set_current(FocusCycleSlot::GpuiChrome)
                .expect("chrome sentinel is always valid");
        }
    }
    let after = cycle.request_for_current(reason);
    if before == after {
        None
    } else {
        Some(after)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::focus::{FocusHwnd, FocusOwner};
    use crate::kinds::SurfaceKind;
    use std::collections::HashMap;
    use wormhole_ui::WorkspaceState;

    fn handle(id: u64, kind: SurfaceKind) -> SurfaceHandle {
        SurfaceHandle {
            id: crate::SurfaceId(id),
            kind,
        }
    }

    fn map_resolve(
        map: &HashMap<PaneId, SurfaceHandle>,
    ) -> impl Fn(PaneId) -> Option<SurfaceHandle> + '_ {
        move |id| map.get(&id).copied()
    }

    #[test]
    fn empty_layout_activate_and_cycle_fail_closed() {
        let mut ws = WorkspaceState::empty();
        let mut cycle = FocusCycle::new();
        let before_slots = cycle.slots();
        assert_eq!(
            activate_pane(
                &mut ws,
                &mut cycle,
                |_| None,
                PaneId(0),
                FocusReason::Explicit
            ),
            Err(PaneFocusError::EmptyLayout)
        );
        assert_eq!(
            cycle_pane_focus(
                &mut ws,
                &mut cycle,
                |_| None,
                FocusCycleDirection::Next,
                FocusReason::UserHandoff
            ),
            Err(PaneFocusError::EmptyLayout)
        );
        assert_eq!(ws.pane_count(), 0);
        assert_eq!(cycle.slots(), before_slots);
        assert_eq!(cycle.current(), FocusCycleSlot::GpuiChrome);
    }

    #[test]
    fn activate_unknown_pane_fail_closed() {
        let mut ws = WorkspaceState::single_pane();
        let mut cycle = FocusCycle::new();
        let web = handle(1, SurfaceKind::WebView2);
        cycle.insert_surface(web);
        cycle
            .set_current(FocusCycleSlot::Surface(web))
            .expect("registered");
        let before_slots = cycle.slots();
        assert_eq!(
            activate_pane(
                &mut ws,
                &mut cycle,
                |_| Some(web),
                PaneId(9),
                FocusReason::Explicit
            ),
            Err(PaneFocusError::UnknownPane(PaneId(9)))
        );
        assert_eq!(ws.focused(), PaneId(0));
        assert_eq!(cycle.slots(), before_slots);
        assert_eq!(cycle.current(), FocusCycleSlot::Surface(web));
    }

    #[test]
    fn activate_idempotent_when_already_synced() {
        let mut ws = WorkspaceState::single_pane();
        let mut cycle = FocusCycle::new();
        let web = handle(1, SurfaceKind::WebView2);
        let mut map = HashMap::new();
        map.insert(PaneId(0), web);

        // First activate: workspace already focused; still syncs FocusCycle.
        let first = activate_pane(
            &mut ws,
            &mut cycle,
            map_resolve(&map),
            PaneId(0),
            FocusReason::Explicit,
        )
        .expect("activate");
        assert!(!first.changed);
        assert_eq!(
            first.request.as_ref().map(|r| r.owner),
            Some(FocusOwner::WebView2)
        );
        assert_eq!(cycle.current(), FocusCycleSlot::Surface(web));

        // Second activate: fully idempotent — no workspace or broker change.
        let again = activate_pane(
            &mut ws,
            &mut cycle,
            map_resolve(&map),
            PaneId(0),
            FocusReason::UserHandoff,
        )
        .expect("idempotent");
        assert!(!again.changed);
        assert!(again.request.is_none());
        assert_eq!(cycle.current(), FocusCycleSlot::Surface(web));

        ws.split().unwrap();
        assert_eq!(ws.focused(), PaneId(1));
        let rdp = handle(2, SurfaceKind::RdpActiveX);
        map.insert(PaneId(1), rdp);
        let on_rdp = activate_pane(
            &mut ws,
            &mut cycle,
            map_resolve(&map),
            PaneId(1),
            FocusReason::UserHandoff,
        )
        .expect("activate rdp pane");
        assert!(!on_rdp.changed); // split already focused pane 1
        assert_eq!(
            on_rdp.request.as_ref().map(|r| r.owner),
            Some(FocusOwner::RdpActiveX)
        );
        assert_eq!(cycle.current(), FocusCycleSlot::Surface(rdp));

        let moved = activate_pane(
            &mut ws,
            &mut cycle,
            map_resolve(&map),
            PaneId(0),
            FocusReason::UserHandoff,
        )
        .expect("activate");
        assert!(moved.changed);
        assert_eq!(moved.pane, PaneId(0));
        assert_eq!(
            moved.request.as_ref().map(|r| r.owner),
            Some(FocusOwner::WebView2)
        );
        assert_eq!(cycle.current(), FocusCycleSlot::Surface(web));
    }

    #[test]
    fn activate_bound_emits_focus_request() {
        let mut ws = WorkspaceState::single_pane();
        ws.split().unwrap();
        assert_eq!(ws.focused(), PaneId(1));
        let mut cycle = FocusCycle::new();
        let web = handle(10, SurfaceKind::WebView2);
        let map = HashMap::from([(PaneId(0), web)]);
        cycle.set_surface_hwnd(web.id, Some(FocusHwnd(0xABC)));

        let notify = activate_pane(
            &mut ws,
            &mut cycle,
            map_resolve(&map),
            PaneId(0),
            FocusReason::UserHandoff,
        )
        .expect("activate");
        assert!(notify.changed);
        let req = notify.request.expect("bound surface notify");
        assert_eq!(req.owner, FocusOwner::WebView2);
        assert_eq!(req.hwnd, Some(FocusHwnd(0xABC)));
        assert_eq!(req.reason, FocusReason::UserHandoff);
        assert_eq!(cycle.current(), FocusCycleSlot::Surface(web));
    }

    #[test]
    fn activate_unbound_updates_workspace_only_when_already_chrome() {
        let mut ws = WorkspaceState::single_pane();
        ws.split().unwrap();
        let mut cycle = FocusCycle::new();
        let notify = activate_pane(
            &mut ws,
            &mut cycle,
            |_| None,
            PaneId(0),
            FocusReason::Explicit,
        )
        .expect("activate");
        assert!(notify.changed);
        assert_eq!(ws.focused(), PaneId(0));
        assert!(notify.request.is_none());
        assert_eq!(cycle.current(), FocusCycleSlot::GpuiChrome);
    }

    #[test]
    fn activate_bound_then_unbound_hands_cycle_to_chrome() {
        let mut ws = WorkspaceState::single_pane();
        ws.split().unwrap();
        let web = handle(1, SurfaceKind::WebView2);
        let map = HashMap::from([(PaneId(0), web)]);
        let mut cycle = FocusCycle::new();

        let bound = activate_pane(
            &mut ws,
            &mut cycle,
            map_resolve(&map),
            PaneId(0),
            FocusReason::Explicit,
        )
        .expect("bound");
        assert_eq!(cycle.current(), FocusCycleSlot::Surface(web));
        assert_eq!(
            bound.request.as_ref().map(|r| r.owner),
            Some(FocusOwner::WebView2)
        );

        // Pane 1 unbound — must not leave FocusCycle on web (WorkspaceState drift).
        let unbound = activate_pane(
            &mut ws,
            &mut cycle,
            map_resolve(&map),
            PaneId(1),
            FocusReason::UserHandoff,
        )
        .expect("unbound");
        assert!(unbound.changed);
        assert_eq!(ws.focused(), PaneId(1));
        assert_eq!(cycle.current(), FocusCycleSlot::GpuiChrome);
        let req = unbound.request.expect("chrome handoff");
        assert_eq!(req.owner, FocusOwner::GpuiChrome);
        assert_eq!(req.reason, FocusReason::UserHandoff);
    }

    #[test]
    fn idempotent_activate_repairs_rebind_under_focused_pane() {
        let mut ws = WorkspaceState::single_pane();
        let web = handle(1, SurfaceKind::WebView2);
        let rdp = handle(2, SurfaceKind::RdpActiveX);
        let mut map = HashMap::from([(PaneId(0), web)]);
        let mut cycle = FocusCycle::new();

        activate_pane(
            &mut ws,
            &mut cycle,
            map_resolve(&map),
            PaneId(0),
            FocusReason::Explicit,
        )
        .expect("initial");
        assert_eq!(cycle.current(), FocusCycleSlot::Surface(web));

        // Rebind under the already-focused pane without leaving focus.
        map.insert(PaneId(0), rdp);
        let repaired = activate_pane(
            &mut ws,
            &mut cycle,
            map_resolve(&map),
            PaneId(0),
            FocusReason::Explicit,
        )
        .expect("rebind repair");
        assert!(!repaired.changed);
        assert_eq!(ws.focused(), PaneId(0));
        assert_eq!(
            repaired.request.as_ref().map(|r| r.owner),
            Some(FocusOwner::RdpActiveX)
        );
        assert_eq!(cycle.current(), FocusCycleSlot::Surface(rdp));
    }

    #[test]
    fn idempotent_activate_repairs_late_bind_under_focused_pane() {
        let mut ws = WorkspaceState::single_pane();
        let mut cycle = FocusCycle::new();
        let web = handle(5, SurfaceKind::WebView2);

        let unbound = activate_pane(
            &mut ws,
            &mut cycle,
            |_| None,
            PaneId(0),
            FocusReason::Explicit,
        )
        .expect("unbound");
        assert!(!unbound.changed);
        assert!(unbound.request.is_none());
        assert_eq!(cycle.current(), FocusCycleSlot::GpuiChrome);

        let map = HashMap::from([(PaneId(0), web)]);
        let late = activate_pane(
            &mut ws,
            &mut cycle,
            map_resolve(&map),
            PaneId(0),
            FocusReason::UserHandoff,
        )
        .expect("late bind");
        assert!(!late.changed);
        assert_eq!(
            late.request.as_ref().map(|r| r.owner),
            Some(FocusOwner::WebView2)
        );
        assert_eq!(cycle.current(), FocusCycleSlot::Surface(web));
    }

    #[test]
    fn idempotent_activate_repairs_same_id_kind_change() {
        let mut ws = WorkspaceState::single_pane();
        let id = crate::SurfaceId(42);
        let as_web = SurfaceHandle {
            id,
            kind: SurfaceKind::WebView2,
        };
        let as_rdp = SurfaceHandle {
            id,
            kind: SurfaceKind::RdpActiveX,
        };
        let mut map = HashMap::from([(PaneId(0), as_web)]);
        let mut cycle = FocusCycle::new();

        activate_pane(
            &mut ws,
            &mut cycle,
            map_resolve(&map),
            PaneId(0),
            FocusReason::Explicit,
        )
        .expect("web");
        assert_eq!(
            cycle.current(),
            FocusCycleSlot::Surface(as_web)
        );

        map.insert(PaneId(0), as_rdp);
        let repaired = activate_pane(
            &mut ws,
            &mut cycle,
            map_resolve(&map),
            PaneId(0),
            FocusReason::Explicit,
        )
        .expect("kind refresh");
        assert!(!repaired.changed);
        assert_eq!(
            repaired.request.as_ref().map(|r| r.owner),
            Some(FocusOwner::RdpActiveX)
        );
        assert_eq!(cycle.current(), FocusCycleSlot::Surface(as_rdp));
    }

    #[test]
    fn cycle_among_unbound_panes_keeps_chrome_without_request() {
        let mut ws = WorkspaceState::single_pane();
        ws.split().unwrap();
        let mut cycle = FocusCycle::new();
        // Start on pane 1 (split focus); move to 0 then back — both unbound.
        let a = cycle_pane_focus(
            &mut ws,
            &mut cycle,
            |_| None,
            FocusCycleDirection::Next,
            FocusReason::UserHandoff,
        )
        .expect("to 0");
        assert_eq!(a.pane, PaneId(0));
        assert!(a.changed);
        assert!(a.request.is_none());
        assert_eq!(cycle.current(), FocusCycleSlot::GpuiChrome);

        let b = cycle_pane_focus(
            &mut ws,
            &mut cycle,
            |_| None,
            FocusCycleDirection::Next,
            FocusReason::UserHandoff,
        )
        .expect("to 1");
        assert_eq!(b.pane, PaneId(1));
        assert!(b.changed);
        assert!(b.request.is_none());
        assert_eq!(cycle.current(), FocusCycleSlot::GpuiChrome);
    }

    #[test]
    fn hwnd_map_update_while_current_does_not_reemit_via_activate() {
        // HWND is learned on FocusCycle after the pane is already synced. A later
        // activate sees the same FocusRequest before and after sync, so it stays
        // idempotent — callers that obtain an HWND later should call
        // FocusCycle::request_for_current + FocusBroker directly.
        let mut ws = WorkspaceState::single_pane();
        let web = handle(11, SurfaceKind::WebView2);
        let map = HashMap::from([(PaneId(0), web)]);
        let mut cycle = FocusCycle::new();

        let first = activate_pane(
            &mut ws,
            &mut cycle,
            map_resolve(&map),
            PaneId(0),
            FocusReason::Explicit,
        )
        .expect("no hwnd yet");
        assert_eq!(first.request.as_ref().and_then(|r| r.hwnd), None);

        cycle.set_surface_hwnd(web.id, Some(FocusHwnd(0xDEF)));
        let again = activate_pane(
            &mut ws,
            &mut cycle,
            map_resolve(&map),
            PaneId(0),
            FocusReason::Explicit,
        )
        .expect("still synced");
        assert!(!again.changed);
        assert!(again.request.is_none());
        assert_eq!(
            cycle.request_for_current(FocusReason::Explicit).hwnd,
            Some(FocusHwnd(0xDEF))
        );
    }

    #[test]
    fn cycle_next_prev_among_panes_with_bindings() {
        let mut ws = WorkspaceState::single_pane();
        ws.split().unwrap();
        ws.split().unwrap();
        // panes insertion: 0,1,2 — focused is 2 after last split
        assert_eq!(ws.panes(), &[PaneId(0), PaneId(1), PaneId(2)]);
        assert_eq!(ws.focused(), PaneId(2));

        let web = handle(1, SurfaceKind::WebView2);
        let rdp = handle(2, SurfaceKind::RdpActiveX);
        let map = HashMap::from([(PaneId(0), web), (PaneId(1), rdp)]);
        let mut cycle = FocusCycle::new();

        // 2 → 0 (Next wrap)
        let a = cycle_pane_focus(
            &mut ws,
            &mut cycle,
            map_resolve(&map),
            FocusCycleDirection::Next,
            FocusReason::UserHandoff,
        )
        .expect("cycle");
        assert_eq!(a.pane, PaneId(0));
        assert!(a.changed);
        assert_eq!(a.request.unwrap().owner, FocusOwner::WebView2);

        // 0 → 1
        let b = cycle_pane_focus(
            &mut ws,
            &mut cycle,
            map_resolve(&map),
            FocusCycleDirection::Next,
            FocusReason::UserHandoff,
        )
        .expect("cycle");
        assert_eq!(b.pane, PaneId(1));
        assert_eq!(b.request.unwrap().owner, FocusOwner::RdpActiveX);

        // 1 → 0 (Prev)
        let c = cycle_pane_focus(
            &mut ws,
            &mut cycle,
            map_resolve(&map),
            FocusCycleDirection::Prev,
            FocusReason::UserHandoff,
        )
        .expect("cycle");
        assert_eq!(c.pane, PaneId(0));
        assert_eq!(cycle.current(), FocusCycleSlot::Surface(web));
    }

    #[test]
    fn cycle_prev_wraps_from_first_to_last() {
        let mut ws = WorkspaceState::single_pane();
        ws.split().unwrap();
        ws.split().unwrap();
        // Focus first pane explicitly.
        ws.focus(PaneId(0)).unwrap();
        let web = handle(1, SurfaceKind::WebView2);
        let rdp = handle(2, SurfaceKind::RdpActiveX);
        let map = HashMap::from([(PaneId(0), web), (PaneId(2), rdp)]);
        let mut cycle = FocusCycle::new();

        let notify = cycle_pane_focus(
            &mut ws,
            &mut cycle,
            map_resolve(&map),
            FocusCycleDirection::Prev,
            FocusReason::UserHandoff,
        )
        .expect("prev wrap");
        assert_eq!(notify.pane, PaneId(2));
        assert!(notify.changed);
        assert_eq!(
            notify.request.as_ref().map(|r| r.owner),
            Some(FocusOwner::RdpActiveX)
        );
        assert_eq!(cycle.current(), FocusCycleSlot::Surface(rdp));
    }

    #[test]
    fn cycle_single_pane_syncs_then_idempotent() {
        let mut ws = WorkspaceState::single_pane();
        let mut cycle = FocusCycle::new();
        let web = handle(3, SurfaceKind::WebView2);
        let map = HashMap::from([(PaneId(0), web)]);

        let first = cycle_pane_focus(
            &mut ws,
            &mut cycle,
            map_resolve(&map),
            FocusCycleDirection::Next,
            FocusReason::Explicit,
        )
        .expect("cycle");
        assert!(!first.changed);
        assert_eq!(ws.focused(), PaneId(0));
        assert_eq!(
            first.request.as_ref().map(|r| r.owner),
            Some(FocusOwner::WebView2)
        );
        assert_eq!(cycle.current(), FocusCycleSlot::Surface(web));

        let second = cycle_pane_focus(
            &mut ws,
            &mut cycle,
            map_resolve(&map),
            FocusCycleDirection::Prev,
            FocusReason::Explicit,
        )
        .expect("cycle again");
        assert!(!second.changed);
        assert!(second.request.is_none());
        assert_eq!(cycle.current(), FocusCycleSlot::Surface(web));
    }

    #[test]
    fn double_activate_same_bound_pane_second_is_noop() {
        let mut ws = WorkspaceState::single_pane();
        ws.split().unwrap();
        let web = handle(7, SurfaceKind::WebView2);
        let map = HashMap::from([(PaneId(0), web)]);
        let mut cycle = FocusCycle::new();

        let a = activate_pane(
            &mut ws,
            &mut cycle,
            map_resolve(&map),
            PaneId(0),
            FocusReason::Explicit,
        )
        .expect("first");
        let b = activate_pane(
            &mut ws,
            &mut cycle,
            map_resolve(&map),
            PaneId(0),
            FocusReason::Explicit,
        )
        .expect("second");
        assert!(a.changed);
        assert_eq!(
            a.request.as_ref().map(|r| r.owner),
            Some(FocusOwner::WebView2)
        );
        assert!(!b.changed);
        assert!(b.request.is_none());
        assert_eq!(cycle.current(), FocusCycleSlot::Surface(web));
    }

    #[cfg(windows)]
    #[test]
    fn activate_via_broker_pane_layout_sink_binding() {
        use crate::{OwnerHwnd, StubNativeSurfaceBroker};

        let mut broker = StubNativeSurfaceBroker::new();
        let web = broker
            .register(OwnerHwnd(0x10), SurfaceKind::WebView2)
            .expect("register");
        let mut sink = BrokerPaneLayoutSink::new(broker);
        sink.bind(PaneId(0), web);

        let mut ws = WorkspaceState::single_pane();
        ws.split().unwrap();
        let mut cycle = FocusCycle::new();

        let notify = activate_pane_bound(
            &mut ws,
            &mut cycle,
            &sink,
            PaneId(0),
            FocusReason::Explicit,
        )
        .expect("bound activate");
        assert!(notify.changed);
        assert_eq!(notify.request.unwrap().owner, FocusOwner::WebView2);
        assert_eq!(cycle.current(), FocusCycleSlot::Surface(web));

        let cycled = cycle_pane_focus_bound(
            &mut ws,
            &mut cycle,
            &sink,
            FocusCycleDirection::Next,
            FocusReason::UserHandoff,
        )
        .expect("cycle");
        assert_eq!(cycled.pane, PaneId(1));
        // Pane 1 unbound → workspace moves; cycle → chrome (leaving web).
        assert!(cycled.changed);
        assert_eq!(cycle.current(), FocusCycleSlot::GpuiChrome);
        assert_eq!(
            cycled.request.as_ref().map(|r| r.owner),
            Some(FocusOwner::GpuiChrome)
        );
    }
}
