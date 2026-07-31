//! Tab / Shift-Tab style focus cycle among GPUI chrome + registered surfaces.
//!
//! Stub for shell handoff: [`FocusCycle`] tracks an ordered ring
//! (`GpuiChrome` sentinel + [`SurfaceHandle`]s) and builds [`FocusRequest`]s
//! for [`super::FocusBroker`]. No Win32 calls here — HWND resolution is
//! optional bookkeeping so unit tests can run with [`RecordingFocusOps`].

use std::collections::{HashMap, HashSet};

use crate::broker::{NativeSurfaceBroker, SurfaceHandle, SurfaceId};
use crate::kinds::SurfaceKind;

use super::broker::{FocusOwner, FocusReason, FocusRequest};
use super::ops::FocusHwnd;

/// Direction for [`FocusCycle::advance`] / [`FocusCycle::peek`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FocusCycleDirection {
    /// Forward (Tab / next surface).
    Next,
    /// Backward (Shift-Tab / previous surface).
    Prev,
}

/// One stop in the focus ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FocusCycleSlot {
    /// Always-present GPUI chrome sentinel (tree / tabs / menus / dialogs).
    GpuiChrome,
    /// Registered native surface from the broker.
    Surface(SurfaceHandle),
}

impl FocusCycleSlot {
    /// Map to the logical [`FocusOwner`] used by [`FocusRequest`].
    pub fn to_owner(self) -> FocusOwner {
        match self {
            Self::GpuiChrome => FocusOwner::GpuiChrome,
            Self::Surface(h) => match h.kind {
                SurfaceKind::WebView2 => FocusOwner::WebView2,
                SurfaceKind::RdpActiveX => FocusOwner::RdpActiveX,
            },
        }
    }
}

/// Errors from cycle membership / current-slot updates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FocusCycleError {
    /// [`FocusCycle::set_current`] named a surface that is not in the ring.
    UnknownSurface(SurfaceId),
}

impl std::fmt::Display for FocusCycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownSurface(id) => {
                write!(f, "surface {id} is not in the focus cycle")
            }
        }
    }
}

impl std::error::Error for FocusCycleError {}

/// Ordered focus ring: GPUI chrome sentinel + registered [`SurfaceHandle`]s.
///
/// Independent of pane-layout sink — callers sync membership from a broker
/// snapshot or insert/remove handles directly.
#[derive(Debug)]
pub struct FocusCycle {
    /// Surfaces in registration / sync order (chrome is implicit first).
    surfaces: Vec<SurfaceHandle>,
    /// Optional focus HWND per surface (AxHost child / WebView2 child).
    surface_hwnds: HashMap<SurfaceId, FocusHwnd>,
    /// Optional main-window HWND for the chrome sentinel.
    chrome_hwnd: Option<FocusHwnd>,
    /// Current ring position.
    current: FocusCycleSlot,
}

impl Default for FocusCycle {
    fn default() -> Self {
        Self::new()
    }
}

impl FocusCycle {
    /// Empty ring with only the GPUI chrome sentinel (current).
    pub fn new() -> Self {
        Self {
            surfaces: Vec::new(),
            surface_hwnds: HashMap::new(),
            chrome_hwnd: None,
            current: FocusCycleSlot::GpuiChrome,
        }
    }

    /// Full ring: chrome first, then surfaces in order.
    pub fn slots(&self) -> Vec<FocusCycleSlot> {
        let mut out = Vec::with_capacity(1 + self.surfaces.len());
        out.push(FocusCycleSlot::GpuiChrome);
        out.extend(self.surfaces.iter().copied().map(FocusCycleSlot::Surface));
        out
    }

    /// Current ring position.
    pub fn current(&self) -> FocusCycleSlot {
        self.current
    }

    /// Surfaces currently in the ring (excludes chrome sentinel).
    pub fn surfaces(&self) -> &[SurfaceHandle] {
        &self.surfaces
    }

    /// Move current to `slot`. Surfaces must already be registered.
    ///
    /// Surface slots are canonicalized to the ring's [`SurfaceHandle`] (kind
    /// from membership, not a caller-supplied stale payload).
    pub fn set_current(&mut self, slot: FocusCycleSlot) -> Result<(), FocusCycleError> {
        match slot {
            FocusCycleSlot::GpuiChrome => {
                self.current = FocusCycleSlot::GpuiChrome;
                Ok(())
            }
            FocusCycleSlot::Surface(handle) => {
                if let Some(fresh) = self.surfaces.iter().find(|h| h.id == handle.id).copied() {
                    self.current = FocusCycleSlot::Surface(fresh);
                    Ok(())
                } else {
                    Err(FocusCycleError::UnknownSurface(handle.id))
                }
            }
        }
    }

    /// Append a surface if not already present (idempotent by [`SurfaceId`]).
    ///
    /// Re-inserting the same id refreshes the stored handle (kind) and, when
    /// that surface is current, refreshes [`Self::current`] so
    /// [`Self::request_for_current`] cannot emit a stale [`FocusOwner`].
    pub fn insert_surface(&mut self, handle: SurfaceHandle) {
        if let Some(existing) = self.surfaces.iter_mut().find(|h| h.id == handle.id) {
            *existing = handle;
            self.refresh_current_surface_payload();
            return;
        }
        self.surfaces.push(handle);
    }

    /// Drop a surface; if it was current, fall back to chrome.
    pub fn remove_surface(&mut self, id: SurfaceId) {
        self.surfaces.retain(|h| h.id != id);
        self.surface_hwnds.remove(&id);
        if matches!(self.current, FocusCycleSlot::Surface(h) if h.id == id) {
            self.current = FocusCycleSlot::GpuiChrome;
        }
    }

    /// Replace surface membership from a snapshot.
    ///
    /// Preserves relative order of surviving ids; appends newly seen handles
    /// sorted by [`SurfaceId`] for stable tests (broker `list` may be unordered).
    /// Dropped current surfaces fall back to the chrome sentinel; surviving
    /// current handles are refreshed from the snapshot payload.
    pub fn sync_surfaces(&mut self, handles: impl IntoIterator<Item = SurfaceHandle>) {
        // Last handle wins for duplicate ids in the snapshot.
        let mut by_id: HashMap<SurfaceId, SurfaceHandle> =
            handles.into_iter().map(|h| (h.id, h)).collect();
        let incoming_ids: HashSet<SurfaceId> = by_id.keys().copied().collect();

        // Keep prior order for survivors; refresh handle payloads from incoming.
        let mut next = Vec::with_capacity(by_id.len());
        for old in &self.surfaces {
            if let Some(h) = by_id.remove(&old.id) {
                next.push(h);
            }
        }
        let mut appended: Vec<SurfaceHandle> = by_id.into_values().collect();
        appended.sort_by_key(|h| h.id.0);
        next.extend(appended);

        self.surfaces = next;
        self.surface_hwnds
            .retain(|id, _| incoming_ids.contains(id));
        self.refresh_current_surface_payload();
    }

    /// Sync surface membership from a [`NativeSurfaceBroker`] snapshot.
    ///
    /// The broker list is sorted by id before sync so a first populate from an
    /// empty ring is deterministic (stub `HashMap` iteration is unordered).
    /// On later syncs, surviving surfaces keep their prior ring order; only
    /// newly seen ids are appended in id order (see [`Self::sync_surfaces`]).
    pub fn sync_from_broker(&mut self, broker: &impl NativeSurfaceBroker) {
        let mut list = broker.list();
        list.sort_by_key(|h| h.id.0);
        self.sync_surfaces(list);
    }

    /// Optional HWND for the chrome sentinel (main window).
    ///
    /// `Some` null HWND is treated as clear — cycle never stores a null target
    /// (broker would still reject; this keeps requests clean upstream).
    pub fn set_chrome_hwnd(&mut self, hwnd: Option<FocusHwnd>) {
        self.chrome_hwnd = hwnd.filter(|h| !h.is_null());
    }

    /// Optional HWND for a registered surface (AxHost child / WebView2 child).
    ///
    /// `Some` null HWND clears any stored handle for `id` (same as `None`).
    pub fn set_surface_hwnd(&mut self, id: SurfaceId, hwnd: Option<FocusHwnd>) {
        match hwnd.filter(|h| !h.is_null()) {
            Some(h) => {
                self.surface_hwnds.insert(id, h);
            }
            None => {
                self.surface_hwnds.remove(&id);
            }
        }
    }

    /// Keep [`Self::current`]'s surface payload aligned with `surfaces`, or
    /// fall back to chrome when the id left the ring.
    fn refresh_current_surface_payload(&mut self) {
        if let FocusCycleSlot::Surface(h) = self.current {
            if let Some(fresh) = self.surfaces.iter().find(|s| s.id == h.id).copied() {
                self.current = FocusCycleSlot::Surface(fresh);
            } else {
                self.current = FocusCycleSlot::GpuiChrome;
            }
        }
    }

    /// Peek the next/prev slot without mutating current.
    pub fn peek(&self, dir: FocusCycleDirection) -> FocusCycleSlot {
        let slots = self.slots();
        let len = slots.len();
        debug_assert!(len >= 1, "chrome sentinel always present");
        let idx = slots
            .iter()
            .position(|s| slot_eq(*s, self.current))
            .unwrap_or(0);
        let next_idx = match dir {
            FocusCycleDirection::Next => (idx + 1) % len,
            FocusCycleDirection::Prev => (idx + len - 1) % len,
        };
        slots[next_idx]
    }

    /// Advance current and build a [`FocusRequest`] for the new slot.
    pub fn advance(&mut self, dir: FocusCycleDirection, reason: FocusReason) -> FocusRequest {
        let next = self.peek(dir);
        self.current = next;
        self.request_for_current(reason)
    }

    /// Build a [`FocusRequest`] for the current slot (no advance).
    pub fn request_for_current(&self, reason: FocusReason) -> FocusRequest {
        let hwnd = match self.current {
            FocusCycleSlot::GpuiChrome => self.chrome_hwnd,
            FocusCycleSlot::Surface(h) => self.surface_hwnds.get(&h.id).copied(),
        };
        FocusRequest {
            owner: self.current.to_owner(),
            hwnd,
            reason,
        }
    }
}

fn slot_eq(a: FocusCycleSlot, b: FocusCycleSlot) -> bool {
    match (a, b) {
        (FocusCycleSlot::GpuiChrome, FocusCycleSlot::GpuiChrome) => true,
        (FocusCycleSlot::Surface(x), FocusCycleSlot::Surface(y)) => x.id == y.id,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::focus::{FocusAction, FocusBroker, FocusOwner, RecordingFocusOps};
    use crate::kinds::SurfaceKind;
    use crate::{NativeSurfaceBroker, OwnerHwnd, StubNativeSurfaceBroker};

    fn handle(id: u64, kind: SurfaceKind) -> SurfaceHandle {
        SurfaceHandle {
            id: SurfaceId(id),
            kind,
        }
    }

    #[test]
    fn chrome_only_next_prev_stays_on_sentinel() {
        let mut cycle = FocusCycle::new();
        assert_eq!(cycle.slots(), vec![FocusCycleSlot::GpuiChrome]);
        let req = cycle.advance(FocusCycleDirection::Next, FocusReason::UserHandoff);
        assert_eq!(req.owner, FocusOwner::GpuiChrome);
        assert_eq!(cycle.current(), FocusCycleSlot::GpuiChrome);
        let prev = cycle.advance(FocusCycleDirection::Prev, FocusReason::UserHandoff);
        assert_eq!(prev.owner, FocusOwner::GpuiChrome);
    }

    #[test]
    fn next_prev_among_chrome_and_surfaces() {
        let mut cycle = FocusCycle::new();
        let web = handle(1, SurfaceKind::WebView2);
        let rdp = handle(2, SurfaceKind::RdpActiveX);
        cycle.insert_surface(web);
        cycle.insert_surface(rdp);
        cycle.set_surface_hwnd(web.id, Some(FocusHwnd(0x100)));
        cycle.set_surface_hwnd(rdp.id, Some(FocusHwnd(0x200)));

        assert_eq!(
            cycle.slots(),
            vec![
                FocusCycleSlot::GpuiChrome,
                FocusCycleSlot::Surface(web),
                FocusCycleSlot::Surface(rdp),
            ]
        );

        // chrome → web → rdp → chrome
        let a = cycle.advance(FocusCycleDirection::Next, FocusReason::UserHandoff);
        assert_eq!(a.owner, FocusOwner::WebView2);
        assert_eq!(a.hwnd, Some(FocusHwnd(0x100)));
        let b = cycle.advance(FocusCycleDirection::Next, FocusReason::UserHandoff);
        assert_eq!(b.owner, FocusOwner::RdpActiveX);
        assert_eq!(b.hwnd, Some(FocusHwnd(0x200)));
        let c = cycle.advance(FocusCycleDirection::Next, FocusReason::UserHandoff);
        assert_eq!(c.owner, FocusOwner::GpuiChrome);
        assert!(c.hwnd.is_none());

        // chrome ← rdp (Prev)
        let d = cycle.advance(FocusCycleDirection::Prev, FocusReason::UserHandoff);
        assert_eq!(d.owner, FocusOwner::RdpActiveX);
        assert_eq!(cycle.current(), FocusCycleSlot::Surface(rdp));
    }

    #[test]
    fn remove_current_falls_back_to_chrome() {
        let mut cycle = FocusCycle::new();
        let web = handle(3, SurfaceKind::WebView2);
        cycle.insert_surface(web);
        cycle
            .set_current(FocusCycleSlot::Surface(web))
            .expect("in ring");
        cycle.remove_surface(web.id);
        assert_eq!(cycle.current(), FocusCycleSlot::GpuiChrome);
        assert!(cycle.surfaces().is_empty());
    }

    #[test]
    fn sync_preserves_order_and_appends_new_sorted() {
        let mut cycle = FocusCycle::new();
        let a = handle(10, SurfaceKind::WebView2);
        let b = handle(20, SurfaceKind::RdpActiveX);
        cycle.insert_surface(a);
        cycle.insert_surface(b);

        // Snapshot drops `a`, keeps `b`, adds `c` then `d` out of id order.
        let c = handle(5, SurfaceKind::WebView2);
        let d = handle(15, SurfaceKind::RdpActiveX);
        cycle.sync_surfaces([b, d, c]);
        assert_eq!(
            cycle.surfaces(),
            &[b, c, d],
            "b preserved first; c then d appended sorted by id"
        );
    }

    #[test]
    fn apply_cycle_through_recording_broker() {
        let mut cycle = FocusCycle::new();
        let web = handle(1, SurfaceKind::WebView2);
        cycle.insert_surface(web);
        cycle.set_surface_hwnd(web.id, Some(FocusHwnd(0xABC)));

        let mut broker = FocusBroker::new(RecordingFocusOps::new());
        let action = broker.request_focus(cycle.advance(
            FocusCycleDirection::Next,
            FocusReason::UserHandoff,
        ));
        assert!(matches!(
            action,
            FocusAction::Applied {
                owner: FocusOwner::WebView2,
                hwnd: Some(FocusHwnd(0xABC)),
                ..
            }
        ));
        assert_eq!(broker.ops().set_calls, vec![FocusHwnd(0xABC)]);

        let back = broker.request_focus(cycle.advance(
            FocusCycleDirection::Next,
            FocusReason::UserHandoff,
        ));
        assert!(matches!(
            back,
            FocusAction::Applied {
                owner: FocusOwner::GpuiChrome,
                hwnd: None,
                ..
            }
        ));
        // Chrome without HWND does not call SetFocus.
        assert_eq!(broker.ops().set_calls.len(), 1);
    }

    #[test]
    fn set_current_unknown_surface_errors() {
        let mut cycle = FocusCycle::new();
        let ghost = handle(99, SurfaceKind::WebView2);
        assert_eq!(
            cycle.set_current(FocusCycleSlot::Surface(ghost)),
            Err(FocusCycleError::UnknownSurface(SurfaceId(99)))
        );
    }

    #[test]
    fn insert_surface_duplicate_id_refreshes_kind_on_current() {
        let mut cycle = FocusCycle::new();
        let web = handle(7, SurfaceKind::WebView2);
        cycle.insert_surface(web);
        cycle
            .set_current(FocusCycleSlot::Surface(web))
            .expect("in ring");
        // Same id, different kind (re-register) must update current payload.
        let as_rdp = handle(7, SurfaceKind::RdpActiveX);
        cycle.insert_surface(as_rdp);
        assert_eq!(cycle.surfaces(), &[as_rdp]);
        assert_eq!(cycle.current(), FocusCycleSlot::Surface(as_rdp));
        let req = cycle.request_for_current(FocusReason::Explicit);
        assert_eq!(req.owner, FocusOwner::RdpActiveX);
    }

    #[test]
    fn set_current_canonicalizes_kind_from_ring() {
        let mut cycle = FocusCycle::new();
        let web = handle(8, SurfaceKind::WebView2);
        cycle.insert_surface(web);
        let stale = handle(8, SurfaceKind::RdpActiveX);
        cycle
            .set_current(FocusCycleSlot::Surface(stale))
            .expect("id in ring");
        assert_eq!(cycle.current(), FocusCycleSlot::Surface(web));
        assert_eq!(
            cycle.request_for_current(FocusReason::Explicit).owner,
            FocusOwner::WebView2
        );
    }

    #[test]
    fn null_hwnd_not_stored_in_cycle() {
        let mut cycle = FocusCycle::new();
        let web = handle(9, SurfaceKind::WebView2);
        cycle.insert_surface(web);
        cycle.set_chrome_hwnd(Some(FocusHwnd(0)));
        cycle.set_surface_hwnd(web.id, Some(FocusHwnd(0)));
        assert!(cycle.request_for_current(FocusReason::Explicit).hwnd.is_none());
        cycle
            .set_current(FocusCycleSlot::Surface(web))
            .expect("in ring");
        assert!(cycle.request_for_current(FocusReason::Explicit).hwnd.is_none());
        // Non-null then clear via null Some.
        cycle.set_surface_hwnd(web.id, Some(FocusHwnd(0x50)));
        assert_eq!(
            cycle.request_for_current(FocusReason::Explicit).hwnd,
            Some(FocusHwnd(0x50))
        );
        cycle.set_surface_hwnd(web.id, Some(FocusHwnd(0)));
        assert!(cycle.request_for_current(FocusReason::Explicit).hwnd.is_none());
    }

    #[test]
    fn duplicate_insert_keeps_single_slot() {
        let mut cycle = FocusCycle::new();
        let web = handle(11, SurfaceKind::WebView2);
        cycle.insert_surface(web);
        cycle.insert_surface(web);
        assert_eq!(cycle.surfaces(), &[web]);
        assert_eq!(
            cycle.slots(),
            vec![FocusCycleSlot::GpuiChrome, FocusCycleSlot::Surface(web)]
        );
    }

    #[test]
    fn sync_surfaces_drops_current_to_chrome() {
        let mut cycle = FocusCycle::new();
        let web = handle(12, SurfaceKind::WebView2);
        let rdp = handle(13, SurfaceKind::RdpActiveX);
        cycle.insert_surface(web);
        cycle.insert_surface(rdp);
        cycle.set_surface_hwnd(web.id, Some(FocusHwnd(0x12)));
        cycle
            .set_current(FocusCycleSlot::Surface(web))
            .expect("in ring");
        cycle.sync_surfaces([rdp]);
        assert_eq!(cycle.surfaces(), &[rdp]);
        assert_eq!(cycle.current(), FocusCycleSlot::GpuiChrome);
        // HWND for dropped surface must not linger.
        cycle
            .set_current(FocusCycleSlot::Surface(rdp))
            .expect("in ring");
        // No hwnd was set for rdp; dropped web hwnd gone from map (no panic / leak into rdp).
        assert!(cycle.request_for_current(FocusReason::Explicit).hwnd.is_none());
    }

    #[test]
    fn peek_does_not_mutate_current() {
        let mut cycle = FocusCycle::new();
        let web = handle(14, SurfaceKind::WebView2);
        cycle.insert_surface(web);
        assert_eq!(cycle.current(), FocusCycleSlot::GpuiChrome);
        assert_eq!(
            cycle.peek(FocusCycleDirection::Next),
            FocusCycleSlot::Surface(web)
        );
        assert_eq!(cycle.current(), FocusCycleSlot::GpuiChrome);
        assert_eq!(
            cycle.peek(FocusCycleDirection::Prev),
            FocusCycleSlot::Surface(web)
        );
        assert_eq!(cycle.current(), FocusCycleSlot::GpuiChrome);
    }

    #[test]
    fn remove_non_current_preserves_current() {
        let mut cycle = FocusCycle::new();
        let web = handle(15, SurfaceKind::WebView2);
        let rdp = handle(16, SurfaceKind::RdpActiveX);
        cycle.insert_surface(web);
        cycle.insert_surface(rdp);
        cycle
            .set_current(FocusCycleSlot::Surface(rdp))
            .expect("in ring");
        cycle.remove_surface(web.id);
        assert_eq!(cycle.current(), FocusCycleSlot::Surface(rdp));
        assert_eq!(cycle.surfaces(), &[rdp]);
    }

    #[test]
    fn cycle_never_calls_ops_without_broker() {
        // FocusCycle only builds FocusRequest; SetFocus policy stays in FocusBroker.
        let mut cycle = FocusCycle::new();
        let web = handle(17, SurfaceKind::WebView2);
        cycle.insert_surface(web);
        cycle.set_surface_hwnd(web.id, Some(FocusHwnd(0x17)));
        let req = cycle.advance(FocusCycleDirection::Next, FocusReason::UserHandoff);
        assert_eq!(req.owner, FocusOwner::WebView2);
        assert_eq!(req.hwnd, Some(FocusHwnd(0x17)));
        // Applying requires an explicit broker call (regression: no hidden bypass API).
        let mut broker = FocusBroker::new(RecordingFocusOps::new());
        assert!(broker.ops().set_calls.is_empty());
        let _ = broker.request_focus(req);
        assert_eq!(broker.ops().set_calls, vec![FocusHwnd(0x17)]);
    }

    #[test]
    fn sync_surfaces_refreshes_kind_on_current() {
        let mut cycle = FocusCycle::new();
        let web = handle(18, SurfaceKind::WebView2);
        cycle.insert_surface(web);
        cycle
            .set_current(FocusCycleSlot::Surface(web))
            .expect("in ring");
        let as_rdp = handle(18, SurfaceKind::RdpActiveX);
        cycle.sync_surfaces([as_rdp]);
        assert_eq!(cycle.current(), FocusCycleSlot::Surface(as_rdp));
        assert_eq!(
            cycle.request_for_current(FocusReason::Explicit).owner,
            FocusOwner::RdpActiveX
        );
    }

    #[test]
    fn sync_surfaces_empty_clears_to_chrome_only() {
        let mut cycle = FocusCycle::new();
        let web = handle(19, SurfaceKind::WebView2);
        cycle.insert_surface(web);
        cycle.set_surface_hwnd(web.id, Some(FocusHwnd(0x19)));
        cycle
            .set_current(FocusCycleSlot::Surface(web))
            .expect("in ring");
        cycle.sync_surfaces([]);
        assert!(cycle.surfaces().is_empty());
        assert_eq!(cycle.current(), FocusCycleSlot::GpuiChrome);
        assert!(cycle.request_for_current(FocusReason::Explicit).hwnd.is_none());
        // Chrome-only wrap still defined.
        let req = cycle.advance(FocusCycleDirection::Prev, FocusReason::UserHandoff);
        assert_eq!(req.owner, FocusOwner::GpuiChrome);
    }

    /// Stub broker path — registration is Windows-gated on the stub; cycle
    /// logic itself is platform-agnostic (`sync_surfaces_*` tests above).
    #[cfg(windows)]
    #[test]
    fn sync_from_stub_broker_no_real_hwnd() {
        let mut broker = StubNativeSurfaceBroker::new();
        let web = broker
            .register(OwnerHwnd(0x10), SurfaceKind::WebView2)
            .expect("stub register");
        let rdp = broker
            .register(OwnerHwnd(0x20), SurfaceKind::RdpActiveX)
            .expect("stub register");

        let mut cycle = FocusCycle::new();
        cycle.sync_from_broker(&broker);
        // Stub stores no focus HWND — requests carry owner only.
        assert_eq!(
            cycle.surfaces().iter().map(|h| h.id).collect::<Vec<_>>(),
            vec![web.id, rdp.id]
        );

        let req = cycle.advance(FocusCycleDirection::Next, FocusReason::Explicit);
        assert_eq!(req.owner, FocusOwner::WebView2);
        assert!(req.hwnd.is_none());
        assert_eq!(cycle.current(), FocusCycleSlot::Surface(web));

        let req2 = cycle.advance(FocusCycleDirection::Next, FocusReason::Explicit);
        assert_eq!(req2.owner, FocusOwner::RdpActiveX);

        // Drop the surface that is *not* current — ring shrinks; current stays RDP.
        broker.unregister(web.id).expect("unregister");
        cycle.sync_from_broker(&broker);
        assert_eq!(cycle.surfaces(), &[rdp]);
        assert_eq!(cycle.current(), FocusCycleSlot::Surface(rdp));

        // Drop current surface via sync → fall back to chrome sentinel.
        broker.unregister(rdp.id).expect("unregister");
        cycle.sync_from_broker(&broker);
        assert!(cycle.surfaces().is_empty());
        assert_eq!(cycle.current(), FocusCycleSlot::GpuiChrome);
    }
}
