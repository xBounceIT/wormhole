//! [`wormhole_ui::PaneLayoutSink`] → [`NativeSurfaceBroker`] adapter.
//!
//! Enabled with `--features pane-layout`. Maps workspace [`PaneId`]s to registered
//! [`SurfaceHandle`]s (WebView2 / RdpActiveX) and forwards each layout tick as
//! [`PhysicalBounds`] via [`NativeSurfaceBroker::update_bounds`].
//!
//! # Safe bind / unbind timing
//!
//! Layout ticks take `&mut self`, so bind/unbind cannot interleave *inside* a
//! tick on the same sink. Between ticks:
//! - **bind after a tick**: soft no-op until the next `on_pane_layout` (no panic).
//! - **unbind**: hides the previously bound surface (using last known bounds, or
//!   [`PhysicalBounds::SEED`] if never laid out), then drops the mapping.
//! - **rebind** (same `PaneId`, different handle): hides the previous surface
//!   before installing the new mapping and clears that pane's last-push cache.

use std::collections::{HashMap, HashSet};

use wormhole_ui::{PaneId, PaneLayoutSink, PaneLayoutUpdate, PanePhysicalBounds};

use crate::bounds::{PhysicalBounds, SurfaceVisibility, ZOrderHint};
use crate::broker::{
    NativeSurfaceBroker, OwnerHwnd, SurfaceHandle, SurfaceId, SurfaceLayoutUpdate,
};
use crate::kinds::SurfaceKind;
use crate::{Result, SurfaceError};

/// Convert UI pane bounds into broker physical bounds (field-compatible layouts).
#[inline]
pub fn pane_bounds_to_physical(bounds: PanePhysicalBounds) -> PhysicalBounds {
    PhysicalBounds {
        x: bounds.x,
        y: bounds.y,
        width: bounds.width,
        height: bounds.height,
        dpi: bounds.dpi,
    }
}

/// Visibility derived from pane bounds: degenerate slots are hidden.
#[inline]
pub fn visibility_for_pane_bounds(bounds: PanePhysicalBounds) -> SurfaceVisibility {
    if bounds.is_degenerate() {
        SurfaceVisibility::Hidden
    } else {
        SurfaceVisibility::Visible
    }
}

/// [`PaneLayoutSink`] that pushes layout ticks into a [`NativeSurfaceBroker`].
///
/// Bind each live pane to a previously registered [`SurfaceHandle`] (or use
/// [`Self::register_and_bind`]). Unbound panes in a tick are ignored. Bound
/// panes omitted from a tick (closed slots) are hidden so leftover surfaces do
/// not keep the previous on-screen rect.
#[derive(Debug)]
pub struct BrokerPaneLayoutSink<B: NativeSurfaceBroker> {
    broker: B,
    bindings: HashMap<PaneId, SurfaceHandle>,
    /// Last layout payload successfully pushed per pane (hide reuse + identical-tick skip).
    last_pushed: HashMap<PaneId, SurfaceLayoutUpdate>,
    /// Errors from the most recent [`PaneLayoutSink::on_pane_layout`] call,
    /// or from the most recent hide issued by [`Self::bind`] / [`Self::unbind`].
    last_errors: Vec<(PaneId, SurfaceError)>,
}

impl<B: NativeSurfaceBroker> BrokerPaneLayoutSink<B> {
    /// Wrap an owned broker (typically [`crate::StubNativeSurfaceBroker`] in tests).
    pub fn new(broker: B) -> Self {
        Self {
            broker,
            bindings: HashMap::new(),
            last_pushed: HashMap::new(),
            last_errors: Vec::new(),
        }
    }

    /// Borrow the inner broker.
    pub fn broker(&self) -> &B {
        &self.broker
    }

    /// Mutably borrow the inner broker (e.g. lab diagnostics).
    pub fn broker_mut(&mut self) -> &mut B {
        &mut self.broker
    }

    /// Consume the sink and return the broker.
    pub fn into_broker(self) -> B {
        self.broker
    }

    /// Bind `pane` to an already-registered surface handle.
    ///
    /// Replaces any previous binding for that pane. If the previous handle differs,
    /// it is hidden first so the old HWND does not remain visible, and the pane's
    /// last-push cache is cleared so the new handle is not identical-skipped.
    /// Does not call `register`. Clears [`Self::last_errors`] then records any hide
    /// failures.
    pub fn bind(&mut self, pane: PaneId, handle: SurfaceHandle) {
        self.last_errors.clear();
        match self.bindings.insert(pane, handle) {
            Some(prev) if prev.id != handle.id => {
                // Hide the old HWND, then drop pane push cache so the new handle
                // is not identical-skipped against the previous surface's payload.
                self.hide_surface(pane, prev);
                self.last_pushed.remove(&pane);
            }
            None => {
                self.last_pushed.remove(&pane);
            }
            Some(_) => {}
        }
    }

    /// Remove a pane → surface mapping without unregistering the surface.
    ///
    /// Hides the surface (last known bounds, or [`PhysicalBounds::SEED`] if never
    /// laid out) so unbind between ticks cannot leave a stale visible overlay.
    /// When a binding existed, clears [`Self::last_errors`] then records any hide
    /// failure. A missing pane is a soft no-op that leaves `last_errors` intact.
    pub fn unbind(&mut self, pane: PaneId) -> Option<SurfaceHandle> {
        let handle = self.bindings.remove(&pane)?;
        self.last_errors.clear();
        self.hide_surface(pane, handle);
        self.last_pushed.remove(&pane);
        Some(handle)
    }

    /// Register `kind` under `owner`, then bind the returned handle to `pane`.
    pub fn register_and_bind(
        &mut self,
        pane: PaneId,
        owner: OwnerHwnd,
        kind: SurfaceKind,
    ) -> Result<SurfaceHandle> {
        match kind {
            SurfaceKind::WebView2 | SurfaceKind::RdpActiveX => {}
        }
        let handle = self.broker.register(owner, kind)?;
        self.bind(pane, handle);
        Ok(handle)
    }

    /// Current binding for `pane`, if any.
    pub fn binding(&self, pane: PaneId) -> Option<SurfaceHandle> {
        self.bindings.get(&pane).copied()
    }

    /// Snapshot of all pane → surface bindings.
    pub fn bindings(&self) -> &HashMap<PaneId, SurfaceHandle> {
        &self.bindings
    }

    /// Errors collected during the last layout tick or bind/unbind hide.
    pub fn last_errors(&self) -> &[(PaneId, SurfaceError)] {
        &self.last_errors
    }

    /// Surface id for a bound pane, if mapped.
    pub fn surface_id(&self, pane: PaneId) -> Option<SurfaceId> {
        self.bindings.get(&pane).map(|h| h.id)
    }

    fn hide_surface(&mut self, pane: PaneId, handle: SurfaceHandle) {
        let bounds = self
            .last_pushed
            .get(&pane)
            .map(|u| u.bounds)
            .unwrap_or(PhysicalBounds::SEED);
        self.push_update(pane, handle, bounds, SurfaceVisibility::Hidden);
    }

    fn push_update(
        &mut self,
        pane: PaneId,
        handle: SurfaceHandle,
        bounds: PhysicalBounds,
        visibility: SurfaceVisibility,
    ) {
        let update = SurfaceLayoutUpdate {
            bounds,
            visibility,
            z_order: ZOrderHint::Unchanged,
        };
        if self.last_pushed.get(&pane) == Some(&update) {
            return;
        }
        match self.broker.update_bounds(handle.id, update) {
            Ok(()) => {
                self.last_pushed.insert(pane, update);
            }
            Err(err) => self.last_errors.push((pane, err)),
        }
    }
}

impl<B> PaneLayoutSink for BrokerPaneLayoutSink<B>
where
    B: NativeSurfaceBroker + Send,
{
    fn on_pane_layout(&mut self, updates: &[PaneLayoutUpdate]) {
        self.last_errors.clear();

        let reported: HashSet<PaneId> = updates.iter().map(|u| u.pane).collect();

        // Hide surfaces whose panes were closed (omitted from this tick).
        let stale: Vec<(PaneId, SurfaceHandle)> = self
            .bindings
            .iter()
            .filter(|(pane, _)| !reported.contains(pane))
            .map(|(pane, handle)| (*pane, *handle))
            .collect();
        for (pane, handle) in stale {
            self.hide_surface(pane, handle);
        }

        for update in updates {
            let Some(handle) = self.bindings.get(&update.pane).copied() else {
                continue;
            };
            let bounds = pane_bounds_to_physical(update.bounds);
            let visibility = visibility_for_pane_bounds(update.bounds);
            self.push_update(update.pane, handle, bounds, visibility);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StubNativeSurfaceBroker;

    #[derive(Debug, Default)]
    struct CountingBroker {
        inner: StubNativeSurfaceBroker,
        update_calls: usize,
    }

    impl NativeSurfaceBroker for CountingBroker {
        fn register(&mut self, owner: OwnerHwnd, kind: SurfaceKind) -> Result<SurfaceHandle> {
            self.inner.register(owner, kind)
        }

        fn update_bounds(&mut self, id: SurfaceId, update: SurfaceLayoutUpdate) -> Result<()> {
            self.update_calls += 1;
            self.inner.update_bounds(id, update)
        }

        fn unregister(&mut self, id: SurfaceId) -> Result<()> {
            self.inner.unregister(id)
        }

        fn list(&self) -> Vec<SurfaceHandle> {
            self.inner.list()
        }
    }

    impl CountingBroker {
        fn last_update(&self, id: SurfaceId) -> Option<SurfaceLayoutUpdate> {
            self.inner.last_update(id)
        }
    }

    fn pane_update(pane: u8, x: i32, y: i32, w: u32, h: u32, dpi: u32) -> PaneLayoutUpdate {
        PaneLayoutUpdate {
            pane: PaneId(pane),
            bounds: PanePhysicalBounds {
                x,
                y,
                width: w,
                height: h,
                dpi,
            },
        }
    }

    #[test]
    fn maps_pane_layout_to_broker_bounds() {
        let mut sink = BrokerPaneLayoutSink::new(StubNativeSurfaceBroker::new());
        let web = sink
            .register_and_bind(PaneId(0), OwnerHwnd(0x1000), SurfaceKind::WebView2)
            .expect("webview");
        let rdp = sink
            .register_and_bind(PaneId(1), OwnerHwnd(0x1000), SurfaceKind::RdpActiveX)
            .expect("rdp");

        assert_eq!(web.kind, SurfaceKind::WebView2);
        assert_eq!(rdp.kind, SurfaceKind::RdpActiveX);
        assert_eq!(sink.binding(PaneId(0)).map(|h| h.id), Some(web.id));
        assert_eq!(sink.binding(PaneId(1)).map(|h| h.id), Some(rdp.id));

        sink.on_pane_layout(&[
            pane_update(0, 10, 20, 800, 600, 144),
            pane_update(1, 810, 20, 400, 600, 144),
        ]);

        assert!(sink.last_errors().is_empty());
        let web_u = sink.broker().last_update(web.id).expect("web update");
        assert_eq!(
            web_u.bounds,
            PhysicalBounds {
                x: 10,
                y: 20,
                width: 800,
                height: 600,
                dpi: 144,
            }
        );
        assert_eq!(web_u.visibility, SurfaceVisibility::Visible);

        let rdp_u = sink.broker().last_update(rdp.id).expect("rdp update");
        assert_eq!(rdp_u.bounds.width, 400);
        assert_eq!(rdp_u.visibility, SurfaceVisibility::Visible);
    }

    #[test]
    fn unbound_panes_are_ignored() {
        let mut sink = BrokerPaneLayoutSink::new(StubNativeSurfaceBroker::new());
        let web = sink
            .register_and_bind(PaneId(0), OwnerHwnd(1), SurfaceKind::WebView2)
            .expect("reg");

        sink.on_pane_layout(&[
            pane_update(0, 0, 0, 100, 100, 96),
            pane_update(2, 0, 0, 50, 50, 96), // not bound
        ]);

        assert!(sink.broker().last_update(web.id).is_some());
        assert!(sink.last_errors().is_empty());
        assert_eq!(sink.broker().list().len(), 1);
    }

    #[test]
    fn degenerate_bounds_hide_surface() {
        let mut sink = BrokerPaneLayoutSink::new(StubNativeSurfaceBroker::new());
        let web = sink
            .register_and_bind(PaneId(0), OwnerHwnd(1), SurfaceKind::WebView2)
            .expect("reg");

        sink.on_pane_layout(&[pane_update(0, 0, 0, 0, 100, 96)]);
        let u = sink.broker().last_update(web.id).expect("update");
        assert_eq!(u.visibility, SurfaceVisibility::Hidden);
        assert!(u.bounds.is_degenerate());
    }

    #[test]
    fn degenerate_height_zero_hides_surface() {
        let mut sink = BrokerPaneLayoutSink::new(StubNativeSurfaceBroker::new());
        let web = sink
            .register_and_bind(PaneId(0), OwnerHwnd(1), SurfaceKind::WebView2)
            .expect("reg");

        sink.on_pane_layout(&[pane_update(0, 5, 5, 100, 0, 96)]);
        let u = sink.broker().last_update(web.id).expect("update");
        assert_eq!(u.visibility, SurfaceVisibility::Hidden);
        assert!(u.bounds.is_degenerate());
        assert_eq!(u.bounds.x, 5);
        assert_eq!(u.bounds.y, 5);
    }

    #[test]
    fn extreme_coords_do_not_panic_and_stay_hidden_when_degenerate() {
        let mut sink = BrokerPaneLayoutSink::new(StubNativeSurfaceBroker::new());
        let web = sink
            .register_and_bind(PaneId(0), OwnerHwnd(1), SurfaceKind::WebView2)
            .expect("reg");

        sink.on_pane_layout(&[pane_update(0, i32::MIN, i32::MAX, 0, 0, 0)]);
        let u = sink.broker().last_update(web.id).expect("update");
        assert_eq!(u.visibility, SurfaceVisibility::Hidden);
        assert_eq!(u.bounds.x, i32::MIN);
        assert_eq!(u.bounds.y, i32::MAX);
        assert_eq!(u.bounds.dpi, 0);
    }

    #[test]
    fn omitted_bound_pane_is_hidden() {
        let mut sink = BrokerPaneLayoutSink::new(StubNativeSurfaceBroker::new());
        let a = sink
            .register_and_bind(PaneId(0), OwnerHwnd(1), SurfaceKind::WebView2)
            .expect("a");
        let b = sink
            .register_and_bind(PaneId(1), OwnerHwnd(1), SurfaceKind::RdpActiveX)
            .expect("b");

        sink.on_pane_layout(&[
            pane_update(0, 0, 0, 200, 200, 96),
            pane_update(1, 200, 0, 200, 200, 96),
        ]);
        // Pane 1 closed — only pane 0 reported.
        sink.on_pane_layout(&[pane_update(0, 0, 0, 400, 200, 96)]);

        let a_u = sink.broker().last_update(a.id).expect("a");
        assert_eq!(a_u.bounds.width, 400);
        assert_eq!(a_u.visibility, SurfaceVisibility::Visible);

        let b_u = sink.broker().last_update(b.id).expect("b hidden");
        assert_eq!(b_u.visibility, SurfaceVisibility::Hidden);
        assert_eq!(b_u.bounds.width, 200);
    }

    #[test]
    fn empty_tick_hides_all_bound_surfaces() {
        let mut sink = BrokerPaneLayoutSink::new(StubNativeSurfaceBroker::new());
        let a = sink
            .register_and_bind(PaneId(0), OwnerHwnd(1), SurfaceKind::WebView2)
            .expect("a");
        let b = sink
            .register_and_bind(PaneId(1), OwnerHwnd(1), SurfaceKind::RdpActiveX)
            .expect("b");

        sink.on_pane_layout(&[
            pane_update(0, 1, 2, 100, 100, 96),
            pane_update(1, 10, 20, 50, 50, 144),
        ]);
        sink.on_pane_layout(&[]);

        let a_u = sink.broker().last_update(a.id).expect("a");
        let b_u = sink.broker().last_update(b.id).expect("b");
        assert_eq!(a_u.visibility, SurfaceVisibility::Hidden);
        assert_eq!(b_u.visibility, SurfaceVisibility::Hidden);
        assert_eq!(a_u.bounds.width, 100);
        assert_eq!(b_u.bounds.dpi, 144);
    }

    #[test]
    fn unbind_hides_then_stops_updates_without_unregister() {
        let mut sink = BrokerPaneLayoutSink::new(StubNativeSurfaceBroker::new());
        let web = sink
            .register_and_bind(PaneId(0), OwnerHwnd(1), SurfaceKind::WebView2)
            .expect("reg");
        sink.on_pane_layout(&[pane_update(0, 1, 2, 3, 4, 96)]);
        assert!(sink.unbind(PaneId(0)).is_some());

        let after_unbind = sink.broker().last_update(web.id).expect("hidden");
        assert_eq!(after_unbind.visibility, SurfaceVisibility::Hidden);
        assert_eq!(after_unbind.bounds.x, 1);
        assert_eq!(after_unbind.bounds.width, 3);

        sink.on_pane_layout(&[pane_update(0, 9, 9, 9, 9, 96)]);
        // Still registered; last update unchanged (no binding → no push).
        let u = sink.broker().last_update(web.id).expect("kept");
        assert_eq!(u.bounds.x, 1);
        assert_eq!(u.visibility, SurfaceVisibility::Hidden);
        assert_eq!(sink.broker().list().len(), 1);
    }

    #[test]
    fn unbind_never_laid_out_hides_with_seed_bounds() {
        let mut sink = BrokerPaneLayoutSink::new(StubNativeSurfaceBroker::new());
        let web = sink
            .register_and_bind(PaneId(0), OwnerHwnd(1), SurfaceKind::WebView2)
            .expect("reg");
        assert!(sink.unbind(PaneId(0)).is_some());

        let u = sink.broker().last_update(web.id).expect("seed hide");
        assert_eq!(u.visibility, SurfaceVisibility::Hidden);
        assert_eq!(u.bounds, PhysicalBounds::SEED);
    }

    #[test]
    fn rebind_hides_previous_surface() {
        let mut sink = BrokerPaneLayoutSink::new(StubNativeSurfaceBroker::new());
        let web = sink
            .register_and_bind(PaneId(0), OwnerHwnd(1), SurfaceKind::WebView2)
            .expect("web");
        sink.on_pane_layout(&[pane_update(0, 10, 20, 30, 40, 96)]);

        let rdp = sink
            .broker_mut()
            .register(OwnerHwnd(1), SurfaceKind::RdpActiveX)
            .expect("rdp");
        sink.bind(PaneId(0), rdp);

        let web_u = sink.broker().last_update(web.id).expect("web hidden");
        assert_eq!(web_u.visibility, SurfaceVisibility::Hidden);
        assert_eq!(web_u.bounds.width, 30);
        assert_eq!(sink.binding(PaneId(0)).map(|h| h.id), Some(rdp.id));
        // New surface waits for next tick (bind-after-tick contract).
        assert!(sink.broker().last_update(rdp.id).is_none());

        sink.on_pane_layout(&[pane_update(0, 50, 60, 70, 80, 144)]);
        let rdp_u = sink.broker().last_update(rdp.id).expect("rdp shown");
        assert_eq!(rdp_u.visibility, SurfaceVisibility::Visible);
        assert_eq!(rdp_u.bounds.width, 70);
        assert_eq!(rdp_u.bounds.dpi, 144);
    }

    #[test]
    fn rebind_then_omit_still_hides_new_surface() {
        let mut sink = BrokerPaneLayoutSink::new(CountingBroker::default());
        let web = sink
            .register_and_bind(PaneId(0), OwnerHwnd(1), SurfaceKind::WebView2)
            .expect("web");
        sink.on_pane_layout(&[pane_update(0, 10, 20, 30, 40, 96)]);

        let rdp = sink
            .broker_mut()
            .register(OwnerHwnd(1), SurfaceKind::RdpActiveX)
            .expect("rdp");
        sink.bind(PaneId(0), rdp);
        assert_eq!(
            sink.broker().last_update(web.id).expect("web").visibility,
            SurfaceVisibility::Hidden
        );

        // Omit before the new surface ever receives a layout tick: must not
        // identical-skip against the previous surface's Hidden payload.
        let calls_before = sink.broker().update_calls;
        sink.on_pane_layout(&[]);
        assert!(sink.broker().update_calls > calls_before);
        let rdp_u = sink.broker().last_update(rdp.id).expect("rdp seed-hidden");
        assert_eq!(rdp_u.visibility, SurfaceVisibility::Hidden);
        assert_eq!(rdp_u.bounds, PhysicalBounds::SEED);

        sink.on_pane_layout(&[pane_update(0, 10, 20, 30, 40, 96)]);
        assert_eq!(
            sink.broker().last_update(rdp.id).expect("shown").visibility,
            SurfaceVisibility::Visible
        );
        let calls_mid = sink.broker().update_calls;
        sink.on_pane_layout(&[]);
        assert!(sink.broker().update_calls > calls_mid);
        assert_eq!(
            sink.broker().last_update(rdp.id).expect("rdp hidden").visibility,
            SurfaceVisibility::Hidden
        );
    }

    #[test]
    fn bind_after_tick_applies_on_next_tick_only() {
        let mut sink = BrokerPaneLayoutSink::new(StubNativeSurfaceBroker::new());
        // Tick with unbound pane — soft no-op.
        sink.on_pane_layout(&[pane_update(0, 1, 2, 3, 4, 96)]);

        let web = sink
            .broker_mut()
            .register(OwnerHwnd(1), SurfaceKind::WebView2)
            .expect("reg");
        sink.bind(PaneId(0), web);
        assert!(sink.broker().last_update(web.id).is_none());

        sink.on_pane_layout(&[pane_update(0, 10, 20, 30, 40, 96)]);
        let u = sink.broker().last_update(web.id).expect("next tick");
        assert_eq!(u.bounds.width, 30);
        assert_eq!(u.visibility, SurfaceVisibility::Visible);
    }

    #[test]
    fn unknown_surface_records_error() {
        let mut sink = BrokerPaneLayoutSink::new(StubNativeSurfaceBroker::new());
        let handle = sink
            .broker_mut()
            .register(OwnerHwnd(1), SurfaceKind::WebView2)
            .expect("reg");
        sink.bind(PaneId(0), handle);
        sink.broker_mut().unregister(handle.id).expect("gone");

        sink.on_pane_layout(&[pane_update(0, 0, 0, 10, 10, 96)]);
        assert_eq!(sink.last_errors().len(), 1);
        assert_eq!(sink.last_errors()[0].0, PaneId(0));
        assert_eq!(
            sink.last_errors()[0].1,
            SurfaceError::UnknownSurface(handle.id)
        );
    }

    #[test]
    fn unbind_missing_pane_is_noop_and_preserves_last_errors() {
        let mut sink = BrokerPaneLayoutSink::new(StubNativeSurfaceBroker::new());
        let handle = sink
            .broker_mut()
            .register(OwnerHwnd(1), SurfaceKind::WebView2)
            .expect("reg");
        sink.bind(PaneId(0), handle);
        sink.broker_mut().unregister(handle.id).expect("gone");
        sink.on_pane_layout(&[pane_update(0, 0, 0, 10, 10, 96)]);
        assert_eq!(sink.last_errors().len(), 1);

        assert!(sink.unbind(PaneId(9)).is_none());
        assert_eq!(sink.last_errors().len(), 1);
        assert_eq!(
            sink.last_errors()[0].1,
            SurfaceError::UnknownSurface(handle.id)
        );
    }

    #[test]
    fn rebind_same_handle_does_not_hide() {
        let mut sink = BrokerPaneLayoutSink::new(StubNativeSurfaceBroker::new());
        let web = sink
            .register_and_bind(PaneId(0), OwnerHwnd(1), SurfaceKind::WebView2)
            .expect("reg");
        sink.on_pane_layout(&[pane_update(0, 1, 2, 3, 4, 96)]);
        sink.bind(PaneId(0), web);
        let u = sink.broker().last_update(web.id).expect("unchanged");
        assert_eq!(u.visibility, SurfaceVisibility::Visible);
        assert_eq!(u.bounds.width, 3);
        assert!(sink.last_errors().is_empty());
    }

    #[test]
    fn pane_bounds_conversion_round_trip_fields() {
        let p = PanePhysicalBounds {
            x: -4,
            y: 8,
            width: 16,
            height: 32,
            dpi: 192,
        };
        let phys = pane_bounds_to_physical(p);
        assert_eq!(phys.x, -4);
        assert_eq!(phys.y, 8);
        assert_eq!(phys.width, 16);
        assert_eq!(phys.height, 32);
        assert_eq!(phys.dpi, 192);
        assert_eq!(visibility_for_pane_bounds(p), SurfaceVisibility::Visible);
    }

    #[test]
    fn identical_omit_hide_skips_broker_update() {
        let mut sink = BrokerPaneLayoutSink::new(CountingBroker::default());
        let web = sink
            .register_and_bind(PaneId(0), OwnerHwnd(1), SurfaceKind::WebView2)
            .expect("reg");

        sink.on_pane_layout(&[pane_update(0, 1, 2, 3, 4, 96)]);
        let after_show = sink.broker().update_calls;
        sink.on_pane_layout(&[]);
        let after_hide = sink.broker().update_calls;
        assert_eq!(after_hide, after_show + 1);
        assert_eq!(
            sink.broker().last_update(web.id).expect("hidden").visibility,
            SurfaceVisibility::Hidden
        );

        sink.on_pane_layout(&[]);
        assert_eq!(sink.broker().update_calls, after_hide);
    }
}
