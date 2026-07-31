//! [`NativeSurfaceBroker`] trait and in-memory stub implementation.

use std::collections::HashMap;

use crate::bounds::{PhysicalBounds, SurfaceVisibility, ZOrderHint};
use crate::kinds::SurfaceKind;
use crate::{Result, SurfaceError};

/// Opaque id assigned at registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SurfaceId(pub u64);

impl std::fmt::Display for SurfaceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Handle returned after a successful register call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SurfaceHandle {
    /// Unique id for subsequent bounds updates / unregister.
    pub id: SurfaceId,
    /// Kind that was registered.
    pub kind: SurfaceKind,
}

/// Owner window identity (HWND as `isize` until `windows` crate is pinned).
///
/// Phase-1 stub stores the value only; no Win32 calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OwnerHwnd(pub isize);

/// Layout update payload from the shell layout tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SurfaceLayoutUpdate {
    /// Physical pixel bounds + DPI.
    pub bounds: PhysicalBounds,
    /// Show / hide.
    pub visibility: SurfaceVisibility,
    /// Optional z-order hint among sibling surfaces.
    pub z_order: ZOrderHint,
}

/// Minimal broker API: register kinds, push bounds, unregister.
///
/// RDP OCX work is STA UI-thread-affine (see native-surface-broker.md).
/// Do not drive mstscax from a Tokio MTA worker.
pub trait NativeSurfaceBroker {
    /// Register a surface kind under an owner HWND. No COM yet — id bookkeeping only.
    fn register(&mut self, owner: OwnerHwnd, kind: SurfaceKind) -> Result<SurfaceHandle>;

    /// Apply layout bounds from the GPUI/lab layout pass (physical px).
    fn update_bounds(&mut self, id: SurfaceId, update: SurfaceLayoutUpdate) -> Result<()>;

    /// Drop registration; later phases destroy the surface HWND / release COM
    /// (WebView2 child host or RDP owned overlay — never SetParent for RDP).
    fn unregister(&mut self, id: SurfaceId) -> Result<()>;

    /// Snapshot of live registrations (lab / diagnostics).
    fn list(&self) -> Vec<SurfaceHandle>;
}

#[derive(Debug)]
struct SurfaceRecord {
    handle: SurfaceHandle,
    /// Owner HWND (`GWLP_HWNDPARENT` for RDP overlay; parent for WebView2).
    #[allow(dead_code)]
    owner: OwnerHwnd,
    last_update: Option<SurfaceLayoutUpdate>,
}

/// In-memory stub broker: records registrations and layout updates, no HWND/COM.
#[derive(Debug, Default)]
pub struct StubNativeSurfaceBroker {
    next_id: u64,
    surfaces: HashMap<SurfaceId, SurfaceRecord>,
}

impl StubNativeSurfaceBroker {
    /// Create an empty stub broker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Last layout update for a surface, if any (test / lab helper).
    pub fn last_update(&self, id: SurfaceId) -> Option<SurfaceLayoutUpdate> {
        self.surfaces.get(&id).and_then(|r| r.last_update)
    }
}

impl NativeSurfaceBroker for StubNativeSurfaceBroker {
    fn register(&mut self, owner: OwnerHwnd, kind: SurfaceKind) -> Result<SurfaceHandle> {
        if !cfg!(windows) {
            return Err(SurfaceError::UnsupportedPlatform);
        }

        match kind {
            SurfaceKind::WebView2 | SurfaceKind::RdpActiveX => {}
        }

        let id = SurfaceId({
            self.next_id = self.next_id.saturating_add(1);
            self.next_id
        });
        let handle = SurfaceHandle { id, kind };
        self.surfaces.insert(
            id,
            SurfaceRecord {
                handle,
                owner,
                last_update: None,
            },
        );
        Ok(handle)
    }

    fn update_bounds(&mut self, id: SurfaceId, update: SurfaceLayoutUpdate) -> Result<()> {
        let record = self
            .surfaces
            .get_mut(&id)
            .ok_or(SurfaceError::UnknownSurface(id))?;
        record.last_update = Some(update);
        // WebView2: call `ChildWebViewHost::set_bounds` / `set_visible` from the
        // shell when feature `webview` is enabled (gate 3). RDP overlay SetBounds: gate 6.
        Ok(())
    }

    fn unregister(&mut self, id: SurfaceId) -> Result<()> {
        self.surfaces
            .remove(&id)
            .map(|_| ())
            .ok_or(SurfaceError::UnknownSurface(id))
    }

    fn list(&self) -> Vec<SurfaceHandle> {
        self.surfaces.values().map(|r| r.handle).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_update_webview2() {
        let mut broker = StubNativeSurfaceBroker::new();
        let handle = broker
            .register(OwnerHwnd(0x1000), SurfaceKind::WebView2)
            .expect("register");
        assert_eq!(handle.kind, SurfaceKind::WebView2);

        broker
            .update_bounds(
                handle.id,
                SurfaceLayoutUpdate {
                    bounds: PhysicalBounds {
                        x: 10,
                        y: 20,
                        width: 800,
                        height: 600,
                        dpi: 144,
                    },
                    visibility: SurfaceVisibility::Visible,
                    z_order: ZOrderHint::Unchanged,
                },
            )
            .expect("update");

        let last = broker.last_update(handle.id).expect("stored");
        assert_eq!(last.bounds.dpi, 144);
        assert!(!last.bounds.is_degenerate());
    }

    #[test]
    fn stub_registers_rdp_without_com_and_unregister_unknown() {
        let mut broker = StubNativeSurfaceBroker::new();
        let rdp = broker
            .register(OwnerHwnd(0x2000), SurfaceKind::RdpActiveX)
            .expect("stub RDP register must not require COM");
        assert_eq!(rdp.kind, SurfaceKind::RdpActiveX);
        assert_eq!(rdp.kind.label(), "RdpActiveX");
        assert!(broker.last_update(rdp.id).is_none());

        broker.unregister(rdp.id).expect("unregister");
        assert!(broker.list().is_empty());
        assert_eq!(
            broker.unregister(rdp.id),
            Err(SurfaceError::UnknownSurface(rdp.id))
        );
        assert_eq!(
            broker.update_bounds(
                rdp.id,
                SurfaceLayoutUpdate {
                    bounds: PhysicalBounds {
                        x: 0,
                        y: 0,
                        width: 1,
                        height: 1,
                        dpi: 96,
                    },
                    visibility: SurfaceVisibility::Hidden,
                    z_order: ZOrderHint::Unchanged,
                },
            ),
            Err(SurfaceError::UnknownSurface(rdp.id))
        );
    }
}
