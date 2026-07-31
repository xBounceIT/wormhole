//! Owned-overlay HWND host for gate 6 (`--features rdp`).
//!
//! Proves the hosting model: `WS_POPUP` + `GWLP_HWNDPARENT` + `WS_EX_TOOLWINDOW`
//! (not `SetParent` / `WS_CHILD`). OLE in-place MsRdpClient activation lives in
//! [`super::ocx`] and must run on the **same STA** that created this HWND.
//!
//! # Drop order
//!
//! Drop any [`super::ocx::RdpOcx`] activated into this host **before** dropping
//! the host (destroying the overlay HWND). See `docs/migration/05-rdp-spike.md`.

use windows::Win32::Foundation::HWND;

use super::clsid::{select_best_rdp_class, RdpActiveXClass};
use super::host_bounds::HostBounds;
use super::ocx::{InPlaceActivateInfo, RdpOcx};
use super::overlay::OverlayWindow;
use crate::OwnerHwnd;

/// Snapshot of a live overlay host (lab / diagnostics).
#[derive(Debug, Clone)]
pub struct RdpOverlayInfo {
    /// Overlay HWND as isize.
    pub hwnd: isize,
    /// Preferred ActiveX class name (registry probe).
    pub class_name: String,
    /// Preferred CLSID string (registry probe).
    pub clsid: String,
    /// True when style bits show owned overlay (`WS_POPUP`, not `WS_CHILD`, `WS_EX_TOOLWINDOW`).
    pub is_owned_popup: bool,
}

/// Owned-overlay HWND host.
pub struct RdpOverlayHost {
    overlay: OverlayWindow,
    class: RdpActiveXClass,
}

impl RdpOverlayHost {
    /// Create an owned overlay HWND. `owner` may be null (`0`) for lab smoke.
    pub fn spawn(owner: OwnerHwnd, seed: HostBounds) -> windows::core::Result<Self> {
        let activation = if seed.is_degenerate(1) {
            HostBounds::SEED
        } else {
            seed
        };
        let owner_hwnd = HWND(owner.0 as *mut _);
        let mut overlay = OverlayWindow::create(owner_hwnd, activation)?;
        overlay.set_bounds(activation, true)?;
        Ok(Self {
            overlay,
            class: select_best_rdp_class(),
        })
    }

    /// Position the overlay in screen physical pixels.
    pub fn set_bounds(&mut self, bounds: HostBounds) -> windows::core::Result<()> {
        self.overlay.set_bounds(bounds, false)
    }

    /// Show (`SW_SHOWNA`) or hide the overlay without activation.
    pub fn set_visible(&self, visible: bool) -> windows::core::Result<()> {
        self.overlay.set_visible(visible)
    }

    /// Push keyboard focus into the overlay HWND.
    ///
    /// # Production note
    ///
    /// C# `RdpHostForm.RequestFocus` targets the **AxHost child** HWND, not the form.
    /// Until the OCX child is realized here, the lab focuses the overlay HWND as a
    /// stand-in. Always route through [`crate::FocusBroker`] and never pass a null HWND.
    pub fn request_focus(&self) -> crate::Result<()> {
        use crate::focus::{set_focus, FocusHwnd};
        let hwnd = FocusHwnd(self.overlay.hwnd().0 as isize);
        set_focus(hwnd)?;
        Ok(())
    }

    /// Overlay HWND as a [`crate::focus::FocusHwnd`] (lab stand-in for AxHost child).
    pub fn focus_hwnd(&self) -> crate::focus::FocusHwnd {
        crate::focus::FocusHwnd(self.overlay.hwnd().0 as isize)
    }

    /// Diagnostic snapshot (style bits + preferred CLSID probe).
    pub fn info(&self) -> RdpOverlayInfo {
        RdpOverlayInfo {
            hwnd: self.overlay.hwnd().0 as isize,
            class_name: self.class.name.to_string(),
            clsid: self.class.clsid_string.to_string(),
            is_owned_popup: self.overlay.is_popup_not_child(),
        }
    }

    /// Overlay HWND for OLE `DoVerb` / site hosting (same STA as this host).
    pub fn hwnd(&self) -> HWND {
        self.overlay.hwnd()
    }

    /// CoCreate MsRdpClient and in-place activate it into this overlay HWND.
    ///
    /// Must run on the STA that owns the overlay (see [`super::ocx::run_on_sta`]).
    pub fn activate_ocx(&self, ocx: &mut RdpOcx) -> windows::core::Result<InPlaceActivateInfo> {
        ocx.activate_in_place(self.overlay.hwnd())
    }

    /// Destroy the overlay HWND (also runs on drop).
    pub fn shutdown(self) {
        drop(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::UI::WindowsAndMessaging::IsWindow;

    #[test]
    fn owned_overlay_is_popup_toolwindow_not_child() {
        let mut host =
            RdpOverlayHost::spawn(OwnerHwnd(0), HostBounds::SEED).expect("spawn overlay");
        let info = host.info();
        assert!(
            info.is_owned_popup,
            "RDP host must be WS_POPUP + WS_EX_TOOLWINDOW owned overlay, not WS_CHILD/SetParent"
        );
        assert!(info.hwnd != 0);
        host.set_bounds(HostBounds::new(10, 10, 320, 240))
            .expect("bounds");
        host.set_visible(false).expect("hide");
        host.set_visible(true).expect("show");
        host.shutdown();
    }

    #[test]
    fn spawn_empty_uses_seed_and_rejects_degenerate_bounds() {
        let mut host =
            RdpOverlayHost::spawn(OwnerHwnd(0), HostBounds::EMPTY).expect("spawn from empty");
        assert!(host.info().is_owned_popup);
        let err = host
            .set_bounds(HostBounds::new(0, 0, 0, 0))
            .expect_err("zero size must fail");
        assert_eq!(err.code(), windows::Win32::Foundation::E_INVALIDARG);
        let err = host
            .set_bounds(HostBounds::new(0, 0, -1, 10))
            .expect_err("negative size must fail");
        assert_eq!(err.code(), windows::Win32::Foundation::E_INVALIDARG);
        host.shutdown();
    }

    #[test]
    fn drop_destroys_hwnd() {
        let host = RdpOverlayHost::spawn(OwnerHwnd(0), HostBounds::SEED).expect("spawn");
        let hwnd = HWND(host.info().hwnd as *mut _);
        assert!(unsafe { IsWindow(Some(hwnd)).as_bool() });
        drop(host);
        assert!(
            !unsafe { IsWindow(Some(hwnd)).as_bool() },
            "overlay HWND must be destroyed on drop (no leak)"
        );
    }
}
