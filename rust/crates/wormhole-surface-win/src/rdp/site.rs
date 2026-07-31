//! Minimal `IOleClientSite` + `IOleInPlaceSite` for MsRdpClient in-place activation.
//!
//! The site's window is the owned overlay HWND (`GWLP_HWNDPARENT` model). The OCX
//! is embedded *into* that HWND via OLE — we never `SetParent` the overlay itself.

use std::cell::Cell;

use windows::core::{implement, BOOL};
use windows::Win32::Foundation::{E_NOINTERFACE, E_NOTIMPL, HWND, RECT, SIZE};
use windows::Win32::System::Com::IMoniker;
use windows::Win32::System::Ole::{
    IOleClientSite, IOleClientSite_Impl, IOleContainer, IOleInPlaceFrame, IOleInPlaceObject,
    IOleInPlaceSite, IOleInPlaceSite_Impl, IOleInPlaceUIWindow, IOleWindow_Impl, OLEGETMONIKER,
    OLEINPLACEFRAMEINFO, OLEWHICHMK,
};
use windows::Win32::UI::WindowsAndMessaging::GetClientRect;

/// OLE client / in-place site bound to the owned overlay HWND.
#[implement(IOleClientSite, IOleInPlaceSite)]
pub struct RdpOleSite {
    hwnd: HWND,
    /// Optional in-place object for `OnPosRectChange` → `SetObjectRects`.
    inplace: Cell<Option<IOleInPlaceObject>>,
}

impl RdpOleSite {
    /// Create a site for `hwnd` (the owned overlay container).
    pub fn new(hwnd: HWND) -> Self {
        Self {
            hwnd,
            inplace: Cell::new(None),
        }
    }

    /// Remember the activated in-place object (for resize notifications).
    pub fn set_inplace_object(&self, obj: Option<IOleInPlaceObject>) {
        self.inplace.replace(obj);
    }

    fn client_rect(&self) -> RECT {
        let mut rc = RECT::default();
        let _ = unsafe { GetClientRect(self.hwnd, &mut rc) };
        ensure_min_rect(&mut rc);
        rc
    }
}

/// Ensure OLE pos/clip rects are at least 1×1 (ActiveX rejects empty rects).
pub(crate) fn ensure_min_rect(rc: &mut RECT) {
    if rc.right <= rc.left {
        rc.right = rc.left + 1;
    }
    if rc.bottom <= rc.top {
        rc.bottom = rc.top + 1;
    }
}

impl IOleClientSite_Impl for RdpOleSite_Impl {
    fn SaveObject(&self) -> windows::core::Result<()> {
        Err(windows::core::Error::from(E_NOTIMPL))
    }

    fn GetMoniker(
        &self,
        _dwassign: &OLEGETMONIKER,
        _dwwhichmoniker: &OLEWHICHMK,
    ) -> windows::core::Result<IMoniker> {
        Err(windows::core::Error::from(E_NOTIMPL))
    }

    fn GetContainer(&self) -> windows::core::Result<IOleContainer> {
        Err(windows::core::Error::from(E_NOINTERFACE))
    }

    fn ShowObject(&self) -> windows::core::Result<()> {
        Ok(())
    }

    fn OnShowWindow(&self, _fshow: BOOL) -> windows::core::Result<()> {
        Ok(())
    }

    fn RequestNewObjectLayout(&self) -> windows::core::Result<()> {
        Err(windows::core::Error::from(E_NOTIMPL))
    }
}

impl IOleWindow_Impl for RdpOleSite_Impl {
    fn GetWindow(&self) -> windows::core::Result<HWND> {
        Ok(self.hwnd)
    }

    fn ContextSensitiveHelp(&self, _fentermode: BOOL) -> windows::core::Result<()> {
        Ok(())
    }
}

impl IOleInPlaceSite_Impl for RdpOleSite_Impl {
    fn CanInPlaceActivate(&self) -> windows::core::Result<()> {
        Ok(())
    }

    fn OnInPlaceActivate(&self) -> windows::core::Result<()> {
        Ok(())
    }

    fn OnUIActivate(&self) -> windows::core::Result<()> {
        Ok(())
    }

    fn GetWindowContext(
        &self,
        ppframe: windows::core::OutRef<'_, IOleInPlaceFrame>,
        ppdoc: windows::core::OutRef<'_, IOleInPlaceUIWindow>,
        lprcposrect: *mut RECT,
        lprccliprect: *mut RECT,
        lpframeinfo: *mut OLEINPLACEFRAMEINFO,
    ) -> windows::core::Result<()> {
        let _ = ppframe.write(None);
        let _ = ppdoc.write(None);
        let rc = self.client_rect();
        unsafe {
            if !lprcposrect.is_null() {
                *lprcposrect = rc;
            }
            if !lprccliprect.is_null() {
                *lprccliprect = rc;
            }
            if !lpframeinfo.is_null() {
                (*lpframeinfo).cb = std::mem::size_of::<OLEINPLACEFRAMEINFO>() as u32;
                (*lpframeinfo).fMDIApp = false.into();
                (*lpframeinfo).hwndFrame = self.hwnd;
                (*lpframeinfo).haccel = windows::Win32::UI::WindowsAndMessaging::HACCEL::default();
                (*lpframeinfo).cAccelEntries = 0;
            }
        }
        Ok(())
    }

    fn Scroll(&self, _scrollextant: &SIZE) -> windows::core::Result<()> {
        Ok(())
    }

    fn OnUIDeactivate(&self, _fundoable: BOOL) -> windows::core::Result<()> {
        Ok(())
    }

    fn OnInPlaceDeactivate(&self) -> windows::core::Result<()> {
        self.inplace.replace(None);
        Ok(())
    }

    fn DiscardUndoState(&self) -> windows::core::Result<()> {
        Ok(())
    }

    fn DeactivateAndUndo(&self) -> windows::core::Result<()> {
        Ok(())
    }

    fn OnPosRectChange(&self, lprcposrect: *const RECT) -> windows::core::Result<()> {
        if lprcposrect.is_null() {
            return Ok(());
        }
        // replace(None) avoids holding a borrow across SetObjectRects.
        if let Some(obj) = self.inplace.replace(None) {
            let rc = unsafe { *lprcposrect };
            let _ = unsafe { obj.SetObjectRects(&rc, &rc) };
            self.inplace.replace(Some(obj));
        }
        Ok(())
    }
}

/// Build a counted `IOleClientSite` for the overlay HWND.
pub fn create_client_site(hwnd: HWND) -> windows::core::ComObject<RdpOleSite> {
    windows::core::ComObject::new(RdpOleSite::new(hwnd))
}

/// QI helper: site as `IOleClientSite` (also QI's to `IOleInPlaceSite` for the OCX).
pub fn as_client_site(site: &windows::core::ComObject<RdpOleSite>) -> IOleClientSite {
    site.to_interface()
}
