//! Owned top-level overlay HWND (GWLP_HWNDPARENT + WS_EX_TOOLWINDOW, not SetParent).

use windows::core::PCWSTR;
use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Graphics::Gdi::{GetStockObject, UpdateWindow, HBRUSH, WHITE_BRUSH};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, GetWindowLongPtrW, IsWindow, LoadCursorW,
    RegisterClassW, SetWindowLongPtrW, SetWindowPos, ShowWindow, CS_HREDRAW, CS_VREDRAW,
    GWLP_HWNDPARENT, GWL_EXSTYLE, GWL_STYLE, HCURSOR, IDC_ARROW, SWP_FRAMECHANGED,
    SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER, SWP_SHOWWINDOW, SW_HIDE, SW_SHOWNA,
    WM_DESTROY, WNDCLASSW, WS_CHILD, WS_EX_TOOLWINDOW, WS_POPUP,
};

use super::host_bounds::HostBounds;

const CLASS_NAME: PCWSTR = windows::core::w!("WormholeRdpOverlayHost");

pub(crate) struct OverlayWindow {
    hwnd: HWND,
    last: Option<HostBounds>,
}

impl OverlayWindow {
    /// Create a top-level `WS_POPUP` host (not `WS_CHILD`) and configure ownership.
    pub(crate) fn create(owner: HWND, seed: HostBounds) -> windows::core::Result<Self> {
        register_class()?;
        let instance = unsafe { GetModuleHandleW(None)? };
        let hwnd = unsafe {
            CreateWindowExW(
                WS_EX_TOOLWINDOW,
                CLASS_NAME,
                windows::core::w!("Wormhole RDP host"),
                WS_POPUP,
                seed.x,
                seed.y,
                seed.width.max(1),
                seed.height.max(1),
                None,
                None,
                Some(HINSTANCE(instance.0)),
                None,
            )?
        };

        configure_as_owned_overlay(hwnd, owner)?;
        Ok(Self {
            hwnd,
            last: None,
        })
    }

    pub(crate) fn hwnd(&self) -> HWND {
        self.hwnd
    }

    /// Apply screen-physical bounds. Dedupes equal rects. Programmatic moves use `SWP_NOACTIVATE`.
    ///
    /// Rejects width/height < 1 (matches C# `RdpHostForm.SetHostBounds`). Layout-layer
    /// `is_degenerate(8)` skips remain a session/broker concern.
    pub(crate) fn set_bounds(
        &mut self,
        bounds: HostBounds,
        reveal: bool,
    ) -> windows::core::Result<()> {
        if bounds.width < 1 || bounds.height < 1 {
            return Err(windows::core::Error::from(
                windows::Win32::Foundation::E_INVALIDARG,
            ));
        }
        if self.last == Some(bounds) && !reveal {
            return Ok(());
        }

        let mut flags = SWP_NOACTIVATE | SWP_NOZORDER;
        if reveal {
            flags |= SWP_SHOWWINDOW;
        }

        unsafe {
            SetWindowPos(
                self.hwnd,
                None,
                bounds.x,
                bounds.y,
                bounds.width,
                bounds.height,
                flags,
            )?;
            if reveal {
                let _ = ShowWindow(self.hwnd, SW_SHOWNA);
                let _ = UpdateWindow(self.hwnd);
            }
        }
        self.last = Some(bounds);
        Ok(())
    }

    pub(crate) fn set_visible(&self, visible: bool) -> windows::core::Result<()> {
        unsafe {
            let _ = ShowWindow(self.hwnd, if visible { SW_SHOWNA } else { SW_HIDE });
            if visible {
                let _ = UpdateWindow(self.hwnd);
            }
        }
        Ok(())
    }

    /// Diagnostic style bits: expect `WS_POPUP`, not `WS_CHILD`.
    pub(crate) fn style_bits(&self) -> (isize, isize) {
        unsafe {
            (
                GetWindowLongPtrW(self.hwnd, GWL_STYLE),
                GetWindowLongPtrW(self.hwnd, GWL_EXSTYLE),
            )
        }
    }

    /// True when styles match the owned-overlay contract:
    /// `WS_POPUP`, not `WS_CHILD`, and `WS_EX_TOOLWINDOW`.
    pub(crate) fn is_popup_not_child(&self) -> bool {
        let (style, ex) = self.style_bits();
        let style = style as u32;
        let ex = ex as u32;
        (style & WS_POPUP.0) != 0
            && (style & WS_CHILD.0) == 0
            && (ex & WS_EX_TOOLWINDOW.0) != 0
    }
}

impl Drop for OverlayWindow {
    fn drop(&mut self) {
        unsafe {
            if IsWindow(Some(self.hwnd)).as_bool() {
                let _ = DestroyWindow(self.hwnd);
            }
            self.hwnd = HWND::default();
        }
    }
}

fn configure_as_owned_overlay(hwnd: HWND, owner: HWND) -> windows::core::Result<()> {
    unsafe {
        // Null owner is allowed for lab smoke (unowned popup). Production always
        // passes the main window HWND. Never use SetParent / WS_CHILD.
        if !owner.0.is_null() {
            windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(0));
            let prev = SetWindowLongPtrW(hwnd, GWLP_HWNDPARENT, owner.0 as isize);
            if prev == 0 {
                let err = windows::Win32::Foundation::GetLastError();
                if err.0 != 0 {
                    return Err(windows::core::Error::from(err));
                }
            }
        }

        windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(0));
        let ex = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
        let new_ex = ex | WS_EX_TOOLWINDOW.0 as isize;
        if new_ex != ex {
            windows::Win32::Foundation::SetLastError(windows::Win32::Foundation::WIN32_ERROR(0));
            let prev_ex = SetWindowLongPtrW(hwnd, GWL_EXSTYLE, new_ex);
            if prev_ex == 0 {
                let err = windows::Win32::Foundation::GetLastError();
                if err.0 != 0 {
                    return Err(windows::core::Error::from(err));
                }
            }
        }

        let _ = SetWindowPos(
            hwnd,
            None,
            0,
            0,
            0,
            0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED,
        );
    }
    Ok(())
}

fn register_class() -> windows::core::Result<()> {
    use std::sync::OnceLock;
    static DONE: OnceLock<windows::core::Result<()>> = OnceLock::new();
    DONE.get_or_init(|| {
        let instance = unsafe { GetModuleHandleW(None)? };
        let cursor: HCURSOR = unsafe { LoadCursorW(None, IDC_ARROW)? };
        let brush: HBRUSH = unsafe { HBRUSH(GetStockObject(WHITE_BRUSH).0) };
        let wc = WNDCLASSW {
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(overlay_wnd_proc),
            hInstance: HINSTANCE(instance.0),
            hCursor: cursor,
            hbrBackground: brush,
            lpszClassName: CLASS_NAME,
            ..Default::default()
        };
        let atom = unsafe { RegisterClassW(&wc) };
        if atom == 0 {
            let err = unsafe { windows::Win32::Foundation::GetLastError() };
            // Already registered in this process is fine.
            if err.0 == 1410 {
                // ERROR_CLASS_ALREADY_EXISTS
                Ok(())
            } else {
                Err(windows::core::Error::from(err))
            }
        } else {
            Ok(())
        }
    })
    .clone()
}

unsafe extern "system" fn overlay_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if msg == WM_DESTROY {
        return LRESULT(0);
    }
    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}
