//! `HasWindowHandle` wrapper around a raw Win32 HWND.

use std::num::NonZeroIsize;

use raw_window_handle::{
    HandleError, HasWindowHandle, RawWindowHandle, Win32WindowHandle, WindowHandle,
};

use crate::OwnerHwnd;

/// Borrowed owner HWND for wry `build_as_child`.
///
/// The underlying HWND must remain alive for the lifetime of any child WebView2
/// created from this handle.
#[derive(Debug, Clone, Copy)]
pub struct OwnerWindowHandle {
    hwnd: NonZeroIsize,
}

impl OwnerWindowHandle {
    /// Wrap a non-null owner HWND.
    pub fn new(owner: OwnerHwnd) -> Option<Self> {
        NonZeroIsize::new(owner.0).map(|hwnd| Self { hwnd })
    }

    /// Raw HWND value as `isize`.
    pub fn as_raw(&self) -> isize {
        self.hwnd.get()
    }

    /// As broker [`OwnerHwnd`].
    pub fn owner_hwnd(&self) -> OwnerHwnd {
        OwnerHwnd(self.hwnd.get())
    }
}

impl HasWindowHandle for OwnerWindowHandle {
    fn window_handle(&self) -> Result<WindowHandle<'_>, HandleError> {
        let handle = Win32WindowHandle::new(self.hwnd);
        let raw = RawWindowHandle::Win32(handle);
        // SAFETY: caller keeps the HWND alive for the duration of the WebView.
        Ok(unsafe { WindowHandle::borrow_raw(raw) })
    }
}
