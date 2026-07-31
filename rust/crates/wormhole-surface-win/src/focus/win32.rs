//! Win32 `SetFocus` / `GetFocus` wrappers.
//!
//! C# parity (`Helpers/Win32Interop.SetFocus`):
//! - Never pass null (broker / these helpers reject first).
//! - `windows` 0.61: `SetFocus(Option<HWND>) -> Result<HWND>`; map errors via `GetLastError`.

use windows::Win32::Foundation::{GetLastError, SetLastError, HWND, WIN32_ERROR};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetFocus as Win32GetFocus, SetFocus as Win32SetFocus,
};

use super::ops::{FocusError, FocusHwnd, FocusOps};

/// Push keyboard focus to `hwnd`. Rejects null before calling Win32.
pub fn set_focus(hwnd: FocusHwnd) -> Result<Option<FocusHwnd>, FocusError> {
    if hwnd.is_null() {
        return Err(FocusError::NullHwndRejected);
    }
    unsafe {
        SetLastError(WIN32_ERROR(0));
        match Win32SetFocus(Some(HWND(hwnd.0 as *mut _))) {
            Ok(previous) => {
                if previous.0.is_null() {
                    Ok(None)
                } else {
                    Ok(Some(FocusHwnd(previous.0 as isize)))
                }
            }
            Err(_) => {
                let err = GetLastError();
                if err.0 == 0 {
                    // No prior focus HWND — treat as success with no previous.
                    Ok(None)
                } else {
                    Err(FocusError::SetFocusFailed {
                        hwnd,
                        code: err.0,
                    })
                }
            }
        }
    }
}

/// Current thread keyboard focus, if any.
pub fn get_focus() -> Result<Option<FocusHwnd>, FocusError> {
    let hwnd = unsafe { Win32GetFocus() };
    if hwnd.0.is_null() {
        Ok(None)
    } else {
        Ok(Some(FocusHwnd(hwnd.0 as isize)))
    }
}

/// [`FocusOps`] backed by real Win32 APIs.
#[derive(Debug, Default, Clone, Copy)]
pub struct Win32FocusOps;

impl FocusOps for Win32FocusOps {
    fn set_focus(&mut self, hwnd: FocusHwnd) -> Result<Option<FocusHwnd>, FocusError> {
        set_focus(hwnd)
    }

    fn get_focus(&mut self) -> Result<Option<FocusHwnd>, FocusError> {
        get_focus()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_focus_rejects_null_without_win32() {
        assert_eq!(set_focus(FocusHwnd(0)), Err(FocusError::NullHwndRejected));
    }

    #[test]
    fn get_focus_does_not_panic() {
        // May be None depending on thread state; must not throw.
        let _ = get_focus().expect("GetFocus should not error");
    }
}
