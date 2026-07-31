//! Minimal Win32 owner window for surface-lab WebView2 smokes (not GPUI).

use std::ffi::c_void;
use std::ptr;
use std::sync::OnceLock;

use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::HBRUSH;
use windows::Win32::System::Com::{CoInitializeEx, COINIT_APARTMENTTHREADED};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetClientRect,
    GetMessageW, LoadCursorW, PeekMessageW, PostQuitMessage, RegisterClassExW, ShowWindow,
    TranslateMessage, CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT, IDC_ARROW, MSG, PM_REMOVE,
    SW_SHOW, WINDOW_EX_STYLE, WM_CLOSE, WM_DESTROY, WNDCLASSEXW, WS_OVERLAPPEDWINDOW,
};

use crate::OwnerHwnd;

/// Errors creating / pumping a lab owner window.
#[derive(Debug)]
pub enum OwnerWindowError {
    /// `CoInitializeEx` failed (other than `S_FALSE` / already initialized).
    ComInit(windows::core::Error),
    /// Window class registration failed.
    RegisterClass(windows::core::Error),
    /// `CreateWindowExW` returned null.
    CreateWindow(windows::core::Error),
    /// Null HWND where a live window was required.
    NullHwnd,
}

impl std::fmt::Display for OwnerWindowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ComInit(e) => write!(f, "COM init failed: {e}"),
            Self::RegisterClass(e) => write!(f, "RegisterClassExW failed: {e}"),
            Self::CreateWindow(e) => write!(f, "CreateWindowExW failed: {e}"),
            Self::NullHwnd => write!(f, "owner HWND is null"),
        }
    }
}

impl std::error::Error for OwnerWindowError {}

static CLASS_ATOM: OnceLock<u16> = OnceLock::new();

const CLASS_NAME: PCWSTR = w!("WormholeSurfaceLabOwner");

unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    // Do NOT PostQuitMessage on WM_DESTROY — lab smokes create multiple owner
    // windows on one thread; a leftover WM_QUIT cancels the next WebView2
    // environment create (TaskCanceled). Interactive loops call PostQuitMessage
    // explicitly from run_until_quit's close path via request_quit().
    if msg == WM_DESTROY {
        return LRESULT(0);
    }
    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}

fn ensure_class(hinstance: HINSTANCE) -> Result<u16, OwnerWindowError> {
    if let Some(atom) = CLASS_ATOM.get() {
        return Ok(*atom);
    }
    let atom = unsafe {
        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wnd_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinstance,
            hIcon: Default::default(),
            hCursor: LoadCursorW(None, IDC_ARROW).unwrap_or_default(),
            hbrBackground: HBRUSH(ptr::null_mut()),
            lpszMenuName: PCWSTR::null(),
            lpszClassName: CLASS_NAME,
            hIconSm: Default::default(),
        };
        let atom = RegisterClassExW(&wc);
        if atom == 0 {
            return Err(OwnerWindowError::RegisterClass(windows::core::Error::from_win32()));
        }
        atom
    };
    let _ = CLASS_ATOM.set(atom);
    Ok(atom)
}

/// Top-level owner HWND suitable as a wry `build_as_child` parent.
pub struct LabOwnerWindow {
    hwnd: HWND,
}

impl LabOwnerWindow {
    /// Create a visible overlapped window and initialize STA COM for WebView2.
    pub fn create(title: &str, width: i32, height: i32) -> Result<Self, OwnerWindowError> {
        // WebView2 controller creation is STA-affine.
        // CoInitializeEx returns HRESULT (S_OK / S_FALSE are success).
        let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
        if hr.is_err() {
            return Err(OwnerWindowError::ComInit(windows::core::Error::from(hr)));
        }

        let hinstance = unsafe { GetModuleHandleW(None) }
            .map_err(OwnerWindowError::CreateWindow)?;
        let _atom = ensure_class(hinstance.into())?;

        let mut title_wide: Vec<u16> = title.encode_utf16().collect();
        title_wide.push(0);

        let hwnd = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                CLASS_NAME,
                PCWSTR(title_wide.as_ptr()),
                WS_OVERLAPPEDWINDOW,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                width,
                height,
                None,
                None,
                Some(hinstance.into()),
                None,
            )
        }
        .map_err(OwnerWindowError::CreateWindow)?;

        if hwnd.0.is_null() {
            return Err(OwnerWindowError::NullHwnd);
        }

        unsafe {
            let _ = ShowWindow(hwnd, SW_SHOW);
        }

        Ok(Self { hwnd })
    }

    /// Broker owner identity.
    pub fn owner_hwnd(&self) -> OwnerHwnd {
        OwnerHwnd(self.hwnd.0 as isize)
    }

    /// Raw Win32 HWND.
    pub fn hwnd(&self) -> HWND {
        self.hwnd
    }

    /// Client area size in physical pixels.
    pub fn client_size(&self) -> (u32, u32) {
        let mut rect = RECT::default();
        unsafe {
            let _ = GetClientRect(self.hwnd, &mut rect);
        }
        (
            (rect.right - rect.left).max(0) as u32,
            (rect.bottom - rect.top).max(0) as u32,
        )
    }

    /// Pump the Win32 queue until empty (non-blocking). Needed for WebView2 callbacks.
    pub fn pump_once(&self) {
        let mut msg = MSG::default();
        unsafe {
            while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                if msg.message == WM_DESTROY {
                    break;
                }
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }

    /// Blocking pump until `WM_QUIT` (interactive lab).
    ///
    /// Call [`Self::request_quit`] from a close button handler, or destroy the
    /// window after posting quit yourself. For the lab, set
    /// `SURFACE_LAB_INTERACTIVE` and close via Alt+F4 after posting quit:
    pub fn run_until_quit(&self) {
        // Subclass-free: treat WM_CLOSE by posting quit so GetMessage exits.
        let mut msg = MSG::default();
        unsafe {
            while GetMessageW(&mut msg, None, 0, 0).into() {
                if msg.message == WM_CLOSE {
                    let _ = DestroyWindow(self.hwnd);
                    PostQuitMessage(0);
                    continue;
                }
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }

    /// Post `WM_QUIT` so [`Self::run_until_quit`] returns.
    pub fn request_quit(&self) {
        unsafe {
            PostQuitMessage(0);
        }
    }

    /// Pump messages for approximately `millis`, processing WebView2 work.
    pub fn pump_for(&self, millis: u64) {
        let start = std::time::Instant::now();
        while start.elapsed().as_millis() < u128::from(millis) {
            self.pump_once();
            std::thread::sleep(std::time::Duration::from_millis(8));
        }
    }
}

impl Drop for LabOwnerWindow {
    fn drop(&mut self) {
        if !self.hwnd.0.is_null() {
            unsafe {
                let _ = DestroyWindow(self.hwnd);
            }
            self.hwnd = HWND(ptr::null_mut::<c_void>());
        }
    }
}
