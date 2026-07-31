//! Focus HWND identity + pluggable SetFocus/GetFocus ops (mockable in tests).

/// HWND as `isize` (same convention as [`crate::OwnerHwnd`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FocusHwnd(pub isize);

impl FocusHwnd {
    /// True when the handle is null (`0`) — must never be passed to `SetFocus`.
    pub fn is_null(self) -> bool {
        self.0 == 0
    }
}

impl std::fmt::Display for FocusHwnd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#x}", self.0 as usize)
    }
}

/// Errors from focus helpers / broker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FocusError {
    /// Caller attempted `SetFocus(NULL)` — rejected before any Win32 call.
    NullHwndRejected,
    /// Win32 `SetFocus` failed (`NULL` return + nonzero `GetLastError`).
    SetFocusFailed {
        /// Target HWND that was requested.
        hwnd: FocusHwnd,
        /// Win32 error code.
        code: u32,
    },
    /// Platform is not Windows.
    UnsupportedPlatform,
    /// Other diagnostic message (lab / host path).
    Message(String),
}

impl std::fmt::Display for FocusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NullHwndRejected => {
                write!(f, "SetFocus(NULL) rejected — would detach keyboard focus")
            }
            Self::SetFocusFailed { hwnd, code } => {
                write!(f, "SetFocus({hwnd}) failed with Win32 error {code:#x}")
            }
            Self::UnsupportedPlatform => write!(f, "focus helpers require Windows"),
            Self::Message(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for FocusError {}

/// Pluggable focus primitives — real Win32 or an in-memory recorder for tests.
pub trait FocusOps {
    /// Push keyboard focus to `hwnd`. Must reject null before any native call.
    fn set_focus(&mut self, hwnd: FocusHwnd) -> Result<Option<FocusHwnd>, FocusError>;

    /// Current thread focus HWND, if any.
    fn get_focus(&mut self) -> Result<Option<FocusHwnd>, FocusError>;
}

/// Records SetFocus/GetFocus calls without touching Win32 (unit tests / default lab).
#[derive(Debug, Default)]
pub struct RecordingFocusOps {
    /// Chronological SetFocus targets (never includes null — rejected).
    pub set_calls: Vec<FocusHwnd>,
    /// Simulated current focus.
    pub current: Option<FocusHwnd>,
    /// When true, next `set_focus` returns [`FocusError::SetFocusFailed`].
    pub fail_next: bool,
}

impl RecordingFocusOps {
    /// Empty recorder.
    pub fn new() -> Self {
        Self::default()
    }
}

impl FocusOps for RecordingFocusOps {
    fn set_focus(&mut self, hwnd: FocusHwnd) -> Result<Option<FocusHwnd>, FocusError> {
        if hwnd.is_null() {
            return Err(FocusError::NullHwndRejected);
        }
        if self.fail_next {
            self.fail_next = false;
            return Err(FocusError::SetFocusFailed { hwnd, code: 5 });
        }
        let previous = self.current;
        self.set_calls.push(hwnd);
        self.current = Some(hwnd);
        Ok(previous)
    }

    fn get_focus(&mut self) -> Result<Option<FocusHwnd>, FocusError> {
        Ok(self.current)
    }
}
