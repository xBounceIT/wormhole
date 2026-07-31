//! Focus handoff among GPUI chrome, WebView2 children, and RDP overlay HWNDs.
//!
//! Mirrors C# rules from `RdpHostForm.RequestFocus` / `RdpSurfaceHost` `_focusPushed`:
//! - **Never** call `SetFocus(NULL)` — that detaches keyboard focus from the thread.
//! - RDP cold connect / Retry: one-shot focus push onto the **AxHost child** HWND.
//! - RDP `AutoReconnected`: do **not** steal focus (skipped by connect kind; latch is
//!   separate and only gates duplicate cold/Retry within one lifecycle).
//! - Latch clears only on terminal `Disconnected` / `Failed`, not transient Connecting.
//!
//! # Cold-connect focus order
//!
//! 1. Shell may programmatically focus the chrome slot (GPUI / former WinUI host).
//! 2. Win32 `SetFocus` on the RDP **AxHost child** HWND (never the overlay form alone;
//!    never a null HWND).
//! 3. Latch `rdp_focus_pushed` so a later ColdOrRetry in this lifecycle skips step 2.
//!    AutoReconnected is skipped by [`RdpConnectKind`], not by the latch.
//!
//! # Focus cycle (Tab / Shift-Tab stub)
//!
//! [`FocusCycle`] orders the GPUI chrome sentinel plus registered
//! [`crate::SurfaceHandle`]s and builds [`FocusRequest`]s for
//! [`FocusBroker::request_focus`] — it does not call Win32 or bypass broker
//! policy. Independent of the pane-layout sink.
//!
//! Workspace **pane** activate / cycle (which slot is focused among ≤4 panes)
//! is a separate `pane_focus` module behind `--features pane-layout`: it updates
//! `WorkspaceState`, syncs [`FocusCycle`] to the pane binding (surface or chrome
//! when unbound), and emits a [`FocusRequest`] when the broker target changes —
//! still no Win32 / no GPUI chrome.
//!
//! WebView2 handoff uses wry `WebView::focus` (or `SetFocus` on the child HWND when
//! known). GPUI chrome is tracked as an owner without requiring a native HWND.

mod broker;
mod cycle;
mod ops;
#[cfg(windows)]
mod win32;

pub use broker::{
    FocusAction, FocusBroker, FocusOwner, FocusReason, FocusRequest, RdpConnectKind,
};
pub use cycle::{FocusCycle, FocusCycleDirection, FocusCycleError, FocusCycleSlot};
pub use ops::{FocusError, FocusHwnd, FocusOps, RecordingFocusOps};

#[cfg(windows)]
pub use win32::{get_focus, set_focus, Win32FocusOps};
