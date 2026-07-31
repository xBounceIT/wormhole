//! Native HWND surface broker for Wormhole's GPUI migration.
//!
//! # Role
//!
//! GPUI (and later the main shell) owns chrome, layout, and non-HWND UI.
//! Protocol surfaces that must live as real HWNDs — **WebView2** (in-tree /
//! child composition) and **RDP ActiveX (`MsRdpClient9`)** (owned top-level
//! overlay via `GWLP_HWNDPARENT`, **not** `SetParent`/`WS_CHILD`) — are
//! registered here and positioned each layout tick in **physical pixels**.
//! See `docs/migration/native-surface-broker.md`.
//!
//! # Features
//!
//! - Default: API skeleton + stub broker + [`focus::FocusBroker`] (no WebView2 / COM graph).
//! - `webview`: wry 0.56 child WebView2 host ([`webview::ChildWebViewHost`]).
//!   Do **not** use `gpui-wry` for production SSH/HTTP surfaces.
//!   Includes pure [`webview::cert_policy_to_webview2_behavior`] plus leaf/target
//!   glue ([`webview::http_ignore_cert_to_webview2_behavior`] /
//!   [`webview::target_cert_to_webview2_behavior`]) —
//!   `HttpCertPolicy::Default` → validate; `IgnoreErrors` → AlwaysAllow only;
//!   fail-closed unless HTTPS ∧ profile `HttpIgnoreCertErrors`.
//!   COM `ServerCertificateErrorDetected` is **not** subscribed in lab/create.
//! - `rdp`: owned-overlay ActiveX + OLE in-place + CredSSP configure (`GWLP_HWNDPARENT`, not SetParent)
//!   + CredSSP password-wipe ↔ connect Fake glue
//!   + ConnectionProfile display/redirect → Fake configure glue (TrySet soft-skip; no live OCX)
//!   + ConnectionProfile performance flags / bitmap cache → Fake configure glue (TrySet soft-skip; no live OCX)
//!   + External mstsc.exe + tunnel reject → Fake policy glue (no Process::Command)
//!   + Azure AD / external-client routing → Fake detection glue (no live WAM/AAD).
//! - `pane-layout`: [`pane_layout::BrokerPaneLayoutSink`] — maps `wormhole_ui` pane
//!   layout ticks to [`NativeSurfaceBroker::update_bounds`]; plus
//!   [`pane_focus`] helpers that activate/cycle workspace panes, sync
//!   [`FocusCycle`] to bindings, and emit [`FocusRequest`]s when the broker
//!   target changes (no GPUI chrome); plus [`session_surface`] open/close ↔
//!   bind/unbind Fake dispose (no live HWND); plus [`pane_split`] split/merge →
//!   layout-tick notify against the Fake sink (no GPUI chrome).

#![cfg_attr(not(windows), allow(dead_code))]
#![deny(missing_docs)]

mod bounds;
mod broker;
mod kinds;
mod zorder;

#[cfg(feature = "pane-layout")]
pub mod pane_layout;

/// Pane focus glue (`WorkspaceState` ↔ [`FocusCycle`]) — `--features pane-layout`.
#[cfg(feature = "pane-layout")]
pub mod pane_focus;

/// Session open/close ↔ Fake broker bind/unbind — `--features pane-layout`.
#[cfg(feature = "pane-layout")]
pub mod session_surface;

/// Pane split/merge → Fake broker layout-tick notify — `--features pane-layout`.
#[cfg(feature = "pane-layout")]
pub mod pane_split;

/// Focus handoff (GPUI ↔ WebView2 ↔ RDP) — gate 7.
pub mod focus;

/// RDP ActiveX owned-overlay helpers (sentinel always; COM host behind `rdp`).
pub mod rdp;

#[cfg(all(windows, feature = "webview"))]
pub mod webview;

pub use bounds::{PhysicalBounds, SurfaceVisibility, ZOrderHint};
pub use broker::{
    NativeSurfaceBroker, OwnerHwnd, StubNativeSurfaceBroker, SurfaceHandle, SurfaceId,
    SurfaceLayoutUpdate,
};
pub use focus::{
    FocusAction, FocusBroker, FocusCycle, FocusCycleDirection, FocusCycleError, FocusCycleSlot,
    FocusError, FocusHwnd, FocusOps, FocusOwner, FocusReason, FocusRequest, RdpConnectKind,
    RecordingFocusOps,
};
pub use kinds::SurfaceKind;
pub use zorder::{OverlayStackController, OverlayStackPolicy};

#[cfg(feature = "pane-layout")]
pub use pane_layout::{
    pane_bounds_to_physical, visibility_for_pane_bounds, BrokerPaneLayoutSink,
};

#[cfg(feature = "pane-layout")]
pub use pane_focus::{
    activate_pane, activate_pane_bound, cycle_pane_focus, cycle_pane_focus_bound, PaneFocusError,
    PaneFocusNotify,
};

#[cfg(feature = "pane-layout")]
pub use session_surface::{
    close_session_surface, open_session_surface, session_surface, FakeNativeSurfaceBroker,
    SessionSurfaceBinding, SessionSurfaceError, SessionSurfaceRegistry,
};

#[cfg(feature = "pane-layout")]
pub use pane_split::{
    merge_and_notify, merge_and_notify_bound, notify_bound_layout, split_and_notify,
    split_and_notify_bound, split_focused_and_notify, split_with_and_notify,
};

#[cfg(windows)]
pub use focus::{get_focus, set_focus, Win32FocusOps};

/// Crate-level result alias (no rich error taxonomy yet).
pub type Result<T> = std::result::Result<T, SurfaceError>;

/// Errors returned by the broker / native hosts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SurfaceError {
    /// Surface id was never registered (or already unregistered).
    UnknownSurface(SurfaceId),
    /// Kind is not supported by this broker build.
    UnsupportedKind(SurfaceKind),
    /// Platform is not Windows — broker is a no-op stub elsewhere.
    UnsupportedPlatform,
    /// Placeholder for unfinished paths.
    NotImplemented(&'static str),
    /// WebView2 Runtime appears missing or failed to bootstrap.
    WebViewRuntimeMissing(String),
    /// Other WebView2 / wry failure.
    WebView(String),
    /// Focus handoff failure (null HWND rejected, SetFocus error, …).
    Focus(FocusError),
}

impl std::fmt::Display for SurfaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownSurface(id) => write!(f, "unknown surface id {id}"),
            Self::UnsupportedKind(kind) => write!(f, "unsupported surface kind {kind:?}"),
            Self::UnsupportedPlatform => write!(f, "native surface broker requires Windows"),
            Self::NotImplemented(what) => write!(f, "not implemented: {what}"),
            Self::WebViewRuntimeMissing(msg) => {
                write!(
                    f,
                    "WebView2 Runtime missing or failed to start ({msg}). \
                     Install the Evergreen Runtime from Microsoft and retry."
                )
            }
            Self::WebView(msg) => write!(f, "WebView2 error: {msg}"),
            Self::Focus(err) => write!(f, "focus error: {err}"),
        }
    }
}

impl From<FocusError> for SurfaceError {
    fn from(value: FocusError) -> Self {
        Self::Focus(value)
    }
}

impl std::error::Error for SurfaceError {}
