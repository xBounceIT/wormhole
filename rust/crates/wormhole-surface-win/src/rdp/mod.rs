//! RDP ActiveX owned-overlay surface for the native broker.
//!
//! # Architecture (mandatory)
//!
//! RDP is an **owned top-level overlay** (`GWLP_HWNDPARENT` + `WS_EX_TOOLWINDOW`),
//! **not** `SetParent` / `WS_CHILD`. See `docs/migration/native-surface-broker.md`
//! and `docs/migration/05-rdp-spike.md`.
//!
//! # Features
//!
//! - [`HostBounds`], [`RdpCrashSentinel`], [`ResolutionDebouncer`], and
//!   [`RdpResolutionLayoutGlue`] / [`FakeRdpResizeSurface`] always compile
//!   (no `mstscax`).
//! - `--features rdp`: owned overlay + OLE in-place MsRdpClient + CredSSP configure
//!   + tunnel policy validation + BindLocalForwarder dial-target stub + event sink stub
//!   + CredSSP password-wipe ↔ connect-attempt Fake glue (no live OCX).

mod host_bounds;
mod resize_glue;
mod resolution;
mod sentinel;

pub use host_bounds::HostBounds;
pub use resize_glue::{
    desktop_size_from_layout_f64, FakeRdpResizeSurface, RdpResolutionLayoutGlue,
    LAYOUT_RESOLUTION_MIN_DIM,
};
pub use resolution::{
    ApplyDesktopSize, DesktopSize, MonoTime, ResolutionDebouncer, RESOLUTION_DEBOUNCE_DEFAULT,
};
pub use sentinel::{RdpCrashRecord, RdpCrashSentinel, SENTINEL_FILE_NAME};

#[cfg(all(windows, feature = "rdp"))]
mod clsid;
#[cfg(all(windows, feature = "rdp"))]
mod configure;
#[cfg(all(windows, feature = "rdp"))]
mod credssp_connect_glue;
#[cfg(all(windows, feature = "rdp"))]
mod dispatch;
#[cfg(all(windows, feature = "rdp"))]
mod events;
#[cfg(all(windows, feature = "rdp"))]
mod host;
#[cfg(all(windows, feature = "rdp"))]
mod ocx;
#[cfg(all(windows, feature = "rdp"))]
mod overlay;
#[cfg(all(windows, feature = "rdp"))]
mod site;
#[cfg(all(windows, feature = "rdp"))]
mod target;

#[cfg(all(windows, feature = "rdp"))]
pub use clsid::{probe_registered_classes, select_best_rdp_class, RdpActiveXClass};
#[cfg(all(windows, feature = "rdp"))]
pub use configure::{
    normalise_color_depth, validate_rdp_configure_options, validate_rdp_gateway_tunnel_combo,
    validate_tunnel_rdp_policy, ConfigureReport, RdpConfigureOptions, TunnelRdpConflict,
    TunnelRdpPolicy, CREDSSP_SOFT_MISS_NLA_RISK, MAX_DESKTOP_AXIS, MAX_DOMAIN_CHARS,
    MAX_PASSWORD_CHARS, MAX_SERVER_CHARS, MAX_USERNAME_CHARS, NEGOTIATE_SOFT_MISS,
    TUNNEL_EXTERNAL_CLIENT_UNSUPPORTED, TUNNEL_GATEWAY_UNSUPPORTED,
    TUNNEL_STRICT_SERVER_AUTH_UNSUPPORTED,
};
#[cfg(all(windows, feature = "rdp"))]
pub use credssp_connect_glue::{
    CredSspConnectGlueError, FakeRdpCredSspSurface, RdpCredSspConnectAttempt,
    RdpCredSspConnectGlue,
};
#[cfg(all(windows, feature = "rdp"))]
pub use events::RdpEventState;
#[cfg(all(windows, feature = "rdp"))]
pub use host::{RdpOverlayHost, RdpOverlayInfo};
#[cfg(all(windows, feature = "rdp"))]
pub use ocx::{
    pump_messages, rdp_fail, run_on_sta, ConnectStubOptions, InPlaceActivateInfo, RdpOcx,
};
#[cfg(all(windows, feature = "rdp"))]
pub use target::{
    forwarder_socket_addr, prepare_rdp_connect_target, reject_rdp_socks_only_path,
    select_rdp_connect_target, FakeForwarderBind, FakeTunnelForwarder, RdpConnectTarget,
    RdpConnectTargetError, RdpConnectTargetResult, TunnelLocalForwarderSource,
};
