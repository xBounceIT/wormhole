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
//!   (no `mstscax`); so does [`normalise_drive_list`] / [`parse_drive_letters`] /
//!   [`validate_drive_list`] + [`DriveLetters`] (pure `RdpDriveList` port, no COM).
//! - `--features rdp`: owned overlay + OLE in-place MsRdpClient + CredSSP configure
//!   + tunnel policy validation + BindLocalForwarder dial-target stub + event sink stub
//!   + CredSSP password-wipe ↔ connect-attempt Fake glue (no live OCX)
//!   + ConnectionProfile display/redirect → Fake configure glue (no live OCX)
//!   + ConnectionProfile performance flags / bitmap cache → Fake configure glue (no live OCX)
//!   + External mstsc.exe + tunnel reject → Fake policy glue (no Process::Command)
//!   + Azure AD / external-client routing → Fake detection glue (no live WAM/AAD).

mod drive_list;
mod host_bounds;
mod resize_glue;
mod resolution;
mod sentinel;

pub use drive_list::{
    normalise_drive_list, parse_drive_letters, validate_drive_list, DriveLetters,
    RdpDriveListError, RdpDriveListErrorKind, DRIVE_LIST_ALL_SENTINEL,
};
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
mod display_redirect_glue;
#[cfg(all(windows, feature = "rdp"))]
mod performance_flags_glue;
#[cfg(all(windows, feature = "rdp"))]
mod aad_external_client_glue;
#[cfg(all(windows, feature = "rdp"))]
mod external_mstsc_glue;
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
pub use display_redirect_glue::{
    parse_redirect_drives, parse_redirect_drives_canonical, resolve_connect_desktop_size,
    validate_desktop_axes, DesktopSizeContext, DisplayRedirectGlueError, DisplayRedirectReport,
    FakePropOutcome, FakePropPut, FakePropRecord, FakeRdpPropertySurface, RdpDisplayRedirectGlue,
    RedirectDrivesIntent, DESKTOP_DEFAULT_HEIGHT, DESKTOP_DEFAULT_WIDTH, DESKTOP_MIN_HEIGHT,
    DESKTOP_MIN_WIDTH, LOUD_DISPLAY_PROPS, REDIRECT_DRIVES_ALL, SOFT_DISPLAY_REDIRECT_PROPS,
};
#[cfg(all(windows, feature = "rdp"))]
pub use aad_external_client_glue::{
    decide_rdp_client_routing, has_azure_ad_domain, has_azure_ad_prefix,
    is_azure_ad_credential, is_azure_ad_profile, resolve_rdp_routing, FakeAadRoutingSurface,
    FakeCredentialLookup, FakeRdpCredentialCatalog, RdpAadExternalClientGlue, RdpAadSignal,
    RdpClientRouting, RdpConnectRouteOutcome, RdpRoutingResolution, ScriptedRdpCredential,
    AZURE_AD_DOMAIN, AZURE_AD_USERNAME_PREFIX,
};
#[cfg(all(windows, feature = "rdp"))]
pub use external_mstsc_glue::{
    decide_external_mstsc_tunnel, external_decision_matches_tunnel_policy,
    validate_external_mstsc_tunnel, ExternalMstscGlueError, ExternalMstscPolicyInputs,
    ExternalMstscTunnelDecision, FakeExternalMstscSurface, RdpExternalMstscGlue,
};
#[cfg(all(windows, feature = "rdp"))]
pub use performance_flags_glue::{
    build_performance_flags, FakePerfPropOutcome, FakePerfPropPut, FakePerfPropRecord,
    FakeRdpPerformanceSurface, PerformanceFlagsGlueError, PerformanceFlagsReport,
    RdpPerformanceFlagsGlue, SOFT_PERFORMANCE_PROPS, TS_PERF_DISABLE_CURSORSETTINGS,
    TS_PERF_DISABLE_CURSOR_SHADOW, TS_PERF_DISABLE_FULLWINDOWDRAG, TS_PERF_DISABLE_MENUANIMATIONS,
    TS_PERF_DISABLE_THEMING, TS_PERF_DISABLE_WALLPAPER, TS_PERF_ENABLE_DESKTOP_COMPOSITION,
    TS_PERF_ENABLE_FONT_SMOOTHING, TS_PERF_VISUAL_STYLES_OFF_MASK,
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
