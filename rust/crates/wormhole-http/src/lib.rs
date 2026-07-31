//! HTTP/HTTPS connection target types for Wormhole web sessions.
//!
//! Pure Rust port of `HttpConnectionTarget` / `BuildTargetAsync` from
//! `ViewModels/Sessions/HttpSessionViewModel.cs`, plus Fake-WebView
//! navigation-result → session-status glue (`nav_report`), non-extension
//! WebView2 profile isolation / wipe Fake glue (`profile_wipe`), and
//! new-window / popup policy Fake glue (`new_window`). Live WebView2 hosting
//! stays in `wormhole-surface-win`.
//!
//! See `docs/migration/10-http.md`.

mod bitwarden;
mod browser_args;
mod error;
mod nav_report;
mod new_window;
mod profile_wipe;
mod route;
mod target;
mod uri;

pub use bitwarden::{
    build_bitwarden_browser_arguments, build_context_folder_name, build_persistent_route_key,
    ensure_https_bitwarden_target, is_https_target, user_data_folder, user_data_folder_for_target,
    PERSISTENT_ROUTE_KEY_FILE_NAME,
};
pub use browser_args::{build_browser_arguments, HARDENING_BROWSER_ARGS};
pub use error::HttpError;
pub use nav_report::{
    apply_navigation_report, validate_navigate_uri, FakeWebViewSurface, HttpNavSession,
    HttpSessionNavStatus, NavigationOutcome,
};
pub use new_window::{
    build_bitwarden_popup_uri, decide_bitwarden_popup, decide_new_window_policy,
    get_in_session_navigation_uri, FakeNewWindowSurface, NewWindowPolicy,
};
pub use profile_wipe::{
    keyed_shared_folder_fingerprint_args, keyed_shared_folder_name, requires_isolated_web_profile,
    select_web_browser_profile_kind, select_web_browser_user_data_folder,
    select_web_browser_user_data_folder_for_target, stale_keyed_folder_names,
    target_requires_isolated_web_profile, web_browser_isolated_user_data,
    web_browser_shared_user_data, FakeWebBrowserProfileStore, WebBrowserProfileKind,
    WebBrowserWipeReport,
};
pub use route::{
    select_http_tunnel_route, FakeHttpTunnelRoute, HttpTunnelRoute, HttpTunnelRouteSource,
};
pub use target::{
    build_direct_target, build_forwarder_target, build_socks_target, effective_ignore_cert,
    resolve_cert_policy, HttpCertPolicy, HttpConnectionTarget, HttpScheme, Socks5Proxy,
    TunnelRouteHint,
};
pub use uri::{build_navigate_uri, validate_host};

/// Crate-level result alias.
pub type Result<T> = std::result::Result<T, HttpError>;
