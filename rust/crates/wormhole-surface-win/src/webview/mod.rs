//! WebView2 child HWND hosting (feature `webview`).
//!
//! Uses **wry 0.56** `build_as_child` — not `gpui-wry` / `lb-wry`. Parent is a
//! real owner HWND; bounds are physical pixels via [`crate::PhysicalBounds`].
//!
//! Each [`ChildWebViewHost`] gets a **unique** user-data folder so proxy /
//! ignore-cert environment fingerprints cannot leak across tabs.
//!
//! [`cert_policy_to_webview2_behavior`] maps
//! `HttpCertPolicy::Default` → [`WebView2CertErrorAction::Default`] and
//! `HttpCertPolicy::IgnoreErrors` → [`WebView2CertErrorAction::AlwaysAllow`]
//! only. Leaf profile glue
//! ([`http_ignore_cert_to_webview2_behavior`] /
//! [`target_cert_to_webview2_behavior`]) chains scheme +
//! `HttpIgnoreCertErrors` (or a built target) through that adapter and
//! **fail-closes** unless HTTPS ∧ leaf true. Pure mapping only — surface-lab /
//! [`ChildWebViewHost::create`] do **not** subscribe
//! `ServerCertificateErrorDetected` (**lab ≠ production:** AlwaysAllow not
//! applied in create/lab).

mod assets;
mod cert_policy;
mod env;
mod host;
mod hwnd;
mod ipc;
mod owner;

pub use cert_policy::{
    cert_policy_to_webview2_behavior, http_ignore_cert_to_webview2_behavior,
    target_cert_to_webview2_behavior, WebView2CertErrorAction,
};
pub use host::{ChildWebViewHost, WebViewCreateOptions, WebViewNavigation};
pub use hwnd::OwnerWindowHandle;
pub use ipc::{escape_js_string, summarize_ipc_for_log, IpcInbox, IPC_INBOX_CAP, IPC_MAX_MESSAGE_BYTES};
pub use owner::{LabOwnerWindow, OwnerWindowError};

#[doc(inline)]
pub use assets::{
    is_assets_web_layout, is_wormhole_virtual_host, normalize_protocol_path, WORMHOLE_VIRTUAL_HOST,
};
#[doc(inline)]
pub use env::{args_require_isolated_udf, unique_user_data_dir};
