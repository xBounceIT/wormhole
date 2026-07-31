//! Child WebView2 host via wry `build_as_child`.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use wry::{Rect, WebContext, WebView, WebViewBuilder, WebViewBuilderExtWindows, WebViewExtWindows};

use crate::bounds::{PhysicalBounds, SurfaceVisibility};
use crate::webview::assets;
use crate::webview::env::{try_remove_user_data_dir, unique_user_data_dir};
use crate::webview::hwnd::OwnerWindowHandle;
use crate::webview::ipc::{escape_js_string, IpcInbox};
use crate::{OwnerHwnd, Result, SurfaceError};

/// What to load into the new controller.
#[derive(Debug, Clone)]
pub enum WebViewNavigation {
    /// Navigate to a URL (`about:blank`, `https://…`, custom protocol, …).
    Url(String),
    /// Inline HTML document.
    Html(String),
}

impl WebViewNavigation {
    /// Minimal blank document (works without network / custom protocol).
    pub fn about_blank_html() -> Self {
        Self::Html(
            r#"<!doctype html><html><head><meta charset="utf-8"><title>blank</title></head>
<body style="margin:0;background:#1e1e1e;color:#ccc;font:14px sans-serif;">
<p style="padding:12px">wormhole-surface-win WebView2 child host</p>
</body></html>"#
                .into(),
        )
    }

    /// Echo / IPC smoke page (uses wry `window.ipc.postMessage`).
    ///
    /// Visible NOTE points at `scripts/Fetch-WebAssets.ps1` so interactive runs
    /// are not mistaken for a full xterm gate when vendor assets are missing.
    pub fn echo_stub_html() -> Self {
        Self::Html(
            r#"<!doctype html><html><head><meta charset="utf-8"><title>echo stub</title></head>
<body style="margin:0;background:#111;color:#eee;font:14px Consolas,monospace;">
<pre id="log">echo stub ready
NOTE: Assets/web vendor/xterm not staged — this is NOT the xterm.js bridge.
Stage with: powershell -NoProfile -File scripts\Fetch-WebAssets.ps1
See Assets/web/README.md</pre>
<script>
  function log(m) {
    var el = document.getElementById('log');
    el.textContent += '\n' + m;
  }
  window.addEventListener('DOMContentLoaded', function () {
    if (window.ipc && window.ipc.postMessage) {
      window.ipc.postMessage('ready');
    }
  });
  window.__wormholeHostMessage = function (msg) {
    log('host→web: ' + msg);
    if (window.ipc && window.ipc.postMessage) {
      window.ipc.postMessage('echo:' + msg);
    }
  };
</script>
</body></html>"#
                .into(),
        )
    }
}

/// Options for [`ChildWebViewHost::create`].
///
/// **Cert policy:** there is intentionally **no** `cert_policy` /
/// AlwaysAllow field. [`create`](ChildWebViewHost::create) leaves WebView2
/// default certificate validation. Production HTTPS hosts that need
/// [`wormhole_http::HttpCertPolicy::IgnoreErrors`] must subscribe
/// `ServerCertificateErrorDetected` themselves after mapping via
/// [`crate::webview::cert_policy_to_webview2_behavior`] (or leaf/target glue
/// [`crate::webview::http_ignore_cert_to_webview2_behavior`] /
/// [`crate::webview::target_cert_to_webview2_behavior`]) — never by stuffing
/// `--ignore-certificate-errors` into [`Self::additional_browser_args`].
/// Mapping helpers do **not** auto-subscribe COM.
pub struct WebViewCreateOptions {
    /// Owner HWND (parent for child controller).
    pub owner: OwnerHwnd,
    /// Initial bounds relative to owner client area (physical px).
    pub bounds: PhysicalBounds,
    /// Initial document.
    pub navigation: WebViewNavigation,
    /// Optional directory served at `http://wormhole.localhost/…` (Windows wry shape).
    pub custom_protocol_root: Option<PathBuf>,
    /// Invoked on UI thread when the page posts via wry IPC / `chrome.webview`.
    ///
    /// Callers that log must use [`crate::webview::summarize_ipc_for_log`] — never
    /// print raw terminal/clipboard frames.
    pub on_message: Option<Box<dyn Fn(String) + Send>>,
    /// Invoked when WebView2 reports `BrowserProcessExited` (controller must be recreated).
    pub on_browser_process_exited: Option<Box<dyn Fn() + Send>>,
    /// Extra Chromium/WebView2 args fixed at environment creation (proxy, hardening).
    ///
    /// Different args → different user-data folder (always unique here). Proxy /
    /// args that fingerprint the env must never share a folder with plain tabs.
    /// Do **not** use `--ignore-certificate-errors` here — that is a silent
    /// insecure global; C# parity is COM `AlwaysAllow` only when
    /// `HttpCertPolicy::IgnoreErrors` (not wired in this create path).
    pub additional_browser_args: Option<String>,
}

/// Live WebView2 child surface.
///
/// Field order matters:
/// 1. [`BrowserExitHook`] drops first (unhook while COM objects live),
/// 2. `webview` / `_context` tear down next,
/// 3. [`UserDataDirGuard`] cleans the user-data folder last.
pub struct ChildWebViewHost {
    /// `BrowserProcessExited` registration (Environment5); unhooks on drop.
    #[allow(dead_code)] // retained solely for Drop / lifetime
    browser_exit: Option<BrowserExitHook>,
    webview: WebView,
    /// Kept alive: wry ties the environment to this context.
    _context: WebContext,
    owner: OwnerHwnd,
    last_bounds: PhysicalBounds,
    /// Last visibility requested by the shell (layout / overlay policy).
    desired_visible: bool,
    /// Effective controller visibility after degenerate-bounds gating.
    visible: bool,
    /// Shared inbox for lab smokes (optional).
    inbox: Arc<Mutex<IpcInbox>>,
    /// Monotonic generation; bump when browser process exits so stale work is ignored.
    recreate_generation: Arc<std::sync::atomic::AtomicU64>,
    needs_recreate: Arc<AtomicBool>,
    /// Unique WebView2 user-data folder (cleaned best-effort after COM teardown).
    user_data_dir: UserDataDirGuard,
}

/// RAII cleanup for a WebView2 user-data directory (declared last on the host).
struct UserDataDirGuard(PathBuf);

impl Drop for UserDataDirGuard {
    fn drop(&mut self) {
        try_remove_user_data_dir(&self.0);
    }
}

struct BrowserExitHook {
    env5: webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2Environment5,
    token: i64,
}

impl Drop for BrowserExitHook {
    fn drop(&mut self) {
        unsafe {
            let _ = self.env5.remove_BrowserProcessExited(self.token);
        }
    }
}

impl ChildWebViewHost {
    /// Create a WebView2 controller as a **child** of `options.owner`.
    ///
    /// Requires the WebView2 Runtime. Failures map to [`SurfaceError::WebView`].
    ///
    /// Leaves default certificate validation: this path does **not** call
    /// [`crate::webview::cert_policy_to_webview2_behavior`],
    /// [`crate::webview::http_ignore_cert_to_webview2_behavior`], or
    /// [`crate::webview::target_cert_to_webview2_behavior`], and does **not**
    /// subscribe `ServerCertificateErrorDetected` (see [`WebViewCreateOptions`]).
    pub fn create(options: WebViewCreateOptions) -> Result<Self> {
        let handle = OwnerWindowHandle::new(options.owner).ok_or_else(|| {
            SurfaceError::WebView(
                "owner HWND is null — create a real Win32/GPUI window first".into(),
            )
        })?;

        let inbox: Arc<Mutex<IpcInbox>> = Arc::new(Mutex::new(IpcInbox::new()));
        let inbox_ipc = Arc::clone(&inbox);
        let user_cb = options.on_message;
        let exit_cb = options.on_browser_process_exited;

        // Unique user-data folder per host — WebView2 forbids sharing a UDF across
        // mismatched environment options / concurrent controllers. Always isolate
        // so proxy / ignore-cert policy cannot leak into shared tabs
        // (`args_require_isolated_udf` documents when shared envs would be illegal).
        let udf = unique_user_data_dir();
        let mut context = WebContext::new(Some(udf.clone()));
        let mut builder = WebViewBuilder::new_with_web_context(&mut context)
            .with_bounds(physical_to_rect(options.bounds))
            .with_ipc_handler(move |req: wry::http::Request<String>| {
                let body = req.body().clone();
                if let Ok(mut guard) = inbox_ipc.lock() {
                    guard.push(body.clone());
                }
                if let Some(ref cb) = user_cb {
                    cb(body);
                }
            });

        if let Some(args) = options.additional_browser_args.clone() {
            builder = builder.with_additional_browser_args(args);
        }

        if let Some(root) = options.custom_protocol_root.clone() {
            builder = builder.with_custom_protocol("wormhole".into(), move |_id, request| {
                // Virtual-host + path-safe serve (rejects evil hosts / `..` / abs paths).
                assets::serve_protocol_request(&root, &request)
            });
        }

        builder = match &options.navigation {
            WebViewNavigation::Url(url) => builder.with_url(url),
            WebViewNavigation::Html(html) => builder.with_html(html),
        };

        let webview = builder.build_as_child(&handle).map_err(map_wry_error)?;

        // Hook point — intentionally NOT wired here (lab ≠ production):
        // create leaves default cert validation for SSH/terminal/lab surfaces.
        // Production HTTP hosts with `HttpCertPolicy::IgnoreErrors` must
        // subscribe `ICoreWebView2::ServerCertificateErrorDetected` and set
        // action from `cert_policy_to_webview2_behavior` → AlwaysAllow **only**
        // for that policy (Default stays Default / no subscription).
        // Do not enable AlwaysAllow by default, and do not substitute Chromium
        // `--ignore-certificate-errors` in `additional_browser_args`.
        // When wiring COM, use an isolated UDF — AlwaysAllow is cached for the
        // environment lifetime (C# WebBrowserView).

        let needs_recreate = Arc::new(AtomicBool::new(false));
        let needs_flag = Arc::clone(&needs_recreate);
        let generation = Arc::new(std::sync::atomic::AtomicU64::new(1));
        let generation_hook = Arc::clone(&generation);
        let browser_exit = match attach_browser_process_exited(&webview, move || {
            needs_flag.store(true, Ordering::SeqCst);
            let _ = generation_hook.fetch_add(1, Ordering::SeqCst);
            if let Some(ref cb) = exit_cb {
                cb();
            }
        }) {
            Ok(hook) => Some(hook),
            Err(err) => {
                // Environment5 may be unavailable on ancient runtimes — host still works;
                // shell must treat missing hook as "no auto recreate signal".
                let _ = err;
                None
            }
        };

        let desired_visible = true;
        let effective_visible = desired_visible && !options.bounds.is_degenerate();
        if !effective_visible {
            webview
                .set_visible(false)
                .map_err(map_wry_error)?;
        }

        Ok(Self {
            browser_exit,
            webview,
            _context: context,
            owner: options.owner,
            last_bounds: options.bounds,
            desired_visible,
            visible: effective_visible,
            inbox,
            recreate_generation: generation,
            needs_recreate,
            user_data_dir: UserDataDirGuard(udf),
        })
    }

    /// Owner HWND this child was created under.
    pub fn owner(&self) -> OwnerHwnd {
        self.owner
    }

    /// Apply physical-pixel bounds (relative to parent client area).
    ///
    /// Degenerate bounds (0×N / N×0) hide the controller; a later non-degenerate
    /// update restores the last [`Self::set_visible`] intent without requiring a
    /// separate show call.
    pub fn set_bounds(&mut self, bounds: PhysicalBounds) -> Result<()> {
        if !bounds.is_degenerate() {
            self.webview
                .set_bounds(physical_to_rect(bounds))
                .map_err(map_wry_error)?;
        }
        self.last_bounds = bounds;
        self.sync_visibility()
    }

    /// Show or hide the child controller (airspace / tab background / chrome overlay).
    pub fn set_visible(&mut self, visibility: SurfaceVisibility) -> Result<()> {
        self.desired_visible = matches!(visibility, SurfaceVisibility::Visible);
        self.sync_visibility()
    }

    fn sync_visibility(&mut self) -> Result<()> {
        let effective = self.desired_visible && !self.last_bounds.is_degenerate();
        if effective != self.visible {
            self.webview
                .set_visible(effective)
                .map_err(map_wry_error)?;
            self.visible = effective;
        }
        Ok(())
    }

    /// Last bounds applied.
    pub fn last_bounds(&self) -> PhysicalBounds {
        self.last_bounds
    }

    /// Whether the controller is effectively shown (desired ∧ non-degenerate).
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Push keyboard focus into the WebView2 controller (wry `focus`).
    ///
    /// Prefer routing through [`crate::FocusBroker`] so GPUI/RDP owners stay consistent.
    pub fn request_focus(&self) -> Result<()> {
        self.webview.focus().map_err(map_wry_error)
    }

    /// Shell-requested visibility (ignores degenerate gating).
    pub fn desired_visible(&self) -> bool {
        self.desired_visible
    }

    /// Navigate to a URL.
    pub fn load_url(&self, url: &str) -> Result<()> {
        self.webview.load_url(url).map_err(map_wry_error)
    }

    /// Load inline HTML.
    pub fn load_html(&self, html: &str) -> Result<()> {
        self.webview.load_html(html).map_err(map_wry_error)
    }

    /// Host → web: evaluate JS (echo stub uses `window.__wormholeHostMessage`).
    pub fn evaluate_script(&self, js: &str) -> Result<()> {
        self.webview.evaluate_script(js).map_err(map_wry_error)
    }

    /// Post a host→page WebView2 string message.
    ///
    /// Uses `ICoreWebView2::PostWebMessageAsString` so `Assets/web/bridge.js`
    /// (`chrome.webview` message listeners) receives terminal bridge frames.
    /// Also invokes `window.__wormholeHostMessage` when present (echo stub).
    pub fn post_host_message(&self, msg: &str) -> Result<()> {
        use windows::core::HSTRING;

        let hmsg = HSTRING::from(msg);
        unsafe {
            self.webview
                .webview()
                .PostWebMessageAsString(&hmsg)
                .map_err(|e| SurfaceError::WebView(format!("PostWebMessageAsString failed: {e}")))?;
        }

        let lit = escape_js_string(msg);
        // Echo stub path — no-op on real terminal.html (helper undefined).
        let _ = self.evaluate_script(&format!(
            "window.__wormholeHostMessage && window.__wormholeHostMessage({lit})"
        ));
        Ok(())
    }

    /// Drain IPC messages received so far (lab / tests).
    pub fn drain_messages(&self) -> Vec<String> {
        self.inbox
            .lock()
            .map(|mut g| g.drain())
            .unwrap_or_default()
    }

    /// Count of IPC messages dropped for size/backpressure (lab / tests).
    pub fn ipc_dropped_count(&self) -> u64 {
        self.inbox
            .lock()
            .map(|g| g.dropped_count())
            .unwrap_or(0)
    }

    /// True when `BrowserProcessExited` fired — dispose and recreate the host.
    pub fn needs_recreate(&self) -> bool {
        self.needs_recreate.load(Ordering::SeqCst)
    }

    /// Current recreate generation (stale async work should compare tokens).
    pub fn recreate_generation(&self) -> u64 {
        self.recreate_generation.load(Ordering::SeqCst)
    }

    /// User-data folder for this host (unique; do not share across env fingerprints).
    pub fn user_data_dir(&self) -> &Path {
        &self.user_data_dir.0
    }

    /// Resolve `Assets/web` relative to common repo layouts (cwd / ancestors).
    ///
    /// Requires the directory to end with `Assets/web` (case-insensitive) so a
    /// hostile cwd cannot satisfy the probe with an unrelated `terminal.html`.
    pub fn find_assets_web() -> Option<PathBuf> {
        let candidates = [
            PathBuf::from("Assets/web"),
            PathBuf::from("../Assets/web"),
            PathBuf::from("../../Assets/web"),
            PathBuf::from("../../../Assets/web"),
        ];
        for c in candidates {
            if Self::assets_web_ready(&c) && assets::is_assets_web_layout(&c) {
                return c.canonicalize().ok().or(Some(c));
            }
        }
        None
    }

    /// True when `terminal.html` exists under `root` (vendor/xterm may still be missing).
    pub fn assets_web_ready(root: &Path) -> bool {
        root.join("terminal.html").is_file()
    }

    /// True when xterm vendor bundle is present (full gate-5 UI).
    pub fn xterm_vendor_ready(root: &Path) -> bool {
        root.join("vendor/xterm/xterm.js").is_file()
            && root.join("vendor/xterm/xterm.css").is_file()
            && root.join("vendor/addon-fit/addon-fit.js").is_file()
            && root.join("bridge.js").is_file()
            && root.join("terminal.html").is_file()
    }
}

fn attach_browser_process_exited(
    webview: &WebView,
    on_exit: impl Fn() + Send + 'static,
) -> std::result::Result<BrowserExitHook, String> {
    use windows::core::Interface;
    use webview2_com::BrowserProcessExitedEventHandler;
    use webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2Environment5;

    let env = webview.environment();
    let env5: ICoreWebView2Environment5 = env
        .cast()
        .map_err(|e| format!("ICoreWebView2Environment5 cast failed: {e}"))?;

    let mut token: i64 = 0;
    let handler = BrowserProcessExitedEventHandler::create(Box::new(move |_env, _args| {
        on_exit();
        Ok(())
    }));
    unsafe {
        env5
            .add_BrowserProcessExited(&handler, &mut token)
            .map_err(|e| format!("add_BrowserProcessExited failed: {e}"))?;
    }
    Ok(BrowserExitHook { env5, token })
}

fn physical_to_rect(bounds: PhysicalBounds) -> Rect {
    Rect {
        position: wry::dpi::PhysicalPosition::new(bounds.x, bounds.y).into(),
        size: wry::dpi::PhysicalSize::new(bounds.width, bounds.height).into(),
    }
}

fn map_wry_error(err: wry::Error) -> SurfaceError {
    let msg = err.to_string();
    let lower = msg.to_lowercase();
    let is_runtime = match &err {
        wry::Error::WebView2Error(_) => {
            lower.contains("not installed")
                || lower.contains("0x80070002")
                || lower.contains("could not find")
                || lower.contains("webview2 loader")
                || lower.contains("failed to create environment")
        }
        _ => {
            lower.contains("not installed")
                || lower.contains("0x80070002")
                || lower.contains("webview2 loader")
        }
    };
    if is_runtime {
        SurfaceError::WebViewRuntimeMissing(msg)
    } else {
        SurfaceError::WebView(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_to_rect_maps_axes() {
        let r = physical_to_rect(PhysicalBounds {
            x: 10,
            y: -2,
            width: 800,
            height: 600,
            dpi: 144,
        });
        assert_eq!(r.position.to_physical::<i32>(1.0).x, 10);
        assert_eq!(r.position.to_physical::<i32>(1.0).y, -2);
        assert_eq!(r.size.to_physical::<u32>(1.0).width, 800);
        assert_eq!(r.size.to_physical::<u32>(1.0).height, 600);
    }

    #[test]
    fn visibility_contract_desired_and_degenerate() {
        // Pure logic mirror of sync_visibility (no Runtime).
        let desired = true;
        let degenerate = PhysicalBounds {
            x: 0,
            y: 0,
            width: 0,
            height: 40,
            dpi: 96,
        };
        assert!(degenerate.is_degenerate());
        assert!(!(desired && !degenerate.is_degenerate()));

        let ok = PhysicalBounds {
            x: 0,
            y: 0,
            width: 8,
            height: 8,
            dpi: 96,
        };
        assert!(desired && !ok.is_degenerate());
    }
}
