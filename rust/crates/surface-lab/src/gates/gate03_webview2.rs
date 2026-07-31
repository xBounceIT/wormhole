//! Gate 3 — WebView2 hosted inside a movable/resizable pane (**kill switch**).
//!
//! With `--features webview`, creates a minimal Win32 owner HWND and a wry
//! child WebView2 navigating inline blank HTML (or `about:blank` fallback).

use super::GateStatus;

/// Current lab status for this gate.
pub const STATUS: GateStatus = {
    #[cfg(all(windows, feature = "webview"))]
    {
        GateStatus::Partial
    }
    #[cfg(not(all(windows, feature = "webview")))]
    {
        GateStatus::Blocked("enable `--features webview` (wry child host)")
    }
};

/// Short TODO note for the gate map.
pub const NOTE: &str =
    "Win32 owner + wry build_as_child; bounds/show-hide; Runtime may be required";

/// Run the gate-3 smoke (no-op / message when feature off).
pub fn run_smoke() {
    #[cfg(all(windows, feature = "webview"))]
    {
        match run_webview_smoke() {
            Ok(msg) => println!("[gate3] {msg}"),
            Err(err) => println!("[gate3] blocked/failed: {err}"),
        }
    }
    #[cfg(not(all(windows, feature = "webview")))]
    {
        println!(
            "[gate3] skipped — rebuild with `cargo run -p surface-lab --features webview`"
        );
    }
}

#[cfg(all(windows, feature = "webview"))]
fn run_webview_smoke() -> Result<String, String> {
    use wormhole_surface_win::webview::{
        ChildWebViewHost, LabOwnerWindow, WebViewCreateOptions, WebViewNavigation,
    };
    use wormhole_surface_win::{
        NativeSurfaceBroker, PhysicalBounds, StubNativeSurfaceBroker, SurfaceKind,
        SurfaceLayoutUpdate, SurfaceVisibility, ZOrderHint,
    };

    let owner_win = LabOwnerWindow::create("surface-lab gate3 WebView2", 960, 640)
        .map_err(|e| e.to_string())?;
    let (cw, ch) = owner_win.client_size();
    let bounds = PhysicalBounds {
        x: 0,
        y: 0,
        width: cw.max(1),
        height: ch.max(1),
        dpi: 96,
    };

    let mut broker = StubNativeSurfaceBroker::new();
    let handle = broker
        .register(owner_win.owner_hwnd(), SurfaceKind::WebView2)
        .map_err(|e| e.to_string())?;

    let mut host = ChildWebViewHost::create(WebViewCreateOptions {
        owner: owner_win.owner_hwnd(),
        bounds,
        navigation: WebViewNavigation::about_blank_html(),
        custom_protocol_root: None,
        on_message: None,
        on_browser_process_exited: None,
        additional_browser_args: None,
    })
    .map_err(|e| e.to_string())?;

    // Exercise bounds + visibility like a layout tick.
    let shrunk = PhysicalBounds {
        x: 8,
        y: 8,
        width: bounds.width.saturating_sub(16).max(1),
        height: bounds.height.saturating_sub(16).max(1),
        dpi: 96,
    };
    host.set_bounds(shrunk).map_err(|e| e.to_string())?;
    broker
        .update_bounds(
            handle.id,
            SurfaceLayoutUpdate {
                bounds: shrunk,
                visibility: SurfaceVisibility::Visible,
                z_order: ZOrderHint::Unchanged,
            },
        )
        .map_err(|e| e.to_string())?;

    // Degenerate → hide; restore non-degenerate → show again (desired_visible stays true).
    host.set_bounds(PhysicalBounds {
        x: 0,
        y: 0,
        width: 0,
        height: 40,
        dpi: 96,
    })
    .map_err(|e| e.to_string())?;
    if host.is_visible() {
        return Err("degenerate bounds must hide webview".into());
    }
    host.set_bounds(shrunk).map_err(|e| e.to_string())?;
    if !host.is_visible() {
        return Err("non-degenerate bounds must restore desired visibility".into());
    }

    host.set_visible(SurfaceVisibility::Hidden)
        .map_err(|e| e.to_string())?;
    host.set_visible(SurfaceVisibility::Visible)
        .map_err(|e| e.to_string())?;

    owner_win.pump_for(400);

    if std::env::var_os("SURFACE_LAB_INTERACTIVE").is_some() {
        println!("[gate3] SURFACE_LAB_INTERACTIVE set — close the window to continue");
        owner_win.run_until_quit();
    }

    Ok(format!(
        "child WebView2 ok (surface id={}, client={}x{}, udf unique, wry build_as_child)",
        handle.id,
        shrunk.width,
        shrunk.height
    ))
}
