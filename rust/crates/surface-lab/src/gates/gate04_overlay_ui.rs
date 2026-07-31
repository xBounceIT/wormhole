//! Gate 4 — Menus, tooltips, dialogs correctly above WebView2 (**kill switch**).
//!
//! # Z-order spike (documented approach)
//!
//! Child WebView2 HWNDs composite **above** GPUI's GPU surface (same airspace
//! class as `gpui-wry`). Sustainable options — **not** per-frame screenshots:
//!
//! 1. **Suppress / hide** the WebView2 while GPUI chrome (menu, tooltip, dialog)
//!    is open — [`wormhole_surface_win::OverlayStackController`] +
//!    [`wormhole_surface_win::SurfaceVisibility::Hidden`].
//! 2. Host chrome in a **separate top-level HWND** above the webview.
//!
//! API hooks are in-tree; GPUI popup wiring is still TODO (needs `--features gpui`).

use super::GateStatus;

/// Current lab status for this gate.
pub const STATUS: GateStatus = GateStatus::Partial;

/// Short TODO note for the gate map.
pub const NOTE: &str =
    "OverlayStackController hide-on-chrome; GPUI popup wiring TODO; no screenshot hacks";

/// Print / exercise the z-order policy hooks.
pub fn run_smoke() {
    use wormhole_surface_win::{OverlayStackController, OverlayStackPolicy, SurfaceKind, SurfaceVisibility};

    let mut stack = OverlayStackController::new();
    let idle = stack.effective_webview_visibility(true);
    println!(
        "[gate4] idle policy={:?} hide_webview={} effective={idle:?}",
        stack.policy(),
        stack.should_hide_webview(),
    );

    stack.push_chrome_overlay();
    let hidden = stack.effective_webview_visibility(true);
    assert_eq!(hidden, SurfaceVisibility::Hidden);
    println!(
        "[gate4] menu open → {:?} hide_webview={} effective={hidden:?} \
         (shell: ChildWebViewHost::set_visible(Hidden))",
        stack.policy(),
        stack.should_hide_webview(),
    );

    stack.pop_chrome_overlay();
    stack.set_idle_policy(OverlayStackPolicy::PreferKind(SurfaceKind::WebView2));
    let restored = stack.effective_webview_visibility(true);
    assert_eq!(restored, SurfaceVisibility::Visible);
    println!(
        "[gate4] menu closed → {:?} effective={restored:?} — TODO: wire GPUI Menu/Tooltip open/close to push/pop",
        stack.policy()
    );

    #[cfg(all(windows, feature = "webview"))]
    {
        // Demonstrate the hide/show contract on a live child when Runtime is present.
        if let Err(err) = run_overlay_hide_smoke(&mut stack) {
            println!("[gate4] live hide smoke skipped/failed: {err}");
        }
    }
}

#[cfg(all(windows, feature = "webview"))]
fn run_overlay_hide_smoke(
    stack: &mut wormhole_surface_win::OverlayStackController,
) -> Result<(), String> {
    use wormhole_surface_win::webview::{
        ChildWebViewHost, LabOwnerWindow, WebViewCreateOptions, WebViewNavigation,
    };
    use wormhole_surface_win::PhysicalBounds;

    let owner_win = LabOwnerWindow::create("surface-lab gate4 overlay", 640, 480)
        .map_err(|e| e.to_string())?;
    let (cw, ch) = owner_win.client_size();
    let mut host = ChildWebViewHost::create(WebViewCreateOptions {
        owner: owner_win.owner_hwnd(),
        bounds: PhysicalBounds {
            x: 0,
            y: 0,
            width: cw.max(1),
            height: ch.max(1),
            dpi: 96,
        },
        navigation: WebViewNavigation::about_blank_html(),
        custom_protocol_root: None,
        on_message: None,
        on_browser_process_exited: None,
        additional_browser_args: None,
    })
    .map_err(|e| e.to_string())?;

    stack.push_chrome_overlay();
    host.set_visible(stack.effective_webview_visibility(true))
        .map_err(|e| e.to_string())?;
    assert!(!host.is_visible());
    stack.pop_chrome_overlay();
    host.set_visible(stack.effective_webview_visibility(true))
        .map_err(|e| e.to_string())?;
    assert!(host.is_visible());

    owner_win.pump_for(200);
    println!(
        "[gate4] live ChildWebViewHost hide/show via OverlayStackController ok (gen={})",
        host.recreate_generation()
    );
    Ok(())
}
