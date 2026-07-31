//! Gate 7 — Focus handoff among GPUI, RDP, and WebView2 (**kill switch**).
//!
//! Exercises [`wormhole_surface_win::FocusBroker`] policy without live RDP:
//! - never `SetFocus(NULL)`
//! - cold-connect one-shot latch
//! - auto-reconnect must not steal focus
//!
//! Optional live smokes when `--features webview` / `--features rdp`.
//!
//! See `docs/migration/08-focus-a11y.md`.

use super::GateStatus;
use wormhole_surface_win::{
    FocusAction, FocusBroker, FocusCycle, FocusCycleDirection, FocusError, FocusHwnd, FocusOwner,
    FocusReason, FocusRequest, RdpConnectKind, RecordingFocusOps, SurfaceHandle, SurfaceId,
    SurfaceKind,
};

/// Current lab status for this gate.
pub const STATUS: GateStatus = GateStatus::Partial;

/// Short note for the gate map.
pub const NOTE: &str =
    "FocusBroker + FocusCycle (chrome↔surfaces); Win32 SetFocus/GetFocus; cold-connect latch; no SetFocus(NULL) — docs/migration/08-focus-a11y.md";

/// Run the gate-7 focus policy smoke (always; no COM required).
pub fn run_smoke() {
    println!("--- Gate 7: Focus handoff ---");
    println!("  docs: docs/migration/08-focus-a11y.md");
    println!("  cold-connect order:");
    println!("    1) shell/GPUI focus chrome slot (optional)");
    println!("    2) Win32 SetFocus on RDP AxHost child HWND (never NULL, never form alone)");
    println!("    3) latch rdp_focus_pushed — duplicate ColdOrRetry skips; AutoReconnected skips by kind");

    let mut broker = FocusBroker::new(RecordingFocusOps::new());

    // GPUI chrome owns focus (no HWND required).
    let gpui = broker.request_focus(FocusRequest {
        owner: FocusOwner::GpuiChrome,
        hwnd: None,
        reason: FocusReason::UserHandoff,
    });
    assert!(matches!(
        gpui,
        FocusAction::Applied {
            owner: FocusOwner::GpuiChrome,
            ..
        }
    ));
    println!("  [ok] GPUI chrome owner (no SetFocus)");

    // Null HWND must be rejected before any ops call.
    let null_reject = broker.request_focus(FocusRequest {
        owner: FocusOwner::RdpActiveX,
        hwnd: Some(FocusHwnd(0)),
        reason: FocusReason::Explicit,
    });
    assert_eq!(null_reject, FocusAction::Failed(FocusError::NullHwndRejected));
    assert!(broker.ops().set_calls.is_empty());
    println!("  [ok] SetFocus(NULL) rejected");

    let ax_child = FocusHwnd(0x0D00_0001);
    let cold = broker.on_rdp_connected(ax_child, RdpConnectKind::ColdOrRetry);
    assert!(matches!(cold, FocusAction::Applied { .. }));
    assert!(broker.rdp_focus_pushed());
    println!("  [ok] cold-connect SetFocus(AxHost child) + latch");

    let auto = broker.on_rdp_connected(ax_child, RdpConnectKind::AutoReconnected);
    assert_eq!(
        auto,
        FocusAction::Skipped {
            reason: "auto-reconnect must not steal focus"
        }
    );
    assert_eq!(broker.ops().set_calls.len(), 1);
    println!("  [ok] AutoReconnected did not steal focus");

    // Transient Connecting preserves latch; terminal teardown clears it.
    broker.on_rdp_session_not_connected(false);
    assert!(broker.rdp_focus_pushed());
    broker.on_rdp_session_not_connected(true);
    assert!(!broker.rdp_focus_pushed());
    println!("  [ok] latch cleared only on Disconnected/Failed");

    let web = FocusHwnd(0x0EB0_0002);
    let handoff = broker.request_focus(FocusRequest {
        owner: FocusOwner::WebView2,
        hwnd: Some(web),
        reason: FocusReason::UserHandoff,
    });
    assert!(matches!(
        handoff,
        FocusAction::Applied {
            owner: FocusOwner::WebView2,
            ..
        }
    ));
    println!("  [ok] WebView2 handoff recorded");

    // FocusCycle stub: chrome sentinel ↔ registered SurfaceHandles (no live HWND).
    let mut cycle = FocusCycle::new();
    let web_handle = SurfaceHandle {
        id: SurfaceId(1),
        kind: SurfaceKind::WebView2,
    };
    cycle.insert_surface(web_handle);
    cycle.set_surface_hwnd(web_handle.id, Some(web));
    let cycled = broker.request_focus(cycle.advance(
        FocusCycleDirection::Next,
        FocusReason::UserHandoff,
    ));
    assert!(matches!(
        cycled,
        FocusAction::Applied {
            owner: FocusOwner::WebView2,
            ..
        }
    ));
    let back_chrome = broker.request_focus(cycle.advance(
        FocusCycleDirection::Next,
        FocusReason::UserHandoff,
    ));
    assert!(matches!(
        back_chrome,
        FocusAction::Applied {
            owner: FocusOwner::GpuiChrome,
            ..
        }
    ));
    println!("  [ok] FocusCycle next: chrome → WebView2 → chrome");

    #[cfg(windows)]
    {
        // Real GetFocus/SetFocus(NULL) path — no live RDP.
        match wormhole_surface_win::set_focus(FocusHwnd(0)) {
            Err(FocusError::NullHwndRejected) => {
                println!("  [ok] Win32 helper rejects null before user32")
            }
            other => println!("  [warn] unexpected set_focus(null) result: {other:?}"),
        }
        match wormhole_surface_win::get_focus() {
            Ok(cur) => println!("  [ok] GetFocus => {cur:?}"),
            Err(e) => println!("  [warn] GetFocus: {e}"),
        }
    }

    #[cfg(all(windows, feature = "webview"))]
    {
        if let Err(err) = run_webview_focus_smoke() {
            println!("  [webview] live focus smoke skipped/failed: {err}");
        }
    }

    #[cfg(all(windows, feature = "rdp"))]
    {
        if let Err(err) = run_rdp_focus_smoke() {
            println!("  [rdp] overlay focus smoke skipped/failed: {err}");
        }
    }

    println!("[gate7] FocusBroker policy smoke ok");
}

#[cfg(all(windows, feature = "webview"))]
fn run_webview_focus_smoke() -> Result<(), String> {
    use wormhole_surface_win::webview::{
        ChildWebViewHost, LabOwnerWindow, WebViewCreateOptions, WebViewNavigation,
    };
    use wormhole_surface_win::PhysicalBounds;

    let owner = LabOwnerWindow::create("surface-lab gate7 focus", 480, 320)
        .map_err(|e| e.to_string())?;
    let (cw, ch) = owner.client_size();
    let host = ChildWebViewHost::create(WebViewCreateOptions {
        owner: owner.owner_hwnd(),
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

    host.request_focus().map_err(|e| e.to_string())?;
    println!("  [webview] ChildWebViewHost::request_focus ok");
    Ok(())
}

#[cfg(all(windows, feature = "rdp"))]
fn run_rdp_focus_smoke() -> Result<(), String> {
    use wormhole_surface_win::rdp::{HostBounds, RdpOverlayHost};
    use wormhole_surface_win::{FocusBroker, FocusOwner, FocusReason, FocusRequest, OwnerHwnd};
    #[cfg(windows)]
    use wormhole_surface_win::Win32FocusOps;

    let host = RdpOverlayHost::spawn(OwnerHwnd(0), HostBounds::SEED).map_err(|e| e.to_string())?;
    let hwnd = host.focus_hwnd();
    let mut broker = FocusBroker::new(Win32FocusOps);
    // Cold-connect path through broker (overlay HWND is lab stand-in for AxHost child).
    let action = broker.on_rdp_connected(hwnd, RdpConnectKind::ColdOrRetry);
    match &action {
        FocusAction::Applied { owner, .. } => {
            assert_eq!(*owner, FocusOwner::RdpActiveX);
            println!("  [rdp] FocusBroker→overlay HWND applied ({hwnd})");
        }
        FocusAction::Skipped { reason } => {
            println!("  [rdp] focus skipped ({reason}) — overlay may lack input queue");
        }
        FocusAction::Failed(e) => {
            // SetFocus can fail when the thread does not own the input queue; policy still ran.
            println!("  [rdp] SetFocus failed (acceptable in headless lab): {e}");
        }
    }
    let _ = broker.request_focus(FocusRequest {
        owner: FocusOwner::GpuiChrome,
        hwnd: None,
        reason: FocusReason::RestoreAfterDialog,
    });
    host.shutdown();
    Ok(())
}
