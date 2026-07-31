//! Gate 5 — xterm.js bidirectional bridge (**kill switch**).
//!
//! Prefers `Assets/web/terminal.html` via the wry custom protocol
//! (`http://wormhole.localhost/…`) when vendor xterm.js is staged. Falls back
//! to an echo-only HTML stub with an explicit NOTE when vendor is missing.

use super::GateStatus;

/// Current lab status for this gate.
pub const STATUS: GateStatus = {
    #[cfg(all(windows, feature = "webview"))]
    {
        GateStatus::Partial
    }
    #[cfg(not(all(windows, feature = "webview")))]
    {
        GateStatus::Blocked("enable `--features webview` for IPC / Assets/web host")
    }
};

/// Short TODO note for the gate map.
pub const NOTE: &str =
    "Assets/web terminal.html via wormhole.localhost when vendor staged; else echo stub — \
     run scripts/Fetch-WebAssets.ps1; clipboard paste assembly still lab-partial";

/// Run the gate-5 smoke (no-op when feature off).
pub fn run_smoke() {
    #[cfg(all(windows, feature = "webview"))]
    {
        match run_xterm_smoke() {
            Ok(msg) => println!("[gate5] {msg}"),
            Err(err) => println!("[gate5] blocked/failed: {err}"),
        }
    }
    #[cfg(not(all(windows, feature = "webview")))]
    {
        println!(
            "[gate5] skipped — rebuild with `cargo run -p surface-lab --features webview`"
        );
    }
}

#[cfg(all(windows, feature = "webview"))]
fn run_xterm_smoke() -> Result<String, String> {
    use std::path::PathBuf;

    use wormhole_surface_win::webview::{
        summarize_ipc_for_log, ChildWebViewHost, LabOwnerWindow, WebViewCreateOptions,
        WebViewNavigation,
    };
    use wormhole_surface_win::{PhysicalBounds, SurfaceVisibility};
    use wormhole_terminal::{encode_message, TerminalMessage};
    use bytes::Bytes;

    let assets = find_assets_web();
    let mut protocol_root: Option<PathBuf> = None;
    let (navigation, mode, use_real_terminal) = match assets {
        Some(root) if ChildWebViewHost::xterm_vendor_ready(&root) => {
            protocol_root = Some(root);
            (
                WebViewNavigation::Url("http://wormhole.localhost/terminal.html".into()),
                "Assets/web terminal.html + xterm vendor (custom protocol)",
                true,
            )
        }
        Some(root) if ChildWebViewHost::assets_web_ready(&root) => {
            println!(
                "[gate5] NOTE: {root:?} has terminal.html but vendor/xterm is missing — \
                 using echo stub IPC. Stage with: powershell -NoProfile -File scripts\\Fetch-WebAssets.ps1 \
                 (see Assets/web/README.md)"
            );
            let _ = root;
            (
                WebViewNavigation::echo_stub_html(),
                "echo stub (Assets/web incomplete — no vendor/xterm)",
                false,
            )
        }
        Some(_) | None => {
            println!(
                "[gate5] NOTE: Assets/web not found from cwd/manifest — echo stub. \
                 Expected repo Assets/web; stage vendor via scripts\\Fetch-WebAssets.ps1"
            );
            (
                WebViewNavigation::echo_stub_html(),
                "echo stub (Assets/web not found from cwd)",
                false,
            )
        }
    };

    let owner_win = LabOwnerWindow::create("surface-lab gate5 xterm/echo", 960, 640)
        .map_err(|e| e.to_string())?;
    let (cw, ch) = owner_win.client_size();
    let bounds = PhysicalBounds {
        x: 0,
        y: 0,
        width: cw.max(1),
        height: ch.max(1),
        dpi: 96,
    };

    let mut host = ChildWebViewHost::create(WebViewCreateOptions {
        owner: owner_win.owner_hwnd(),
        bounds,
        navigation,
        custom_protocol_root: protocol_root,
        on_message: Some(Box::new(|msg| {
            // Never print raw terminal/clipboard frames (may contain secrets).
            println!("[gate5] web→host: {}", summarize_ipc_for_log(&msg));
        })),
        on_browser_process_exited: Some(Box::new(|| {
            println!("[gate5] BrowserProcessExited — recreate host before further IPC");
        })),
        additional_browser_args: None,
    })
    .map_err(|e| e.to_string())?;

    owner_win.pump_for(700);

    let (saw_bridge_signal, echoed) = if use_real_terminal {
        // Wait briefly for bridge.js `ready:COLSxROWS` after fit.
        let mut ready = false;
        for _ in 0..8 {
            owner_win.pump_for(150);
            let batch = host.drain_messages();
            ready = batch.iter().any(|m| m.starts_with("ready:"));
            if ready {
                break;
            }
        }

        // Exercise host→page bridge frames (PostWebMessageAsString path).
        let focus = encode_message(&TerminalMessage::FocusBarrier { stream_id: 1 })
            .map_err(|e| e.to_string())?;
        host.post_host_message(&focus).map_err(|e| e.to_string())?;

        let output = encode_message(&TerminalMessage::Output {
            stream_id: 1,
            frame_id: 1,
            data: Bytes::from_static(b"gate5\r\n"),
        })
        .map_err(|e| e.to_string())?;
        host.post_host_message(&output).map_err(|e| e.to_string())?;
        owner_win.pump_for(500);

        let msgs = host.drain_messages();
        let bridge = ready
            || msgs.iter().any(|m| {
                m.starts_with("ready:")
                    || m.starts_with("focus:")
                    || m.starts_with("a:")
                    || m.starts_with("r:")
                    || m.starts_with("error:")
            });
        (bridge, false)
    } else {
        // Bidirectional stub: host → web → echo back.
        host.post_host_message("ping-from-host")
            .map_err(|e| e.to_string())?;
        host.post_host_message("ping-2\nwith-newline")
            .map_err(|e| e.to_string())?;
        owner_win.pump_for(400);

        let msgs = host.drain_messages();
        let echoed = msgs.iter().any(|m| {
            m.contains("echo:ping-from-host") || m.contains("echo:ping-2") || m == "ready"
        });
        (false, echoed)
    };

    host.set_visible(SurfaceVisibility::Visible)
        .map_err(|e| e.to_string())?;

    if std::env::var_os("SURFACE_LAB_INTERACTIVE").is_some() {
        println!("[gate5] SURFACE_LAB_INTERACTIVE set — close the window to continue");
        owner_win.run_until_quit();
    }

    Ok(format!(
        "{mode}; ipc_dropped={} bridge_signal={saw_bridge_signal} echoed_or_ready={echoed} \
         needs_recreate={} (paste/clipboard assembly still lab-partial)",
        host.ipc_dropped_count(),
        host.needs_recreate(),
    ))
}

#[cfg(all(windows, feature = "webview"))]
fn find_assets_web() -> Option<std::path::PathBuf> {
    use std::path::PathBuf;

    use wormhole_surface_win::webview::{is_assets_web_layout, ChildWebViewHost};

    if let Some(p) = ChildWebViewHost::find_assets_web() {
        return Some(p);
    }
    // Compile-time path from this crate → repo Assets/web.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidates = [
        manifest.join("../../Assets/web"),
        manifest.join("../../../Assets/web"),
    ];
    for c in candidates {
        if ChildWebViewHost::assets_web_ready(&c) && is_assets_web_layout(&c) {
            return c.canonicalize().ok().or(Some(c));
        }
    }
    None
}
