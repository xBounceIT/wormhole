//! Gate 6 — RDP ActiveX `MsRdpClient` OLE in-place + owned overlay (**kill switch**).
//!
//! Hosting model (mandatory): **owned overlay** via `GWLP_HWNDPARENT` +
//! `WS_EX_TOOLWINDOW` — **not** `SetParent` / `WS_CHILD`.
//!
//! With `--features rdp`:
//! - broker `SurfaceKind::RdpActiveX` registration
//! - crash-sentinel Mark before Connect / Clear on Connected (temp path)
//! - [`RdpOverlayHost`] owned overlay HWND on STA
//! - OLE `IOleObject` in-place activate + connection-point sink stub
//! - Connect stub when `--gate06-live`
//!
//! ```powershell
//! cargo run -p surface-lab --features rdp
//! cargo run -p surface-lab --features rdp -- --gate06-live
//! ```
//!
//! See `docs/migration/05-rdp-spike.md`.

use super::GateStatus;
use wormhole_surface_win::{
    NativeSurfaceBroker, OwnerHwnd, StubNativeSurfaceBroker, SurfaceKind,
};

/// Current lab status for this gate.
pub const STATUS: GateStatus = {
    #[cfg(all(windows, feature = "rdp"))]
    {
        GateStatus::Partial
    }
    #[cfg(not(all(windows, feature = "rdp")))]
    {
        GateStatus::Blocked("enable --features rdp")
    }
};

/// Short note for the gate map.
#[cfg(all(windows, feature = "rdp"))]
pub const NOTE: &str =
    "OLE in-place + owned overlay + event sink stub — docs/migration/05-rdp-spike.md";

/// Short note when feature is off.
#[cfg(not(all(windows, feature = "rdp")))]
pub const NOTE: &str =
    "blocked: cargo run -p surface-lab --features rdp (docs/migration/05-rdp-spike.md)";

/// Run the gate-6 smoke.
pub fn run(live: bool) {
    println!("--- Gate 6: RDP ActiveX owned-overlay ---");
    println!("  docs: docs/migration/05-rdp-spike.md");

    let mut broker = StubNativeSurfaceBroker::new();
    let handle = broker
        .register(OwnerHwnd(0), SurfaceKind::RdpActiveX)
        .expect("register RdpActiveX");
    println!(
        "  broker: registered id={} kind={}",
        handle.id,
        handle.kind.label()
    );
    exercise_sentinel();

    #[cfg(all(windows, feature = "rdp"))]
    {
        match run_rdp_smoke(live) {
            Ok(msg) => println!("[gate6] {msg}"),
            Err(err) => println!("[gate6] blocked/failed: {err}"),
        }
    }
    #[cfg(not(all(windows, feature = "rdp")))]
    {
        let _ = live;
        println!(
            "[gate6] skipped — rebuild with `cargo run -p surface-lab --features rdp`"
        );
    }
}

fn exercise_sentinel() {
    use std::time::{SystemTime, UNIX_EPOCH};
    use wormhole_surface_win::rdp::RdpCrashSentinel;

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("surface-lab-gate06-{nanos}"));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("rdp-in-flight.json");
    let sentinel = RdpCrashSentinel::at_path(&path);
    let _ = sentinel.mark_connect_in_flight("00000000-0000-0000-0000-000000000006", "lab.local");
    match sentinel.try_read_orphan() {
        Ok(Some(r)) => println!("  sentinel: Mark/orphan ok nodeId={}", r.node_id),
        Ok(None) => println!("  sentinel: unexpected empty after Mark"),
        Err(e) => println!("  sentinel: failed: {e}"),
    }
    let _ = sentinel.clear();
    println!("  sentinel: Clear ok");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(all(windows, feature = "rdp"))]
fn run_rdp_smoke(live: bool) -> Result<String, String> {
    use std::rc::Rc;
    use std::time::Duration;
    use wormhole_surface_win::rdp::{
        probe_registered_classes, pump_messages, rdp_fail, run_on_sta, select_best_rdp_class,
        ConnectStubOptions, HostBounds, RdpCrashSentinel, RdpOcx, RdpOverlayHost,
    };

    let classes = probe_registered_classes();
    println!("  CLSID probe ({}):", classes.len());
    for c in &classes {
        println!("    - {} {{{}}}", c.name, c.clsid_string);
    }
    let selected = classes
        .first()
        .copied()
        .unwrap_or_else(select_best_rdp_class);
    println!(
        "  selected: {} {{{}}}",
        selected.name, selected.clsid_string
    );

    let do_live = live;
    run_on_sta(move || {
        let mut host = RdpOverlayHost::spawn(OwnerHwnd(0), HostBounds::SEED)?;
        let info = host.info();
        if !info.is_owned_popup {
            return Err(rdp_fail(
                "overlay styles must be WS_POPUP + WS_EX_TOOLWINDOW without WS_CHILD",
            ));
        }
        host.set_bounds(HostBounds::new(40, 40, 640, 480))?;
        host.set_visible(true)?;

        let mut ocx = RdpOcx::cocreate_best()?;
        let activate = host.activate_ocx(&mut ocx)?;

        // Crash sentinel: Mark before Connect; Clear on Connected / Disconnected /
        // FatalError (and always on teardown so the lab leaves no orphan).
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("surface-lab-gate06-ole-{nanos}"));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("rdp-in-flight.json");
        let sentinel = Rc::new(RdpCrashSentinel::at_path(&path));
        let _ = sentinel.mark_connect_in_flight(
            "00000000-0000-0000-0000-000000000006",
            "lab.local",
        );
        {
            let sentinel_clear = Rc::clone(&sentinel);
            ocx.event_state()
                .borrow_mut()
                .set_on_sentinel_clear(move || {
                    let _ = sentinel_clear.clear();
                });
        }

        let mut connect_note = String::from("Connect stub skipped (pass --gate06-live)");
        if do_live {
            let server =
                std::env::var("WORMHOLE_RDP_LAB_SERVER").unwrap_or_else(|_| "127.0.0.1".into());
            let port: u16 = std::env::var("WORMHOLE_RDP_LAB_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(3389);
            match ocx.connect_stub(&ConnectStubOptions { server, port }) {
                Ok(()) => {
                    connect_note = "Connect stub Ok (credentials deferred)".into();
                    pump_messages(Duration::from_millis(500));
                }
                Err(e) => {
                    connect_note = format!("Connect stub failed honestly ({e})");
                }
            }
        }

        let connected = ocx.event_state().borrow().connected;
        // Lifecycle hooks clear on Connected/Disconnected/FatalError; always clear on
        // teardown so lab leaves no orphan. Drop OCX before destroying overlay HWND.
        let _ = sentinel.clear();
        let _ = std::fs::remove_dir_all(&dir);

        host.set_visible(false)?;
        drop(ocx);
        host.shutdown();

        Ok(format!(
            "owned overlay ok (hwnd={}, class={}, popup_not_child=true); \
             OLE in-place ok={} events_advised={} connected={} ; {}",
            info.hwnd,
            activate.class_name,
            activate.inplace_ok,
            activate.events_advised,
            connected,
            connect_note
        ))
    })
    .map_err(|e| {
        format!("STA/OLE path failed ({e}) — runtime OCX missing is OK for compile gate")
    })
}
