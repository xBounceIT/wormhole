//! Phase-1 surface technical gate lab.
//!
//! Default binary prints gate status and exercises the
//! [`wormhole_surface_win`] stub broker. Optional features:
//! - `gpui` — GPUI window chrome (`gates::gpui_host`); AccessKit spike via `SURFACE_LAB_A11Y=1`
//! - `webview` — real WebView2 child host smokes (gates 3–5, 7)
//! - `rdp` — RDP ActiveX owned-overlay spike (gates 6–7)
//!
//! Flags: `--diagnostics` prints a secrets-free support report and exits
//! (see `docs/migration/19-diagnostics-soak.md`).

mod gates;

use wormhole_surface_win::{
    NativeSurfaceBroker, OwnerHwnd, PhysicalBounds, StubNativeSurfaceBroker, SurfaceKind,
    SurfaceLayoutUpdate, SurfaceVisibility, ZOrderHint,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--diagnostics") {
        let report = wormhole_diagnostics::collect_report();
        print!("{}", wormhole_diagnostics::format_report(&report));
        return;
    }

    let gate06_live = args.iter().any(|a| a == "--gate06-live");
    // Default GPUI boot is gate 1; a11y spike is opt-in so gate 8 checklist can run first.
    let boot_a11y = std::env::var_os("SURFACE_LAB_A11Y").is_some()
        || args.iter().any(|a| a == "--gate08-a11y");

    println!("wormhole surface-lab — Phase-1 technical gate");
    println!("target: {} ({})", std::env::consts::ARCH, std::env::consts::OS);
    println!();

    gates::print_gate_map();
    println!();

    demo_broker_stub();
    println!();

    gates::gate02_panes::run_pane_layout_smoke();
    println!();

    gates::gate03_webview2::run_smoke();
    gates::gate04_overlay_ui::run_smoke();
    gates::gate05_xterm::run_smoke();
    println!();

    gates::gate06_rdp_activex::run(gate06_live);
    println!();

    gates::gate07_focus::run_smoke();
    println!();
    gates::gate08_a11y::run_smoke();
    println!();

    #[cfg(feature = "gpui")]
    {
        if boot_a11y {
            match gates::gpui_host::try_boot_a11y() {
                Ok(msg) => println!("[gpui] {msg}"),
                Err(msg) => println!("[gpui] a11y not ready: {msg}"),
            }
        } else {
            match gates::gpui_host::try_boot() {
                Ok(msg) => println!("[gpui] {msg}"),
                Err(msg) => println!("[gpui] not ready: {msg}"),
            }
        }
    }
    #[cfg(not(feature = "gpui"))]
    {
        let _ = boot_a11y;
        println!(
            "[gpui] feature disabled — rebuild with `--features gpui` when deps are pinned \
             (see docs/migration/deps-pins.md and docs/migration/toolchain.md)."
        );
    }

    println!();
    println!("Done. Checklist: docs/migration/gate-checklist.md");
}

fn demo_broker_stub() {
    println!("--- NativeSurfaceBroker stub smoke ---");
    let mut broker = StubNativeSurfaceBroker::new();
    let owner = OwnerHwnd(0);

    let web = broker
        .register(owner, SurfaceKind::WebView2)
        .expect("register WebView2");
    let rdp = broker
        .register(owner, SurfaceKind::RdpActiveX)
        .expect("register RdpActiveX");

    let update = SurfaceLayoutUpdate {
        bounds: PhysicalBounds {
            x: 0,
            y: 40,
            width: 1280,
            height: 720,
            dpi: 96,
        },
        visibility: SurfaceVisibility::Visible,
        z_order: ZOrderHint::Unchanged,
    };
    broker.update_bounds(web.id, update).expect("webview bounds");
    broker
        .update_bounds(
            rdp.id,
            SurfaceLayoutUpdate {
                bounds: PhysicalBounds {
                    x: 640,
                    y: 40,
                    width: 640,
                    height: 720,
                    dpi: 96,
                },
                visibility: SurfaceVisibility::Hidden,
                z_order: ZOrderHint::BelowSiblings,
            },
        )
        .expect("rdp bounds");

    for h in broker.list() {
        println!("  surface id={} kind={}", h.id, h.kind.label());
    }
    println!(
        "  registered {} surface(s); RDP: `--features rdp` (gate 6); WebView2: `--features webview`",
        broker.list().len()
    );
}
