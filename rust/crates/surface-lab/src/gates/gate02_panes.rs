//! Gate 2 — Four resizable panes with drag-and-drop.

use super::GateStatus;

/// Current lab status for this gate.
pub const STATUS: GateStatus = {
    #[cfg(feature = "gpui")]
    {
        // 2×2 panes + live splitter drag work in gpui_host::lab; tab DnD is a swap stub only.
        GateStatus::Partial
    }
    #[cfg(not(feature = "gpui"))]
    {
        GateStatus::Blocked("enable `--features gpui` (panes live in gpui_host)")
    }
};

/// Short TODO note for the gate map.
pub const NOTE: &str = {
    #[cfg(all(feature = "gpui", feature = "pane-layout"))]
    {
        "2x2 panes + drag splitters; DnD tab swap stub; BrokerPaneLayoutSink smoke on"
    }
    #[cfg(all(feature = "gpui", not(feature = "pane-layout")))]
    {
        "2x2 panes + drag splitters; DnD tab swap stub; enable `--features pane-layout` for broker sink"
    }
    #[cfg(all(not(feature = "gpui"), feature = "pane-layout"))]
    {
        "BrokerPaneLayoutSink smoke available; gpui feature off for interactive panes"
    }
    #[cfg(all(not(feature = "gpui"), not(feature = "pane-layout")))]
    {
        "gpui feature off — panes implemented behind gpui_host"
    }
};

/// Headless smoke: bind panes → surfaces and push one layout tick through the sink.
#[cfg(feature = "pane-layout")]
pub fn run_pane_layout_smoke() {
    use wormhole_surface_win::{
        BrokerPaneLayoutSink, OwnerHwnd, StubNativeSurfaceBroker, SurfaceKind, SurfaceVisibility,
    };
    use wormhole_ui::{PaneId, PaneLayoutSink, PaneLayoutUpdate, PanePhysicalBounds};

    println!("--- Gate 2: BrokerPaneLayoutSink smoke ---");
    let mut sink = BrokerPaneLayoutSink::new(StubNativeSurfaceBroker::new());
    let owner = OwnerHwnd(0);
    let web = sink
        .register_and_bind(PaneId(0), owner, SurfaceKind::WebView2)
        .expect("bind WebView2");
    let rdp = sink
        .register_and_bind(PaneId(1), owner, SurfaceKind::RdpActiveX)
        .expect("bind RdpActiveX");

    sink.on_pane_layout(&[
        PaneLayoutUpdate {
            pane: PaneId(0),
            bounds: PanePhysicalBounds {
                x: 0,
                y: 40,
                width: 640,
                height: 720,
                dpi: 96,
            },
        },
        PaneLayoutUpdate {
            pane: PaneId(1),
            bounds: PanePhysicalBounds {
                x: 640,
                y: 40,
                width: 640,
                height: 720,
                dpi: 96,
            },
        },
    ]);

    let web_u = sink.broker().last_update(web.id).expect("webview bounds");
    let rdp_u = sink.broker().last_update(rdp.id).expect("rdp bounds");
    println!(
        "  pane0 → surface {} ({}) {}×{} vis={:?}",
        web.id,
        web.kind.label(),
        web_u.bounds.width,
        web_u.bounds.height,
        web_u.visibility
    );
    println!(
        "  pane1 → surface {} ({}) {}×{} vis={:?}",
        rdp.id,
        rdp.kind.label(),
        rdp_u.bounds.width,
        rdp_u.bounds.height,
        rdp_u.visibility
    );
    assert_eq!(web_u.visibility, SurfaceVisibility::Visible);
    assert_eq!(rdp_u.visibility, SurfaceVisibility::Visible);
    assert!(sink.last_errors().is_empty());
    println!("  ok — PaneLayoutSink → NativeSurfaceBroker::update_bounds");
}

#[cfg(not(feature = "pane-layout"))]
pub fn run_pane_layout_smoke() {
    println!(
        "--- Gate 2: BrokerPaneLayoutSink smoke skipped \
         (rebuild with `--features pane-layout`) ---"
    );
}

// TODO: richer DnD (tab strip reorder / dock targets) beyond slot swap stub.
// TODO: live GPUI lab path: feed gpui_host pane PhysicalBounds into BrokerPaneLayoutSink.
