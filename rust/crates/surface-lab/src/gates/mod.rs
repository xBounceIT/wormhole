//! Gate TODO map (1–8). Each module is a stub until that gate is implemented.
//!
//! Pass/fail criteria live in `docs/migration/gate-checklist.md`.
//! Do not mark gates passed from this lab alone — real hardware evidence required.

pub mod gate01_window;
pub mod gate02_panes;
pub mod gate03_webview2;
pub mod gate04_overlay_ui;
pub mod gate05_xterm;
pub mod gate06_rdp_activex;
pub mod gate07_focus;
pub mod gate08_a11y;

#[cfg(feature = "gpui")]
pub mod gpui_host;

/// Shared status printed by the lab binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateStatus {
    /// Not started — module is a TODO stub.
    #[allow(dead_code)] // reserved for future gates / temporary regressions
    Todo,
    /// Partial scaffold (types / hooks) but not demonstrable.
    #[allow(dead_code)] // used by gate 6 when `rdp` is enabled
    Scaffold,
    /// Near-real implementation; interactive / hardware evidence still required.
    Partial,
    /// Lab path implemented; still needs gate-checklist hardware sign-off.
    #[allow(dead_code)] // reserved for fully demonstrated gates
    Implemented,
    /// Feature-flagged or blocked on deps (e.g. GPUI not linked).
    #[allow(dead_code)] // used when `gpui` feature is off (gate 1)
    Blocked(&'static str),
}

impl GateStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Todo => "TODO",
            Self::Scaffold => "scaffold",
            Self::Partial => "partial",
            Self::Implemented => "implemented",
            Self::Blocked(_) => "blocked",
        }
    }
}

struct GateRow {
    id: u8,
    title: &'static str,
    module: &'static str,
    status: GateStatus,
    note: &'static str,
}

fn rows() -> [GateRow; 8] {
    [
        GateRow {
            id: 1,
            title: "GPUI window: custom title bar / Mica / theme / DPI",
            module: "gates::gate01_window",
            status: gate01_window::STATUS,
            note: gate01_window::NOTE,
        },
        GateRow {
            id: 2,
            title: "Four resizable panes + drag-and-drop",
            module: "gates::gate02_panes",
            status: gate02_panes::STATUS,
            note: gate02_panes::NOTE,
        },
        GateRow {
            id: 3,
            title: "WebView2 inside a movable/resizable pane",
            module: "gates::gate03_webview2",
            status: gate03_webview2::STATUS,
            note: gate03_webview2::NOTE,
        },
        GateRow {
            id: 4,
            title: "Menus / tooltips / dialogs above WebView2",
            module: "gates::gate04_overlay_ui",
            status: gate04_overlay_ui::STATUS,
            note: gate04_overlay_ui::NOTE,
        },
        GateRow {
            id: 5,
            title: "xterm.js bridge (focus, resize, clipboard)",
            module: "gates::gate05_xterm",
            status: gate05_xterm::STATUS,
            note: gate05_xterm::NOTE,
        },
        GateRow {
            id: 6,
            title: "RDP ActiveX MsRdpClient9 (COM events, connect)",
            module: "gates::gate06_rdp_activex",
            status: gate06_rdp_activex::STATUS,
            note: gate06_rdp_activex::NOTE,
        },
        GateRow {
            id: 7,
            title: "Focus handoff GPUI ↔ RDP ↔ WebView2",
            module: "gates::gate07_focus",
            status: gate07_focus::STATUS,
            note: gate07_focus::NOTE,
        },
        GateRow {
            id: 8,
            title: "UIA + full keyboard navigation",
            module: "gates::gate08_a11y",
            status: gate08_a11y::STATUS,
            note: gate08_a11y::NOTE,
        },
    ]
}

/// Print the gate checklist mapped to code modules.
pub fn print_gate_map() {
    println!("--- Gate map (modules) ---");
    for row in rows() {
        let detail = match row.status {
            GateStatus::Blocked(why) => format!("{} ({why})", row.status.label()),
            other => other.label().to_string(),
        };
        println!(
            "  [{id}] {status:<10} {title}",
            id = row.id,
            status = detail,
            title = row.title
        );
        println!("       module: {} — {}", row.module, row.note);
    }
}
