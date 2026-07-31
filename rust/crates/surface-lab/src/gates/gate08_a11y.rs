//! Gate 8 — UI Automation + full keyboard navigation (**kill switch**).
//!
//! # AccessKit / GPUI chrome
//!
//! With `--features gpui`, [`super::gpui_host::try_boot_a11y`] spikes AccessKit roles,
//! tab stops, and Tab/Shift-Tab keybindings (see Zed `gpui` example `a11y`).
//!
//! # HWND overlay UIA gaps (honest)
//!
//! | Surface | Local UIA tree | Keyboard | Notes |
//! |---------|----------------|----------|-------|
//! | GPUI chrome | AccessKit → UIA | Tab order in GPUI | Primary a11y surface for tree/tabs/dialogs |
//! | WebView2 child | Chromium UIA subtree | In-page + host focus | Separate tree under the child HWND; not merged into GPUI AccessKit |
//! | RDP overlay OCX | Remote desktop content | After SetFocus on AxHost child | Local UIA does **not** expose remote controls; Narrator sees a generic window/pane at best |
//!
//! Sustainable path: GPUI chrome fully keyboard + AccessKit; WebView2 relies on
//! Edge a11y; RDP documents the remote-desktop limitation (same as WinUI today).
//!
//! Checklist hooks mirror [`docs/migration/gate-checklist.md`] rows 7–8 and the
//! detailed list in `docs/migration/08-focus-a11y.md`.

use super::GateStatus;

/// Current lab status for this gate (AccessKit spike still needs hardware evidence).
pub const STATUS: GateStatus = GateStatus::Partial;

/// Short note for the gate map.
#[cfg(feature = "gpui")]
pub const NOTE: &str =
    "AccessKit chrome spike + UIA gap table + keyboard checklist — docs/migration/08-focus-a11y.md";

/// Short note when GPUI feature is off (checklist still available).
#[cfg(not(feature = "gpui"))]
pub const NOTE: &str =
    "UIA gaps + keyboard checklist hooks; AccessKit spike needs `--features gpui` — docs/migration/08-focus-a11y.md";

/// Hardware / interactive checklist hooks (gate-checklist evidence).
pub const KEYBOARD_A11Y_CHECKLIST: &[&str] = &[
    "GPUI: Tab / Shift-Tab cycles chrome controls (tree, tabs, dialogs)",
    "GPUI: AccessKit roles visible in Inspect.exe / Narrator when AT active",
    "WebView2: focus enters terminal/browser via FocusBroker; page Tab stays in Chromium",
    "WebView2: chrome menu/dialog hides webview (gate 4) then restores focus without black surface",
    "RDP: cold-connect lands keyboard on AxHost child; first keystroke reaches logon UI",
    "RDP: AutoReconnected does not steal focus from chrome / other tab",
    "RDP: local UIA does not claim remote controls (document gap; do not fake a tree)",
    "x64 hardware: record evidence pack (gate-checklist.md)",
    "ARM64 hardware: record evidence pack (gate-checklist.md)",
];

/// Print UIA gaps + checklist (does **not** boot AccessKit — that is opt-in in `main`
/// via `SURFACE_LAB_A11Y` / `--gate08-a11y` so headless `cargo test` / default lab runs stay non-blocking).
pub fn run_smoke() {
    println!("--- Gate 8: UIA + keyboard navigation ---");
    println!("  docs: docs/migration/08-focus-a11y.md");
    println!();
    println!("  HWND overlay UIA gaps:");
    println!("    - GPUI chrome: AccessKit → UIA (spike under --features gpui)");
    println!("    - WebView2: Chromium UIA subtree under child HWND (not merged into GPUI)");
    println!("    - RDP OCX: remote content only; local UIA is a generic HWND — same as WinUI");
    println!();
    println!("  Keyboard / a11y checklist hooks (hardware sign-off):");
    for (i, item) in KEYBOARD_A11Y_CHECKLIST.iter().enumerate() {
        println!("    [ ] {}: {item}", i + 1);
    }

    #[cfg(feature = "gpui")]
    {
        println!();
        println!(
            "  [gpui] AccessKit spike: `SURFACE_LAB_A11Y=1` or `--gate08-a11y` with `--features gpui`"
        );
    }
    #[cfg(not(feature = "gpui"))]
    {
        println!();
        println!(
            "  [gpui] feature disabled — rebuild with `--features gpui` for AccessKit chrome spike"
        );
    }

    println!("[gate8] checklist hooks printed (hardware evidence still required)");
}
