//! Gate 1 — GPUI window: custom title bar, Mica, light/dark, DPI 100–200%.

use super::GateStatus;

/// Current lab status for this gate.
pub const STATUS: GateStatus = {
    #[cfg(feature = "gpui")]
    {
        // Lab path: custom title bar + theme toggle + DPI helpers + MicaBackdrop API.
        // Hardware 100/150/200% evidence still required (gate-checklist.md) — not a pass.
        GateStatus::Partial
    }
    #[cfg(not(feature = "gpui"))]
    {
        GateStatus::Blocked("enable `--features gpui` + pin (deps-pins.md)")
    }
};

/// Short TODO note for the gate map.
pub const NOTE: &str = {
    #[cfg(feature = "gpui")]
    {
        "custom titlebar + theme toggle + MicaBackdrop + PhysicalBounds DPI helpers; hardware DPI matrix TODO"
    }
    #[cfg(not(feature = "gpui"))]
    {
        "gpui feature off — see deps-pins.md"
    }
};

// Hardware evidence (do not check gate-checklist from this lab alone):
// - Exercise 100% / 150% / 200% DPI on real x64 and ARM64 hardware.
// - Confirm Win11 Mica shows through translucent chrome; Win10 may stay opaque.
