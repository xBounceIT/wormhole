//! Physical-pixel layout hints pushed from the GPUI (or lab) layout pass.

use crate::SurfaceKind;

/// Axis-aligned bounds in **physical pixels**.
///
/// Convention matches today's layout ticks: for RDP this is typically
/// **screen** physical pixels for the owned overlay; for WebView2 it is the
/// composition slot (see `docs/migration/native-surface-broker.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PhysicalBounds {
    /// Left edge in physical pixels.
    pub x: i32,
    /// Top edge in physical pixels.
    pub y: i32,
    /// Width in physical pixels (must be > 0 when visible).
    pub width: u32,
    /// Height in physical pixels (must be > 0 when visible).
    pub height: u32,
    /// DPI of the monitor / window at the time of the layout pass (e.g. 96, 144, 192).
    pub dpi: u32,
}

impl PhysicalBounds {
    /// Returns true when width or height is zero (degenerate — hide / skip SetWindowPos).
    pub fn is_degenerate(self) -> bool {
        self.width == 0 || self.height == 0
    }

    /// Seed bounds used to force HWND/controller realization before real layout (1×1).
    pub const SEED: Self = Self {
        x: 0,
        y: 0,
        width: 1,
        height: 1,
        dpi: 96,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn degenerate_when_any_axis_zero() {
        assert!(PhysicalBounds {
            x: 0,
            y: 0,
            width: 0,
            height: 10,
            dpi: 96
        }
        .is_degenerate());
        assert!(PhysicalBounds {
            x: 0,
            y: 0,
            width: 10,
            height: 0,
            dpi: 96
        }
        .is_degenerate());
        assert!(!PhysicalBounds::SEED.is_degenerate());
    }
}

/// Whether the native surface HWND should be shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SurfaceVisibility {
    /// Surface is on-screen and should receive input when focused.
    Visible,
    /// Surface is laid out but hidden (tab background, collapsed pane, etc.).
    Hidden,
}

/// Relative z-order hint among sibling native surfaces under the same owner.
///
/// # Gate 4 (menus / tooltips above WebView2)
///
/// Child WebView2 HWNDs sit above GPUI's composition surface. Prefer
/// [`crate::OverlayStackPolicy::SuppressWebViewForChrome`] (hide the webview
/// while menus/dialogs are open) over per-frame screenshots. Sibling HWND
/// `HWND_TOP` / `HWND_BOTTOM` mapping for multiple native surfaces is still TODO.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ZOrderHint {
    /// Default stacking; broker may leave order unchanged.
    Unchanged,
    /// Raise above other registered surfaces of the same owner.
    AboveSiblings,
    /// Lower below other registered surfaces of the same owner.
    BelowSiblings,
    /// Prefer above a specific kind when both are visible (e.g. chrome overlays).
    AboveKind(SurfaceKind),
}
