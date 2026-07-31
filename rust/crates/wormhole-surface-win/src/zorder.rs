//! Z-order / airspace hooks for chrome (menus, tooltips, dialogs) above WebView2.
//!
//! # Problem (gate 4)
//!
//! Child WebView2 HWNDs composite **above** GPUI's DirectComposition / DX surface.
//! The same airspace issue applies to experimental `gpui-wry` overlays — which is
//! why production SSH/HTTP surfaces must live in this crate, not gpui-wry.
//!
//! Menus, tooltips, and modal dialogs drawn by GPUI will appear **under** a visible
//! WebView2 child unless we either:
//! 1. Temporarily [`crate::SurfaceVisibility::Hidden`] the webview while chrome is open
//!    (matches WinUI collapsing `Visibility` for background tabs / airspace), or
//! 2. Host chrome in a separate top-level HWND above the webview (popup / owned window).
//!
//! # API hooks (implemented as policy markers; Win32 Apply is TODO)
//!
//! - [`crate::ZOrderHint`] on each layout tick
//! - [`OverlayStackPolicy`] for modal / menu depth
//! - [`OverlayStackController`] records suppress depth for the lab / future broker

use crate::SurfaceKind;

/// How the broker should stack native surfaces relative to GPUI chrome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum OverlayStackPolicy {
    /// Leave native HWNDs as laid out (default).
    #[default]
    Normal,
    /// Modal menu / dialog / tooltip is open — hide or lower WebView2 children so
    /// GPUI chrome is visible and hittable.
    SuppressWebViewForChrome,
    /// Prefer raising surfaces of this kind (future: HWND_TOP among siblings).
    PreferKind(SurfaceKind),
}

/// Ref-counted suppress depth for overlay coordination (mirrors C# `RdpOverlayCoordinator`
/// for RDP; reused here as the WebView2 airspace suppress hook).
#[derive(Debug, Default)]
pub struct OverlayStackController {
    suppress_depth: u32,
    policy: OverlayStackPolicy,
}

impl OverlayStackController {
    /// Create a controller in the normal (non-suppressed) state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Current policy derived from suppress depth.
    pub fn policy(&self) -> OverlayStackPolicy {
        if self.suppress_depth > 0 {
            OverlayStackPolicy::SuppressWebViewForChrome
        } else {
            self.policy
        }
    }

    /// Enter a chrome overlay (menu / tooltip / dialog). Nested calls nest.
    pub fn push_chrome_overlay(&mut self) {
        self.suppress_depth = self.suppress_depth.saturating_add(1);
    }

    /// Leave a chrome overlay. No-op at zero.
    pub fn pop_chrome_overlay(&mut self) {
        self.suppress_depth = self.suppress_depth.saturating_sub(1);
    }

    /// True when WebView2 should be hidden / non-hit-test for chrome airspace.
    pub fn should_hide_webview(&self) -> bool {
        matches!(
            self.policy(),
            OverlayStackPolicy::SuppressWebViewForChrome
        )
    }

    /// Resolve effective WebView2 visibility for a layout tick.
    ///
    /// When chrome (menu / tooltip / dialog) is open, returns
    /// [`crate::SurfaceVisibility::Hidden`] even if the pane layout wants the
    /// surface visible — callers pass the result to
    /// `ChildWebViewHost::set_visible` (feature `webview`).
    pub fn effective_webview_visibility(
        &self,
        layout_wants_visible: bool,
    ) -> crate::SurfaceVisibility {
        if layout_wants_visible && !self.should_hide_webview() {
            crate::SurfaceVisibility::Visible
        } else {
            crate::SurfaceVisibility::Hidden
        }
    }

    /// Current suppress nesting depth (tests / diagnostics).
    pub fn suppress_depth(&self) -> u32 {
        self.suppress_depth
    }

    /// Set an explicit prefer-kind policy when not suppressed.
    pub fn set_idle_policy(&mut self, policy: OverlayStackPolicy) {
        if !matches!(policy, OverlayStackPolicy::SuppressWebViewForChrome) {
            self.policy = policy;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suppress_nests_and_clears() {
        let mut c = OverlayStackController::new();
        assert!(!c.should_hide_webview());
        c.push_chrome_overlay();
        assert!(c.should_hide_webview());
        c.push_chrome_overlay();
        assert!(c.should_hide_webview());
        c.pop_chrome_overlay();
        assert!(c.should_hide_webview());
        c.pop_chrome_overlay();
        assert!(!c.should_hide_webview());
    }

    #[test]
    fn effective_visibility_hides_while_chrome_open() {
        use crate::SurfaceVisibility;

        let mut c = OverlayStackController::new();
        assert_eq!(
            c.effective_webview_visibility(true),
            SurfaceVisibility::Visible
        );
        assert_eq!(
            c.effective_webview_visibility(false),
            SurfaceVisibility::Hidden
        );

        c.push_chrome_overlay();
        assert_eq!(
            c.effective_webview_visibility(true),
            SurfaceVisibility::Hidden
        );
        c.pop_chrome_overlay();
        assert_eq!(
            c.effective_webview_visibility(true),
            SurfaceVisibility::Visible
        );
        assert_eq!(c.suppress_depth(), 0);
    }

    #[test]
    fn pop_at_zero_is_idempotent() {
        let mut c = OverlayStackController::new();
        c.pop_chrome_overlay();
        c.pop_chrome_overlay();
        assert_eq!(c.suppress_depth(), 0);
        assert!(!c.should_hide_webview());
    }
}
