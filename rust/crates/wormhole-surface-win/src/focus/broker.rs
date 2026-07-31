//! [`FocusBroker`] — coordinates focus owner + RDP one-shot latch.

use super::ops::{FocusError, FocusHwnd, FocusOps};

/// Logical focus owner in the GPUI + native-surface model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FocusOwner {
    /// GPUI chrome (connection tree, tabs, menus, dialogs).
    GpuiChrome,
    /// WebView2 child (terminal / HTTP browser).
    WebView2,
    /// RDP ActiveX — focus target must be the **AxHost child** HWND, not the overlay form alone.
    RdpActiveX,
}

impl FocusOwner {
    /// Human-readable label for logs / lab output.
    pub fn label(self) -> &'static str {
        match self {
            Self::GpuiChrome => "GPUI",
            Self::WebView2 => "WebView2",
            Self::RdpActiveX => "RdpActiveX",
        }
    }
}

/// Why focus is being requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FocusReason {
    /// User click / Tab into a surface.
    UserHandoff,
    /// Cold connect or user Retry — may push RDP focus once.
    ColdConnect,
    /// Restore after modal dialog / chrome overlay dismissed.
    RestoreAfterDialog,
    /// Explicit shell API (tests / lab).
    Explicit,
}

/// How an RDP Connected transition should treat focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RdpConnectKind {
    /// First Connected after connect / Retry — allow one-shot focus push.
    ColdOrRetry,
    /// `OnAutoReconnected` — must **not** steal keyboard focus.
    AutoReconnected,
}

/// Request payload for [`FocusBroker::request_focus`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FocusRequest {
    /// Logical owner after a successful handoff.
    pub owner: FocusOwner,
    /// Native HWND to `SetFocus`, when applicable.
    ///
    /// - [`FocusOwner::RdpActiveX`]: AxHost child (required for a Win32 push).
    /// - [`FocusOwner::WebView2`]: child controller HWND when known; optional if the
    ///   host uses wry `focus()` separately.
    /// - [`FocusOwner::GpuiChrome`]: optional main-window HWND; broker may track owner only.
    pub hwnd: Option<FocusHwnd>,
    /// Why this handoff is happening.
    pub reason: FocusReason,
}

/// Outcome of a broker decision (before or after Win32).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FocusAction {
    /// Focus was applied (or GPUI-only owner update with no HWND).
    Applied {
        /// New logical owner.
        owner: FocusOwner,
        /// HWND that received SetFocus, if any.
        hwnd: Option<FocusHwnd>,
        /// Previous Win32 focus, when SetFocus ran.
        previous: Option<FocusHwnd>,
    },
    /// Intentionally skipped (auto-reconnect, latch, missing HWND, etc.).
    Skipped {
        /// Short reason for lab / diagnostics.
        reason: &'static str,
    },
    /// Rejected / failed.
    Failed(FocusError),
}

/// Coordinates focus among GPUI, WebView2, and RDP with C# latch semantics.
#[derive(Debug)]
pub struct FocusBroker<O: FocusOps> {
    ops: O,
    owner: Option<FocusOwner>,
    /// C# `RdpSurfaceHost._focusPushed` — one-shot cold-connect latch.
    rdp_focus_pushed: bool,
}

impl<O: FocusOps> FocusBroker<O> {
    /// Wrap focus ops (Win32 or recorder).
    pub fn new(ops: O) -> Self {
        Self {
            ops,
            owner: None,
            rdp_focus_pushed: false,
        }
    }

    /// Current logical owner, if any.
    pub fn owner(&self) -> Option<FocusOwner> {
        self.owner
    }

    /// Whether the RDP cold-connect focus latch is set.
    pub fn rdp_focus_pushed(&self) -> bool {
        self.rdp_focus_pushed
    }

    /// Borrow the underlying ops (tests / diagnostics).
    pub fn ops(&self) -> &O {
        &self.ops
    }

    /// Mutable borrow of ops.
    pub fn ops_mut(&mut self) -> &mut O {
        &mut self.ops
    }

    /// Request focus for a surface or chrome.
    ///
    /// Rejects null HWNDs before calling [`FocusOps::set_focus`]. GPUI chrome may
    /// omit an HWND and only update the logical owner. [`FocusReason`] is carried for
    /// callers/diagnostics; latch / auto-reconnect policy lives in
    /// [`Self::on_rdp_connected`].
    pub fn request_focus(&mut self, req: FocusRequest) -> FocusAction {
        if let Some(hwnd) = req.hwnd {
            if hwnd.is_null() {
                return FocusAction::Failed(FocusError::NullHwndRejected);
            }
        }

        match req.owner {
            FocusOwner::GpuiChrome => {
                if let Some(hwnd) = req.hwnd {
                    match self.ops.set_focus(hwnd) {
                        Ok(previous) => {
                            self.owner = Some(FocusOwner::GpuiChrome);
                            FocusAction::Applied {
                                owner: FocusOwner::GpuiChrome,
                                hwnd: Some(hwnd),
                                previous,
                            }
                        }
                        Err(e) => FocusAction::Failed(e),
                    }
                } else {
                    self.owner = Some(FocusOwner::GpuiChrome);
                    FocusAction::Applied {
                        owner: FocusOwner::GpuiChrome,
                        hwnd: None,
                        previous: None,
                    }
                }
            }
            FocusOwner::WebView2 => {
                let Some(hwnd) = req.hwnd else {
                    // Shell may call wry `focus()` without an HWND; still record owner.
                    self.owner = Some(FocusOwner::WebView2);
                    return FocusAction::Applied {
                        owner: FocusOwner::WebView2,
                        hwnd: None,
                        previous: None,
                    };
                };
                match self.ops.set_focus(hwnd) {
                    Ok(previous) => {
                        self.owner = Some(FocusOwner::WebView2);
                        FocusAction::Applied {
                            owner: FocusOwner::WebView2,
                            hwnd: Some(hwnd),
                            previous,
                        }
                    }
                    Err(e) => FocusAction::Failed(e),
                }
            }
            FocusOwner::RdpActiveX => {
                let Some(hwnd) = req.hwnd else {
                    return FocusAction::Skipped {
                        reason: "RDP focus requires AxHost child HWND",
                    };
                };
                match self.ops.set_focus(hwnd) {
                    Ok(previous) => {
                        self.owner = Some(FocusOwner::RdpActiveX);
                        FocusAction::Applied {
                            owner: FocusOwner::RdpActiveX,
                            hwnd: Some(hwnd),
                            previous,
                        }
                    }
                    Err(e) => FocusAction::Failed(e),
                }
            }
        }
    }

    /// Handle an RDP `IsConnected=true` transition (cold vs auto-reconnect).
    ///
    /// # Cold-connect order
    ///
    /// Callers should focus chrome first (optional), then call this with the
    /// AxHost child HWND. Latch is set only after a successful cold/Retry push.
    ///
    /// # Auto-reconnect
    ///
    /// [`RdpConnectKind::AutoReconnected`] always returns [`FocusAction::Skipped`]
    /// by kind (C# `OnSessionAutoReconnected` never calls `TryFocusSession`). The
    /// latch is a separate one-shot for duplicate [`RdpConnectKind::ColdOrRetry`]
    /// within the same connect lifecycle — it is not what skips auto-reconnect.
    pub fn on_rdp_connected(
        &mut self,
        ax_host_child: FocusHwnd,
        kind: RdpConnectKind,
    ) -> FocusAction {
        match kind {
            RdpConnectKind::AutoReconnected => FocusAction::Skipped {
                reason: "auto-reconnect must not steal focus",
            },
            RdpConnectKind::ColdOrRetry => {
                if self.rdp_focus_pushed {
                    return FocusAction::Skipped {
                        reason: "RDP focus already pushed for this connect lifecycle",
                    };
                }
                let action = self.request_focus(FocusRequest {
                    owner: FocusOwner::RdpActiveX,
                    hwnd: Some(ax_host_child),
                    reason: FocusReason::ColdConnect,
                });
                // Only burn the one-shot on Applied — a Failed/Skipped push must
                // leave the latch clear so Retry can try again (C# TryFocusHost).
                if matches!(action, FocusAction::Applied { .. }) {
                    self.rdp_focus_pushed = true;
                }
                action
            }
        }
    }

    /// Clear the RDP focus latch on terminal teardown only.
    ///
    /// Pass `true` for `Disconnected` / `Failed`. Pass `false` for transient
    /// `Connecting` during auto-reconnect (preserves the latch).
    pub fn on_rdp_session_not_connected(&mut self, terminal: bool) {
        if terminal {
            self.rdp_focus_pushed = false;
        }
    }
}

impl Default for FocusBroker<super::ops::RecordingFocusOps> {
    fn default() -> Self {
        Self::new(super::ops::RecordingFocusOps::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::focus::RecordingFocusOps;

    #[test]
    fn cold_connect_pushes_once_auto_reconnect_skips() {
        let mut broker = FocusBroker::new(RecordingFocusOps::new());
        let child = FocusHwnd(0xABC);

        let first = broker.on_rdp_connected(child, RdpConnectKind::ColdOrRetry);
        assert!(matches!(
            first,
            FocusAction::Applied {
                owner: FocusOwner::RdpActiveX,
                hwnd: Some(FocusHwnd(0xABC)),
                ..
            }
        ));
        assert!(broker.rdp_focus_pushed());
        assert_eq!(broker.ops().set_calls, vec![child]);

        let again = broker.on_rdp_connected(child, RdpConnectKind::ColdOrRetry);
        assert_eq!(
            again,
            FocusAction::Skipped {
                reason: "RDP focus already pushed for this connect lifecycle"
            }
        );

        let auto = broker.on_rdp_connected(child, RdpConnectKind::AutoReconnected);
        assert_eq!(
            auto,
            FocusAction::Skipped {
                reason: "auto-reconnect must not steal focus"
            }
        );
        assert_eq!(broker.ops().set_calls.len(), 1);
        assert!(broker.rdp_focus_pushed());
    }

    #[test]
    fn connecting_preserves_latch_terminal_clears() {
        let mut broker = FocusBroker::new(RecordingFocusOps::new());
        let child = FocusHwnd(0x100);
        let _ = broker.on_rdp_connected(child, RdpConnectKind::ColdOrRetry);
        assert!(broker.rdp_focus_pushed());

        // Transient Connecting (auto-reconnect) — do not clear.
        broker.on_rdp_session_not_connected(false);
        assert!(broker.rdp_focus_pushed());

        broker.on_rdp_session_not_connected(true);
        assert!(!broker.rdp_focus_pushed());

        let retry = broker.on_rdp_connected(child, RdpConnectKind::ColdOrRetry);
        assert!(matches!(retry, FocusAction::Applied { .. }));
        assert_eq!(broker.ops().set_calls.len(), 2);
    }

    #[test]
    fn gpui_owner_without_hwnd() {
        let mut broker = FocusBroker::new(RecordingFocusOps::new());
        let action = broker.request_focus(FocusRequest {
            owner: FocusOwner::GpuiChrome,
            hwnd: None,
            reason: FocusReason::UserHandoff,
        });
        assert_eq!(
            action,
            FocusAction::Applied {
                owner: FocusOwner::GpuiChrome,
                hwnd: None,
                previous: None,
            }
        );
        assert_eq!(broker.owner(), Some(FocusOwner::GpuiChrome));
        assert!(broker.ops().set_calls.is_empty());
    }

    #[test]
    fn webview_and_rdp_handoff() {
        let mut broker = FocusBroker::new(RecordingFocusOps::new());
        let web = FocusHwnd(0x200);
        let rdp = FocusHwnd(0x300);

        let a = broker.request_focus(FocusRequest {
            owner: FocusOwner::WebView2,
            hwnd: Some(web),
            reason: FocusReason::UserHandoff,
        });
        assert!(matches!(a, FocusAction::Applied { owner: FocusOwner::WebView2, .. }));

        let b = broker.request_focus(FocusRequest {
            owner: FocusOwner::RdpActiveX,
            hwnd: Some(rdp),
            reason: FocusReason::UserHandoff,
        });
        assert!(matches!(b, FocusAction::Applied { owner: FocusOwner::RdpActiveX, .. }));
        assert_eq!(broker.ops().set_calls, vec![web, rdp]);
        assert_eq!(broker.ops().current, Some(rdp));
    }

    #[test]
    fn recording_ops_reject_null() {
        let mut ops = RecordingFocusOps::new();
        assert_eq!(
            ops.set_focus(FocusHwnd(0)),
            Err(FocusError::NullHwndRejected)
        );
    }

    #[test]
    fn cold_connect_null_hwnd_rejects_without_latch() {
        let mut broker = FocusBroker::new(RecordingFocusOps::new());
        let action = broker.on_rdp_connected(FocusHwnd(0), RdpConnectKind::ColdOrRetry);
        assert_eq!(action, FocusAction::Failed(FocusError::NullHwndRejected));
        assert!(!broker.rdp_focus_pushed());
        assert!(broker.ops().set_calls.is_empty());
        assert_eq!(broker.owner(), None);
    }

    #[test]
    fn failed_set_focus_does_not_latch_retry_can_push() {
        let mut ops = RecordingFocusOps::new();
        ops.fail_next = true;
        let mut broker = FocusBroker::new(ops);
        let child = FocusHwnd(0x400);

        let failed = broker.on_rdp_connected(child, RdpConnectKind::ColdOrRetry);
        assert!(matches!(failed, FocusAction::Failed(FocusError::SetFocusFailed { .. })));
        assert!(!broker.rdp_focus_pushed());
        assert!(broker.ops().set_calls.is_empty());

        let retry = broker.on_rdp_connected(child, RdpConnectKind::ColdOrRetry);
        assert!(matches!(retry, FocusAction::Applied { .. }));
        assert!(broker.rdp_focus_pushed());
        assert_eq!(broker.ops().set_calls, vec![child]);
    }

    #[test]
    fn auto_reconnect_before_cold_skips_without_ops() {
        let mut broker = FocusBroker::new(RecordingFocusOps::new());
        let action = broker.on_rdp_connected(FocusHwnd(0x500), RdpConnectKind::AutoReconnected);
        assert_eq!(
            action,
            FocusAction::Skipped {
                reason: "auto-reconnect must not steal focus"
            }
        );
        assert!(!broker.rdp_focus_pushed());
        assert!(broker.ops().set_calls.is_empty());
        assert_eq!(broker.owner(), None);

        // Kind short-circuits before HWND validation — null must not become SetFocus(NULL).
        let null_auto = broker.on_rdp_connected(FocusHwnd(0), RdpConnectKind::AutoReconnected);
        assert_eq!(
            null_auto,
            FocusAction::Skipped {
                reason: "auto-reconnect must not steal focus"
            }
        );
        assert!(broker.ops().set_calls.is_empty());
    }

    #[test]
    fn chrome_handoff_does_not_clear_rdp_latch() {
        let mut broker = FocusBroker::new(RecordingFocusOps::new());
        let child = FocusHwnd(0x600);
        let _ = broker.on_rdp_connected(child, RdpConnectKind::ColdOrRetry);
        assert!(broker.rdp_focus_pushed());

        let _ = broker.request_focus(FocusRequest {
            owner: FocusOwner::GpuiChrome,
            hwnd: None,
            reason: FocusReason::UserHandoff,
        });
        assert_eq!(broker.owner(), Some(FocusOwner::GpuiChrome));
        assert!(broker.rdp_focus_pushed());

        let auto = broker.on_rdp_connected(child, RdpConnectKind::AutoReconnected);
        assert_eq!(
            auto,
            FocusAction::Skipped {
                reason: "auto-reconnect must not steal focus"
            }
        );
        // Duplicate cold still blocked by latch (C#: only terminal teardown clears).
        let again = broker.on_rdp_connected(child, RdpConnectKind::ColdOrRetry);
        assert_eq!(
            again,
            FocusAction::Skipped {
                reason: "RDP focus already pushed for this connect lifecycle"
            }
        );
        assert_eq!(broker.ops().set_calls.len(), 1);
    }

    #[test]
    fn explicit_rdp_request_does_not_set_latch() {
        let mut broker = FocusBroker::new(RecordingFocusOps::new());
        let child = FocusHwnd(0x700);
        let action = broker.request_focus(FocusRequest {
            owner: FocusOwner::RdpActiveX,
            hwnd: Some(child),
            reason: FocusReason::UserHandoff,
        });
        assert!(matches!(action, FocusAction::Applied { .. }));
        assert!(
            !broker.rdp_focus_pushed(),
            "latch is only for on_rdp_connected ColdOrRetry"
        );

        // Cold connect still allowed once (user click must not burn the one-shot).
        let cold = broker.on_rdp_connected(child, RdpConnectKind::ColdOrRetry);
        assert!(matches!(cold, FocusAction::Applied { .. }));
        assert!(broker.rdp_focus_pushed());
        assert_eq!(broker.ops().set_calls.len(), 2);
    }

    #[test]
    fn rdp_without_hwnd_skipped_webview_without_hwnd_applied() {
        let mut broker = FocusBroker::new(RecordingFocusOps::new());

        let rdp = broker.request_focus(FocusRequest {
            owner: FocusOwner::RdpActiveX,
            hwnd: None,
            reason: FocusReason::Explicit,
        });
        assert_eq!(
            rdp,
            FocusAction::Skipped {
                reason: "RDP focus requires AxHost child HWND"
            }
        );
        assert_eq!(broker.owner(), None);

        let web = broker.request_focus(FocusRequest {
            owner: FocusOwner::WebView2,
            hwnd: None,
            reason: FocusReason::UserHandoff,
        });
        assert_eq!(
            web,
            FocusAction::Applied {
                owner: FocusOwner::WebView2,
                hwnd: None,
                previous: None,
            }
        );
        assert_eq!(broker.owner(), Some(FocusOwner::WebView2));
        assert!(broker.ops().set_calls.is_empty());
    }

    #[test]
    fn null_hwnd_rejected_for_all_owners() {
        let mut broker = FocusBroker::new(RecordingFocusOps::new());
        for owner in [
            FocusOwner::GpuiChrome,
            FocusOwner::WebView2,
            FocusOwner::RdpActiveX,
        ] {
            let action = broker.request_focus(FocusRequest {
                owner,
                hwnd: Some(FocusHwnd(0)),
                reason: FocusReason::Explicit,
            });
            assert_eq!(
                action,
                FocusAction::Failed(FocusError::NullHwndRejected),
                "{owner:?}"
            );
        }
        assert!(broker.ops().set_calls.is_empty());
        assert_eq!(broker.owner(), None);
    }

    #[test]
    fn auto_reconnect_never_mutates_latch_or_owner() {
        let mut broker = FocusBroker::new(RecordingFocusOps::new());
        let child = FocusHwnd(0x800);
        let _ = broker.on_rdp_connected(child, RdpConnectKind::ColdOrRetry);
        let owner_before = broker.owner();
        assert!(broker.rdp_focus_pushed());

        broker.on_rdp_session_not_connected(false); // transient Connecting
        let skipped = broker.on_rdp_connected(child, RdpConnectKind::AutoReconnected);
        assert!(matches!(skipped, FocusAction::Skipped { .. }));
        assert!(broker.rdp_focus_pushed());
        assert_eq!(broker.owner(), owner_before);
        assert_eq!(broker.ops().set_calls.len(), 1);
    }
}
