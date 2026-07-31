//! Optional `vnc-rs` engine presence (feature `engine`).
//!
//! Live connect/poll wiring is deferred; this marker proves the dependency
//! unifies when agents enable the feature for spikes. Call sites that need the
//! real client should gate on `cfg(feature = "engine")` and use
//! [`VncRsEngineMarker::crate_linked`].

/// Linked when `--features engine` is on.
#[derive(Debug, Clone, Copy, Default)]
pub struct VncRsEngineMarker;

impl VncRsEngineMarker {
    /// Touch a `vnc-rs` type so the optional dep stays linked under `engine`.
    pub fn crate_linked() -> bool {
        let _ = std::any::type_name::<vnc::VncEncoding>();
        true
    }

    /// Placeholder for a future connect path; today always reports not wired.
    pub fn live_client_available() -> bool {
        // Presence-only: Raw decode + input queue live in the default build;
        // TCP/encoding engines remain unimplemented here.
        Self::crate_linked() && false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_feature_links_vnc_rs() {
        assert!(VncRsEngineMarker::crate_linked());
        assert!(!VncRsEngineMarker::live_client_available());
    }
}
