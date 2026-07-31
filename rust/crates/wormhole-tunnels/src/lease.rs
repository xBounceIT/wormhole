use std::fmt;
use std::sync::Arc;

use crate::traits::TunnelInstance;

/// Lease over a shared [`TunnelInstance`]. Dropping (or calling [`TunnelLease::release`])
/// decrements the manager ref-count; the real tunnel closes when the last lease is gone.
pub struct TunnelLease {
    pub(crate) instance: Arc<dyn TunnelInstance>,
    pub(crate) on_release: Option<Box<dyn FnOnce() + Send + Sync>>,
}

impl fmt::Debug for TunnelLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Counts only — never dump instance/provider internals (tests may plant markers).
        f.debug_struct("TunnelLease")
            .field("armed", &self.on_release.is_some())
            .finish_non_exhaustive()
    }
}

impl TunnelLease {
    pub fn instance(&self) -> &Arc<dyn TunnelInstance> {
        &self.instance
    }

    /// Explicit release (preferred in async code). Equivalent to dropping the lease.
    pub fn release(mut self) {
        if let Some(f) = self.on_release.take() {
            f();
        }
    }
}

impl Drop for TunnelLease {
    fn drop(&mut self) {
        if let Some(f) = self.on_release.take() {
            f();
        }
    }
}
