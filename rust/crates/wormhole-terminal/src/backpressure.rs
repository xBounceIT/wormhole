//! Output-pump backpressure hooks mirroring C# `TerminalBridge` watermarks.
//!
//! The full WebView pump lives outside this crate; these helpers let a host
//! apply the same high/low hysteresis before calling
//! [`crate::TerminalSession::pause_reading`] /
//! [`crate::TerminalSession::resume_reading`].

/// High watermark (queued + posted bytes not yet ACKed) — pause the producer.
pub const HIGH_WATERMARK_BYTES: usize = 512 * 1024;
/// Low watermark — resume after falling at/below this while paused.
pub const LOW_WATERMARK_BYTES: usize = 128 * 1024;
/// Frames at or below this size may skip coalesce windows (C# immediate path).
pub const IMMEDIATE_FRAME_THRESHOLD_BYTES: usize = 512;
/// Soft cap on pending host→page web messages (`MaximumPendingWebMessages`).
pub const MAX_PENDING_WEB_MESSAGES: usize = 4096;

/// Action a pump should take after updating outstanding byte credit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BackpressureAction {
    /// No producer state change.
    None,
    /// Call [`crate::TerminalSession::pause_reading`].
    Pause,
    /// Call [`crate::TerminalSession::resume_reading`].
    Resume,
}

/// Tracks outstanding host→page output bytes with high/low hysteresis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputBackpressure {
    outstanding_bytes: usize,
    paused: bool,
    high: usize,
    low: usize,
}

impl Default for OutputBackpressure {
    fn default() -> Self {
        Self::new()
    }
}

impl OutputBackpressure {
    /// Create with C# `TerminalBridge` watermarks.
    pub fn new() -> Self {
        Self::with_watermarks(HIGH_WATERMARK_BYTES, LOW_WATERMARK_BYTES)
    }

    /// Create with explicit watermarks (`high` must be strictly greater than `low`,
/// matching C# `TerminalOutputPump` construction).
    pub fn with_watermarks(high: usize, low: usize) -> Self {
        assert!(
            high > low,
            "low watermark must be strictly below the high watermark (high={high}, low={low})"
        );
        Self {
            outstanding_bytes: 0,
            paused: false,
            high,
            low,
        }
    }

    /// Bytes posted/queued that have not been ACKed (or cleared).
    pub fn outstanding_bytes(&self) -> usize {
        self.outstanding_bytes
    }

    /// Whether the last action left the producer paused.
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    /// Record a host→page output/replay frame being queued or posted.
    pub fn on_output_queued(&mut self, frame_bytes: usize) -> BackpressureAction {
        self.outstanding_bytes = self.outstanding_bytes.saturating_add(frame_bytes);
        if !self.paused && self.outstanding_bytes >= self.high {
            self.paused = true;
            BackpressureAction::Pause
        } else {
            BackpressureAction::None
        }
    }

    /// Record page ACK (`a:`) credit or equivalent release for `frame_bytes`.
    pub fn on_output_acked(&mut self, frame_bytes: usize) -> BackpressureAction {
        self.outstanding_bytes = self.outstanding_bytes.saturating_sub(frame_bytes);
        if self.paused && self.outstanding_bytes <= self.low {
            self.paused = false;
            BackpressureAction::Resume
        } else {
            BackpressureAction::None
        }
    }

    /// Drop all outstanding credit (ordered `clear:` / fatal recovery).
    pub fn reset(&mut self) -> BackpressureAction {
        self.outstanding_bytes = 0;
        if self.paused {
            self.paused = false;
            BackpressureAction::Resume
        } else {
            BackpressureAction::None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hysteresis_pauses_at_high_and_resumes_at_low() {
        let mut bp = OutputBackpressure::with_watermarks(100, 40);
        assert_eq!(bp.on_output_queued(50), BackpressureAction::None);
        assert_eq!(bp.on_output_queued(50), BackpressureAction::Pause);
        assert!(bp.is_paused());
        assert_eq!(bp.on_output_acked(10), BackpressureAction::None);
        assert!(bp.is_paused());
        assert_eq!(bp.on_output_acked(50), BackpressureAction::Resume);
        assert!(!bp.is_paused());
        assert_eq!(bp.outstanding_bytes(), 40);
    }

    #[test]
    fn reset_releases_paused_producer() {
        let mut bp = OutputBackpressure::with_watermarks(10, 5);
        assert_eq!(bp.on_output_queued(10), BackpressureAction::Pause);
        assert_eq!(bp.reset(), BackpressureAction::Resume);
        assert_eq!(bp.outstanding_bytes(), 0);
        assert!(!bp.is_paused());
    }

    #[test]
    fn default_watermarks_match_csharp_bridge() {
        assert_eq!(HIGH_WATERMARK_BYTES, 512 * 1024);
        assert_eq!(LOW_WATERMARK_BYTES, 128 * 1024);
        assert_eq!(IMMEDIATE_FRAME_THRESHOLD_BYTES, 512);
        assert_eq!(MAX_PENDING_WEB_MESSAGES, 4096);
        let bp = OutputBackpressure::new();
        assert_eq!(bp.high, HIGH_WATERMARK_BYTES);
        assert_eq!(bp.low, LOW_WATERMARK_BYTES);
    }

    #[test]
    fn pause_at_exact_high_and_resume_at_exact_low() {
        let mut bp = OutputBackpressure::with_watermarks(100, 40);
        assert_eq!(bp.on_output_queued(99), BackpressureAction::None);
        assert_eq!(bp.on_output_queued(1), BackpressureAction::Pause);
        assert_eq!(bp.on_output_acked(60), BackpressureAction::Resume);
        assert_eq!(bp.outstanding_bytes(), 40);
        // Re-pause after climbing back to high.
        assert_eq!(bp.on_output_queued(60), BackpressureAction::Pause);
    }

    #[test]
    fn ack_past_zero_saturates_and_can_resume() {
        let mut bp = OutputBackpressure::with_watermarks(10, 5);
        assert_eq!(bp.on_output_queued(10), BackpressureAction::Pause);
        assert_eq!(bp.on_output_acked(50), BackpressureAction::Resume);
        assert_eq!(bp.outstanding_bytes(), 0);
        assert_eq!(bp.on_output_acked(1), BackpressureAction::None);
        assert_eq!(bp.outstanding_bytes(), 0);
    }

    #[test]
    #[should_panic(expected = "low watermark must be strictly below")]
    fn rejects_collapsed_watermarks() {
        let _ = OutputBackpressure::with_watermarks(10, 10);
    }
}
