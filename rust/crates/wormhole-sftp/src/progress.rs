//! Transfer progress callback glue — cumulative bytes → strip snapshot.
//!
//! Mirrors C# `IProgress<long>` wiring in `SftpSession` / `FileTransferOrchestrator`
//! plus `TransferItemViewModel.ProgressFraction`:
//! - SSH.NET reports **cumulative** transferred bytes on each callback.
//! - Expected size may be unknown (`None` / non-positive) → no percent.
//! - Cancel is checked on every report (parity with
//!   `cancellationToken.ThrowIfCancellationRequested` inside the C# callback).
//!
//! Nonsense inputs (negative signed counts, arithmetic overflow when deriving
//! percent) **fail closed**. Snapshots / errors / `Debug` carry sizes only —
//! never paths, credentials, or free-form backend text.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

/// Sanitized progress snapshot for the transfer strip / host binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferProgress {
    pub bytes_transferred: u64,
    /// `None` when total is unknown or non-positive (C# `ExpectedBytes <= 0`).
    pub total_bytes: Option<u64>,
    /// `Some(0..=100)` only when [`Self::total_bytes`] is `Some(t)` with `t > 0`.
    /// Clamped to 100 when transferred exceeds total (sparse / EOF-before-stat).
    pub percent: Option<u8>,
}

/// Failures from progress normalization or a cancel-aware report.
///
/// Display / Debug never include paths or credential-shaped text.
#[derive(Clone, PartialEq, Eq)]
pub enum TransferProgressError {
    /// Caller cancelled mid-transfer (checked before applying a report).
    Cancelled,
    /// Negative counts or overflow deriving percent — fail closed.
    Invalid,
}

impl fmt::Display for TransferProgressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => f.write_str("transfer cancelled"),
            Self::Invalid => f.write_str("invalid transfer progress"),
        }
    }
}

impl fmt::Debug for TransferProgressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => f.write_str("Cancelled"),
            Self::Invalid => f.write_str("Invalid"),
        }
    }
}

impl std::error::Error for TransferProgressError {}

/// Sink that receives sanitized progress snapshots (no credential logging).
pub trait TransferProgressCallback: Send {
    fn on_progress(&mut self, progress: TransferProgress) -> Result<(), TransferProgressError>;
}

/// Recording sink for unit tests / Fake transfers.
#[derive(Debug, Default)]
pub struct RecordingProgressCallback {
    pub reports: Vec<TransferProgress>,
}

impl TransferProgressCallback for RecordingProgressCallback {
    fn on_progress(&mut self, progress: TransferProgress) -> Result<(), TransferProgressError> {
        self.reports.push(progress);
        Ok(())
    }
}

/// Normalize a cumulative byte report into a strip snapshot.
///
/// Signed inputs mirror the C# `long` / `IProgress<long>` surface so negatives
/// can be rejected. `total_bytes == Some(0)` or `None` → unknown (no percent).
///
/// `cancelled == true` → [`TransferProgressError::Cancelled`] without producing
/// a snapshot (fail closed).
pub fn report_progress(
    bytes_transferred: i64,
    total_bytes: Option<i64>,
    cancelled: bool,
) -> Result<TransferProgress, TransferProgressError> {
    if cancelled {
        return Err(TransferProgressError::Cancelled);
    }
    if bytes_transferred < 0 {
        return Err(TransferProgressError::Invalid);
    }
    let transferred = bytes_transferred as u64;

    let total = match total_bytes {
        None => None,
        Some(t) if t < 0 => return Err(TransferProgressError::Invalid),
        Some(0) => None,
        Some(t) => Some(t as u64),
    };

    let percent = match total {
        Some(t) if t > 0 => {
            // Fail closed on mul overflow; clamp display to 100 when transferred > total
            // (parity with C# `Math.Clamp(..., 0, 1)`). `t > 0` so plain `/` is safe.
            let pct = transferred
                .checked_mul(100)
                .ok_or(TransferProgressError::Invalid)?
                / t;
            Some(pct.min(100) as u8)
        }
        _ => None,
    };

    Ok(TransferProgress {
        bytes_transferred: transferred,
        total_bytes: total,
        percent,
    })
}

/// Report through a callback after normalizing; cancel flag checked first.
pub fn report_to_callback(
    bytes_transferred: i64,
    total_bytes: Option<i64>,
    cancelled: &AtomicBool,
    callback: &mut dyn TransferProgressCallback,
) -> Result<TransferProgress, TransferProgressError> {
    let progress = report_progress(
        bytes_transferred,
        total_bytes,
        cancelled.load(Ordering::SeqCst),
    )?;
    callback.on_progress(progress)?;
    Ok(progress)
}

/// Drive a Fake chunked transfer (no network / no live SFTP).
///
/// Emits one cumulative report after each chunk until `fake_payload_len` bytes
/// are "sent" (last report equals `fake_payload_len`, which may be below or above
/// a known `total_bytes` — percent clamps at 100 when transferred exceeds total).
/// Cancel is checked before every chunk; mid-transfer cancel returns
/// [`TransferProgressError::Cancelled`] and stops further reports.
///
/// `total_bytes == None` or `Some(0)` → unknown size (no percent). Totals that do
/// not fit signed `i64` (C# `long`) fail closed as [`TransferProgressError::Invalid`].
pub fn run_fake_transfer(
    total_bytes: Option<u64>,
    chunk_size: u64,
    fake_payload_len: u64,
    cancelled: &AtomicBool,
    callback: &mut dyn TransferProgressCallback,
) -> Result<TransferProgress, TransferProgressError> {
    if chunk_size == 0 {
        return Err(TransferProgressError::Invalid);
    }

    let signed_total = match total_bytes {
        None => None,
        Some(t) => {
            let t = i64::try_from(t).map_err(|_| TransferProgressError::Invalid)?;
            Some(t)
        }
    };

    let mut transferred: u64 = 0;
    let mut last = TransferProgress {
        bytes_transferred: 0,
        total_bytes: None,
        percent: None,
    };

    while transferred < fake_payload_len {
        if cancelled.load(Ordering::SeqCst) {
            return Err(TransferProgressError::Cancelled);
        }
        let remaining = fake_payload_len - transferred;
        let step = remaining.min(chunk_size);
        transferred = transferred
            .checked_add(step)
            .ok_or(TransferProgressError::Invalid)?;

        let signed = i64::try_from(transferred).map_err(|_| TransferProgressError::Invalid)?;
        last = report_to_callback(signed, signed_total, cancelled, callback)?;
    }

    // Empty payload: still emit a single 0-byte report (bar stays empty unless Completed snap).
    if fake_payload_len == 0 {
        last = report_to_callback(0, signed_total, cancelled, callback)?;
    }

    Ok(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_total_reports_percent() {
        let p = report_progress(50, Some(200), false).unwrap();
        assert_eq!(p.bytes_transferred, 50);
        assert_eq!(p.total_bytes, Some(200));
        assert_eq!(p.percent, Some(25));
    }

    #[test]
    fn unknown_and_zero_total_omit_percent() {
        let unknown = report_progress(10, None, false).unwrap();
        assert_eq!(unknown.total_bytes, None);
        assert_eq!(unknown.percent, None);

        let zero = report_progress(10, Some(0), false).unwrap();
        assert_eq!(zero.total_bytes, None);
        assert_eq!(zero.percent, None);
    }

    #[test]
    fn clamp_percent_when_transferred_exceeds_total() {
        let p = report_progress(150, Some(100), false).unwrap();
        assert_eq!(p.percent, Some(100));
    }

    #[test]
    fn negative_transferred_or_total_fail_closed() {
        assert_eq!(
            report_progress(-1, Some(100), false),
            Err(TransferProgressError::Invalid)
        );
        assert_eq!(
            report_progress(10, Some(-5), false),
            Err(TransferProgressError::Invalid)
        );
    }

    #[test]
    fn cancel_fail_closed_before_snapshot() {
        assert_eq!(
            report_progress(10, Some(100), true),
            Err(TransferProgressError::Cancelled)
        );
    }

    #[test]
    fn cancel_takes_precedence_over_invalid_counts() {
        // Cancel is checked before signed validation so a raced cancel does not
        // surface as Invalid.
        assert_eq!(
            report_progress(-1, Some(-5), true),
            Err(TransferProgressError::Cancelled)
        );
    }

    #[test]
    fn exact_zero_and_hundred_percent() {
        let zero = report_progress(0, Some(100), false).unwrap();
        assert_eq!(zero.percent, Some(0));
        assert_eq!(zero.bytes_transferred, 0);

        let done = report_progress(100, Some(100), false).unwrap();
        assert_eq!(done.percent, Some(100));
        assert_eq!(done.total_bytes, Some(100));
    }

    #[test]
    fn percent_mul_overflow_fail_closed() {
        // transferred * 100 overflows u64 → Invalid (not a wrapping percent).
        let huge = i64::MAX;
        assert_eq!(
            report_progress(huge, Some(1), false),
            Err(TransferProgressError::Invalid)
        );
    }

    #[test]
    fn report_to_callback_respects_cancel_flag() {
        let cancel = AtomicBool::new(true);
        let mut rec = RecordingProgressCallback::default();
        assert_eq!(
            report_to_callback(10, Some(100), &cancel, &mut rec),
            Err(TransferProgressError::Cancelled)
        );
        assert!(rec.reports.is_empty());
    }

    #[test]
    fn report_to_callback_skips_sink_on_invalid() {
        let cancel = AtomicBool::new(false);
        let mut rec = RecordingProgressCallback::default();
        assert_eq!(
            report_to_callback(-1, Some(100), &cancel, &mut rec),
            Err(TransferProgressError::Invalid)
        );
        assert!(rec.reports.is_empty());
    }

    #[test]
    fn error_display_has_no_credential_shaped_text() {
        for err in [
            TransferProgressError::Cancelled,
            TransferProgressError::Invalid,
        ] {
            let s = format!("{err}");
            let d = format!("{err:?}");
            for marker in ["password", "secret", "token", "key", "credential"] {
                assert!(!s.to_ascii_lowercase().contains(marker));
                assert!(!d.to_ascii_lowercase().contains(marker));
            }
        }
    }

    #[test]
    fn fake_transfer_emits_cumulative_chunks() {
        let cancel = AtomicBool::new(false);
        let mut rec = RecordingProgressCallback::default();
        let last = run_fake_transfer(Some(100), 40, 100, &cancel, &mut rec).unwrap();
        assert_eq!(last.bytes_transferred, 100);
        assert_eq!(last.percent, Some(100));
        assert_eq!(
            rec.reports
                .iter()
                .map(|r| r.bytes_transferred)
                .collect::<Vec<_>>(),
            vec![40, 80, 100]
        );
        assert_eq!(rec.reports[0].percent, Some(40));
        assert_eq!(rec.reports[1].percent, Some(80));
    }

    #[test]
    fn fake_transfer_unknown_total_omits_percent() {
        let cancel = AtomicBool::new(false);
        let mut rec = RecordingProgressCallback::default();
        let last = run_fake_transfer(None, 30, 60, &cancel, &mut rec).unwrap();
        assert_eq!(last.bytes_transferred, 60);
        assert!(rec.reports.iter().all(|r| r.percent.is_none()));
        assert!(rec.reports.iter().all(|r| r.total_bytes.is_none()));
    }

    #[test]
    fn fake_transfer_payload_below_total_does_not_force_final_snap() {
        // Doc contract: reports stop at fake_payload_len — no extra snap to total.
        let cancel = AtomicBool::new(false);
        let mut rec = RecordingProgressCallback::default();
        let last = run_fake_transfer(Some(100), 30, 60, &cancel, &mut rec).unwrap();
        assert_eq!(last.bytes_transferred, 60);
        assert_eq!(last.percent, Some(60));
        assert_eq!(
            rec.reports
                .iter()
                .map(|r| r.bytes_transferred)
                .collect::<Vec<_>>(),
            vec![30, 60]
        );
    }

    #[test]
    fn fake_transfer_cancel_mid_chunk_stops() {
        let cancel = AtomicBool::new(false);
        let mut rec = CancellingAfter {
            after: 1,
            cancel: &cancel,
            inner: RecordingProgressCallback::default(),
        };
        let err = run_fake_transfer(Some(100), 25, 100, &cancel, &mut rec).unwrap_err();
        assert_eq!(err, TransferProgressError::Cancelled);
        assert_eq!(rec.inner.reports.len(), 1);
        assert_eq!(rec.inner.reports[0].bytes_transferred, 25);
    }

    #[test]
    fn fake_transfer_zero_chunk_fail_closed() {
        let cancel = AtomicBool::new(false);
        let mut rec = RecordingProgressCallback::default();
        assert_eq!(
            run_fake_transfer(Some(10), 0, 10, &cancel, &mut rec),
            Err(TransferProgressError::Invalid)
        );
        assert!(rec.reports.is_empty());
    }

    #[test]
    fn fake_transfer_total_above_i64_max_fail_closed() {
        let cancel = AtomicBool::new(false);
        let mut rec = RecordingProgressCallback::default();
        let too_wide = (i64::MAX as u64).saturating_add(1);
        assert_eq!(
            run_fake_transfer(Some(too_wide), 64, 64, &cancel, &mut rec),
            Err(TransferProgressError::Invalid)
        );
        assert!(rec.reports.is_empty());
    }

    #[test]
    fn fake_empty_payload_emits_zero_report() {
        let cancel = AtomicBool::new(false);
        let mut rec = RecordingProgressCallback::default();
        let last = run_fake_transfer(Some(0), 64, 0, &cancel, &mut rec).unwrap();
        assert_eq!(last.bytes_transferred, 0);
        assert_eq!(last.total_bytes, None);
        assert_eq!(last.percent, None);
        assert_eq!(rec.reports.len(), 1);
    }

    #[test]
    fn fake_empty_payload_respects_pre_cancel() {
        let cancel = AtomicBool::new(true);
        let mut rec = RecordingProgressCallback::default();
        assert_eq!(
            run_fake_transfer(Some(0), 64, 0, &cancel, &mut rec),
            Err(TransferProgressError::Cancelled)
        );
        assert!(rec.reports.is_empty());
    }

    /// Sets the cancel flag after `after` successful reports (next chunk sees cancel).
    struct CancellingAfter<'a> {
        after: usize,
        cancel: &'a AtomicBool,
        inner: RecordingProgressCallback,
    }

    impl TransferProgressCallback for CancellingAfter<'_> {
        fn on_progress(&mut self, progress: TransferProgress) -> Result<(), TransferProgressError> {
            self.inner.on_progress(progress)?;
            if self.inner.reports.len() >= self.after {
                self.cancel.store(true, Ordering::SeqCst);
            }
            Ok(())
        }
    }
}
