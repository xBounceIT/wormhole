//! Logging boot / settings ↔ redaction enricher glue (no GPUI).
//!
//! Thin apply path: take a settings-shaped [`LoggingBootConfig`], normalize retention
//! (`1..=365`, else default), and expose [`enrich_log_line`] which delegates to
//! [`crate::redact_log_text`] when redaction is enabled. Does **not** reimplement the
//! redactor — production file/stderr sinks always redact via the writer hook in
//! [`crate::logging`]; this module is the boot/settings apply surface + Fake for tests.

use crate::logging::{redact_log_text, DEFAULT_LOG_RETENTION_DAYS};

/// C# `LogFiles.MinimumRetentionDays`.
pub const MIN_LOG_RETENTION_DAYS: i32 = 1;
/// C# `LogFiles.MaximumRetentionDays`.
pub const MAX_LOG_RETENTION_DAYS: i32 = 365;

/// Settings-shaped logging snapshot applied at boot / settings reload.
///
/// Mirrors the logging-relevant slice of `AppSettings` (`LogRetentionDays`) plus an
/// explicit redaction enable flag (always `true` for production hosts; Fake may toggle
/// it in Lab tests). No GPUI / settings chrome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggingBootConfig {
    /// When `true`, lines pass through [`redact_log_text`] before sinks.
    pub redaction_enabled: bool,
    /// Raw retention days from settings (normalized on [`apply_logging_boot`]).
    pub retention_days: i32,
}

impl Default for LoggingBootConfig {
    fn default() -> Self {
        Self {
            redaction_enabled: true,
            retention_days: DEFAULT_LOG_RETENTION_DAYS as i32,
        }
    }
}

impl LoggingBootConfig {
    /// Production default: redaction on, retention = [`DEFAULT_LOG_RETENTION_DAYS`].
    pub fn production_default() -> Self {
        Self::default()
    }

    /// Build from C# `AppSettings.LogRetentionDays` (redaction always enabled).
    pub fn from_settings_retention_days(days: i32) -> Self {
        Self {
            redaction_enabled: true,
            retention_days: days,
        }
    }
}

/// Normalized result of [`apply_logging_boot`].
///
/// Fields are private so retention cannot bypass [`normalize_retention_days`].
/// Construct only via [`apply_logging_boot`] (or [`AppliedLogging::default`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedLogging {
    redaction_enabled: bool,
    retention_days: u32,
}

impl AppliedLogging {
    pub fn redaction_enabled(&self) -> bool {
        self.redaction_enabled
    }

    pub fn retention_days(&self) -> u32 {
        self.retention_days
    }
}

impl Default for AppliedLogging {
    fn default() -> Self {
        apply_logging_boot(LoggingBootConfig::default())
    }
}

/// Clamp retention like C# `LogFiles.NormalizeRetentionDays` (out of range → default).
pub fn normalize_retention_days(days: i32) -> u32 {
    if (MIN_LOG_RETENTION_DAYS..=MAX_LOG_RETENTION_DAYS).contains(&days) {
        days as u32
    } else {
        DEFAULT_LOG_RETENTION_DAYS
    }
}

/// Apply boot/settings config: normalize retention; record redaction enable.
///
/// Does not init tracing subscribers — hosts call [`crate::init_tracing`] (always
/// redacting writer hook) separately. This apply path is the settings glue + the
/// enricher used by [`FakeLogSink`] / hosts that format lines before a custom sink.
/// Production file/stderr redaction is independent of [`AppliedLogging::redaction_enabled`];
/// that flag only gates [`enrich_log_line`] / [`FakeLogSink`].
pub fn apply_logging_boot(config: LoggingBootConfig) -> AppliedLogging {
    AppliedLogging {
        redaction_enabled: config.redaction_enabled,
        retention_days: normalize_retention_days(config.retention_days),
    }
}

/// Enrich a log line according to applied config.
///
/// When redaction is enabled, delegates to [`redact_log_text`] (no local patterns).
pub fn enrich_log_line(applied: &AppliedLogging, line: &str) -> String {
    if applied.redaction_enabled() {
        redact_log_text(line)
    } else {
        line.to_string()
    }
}

/// Fake log sink for Lab / unit tests (no file, stderr, or GPUI).
///
/// Records lines after [`enrich_log_line`] so tests prove secrets are scrubbed when
/// redaction is enabled via [`apply_logging_boot`]. Does not clear prior lines when
/// [`Self::apply_config`] changes settings — call [`Self::clear`] first if needed.
#[derive(Debug, Default)]
pub struct FakeLogSink {
    applied: AppliedLogging,
    lines: Vec<String>,
}

impl FakeLogSink {
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct with an already-applied boot config (from [`apply_logging_boot`]).
    pub fn with_applied(applied: AppliedLogging) -> Self {
        Self {
            applied,
            lines: Vec::new(),
        }
    }

    /// Apply settings-shaped config (same as [`apply_logging_boot`] + replace).
    /// Does not clear previously recorded lines.
    pub fn apply_config(&mut self, config: LoggingBootConfig) {
        self.applied = apply_logging_boot(config);
    }

    pub fn applied(&self) -> &AppliedLogging {
        &self.applied
    }

    /// Emit one line through the enricher into the recorded buffer.
    pub fn emit(&mut self, line: &str) {
        self.lines.push(enrich_log_line(&self.applied, line));
    }

    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    pub fn clear(&mut self) {
        self.lines.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csharp_retention_constants_match() {
        assert_eq!(MIN_LOG_RETENTION_DAYS, 1);
        assert_eq!(MAX_LOG_RETENTION_DAYS, 365);
        assert_eq!(DEFAULT_LOG_RETENTION_DAYS, 14);
    }

    /// Parity with C# `LogFilesTests.NormalizeRetentionDays_Accepts_Range_And_Defaults_Invalid_Values`.
    #[test]
    fn normalize_retention_days_matches_csharp_theory() {
        for (input, expected) in [
            (1, 1u32),
            (14, 14),
            (365, 365),
            (0, 14),
            (366, 14),
            (-1, 14),
            (i32::MIN, 14),
            (i32::MAX, 14),
        ] {
            assert_eq!(
                normalize_retention_days(input),
                expected,
                "normalize_retention_days({input})"
            );
            assert_eq!(
                apply_logging_boot(LoggingBootConfig::from_settings_retention_days(input))
                    .retention_days(),
                expected
            );
        }
    }

    #[test]
    fn apply_enables_redaction_and_normalizes_retention() {
        let applied = apply_logging_boot(LoggingBootConfig {
            redaction_enabled: true,
            retention_days: 30,
        });
        assert!(applied.redaction_enabled());
        assert_eq!(applied.retention_days(), 30);

        let oob = apply_logging_boot(LoggingBootConfig {
            redaction_enabled: true,
            retention_days: 0,
        });
        assert_eq!(oob.retention_days(), DEFAULT_LOG_RETENTION_DAYS);

        let hi = apply_logging_boot(LoggingBootConfig::from_settings_retention_days(999));
        assert!(hi.redaction_enabled());
        assert_eq!(hi.retention_days(), DEFAULT_LOG_RETENTION_DAYS);

        let edge = apply_logging_boot(LoggingBootConfig::from_settings_retention_days(365));
        assert_eq!(edge.retention_days(), 365);
    }

    #[test]
    fn fake_sink_scrubs_secrets_when_redaction_enabled() {
        let mut sink = FakeLogSink::new();
        assert!(sink.applied().redaction_enabled());

        // Values chosen so they are not substrings of assignment / CLI key names
        // (e.g. avoid `sess` ⊂ `--session`).
        sink.emit(
            "connect password=s3cret! token = t0k3n-val SVPNCOOKIE=cook1e BW_SESSION=bw-uuid-9",
        );
        sink.emit("cli --session sess-key-42 WORMHOLE_BW_PASSWORD=hunter2 done\n");

        let lines = sink.lines();
        assert_eq!(lines.len(), 2);
        for leak in [
            "s3cret!",
            "t0k3n-val",
            "cook1e",
            "bw-uuid-9",
            "sess-key-42",
            "hunter2",
        ] {
            assert!(
                !lines[0].contains(leak) && !lines[1].contains(leak),
                "secret leaked in FakeLogSink lines: {leak:?} in {lines:?}"
            );
        }
        assert!(lines[0].contains("password=[redacted]"));
        assert!(lines[0].contains("token = [redacted]"));
        assert!(lines[0].contains("SVPNCOOKIE=[redacted]"));
        assert!(lines[0].contains("BW_SESSION=[redacted]"));
        assert!(lines[1].contains("--session [redacted]"));
        assert!(lines[1].contains("WORMHOLE_BW_PASSWORD=[redacted]"));
        assert!(lines[1].ends_with('\n'));
    }

    #[test]
    fn fake_sink_passthrough_when_redaction_disabled() {
        let mut sink = FakeLogSink::new();
        sink.apply_config(LoggingBootConfig {
            redaction_enabled: false,
            retention_days: 7,
        });
        assert!(!sink.applied().redaction_enabled());
        assert_eq!(sink.applied().retention_days(), 7);

        let raw = "password=still-visible token=also";
        sink.emit(raw);
        assert_eq!(sink.lines(), &[raw.to_string()]);
    }

    #[test]
    fn fake_sink_clear_and_with_applied() {
        let applied = apply_logging_boot(LoggingBootConfig {
            redaction_enabled: false,
            retention_days: 3,
        });
        let mut sink = FakeLogSink::with_applied(applied);
        assert!(!sink.applied().redaction_enabled());
        assert_eq!(sink.applied().retention_days(), 3);
        sink.emit("password=visible");
        assert_eq!(sink.lines().len(), 1);
        sink.clear();
        assert!(sink.lines().is_empty());
        assert!(!sink.applied().redaction_enabled());
    }

    #[test]
    fn enrich_log_line_delegates_to_redact_log_text() {
        let on = apply_logging_boot(LoggingBootConfig {
            redaction_enabled: true,
            retention_days: 14,
        });
        let off = apply_logging_boot(LoggingBootConfig {
            redaction_enabled: false,
            retention_days: 14,
        });
        let sample = "secret=value password=x";
        assert_eq!(enrich_log_line(&on, sample), redact_log_text(sample));
        assert_eq!(enrich_log_line(&off, sample), sample);
    }

    #[test]
    fn production_default_matches_csharp_defaults() {
        let cfg = LoggingBootConfig::production_default();
        assert!(cfg.redaction_enabled);
        assert_eq!(cfg.retention_days, DEFAULT_LOG_RETENTION_DAYS as i32);
        let applied = apply_logging_boot(cfg);
        assert!(applied.redaction_enabled());
        assert_eq!(applied.retention_days(), DEFAULT_LOG_RETENTION_DAYS);
    }
}
