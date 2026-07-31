//! MCP clean-shutdown vs WebView2 flush ordering Fake glue.
//!
//! Mirrors the **required** `MainWindow.PrepareForProcessExitAsync` invariant:
//! HTTP/HTTPS WebView2 surfaces (including Bitwarden extension storage flush)
//! must complete **before** [`McpServerHost::stop`] so agent clients cannot
//! race session teardown while WebView2 still holds Bitwarden profile state.
//!
//! | Step | C# surface |
//! |---|---|
//! | [`AppExitShutdownStep::FlushHttpWebViews`] | `WebBrowserView.CloseAllForShutdownAsync` (per-tab dispose) |
//! | [`AppExitShutdownStep::FlushBitwardenWebView`] | `CaptureBitwardenStorageAsync` during view close |
//! | [`AppExitShutdownStep::StopMcpServer`] | `IMcpServerHost.StopAsync` (2s bounded in C#) |
//! | [`AppExitShutdownStep::CloseAllSessions`] | `ShellViewModel.CloseAllSessionsAsync` |
//!
//! **No live WebView2 / MCP HTTP.** [`FakeAppExitShutdownGlue`] records steps;
//! [`prepare_for_process_exit`] drives the canonical order against
//! [`HttpPlaceholderMcpHost`] or any [`McpServerHost`] impl. Wrong order →
//! [`ShutdownOrderError`] (deterministic test failure).
//!
//! [`Debug`] on glue / surfaces prints step counts and flags only — never bearer
//! tokens or WebView URIs.

use std::fmt;
use std::time::Duration;

use crate::host::McpServerHost;

/// Ordered shutdown step recorded during app exit teardown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppExitShutdownStep {
    /// Flush and close every live HTTP/HTTPS session WebView2.
    FlushHttpWebViews,
    /// Capture Bitwarden extension storage (`CaptureBitwardenStorageAsync`).
    FlushBitwardenWebView,
    /// Stop the loopback MCP Streamable HTTP host.
    StopMcpServer,
    /// Disconnect every open session tab.
    CloseAllSessions,
}

impl AppExitShutdownStep {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FlushHttpWebViews => "FlushHttpWebViews",
            Self::FlushBitwardenWebView => "FlushBitwardenWebView",
            Self::StopMcpServer => "StopMcpServer",
            Self::CloseAllSessions => "CloseAllSessions",
        }
    }
}

impl fmt::Display for AppExitShutdownStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Canonical C# parity ordering for [`validate_shutdown_order`].
pub const CSHARP_PARITY_SHUTDOWN_ORDER: &[AppExitShutdownStep] = &[
    AppExitShutdownStep::FlushHttpWebViews,
    AppExitShutdownStep::FlushBitwardenWebView,
    AppExitShutdownStep::StopMcpServer,
    AppExitShutdownStep::CloseAllSessions,
];

/// Violation when recorded shutdown steps are out of canonical order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShutdownOrderError {
    pub message: String,
    pub recorded: Vec<AppExitShutdownStep>,
    pub expected_before: AppExitShutdownStep,
    pub found_at: AppExitShutdownStep,
}

impl fmt::Display for ShutdownOrderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ShutdownOrderError {}

/// Fail closed when `recorded` deviates from [`CSHARP_PARITY_SHUTDOWN_ORDER`]
/// (strict next-step match; duplicates rejected).
pub fn validate_shutdown_order(recorded: &[AppExitShutdownStep]) -> Result<(), ShutdownOrderError> {
    let mut canon_idx = 0usize;
    for &step in recorded {
        let Some(&expected) = CSHARP_PARITY_SHUTDOWN_ORDER.get(canon_idx) else {
            return Err(ShutdownOrderError {
                message: format!("unexpected extra shutdown step {step}"),
                recorded: recorded.to_vec(),
                expected_before: AppExitShutdownStep::CloseAllSessions,
                found_at: step,
            });
        };
        if step != expected {
            return Err(ShutdownOrderError {
                message: format!(
                    "shutdown step {step} is out of order (expected {expected} next)"
                ),
                recorded: recorded.to_vec(),
                expected_before: expected,
                found_at: step,
            });
        }
        canon_idx += 1;
    }
    Ok(())
}

/// Returns `true` when any WebView flush step appears **after** [`AppExitShutdownStep::StopMcpServer`].
pub fn mcp_stopped_before_webview_flush(recorded: &[AppExitShutdownStep]) -> bool {
    let Some(mcp_idx) = recorded
        .iter()
        .position(|s| *s == AppExitShutdownStep::StopMcpServer)
    else {
        return false;
    };
    recorded.iter().enumerate().any(|(i, s)| {
        i > mcp_idx
            && matches!(
                s,
                AppExitShutdownStep::FlushHttpWebViews | AppExitShutdownStep::FlushBitwardenWebView
            )
    })
}

/// In-memory recorder for Fake WebView / MCP / session shutdown (no HWND / HTTP).
#[derive(Clone, Default)]
pub struct FakeAppExitShutdownGlue {
    steps: Vec<AppExitShutdownStep>,
    http_views_flushed: usize,
    bitwarden_flushed: bool,
    mcp_stopped: bool,
    sessions_closed: usize,
}

impl FakeAppExitShutdownGlue {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn steps(&self) -> &[AppExitShutdownStep] {
        &self.steps
    }

    pub fn http_views_flushed(&self) -> usize {
        self.http_views_flushed
    }

    pub fn bitwarden_flushed(&self) -> bool {
        self.bitwarden_flushed
    }

    pub fn mcp_stopped(&self) -> bool {
        self.mcp_stopped
    }

    pub fn sessions_closed(&self) -> usize {
        self.sessions_closed
    }

    pub fn validate_order(&self) -> Result<(), ShutdownOrderError> {
        validate_shutdown_order(&self.steps)
    }

    /// Record flushing `view_count` HTTP/HTTPS session WebViews.
    pub fn flush_http_webviews(&mut self, view_count: usize) {
        self.http_views_flushed = view_count;
        self.steps.push(AppExitShutdownStep::FlushHttpWebViews);
    }

    /// Record Bitwarden extension storage capture during WebView teardown.
    pub fn flush_bitwarden_webview(&mut self) {
        self.bitwarden_flushed = true;
        self.steps.push(AppExitShutdownStep::FlushBitwardenWebView);
    }

    /// Record MCP host stop (does not call [`McpServerHost`] — use
    /// [`prepare_for_process_exit`] for the full path).
    pub fn record_stop_mcp_server(&mut self) {
        self.mcp_stopped = true;
        self.steps.push(AppExitShutdownStep::StopMcpServer);
    }

    /// Record session tab disconnect count.
    pub fn close_all_sessions(&mut self, session_count: usize) {
        self.sessions_closed = session_count;
        self.steps.push(AppExitShutdownStep::CloseAllSessions);
    }

    /// Canonical parity path: WebView/Bitwarden flush → MCP stop → sessions.
    pub fn run_parity_shutdown(&mut self, http_view_count: usize, session_count: usize) {
        self.flush_http_webviews(http_view_count);
        self.flush_bitwarden_webview();
        self.record_stop_mcp_server();
        self.close_all_sessions(session_count);
    }
}

impl fmt::Debug for FakeAppExitShutdownGlue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeAppExitShutdownGlue")
            .field("step_count", &self.steps.len())
            .field("http_views_flushed", &self.http_views_flushed)
            .field("bitwarden_flushed", &self.bitwarden_flushed)
            .field("mcp_stopped", &self.mcp_stopped)
            .field("sessions_closed", &self.sessions_closed)
            .finish()
    }
}

/// Bounded MCP stop duration matching C# `CancellationTokenSource(TimeSpan.FromSeconds(2))`.
pub const MCP_STOP_TIMEOUT: Duration = Duration::from_secs(2);

/// Drive the canonical shutdown sequence against Fake glue + an in-process MCP host.
///
/// WebView/Bitwarden flush steps are recorded first; MCP [`McpServerHost::stop`] runs
/// only after both flush steps. MCP stop errors are swallowed (C# fail-open) but the
/// step is still recorded so ordering tests stay deterministic.
pub async fn prepare_for_process_exit(
    glue: &mut FakeAppExitShutdownGlue,
    mcp: &dyn McpServerHost,
    http_view_count: usize,
    session_count: usize,
) {
    glue.flush_http_webviews(http_view_count);
    glue.flush_bitwarden_webview();

    let stop_result = tokio::time::timeout(MCP_STOP_TIMEOUT, mcp.stop()).await;
    match stop_result {
        Ok(Ok(())) | Ok(Err(_)) | Err(_) => {
            // C# swallows MCP shutdown failures — never block WebView flush / exit.
            glue.record_stop_mcp_server();
        }
    }

    glue.close_all_sessions(session_count);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HttpPlaceholderMcpHost;

    #[test]
    fn parity_shutdown_records_canonical_order() {
        let mut glue = FakeAppExitShutdownGlue::new();
        glue.run_parity_shutdown(2, 3);
        assert_eq!(glue.steps(), CSHARP_PARITY_SHUTDOWN_ORDER);
        glue.validate_order().expect("parity path is canonical");
    }

    #[test]
    fn mcp_before_webview_flush_fails_validation() {
        let recorded = vec![
            AppExitShutdownStep::StopMcpServer,
            AppExitShutdownStep::FlushHttpWebViews,
            AppExitShutdownStep::FlushBitwardenWebView,
            AppExitShutdownStep::CloseAllSessions,
        ];
        assert!(mcp_stopped_before_webview_flush(&recorded));
        let err = validate_shutdown_order(&recorded).expect_err("wrong order must fail");
        assert_eq!(err.expected_before, AppExitShutdownStep::FlushHttpWebViews);
        assert_eq!(err.found_at, AppExitShutdownStep::StopMcpServer);
    }

    #[test]
    fn bitwarden_after_mcp_stop_fails_validation() {
        let recorded = vec![
            AppExitShutdownStep::FlushHttpWebViews,
            AppExitShutdownStep::StopMcpServer,
            AppExitShutdownStep::FlushBitwardenWebView,
        ];
        assert!(mcp_stopped_before_webview_flush(&recorded));
        validate_shutdown_order(&recorded).expect_err("bitwarden must precede MCP stop");
    }

    #[test]
    fn close_sessions_before_mcp_stop_fails() {
        let recorded = vec![
            AppExitShutdownStep::FlushHttpWebViews,
            AppExitShutdownStep::FlushBitwardenWebView,
            AppExitShutdownStep::CloseAllSessions,
            AppExitShutdownStep::StopMcpServer,
        ];
        let err = validate_shutdown_order(&recorded).expect_err("sessions after MCP only");
        assert_eq!(err.expected_before, AppExitShutdownStep::StopMcpServer);
        assert_eq!(err.found_at, AppExitShutdownStep::CloseAllSessions);
    }

    #[test]
    fn mcp_stop_between_http_and_bitwarden_fails() {
        let recorded = vec![
            AppExitShutdownStep::FlushHttpWebViews,
            AppExitShutdownStep::StopMcpServer,
            AppExitShutdownStep::FlushBitwardenWebView,
        ];
        assert!(mcp_stopped_before_webview_flush(&recorded));
        let err = validate_shutdown_order(&recorded).expect_err("bitwarden must follow http");
        assert_eq!(err.expected_before, AppExitShutdownStep::FlushBitwardenWebView);
        assert_eq!(err.found_at, AppExitShutdownStep::StopMcpServer);
    }

    #[test]
    fn duplicate_step_fails_validation() {
        let recorded = vec![
            AppExitShutdownStep::FlushHttpWebViews,
            AppExitShutdownStep::FlushHttpWebViews,
        ];
        validate_shutdown_order(&recorded).expect_err("duplicates rejected");
    }

    #[test]
    fn empty_recorded_sequence_is_valid() {
        validate_shutdown_order(&[]).expect("empty is vacuously ordered");
    }

    #[test]
    fn partial_prefix_is_valid() {
        let recorded = vec![
            AppExitShutdownStep::FlushHttpWebViews,
            AppExitShutdownStep::FlushBitwardenWebView,
        ];
        validate_shutdown_order(&recorded).expect("prefix of canonical order");
        assert!(!mcp_stopped_before_webview_flush(&recorded));
    }

    #[tokio::test]
    async fn prepare_for_process_exit_records_order_and_stops_placeholder() {
        let host = HttpPlaceholderMcpHost::new();
        host.start().await.expect("placeholder start");
        assert!(host.is_running());

        let mut glue = FakeAppExitShutdownGlue::new();
        prepare_for_process_exit(&mut glue, &host, 1, 2).await;

        assert_eq!(glue.steps(), CSHARP_PARITY_SHUTDOWN_ORDER);
        glue.validate_order().expect("ordered");
        assert_eq!(glue.http_views_flushed(), 1);
        assert!(glue.bitwarden_flushed());
        assert!(glue.mcp_stopped());
        assert_eq!(glue.sessions_closed(), 2);
        assert!(!host.is_running());
    }

    #[tokio::test]
    async fn prepare_swallows_mcp_stop_failure_still_records_order() {
        let host = HttpPlaceholderMcpHost::new();
        // Never started — stop returns NotRunning; glue must still record MCP step after flushes.
        let mut glue = FakeAppExitShutdownGlue::new();
        prepare_for_process_exit(&mut glue, &host, 0, 0).await;

        assert_eq!(
            glue.steps(),
            &[
                AppExitShutdownStep::FlushHttpWebViews,
                AppExitShutdownStep::FlushBitwardenWebView,
                AppExitShutdownStep::StopMcpServer,
                AppExitShutdownStep::CloseAllSessions,
            ]
        );
        glue.validate_order().expect("flush before MCP even on stop err");
    }

    #[test]
    fn debug_omits_bearer_and_uri_wording() {
        let glue = FakeAppExitShutdownGlue::new();
        let text = format!("{glue:?}");
        let lower = text.to_ascii_lowercase();
        assert!(!lower.contains("bearer"));
        assert!(!lower.contains("token"));
        assert!(!lower.contains("http://"));
        assert!(!lower.contains("chrome-extension"));
    }
}
