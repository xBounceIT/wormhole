//! Settings / UI notify glue over [`wormhole_update::check_now`].
//!
//! Wires an injected [`UpdateChecker`] (tests: [`FakeUpdateChecker`]; product:
//! [`NetworkStubUpdateChecker`]) into Settings Updates bindings — status text,
//! info-bar availability, optional `LastUpdateCheck` stamp. No GPUI chrome, no
//! live HTTP, no installer / changelog WebView.
//!
//! Fail-closed: exhausted Fake / network stub / channel `Err` → error status and
//! **never** advertises a new update. On error, a previously surfaced update stays
//! visible (C# `UpdateViewModel.ApplyResult` parity). API tokens on the request
//! never appear in [`Debug`].

use std::fmt;
use std::sync::Arc;

use wormhole_update::{
    check_now, AppVersion, FakeUpdateChecker, NetworkStubUpdateChecker, SharedUpdateChecker,
    UpdateApiToken, UpdateCheckRequest, UpdateNotifyKind, UpdateNotifyStatus,
};

use crate::settings::AppSettings;

/// C# DEBUG / development-build status (checks disabled).
pub const UPDATE_NOTIFY_DEV_MODE_TEXT: &str = "Update checks are disabled in development builds.";

/// Host-facing notify state (subset of C# `UpdateViewModel` bindings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateNotifyUiState {
    /// Coarse outcome of the **last** [`UpdateNotifyGlue::check_now`].
    pub kind: UpdateNotifyKind,
    /// Status line under Settings → Updates.
    pub status_text: String,
    /// Info-bar visibility (respects skipped version; preserved across Error).
    pub is_update_available: bool,
    /// Latest release label when available.
    pub latest_version_text: String,
    /// Info-bar message when available.
    pub info_bar_message: String,
    /// Release page URL when available.
    pub release_url: Option<String>,
    /// Formatted last-check label (`Never` / `Last checked …`).
    pub last_check_text: String,
}

impl Default for UpdateNotifyUiState {
    fn default() -> Self {
        Self {
            kind: UpdateNotifyKind::None,
            status_text: String::new(),
            is_update_available: false,
            latest_version_text: String::new(),
            info_bar_message: String::new(),
            release_url: None,
            last_check_text: "Never".into(),
        }
    }
}

/// Settings / UI notify surface: `check_now` → Fake/stub checker → status.
///
/// Holds an optional API token only inside [`UpdateCheckRequest`] (redacted Debug).
pub struct UpdateNotifyGlue {
    checker: SharedUpdateChecker,
    request: UpdateCheckRequest,
    state: UpdateNotifyUiState,
    is_development_build: bool,
    /// Last advertised version string (C# `LatestKnown.LatestVersion`), preserved
    /// across Error so [`Self::dismiss`] can record a skip after a failed check.
    last_available_version: Option<String>,
}

impl fmt::Debug for UpdateNotifyGlue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `UpdateCheckRequest` Debug already redacts api_token; never expose().
        f.debug_struct("UpdateNotifyGlue")
            .field("request", &self.request)
            .field("state", &self.state)
            .field("is_development_build", &self.is_development_build)
            .field("last_available_version", &self.last_available_version)
            .field("checker", &"<UpdateChecker>")
            .finish()
    }
}

impl UpdateNotifyGlue {
    /// Glue with a shared checker + check request (token optional on request).
    pub fn new(checker: SharedUpdateChecker, request: UpdateCheckRequest) -> Self {
        Self {
            checker,
            request,
            state: UpdateNotifyUiState::default(),
            is_development_build: false,
            last_available_version: None,
        }
    }

    /// Test harness: Fake checker + empty script (fail-closed until outcomes queued).
    pub fn with_fake(request: UpdateCheckRequest) -> (Self, Arc<FakeUpdateChecker>) {
        let fake = Arc::new(FakeUpdateChecker::new());
        let glue = Self::new(Arc::clone(&fake) as SharedUpdateChecker, request);
        (glue, fake)
    }

    /// Product stub: [`NetworkStubUpdateChecker`] (no sockets).
    pub fn with_network_stub(request: UpdateCheckRequest) -> Self {
        Self::new(Arc::new(NetworkStubUpdateChecker), request)
    }

    /// Mark as a development build (C# `#if DEBUG` — CheckNow is a no-op).
    pub fn with_development_build(mut self, is_dev: bool) -> Self {
        self.is_development_build = is_dev;
        if is_dev {
            self.state.status_text = UPDATE_NOTIFY_DEV_MODE_TEXT.into();
        }
        self
    }

    /// Seed last-check label from settings (does not run a check).
    pub fn sync_last_check_from_settings(&mut self, settings: &AppSettings) {
        self.state.last_check_text = format_last_check(settings.last_update_check.as_deref());
    }

    /// Replace the check request (e.g. bump current version). Token stays redacted in Debug.
    pub fn set_request(&mut self, request: UpdateCheckRequest) {
        self.request = request;
    }

    /// Attach / replace an API token on the request (tests / future HTTP client).
    pub fn set_api_token(&mut self, token: Option<UpdateApiToken>) {
        self.request.api_token = token;
    }

    /// Borrow current UI state.
    pub fn state(&self) -> &UpdateNotifyUiState {
        &self.state
    }

    /// Whether this glue skips live checks (development builds).
    pub fn is_development_build(&self) -> bool {
        self.is_development_build
    }

    /// Manual Check Now (Settings button) — ignores `AutoCheckForUpdates`.
    ///
    /// When `settings` is `Some`, successful checks (`Available` / `None`) stamp
    /// `last_update_check` with `now_utc` and refresh the last-check label.
    /// Failed checks do **not** stamp (C# transport-failure parity). Skipped
    /// versions suppress the info bar without changing notify kind.
    pub fn check_now(
        &mut self,
        settings: Option<&mut AppSettings>,
        now_utc: Option<&str>,
    ) -> UpdateNotifyKind {
        if self.is_development_build {
            self.state.status_text = UPDATE_NOTIFY_DEV_MODE_TEXT.into();
            // Preserve kind / availability; only refresh status copy.
            return self.state.kind;
        }

        let skipped = settings
            .as_ref()
            .and_then(|s| s.skipped_update_version.as_deref())
            .map(str::to_owned);
        let status = check_now(self.checker.as_ref(), &self.request);
        self.apply_status(status, skipped.as_deref());

        if let Some(settings) = settings {
            if matches!(
                self.state.kind,
                UpdateNotifyKind::Available | UpdateNotifyKind::None
            ) {
                if let Some(now) = now_utc {
                    settings.last_update_check = Some(now.to_string());
                }
            }
            self.state.last_check_text =
                format_last_check(settings.last_update_check.as_deref());
        }

        self.state.kind
    }

    /// Startup auto-check when `AutoCheckForUpdates` is on (no-op in development).
    pub fn run_startup_check(
        &mut self,
        settings: &mut AppSettings,
        now_utc: &str,
    ) -> Option<UpdateNotifyKind> {
        if self.is_development_build || !settings.auto_check_for_updates {
            return None;
        }
        Some(self.check_now(Some(settings), Some(now_utc)))
    }

    /// Dismiss the info bar and record `SkippedUpdateVersion` (C# `Dismiss`).
    ///
    /// Uses the remembered advertised version (not `status_text`), so dismiss still
    /// works after a transport Error that replaced the status line.
    pub fn dismiss(&mut self, settings: &mut AppSettings) {
        if !self.state.is_update_available {
            return;
        }
        if let Some(ver) = self.last_available_version.as_ref() {
            settings.skipped_update_version = Some(ver.clone());
        }
        self.state.is_update_available = false;
        self.state.info_bar_message.clear();
    }

    fn apply_status(&mut self, status: UpdateNotifyStatus, skipped: Option<&str>) {
        match status {
            UpdateNotifyStatus::Error { status_text } => {
                // Leave any previously surfaced update visible; only report failure.
                // Keep `last_available_version` (C# `LatestKnown` not clobbered on fail).
                self.state.kind = UpdateNotifyKind::Error;
                self.state.status_text = status_text;
            }
            UpdateNotifyStatus::None { status_text } => {
                self.state.kind = UpdateNotifyKind::None;
                self.state.status_text = status_text;
                self.state.is_update_available = false;
                self.state.latest_version_text.clear();
                self.state.info_bar_message.clear();
                self.state.release_url = None;
                self.last_available_version = None;
            }
            UpdateNotifyStatus::Available {
                latest_version,
                release_name,
                release_url,
                status_text,
                info_bar_message,
                ..
            } => {
                let version_string = latest_version.to_string();
                self.state.kind = UpdateNotifyKind::Available;
                self.state.status_text = status_text;
                self.state.latest_version_text = release_name
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| format!("Wormhole {version_string}"));
                self.state.info_bar_message = info_bar_message;
                self.state.release_url = release_url;
                self.state.is_update_available = skipped
                    .map(|s| s != version_string.as_str())
                    .unwrap_or(true);
                self.last_available_version = Some(version_string);
            }
        }
    }
}

/// Format `LastUpdateCheck` for the Settings label.
pub fn format_last_check(last_update_check: Option<&str>) -> String {
    match last_update_check {
        None => "Never".into(),
        Some(s) if s.trim().is_empty() => "Never".into(),
        Some(s) => format!("Last checked {s}"),
    }
}

/// Convenience: build a default request for tests / labs.
pub fn test_request(current: AppVersion, arch: &str) -> UpdateCheckRequest {
    UpdateCheckRequest::new("wormhole-project", "wormhole", current, arch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wormhole_update::{
        FakeUpdateOutcome, UpdateCheckResult, UPDATE_NOTIFY_ERROR_TEXT,
        UPDATE_NOTIFY_UP_TO_DATE_TEXT,
    };

    fn available_result() -> UpdateCheckResult {
        UpdateCheckResult {
            current_version: AppVersion::new(0, 1),
            latest_version: Some(AppVersion::with_build(9, 9, 9)),
            is_update_available: true,
            check_failed: false,
            release_tag: Some("v9.9.9".into()),
            release_name: Some("Wormhole 9.9.9".into()),
            release_url: Some("https://example/release".into()),
            release_notes: None,
            installer_url: Some("https://example.invalid/setup.exe".into()),
            installer_file_name: Some("setup.exe".into()),
            installer_size: Some(1),
            installer_sha256: None,
        }
    }

    #[test]
    fn check_now_available_none_error_and_stamp() {
        let (mut glue, fake) = UpdateNotifyGlue::with_fake(test_request(AppVersion::new(0, 1), "x64"));
        fake.push(FakeUpdateOutcome::Result(available_result()));
        fake.push(FakeUpdateOutcome::Result(UpdateCheckResult::no_update(
            AppVersion::new(0, 1),
            Some(AppVersion::new(0, 1)),
        )));
        fake.push(FakeUpdateOutcome::Result(UpdateCheckResult::failed(
            AppVersion::new(0, 1),
        )));

        let mut settings = AppSettings::default();
        assert_eq!(
            glue.check_now(Some(&mut settings), Some("2026-07-31T12:00:00Z")),
            UpdateNotifyKind::Available
        );
        assert!(glue.state().is_update_available);
        assert_eq!(
            settings.last_update_check.as_deref(),
            Some("2026-07-31T12:00:00Z")
        );
        assert!(glue.state().last_check_text.contains("2026-07-31"));

        assert_eq!(
            glue.check_now(Some(&mut settings), Some("2026-07-31T13:00:00Z")),
            UpdateNotifyKind::None
        );
        assert!(!glue.state().is_update_available);
        assert_eq!(glue.state().status_text, UPDATE_NOTIFY_UP_TO_DATE_TEXT);
        assert_eq!(
            settings.last_update_check.as_deref(),
            Some("2026-07-31T13:00:00Z")
        );

        // Error must not stamp; prior last_check kept; prior availability cleared by None above.
        assert_eq!(
            glue.check_now(Some(&mut settings), Some("2026-07-31T14:00:00Z")),
            UpdateNotifyKind::Error
        );
        assert_eq!(glue.state().status_text, UPDATE_NOTIFY_ERROR_TEXT);
        assert_eq!(
            settings.last_update_check.as_deref(),
            Some("2026-07-31T13:00:00Z")
        );
    }

    #[test]
    fn error_preserves_prior_available() {
        let (mut glue, fake) = UpdateNotifyGlue::with_fake(test_request(AppVersion::new(0, 1), "x64"));
        fake.push(FakeUpdateOutcome::Result(available_result()));
        fake.push(FakeUpdateOutcome::Result(UpdateCheckResult::failed(
            AppVersion::new(0, 1),
        )));

        glue.check_now(None, None);
        assert!(glue.state().is_update_available);
        let latest = glue.state().latest_version_text.clone();

        glue.check_now(None, None);
        assert_eq!(glue.state().kind, UpdateNotifyKind::Error);
        assert!(
            glue.state().is_update_available,
            "error must not clear a prior update"
        );
        assert_eq!(glue.state().latest_version_text, latest);
    }

    #[test]
    fn exhausted_fake_fail_closed_no_token_in_debug() {
        let secret = "ghp_ui_glue_must_never_appear";
        let req = test_request(AppVersion::new(0, 1), "x64")
            .with_api_token(UpdateApiToken::new(secret));
        let (mut glue, fake) = UpdateNotifyGlue::with_fake(req);
        fake.push(FakeUpdateOutcome::Result(available_result()));

        assert_eq!(glue.check_now(None, None), UpdateNotifyKind::Available);
        assert_eq!(glue.check_now(None, None), UpdateNotifyKind::Error);
        assert!(glue.state().is_update_available); // preserved from first check

        let dbg = format!("{glue:?}");
        assert!(dbg.contains("UpdateNotifyGlue"), "{dbg}");
        assert!(!dbg.contains(secret), "{dbg}");
        assert!(!dbg.contains("ghp_"), "{dbg}");
        assert!(dbg.contains("[REDACTED"), "{dbg}");
    }

    #[test]
    fn skipped_version_hides_info_bar() {
        let (mut glue, fake) = UpdateNotifyGlue::with_fake(test_request(AppVersion::new(0, 1), "x64"));
        fake.push(FakeUpdateOutcome::Result(available_result()));
        let mut settings = AppSettings::default();
        settings.skipped_update_version = Some("9.9.9".into());

        assert_eq!(
            glue.check_now(Some(&mut settings), Some("t")),
            UpdateNotifyKind::Available
        );
        assert!(
            !glue.state().is_update_available,
            "skipped version must suppress info bar"
        );
        assert!(glue.state().status_text.contains("9.9.9"));
    }

    #[test]
    fn dismiss_records_skip() {
        let (mut glue, fake) = UpdateNotifyGlue::with_fake(test_request(AppVersion::new(0, 1), "x64"));
        fake.push(FakeUpdateOutcome::Result(available_result()));
        let mut settings = AppSettings::default();
        glue.check_now(Some(&mut settings), Some("t"));
        assert!(glue.state().is_update_available);

        glue.dismiss(&mut settings);
        assert!(!glue.state().is_update_available);
        assert_eq!(settings.skipped_update_version.as_deref(), Some("9.9.9"));
    }

    #[test]
    fn dismiss_after_error_still_records_skip() {
        // C# Dismiss uses LatestKnown (not clobbered on CheckFailed). Status line is
        // the error text after ApplyResult(Failed) — skip must still record the version.
        let (mut glue, fake) = UpdateNotifyGlue::with_fake(test_request(AppVersion::new(0, 1), "x64"));
        fake.push(FakeUpdateOutcome::Result(available_result()));
        fake.push(FakeUpdateOutcome::Result(UpdateCheckResult::failed(
            AppVersion::new(0, 1),
        )));
        let mut settings = AppSettings::default();

        glue.check_now(Some(&mut settings), Some("t1"));
        assert!(glue.state().is_update_available);
        glue.check_now(Some(&mut settings), Some("t2"));
        assert_eq!(glue.state().kind, UpdateNotifyKind::Error);
        assert!(glue.state().is_update_available);
        assert_eq!(glue.state().status_text, UPDATE_NOTIFY_ERROR_TEXT);

        glue.dismiss(&mut settings);
        assert!(!glue.state().is_update_available);
        assert!(glue.state().info_bar_message.is_empty());
        assert_eq!(settings.skipped_update_version.as_deref(), Some("9.9.9"));
    }

    #[test]
    fn empty_fake_glue_fail_closed_no_advertise() {
        let (mut glue, fake) = UpdateNotifyGlue::with_fake(test_request(AppVersion::new(0, 1), "x64"));
        assert_eq!(glue.check_now(None, None), UpdateNotifyKind::Error);
        assert!(!glue.state().is_update_available);
        assert_eq!(fake.check_calls(), 1);
    }

    #[test]
    fn development_check_now_skips_checker() {
        let (glue, fake) = UpdateNotifyGlue::with_fake(test_request(AppVersion::new(0, 1), "x64"));
        fake.push(FakeUpdateOutcome::Result(available_result()));
        let mut glue = glue.with_development_build(true);
        let mut settings = AppSettings::default();
        assert_eq!(
            glue.check_now(Some(&mut settings), Some("2026-07-31T16:00:00Z")),
            UpdateNotifyKind::None
        );
        assert_eq!(fake.check_calls(), 0);
        assert!(settings.last_update_check.is_none());
        assert_eq!(glue.state().status_text, UPDATE_NOTIFY_DEV_MODE_TEXT);
    }

    #[test]
    fn startup_respects_auto_check_and_dev() {
        let (mut glue, fake) = UpdateNotifyGlue::with_fake(test_request(AppVersion::new(0, 1), "x64"));
        fake.push(FakeUpdateOutcome::Result(available_result()));
        let mut settings = AppSettings::default();
        settings.auto_check_for_updates = false;
        assert!(glue.run_startup_check(&mut settings, "t").is_none());

        settings.auto_check_for_updates = true;
        let mut glue_dev = UpdateNotifyGlue::with_network_stub(test_request(AppVersion::new(0, 1), "x64"))
            .with_development_build(true);
        assert!(glue_dev.run_startup_check(&mut settings, "t").is_none());
        assert_eq!(glue_dev.state().status_text, UPDATE_NOTIFY_DEV_MODE_TEXT);

        assert_eq!(
            glue.run_startup_check(&mut settings, "2026-07-31T15:00:00Z"),
            Some(UpdateNotifyKind::Available)
        );
    }

    #[test]
    fn network_stub_glue_fail_closed() {
        let mut glue = UpdateNotifyGlue::with_network_stub(test_request(AppVersion::new(1, 0), "x64"));
        assert_eq!(glue.check_now(None, None), UpdateNotifyKind::Error);
        assert!(!glue.state().is_update_available);
    }

    #[test]
    fn format_last_check_never_and_stamp() {
        assert_eq!(format_last_check(None), "Never");
        assert_eq!(format_last_check(Some("")), "Never");
        assert_eq!(format_last_check(Some("   ")), "Never");
        assert_eq!(
            format_last_check(Some("2026-07-31T12:00:00Z")),
            "Last checked 2026-07-31T12:00:00Z"
        );
    }

    #[test]
    fn sync_last_check_from_settings_without_running_check() {
        let (mut glue, fake) = UpdateNotifyGlue::with_fake(test_request(AppVersion::new(0, 1), "x64"));
        let mut settings = AppSettings::default();
        settings.last_update_check = Some("2026-01-01T00:00:00Z".into());
        glue.sync_last_check_from_settings(&settings);
        assert_eq!(fake.check_calls(), 0);
        assert!(glue.state().last_check_text.contains("2026-01-01"));
        assert_eq!(glue.state().kind, UpdateNotifyKind::None);
    }

    #[test]
    fn set_api_token_stays_redacted_in_debug() {
        let (mut glue, _) = UpdateNotifyGlue::with_fake(test_request(AppVersion::new(0, 1), "x64"));
        let secret = "ghp_set_api_token_must_redact";
        glue.set_api_token(Some(UpdateApiToken::new(secret)));
        let dbg = format!("{glue:?}");
        assert!(!dbg.contains(secret), "{dbg}");
        assert!(!dbg.contains("ghp_"), "{dbg}");
        assert!(dbg.contains("[REDACTED"), "{dbg}");
        glue.set_api_token(None);
        assert!(!format!("{glue:?}").contains(secret));
    }
}
