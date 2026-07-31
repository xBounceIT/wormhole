//! Update check → UI notify status (`Available` / `None` / `Error`).
//!
//! Thin glue over [`UpdateChecker`] (Fake / NetworkStub). No HTTP, no installer UX,
//! no settings throttle. Hosts bind [`UpdateNotifyStatus`] / [`check_now`]; tokens on
//! [`UpdateCheckRequest`] must never be logged (`Debug` redacts).

use crate::channel::{UpdateCheckRequest, UpdateChecker};
use crate::check::UpdateCheckResult;
use crate::version::AppVersion;

/// C# `UpdateViewModel` failure status after a failed / stubbed check.
pub const UPDATE_NOTIFY_ERROR_TEXT: &str =
    "Couldn't reach the update server. Try again later.";

/// C# `UpdateViewModel` status when the running build is current.
pub const UPDATE_NOTIFY_UP_TO_DATE_TEXT: &str = "You're on the latest version.";

/// Coarse UI kind (Settings Updates / info bar).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UpdateNotifyKind {
    /// Newer release advertised by the check (version present; installer may be unset on hostile Fakes).
    Available,
    /// Checked successfully; no newer release.
    None,
    /// Transport / stub / Fake exhausted / channel `Err` — never advertise.
    Error,
}

/// UI-facing outcome of one [`check_now`] (mirrors `UpdateViewModel.ApplyResult` kinds).
///
/// Contains no API tokens. [`Debug`] is safe to format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateNotifyStatus {
    /// Newer release available.
    Available {
        /// Parsed latest version.
        latest_version: AppVersion,
        /// Release tag when known.
        release_tag: Option<String>,
        /// Release display name when known.
        release_name: Option<String>,
        /// http(s) release page when allowed by the evaluator.
        release_url: Option<String>,
        /// Settings status line (`Update available: …`).
        status_text: String,
        /// Info-bar copy (`Wormhole {version} is available.`).
        info_bar_message: String,
    },
    /// Checked; up to date (or no usable asset).
    None {
        /// Settings status line.
        status_text: String,
    },
    /// Check failed — hosts should **not** clear a previously surfaced update.
    Error {
        /// Settings status line.
        status_text: String,
    },
}

impl UpdateNotifyStatus {
    /// Coarse kind for bindings / match arms.
    pub fn kind(&self) -> UpdateNotifyKind {
        match self {
            Self::Available { .. } => UpdateNotifyKind::Available,
            Self::None { .. } => UpdateNotifyKind::None,
            Self::Error { .. } => UpdateNotifyKind::Error,
        }
    }

    /// `true` only for [`Self::Available`] (this check advertised an update).
    pub fn is_update_available(&self) -> bool {
        matches!(self, Self::Available { .. })
    }

    /// `true` when the check failed closed.
    pub fn is_error(&self) -> bool {
        matches!(self, Self::Error { .. })
    }

    /// Borrow the status line.
    pub fn status_text(&self) -> &str {
        match self {
            Self::Available { status_text, .. }
            | Self::None { status_text }
            | Self::Error { status_text } => status_text,
        }
    }
}

/// Map a channel [`UpdateCheckResult`] to UI notify status (pure; no secrets).
///
/// `check_failed` / missing latest on an "available" flag → [`UpdateNotifyStatus::Error`]
/// or [`UpdateNotifyStatus::None`] (fail closed — never advertise without a version).
pub fn notify_status_from_result(result: &UpdateCheckResult) -> UpdateNotifyStatus {
    if result.check_failed {
        return UpdateNotifyStatus::Error {
            status_text: UPDATE_NOTIFY_ERROR_TEXT.to_string(),
        };
    }
    if result.is_update_available {
        let Some(latest_version) = result.latest_version else {
            // Invariant violation from a hostile Fake Result — fail closed.
            return UpdateNotifyStatus::Error {
                status_text: UPDATE_NOTIFY_ERROR_TEXT.to_string(),
            };
        };
        let version_string = latest_version.to_string();
        return UpdateNotifyStatus::Available {
            latest_version,
            release_tag: result.release_tag.clone(),
            release_name: result.release_name.clone(),
            release_url: result.release_url.clone(),
            status_text: format!("Update available: {version_string}"),
            info_bar_message: format!("Wormhole {version_string} is available."),
        };
    }
    UpdateNotifyStatus::None {
        status_text: UPDATE_NOTIFY_UP_TO_DATE_TEXT.to_string(),
    }
}

/// Run one injected check → UI notify status.
///
/// Fail-closed: channel `Err`, `check_failed`, empty/exhausted Fake queue →
/// [`UpdateNotifyStatus::Error`] (never advertises an update). Does not log
/// [`UpdateCheckRequest::api_token`].
pub fn check_now(
    checker: &dyn UpdateChecker,
    request: &UpdateCheckRequest,
) -> UpdateNotifyStatus {
    // Observe length only if present — never format / log the value.
    let _ = request.api_token.as_ref().map(|t| t.len());
    match checker.check(request) {
        Ok(result) => notify_status_from_result(&result),
        Err(_) => UpdateNotifyStatus::Error {
            status_text: UPDATE_NOTIFY_ERROR_TEXT.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::{
        FakeUpdateChecker, FakeUpdateOutcome, NetworkStubUpdateChecker, UpdateApiToken,
    };
    use crate::github::{ReleaseAsset, ReleaseManifest};
    use std::sync::Arc;

    fn sample_release(tag: &str, arch: &str) -> ReleaseManifest {
        ReleaseManifest {
            tag_name: tag.into(),
            name: Some("Wormhole".into()),
            html_url: Some("https://example/release".into()),
            body: Some("## Notes".into()),
            draft: false,
            prerelease: false,
            assets: vec![ReleaseAsset {
                name: format!("Wormhole-9.9.9-win-{arch}-setup.exe"),
                browser_download_url: "https://example.invalid/installer.exe".into(),
                size: 42,
            }],
        }
    }

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
    fn check_now_fake_available_none_error() {
        let fake = FakeUpdateChecker::from_outcomes([
            FakeUpdateOutcome::Result(available_result()),
            FakeUpdateOutcome::Result(UpdateCheckResult::no_update(
                AppVersion::new(0, 1),
                Some(AppVersion::new(0, 1)),
            )),
            FakeUpdateOutcome::Result(UpdateCheckResult::failed(AppVersion::new(0, 1))),
        ]);
        let req = UpdateCheckRequest::new("o", "r", AppVersion::new(0, 1), "x64");

        let available = check_now(&fake, &req);
        assert_eq!(available.kind(), UpdateNotifyKind::Available);
        assert!(available.is_update_available());
        assert!(available.status_text().contains("9.9.9"));

        let none = check_now(&fake, &req);
        assert_eq!(none.kind(), UpdateNotifyKind::None);
        assert_eq!(none.status_text(), UPDATE_NOTIFY_UP_TO_DATE_TEXT);

        let err = check_now(&fake, &req);
        assert_eq!(err.kind(), UpdateNotifyKind::Error);
        assert_eq!(err.status_text(), UPDATE_NOTIFY_ERROR_TEXT);
        assert_eq!(fake.check_calls(), 3);
    }

    #[test]
    fn check_now_exhausted_fake_fail_closed() {
        let fake = FakeUpdateChecker::from_results([available_result()]);
        let secret = "ghp_notify_exhaust_must_not_leak";
        let req = UpdateCheckRequest::new("o", "r", AppVersion::new(0, 1), "x64")
            .with_api_token(UpdateApiToken::new(secret));

        assert_eq!(check_now(&fake, &req).kind(), UpdateNotifyKind::Available);
        // Exhausted script → Fake returns failed → Error notify (never advertise).
        let drained = check_now(&fake, &req);
        assert_eq!(drained.kind(), UpdateNotifyKind::Error);
        assert!(!drained.is_update_available());
        assert_eq!(drained.status_text(), UPDATE_NOTIFY_ERROR_TEXT);

        let fake_dbg = format!("{fake:?}");
        let req_dbg = format!("{req:?}");
        let status_dbg = format!("{drained:?}");
        assert!(!fake_dbg.contains(secret), "{fake_dbg}");
        assert!(!req_dbg.contains(secret), "{req_dbg}");
        assert!(!status_dbg.contains(secret), "{status_dbg}");
        assert!(!status_dbg.contains("ghp_"));
    }

    #[test]
    fn check_now_network_stub_and_err_path_fail_closed() {
        let stub = NetworkStubUpdateChecker;
        let secret = "ghp_notify_stub_token";
        let req = UpdateCheckRequest::new("o", "r", AppVersion::new(1, 0), "x64")
            .with_api_token(UpdateApiToken::new(secret));
        let status = check_now(&stub, &req);
        assert_eq!(status.kind(), UpdateNotifyKind::Error);
        assert!(!format!("{status:?}").contains(secret));

        let fake = FakeUpdateChecker::from_outcomes([FakeUpdateOutcome::NetworkStubError]);
        let err_status = check_now(&fake, &req);
        assert_eq!(err_status.kind(), UpdateNotifyKind::Error);
        assert!(!format!("{err_status:?}").contains(secret));
    }

    #[test]
    fn check_now_fake_manifest_and_token_never_in_debug() {
        let secret = "ghp_notify_manifest_pat";
        let fake = FakeUpdateChecker::from_manifest(sample_release("v9.9.9", "x64"), None);
        let req = UpdateCheckRequest::new("owner", "repo", AppVersion::new(0, 1), "x64")
            .with_api_token(UpdateApiToken::new(secret));
        let status = check_now(&fake, &req);
        assert_eq!(status.kind(), UpdateNotifyKind::Available);
        let seen = fake.seen_requests();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].api_token_present);
        assert_eq!(seen[0].api_token_len, secret.len());
        assert!(!format!("{fake:?}").contains(secret));
        assert!(!format!("{status:?}").contains(secret));
        assert!(!format!("{req:?}").contains(secret));
    }

    #[test]
    fn hostile_available_without_latest_fail_closed() {
        let mut hostile = available_result();
        hostile.latest_version = None;
        let status = notify_status_from_result(&hostile);
        assert_eq!(status.kind(), UpdateNotifyKind::Error);
        assert!(!status.is_update_available());
    }

    #[test]
    fn check_failed_takes_precedence_over_available_flag() {
        let mut hostile = available_result();
        hostile.check_failed = true;
        let status = notify_status_from_result(&hostile);
        assert_eq!(status.kind(), UpdateNotifyKind::Error);
        assert!(!status.is_update_available());
        assert_eq!(status.status_text(), UPDATE_NOTIFY_ERROR_TEXT);
    }

    #[test]
    fn trait_object_check_now() {
        let checker: Arc<dyn UpdateChecker> = Arc::new(NetworkStubUpdateChecker);
        let status = check_now(
            checker.as_ref(),
            &UpdateCheckRequest::new("o", "r", AppVersion::new(0, 9), "x64"),
        );
        assert_eq!(status.kind(), UpdateNotifyKind::Error);
    }
}
