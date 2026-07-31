//! Update check channel — trait + fail-closed network stub + [`FakeUpdateChecker`].
//!
//! Mirrors the injectable surface of C# `IUpdateService.CheckAsync` without HTTP.
//! Production hosts use [`NetworkStubUpdateChecker`] until a real GitHub client lands.
//! Unit tests inject [`FakeUpdateChecker`] with scripted manifests / results.
//!
//! **Never** log GitHub API tokens / PATs. Prefer [`UpdateApiToken`]'s redacting
//! `Debug` / `Display`, and never format [`UpdateApiToken::expose`].

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::check::{evaluate_release, UpdateCheckResult};
use crate::error::{Result, UpdateError};
use crate::github::ReleaseManifest;
use crate::version::AppVersion;

/// Documented gap: live `releases/latest` HTTP is not wired in `wormhole-update`.
///
/// Until a host-supplied HTTP client lands, update checks must stay fail-closed
/// (no sockets, no advertised updates from the network stub).
pub const UPDATE_CHECK_NETWORK_GAP: &str =
    "GitHub releases/latest check is not yet wired in Rust. Update checks fail closed until an HTTP client is supplied by the host.";

/// Opaque GitHub API / PAT bearer for a future authenticated check client.
///
/// `Debug` / `Display` never echo the value — only presence / length — so logging
/// a request or checker cannot leak material. Compare or assert via [`Self::expose`],
/// never via `format!("{:?}", token)`.
#[derive(Clone, PartialEq, Eq)]
pub struct UpdateApiToken {
    value: String,
}

impl UpdateApiToken {
    /// Wrap a token string (tests / future HTTP layer only).
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }

    /// Borrow the raw token. **Never** log the return value.
    pub fn expose(&self) -> &str {
        &self.value
    }

    /// UTF-8 byte length (safe to log / assert).
    pub fn len(&self) -> usize {
        self.value.len()
    }

    /// Whether the token is empty.
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
}

impl fmt::Debug for UpdateApiToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpdateApiToken")
            .field("len", &self.value.len())
            .finish()
    }
}

impl fmt::Display for UpdateApiToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED update API token; len={}]", self.value.len())
    }
}

/// Parameters for one update check (repo + running version + optional API token).
///
/// [`Debug`] redacts any attached API token.
#[derive(Clone)]
pub struct UpdateCheckRequest {
    /// GitHub owner (`wormhole-project`).
    pub owner: String,
    /// GitHub repo (`wormhole`).
    pub repo: String,
    /// Installed / running version.
    pub current: AppVersion,
    /// Target arch (`x64` / `arm64`).
    pub arch: String,
    /// Optional GitHub API token — never logged.
    pub api_token: Option<UpdateApiToken>,
}

impl UpdateCheckRequest {
    /// Build a request without an API token.
    pub fn new(
        owner: impl Into<String>,
        repo: impl Into<String>,
        current: AppVersion,
        arch: impl Into<String>,
    ) -> Self {
        Self {
            owner: owner.into(),
            repo: repo.into(),
            current,
            arch: arch.into(),
            api_token: None,
        }
    }

    /// Attach a GitHub API token (future authenticated client / tests).
    pub fn with_api_token(mut self, token: UpdateApiToken) -> Self {
        self.api_token = Some(token);
        self
    }
}

impl fmt::Debug for UpdateCheckRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpdateCheckRequest")
            .field("owner", &self.owner)
            .field("repo", &self.repo)
            .field("current", &self.current)
            .field("arch", &self.arch)
            .field(
                "api_token",
                &self
                    .api_token
                    .as_ref()
                    .map(|t| format!("[REDACTED; len={}]", t.len())),
            )
            .finish()
    }
}

/// Injectable update-check channel (mirrors `IUpdateService.CheckAsync` without HTTP).
///
/// Implementations must **never** write API tokens to logs or tracing.
pub trait UpdateChecker: Send + Sync {
    /// Check for a newer release for `request`.
    ///
    /// Fail-closed network stubs return [`UpdateCheckResult::failed`] (or
    /// [`UpdateError::CheckNetworkStub`]) and must not open sockets or consume
    /// [`UpdateCheckRequest::api_token`].
    fn check(&self, request: &UpdateCheckRequest) -> Result<UpdateCheckResult>;
}

/// Production stub: never opens sockets; never retains or logs API token values.
///
/// Returns [`UpdateCheckResult::failed`] so hosts mirror C# transport-failure
/// semantics (`check_failed = true`, no advertised update) without claiming the
/// network layer exists. Any attached token is ignored (length may be observed
/// only to document intentional non-use).
#[derive(Debug, Default, Clone, Copy)]
pub struct NetworkStubUpdateChecker;

impl UpdateChecker for NetworkStubUpdateChecker {
    fn check(&self, request: &UpdateCheckRequest) -> Result<UpdateCheckResult> {
        // Explicitly ignore secrets — may be a PAT / bearer (observe length only).
        let _ = request.api_token.as_ref().map(UpdateApiToken::len);
        Ok(UpdateCheckResult::failed(request.current))
    }
}

/// Free-function fail-closed check (parity with Hello / Bitwarden stubs).
///
/// Always returns [`UpdateError::CheckNetworkStub`]. Prefer
/// [`NetworkStubUpdateChecker`] when injecting via [`UpdateChecker`].
pub fn check_for_update_network_stub(request: &UpdateCheckRequest) -> Result<UpdateCheckResult> {
    let _ = request.api_token.as_ref().map(UpdateApiToken::len);
    Err(UpdateError::CheckNetworkStub)
}

/// Scripted outcome for [`FakeUpdateChecker`].
#[derive(Debug, Clone)]
pub enum FakeUpdateOutcome {
    /// Return this result as-is (tests control `check_failed` / availability).
    Result(UpdateCheckResult),
    /// Evaluate `manifest` with the request's current version + arch (+ optional SHA).
    Manifest {
        /// Release JSON subset.
        release: ReleaseManifest,
        /// Optional installer SHA-256 hex.
        installer_sha256: Option<String>,
    },
    /// Surface [`UpdateError::CheckNetworkStub`] (explicit stub error path).
    NetworkStubError,
}

struct FakeState {
    script: VecDeque<FakeUpdateOutcome>,
    /// Safe request summaries only (never API token values).
    seen: Vec<FakeSeenRequest>,
}

/// Token-free snapshot of a check request (safe for `Debug` / assertions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeSeenRequest {
    /// GitHub owner.
    pub owner: String,
    /// GitHub repo.
    pub repo: String,
    /// Running version.
    pub current: AppVersion,
    /// Target arch.
    pub arch: String,
    /// Whether a non-empty API token was attached (value never retained).
    ///
    /// `None` and `Some("")` both record as absent (`false` / len `0`).
    pub api_token_present: bool,
    /// Token UTF-8 byte length when a non-empty token was attached (else `0`) — never the value.
    pub api_token_len: usize,
}

impl FakeSeenRequest {
    fn from_request(request: &UpdateCheckRequest) -> Self {
        let token = request.api_token.as_ref().filter(|t| !t.is_empty());
        Self {
            owner: request.owner.clone(),
            repo: request.repo.clone(),
            current: request.current,
            arch: request.arch.clone(),
            api_token_present: token.is_some(),
            api_token_len: token.map(UpdateApiToken::len).unwrap_or(0),
        }
    }
}

/// Scripted [`UpdateChecker`] for unit tests (no HTTP).
///
/// Each [`check`](UpdateChecker::check) dequeues the next outcome. An empty
/// queue fails closed with [`UpdateCheckResult::failed`] (same as the network
/// stub). API tokens on requests are **not** retained — only presence / length.
pub struct FakeUpdateChecker {
    state: Mutex<FakeState>,
    check_calls: AtomicUsize,
}

impl Default for FakeUpdateChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for FakeUpdateChecker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        f.debug_struct("FakeUpdateChecker")
            .field("script_len", &state.script.len())
            .field("seen", &state.seen)
            .field("check_calls", &self.check_calls.load(Ordering::SeqCst))
            .finish()
    }
}

impl FakeUpdateChecker {
    /// Empty script — every check fails closed until outcomes are queued.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(FakeState {
                script: VecDeque::new(),
                seen: Vec::new(),
            }),
            check_calls: AtomicUsize::new(0),
        }
    }

    /// Queue outcomes in order.
    pub fn from_outcomes(outcomes: impl IntoIterator<Item = FakeUpdateOutcome>) -> Self {
        let fake = Self::new();
        {
            let mut state = fake.state.lock().unwrap_or_else(|p| p.into_inner());
            state.script.extend(outcomes);
        }
        fake
    }

    /// Queue pre-built [`UpdateCheckResult`] values.
    pub fn from_results(results: impl IntoIterator<Item = UpdateCheckResult>) -> Self {
        Self::from_outcomes(results.into_iter().map(FakeUpdateOutcome::Result))
    }

    /// Queue a manifest evaluation (uses the request's `current` + `arch` at check time).
    pub fn from_manifest(release: ReleaseManifest, installer_sha256: Option<String>) -> Self {
        Self::from_outcomes([FakeUpdateOutcome::Manifest {
            release,
            installer_sha256,
        }])
    }

    /// Queue an outcome.
    pub fn push(&self, outcome: FakeUpdateOutcome) {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .script
            .push_back(outcome);
    }

    /// How many times [`UpdateChecker::check`] was called.
    pub fn check_calls(&self) -> usize {
        self.check_calls.load(Ordering::SeqCst)
    }

    /// Token-free snapshots of requests seen so far.
    pub fn seen_requests(&self) -> Vec<FakeSeenRequest> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .seen
            .clone()
    }
}

impl UpdateChecker for FakeUpdateChecker {
    fn check(&self, request: &UpdateCheckRequest) -> Result<UpdateCheckResult> {
        self.check_calls.fetch_add(1, Ordering::SeqCst);
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.seen.push(FakeSeenRequest::from_request(request));
        match state.script.pop_front() {
            None => Ok(UpdateCheckResult::failed(request.current)),
            Some(FakeUpdateOutcome::Result(result)) => Ok(result),
            Some(FakeUpdateOutcome::Manifest {
                release,
                installer_sha256,
            }) => {
                if request.arch != "x64" && request.arch != "arm64" {
                    return Ok(UpdateCheckResult::no_update(request.current, None));
                }
                Ok(evaluate_release(
                    request.current,
                    &release,
                    &request.arch,
                    installer_sha256,
                ))
            }
            Some(FakeUpdateOutcome::NetworkStubError) => Err(UpdateError::CheckNetworkStub),
        }
    }
}

/// Shared handle for DI / future app service bag fields.
pub type SharedUpdateChecker = Arc<dyn UpdateChecker>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::ReleaseAsset;

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

    #[test]
    fn api_token_debug_and_display_redact() {
        let secret = "ghp_this_must_never_appear_in_logs";
        let token = UpdateApiToken::new(secret);
        let dbg = format!("{token:?}");
        let disp = format!("{token}");
        assert!(dbg.contains("len"), "{dbg}");
        assert!(!dbg.contains(secret), "{dbg}");
        assert!(!dbg.contains("ghp_"), "{dbg}");
        assert!(disp.contains("[REDACTED"), "{disp}");
        assert!(!disp.contains(secret), "{disp}");
        // Never treat Debug/Display as a secret oracle — only expose().
        assert_eq!(token.expose(), secret);
        assert_ne!(dbg, token.expose());
        assert_ne!(disp, token.expose());
    }

    #[test]
    fn api_token_unicode_len_is_utf8_bytes_value_never_in_debug() {
        let secret = "ghp_unicöde_🔐_token";
        let token = UpdateApiToken::new(secret);
        assert_eq!(token.len(), secret.len());
        assert!(!token.is_empty());
        let dbg = format!("{token:?}");
        assert!(dbg.contains(&format!("len: {}", secret.len())), "{dbg}");
        assert!(!dbg.contains(secret), "{dbg}");
        assert!(!dbg.contains("unicöde"), "{dbg}");
        assert!(!dbg.contains("🔐"), "{dbg}");
        assert_eq!(token.expose(), secret);
    }

    #[test]
    fn request_debug_redacts_api_token() {
        let secret = "github_pat_secret_value_do_not_log";
        let request = UpdateCheckRequest::new("o", "r", AppVersion::new(0, 1), "x64")
            .with_api_token(UpdateApiToken::new(secret));
        let dbg = format!("{request:?}");
        assert!(dbg.contains("[REDACTED"), "{dbg}");
        assert!(!dbg.contains(secret), "{dbg}");
        assert!(!dbg.contains("github_pat"), "{dbg}");
        assert!(dbg.contains("owner"), "{dbg}");
        assert_ne!(dbg, secret);
    }

    #[test]
    fn network_stub_fail_closed_never_advertises_update() {
        let secret = "ghp_network_stub_must_ignore";
        let request = UpdateCheckRequest::new("owner", "repo", AppVersion::new(1, 2), "x64")
            .with_api_token(UpdateApiToken::new(secret));
        let result = NetworkStubUpdateChecker.check(&request).unwrap();
        assert!(result.check_failed);
        assert!(!result.is_update_available);
        assert!(result.installer_url.is_none());
        assert_eq!(result.current_version, AppVersion::new(1, 2));
        let stub_dbg = format!("{:?}", NetworkStubUpdateChecker);
        assert!(!stub_dbg.contains(secret), "{stub_dbg}");
        assert!(!format!("{request:?}").contains(secret));
    }

    #[test]
    fn network_stub_hostile_fields_still_fail_closed_no_sockets() {
        // Structural: channel has no HTTP/socket deps; stub must ignore owner/repo/arch/token
        // and never advertise an update across repeated calls.
        let secret = "ghp_hostile_repeated_check";
        let request = UpdateCheckRequest::new(
            "evil\nowner",
            "repo/../escape",
            AppVersion::new(0, 1),
            "not-an-arch",
        )
        .with_api_token(UpdateApiToken::new(secret));
        for _ in 0..3 {
            let result = NetworkStubUpdateChecker.check(&request).unwrap();
            assert!(result.check_failed);
            assert!(!result.is_update_available);
            assert!(result.installer_url.is_none());
            assert!(result.release_tag.is_none());
            assert_eq!(result.current_version, AppVersion::new(0, 1));
        }
        assert!(!format!("{request:?}").contains(secret));
    }

    #[test]
    fn free_network_stub_errors() {
        let request = UpdateCheckRequest::new("o", "r", AppVersion::new(0, 1), "x64")
            .with_api_token(UpdateApiToken::new("ghp_free_stub"));
        assert!(matches!(
            check_for_update_network_stub(&request),
            Err(UpdateError::CheckNetworkStub)
        ));
        // Error Display must not echo the PAT.
        let err = check_for_update_network_stub(&request).unwrap_err();
        let msg = err.to_string();
        assert!(!msg.contains("ghp_free_stub"), "{msg}");
        assert!(!format!("{err:?}").contains("ghp_free_stub"));
    }

    #[test]
    fn fake_evaluates_manifest_and_records_token_presence_only() {
        let secret = "ghp_fake_must_not_retain";
        let fake = FakeUpdateChecker::from_manifest(sample_release("v9.9.9", "x64"), None);
        let request = UpdateCheckRequest::new("o", "r", AppVersion::new(0, 1), "x64")
            .with_api_token(UpdateApiToken::new(secret));
        let result = fake.check(&request).unwrap();
        assert!(result.is_update_available);
        assert!(!result.check_failed);
        assert_eq!(fake.check_calls(), 1);
        let seen = fake.seen_requests();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].api_token_present);
        assert_eq!(seen[0].api_token_len, secret.len());
        let fake_dbg = format!("{fake:?}");
        assert!(!fake_dbg.contains(secret), "{fake_dbg}");
        assert!(!format!("{seen:?}").contains(secret));
        assert_ne!(format!("{seen:?}"), secret);
    }

    #[test]
    fn fake_records_absent_and_empty_token_presence_only() {
        let fake = FakeUpdateChecker::from_results([
            UpdateCheckResult::failed(AppVersion::new(0, 1)),
            UpdateCheckResult::failed(AppVersion::new(0, 1)),
            UpdateCheckResult::failed(AppVersion::new(0, 1)),
        ]);
        let none_req = UpdateCheckRequest::new("o", "r", AppVersion::new(0, 1), "x64");
        let empty_req = UpdateCheckRequest::new("o", "r", AppVersion::new(0, 1), "x64")
            .with_api_token(UpdateApiToken::new(""));
        let secret = "ghp_presence_probe_only";
        let present_req = UpdateCheckRequest::new("o", "r", AppVersion::new(0, 1), "x64")
            .with_api_token(UpdateApiToken::new(secret));
        fake.check(&none_req).unwrap();
        fake.check(&empty_req).unwrap();
        fake.check(&present_req).unwrap();
        let seen = fake.seen_requests();
        assert_eq!(seen.len(), 3);
        assert!(!seen[0].api_token_present);
        assert_eq!(seen[0].api_token_len, 0);
        // Empty string token is not a usable secret — record as absent / len 0.
        assert!(!seen[1].api_token_present);
        assert_eq!(seen[1].api_token_len, 0);
        assert!(seen[2].api_token_present);
        assert_eq!(seen[2].api_token_len, secret.len());
        assert!(!format!("{seen:?}").contains(secret));
        assert!(!format!("{fake:?}").contains(secret));
    }

    #[test]
    fn fake_empty_queue_fail_closed() {
        let fake = FakeUpdateChecker::new();
        let result = fake
            .check(&UpdateCheckRequest::new(
                "o",
                "r",
                AppVersion::with_build(3, 0, 0),
                "arm64",
            ))
            .unwrap();
        assert!(result.check_failed);
        assert!(!result.is_update_available);
        assert_eq!(fake.check_calls(), 1);
    }

    #[test]
    fn fake_exhausted_script_fail_closed_again() {
        let available = UpdateCheckResult {
            current_version: AppVersion::new(0, 1),
            latest_version: Some(AppVersion::with_build(9, 9, 9)),
            is_update_available: true,
            check_failed: false,
            release_tag: Some("v9.9.9".into()),
            release_name: None,
            release_url: None,
            release_notes: None,
            installer_url: Some("https://example.invalid/setup.exe".into()),
            installer_file_name: Some("setup.exe".into()),
            installer_size: Some(1),
            installer_sha256: None,
        };
        let fake = FakeUpdateChecker::from_results([available.clone()]);
        let req = UpdateCheckRequest::new("o", "r", AppVersion::new(0, 1), "x64")
            .with_api_token(UpdateApiToken::new("ghp_after_exhaust"));
        assert_eq!(fake.check(&req).unwrap(), available);
        // Queue empty again → same fail-closed shape as NetworkStub (never advertise).
        let drained = fake.check(&req).unwrap();
        assert!(drained.check_failed);
        assert!(!drained.is_update_available);
        assert!(drained.installer_url.is_none());
        assert_eq!(fake.check_calls(), 2);
        assert!(!format!("{:?}", fake.seen_requests()).contains("ghp_after_exhaust"));
    }

    #[test]
    fn fake_scripted_results_and_network_stub_error() {
        let failed = UpdateCheckResult::failed(AppVersion::new(0, 1));
        let fake = FakeUpdateChecker::from_outcomes([
            FakeUpdateOutcome::Result(failed.clone()),
            FakeUpdateOutcome::NetworkStubError,
        ]);
        let req = UpdateCheckRequest::new("o", "r", AppVersion::new(0, 1), "x64");
        assert_eq!(fake.check(&req).unwrap(), failed);
        assert!(matches!(
            fake.check(&req),
            Err(UpdateError::CheckNetworkStub)
        ));
        assert_eq!(fake.check_calls(), 2);
    }

    #[test]
    fn trait_object_network_stub() {
        let checker: SharedUpdateChecker = Arc::new(NetworkStubUpdateChecker);
        let result = checker
            .check(&UpdateCheckRequest::new(
                "o",
                "r",
                AppVersion::new(0, 9),
                "x64",
            ))
            .unwrap();
        assert!(result.check_failed);
    }

    #[test]
    fn gap_message_has_no_secret_shaped_assignments() {
        let gap = UPDATE_CHECK_NETWORK_GAP.to_ascii_lowercase();
        assert!(!gap.contains("token="));
        assert!(!gap.contains("password="));
        assert!(!gap.contains("ghp_"));
    }
}
