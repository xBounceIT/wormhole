//! Update check result types + evaluation (no live HTTP).

use crate::download::is_safe_installer_file_name;
use crate::error::Result;
use crate::github::{find_installer_asset, is_allowed_http_url, ReleaseManifest};
use crate::version::{is_newer, try_parse_tag_version, AppVersion};

/// Result of comparing the running app to a release manifest (mirrors `UpdateCheckResult`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateCheckResult {
    /// Installed / running version.
    pub current_version: AppVersion,
    /// Parsed latest tag version when known.
    pub latest_version: Option<AppVersion>,
    /// `true` when a newer installer asset exists.
    pub is_update_available: bool,
    /// `true` when the check itself failed (transport / stub).
    pub check_failed: bool,
    /// Release tag string.
    pub release_tag: Option<String>,
    /// Release display name.
    pub release_name: Option<String>,
    /// Release HTML URL.
    pub release_url: Option<String>,
    /// Markdown release notes body.
    pub release_notes: Option<String>,
    /// Installer download URL.
    pub installer_url: Option<String>,
    /// Installer file name.
    pub installer_file_name: Option<String>,
    /// Installer size when known.
    pub installer_size: Option<u64>,
    /// Expected SHA-256 (lowercase hex) when a sidecar was supplied.
    pub installer_sha256: Option<String>,
}

impl UpdateCheckResult {
    /// No update / not newer.
    pub fn no_update(current: AppVersion, latest: Option<AppVersion>) -> Self {
        Self {
            current_version: current,
            latest_version: latest,
            is_update_available: false,
            check_failed: false,
            release_tag: None,
            release_name: None,
            release_url: None,
            release_notes: None,
            installer_url: None,
            installer_file_name: None,
            installer_size: None,
            installer_sha256: None,
        }
    }

    /// Check failed (do not clobber a prior known update in a real service).
    pub fn failed(current: AppVersion) -> Self {
        Self {
            current_version: current,
            latest_version: None,
            is_update_available: false,
            check_failed: true,
            release_tag: None,
            release_name: None,
            release_url: None,
            release_notes: None,
            installer_url: None,
            installer_file_name: None,
            installer_size: None,
            installer_sha256: None,
        }
    }
}

/// Evaluate a local [`ReleaseManifest`] against `current` (pure; no network).
///
/// Draft / prerelease → no update. Missing / unparsable tag → no update.
/// Version ≤ current → no update. Missing arch asset → no update (not failed).
pub fn evaluate_release(
    current: AppVersion,
    release: &ReleaseManifest,
    arch: &str,
    installer_sha256: Option<String>,
) -> UpdateCheckResult {
    if release.draft || release.prerelease {
        return UpdateCheckResult::no_update(current, None);
    }
    let Some(latest) = try_parse_tag_version(&release.tag_name) else {
        return UpdateCheckResult::no_update(current, None);
    };
    if !is_newer(&current, &latest) {
        return UpdateCheckResult::no_update(current, Some(latest));
    }
    let Some(asset) = find_installer_asset(release, arch) else {
        return UpdateCheckResult::no_update(current, Some(latest));
    };
    if !is_safe_installer_file_name(&asset.name) {
        return UpdateCheckResult::no_update(current, Some(latest));
    }
    if asset.browser_download_url.is_empty()
        || !is_allowed_http_url(&asset.browser_download_url)
    {
        // Reject file:// / javascript: / empty hosts — treat as no update (not failed).
        return UpdateCheckResult::no_update(current, Some(latest));
    }
    let release_url = release
        .html_url
        .as_deref()
        .filter(|u| is_allowed_http_url(u))
        .map(str::to_string);
    UpdateCheckResult {
        current_version: current,
        latest_version: Some(latest),
        is_update_available: true,
        check_failed: false,
        release_tag: Some(release.tag_name.clone()),
        release_name: release.name.clone(),
        release_url,
        release_notes: release.body.clone(),
        installer_url: Some(asset.browser_download_url.clone()),
        installer_file_name: Some(asset.name.clone()),
        installer_size: if asset.size > 0 {
            Some(asset.size)
        } else {
            None
        },
        installer_sha256,
    }
}

/// Stub “check for update” that requires a caller-supplied manifest (no HTTP).
pub fn check_for_update_with_manifest(
    current: AppVersion,
    release: &ReleaseManifest,
    arch: &str,
    installer_sha256: Option<String>,
) -> Result<UpdateCheckResult> {
    if arch != "x64" && arch != "arm64" {
        return Ok(UpdateCheckResult::no_update(current, None));
    }
    Ok(evaluate_release(
        current,
        release,
        arch,
        installer_sha256,
    ))
}

/// Placeholder for live GitHub `releases/latest` — always returns [`UpdateError::CheckNetworkStub`].
///
/// Prefer injecting [`crate::NetworkStubUpdateChecker`] / [`crate::FakeUpdateChecker`] via
/// [`crate::UpdateChecker`]. Real HTTP belongs in the host (settings throttle), matching
/// C# `UpdateService.CheckAsync`.
pub fn check_for_update_live_stub(
    owner: &str,
    repo: &str,
    current: AppVersion,
) -> Result<UpdateCheckResult> {
    crate::channel::check_for_update_network_stub(&crate::channel::UpdateCheckRequest::new(
        owner, repo, current, "x64",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::UpdateError;
    use crate::github::ReleaseAsset;

    fn sample_release(tag: &str, arch: &str) -> ReleaseManifest {
        ReleaseManifest {
            tag_name: tag.into(),
            name: Some("Wormhole".into()),
            html_url: Some("https://example/release".into()),
            body: Some("## Notes\n\n- item".into()),
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
    fn flags_update_when_newer() {
        let current = AppVersion::with_build(0, 1, 0);
        let release = sample_release("v9.9.9", "x64");
        let result = evaluate_release(current, &release, "x64", None);
        assert!(result.is_update_available);
        assert_eq!(result.latest_version, Some(AppVersion::with_build(9, 9, 9)));
        assert_eq!(
            result.installer_url.as_deref(),
            Some("https://example.invalid/installer.exe")
        );
    }

    #[test]
    fn no_update_when_equal() {
        let current = AppVersion::with_build(9, 9, 9);
        let release = sample_release("v9.9.9", "x64");
        let result = evaluate_release(current, &release, "x64", None);
        assert!(!result.is_update_available);
        assert_eq!(result.latest_version, Some(current));
    }

    #[test]
    fn draft_ignored() {
        let mut release = sample_release("v9.9.9", "x64");
        release.draft = true;
        let result = evaluate_release(AppVersion::new(0, 1), &release, "x64", None);
        assert!(!result.is_update_available);
    }

    #[test]
    fn prerelease_ignored() {
        let mut release = sample_release("v9.9.9", "x64");
        release.prerelease = true;
        let result = evaluate_release(AppVersion::new(0, 1), &release, "x64", None);
        assert!(!result.is_update_available);
        assert!(result.latest_version.is_none());
    }

    #[test]
    fn rejects_traversal_installer_file_name() {
        let mut release = sample_release("v9.9.9", "x64");
        // Still matches find_installer_asset (wormhole-*-win-x64-setup.exe) but is unsafe.
        release.assets[0].name = "Wormhole-evil/nested-win-x64-setup.exe".into();
        let result = evaluate_release(AppVersion::new(0, 1), &release, "x64", None);
        assert!(!result.is_update_available);
        assert!(result.installer_file_name.is_none());
    }

    #[test]
    fn rejects_file_scheme_installer_url() {
        let mut release = sample_release("v9.9.9", "x64");
        release.assets[0].browser_download_url = "file:///C:/Temp/evil.exe".into();
        let result = evaluate_release(AppVersion::new(0, 1), &release, "x64", None);
        assert!(!result.is_update_available);
        assert_eq!(result.latest_version, Some(AppVersion::with_build(9, 9, 9)));
        assert!(result.installer_url.is_none());
    }

    #[test]
    fn strips_disallowed_release_html_url() {
        let mut release = sample_release("v9.9.9", "x64");
        release.html_url = Some("javascript:alert(1)".into());
        let result = evaluate_release(AppVersion::new(0, 1), &release, "x64", None);
        assert!(result.is_update_available);
        assert!(result.release_url.is_none());
    }

    #[test]
    fn unparsable_prerelease_tag_is_no_update() {
        let release = sample_release("v9.9.9-rc1", "x64");
        let result = evaluate_release(AppVersion::new(0, 1), &release, "x64", None);
        assert!(!result.is_update_available);
        assert!(result.latest_version.is_none());
    }

    #[test]
    fn live_stub_errors() {
        assert!(matches!(
            check_for_update_live_stub("o", "r", AppVersion::new(0, 1)),
            Err(UpdateError::CheckNetworkStub)
        ));
    }
}
