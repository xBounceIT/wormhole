//! Bitwarden CLI install / update **pin + hash** Fake glue (C# `BitwardenCliInstaller`).
//!
//! Lab hosts inject [`FakeBitwardenCliReleaseSource`] and [`FakeBitwardenCliInstallSettings`]
//! — **no** GitHub HTTP download, **no** `bw` process spawn. Pinned releases must carry a
//! non-empty version and SHA-256 digest; hash mismatch or blank version **fail closed**.
//!
//! Production wiring (HTTP + zip extract + settings persistence via `wormhole-storage`) lands
//! later; this crate owns path helpers, pure release parsers, and the verify-and-stage contract.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::paths::{bitwarden_cli_download_cache_dir, bitwarden_cli_install_dir};

/// Windows CLI executable name inside official Bitwarden ZIPs.
pub const BW_EXECUTABLE_NAME: &str = "bw.exe";

/// Default GitHub releases API path (C# `DefaultReleasesPath`).
pub const DEFAULT_BITWARDEN_CLI_RELEASES_PATH: &str =
    "repos/bitwarden/clients/releases?per_page=20";

/// Installed CLI descriptor (C# `BitwardenCliInstall`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitwardenCliInstall {
    /// Parsed release version, `external`, or `official`.
    pub version: String,
    /// Absolute path to `bw.exe` (or configured external binary).
    pub executable_path: PathBuf,
    /// Lowercase hex SHA-256 of the downloaded artifact (when known).
    pub sha256: Option<String>,
    /// GitHub asset file name (e.g. `bw-windows-2026.6.0.zip`).
    pub asset_name: Option<String>,
    /// Browser download URL used for the install (metadata only in Fake glue).
    pub download_url: Option<String>,
}

/// Settings snapshot consumed by the installer (maps `AppSettings` Bitwarden CLI fields).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitwardenCliInstallSettings {
    /// Configured executable path (`bw` or absolute `bw.exe`).
    pub cli_path: String,
    /// Installed / pinned version string.
    pub version: Option<String>,
    /// Expected artifact SHA-256 (lowercase hex).
    pub sha256: Option<String>,
    /// GitHub asset name.
    pub asset_name: Option<String>,
    /// Last successful download URL (empty → external install).
    pub download_url: Option<String>,
}

impl Default for BitwardenCliInstallSettings {
    fn default() -> Self {
        Self {
            cli_path: "bw".into(),
            version: None,
            sha256: None,
            asset_name: None,
            download_url: None,
        }
    }
}

/// Fields persisted after a successful pinned install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitwardenCliInstallPersist {
    /// Absolute `bw.exe` path written under the install root.
    pub executable_path: PathBuf,
    /// Sanitized release version.
    pub version: String,
    /// Verified lowercase hex SHA-256.
    pub sha256: String,
    /// Asset file name from the release metadata.
    pub asset_name: String,
    /// Download URL metadata (not fetched in Fake glue).
    pub download_url: String,
    /// Human-readable status for settings UI.
    pub install_status: String,
}

/// Installer errors — never embed artifact bytes, secrets, or full paths.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BitwardenCliInstallError {
    /// Pinned install requires a non-empty version string.
    #[error("Bitwarden CLI version pin is required")]
    EmptyVersion,
    /// Pinned install requires a non-empty SHA-256 digest.
    #[error("Bitwarden CLI SHA-256 pin is required")]
    EmptySha256,
    /// Artifact digest does not match the pinned SHA-256.
    #[error("Bitwarden CLI artifact checksum does not match the pinned digest")]
    HashMismatch,
    /// Scripted / pinned release catalog returned no row.
    #[error("no pinned Bitwarden CLI release is available")]
    NoPinnedRelease,
    /// Configured executable path does not exist on disk.
    #[error("configured Bitwarden CLI executable was not found")]
    ExecutableNotFound,
    /// Settings persistence failed.
    #[error("failed to persist Bitwarden CLI install settings")]
    SettingsPersist,
    /// Filesystem error while staging the executable.
    #[error("Bitwarden CLI install I/O failed")]
    Io,
    /// Install root path could not be created.
    #[error("Bitwarden CLI install directory is unavailable")]
    InstallRootUnavailable,
}

/// Read / write installer settings (SQLite `AppSettings` adapter or Fake).
pub trait BitwardenCliInstallSettingsStore: Send + Sync {
    /// Load the current installer-related settings snapshot.
    fn load(&self) -> BitwardenCliInstallSettings;
    /// Persist a successful install (path, version, digest, metadata).
    fn save_install(&self, update: &BitwardenCliInstallPersist) -> Result<(), BitwardenCliInstallError>;
}

/// Pinned release row for Fake glue (no HTTP).
#[derive(Clone)]
pub struct BitwardenCliPinnedRelease {
    /// Release version (e.g. `2026.6.0`).
    pub version: String,
    /// Asset file name.
    pub asset_name: String,
    /// Download URL metadata.
    pub download_url: String,
    /// Expected lowercase hex SHA-256 of [`Self::executable_bytes`].
    pub expected_sha256: String,
    /// Pre-built `bw.exe` payload (Fake — production uses ZIP download + extract).
    pub executable_bytes: Vec<u8>,
}

impl fmt::Debug for BitwardenCliPinnedRelease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitwardenCliPinnedRelease")
            .field("version", &self.version)
            .field("asset_name", &self.asset_name)
            .field("download_url", &self.download_url)
            .field("expected_sha256_len", &self.expected_sha256.len())
            .field("executable_bytes_len", &self.executable_bytes.len())
            .finish()
    }
}

/// Scripted release catalog (Fake — replaces GitHub `releases` HTTP).
pub trait BitwardenCliReleaseSource: Send + Sync {
    /// Return the lab-pinned release row (newest / only entry).
    fn pinned_release(&self) -> Result<BitwardenCliPinnedRelease, BitwardenCliInstallError>;
}

/// Orchestrator mirroring C# `BitwardenCliInstaller` (pin + hash, no network).
pub struct BitwardenCliInstallGlue<S, R>
where
    S: BitwardenCliInstallSettingsStore,
    R: BitwardenCliReleaseSource,
{
    settings: S,
    releases: R,
    install_root: PathBuf,
    #[allow(dead_code)]
    download_root: PathBuf,
}

impl<S, R> fmt::Debug for BitwardenCliInstallGlue<S, R>
where
    S: BitwardenCliInstallSettingsStore,
    R: BitwardenCliReleaseSource,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitwardenCliInstallGlue")
            .field("install_root", &self.install_root)
            .field("download_root", &self.download_root)
            .finish_non_exhaustive()
    }
}

impl<S, R> BitwardenCliInstallGlue<S, R>
where
    S: BitwardenCliInstallSettingsStore,
    R: BitwardenCliReleaseSource,
{
    /// Default profile roots under `%LOCALAPPDATA%\Wormhole\…`.
    pub fn new(settings: S, releases: R) -> Self {
        Self {
            settings,
            releases,
            install_root: bitwarden_cli_install_dir(),
            download_root: bitwarden_cli_download_cache_dir(),
        }
    }

    /// Injectable roots for unit tests (`tempfile` install + cache dirs).
    pub fn with_roots(
        settings: S,
        releases: R,
        install_root: PathBuf,
        download_root: PathBuf,
    ) -> Self {
        Self {
            settings,
            releases,
            install_root,
            download_root,
        }
    }

    /// C# `GetConfiguredInstall` — returns `None` when the configured binary is absent.
    pub fn configured_install(&self) -> Option<BitwardenCliInstall> {
        let current = self.settings.load();
        let path = resolve_executable_path(&current.cli_path)?;
        Some(configured_install_from_settings(&current, path))
    }

    /// C# `EnsureInstalledAsync` — reuse configured install or install the pinned release.
    pub fn ensure_installed(&self) -> Result<BitwardenCliInstall, BitwardenCliInstallError> {
        if let Some(existing) = self.configured_install() {
            return Ok(existing);
        }
        self.install_pinned()
    }

    /// C# `InstallLatestAsync` — always install the pinned release (verify digest, stage exe).
    pub fn install_pinned(&self) -> Result<BitwardenCliInstall, BitwardenCliInstallError> {
        let release = self.releases.pinned_release()?;
        let version = require_non_empty_version(&release.version)?;
        let expected = require_non_empty_sha256(&release.expected_sha256)?;
        let actual = sha256_hex_lower(&release.executable_bytes);
        if !digest_equals(&expected, &actual) {
            return Err(BitwardenCliInstallError::HashMismatch);
        }

        let final_dir = unique_install_dir(&self.install_root, &sanitize_version(version));
        std::fs::create_dir_all(&final_dir).map_err(|_| BitwardenCliInstallError::InstallRootUnavailable)?;
        let executable_path = final_dir.join(BW_EXECUTABLE_NAME);
        std::fs::write(&executable_path, &release.executable_bytes)
            .map_err(|_| BitwardenCliInstallError::Io)?;

        let persist = BitwardenCliInstallPersist {
            executable_path: executable_path.clone(),
            version: sanitize_version(version),
            sha256: actual,
            asset_name: release.asset_name,
            download_url: release.download_url,
            install_status: format!("Installed official Bitwarden CLI {version}."),
        };
        self.settings.save_install(&persist)?;

        Ok(BitwardenCliInstall {
            version: persist.version.clone(),
            executable_path,
            sha256: Some(persist.sha256),
            asset_name: Some(persist.asset_name),
            download_url: Some(persist.download_url),
        })
    }
}

/// Build a configured install record from settings + resolved path (C# `GetConfiguredInstall`).
pub fn configured_install_from_settings(
    settings: &BitwardenCliInstallSettings,
    executable_path: PathBuf,
) -> BitwardenCliInstall {
    let version = configured_version_label(settings);
    BitwardenCliInstall {
        version,
        executable_path,
        sha256: settings.sha256.clone(),
        asset_name: settings.asset_name.clone(),
        download_url: settings.download_url.clone(),
    }
}

fn configured_version_label(settings: &BitwardenCliInstallSettings) -> String {
    if settings
        .download_url
        .as_deref()
        .map(str::trim)
        .is_none_or(str::is_empty)
    {
        "external".into()
    } else if settings
        .version
        .as_deref()
        .map(str::trim)
        .is_none_or(str::is_empty)
    {
        "official".into()
    } else {
        settings.version.clone().unwrap()
    }
}

/// True for non-draft, non-prerelease `cli-v*` tags (C# `IsCliRelease`).
pub fn is_cli_release(tag_name: &str, draft: bool, prerelease: bool) -> bool {
    !draft
        && !prerelease
        && tag_name
            .get(..5)
            .is_some_and(|head| head.eq_ignore_ascii_case("cli-v"))
}

/// Pick the official Windows ZIP asset (C# `FindWindowsAsset`).
pub fn find_windows_asset<'a>(
    assets: &'a [(&'a str, &'a str)],
) -> Option<(&'a str, &'a str)> {
    assets.iter().copied().find(|(name, url)| {
        !name.trim().is_empty()
            && !url.trim().is_empty()
            && name
                .get(..11)
                .is_some_and(|head| head.eq_ignore_ascii_case("bw-windows-"))
            && name
                .get(name.len().saturating_sub(4)..)
                .is_some_and(|tail| tail.eq_ignore_ascii_case(".zip"))
    })
}

/// Parse `cli-v…`, `bw-windows-….zip`, or bare version strings (C# `ParseCliVersion`).
pub fn parse_cli_version(value: &str) -> Option<String> {
    let mut text = value.trim();
    if text.is_empty() {
        return None;
    }
    if let Some(idx) = text.to_ascii_lowercase().find("cli-v") {
        text = &text[idx + "cli-v".len()..];
    }
    if text
        .get(..11)
        .is_some_and(|head| head.eq_ignore_ascii_case("bw-windows-"))
    {
        text = &text[11..];
    }
    if text
        .get(text.len().saturating_sub(4)..)
        .is_some_and(|tail| tail.eq_ignore_ascii_case(".zip"))
    {
        text = &text[..text.len() - 4];
    }
    if text.trim().is_empty() {
        return None;
    }
    Some(sanitize_version(text))
}

/// Parse `sha256:…` GitHub digest metadata (C# `ParseGitHubSha256`).
pub fn parse_github_sha256(digest: &str) -> Option<String> {
    let mut value = digest.trim();
    if value.len() >= 7 && value[..7].eq_ignore_ascii_case("sha256:") {
        value = &value[7..];
    }
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(value.to_ascii_lowercase())
}

/// Resolve `bw` / `bw.exe` on `PATH` or an existing absolute path (C# `ResolveExecutablePath`).
pub fn resolve_executable_path(configured_path: &str) -> Option<PathBuf> {
    let path = {
        let trimmed = configured_path.trim();
        if trimmed.is_empty() {
            "bw"
        } else {
            trimmed
        }
    };

    let path_obj = Path::new(path);
    if path_obj.is_absolute()
        || path.contains(std::path::MAIN_SEPARATOR)
        || path.contains('/')
    {
        return path_obj
            .exists()
            .then(|| std::fs::canonicalize(path_obj).unwrap_or_else(|_| path_obj.to_path_buf()));
    }

    let candidates: Vec<String> = if path.ends_with(".exe") || path.ends_with(".EXE") {
        vec![path.to_owned()]
    } else {
        vec![path.to_owned(), format!("{path}.exe")]
    };

    let path_env = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path_env) {
        for candidate in &candidates {
            let full = directory.join(candidate);
            if full.is_file() {
                return Some(
                    std::fs::canonicalize(&full).unwrap_or(full),
                );
            }
        }
    }
    None
}

/// Sanitize a version segment for directory names (C# `SanitizeVersion`).
pub fn sanitize_version(value: &str) -> String {
    let sanitized: String = value
        .trim()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '-'
            }
        })
        .collect();
    if sanitized.is_empty() {
        "latest".into()
    } else {
        sanitized
    }
}

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex_lower(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("{digest:x}")
}

fn require_non_empty_version(version: &str) -> Result<&str, BitwardenCliInstallError> {
    let trimmed = version.trim();
    if trimmed.is_empty() {
        Err(BitwardenCliInstallError::EmptyVersion)
    } else {
        Ok(trimmed)
    }
}

fn require_non_empty_sha256(digest: &str) -> Result<String, BitwardenCliInstallError> {
    let trimmed = digest.trim();
    if trimmed.is_empty() {
        return Err(BitwardenCliInstallError::EmptySha256);
    }
    parse_github_sha256(trimmed).ok_or(BitwardenCliInstallError::EmptySha256)
}

fn digest_equals(expected: &str, actual: &str) -> bool {
    expected.eq_ignore_ascii_case(actual)
}

fn unique_install_dir(root: &Path, version: &str) -> PathBuf {
    let base = root.join(version);
    if !base.exists() {
        return base;
    }
    for i in 2..1000 {
        let candidate = root.join(format!("{version}-{i}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    root.join(format!("{version}-overflow"))
}

// --- Fake harness ---

/// In-memory settings store for tests / lab.
#[derive(Debug, Default)]
pub struct FakeBitwardenCliInstallSettings {
    inner: Mutex<FakeSettingsState>,
}

#[derive(Debug, Default)]
struct FakeSettingsState {
    current: BitwardenCliInstallSettings,
    save_count: usize,
    fail_save: bool,
}

impl FakeBitwardenCliInstallSettings {
    /// Empty defaults (`cli_path = "bw"`).
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed settings (e.g. pre-configured external `bw.exe`).
    pub fn with_settings(settings: BitwardenCliInstallSettings) -> Self {
        Self {
            inner: Mutex::new(FakeSettingsState {
                current: settings,
                ..Default::default()
            }),
        }
    }

    /// Fail the next `save_install` call (persistence atomicity tests).
    pub fn fail_next_save(&self) {
        let mut guard = self.inner.lock().expect("fake settings lock");
        guard.fail_save = true;
    }

    /// Number of successful `save_install` calls.
    pub fn save_count(&self) -> usize {
        self.inner.lock().expect("fake settings lock").save_count
    }

    /// Current settings snapshot (test oracle).
    pub fn snapshot(&self) -> BitwardenCliInstallSettings {
        self.inner.lock().expect("fake settings lock").current.clone()
    }
}

impl BitwardenCliInstallSettingsStore for FakeBitwardenCliInstallSettings {
    fn load(&self) -> BitwardenCliInstallSettings {
        self.inner.lock().expect("fake settings lock").current.clone()
    }

    fn save_install(&self, update: &BitwardenCliInstallPersist) -> Result<(), BitwardenCliInstallError> {
        let mut guard = self.inner.lock().expect("fake settings lock");
        if guard.fail_save {
            guard.fail_save = false;
            return Err(BitwardenCliInstallError::SettingsPersist);
        }
        guard.current = BitwardenCliInstallSettings {
            cli_path: update.executable_path.to_string_lossy().into_owned(),
            version: Some(update.version.clone()),
            sha256: Some(update.sha256.clone()),
            asset_name: Some(update.asset_name.clone()),
            download_url: Some(update.download_url.clone()),
        };
        guard.save_count += 1;
        Ok(())
    }
}

/// Scripted pinned release (tests / lab).
#[derive(Debug, Clone)]
pub struct FakeBitwardenCliReleaseSource {
    release: Option<BitwardenCliPinnedRelease>,
}

impl FakeBitwardenCliReleaseSource {
    /// No pinned row — `pinned_release` returns [`BitwardenCliInstallError::NoPinnedRelease`].
    pub fn empty() -> Self {
        Self { release: None }
    }

    /// Single pinned release row.
    pub fn with_release(release: BitwardenCliPinnedRelease) -> Self {
        Self {
            release: Some(release),
        }
    }

    /// Lab default: `2026.6.0` with deterministic fake `bw.exe` bytes.
    pub fn lab_default() -> Self {
        Self::with_release(lab_pinned_release())
    }
}

impl BitwardenCliReleaseSource for FakeBitwardenCliReleaseSource {
    fn pinned_release(&self) -> Result<BitwardenCliPinnedRelease, BitwardenCliInstallError> {
        self.release
            .clone()
            .ok_or(BitwardenCliInstallError::NoPinnedRelease)
    }
}

/// Build the standard lab pinned release (`2026.6.0` / `bw-windows-2026.6.0.zip` metadata).
pub fn lab_pinned_release() -> BitwardenCliPinnedRelease {
    let executable_bytes = b"fake bw.exe payload for lab".to_vec();
    let expected_sha256 = sha256_hex_lower(&executable_bytes);
    BitwardenCliPinnedRelease {
        version: "2026.6.0".into(),
        asset_name: "bw-windows-2026.6.0.zip".into(),
        download_url: "https://downloads.example/bw.zip".into(),
        expected_sha256,
        executable_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_roots() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let install = dir.path().join("install");
        let download = dir.path().join("download");
        (dir, install, download)
    }

    type TestGlue = BitwardenCliInstallGlue<
        FakeBitwardenCliInstallSettings,
        FakeBitwardenCliReleaseSource,
    >;

    fn glue_with_roots(
        settings: FakeBitwardenCliInstallSettings,
        releases: FakeBitwardenCliReleaseSource,
        install: PathBuf,
        download: PathBuf,
    ) -> TestGlue {
        BitwardenCliInstallGlue::with_roots(settings, releases, install, download)
    }

    #[test]
    fn release_helpers_filter_cli_release_and_prefer_windows_zip() {
        assert!(is_cli_release("cli-v2026.6.0", false, false));
        assert!(!is_cli_release("cli-v2026.6.0", true, false));
        assert!(!is_cli_release("app-v1", false, false));

        let assets = [
            (
                "bw-oss-windows-2026.6.0.zip",
                "https://example/oss.zip",
            ),
            (
                "bw-windows-2026.6.0.zip",
                "https://example/windows.zip",
            ),
        ];
        let picked = find_windows_asset(&assets).expect("asset");
        assert_eq!(picked.0, "bw-windows-2026.6.0.zip");

        assert_eq!(
            parse_cli_version("cli-v2026.6.0").as_deref(),
            Some("2026.6.0")
        );
        assert_eq!(
            parse_cli_version("bw-windows-2026.6.0.zip").as_deref(),
            Some("2026.6.0")
        );
    }

    #[test]
    fn parse_github_sha256_accepts_prefix_and_rejects_garbage() {
        let hex = "a".repeat(64);
        assert_eq!(
            parse_github_sha256(&format!("sha256:{hex}")).as_deref(),
            Some(hex.as_str())
        );
        assert!(parse_github_sha256("sha256:abc").is_none());
        assert!(parse_github_sha256("").is_none());
    }

    #[test]
    fn install_pinned_verifies_digest_and_persists_path() {
        let (_dir, install, download) = temp_roots();
        let settings = FakeBitwardenCliInstallSettings::new();
        let glue = glue_with_roots(
            settings,
            FakeBitwardenCliReleaseSource::lab_default(),
            install.clone(),
            download,
        );

        let install_row = glue.install_pinned().expect("install");
        assert_eq!(install_row.version, "2026.6.0");
        assert!(install_row.executable_path.ends_with(BW_EXECUTABLE_NAME));
        assert!(install_row.executable_path.starts_with(&install));
        assert!(install_row.executable_path.is_file());

        let settings = glue.settings.snapshot();
        assert_eq!(
            settings.cli_path,
            install_row.executable_path.to_string_lossy()
        );
        assert_eq!(settings.asset_name.as_deref(), Some("bw-windows-2026.6.0.zip"));
        assert_eq!(glue.settings.save_count(), 1);
    }

    #[test]
    fn install_pinned_hash_mismatch_fails_closed_without_persist() {
        let (_dir, install, download) = temp_roots();
        let mut release = lab_pinned_release();
        release.expected_sha256 = "b".repeat(64);
        let settings = FakeBitwardenCliInstallSettings::new();
        let glue = glue_with_roots(
            settings,
            FakeBitwardenCliReleaseSource::with_release(release),
            install,
            download,
        );

        let err = glue.install_pinned().unwrap_err();
        assert_eq!(err, BitwardenCliInstallError::HashMismatch);
        assert_eq!(glue.settings.save_count(), 0);
    }

    #[test]
    fn install_pinned_empty_version_fails_closed() {
        let (_dir, install, download) = temp_roots();
        let mut release = lab_pinned_release();
        release.version = "   ".into();
        let glue = glue_with_roots(
            FakeBitwardenCliInstallSettings::new(),
            FakeBitwardenCliReleaseSource::with_release(release),
            install,
            download,
        );
        assert_eq!(
            glue.install_pinned().unwrap_err(),
            BitwardenCliInstallError::EmptyVersion
        );
    }

    #[test]
    fn install_pinned_empty_sha256_fails_closed() {
        let (_dir, install, download) = temp_roots();
        let mut release = lab_pinned_release();
        release.expected_sha256 = "  ".into();
        let glue = glue_with_roots(
            FakeBitwardenCliInstallSettings::new(),
            FakeBitwardenCliReleaseSource::with_release(release),
            install,
            download,
        );
        assert_eq!(
            glue.install_pinned().unwrap_err(),
            BitwardenCliInstallError::EmptySha256
        );
    }

    #[test]
    fn ensure_installed_uses_configured_without_installing() {
        let (_dir, install, download) = temp_roots();
        let exe = install.join("external-bw.exe");
        fs::create_dir_all(&install).unwrap();
        fs::write(&exe, b"external").unwrap();

        let settings = FakeBitwardenCliInstallSettings::with_settings(BitwardenCliInstallSettings {
            cli_path: exe.to_string_lossy().into_owned(),
            download_url: None,
            ..Default::default()
        });
        let glue = glue_with_roots(
            settings,
            FakeBitwardenCliReleaseSource::lab_default(),
            install,
            download,
        );

        let row = glue.ensure_installed().expect("ensure");
        assert_eq!(row.version, "external");
        assert_eq!(row.executable_path, fs::canonicalize(&exe).unwrap_or(exe));
        assert_eq!(glue.settings.save_count(), 0);
    }

    #[test]
    fn configured_install_resolves_explicit_existing_path() {
        let (_dir, install, download) = temp_roots();
        let exe = install.join("bw.exe");
        fs::create_dir_all(&install).unwrap();
        fs::write(&exe, b"fake").unwrap();

        let settings = FakeBitwardenCliInstallSettings::with_settings(BitwardenCliInstallSettings {
            cli_path: exe.to_string_lossy().into_owned(),
            ..Default::default()
        });
        let glue = glue_with_roots(
            settings,
            FakeBitwardenCliReleaseSource::empty(),
            install,
            download,
        );

        let row = glue.configured_install().expect("configured");
        assert_eq!(row.version, "external");
        assert!(row.executable_path.ends_with(BW_EXECUTABLE_NAME));
    }

    #[test]
    fn install_pinned_malformed_sha256_pin_fails_closed() {
        let (_dir, install, download) = temp_roots();
        let mut release = lab_pinned_release();
        release.expected_sha256 = "not-valid-hex-digest-value-at-all-zzzzzzzzzzzzzzzzzzzzzzzz".into();
        let glue = glue_with_roots(
            FakeBitwardenCliInstallSettings::new(),
            FakeBitwardenCliReleaseSource::with_release(release),
            install,
            download,
        );
        assert_eq!(
            glue.install_pinned().unwrap_err(),
            BitwardenCliInstallError::EmptySha256
        );
    }

    #[test]
    fn save_failure_does_not_increment_save_count() {
        let (_dir, install, download) = temp_roots();
        let settings = FakeBitwardenCliInstallSettings::new();
        settings.fail_next_save();
        let glue = glue_with_roots(
            settings,
            FakeBitwardenCliReleaseSource::lab_default(),
            install,
            download,
        );
        assert_eq!(
            glue.install_pinned().unwrap_err(),
            BitwardenCliInstallError::SettingsPersist
        );
        assert_eq!(glue.settings.save_count(), 0);
    }

    #[test]
    fn error_display_never_echoes_digest_or_payload() {
        let secret_hex = "c".repeat(64);
        let err = BitwardenCliInstallError::HashMismatch;
        let text = format!("{err} / {err:?}");
        assert!(!text.contains(&secret_hex));
        let payload = "fake bw.exe payload for lab";
        let release = BitwardenCliPinnedRelease {
            version: String::new(),
            asset_name: "x".into(),
            download_url: "y".into(),
            expected_sha256: secret_hex.clone(),
            executable_bytes: payload.as_bytes().to_vec(),
        };
        let debug = format!("{release:?}");
        assert!(!debug.contains(payload));
        assert!(!debug.contains(&secret_hex));
    }

    #[test]
    fn sanitize_version_replaces_unsafe_chars() {
        assert_eq!(sanitize_version("2026.6.0"), "2026.6.0");
        assert_eq!(sanitize_version("  "), "latest");
        assert_eq!(sanitize_version("1.0 beta"), "1.0-beta");
    }

    #[test]
    fn unique_install_dir_appends_suffix_when_taken() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("cli");
        fs::create_dir_all(root.join("2026.6.0")).unwrap();
        let second = unique_install_dir(&root, "2026.6.0");
        assert_eq!(second.file_name().and_then(|n| n.to_str()), Some("2026.6.0-2"));
    }
}
