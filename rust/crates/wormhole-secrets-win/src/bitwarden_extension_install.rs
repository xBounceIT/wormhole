//! Bitwarden browser extension manual ZIP / folder install pin Fake glue.
//!
//! Lab-only port of pin semantics from `BitwardenBrowserExtensionInstaller` /
//! `BitwardenBrowserExtensionUpdateService`. Manual ZIP and folder installs set
//! [`BitwardenBrowserExtensionSource::ManualZip`] / [`ManualFolder`] and **cannot**
//! auto-update (offline / enterprise pinned installs stay).
//!
//! Uses [`crate::paths`] helpers (`bitwarden_extension_root`, `bitwarden_extension_install_dir`,
//! [`crate::ensure_confined_under`]). Tests inject [`FakeExtensionInstallFs`] and
//! [`FakeZipArchive`] — **no** live unzip of untrusted archives in unit tests.
//! Zip-slip / path escape is rejected before any write ([`confined_zip_destination`]).
//!
//! **Non-goals:** GitHub release download, WebView2 extension host, cookie seeding.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::paths::{bitwarden_extension_install_dir, ensure_confined_under};
use crate::SecretsError;

/// Extension install provenance (C# `BitwardenBrowserExtensionSource`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BitwardenBrowserExtensionSource {
    /// Official GitHub release — auto-update allowed.
    #[default]
    OfficialGitHub,
    /// User-imported ZIP — pinned; auto-update disabled.
    ManualZip,
    /// User-imported unpacked folder — pinned; auto-update disabled.
    ManualFolder,
}

impl BitwardenBrowserExtensionSource {
    /// True when the source is manual (ZIP or folder) and must stay pinned.
    pub fn is_pinned(self) -> bool {
        matches!(self, Self::ManualZip | Self::ManualFolder)
    }

    /// True when [`BitwardenExtensionInstallGlue::update_if_available`] may run.
    pub fn allows_auto_update(self) -> bool {
        matches!(self, Self::OfficialGitHub)
    }
}

/// Resolved install row (C# `BitwardenBrowserExtensionInstall`).
#[derive(Clone, PartialEq, Eq)]
pub struct BitwardenExtensionInstall {
    /// Sanitized manifest / settings version.
    pub version: String,
    /// Absolute unpacked extension directory (contains `manifest.json`).
    pub extension_path: PathBuf,
    /// Content fingerprint (file or directory hash).
    pub sha256: Option<String>,
    /// GitHub asset name when installed from a release.
    pub asset_name: Option<String>,
    /// GitHub download URL when installed from a release.
    pub download_url: Option<String>,
}

impl fmt::Debug for BitwardenExtensionInstall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitwardenExtensionInstall")
            .field("version", &self.version)
            .field("extension_path_len", &self.extension_path.as_os_str().len())
            .field("sha256_present", &self.sha256.is_some())
            .field("asset_name", &self.asset_name)
            .field("download_url_present", &self.download_url.is_some())
            .finish()
    }
}

/// Parsed `manifest.json` metadata (C# `BitwardenBrowserExtensionManifest` subset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitwardenExtensionManifest {
    /// Extension display name (required).
    pub name: String,
    /// Manifest version string.
    pub version: Option<String>,
}

/// Settings snapshot for extension install glue.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BitwardenExtensionSettingsSnapshot {
    /// Whether the browser extension feature is enabled.
    pub enable_bitwarden_browser_extension: bool,
    /// Install provenance.
    pub source: BitwardenBrowserExtensionSource,
    /// Configured version string.
    pub version: Option<String>,
    /// Configured unpacked extension path.
    pub path: Option<PathBuf>,
    /// Content SHA-256 hex.
    pub sha256: Option<String>,
    /// GitHub asset name.
    pub asset_name: Option<String>,
    /// GitHub download URL.
    pub download_url: Option<String>,
    /// Last auto-update check timestamp (RFC3339 string for tests).
    pub last_update_check_utc: Option<String>,
    /// Human-readable last update status.
    pub last_update_status: Option<String>,
    /// Last update error message.
    pub last_update_error: Option<String>,
    /// Available newer version from last check.
    pub available_version: Option<String>,
}

/// Patch applied after a successful install (memory before disk save).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitwardenExtensionInstallPatch {
    /// New provenance.
    pub source: BitwardenBrowserExtensionSource,
    /// Installed version.
    pub version: String,
    /// Installed path.
    pub path: PathBuf,
    /// Content hash.
    pub sha256: Option<String>,
    /// Asset name (official installs).
    pub asset_name: Option<String>,
    /// Download URL (official installs).
    pub download_url: Option<String>,
    /// Status line written to settings.
    pub last_update_status: Option<String>,
    /// Clears last check on manual import.
    pub clear_last_update_check: bool,
}

/// Errors from extension install glue (never carry zip bytes or secrets).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BitwardenExtensionInstallError {
    /// Manual / pinned source blocks auto-update.
    #[error("manual Bitwarden browser extension installations are pinned and cannot be auto-updated")]
    PinnedSource,
    /// Selected path does not exist on the injected filesystem.
    #[error("the selected Bitwarden browser extension path does not exist")]
    PathMissing,
    /// Zip archive contained a path outside the staging root.
    #[error("the extension ZIP contains an unsafe path")]
    UnsafeZipPath,
    /// No usable `manifest.json` in the staged tree.
    #[error("the extension package does not contain manifest.json")]
    MissingManifest,
    /// Manifest JSON invalid or missing required fields.
    #[error("the extension manifest is not valid: {0}")]
    InvalidManifest(&'static str),
    /// Settings persistence failed.
    #[error("failed to persist Bitwarden extension settings: {0}")]
    PersistFailed(String),
    /// Path confinement rejected a candidate.
    #[error("extension path is not confined under the install root")]
    PathNotConfined,
    /// Injected filesystem operation failed.
    #[error("extension install filesystem error")]
    Filesystem,
}

impl From<SecretsError> for BitwardenExtensionInstallError {
    fn from(value: SecretsError) -> Self {
        match value {
            SecretsError::PathNotConfined { .. } | SecretsError::InvalidPathSegment { .. } => {
                Self::PathNotConfined
            }
            _ => Self::Filesystem,
        }
    }
}

/// Settings read/write surface for install glue (SQLite adapter or Fake).
pub trait BitwardenExtensionSettingsStore: Send + Sync {
    /// Current extension settings snapshot.
    fn snapshot(&self) -> BitwardenExtensionSettingsSnapshot;
    /// Apply install patch and persist (C# `IAppSettingsService.Save`).
    fn apply_install(
        &mut self,
        patch: BitwardenExtensionInstallPatch,
    ) -> Result<(), BitwardenExtensionInstallError>;
}

/// Injectable filesystem for staging / copy / move (real disk or Fake map).
pub trait ExtensionInstallFs: Send + Sync {
    /// Directory exists.
    fn is_dir(&self, path: &Path) -> bool;
    /// Regular file exists.
    fn is_file(&self, path: &Path) -> bool;
    /// Read entire file (missing → error).
    fn read_file(&self, path: &Path) -> Result<Vec<u8>, BitwardenExtensionInstallError>;
    /// Recursively copy `from` → `to` (fail if target exists).
    fn copy_tree(&self, from: &Path, to: &Path) -> Result<(), BitwardenExtensionInstallError>;
    /// Create directory and parents.
    fn create_dir_all(&self, path: &Path) -> Result<(), BitwardenExtensionInstallError>;
    /// Write bytes to a file (create parent dirs).
    fn write_file(
        &self,
        path: &Path,
        bytes: &[u8],
    ) -> Result<(), BitwardenExtensionInstallError>;
    /// Move directory `from` → `to`.
    fn move_dir(
        &self,
        from: &Path,
        to: &Path,
    ) -> Result<(), BitwardenExtensionInstallError>;
    /// Delete directory tree (best-effort).
    fn remove_dir_all(&self, path: &Path);
    /// List relative file paths under `root` (files only, `/` separators, sorted).
    fn list_files_recursive(&self, root: &Path) -> Vec<String>;
}

/// One zip entry for lab extraction (Fake or future real archive adapter).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipEntrySpec {
    /// Entry path inside the archive (`/` separators).
    pub name: String,
    /// File bytes (empty for directory-only entries).
    pub content: Vec<u8>,
}

/// Zip archive abstraction — tests use [`FakeZipArchive`] only.
pub trait ExtensionZipArchive: Send + Sync {
    /// Ordered entries (directories have empty `content` and trailing `/` or no file name segment).
    fn entries(&self) -> &[ZipEntrySpec];
    /// Whole-archive SHA-256 hex (C# `ComputeFileSha256Async` on the zip file).
    fn archive_sha256_hex(&self) -> String;
}

/// Orchestrates manual import + pin semantics.
pub struct BitwardenExtensionInstallGlue<S, F> {
    settings: S,
    fs: F,
    install_root: PathBuf,
}

impl<S, F> BitwardenExtensionInstallGlue<S, F>
where
    S: BitwardenExtensionSettingsStore,
    F: ExtensionInstallFs,
{
    /// New glue with injectable install root (tests use temp dir).
    pub fn new(settings: S, fs: F, install_root: PathBuf) -> Self {
        Self {
            settings,
            fs,
            install_root,
        }
    }

    /// C# `GetConfiguredInstall` — None when path missing / manifest unreadable.
    pub fn configured_install(&self) -> Option<BitwardenExtensionInstall> {
        let snap = self.settings.snapshot();
        let path = snap.path?;
        if !self.fs.is_dir(&path) {
            return None;
        }
        let manifest = read_extension_manifest_from_fs(&self.fs, &path).ok()?;
        let version = snap
            .version
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| {
                manifest
                    .version
                    .as_deref()
                    .map(sanitize_browser_version)
                    .unwrap_or_else(|| "manual".to_owned())
            });
        Some(BitwardenExtensionInstall {
            version,
            extension_path: path,
            sha256: snap.sha256,
            asset_name: snap.asset_name,
            download_url: snap.download_url,
        })
    }

    /// Fail closed when source is pinned (C# `UpdateIfAvailableAsync` guard).
    pub fn reject_auto_update_if_pinned(&self) -> Result<(), BitwardenExtensionInstallError> {
        if self.settings.snapshot().source.is_pinned() {
            return Err(BitwardenExtensionInstallError::PinnedSource);
        }
        Ok(())
    }

    /// Import a ZIP via injectable archive (tests: [`FakeZipArchive`] only).
    pub fn import_zip(
        &mut self,
        archive: &dyn ExtensionZipArchive,
        zip_file_name: &str,
    ) -> Result<BitwardenExtensionInstall, BitwardenExtensionInstallError> {
        let _ = zip_file_name; // retained for C# parity / future logging
        self.fs.create_dir_all(&self.install_root)?;
        let staging = staging_path(&self.install_root);
        self.fs.create_dir_all(&staging)?;
        let result = self.import_zip_into_staging(archive, &staging);
        let outcome = match result {
            Ok(install) => Ok(install),
            Err(e) => Err(e),
        };
        self.fs.remove_dir_all(&staging);
        outcome
    }

    fn import_zip_into_staging(
        &mut self,
        archive: &dyn ExtensionZipArchive,
        staging: &Path,
    ) -> Result<BitwardenExtensionInstall, BitwardenExtensionInstallError> {
        for entry in archive.entries() {
            let dest = confined_zip_destination(staging, &entry.name)?;
            if entry_is_directory(&entry.name) {
                self.fs.create_dir_all(&dest)?;
            } else {
                if let Some(parent) = dest.parent() {
                    self.fs.create_dir_all(parent)?;
                }
                self.fs.write_file(&dest, &entry.content)?;
            }
        }
        let extension_root = find_extension_root(&self.fs, staging)?;
        let manifest = read_extension_manifest_from_fs(&self.fs, &extension_root)?;
        let version = sanitize_browser_version(manifest.version.as_deref().unwrap_or("manual"));
        let sha256 = Some(archive.archive_sha256_hex());
        self.activate_install(
            &extension_root,
            version,
            sha256,
            None,
            None,
            BitwardenBrowserExtensionSource::ManualZip,
        )
    }

    /// Import an unpacked folder (copy → stage → activate).
    pub fn import_unpacked_folder(
        &mut self,
        source_folder: &Path,
    ) -> Result<BitwardenExtensionInstall, BitwardenExtensionInstallError> {
        if !self.fs.is_dir(source_folder) {
            return Err(BitwardenExtensionInstallError::PathMissing);
        }
        self.fs.create_dir_all(&self.install_root)?;
        let staging = staging_path(&self.install_root);
        let staged_extension = staging.join("extension");
        self.fs.create_dir_all(&staging)?;
        self.fs.copy_tree(source_folder, &staged_extension)?;
        let manifest = read_extension_manifest_from_fs(&self.fs, &staged_extension)?;
        let version = sanitize_browser_version(manifest.version.as_deref().unwrap_or("manual"));
        let sha256 = Some(compute_directory_sha256_hex(&self.fs, &staged_extension));
        let install = self.activate_install(
            &staged_extension,
            version,
            sha256,
            None,
            None,
            BitwardenBrowserExtensionSource::ManualFolder,
        )?;
        self.fs.remove_dir_all(&staging);
        Ok(install)
    }

    fn activate_install(
        &mut self,
        extension_root: &Path,
        version: String,
        sha256: Option<String>,
        asset_name: Option<String>,
        download_url: Option<String>,
        source: BitwardenBrowserExtensionSource,
    ) -> Result<BitwardenExtensionInstall, BitwardenExtensionInstallError> {
        let final_path = self
            .replacement_path(self.settings.snapshot().path.as_deref())
            .unwrap_or_else(|| unique_install_path(&self.install_root, &version, &self.fs));
        self.fs.create_dir_all(&self.install_root)?;
        if self.fs.is_dir(&final_path) {
            let backup = backup_path(&self.install_root);
            self.fs.move_dir(&final_path, &backup)?;
            if self.fs.move_dir(extension_root, &final_path).is_err() {
                let _ = self.fs.move_dir(&backup, &final_path);
                return Err(BitwardenExtensionInstallError::Filesystem);
            }
            self.fs.remove_dir_all(&backup);
        } else if self.fs.move_dir(extension_root, &final_path).is_err() {
            return Err(BitwardenExtensionInstallError::Filesystem);
        }

        let status = match source {
            BitwardenBrowserExtensionSource::OfficialGitHub => {
                Some(format!("Installed official release {version}."))
            }
            BitwardenBrowserExtensionSource::ManualZip => {
                Some("Manual ZIP install is pinned; auto-update disabled.".to_owned())
            }
            BitwardenBrowserExtensionSource::ManualFolder => {
                Some("Manual folder install is pinned; auto-update disabled.".to_owned())
            }
        };
        let patch = BitwardenExtensionInstallPatch {
            source,
            version: version.clone(),
            path: final_path.clone(),
            sha256: sha256.clone(),
            asset_name: asset_name.clone(),
            download_url: download_url.clone(),
            last_update_status: status,
            clear_last_update_check: source.is_pinned(),
        };
        self.settings.apply_install(patch)?;

        Ok(BitwardenExtensionInstall {
            version,
            extension_path: final_path,
            sha256,
            asset_name,
            download_url,
        })
    }

    /// C# `GetReplacementPath` — only reuse configured path when under `install_root`.
    pub fn replacement_path(&self, configured_path: Option<&Path>) -> Option<PathBuf> {
        replacement_install_path(&self.install_root, configured_path)
    }
}

/// Sanitize a version string (C# `SanitizeVersion`).
pub fn sanitize_browser_version(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.trim().chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
            out.push(ch);
        } else {
            out.push('-');
        }
    }
    if out.is_empty() {
        "manual".to_owned()
    } else {
        out
    }
}

/// Parse browser version from tag / asset name (C# `ParseBrowserVersion`).
pub fn parse_browser_version(value: &str) -> Option<String> {
    let mut text = value.trim().to_string();
    if let Some(idx) = text.to_ascii_lowercase().find("browser-v") {
        text = text[idx + "browser-v".len()..].to_string();
    }
    let lower = text.to_ascii_lowercase();
    if lower.starts_with("dist-edge-") {
        text = text["dist-edge-".len()..].to_string();
    } else if lower.starts_with("dist-chrome-") {
        text = text["dist-chrome-".len()..].to_string();
    }
    if text.to_ascii_lowercase().ends_with(".zip") {
        text.truncate(text.len() - 4);
    }
    if text.trim().is_empty() {
        None
    } else {
        Some(sanitize_browser_version(&text))
    }
}

/// Compare dotted version segments (C# `CompareBrowserVersions`).
pub fn compare_browser_versions(left: &str, right: &str) -> std::cmp::Ordering {
    if left.trim().is_empty() {
        return if right.trim().is_empty() {
            std::cmp::Ordering::Equal
        } else {
            std::cmp::Ordering::Less
        };
    }
    if right.trim().is_empty() {
        return std::cmp::Ordering::Greater;
    }
    let left_parts = split_version_parts(left);
    let right_parts = split_version_parts(right);
    let count = left_parts.len().max(right_parts.len());
    for i in 0..count {
        let l = left_parts.get(i).map(String::as_str).unwrap_or("0");
        let r = right_parts.get(i).map(String::as_str).unwrap_or("0");
        match compare_version_part(l, r) {
            std::cmp::Ordering::Equal => {}
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

/// Resolve destination path for one zip entry; rejects zip-slip (C# `ExtractZipSafely`).
pub fn confined_zip_destination(
    destination_root: &Path,
    entry_name: &str,
) -> Result<PathBuf, BitwardenExtensionInstallError> {
    if entry_name.contains('\0') {
        return Err(BitwardenExtensionInstallError::UnsafeZipPath);
    }
    let normalized = entry_name.replace('\\', "/");
    if normalized.starts_with('/') || normalized.contains("../") {
        return Err(BitwardenExtensionInstallError::UnsafeZipPath);
    }
    let joined = destination_root.join(
        normalized
            .split('/')
            .filter(|s| !s.is_empty() && *s != ".")
            .collect::<PathBuf>(),
    );
    ensure_confined_under(destination_root, &joined, "confined_zip_destination")
        .map_err(BitwardenExtensionInstallError::from)?;
    Ok(joined)
}

/// Reuse configured install path only when confined under `install_root`.
///
/// Lexical only (same class as [`crate::ensure_confined_under`]) — works with
/// injectable Fake paths that are not on disk.
pub fn replacement_install_path(
    install_root: &Path,
    configured_path: Option<&Path>,
) -> Option<PathBuf> {
    let configured = configured_path?;
    ensure_confined_under(install_root, configured, "replacement_install_path").ok()?;
    Some(configured.to_path_buf())
}

/// Parse `manifest.json` bytes.
pub fn parse_extension_manifest(bytes: &[u8]) -> Result<BitwardenExtensionManifest, BitwardenExtensionInstallError> {
    let root: Value = serde_json::from_slice(bytes)
        .map_err(|_| BitwardenExtensionInstallError::InvalidManifest("invalid JSON"))?;
    let name = root
        .get("name")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or(BitwardenExtensionInstallError::InvalidManifest(
            "missing name",
        ))?;
    let version = root
        .get("version")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    Ok(BitwardenExtensionManifest {
        name: name.to_owned(),
        version,
    })
}

fn read_extension_manifest_from_fs<F: ExtensionInstallFs>(
    fs: &F,
    folder: &Path,
) -> Result<BitwardenExtensionManifest, BitwardenExtensionInstallError> {
    let manifest_path = folder.join("manifest.json");
    if !fs.is_file(&manifest_path) {
        return Err(BitwardenExtensionInstallError::MissingManifest);
    }
    let bytes = fs.read_file(&manifest_path)?;
    parse_extension_manifest(&bytes)
}

fn find_extension_root<F: ExtensionInstallFs>(
    fs: &F,
    staging_root: &Path,
) -> Result<PathBuf, BitwardenExtensionInstallError> {
    let direct = staging_root.join("manifest.json");
    if fs.is_file(&direct) {
        return Ok(staging_root.to_path_buf());
    }
    let manifests: Vec<String> = fs
        .list_files_recursive(staging_root)
        .into_iter()
        .filter(|p| p.ends_with("manifest.json"))
        .collect();
    if manifests.is_empty() {
        return Err(BitwardenExtensionInstallError::MissingManifest);
    }
    if manifests.len() == 1 {
        let rel = &manifests[0];
        let parent = rel
            .strip_suffix("manifest.json")
            .and_then(|p| p.strip_suffix('/'))
            .unwrap_or("");
        return Ok(if parent.is_empty() {
            staging_root.to_path_buf()
        } else {
            staging_root.join(parent)
        });
    }
    for rel in &manifests {
        let dir = parent_dir_of_manifest(staging_root, rel);
        if let Ok(manifest) = read_extension_manifest_from_fs(fs, &dir) {
            if manifest.name.to_ascii_lowercase().contains("bitwarden") {
                return Ok(dir);
            }
        }
    }
    Err(BitwardenExtensionInstallError::InvalidManifest(
        "multiple manifests and none identified as Bitwarden",
    ))
}

fn parent_dir_of_manifest(staging_root: &Path, rel_manifest: &str) -> PathBuf {
    let parent = rel_manifest
        .strip_suffix("manifest.json")
        .and_then(|p| p.strip_suffix('/'))
        .unwrap_or("");
    if parent.is_empty() {
        staging_root.to_path_buf()
    } else {
        staging_root.join(parent)
    }
}

fn entry_is_directory(name: &str) -> bool {
    name.ends_with('/') || Path::new(name).file_name().is_none_or(|n| n.is_empty())
}

fn staging_path(install_root: &Path) -> PathBuf {
    install_root.join(format!(".staging-{}", Uuid::new_v4().simple()))
}

fn backup_path(install_root: &Path) -> PathBuf {
    install_root.join(format!(".backup-{}", Uuid::new_v4().simple()))
}

fn unique_install_path<F: ExtensionInstallFs>(
    install_root: &Path,
    version: &str,
    fs: &F,
) -> PathBuf {
    let base = bitwarden_extension_install_dir(version).unwrap_or_else(|_| {
        install_root.join(sanitize_browser_version(version))
    });
    // Prefer install_root-relative path when default helper points at profile root.
    let base = if base.starts_with(install_root) {
        base
    } else {
        install_root.join(
            base.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| sanitize_browser_version(version)),
        )
    };
    if !fs.is_dir(&base) {
        return base;
    }
    for i in 2..1000 {
        let candidate = PathBuf::from(format!("{}-{}", base.to_string_lossy(), i));
        if !fs.is_dir(&candidate) {
            return candidate;
        }
    }
    install_root.join(format!(
        "{}-{}",
        base.to_string_lossy(),
        Uuid::new_v4().simple()
    ))
}

fn compute_directory_sha256_hex<F: ExtensionInstallFs>(fs: &F, directory: &Path) -> String {
    let mut files = fs.list_files_recursive(directory);
    files.sort_by(|a, b| a.to_ascii_lowercase().cmp(&b.to_ascii_lowercase()));
    let mut sha = Sha256::new();
    for rel in files {
        sha.update(rel.as_bytes());
        sha.update([0]);
        if let Ok(bytes) = fs.read_file(&directory.join(&rel)) {
            sha.update(bytes);
        }
    }
    hex_lower(&sha.finalize())
}

fn split_version_parts(value: &str) -> Vec<String> {
    let parsed = parse_browser_version(value).unwrap_or_else(|| value.to_owned());
    parsed
        .split(['.', '-', '_'])
        .filter(|s| !s.is_empty())
        .map(str::trim)
        .map(str::to_owned)
        .collect()
}

fn compare_version_part(left: &str, right: &str) -> std::cmp::Ordering {
    match (left.parse::<i64>(), right.parse::<i64>()) {
        (Ok(l), Ok(r)) => l.cmp(&r),
        _ => left.to_ascii_lowercase().cmp(&right.to_ascii_lowercase()),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

// --- Fake implementations ---

#[derive(Clone)]
#[derive(Debug)]
struct FakeSettingsInner {
    snap: BitwardenExtensionSettingsSnapshot,
    save_count: usize,
    fail_save: Option<String>,
}

/// In-memory settings store for unit tests.
#[derive(Debug, Clone)]
pub struct FakeBitwardenExtensionSettingsStore {
    inner: Arc<Mutex<FakeSettingsInner>>,
}

impl Default for FakeBitwardenExtensionSettingsStore {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeBitwardenExtensionSettingsStore {
    /// Empty settings.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(FakeSettingsInner {
                snap: BitwardenExtensionSettingsSnapshot::default(),
                save_count: 0,
                fail_save: None,
            })),
        }
    }

    /// How many times `apply_install` succeeded.
    pub fn save_count(&self) -> usize {
        self.inner.lock().unwrap().save_count
    }

    /// Next `apply_install` returns `PersistFailed`.
    pub fn fail_next_save(&self, message: impl Into<String>) {
        self.inner.lock().unwrap().fail_save = Some(message.into());
    }

    /// Replace the in-memory snapshot (test setup).
    pub fn set_snapshot(&self, snap: BitwardenExtensionSettingsSnapshot) {
        self.inner.lock().unwrap().snap = snap;
    }
}

impl BitwardenExtensionSettingsStore for FakeBitwardenExtensionSettingsStore {
    fn snapshot(&self) -> BitwardenExtensionSettingsSnapshot {
        self.inner.lock().unwrap().snap.clone()
    }

    fn apply_install(
        &mut self,
        patch: BitwardenExtensionInstallPatch,
    ) -> Result<(), BitwardenExtensionInstallError> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(msg) = inner.fail_save.take() {
            return Err(BitwardenExtensionInstallError::PersistFailed(msg));
        }
        inner.snap.source = patch.source;
        inner.snap.version = Some(patch.version);
        inner.snap.path = Some(patch.path);
        inner.snap.sha256 = patch.sha256;
        inner.snap.asset_name = patch.asset_name;
        inner.snap.download_url = patch.download_url;
        inner.snap.last_update_status = patch.last_update_status;
        inner.snap.last_update_error = None;
        inner.snap.available_version = None;
        if patch.clear_last_update_check {
            inner.snap.last_update_check_utc = None;
        }
        inner.save_count += 1;
        Ok(())
    }
}

#[derive(Debug, Clone)]
enum FakeNode {
    File(Vec<u8>),
    Dir,
}

/// In-memory filesystem for extension install tests (no real disk / zip IO).
#[derive(Debug, Default, Clone)]
pub struct FakeExtensionInstallFs {
    nodes: Arc<Mutex<BTreeMap<PathBuf, FakeNode>>>,
}

impl FakeExtensionInstallFs {
    /// Empty tree.
    pub fn new() -> Self {
        Self {
            nodes: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Seed a directory marker.
    pub fn seed_dir(&self, path: impl Into<PathBuf>) {
        self.nodes
            .lock()
            .unwrap()
            .insert(path.into(), FakeNode::Dir);
    }

    /// Seed a file.
    pub fn seed_file(&self, path: impl Into<PathBuf>, content: impl Into<Vec<u8>>) {
        let path = path.into();
        if let Some(parent) = path.parent() {
            self.seed_dir(parent.to_path_buf());
        }
        self.nodes
            .lock()
            .unwrap()
            .insert(path, FakeNode::File(content.into()));
    }

    fn normalize(path: &Path) -> PathBuf {
        let mut out = PathBuf::new();
        for comp in path.components() {
            match comp {
                Component::RootDir | Component::Prefix(_) => {}
                Component::CurDir => {}
                Component::ParentDir => {
                    out.pop();
                }
                Component::Normal(c) => out.push(c),
            }
        }
        out
    }
}

impl ExtensionInstallFs for FakeExtensionInstallFs {
    fn is_dir(&self, path: &Path) -> bool {
        let path = Self::normalize(path);
        matches!(
            self.nodes.lock().unwrap().get(&path),
            Some(FakeNode::Dir) | Some(FakeNode::File(_))
        ) || self
            .nodes
            .lock()
            .unwrap()
            .keys()
            .any(|p| p.starts_with(&path))
    }

    fn is_file(&self, path: &Path) -> bool {
        matches!(
            self.nodes.lock().unwrap().get(&Self::normalize(path)),
            Some(FakeNode::File(_))
        )
    }

    fn read_file(&self, path: &Path) -> Result<Vec<u8>, BitwardenExtensionInstallError> {
        match self.nodes.lock().unwrap().get(&Self::normalize(path)) {
            Some(FakeNode::File(b)) => Ok(b.clone()),
            _ => Err(BitwardenExtensionInstallError::Filesystem),
        }
    }

    fn copy_tree(&self, from: &Path, to: &Path) -> Result<(), BitwardenExtensionInstallError> {
        let from = Self::normalize(from);
        let to = Self::normalize(to);
        let nodes = self.nodes.lock().unwrap();
        let entries: Vec<(PathBuf, FakeNode)> = nodes
            .iter()
            .filter(|(p, _)| p.starts_with(&from))
            .map(|(p, n)| (p.strip_prefix(&from).unwrap().to_path_buf(), n.clone()))
            .collect();
        drop(nodes);
        self.create_dir_all(&to)?;
        for (rel, node) in entries {
            let dest = to.join(rel);
            match node {
                FakeNode::Dir => self.create_dir_all(&dest)?,
                FakeNode::File(b) => self.write_file(&dest, &b)?,
            }
        }
        Ok(())
    }

    fn create_dir_all(&self, path: &Path) -> Result<(), BitwardenExtensionInstallError> {
        let path = Self::normalize(path);
        self.nodes.lock().unwrap().insert(path, FakeNode::Dir);
        Ok(())
    }

    fn write_file(
        &self,
        path: &Path,
        bytes: &[u8],
    ) -> Result<(), BitwardenExtensionInstallError> {
        let path = Self::normalize(path);
        if let Some(parent) = path.parent() {
            self.create_dir_all(parent)?;
        }
        self.nodes
            .lock()
            .unwrap()
            .insert(path, FakeNode::File(bytes.to_vec()));
        Ok(())
    }

    fn move_dir(&self, from: &Path, to: &Path) -> Result<(), BitwardenExtensionInstallError> {
        let from = Self::normalize(from);
        let to = Self::normalize(to);
        let mut nodes = self.nodes.lock().unwrap();
        let moved: Vec<(PathBuf, FakeNode)> = nodes
            .iter()
            .filter(|(p, _)| *p == &from || p.starts_with(&from))
            .map(|(p, n)| {
                let rel = p.strip_prefix(&from).unwrap();
                (to.join(rel), n.clone())
            })
            .collect();
        if moved.is_empty() {
            return Err(BitwardenExtensionInstallError::Filesystem);
        }
        nodes.retain(|p, _| p != &from && !p.starts_with(&from));
        for (p, n) in moved {
            nodes.insert(p, n);
        }
        Ok(())
    }

    fn remove_dir_all(&self, path: &Path) {
        let path = Self::normalize(path);
        let mut nodes = self.nodes.lock().unwrap();
        nodes.retain(|p, _| p != &path && !p.starts_with(&path));
    }

    fn list_files_recursive(&self, root: &Path) -> Vec<String> {
        let root = Self::normalize(root);
        self.nodes
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(p, n)| {
                if let FakeNode::File(_) = n {
                    p.strip_prefix(&root)
                        .ok()
                        .map(|r| r.to_string_lossy().replace('\\', "/"))
                } else {
                    None
                }
            })
            .collect()
    }
}

/// In-memory zip stand-in (tests only — no `zip` crate / no untrusted IO).
#[derive(Debug, Clone)]
pub struct FakeZipArchive {
    entries: Vec<ZipEntrySpec>,
    sha256_hex: String,
}

impl FakeZipArchive {
    /// Build from entry specs; computes archive SHA-256 from canonical serialization.
    pub fn new(entries: Vec<ZipEntrySpec>) -> Self {
        let mut sha = Sha256::new();
        for e in &entries {
            sha.update(e.name.as_bytes());
            sha.update([0]);
            sha.update(&e.content);
        }
        Self {
            entries,
            sha256_hex: hex_lower(&sha.finalize()),
        }
    }

    /// Precomputed digest (parity tests).
    pub fn with_sha256(entries: Vec<ZipEntrySpec>, sha256_hex: impl Into<String>) -> Self {
        Self {
            entries,
            sha256_hex: sha256_hex.into(),
        }
    }
}

impl ExtensionZipArchive for FakeZipArchive {
    fn entries(&self) -> &[ZipEntrySpec] {
        &self.entries
    }

    fn archive_sha256_hex(&self) -> String {
        self.sha256_hex.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const VALID_MANIFEST: &str = r#"{
      "manifest_version": 3,
      "name": "Bitwarden Password Manager",
      "version": "2026.6.1",
      "action": { "default_popup": "popup.html" }
    }"#;

    fn install_root() -> PathBuf {
        PathBuf::from(r"C:\WormholeTest\extensions\bitwarden")
    }

    #[test]
    fn pinned_sources_block_auto_update() {
        for source in [
            BitwardenBrowserExtensionSource::ManualZip,
            BitwardenBrowserExtensionSource::ManualFolder,
        ] {
            let settings = FakeBitwardenExtensionSettingsStore::new();
            settings.set_snapshot(BitwardenExtensionSettingsSnapshot {
                source,
                ..Default::default()
            });
            let fs = FakeExtensionInstallFs::new();
            let glue = BitwardenExtensionInstallGlue::new(settings, fs, install_root());
            assert_eq!(
                glue.reject_auto_update_if_pinned(),
                Err(BitwardenExtensionInstallError::PinnedSource)
            );
        }
        let settings = FakeBitwardenExtensionSettingsStore::new();
        settings.set_snapshot(BitwardenExtensionSettingsSnapshot {
            source: BitwardenBrowserExtensionSource::OfficialGitHub,
            ..Default::default()
        });
        let glue = BitwardenExtensionInstallGlue::new(
            settings,
            FakeExtensionInstallFs::new(),
            install_root(),
        );
        assert!(glue.reject_auto_update_if_pinned().is_ok());
    }

    #[test]
    fn sanitize_and_parse_versions_match_csharp() {
        assert_eq!(sanitize_browser_version("2026.6.1"), "2026.6.1");
        assert_eq!(sanitize_browser_version("  bad chars!  "), "bad-chars-");
        assert_eq!(sanitize_browser_version("   "), "manual");
        assert_eq!(
            parse_browser_version("browser-v2026.6.1"),
            Some("2026.6.1".to_owned())
        );
        assert_eq!(
            parse_browser_version("dist-edge-2026.6.1.zip"),
            Some("2026.6.1".to_owned())
        );
        assert_eq!(
            compare_browser_versions("2026.6.10", "2026.6.2"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_browser_versions("browser-v2026.6.0", "2026.6"),
            std::cmp::Ordering::Equal
        );
    }

    #[test]
    fn confined_zip_destination_rejects_traversal() {
        let root = Path::new(r"C:\staging");
        assert!(confined_zip_destination(root, "extension/manifest.json").is_ok());
        for bad in ["../outside.txt", "/abs.txt", "foo/../../bar.txt", "a\\..\\b.txt"] {
            assert_eq!(
                confined_zip_destination(root, bad),
                Err(BitwardenExtensionInstallError::UnsafeZipPath),
                "expected reject for {bad:?}"
            );
        }
        let err_display = format!("{}", BitwardenExtensionInstallError::UnsafeZipPath);
        assert!(!err_display.contains("outside"));
        assert!(!err_display.contains(".."));
    }

    #[test]
    fn replacement_path_confined_under_install_root() {
        let root = PathBuf::from(r"C:\Wormhole\extensions\bitwarden");
        let inside = root.join("2026.6.1");
        assert_eq!(
            replacement_install_path(&root, Some(&inside)),
            Some(inside.clone())
        );
        assert!(replacement_install_path(&root, Some(Path::new(r"C:\Windows\evil"))).is_none());
        assert!(replacement_install_path(&root, None).is_none());
    }

    #[test]
    fn import_zip_via_fake_archive_pins_and_persists() {
        let settings = FakeBitwardenExtensionSettingsStore::new();
        let fs = FakeExtensionInstallFs::new();
        let root = install_root();
        let mut glue = BitwardenExtensionInstallGlue::new(settings.clone(), fs, root.clone());
        let zip = FakeZipArchive::new(vec![
            ZipEntrySpec {
                name: "extension/manifest.json".to_owned(),
                content: VALID_MANIFEST.as_bytes().to_vec(),
            },
            ZipEntrySpec {
                name: "extension/popup.html".to_owned(),
                content: b"<html></html>".to_vec(),
            },
        ]);

        let install = glue.import_zip(&zip, "bitwarden.zip").unwrap();

        assert_eq!(install.version, "2026.6.1");
        assert!(install.extension_path.starts_with(&root));
        assert_eq!(settings.save_count(), 1);
        let snap = settings.snapshot();
        assert_eq!(snap.source, BitwardenBrowserExtensionSource::ManualZip);
        assert!(snap
            .last_update_status
            .as_deref()
            .is_some_and(|s| s.contains("pinned")));
        assert!(snap.last_update_check_utc.is_none());
    }

    #[test]
    fn import_zip_blocks_unsafe_entry_without_writing_outside() {
        let settings = FakeBitwardenExtensionSettingsStore::new();
        let fs = FakeExtensionInstallFs::new();
        let root = install_root();
        let mut glue = BitwardenExtensionInstallGlue::new(settings.clone(), fs.clone(), root);
        let zip = FakeZipArchive::new(vec![
            ZipEntrySpec {
                name: "manifest.json".to_owned(),
                content: VALID_MANIFEST.as_bytes().to_vec(),
            },
            ZipEntrySpec {
                name: "../outside.txt".to_owned(),
                content: b"nope".to_vec(),
            },
        ]);

        let err = glue.import_zip(&zip, "unsafe.zip").unwrap_err();
        assert_eq!(err, BitwardenExtensionInstallError::UnsafeZipPath);
        assert_eq!(settings.save_count(), 0);
        assert!(!fs.is_file(&PathBuf::from("outside.txt")));
    }

    #[test]
    fn import_unpacked_folder_copies_and_pins() {
        let settings = FakeBitwardenExtensionSettingsStore::new();
        settings.set_snapshot(BitwardenExtensionSettingsSnapshot {
            source: BitwardenBrowserExtensionSource::OfficialGitHub,
            last_update_check_utc: Some("2020-01-01T00:00:00Z".to_owned()),
            ..Default::default()
        });
        let fs = FakeExtensionInstallFs::new();
        let source = PathBuf::from("source-ext");
        fs.seed_file(source.join("manifest.json"), VALID_MANIFEST.as_bytes());
        fs.seed_file(source.join("popup.html"), b"<html></html>");
        let root = install_root();
        let mut glue = BitwardenExtensionInstallGlue::new(settings.clone(), fs, root.clone());

        let install = glue.import_unpacked_folder(&source).unwrap();

        assert_eq!(install.version, "2026.6.1");
        assert_ne!(install.extension_path, source);
        assert!(install.extension_path.starts_with(&root));
        let snap = settings.snapshot();
        assert_eq!(snap.source, BitwardenBrowserExtensionSource::ManualFolder);
        assert!(snap.last_update_check_utc.is_none());
        assert_eq!(settings.save_count(), 1);
    }

    #[test]
    fn reimport_preserves_configured_path_under_root() {
        let root = install_root();
        let current = root.join("installed-2026.5.1");
        let settings = FakeBitwardenExtensionSettingsStore::new();
        settings.set_snapshot(BitwardenExtensionSettingsSnapshot {
            source: BitwardenBrowserExtensionSource::ManualFolder,
            version: Some("2026.5.1".to_owned()),
            path: Some(current.clone()),
            ..Default::default()
        });
        let fs = FakeExtensionInstallFs::new();
        fs.seed_dir(&current);
        fs.seed_file(current.join("old-only.txt"), b"old");
        let source = PathBuf::from("source-ext");
        fs.seed_file(source.join("manifest.json"), VALID_MANIFEST.as_bytes());
        fs.seed_file(source.join("popup.html"), b"<html></html>");
        let mut glue = BitwardenExtensionInstallGlue::new(settings.clone(), fs.clone(), root);

        let install = glue.import_unpacked_folder(&source).unwrap();

        assert_eq!(install.extension_path, current);
        assert!(!fs.is_file(&current.join("old-only.txt")));
        assert!(fs.is_file(&current.join("popup.html")));
    }

    #[test]
    fn persist_failure_leaves_fs_but_settings_error() {
        let settings = FakeBitwardenExtensionSettingsStore::new();
        settings.fail_next_save("disk unavailable".to_owned());
        let fs = FakeExtensionInstallFs::new();
        let source = PathBuf::from("source-ext");
        fs.seed_file(source.join("manifest.json"), VALID_MANIFEST.as_bytes());
        let mut glue =
            BitwardenExtensionInstallGlue::new(settings.clone(), fs.clone(), install_root());

        let err = glue.import_unpacked_folder(&source).unwrap_err();
        assert!(matches!(err, BitwardenExtensionInstallError::PersistFailed(_)));
        assert_eq!(settings.save_count(), 0);
        // Files landed at stable path even though settings save failed (C# parity).
        let snap = settings.snapshot();
        assert!(snap.path.is_none());
    }

    #[test]
    fn configured_install_none_when_path_missing() {
        let settings = FakeBitwardenExtensionSettingsStore::new();
        settings.set_snapshot(BitwardenExtensionSettingsSnapshot {
            path: Some(PathBuf::from(r"C:\missing")),
            ..Default::default()
        });
        let glue = BitwardenExtensionInstallGlue::new(
            settings,
            FakeExtensionInstallFs::new(),
            install_root(),
        );
        assert!(glue.configured_install().is_none());
    }

    #[test]
    fn manifest_parse_requires_name() {
        let err = parse_extension_manifest(br#"{"version":"1"}"#).unwrap_err();
        assert!(matches!(
            err,
            BitwardenExtensionInstallError::InvalidManifest(_)
        ));
    }

    #[test]
    fn errors_never_embed_hostile_paths() {
        let err = BitwardenExtensionInstallError::PathNotConfined;
        let text = format!("{err} / {err:?}");
        assert!(!text.contains(r"C:\"));
        assert!(!text.contains("Windows"));
    }
}
