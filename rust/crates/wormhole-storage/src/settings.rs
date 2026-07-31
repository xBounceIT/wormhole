//! App settings JSON under `%LOCALAPPDATA%\Wormhole\settings.json`.
//!
//! Mirrors C# `Models.AppSettings` + `Services.AppSettingsService` where practical.
//! **Divergence:** corrupt / unreadable JSON fails closed ([`StorageError::CorruptSettings`]);
//! C# returns defaults. Missing file still yields defaults (no file created until save).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};

use crate::{Result, StorageError};

/// Current settings schema version (C# `AppSettings.CurrentSchemaVersion`).
pub const CURRENT_SCHEMA_VERSION: i32 = 8;

/// Schema version that introduced Bitwarden onboarding notice fields.
pub const BITWARDEN_ONBOARDING_INTRODUCED_SCHEMA_VERSION: i32 = 6;

const DEFAULT_BITWARDEN_RELEASES_URL: &str = "repos/bitwarden/clients/releases?per_page=20";

/// Resolve `%LOCALAPPDATA%\Wormhole`.
pub fn default_app_data_dir() -> Result<PathBuf> {
    let local = std::env::var_os("LOCALAPPDATA").ok_or(StorageError::AppDataPath)?;
    Ok(PathBuf::from(local).join("Wormhole"))
}

/// Resolve `%LOCALAPPDATA%\Wormhole\settings.json`.
pub fn default_settings_path() -> Result<PathBuf> {
    Ok(default_app_data_dir()?.join("settings.json"))
}

/// C# `ApplicationTheme` (numeric JSON).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(i32)]
pub enum ApplicationTheme {
    #[default]
    System = 0,
    Light = 1,
    Dark = 2,
}

/// C# `AppAuthenticationMode` (numeric JSON).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(i32)]
pub enum AppAuthenticationMode {
    #[default]
    Disabled = 0,
    Pin = 1,
    Password = 2,
    WindowsHello = 3,
}

/// C# `AppAuthenticationFallbackMethod` (numeric JSON).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(i32)]
pub enum AppAuthenticationFallbackMethod {
    #[default]
    Pin = 0,
    Password = 1,
}

/// C# `BitwardenBrowserExtensionSource` (numeric JSON).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(i32)]
pub enum BitwardenBrowserExtensionSource {
    #[default]
    OfficialGitHub = 0,
    ManualZip = 1,
    ManualFolder = 2,
}

/// C# `BitwardenCliServerRegion` (numeric JSON).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(i32)]
pub enum BitwardenCliServerRegion {
    #[default]
    UnitedStates = 0,
    Europe = 1,
    Current = 2,
}

macro_rules! serde_i32_enum {
    ($ty:ty) => {
        impl Serialize for $ty {
            fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
                serializer.serialize_i32(*self as i32)
            }
        }
        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
                let v = i32::deserialize(deserializer)?;
                Self::try_from(v).map_err(de::Error::custom)
            }
        }
    };
}

impl TryFrom<i32> for ApplicationTheme {
    type Error = String;
    fn try_from(value: i32) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::System),
            1 => Ok(Self::Light),
            2 => Ok(Self::Dark),
            _ => Err(format!("unknown ApplicationTheme {value}")),
        }
    }
}
impl TryFrom<i32> for AppAuthenticationMode {
    type Error = String;
    fn try_from(value: i32) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Disabled),
            1 => Ok(Self::Pin),
            2 => Ok(Self::Password),
            3 => Ok(Self::WindowsHello),
            _ => Err(format!("unknown AppAuthenticationMode {value}")),
        }
    }
}
impl TryFrom<i32> for AppAuthenticationFallbackMethod {
    type Error = String;
    fn try_from(value: i32) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Pin),
            1 => Ok(Self::Password),
            _ => Err(format!("unknown AppAuthenticationFallbackMethod {value}")),
        }
    }
}
impl TryFrom<i32> for BitwardenBrowserExtensionSource {
    type Error = String;
    fn try_from(value: i32) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::OfficialGitHub),
            1 => Ok(Self::ManualZip),
            2 => Ok(Self::ManualFolder),
            _ => Err(format!("unknown BitwardenBrowserExtensionSource {value}")),
        }
    }
}
impl TryFrom<i32> for BitwardenCliServerRegion {
    type Error = String;
    fn try_from(value: i32) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::UnitedStates),
            1 => Ok(Self::Europe),
            2 => Ok(Self::Current),
            _ => Err(format!("unknown BitwardenCliServerRegion {value}")),
        }
    }
}

serde_i32_enum!(ApplicationTheme);
serde_i32_enum!(AppAuthenticationMode);
serde_i32_enum!(AppAuthenticationFallbackMethod);
serde_i32_enum!(BitwardenBrowserExtensionSource);
serde_i32_enum!(BitwardenCliServerRegion);

/// Mirrors C# `Wormhole.Models.AppSettings` (PascalCase JSON, schema v8).
///
/// No passwords / MCP bearer token -- those stay in Credential Manager / DPAPI.
///
/// Unknown JSON properties are retained in [`Self::unknown_fields`] and written
/// back on save so schema migrations do not silently drop forward-compat keys
/// (intentional hardening vs C# System.Text.Json re-serialize drop).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[serde(default)]
pub struct AppSettings {
    pub settings_schema_version: i32,
    pub theme: ApplicationTheme,
    pub confirm_on_tab_close: bool,
    pub default_ssh_font: String,
    pub default_ssh_font_size: i32,
    pub auto_copy_on_select: bool,
    pub auto_check_for_updates: bool,
    /// .NET `DateTimeOffset?` as round-trip / RFC3339 text when present.
    pub last_update_check: Option<String>,
    pub skipped_update_version: Option<String>,
    pub log_retention_days: i32,
    pub sidebar_width: i32,
    pub app_authentication_mode: AppAuthenticationMode,
    pub app_authentication_hello_fallback: AppAuthenticationFallbackMethod,
    pub app_authentication_idle_timeout_minutes: Option<i32>,
    pub prompt_before_tunnel_connect: bool,
    pub enable_mcp_server: bool,
    pub mcp_server_port: i32,
    pub enable_bitwarden_vault: bool,
    pub bitwarden_cli_path: String,
    pub bitwarden_cli_server_region: BitwardenCliServerRegion,
    pub bitwarden_cli_releases_url: String,
    pub bitwarden_cli_version: Option<String>,
    pub bitwarden_cli_sha256: Option<String>,
    pub bitwarden_cli_asset_name: Option<String>,
    pub bitwarden_cli_download_url: Option<String>,
    pub bitwarden_cli_install_status: Option<String>,
    pub bitwarden_cli_install_error: Option<String>,
    pub bitwarden_credential_last_sync_utc: Option<String>,
    pub bitwarden_credential_last_sync_status: Option<String>,
    pub bitwarden_credential_last_sync_error: Option<String>,
    pub bitwarden_credential_available_count: Option<i32>,
    pub bitwarden_onboarding_notice_seen_version: i32,
    pub bitwarden_onboarding_notice_pending_version: i32,
    pub enable_bitwarden_browser_extension: bool,
    pub bitwarden_browser_extension_source: BitwardenBrowserExtensionSource,
    pub bitwarden_browser_extension_releases_url: String,
    pub bitwarden_browser_extension_version: Option<String>,
    pub bitwarden_browser_extension_path: Option<String>,
    pub bitwarden_browser_extension_sha256: Option<String>,
    pub bitwarden_browser_extension_asset_name: Option<String>,
    pub bitwarden_browser_extension_download_url: Option<String>,
    pub bitwarden_browser_extension_last_update_check_utc: Option<String>,
    pub bitwarden_browser_extension_last_update_status: Option<String>,
    pub bitwarden_browser_extension_last_update_error: Option<String>,
    pub bitwarden_browser_extension_available_version: Option<String>,
    /// Forward-compat JSON keys not modeled on [`AppSettings`] yet.
    #[serde(flatten)]
    pub unknown_fields: serde_json::Map<String, serde_json::Value>,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            settings_schema_version: CURRENT_SCHEMA_VERSION,
            theme: ApplicationTheme::System,
            confirm_on_tab_close: true,
            default_ssh_font: "Cascadia Mono".into(),
            default_ssh_font_size: 12,
            auto_copy_on_select: true,
            auto_check_for_updates: true,
            last_update_check: None,
            skipped_update_version: None,
            log_retention_days: 14,
            sidebar_width: 320,
            app_authentication_mode: AppAuthenticationMode::Disabled,
            app_authentication_hello_fallback: AppAuthenticationFallbackMethod::Pin,
            app_authentication_idle_timeout_minutes: Some(15),
            prompt_before_tunnel_connect: true,
            enable_mcp_server: false,
            mcp_server_port: 8765,
            enable_bitwarden_vault: false,
            bitwarden_cli_path: "bw".into(),
            bitwarden_cli_server_region: BitwardenCliServerRegion::UnitedStates,
            bitwarden_cli_releases_url: DEFAULT_BITWARDEN_RELEASES_URL.into(),
            bitwarden_cli_version: None,
            bitwarden_cli_sha256: None,
            bitwarden_cli_asset_name: None,
            bitwarden_cli_download_url: None,
            bitwarden_cli_install_status: None,
            bitwarden_cli_install_error: None,
            bitwarden_credential_last_sync_utc: None,
            bitwarden_credential_last_sync_status: None,
            bitwarden_credential_last_sync_error: None,
            bitwarden_credential_available_count: None,
            bitwarden_onboarding_notice_seen_version: 0,
            bitwarden_onboarding_notice_pending_version: 0,
            enable_bitwarden_browser_extension: false,
            bitwarden_browser_extension_source: BitwardenBrowserExtensionSource::OfficialGitHub,
            bitwarden_browser_extension_releases_url: DEFAULT_BITWARDEN_RELEASES_URL.into(),
            bitwarden_browser_extension_version: None,
            bitwarden_browser_extension_path: None,
            bitwarden_browser_extension_sha256: None,
            bitwarden_browser_extension_asset_name: None,
            bitwarden_browser_extension_download_url: None,
            bitwarden_browser_extension_last_update_check_utc: None,
            bitwarden_browser_extension_last_update_status: None,
            bitwarden_browser_extension_last_update_error: None,
            bitwarden_browser_extension_available_version: None,
            unknown_fields: serde_json::Map::new(),
        }
    }
}

/// Read/write `settings.json` with a process-local write lock.
pub struct SettingsStore {
    path: PathBuf,
    write_lock: Mutex<()>,
}

impl SettingsStore {
    /// Store backed by an explicit file path.
    ///
    /// Production uses [`Self::default_local`] (`%LOCALAPPDATA%\Wormhole\settings.json`).
    /// Tests should inject a path under a temp directory.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            write_lock: Mutex::new(()),
        }
    }

    /// Store at [`default_settings_path`].
    pub fn default_local() -> Result<Self> {
        Ok(Self::new(default_settings_path()?))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load settings. Missing file -> defaults. Corrupt JSON -> [`StorageError::CorruptSettings`].
    ///
    /// Applies schema migrations in memory; best-effort persists when migration ran
    /// (same as C# `TryPersistMigratedSettings` -- persist failure is swallowed).
    pub fn load(&self) -> Result<AppSettings> {
        let (settings, migrated) = self.load_and_migrate()?;
        if migrated {
            let _ = self.save(&settings);
        }
        Ok(settings)
    }

    /// Load + migrate without auto-persist. Returns `(settings, migrated)`.
    pub fn load_and_migrate(&self) -> Result<(AppSettings, bool)> {
        match fs::read(&self.path) {
            Ok(bytes) => {
                if bytes.is_empty() {
                    return Err(StorageError::CorruptSettings {
                        path: self.path.clone(),
                        message: "empty file".into(),
                    });
                }
                let (mut settings, schema_version) =
                    parse_settings_document(&bytes).map_err(|message| {
                        StorageError::CorruptSettings {
                            path: self.path.clone(),
                            message,
                        }
                    })?;
                let migrated = apply_schema_migrations(&mut settings, schema_version);
                Ok((settings, migrated))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((AppSettings::default(), false)),
            Err(e) => Err(StorageError::Io(e)),
        }
    }

    /// Persist settings as indented PascalCase JSON (creates parent directories).
    pub fn save(&self, settings: &AppSettings) -> Result<()> {
        let _guard = self
            .write_lock
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_vec_pretty(settings)?;
        fs::write(&self.path, json)?;
        Ok(())
    }
}

/// Parse settings JSON once: schema version (missing → 0) + [`AppSettings`].
/// Missing keys use defaults; unknown object keys land in [`AppSettings::unknown_fields`].
fn parse_settings_document(json: &[u8]) -> std::result::Result<(AppSettings, i32), String> {
    let value: serde_json::Value =
        serde_json::from_slice(json).map_err(|e| format!("invalid json: {e}"))?;
    let obj = value
        .as_object()
        .ok_or_else(|| "settings root must be a JSON object".to_owned())?;
    let schema_version = match obj.get("SettingsSchemaVersion") {
        None => 0,
        Some(v) => v
            .as_i64()
            .map(|n| n as i32)
            .ok_or_else(|| "SettingsSchemaVersion must be an integer".to_owned())?,
    };
    let settings: AppSettings =
        serde_json::from_value(value).map_err(|e| format!("settings shape: {e}"))?;
    Ok((settings, schema_version))
}

/// Apply C# `AppSettingsService` schema bump steps. Returns whether anything migrated.
fn apply_schema_migrations(settings: &mut AppSettings, schema_version: i32) -> bool {
    if schema_version >= CURRENT_SCHEMA_VERSION {
        return false;
    }
    if schema_version < 1 {
        settings.prompt_before_tunnel_connect = true;
    }
    if schema_version < 2 && settings.bitwarden_cli_path.trim().is_empty() {
        settings.bitwarden_cli_path = "bw".into();
    }
    if schema_version < 3 && settings.bitwarden_browser_extension_releases_url.trim().is_empty() {
        settings.bitwarden_browser_extension_releases_url = DEFAULT_BITWARDEN_RELEASES_URL.into();
    }
    if schema_version < 4 {
        settings.bitwarden_browser_extension_source =
            infer_bitwarden_browser_extension_source(settings);
    }
    if schema_version < 5 && settings.bitwarden_cli_releases_url.trim().is_empty() {
        settings.bitwarden_cli_releases_url = DEFAULT_BITWARDEN_RELEASES_URL.into();
    }
    if schema_version < BITWARDEN_ONBOARDING_INTRODUCED_SCHEMA_VERSION {
        settings.bitwarden_onboarding_notice_pending_version = 1;
    }
    if schema_version < 8 {
        settings.bitwarden_cli_server_region = BitwardenCliServerRegion::Current;
    }
    settings.settings_schema_version = CURRENT_SCHEMA_VERSION;
    true
}

fn infer_bitwarden_browser_extension_source(
    settings: &AppSettings,
) -> BitwardenBrowserExtensionSource {
    let path = settings
        .bitwarden_browser_extension_path
        .as_deref()
        .unwrap_or("")
        .trim();
    if path.is_empty() {
        return BitwardenBrowserExtensionSource::OfficialGitHub;
    }
    let download = settings
        .bitwarden_browser_extension_download_url
        .as_deref()
        .unwrap_or("")
        .trim();
    if !download.is_empty() {
        return BitwardenBrowserExtensionSource::OfficialGitHub;
    }
    let asset = settings
        .bitwarden_browser_extension_asset_name
        .as_deref()
        .unwrap_or("")
        .trim();
    if asset.is_empty() {
        BitwardenBrowserExtensionSource::ManualFolder
    } else {
        BitwardenBrowserExtensionSource::ManualZip
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn defaults_match_csharp_shape() {
        let s = AppSettings::default();
        assert_eq!(s.settings_schema_version, CURRENT_SCHEMA_VERSION);
        assert!(s.prompt_before_tunnel_connect);
        assert_eq!(s.log_retention_days, 14);
        assert_eq!(s.default_ssh_font, "Cascadia Mono");
        assert!(!s.enable_mcp_server);
        assert_eq!(s.mcp_server_port, 8765);
        assert_eq!(s.bitwarden_cli_path, "bw");
        assert_eq!(
            s.bitwarden_cli_server_region,
            BitwardenCliServerRegion::UnitedStates
        );
    }

    #[test]
    fn missing_file_yields_defaults_without_creating() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        let store = SettingsStore::new(&path);
        let loaded = store.load().unwrap();
        assert_eq!(loaded, AppSettings::default());
        assert!(!path.exists());
    }

    #[test]
    fn round_trip_save_load() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        let store = SettingsStore::new(&path);
        let mut settings = AppSettings::default();
        settings.confirm_on_tab_close = false;
        settings.theme = ApplicationTheme::Dark;
        settings.enable_mcp_server = true;
        settings.mcp_server_port = 9001;
        store.save(&settings).unwrap();

        let loaded = store.load().unwrap();
        assert_eq!(loaded.confirm_on_tab_close, false);
        assert_eq!(loaded.theme, ApplicationTheme::Dark);
        assert!(loaded.enable_mcp_server);
        assert_eq!(loaded.mcp_server_port, 9001);

        let raw = fs::read_to_string(&path).unwrap();
        assert!(raw.contains("\"Theme\": 2"));
        assert!(raw.contains("\"EnableMcpServer\": true"));
        assert!(!raw.to_lowercase().contains("password\":"));
        assert!(!raw.contains("BEGIN "));
    }

    #[test]
    fn corrupt_json_fails_closed() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(&path, b"{ not json").unwrap();
        let store = SettingsStore::new(&path);
        let err = store.load().unwrap_err();
        assert!(
            matches!(err, StorageError::CorruptSettings { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn empty_file_fails_closed() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(&path, b"").unwrap();
        let err = SettingsStore::new(&path).load().unwrap_err();
        assert!(matches!(err, StorageError::CorruptSettings { .. }));
    }

    #[test]
    fn array_root_fails_closed() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(&path, b"[]").unwrap();
        let err = SettingsStore::new(&path).load().unwrap_err();
        assert!(matches!(err, StorageError::CorruptSettings { .. }));
    }

    #[test]
    fn partial_json_keeps_defaults_for_missing_keys() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(
            &path,
            r#"{ "SettingsSchemaVersion": 8, "SidebarWidth": 200 }"#,
        )
        .unwrap();
        let loaded = SettingsStore::new(&path).load().unwrap();
        assert_eq!(loaded.sidebar_width, 200);
        assert_eq!(loaded.log_retention_days, 14);
        assert_eq!(loaded.default_ssh_font, "Cascadia Mono");
        assert!(loaded.confirm_on_tab_close);
        assert!(loaded.prompt_before_tunnel_connect);
    }

    #[test]
    fn legacy_schema_migrates_prompt_and_onboarding() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(
            &path,
            r#"{ "PromptBeforeTunnelConnect": false }"#,
        )
        .unwrap();
        let store = SettingsStore::new(&path);
        let loaded = store.load().unwrap();
        assert!(loaded.prompt_before_tunnel_connect);
        assert_eq!(loaded.bitwarden_onboarding_notice_pending_version, 1);
        assert_eq!(loaded.settings_schema_version, CURRENT_SCHEMA_VERSION);

        let saved = parse_settings_document(&fs::read(&path).unwrap()).unwrap().0;
        assert!(saved.prompt_before_tunnel_connect);
        assert_eq!(saved.settings_schema_version, CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn versioned_off_prompt_preserved() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(
            &path,
            r#"{ "SettingsSchemaVersion": 1, "PromptBeforeTunnelConnect": false }"#,
        )
        .unwrap();
        let loaded = SettingsStore::new(&path).load().unwrap();
        assert!(!loaded.prompt_before_tunnel_connect);
        assert_eq!(loaded.settings_schema_version, CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn schema_7_migrates_cli_region_to_current() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(&path, r#"{ "SettingsSchemaVersion": 7 }"#).unwrap();
        let loaded = SettingsStore::new(&path).load().unwrap();
        assert_eq!(
            loaded.bitwarden_cli_server_region,
            BitwardenCliServerRegion::Current
        );
    }

    #[test]
    fn schema_migrate_preserves_known_and_unknown_fields() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(
            &path,
            r#"{
                "SettingsSchemaVersion": 3,
                "SidebarWidth": 240,
                "Theme": 1,
                "FutureFeatureFlag": true,
                "ExperimentalNested": { "A": 1 }
            }"#,
        )
        .unwrap();
        let store = SettingsStore::new(&path);
        let loaded = store.load().unwrap();
        assert_eq!(loaded.settings_schema_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(loaded.sidebar_width, 240);
        assert_eq!(loaded.theme, ApplicationTheme::Light);
        assert_eq!(
            loaded.unknown_fields.get("FutureFeatureFlag"),
            Some(&serde_json::Value::Bool(true))
        );
        assert!(loaded.unknown_fields.contains_key("ExperimentalNested"));
        // Onboarding + region migrations still apply for schema < 6 / < 8.
        assert_eq!(loaded.bitwarden_onboarding_notice_pending_version, 1);
        assert_eq!(
            loaded.bitwarden_cli_server_region,
            BitwardenCliServerRegion::Current
        );

        let raw = fs::read_to_string(&path).unwrap();
        assert!(raw.contains("\"FutureFeatureFlag\": true"));
        assert!(raw.contains("\"SidebarWidth\": 240"));
        assert!(!raw.to_ascii_lowercase().contains("\"password\":"));
        assert!(!raw.contains("BEGIN "));
    }

    #[test]
    fn unknown_theme_enum_fails_closed() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(&path, r#"{ "SettingsSchemaVersion": 8, "Theme": 99 }"#).unwrap();
        let err = SettingsStore::new(&path).load().unwrap_err();
        assert!(matches!(err, StorageError::CorruptSettings { .. }));
    }

    #[test]
    fn non_integer_schema_version_fails_closed() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        fs::write(&path, r#"{ "SettingsSchemaVersion": "eight" }"#).unwrap();
        let err = SettingsStore::new(&path).load().unwrap_err();
        assert!(matches!(err, StorageError::CorruptSettings { .. }));
    }

    #[test]
    fn default_settings_path_confined_under_wormhole_localappdata() {
        let dir = default_app_data_dir().expect("LOCALAPPDATA");
        assert_eq!(dir.file_name().and_then(|s| s.to_str()), Some("Wormhole"));
        let local = std::env::var_os("LOCALAPPDATA").expect("LOCALAPPDATA");
        assert!(dir.starts_with(PathBuf::from(local)));
        let settings = default_settings_path().unwrap();
        assert_eq!(settings, dir.join("settings.json"));
        assert_eq!(
            settings.file_name().and_then(|s| s.to_str()),
            Some("settings.json")
        );
    }
}
