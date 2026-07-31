//! App settings JSON model (mirrors `Wormhole.Models.AppSettings`).

use serde::{Deserialize, Serialize};
use wormhole_terminal::{DEFAULT_SSH_FONT_FAMILY, DEFAULT_SSH_FONT_SIZE};

/// Current on-disk schema version (C# `AppSettings.CurrentSchemaVersion`).
pub const CURRENT_SCHEMA_VERSION: i32 = 8;
/// Schema version that introduced Bitwarden onboarding notice fields.
pub const BITWARDEN_ONBOARDING_INTRODUCED_SCHEMA_VERSION: i32 = 6;

const DEFAULT_BITWARDEN_RELEASES_URL: &str = "repos/bitwarden/clients/releases?per_page=20";

/// Persisted application settings (`%LOCALAPPDATA%\Wormhole\settings.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AppSettings {
    #[serde(default = "default_schema_version")]
    pub settings_schema_version: i32,

    #[serde(default)]
    pub theme: ApplicationTheme,
    #[serde(default = "default_true")]
    pub confirm_on_tab_close: bool,
    #[serde(default = "default_ssh_font")]
    pub default_ssh_font: String,
    #[serde(default = "default_ssh_font_size")]
    pub default_ssh_font_size: i32,
    #[serde(default = "default_true")]
    pub auto_copy_on_select: bool,

    #[serde(default = "default_true")]
    pub auto_check_for_updates: bool,
    #[serde(default)]
    pub last_update_check: Option<String>,
    #[serde(default)]
    pub skipped_update_version: Option<String>,
    #[serde(default = "default_log_retention_days")]
    pub log_retention_days: i32,

    #[serde(default = "default_sidebar_width")]
    pub sidebar_width: i32,

    #[serde(default)]
    pub app_authentication_mode: AppAuthenticationMode,
    #[serde(default)]
    pub app_authentication_hello_fallback: AppAuthenticationFallbackMethod,
    #[serde(default = "default_idle_timeout")]
    pub app_authentication_idle_timeout_minutes: Option<i32>,

    #[serde(default = "default_true")]
    pub prompt_before_tunnel_connect: bool,

    #[serde(default)]
    pub enable_mcp_server: bool,
    #[serde(default = "default_mcp_port")]
    pub mcp_server_port: i32,

    #[serde(default)]
    pub enable_bitwarden_vault: bool,
    #[serde(default = "default_bw_cli")]
    pub bitwarden_cli_path: String,
    #[serde(default)]
    pub bitwarden_cli_server_region: BitwardenCliServerRegion,
    #[serde(default = "default_bw_releases")]
    pub bitwarden_cli_releases_url: String,
    #[serde(default)]
    pub bitwarden_cli_version: Option<String>,
    #[serde(default)]
    pub bitwarden_cli_sha256: Option<String>,
    #[serde(default)]
    pub bitwarden_cli_asset_name: Option<String>,
    #[serde(default)]
    pub bitwarden_cli_download_url: Option<String>,
    #[serde(default)]
    pub bitwarden_cli_install_status: Option<String>,
    #[serde(default)]
    pub bitwarden_cli_install_error: Option<String>,
    #[serde(default)]
    pub bitwarden_credential_last_sync_utc: Option<String>,
    #[serde(default)]
    pub bitwarden_credential_last_sync_status: Option<String>,
    #[serde(default)]
    pub bitwarden_credential_last_sync_error: Option<String>,
    #[serde(default)]
    pub bitwarden_credential_available_count: Option<i32>,
    #[serde(default)]
    pub bitwarden_onboarding_notice_seen_version: i32,
    #[serde(default)]
    pub bitwarden_onboarding_notice_pending_version: i32,

    #[serde(default)]
    pub enable_bitwarden_browser_extension: bool,
    #[serde(default)]
    pub bitwarden_browser_extension_source: BitwardenBrowserExtensionSource,
    #[serde(default = "default_bw_releases")]
    pub bitwarden_browser_extension_releases_url: String,
    #[serde(default)]
    pub bitwarden_browser_extension_version: Option<String>,
    #[serde(default)]
    pub bitwarden_browser_extension_path: Option<String>,
    #[serde(default)]
    pub bitwarden_browser_extension_sha256: Option<String>,
    #[serde(default)]
    pub bitwarden_browser_extension_asset_name: Option<String>,
    #[serde(default)]
    pub bitwarden_browser_extension_download_url: Option<String>,
    #[serde(default)]
    pub bitwarden_browser_extension_last_update_check_utc: Option<String>,
    #[serde(default)]
    pub bitwarden_browser_extension_last_update_status: Option<String>,
    #[serde(default)]
    pub bitwarden_browser_extension_last_update_error: Option<String>,
    #[serde(default)]
    pub bitwarden_browser_extension_available_version: Option<String>,

    /// Forward-compat JSON keys not modeled yet (parity with `wormhole-storage::AppSettings`).
    /// Retained across load/save so `StorageSettingsStore` does not strip unknown keys.
    #[serde(default, flatten)]
    pub unknown_fields: serde_json::Map<String, serde_json::Value>,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            settings_schema_version: CURRENT_SCHEMA_VERSION,
            theme: ApplicationTheme::System,
            confirm_on_tab_close: true,
            default_ssh_font: default_ssh_font(),
            default_ssh_font_size: default_ssh_font_size(),
            auto_copy_on_select: true,
            auto_check_for_updates: true,
            last_update_check: None,
            skipped_update_version: None,
            log_retention_days: default_log_retention_days(),
            sidebar_width: default_sidebar_width(),
            app_authentication_mode: AppAuthenticationMode::Disabled,
            app_authentication_hello_fallback: AppAuthenticationFallbackMethod::Pin,
            app_authentication_idle_timeout_minutes: default_idle_timeout(),
            prompt_before_tunnel_connect: true,
            enable_mcp_server: false,
            mcp_server_port: default_mcp_port(),
            enable_bitwarden_vault: false,
            bitwarden_cli_path: default_bw_cli(),
            bitwarden_cli_server_region: BitwardenCliServerRegion::UnitedStates,
            bitwarden_cli_releases_url: default_bw_releases(),
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
            bitwarden_browser_extension_releases_url: default_bw_releases(),
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

impl AppSettings {
    /// Apply forward migrations from an older on-disk schema (mirrors C# `AppSettingsService.Load`).
    pub fn migrate_from_schema(&mut self, schema_version: i32) -> bool {
        if schema_version >= CURRENT_SCHEMA_VERSION {
            return false;
        }
        if schema_version < 1 {
            self.prompt_before_tunnel_connect = true;
        }
        if schema_version < 2 && self.bitwarden_cli_path.trim().is_empty() {
            self.bitwarden_cli_path = default_bw_cli();
        }
        if schema_version < 3 && self.bitwarden_browser_extension_releases_url.trim().is_empty() {
            self.bitwarden_browser_extension_releases_url = default_bw_releases();
        }
        if schema_version < 4 {
            self.bitwarden_browser_extension_source =
                infer_bitwarden_browser_extension_source(self);
        }
        if schema_version < 5 && self.bitwarden_cli_releases_url.trim().is_empty() {
            self.bitwarden_cli_releases_url = default_bw_releases();
        }
        if schema_version < BITWARDEN_ONBOARDING_INTRODUCED_SCHEMA_VERSION {
            self.bitwarden_onboarding_notice_pending_version = 1;
        }
        if schema_version < 8 {
            self.bitwarden_cli_server_region = BitwardenCliServerRegion::Current;
        }
        self.settings_schema_version = CURRENT_SCHEMA_VERSION;
        true
    }
}

fn infer_bitwarden_browser_extension_source(
    settings: &AppSettings,
) -> BitwardenBrowserExtensionSource {
    if settings
        .bitwarden_browser_extension_path
        .as_ref()
        .map(|s| s.trim().is_empty())
        .unwrap_or(true)
    {
        return BitwardenBrowserExtensionSource::OfficialGitHub;
    }
    if settings
        .bitwarden_browser_extension_download_url
        .as_ref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false)
    {
        return BitwardenBrowserExtensionSource::OfficialGitHub;
    }
    if settings
        .bitwarden_browser_extension_asset_name
        .as_ref()
        .map(|s| s.trim().is_empty())
        .unwrap_or(true)
    {
        BitwardenBrowserExtensionSource::ManualFolder
    } else {
        BitwardenBrowserExtensionSource::ManualZip
    }
}

/// UI theme (C# `ApplicationTheme` — numeric JSON).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(i32)]
pub enum ApplicationTheme {
    #[default]
    System = 0,
    Light = 1,
    Dark = 2,
}

impl Serialize for ApplicationTheme {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_i32(*self as i32)
    }
}

impl<'de> Deserialize<'de> for ApplicationTheme {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let v = i32::deserialize(deserializer)?;
        match v {
            0 => Ok(Self::System),
            1 => Ok(Self::Light),
            2 => Ok(Self::Dark),
            other => Err(serde::de::Error::custom(format!(
                "unknown ApplicationTheme {other}"
            ))),
        }
    }
}

/// App unlock mode (C# `AppAuthenticationMode` — numeric JSON).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(i32)]
pub enum AppAuthenticationMode {
    #[default]
    Disabled = 0,
    Pin = 1,
    Password = 2,
    WindowsHello = 3,
}

impl Serialize for AppAuthenticationMode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_i32(*self as i32)
    }
}

impl<'de> Deserialize<'de> for AppAuthenticationMode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let v = i32::deserialize(deserializer)?;
        match v {
            0 => Ok(Self::Disabled),
            1 => Ok(Self::Pin),
            2 => Ok(Self::Password),
            3 => Ok(Self::WindowsHello),
            other => Err(serde::de::Error::custom(format!(
                "unknown AppAuthenticationMode {other}"
            ))),
        }
    }
}

/// Hello fallback secret kind (C# `AppAuthenticationFallbackMethod`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(i32)]
pub enum AppAuthenticationFallbackMethod {
    #[default]
    Pin = 0,
    Password = 1,
}

impl Serialize for AppAuthenticationFallbackMethod {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_i32(*self as i32)
    }
}

impl<'de> Deserialize<'de> for AppAuthenticationFallbackMethod {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let v = i32::deserialize(deserializer)?;
        match v {
            0 => Ok(Self::Pin),
            1 => Ok(Self::Password),
            other => Err(serde::de::Error::custom(format!(
                "unknown AppAuthenticationFallbackMethod {other}"
            ))),
        }
    }
}

/// Bitwarden browser extension install source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(i32)]
pub enum BitwardenBrowserExtensionSource {
    #[default]
    OfficialGitHub = 0,
    ManualZip = 1,
    ManualFolder = 2,
}

impl Serialize for BitwardenBrowserExtensionSource {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_i32(*self as i32)
    }
}

impl<'de> Deserialize<'de> for BitwardenBrowserExtensionSource {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let v = i32::deserialize(deserializer)?;
        match v {
            0 => Ok(Self::OfficialGitHub),
            1 => Ok(Self::ManualZip),
            2 => Ok(Self::ManualFolder),
            other => Err(serde::de::Error::custom(format!(
                "unknown BitwardenBrowserExtensionSource {other}"
            ))),
        }
    }
}

/// Bitwarden CLI server region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(i32)]
pub enum BitwardenCliServerRegion {
    #[default]
    UnitedStates = 0,
    Europe = 1,
    Current = 2,
}

impl Serialize for BitwardenCliServerRegion {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_i32(*self as i32)
    }
}

impl<'de> Deserialize<'de> for BitwardenCliServerRegion {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let v = i32::deserialize(deserializer)?;
        match v {
            0 => Ok(Self::UnitedStates),
            1 => Ok(Self::Europe),
            2 => Ok(Self::Current),
            other => Err(serde::de::Error::custom(format!(
                "unknown BitwardenCliServerRegion {other}"
            ))),
        }
    }
}

fn default_schema_version() -> i32 {
    CURRENT_SCHEMA_VERSION
}
fn default_true() -> bool {
    true
}
fn default_ssh_font() -> String {
    DEFAULT_SSH_FONT_FAMILY.into()
}
fn default_ssh_font_size() -> i32 {
    DEFAULT_SSH_FONT_SIZE as i32
}
fn default_log_retention_days() -> i32 {
    14
}
fn default_sidebar_width() -> i32 {
    320
}
fn default_idle_timeout() -> Option<i32> {
    Some(15)
}
fn default_mcp_port() -> i32 {
    8765
}
fn default_bw_cli() -> String {
    "bw".into()
}
fn default_bw_releases() -> String {
    DEFAULT_BITWARDEN_RELEASES_URL.into()
}
