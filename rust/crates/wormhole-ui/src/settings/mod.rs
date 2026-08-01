//! Settings JSON store + view-model (GPUI-independent).

mod model;
mod store;
mod terminal_apply;
mod view_model;

#[cfg(feature = "mcp")]
mod mcp;
mod security;

#[cfg(feature = "storage")]
mod storage_store;

pub use model::{
    AppAuthenticationFallbackMethod, AppAuthenticationMode, AppSettings, ApplicationTheme,
    BitwardenBrowserExtensionSource, BitwardenCliServerRegion, BITWARDEN_ONBOARDING_INTRODUCED_SCHEMA_VERSION,
    CURRENT_SCHEMA_VERSION,
};
pub use store::{
    confined_settings_path, JsonFileSettingsStore, MemorySettingsStore, SettingsError,
    SettingsStore,
};
pub use terminal_apply::{
    apply_terminal_settings_from_app, apply_terminal_settings_to_fake,
    terminal_settings_config_from_app,
};
pub use view_model::{normalize_retention_days, SettingsViewModel};

#[cfg(feature = "mcp")]
pub use mcp::{
    validate_mcp_port_setting, FakeMcpApplyHost, FakeMcpTokenHandle, McpApplyError,
    McpApplyHost, McpNestedSink, McpPortError, McpSettingsError, McpSettingsFakeHarness,
    McpSettingsGlue, McpSettingsUiState, McpSettingsVm, McpTokenError, McpTokenHandle,
};
pub use security::{
    effective_idle_policy, fallback_relevant, validate_idle_timeout,
    IdleLockPolicy, SecuritySettingsError, SecuritySettingsFakeHarness, SecuritySettingsGlue,
    SecuritySettingsUiState, SecuritySettingsVm, IDLE_TIMEOUT_PRESETS,
};

#[cfg(feature = "storage")]
pub use storage_store::StorageSettingsStore;
