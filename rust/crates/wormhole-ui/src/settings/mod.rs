//! Settings JSON store + view-model (GPUI-independent).

mod model;
mod store;
mod view_model;

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
pub use view_model::{normalize_retention_days, SettingsViewModel};

#[cfg(feature = "storage")]
pub use storage_store::StorageSettingsStore;
