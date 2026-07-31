//! Adapter: UI [`SettingsStore`] trait ← [`wormhole_storage::SettingsStore`].
//!
//! Hosts that enable `--features storage` can inject this behind
//! [`SettingsViewModel`] so apply/save uses the storage crate's fail-closed
//! `settings.json` path (tests: temp directory). No secrets belong in this file.
//!
//! **Concurrency:** [`SettingsViewModel`] mutates via `&mut self` (single-threaded
//! per VM). One shared `Arc<StorageSettingsStore>` serializes `save` through the
//! storage crate's process-local write lock. Do not mint multiple store instances
//! for the same path (each owns its own lock) — prefer one writer per path.

use std::path::{Path, PathBuf};

use super::model::{AppSettings, CURRENT_SCHEMA_VERSION};
use super::store::{SettingsError, SettingsStore};

// Keep UI and storage schema stamps aligned; `save` stamps the storage constant.
const _: () = assert!(CURRENT_SCHEMA_VERSION == wormhole_storage::CURRENT_SCHEMA_VERSION);

/// Wraps [`wormhole_storage::SettingsStore`] for the UI settings trait.
///
/// Load/save convert between the UI and storage `AppSettings` shapes via JSON
/// (same PascalCase / numeric-enum wire format). Corrupt JSON and empty files
/// surface as [`SettingsError::Corrupt`] (fail closed — storage semantics).
/// Unknown forward-compat keys round-trip via [`AppSettings::unknown_fields`].
pub struct StorageSettingsStore {
    inner: wormhole_storage::SettingsStore,
}

impl StorageSettingsStore {
    /// Back the store with an explicit `settings.json` path (tests: temp dir).
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            inner: wormhole_storage::SettingsStore::new(path),
        }
    }

    /// `{directory}/settings.json` — same convention as storage tests.
    pub fn in_directory(directory: impl AsRef<Path>) -> Self {
        Self::new(directory.as_ref().join("settings.json"))
    }

    /// `%LOCALAPPDATA%\Wormhole\settings.json` when available.
    pub fn default_local() -> Result<Self, SettingsError> {
        let store = wormhole_storage::SettingsStore::default_local().map_err(map_storage_error)?;
        Ok(Self { inner: store })
    }

    pub fn path(&self) -> &Path {
        self.inner.path()
    }

    pub fn inner(&self) -> &wormhole_storage::SettingsStore {
        &self.inner
    }
}

impl SettingsStore for StorageSettingsStore {
    fn load(&self) -> Result<AppSettings, SettingsError> {
        let storage = self.inner.load().map_err(map_storage_error)?;
        from_storage(storage)
    }

    fn save(&self, settings: &AppSettings) -> Result<(), SettingsError> {
        let mut storage = to_storage(settings)?;
        storage.settings_schema_version = wormhole_storage::CURRENT_SCHEMA_VERSION;
        self.inner.save(&storage).map_err(map_storage_error)
    }
}

fn to_storage(settings: &AppSettings) -> Result<wormhole_storage::AppSettings, SettingsError> {
    bridge_json(settings)
}

fn from_storage(settings: wormhole_storage::AppSettings) -> Result<AppSettings, SettingsError> {
    bridge_json(&settings)
}

fn bridge_json<T, U>(value: &T) -> Result<U, SettingsError>
where
    T: serde::Serialize,
    U: serde::de::DeserializeOwned,
{
    let value = serde_json::to_value(value).map_err(|e| SettingsError::Json(e.to_string()))?;
    serde_json::from_value(value).map_err(|e| SettingsError::Json(e.to_string()))
}

fn map_storage_error(err: wormhole_storage::StorageError) -> SettingsError {
    match err {
        wormhole_storage::StorageError::CorruptSettings { path, message } => {
            SettingsError::Corrupt(format!("{} ({})", message, path.display()))
        }
        wormhole_storage::StorageError::Io(e) => SettingsError::Io(e.to_string()),
        wormhole_storage::StorageError::SettingsJson(e) => SettingsError::Json(e.to_string()),
        wormhole_storage::StorageError::AppDataPath => {
            SettingsError::Path("LOCALAPPDATA / Wormhole path unavailable".into())
        }
        other => SettingsError::Io(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::model::ApplicationTheme;
    use crate::settings::view_model::SettingsViewModel;
    use crate::settings::CURRENT_SCHEMA_VERSION;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn assert_no_settings_secrets(raw: &str) {
        let lower = raw.to_ascii_lowercase();
        assert!(!lower.contains("\"password\":"), "settings must not contain password keys");
        assert!(!raw.contains("BEGIN "), "settings must not contain PEM markers");
        assert!(!lower.contains("mcpbearertoken"), "settings must not contain MCP bearer token");
        assert!(!lower.contains("secret"), "settings must not contain secret needles");
    }

    #[test]
    fn dirty_stage_apply_reload_round_trip() {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(StorageSettingsStore::in_directory(dir.path()));
        let mut vm = SettingsViewModel::new(store.clone()).unwrap();
        assert!(!vm.is_dirty());

        vm.stage(|s| {
            s.theme = ApplicationTheme::Dark;
            s.confirm_on_tab_close = false;
            s.mcp_server_port = 9001;
            s.enable_mcp_server = true;
        });
        assert!(vm.is_dirty());
        assert!(!store.path().exists(), "stage must not write");

        vm.apply().unwrap();
        assert!(!vm.is_dirty());
        assert!(store.path().exists());

        let raw = std::fs::read_to_string(store.path()).unwrap();
        assert!(raw.contains("\"Theme\": 2"));
        assert!(raw.contains("\"EnableMcpServer\": true"));
        assert_no_settings_secrets(&raw);

        let mut reloaded = SettingsViewModel::new(store).unwrap();
        reloaded.reload().unwrap();
        assert_eq!(reloaded.current().theme, ApplicationTheme::Dark);
        assert!(!reloaded.current().confirm_on_tab_close);
        assert_eq!(reloaded.current().mcp_server_port, 9001);
        assert!(reloaded.current().enable_mcp_server);
        assert!(!reloaded.is_dirty());
    }

    #[test]
    fn corrupt_settings_fail_closed_through_adapter() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, b"{ not json").unwrap();
        let store = StorageSettingsStore::new(&path);
        let err = store.load().unwrap_err();
        assert!(
            matches!(err, SettingsError::Corrupt(_)),
            "expected Corrupt, got {err:?}"
        );
        assert!(SettingsViewModel::new(Arc::new(store)).is_err());
    }

    #[test]
    fn empty_file_fail_closed() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, b"").unwrap();
        let err = StorageSettingsStore::new(&path).load().unwrap_err();
        assert!(matches!(err, SettingsError::Corrupt(_)));
    }

    #[test]
    fn apply_noop_when_clean() {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(StorageSettingsStore::in_directory(dir.path()));
        let mut vm = SettingsViewModel::new(store.clone()).unwrap();
        vm.apply().unwrap();
        assert!(!store.path().exists());
    }

    #[test]
    fn missing_file_loads_defaults_without_creating() {
        let dir = TempDir::new().unwrap();
        let store = StorageSettingsStore::in_directory(dir.path());
        let path = store.path().to_path_buf();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.settings_schema_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(loaded.theme, ApplicationTheme::System);
        assert!(!path.exists());
        assert!(SettingsViewModel::new(Arc::new(store)).is_ok());
        assert!(!path.exists());
    }

    #[test]
    fn unknown_fields_survive_stage_apply_reload() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            r#"{
                "SettingsSchemaVersion": 8,
                "Theme": 0,
                "FutureFeatureFlag": true,
                "ExperimentalNested": { "A": 1 }
            }"#,
        )
        .unwrap();

        let store = Arc::new(StorageSettingsStore::new(&path));
        let mut vm = SettingsViewModel::new(store.clone()).unwrap();
        assert_eq!(
            vm.current().unknown_fields.get("FutureFeatureFlag"),
            Some(&serde_json::Value::Bool(true))
        );
        assert!(vm.current().unknown_fields.contains_key("ExperimentalNested"));

        vm.stage(|s| s.theme = ApplicationTheme::Dark);
        assert!(vm.is_dirty());
        vm.apply().unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(raw.contains("\"FutureFeatureFlag\": true"));
        assert!(raw.contains("\"Theme\": 2"));
        assert_no_settings_secrets(&raw);

        vm.reload().unwrap();
        assert_eq!(vm.current().theme, ApplicationTheme::Dark);
        assert_eq!(
            vm.current().unknown_fields.get("FutureFeatureFlag"),
            Some(&serde_json::Value::Bool(true))
        );
    }

    #[test]
    fn apply_stamps_current_schema_version() {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(StorageSettingsStore::in_directory(dir.path()));
        let mut vm = SettingsViewModel::new(store.clone()).unwrap();
        vm.stage(|s| {
            s.settings_schema_version = 3;
            s.theme = ApplicationTheme::Light;
        });
        vm.apply().unwrap();

        assert_eq!(vm.current().settings_schema_version, CURRENT_SCHEMA_VERSION);
        let raw = std::fs::read_to_string(store.path()).unwrap();
        assert!(raw.contains(&format!("\"SettingsSchemaVersion\": {CURRENT_SCHEMA_VERSION}")));
        let reloaded = store.load().unwrap();
        assert_eq!(reloaded.settings_schema_version, CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn legacy_schema_migrates_through_adapter() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            r#"{ "SettingsSchemaVersion": 7, "Theme": 1 }"#,
        )
        .unwrap();
        let store = Arc::new(StorageSettingsStore::new(&path));
        let vm = SettingsViewModel::new(store).unwrap();
        assert_eq!(vm.current().settings_schema_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(vm.current().theme, ApplicationTheme::Light);
        // storage migrate bumps BitwardenCliServerRegion to Current for schema < 8
        assert_eq!(
            vm.current().bitwarden_cli_server_region,
            crate::settings::BitwardenCliServerRegion::Current
        );
    }

    #[test]
    fn array_root_fail_closed() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, b"[]").unwrap();
        let err = StorageSettingsStore::new(&path).load().unwrap_err();
        assert!(matches!(err, SettingsError::Corrupt(_)));
    }

    #[test]
    fn whitespace_only_file_fail_closed() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, b"   \n\t").unwrap();
        let err = StorageSettingsStore::new(&path).load().unwrap_err();
        assert!(matches!(err, SettingsError::Corrupt(_)));
    }

    #[test]
    fn reload_discards_dirty_stage_on_storage() {
        let dir = TempDir::new().unwrap();
        let store = Arc::new(StorageSettingsStore::in_directory(dir.path()));
        let mut vm = SettingsViewModel::new(store.clone()).unwrap();
        vm.set_theme(ApplicationTheme::Light).unwrap();
        vm.stage(|s| s.theme = ApplicationTheme::Dark);
        assert!(vm.is_dirty());
        vm.reload().unwrap();
        assert!(!vm.is_dirty());
        assert_eq!(vm.current().theme, ApplicationTheme::Light);
    }
}
