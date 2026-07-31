//! Settings persistence traits + JSON file / memory backends.
//!
//! Write coordination with the storage-writes agent is via this trait — the JSON
//! file backend here is independent of SQLite node writes.

use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

use thiserror::Error;

use super::model::{AppSettings, CURRENT_SCHEMA_VERSION};

/// Errors from settings load / save.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SettingsError {
    #[error("settings IO error: {0}")]
    Io(String),
    #[error("settings JSON error: {0}")]
    Json(String),
    #[error("settings path error: {0}")]
    Path(String),
    /// Corrupt / unreadable document when the backend fails closed
    /// (storage-backed `StorageSettingsStore` via `wormhole-storage`).
    #[error("corrupt settings: {0}")]
    Corrupt(String),
}

/// Abstraction over the settings JSON store (C# `IAppSettingsService`).
pub trait SettingsStore: Send + Sync {
    fn load(&self) -> Result<AppSettings, SettingsError>;
    fn save(&self, settings: &AppSettings) -> Result<(), SettingsError>;
}

/// In-memory store for tests and hosts that inject settings without a file.
#[derive(Debug, Default)]
pub struct MemorySettingsStore {
    inner: Mutex<AppSettings>,
}

impl MemorySettingsStore {
    pub fn new(settings: AppSettings) -> Self {
        Self {
            inner: Mutex::new(settings),
        }
    }

    pub fn snapshot(&self) -> AppSettings {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

impl SettingsStore for MemorySettingsStore {
    fn load(&self) -> Result<AppSettings, SettingsError> {
        Ok(self
            .inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone())
    }

    fn save(&self, settings: &AppSettings) -> Result<(), SettingsError> {
        *self.inner.lock().unwrap_or_else(|p| p.into_inner()) = settings.clone();
        Ok(())
    }
}

/// `{directory}/settings.json` file store with lexical path confinement.
///
/// Construction rejects directories (or explicit paths) that contain `..` components
/// so callers cannot point the store at an escaped location via relative segments.
///
/// Not `Clone`: each instance owns the write lock for its path. Share via `Arc` if needed.
#[derive(Debug)]
pub struct JsonFileSettingsStore {
    path: PathBuf,
    write_lock: Mutex<()>,
}

impl JsonFileSettingsStore {
    /// Settings file at `{directory}/settings.json`.
    pub fn in_directory(directory: impl AsRef<Path>) -> Result<Self, SettingsError> {
        let path = confined_settings_path(directory.as_ref())?;
        Ok(Self {
            path,
            write_lock: Mutex::new(()),
        })
    }

    /// Explicit `…/settings.json` path; parent directory must be `..`-free.
    pub fn new(path: impl AsRef<Path>) -> Result<Self, SettingsError> {
        let path = validate_settings_file_path(path.as_ref())?;
        Ok(Self {
            path,
            write_lock: Mutex::new(()),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load + migrate; persists migration when the schema was bumped.
    pub fn load_or_default(&self) -> Result<AppSettings, SettingsError> {
        let _guard = self
            .write_lock
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        match self.load_raw_unlocked() {
            Ok((mut settings, schema)) => {
                let migrated = settings.migrate_from_schema(schema);
                if migrated {
                    let _ = self.save_unlocked(&settings);
                }
                Ok(settings)
            }
            // Missing file, corrupt JSON, or other read failures → defaults (C# catch-all).
            Err(_) => Ok(AppSettings::default()),
        }
    }

    fn load_raw_unlocked(&self) -> Result<(AppSettings, i32), SettingsError> {
        let bytes = fs::read(&self.path).map_err(|e| SettingsError::Io(e.to_string()))?;
        let schema = read_schema_version(&bytes).unwrap_or(0);
        let settings: AppSettings = serde_json::from_slice(&bytes)
            .map_err(|e| SettingsError::Json(e.to_string()))?;
        Ok((settings, schema))
    }

    fn save_unlocked(&self, settings: &AppSettings) -> Result<(), SettingsError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| SettingsError::Io(e.to_string()))?;
        }
        let mut to_write = settings.clone();
        to_write.settings_schema_version = CURRENT_SCHEMA_VERSION;
        let json = serde_json::to_vec_pretty(&to_write)
            .map_err(|e| SettingsError::Json(e.to_string()))?;
        fs::write(&self.path, json).map_err(|e| SettingsError::Io(e.to_string()))
    }
}

impl SettingsStore for JsonFileSettingsStore {
    fn load(&self) -> Result<AppSettings, SettingsError> {
        self.load_or_default()
    }

    fn save(&self, settings: &AppSettings) -> Result<(), SettingsError> {
        let _guard = self
            .write_lock
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        self.save_unlocked(settings)
    }
}

/// `{directory}/settings.json` with no `..` in the directory.
pub fn confined_settings_path(directory: &Path) -> Result<PathBuf, SettingsError> {
    if directory.as_os_str().is_empty() {
        return Err(SettingsError::Path(
            "settings directory must not be empty".into(),
        ));
    }
    reject_parent_dir_components(directory)?;
    let path = directory.join("settings.json");
    match path.file_name().and_then(|n| n.to_str()) {
        Some("settings.json") => Ok(path),
        _ => Err(SettingsError::Path(
            "settings file name must be settings.json".into(),
        )),
    }
}

fn validate_settings_file_path(path: &Path) -> Result<PathBuf, SettingsError> {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return Err(SettingsError::Path(
            "settings path must include a file name".into(),
        ));
    };
    if name != "settings.json" {
        return Err(SettingsError::Path(
            "settings file must be named settings.json".into(),
        ));
    }
    let Some(parent) = path.parent() else {
        return Err(SettingsError::Path(
            "settings path must have a parent directory".into(),
        ));
    };
    if parent.as_os_str().is_empty() {
        return Err(SettingsError::Path(
            "settings path must have a parent directory".into(),
        ));
    }
    // Re-derive via confined join so `dir/foo/../settings.json` cannot sneak through
    // when the parent itself still contains `..`.
    confined_settings_path(parent)
}

fn reject_parent_dir_components(path: &Path) -> Result<(), SettingsError> {
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(SettingsError::Path(
            "settings path must not contain '..'".into(),
        ));
    }
    Ok(())
}

fn read_schema_version(json: &[u8]) -> Option<i32> {
    let value: serde_json::Value = serde_json::from_slice(json).ok()?;
    value
        .get("SettingsSchemaVersion")
        .and_then(|v| v.as_i64())
        .map(|n| n as i32)
}

#[cfg(test)]
mod path_tests {
    use super::*;

    #[test]
    fn in_directory_rejects_parent_dir_components() {
        let err = JsonFileSettingsStore::in_directory(Path::new("foo/../bar")).unwrap_err();
        assert!(matches!(err, SettingsError::Path(_)));
    }

    #[test]
    fn new_rejects_non_settings_file_name() {
        let err = JsonFileSettingsStore::new(Path::new("C:/temp/other.json")).unwrap_err();
        assert!(matches!(err, SettingsError::Path(_)));
    }

    #[test]
    fn new_rejects_parent_escape_in_path() {
        let err =
            JsonFileSettingsStore::new(Path::new("C:/temp/foo/../../Windows/settings.json"))
                .unwrap_err();
        assert!(matches!(err, SettingsError::Path(_)));
    }

    #[test]
    fn in_directory_accepts_plain_temp_root() {
        let dir = tempfile::tempdir().unwrap();
        let store = JsonFileSettingsStore::in_directory(dir.path()).unwrap();
        assert_eq!(
            store.path().file_name().and_then(|n| n.to_str()),
            Some("settings.json")
        );
    }
}
