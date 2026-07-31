use std::io;
use std::path::PathBuf;

use thiserror::Error;

/// Result alias for storage operations.
pub type Result<T> = std::result::Result<T, StorageError>;

/// Errors from migrations, connection open, repository queries, or settings JSON.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("invalid guid `{value}`: {message}")]
    InvalidGuid { value: String, message: String },

    #[error("invalid timestamp `{value}`: {message}")]
    InvalidTimestamp { value: String, message: String },

    #[error("migration `{id}` failed: {source}")]
    Migration {
        id: String,
        #[source]
        source: rusqlite::Error,
    },

    /// Path is empty, `:memory:`, or a `file:` URI -- incompatible with one-connection-per-op.
    #[error("unsupported database path `{0}` (need a filesystem file path)")]
    Path(PathBuf),

    /// `%LOCALAPPDATA%` (or equivalent) is missing -- cannot resolve the default Wormhole dir.
    #[error("LOCALAPPDATA is not set; cannot resolve Wormhole app-data path")]
    AppDataPath,

    /// Invalid argument for a write helper (empty id, blank fingerprint, etc.).
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Missing node id (lookup returned no row).
    #[error("node not found: {0}")]
    NotFound(uuid::Uuid),

    /// `settings.json` exists but is not valid JSON / not an object -- fail closed.
    #[error("corrupt settings at `{path}`: {message}")]
    CorruptSettings { path: PathBuf, message: String },

    #[error("settings json error: {0}")]
    SettingsJson(#[from] serde_json::Error),
}
