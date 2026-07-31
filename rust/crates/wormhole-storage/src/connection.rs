use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::Connection;

use crate::{Result, StorageError};

/// Default SQLite busy timeout. Aligns with Microsoft.Data.Sqlite's 30s command timeout
/// so concurrent one-connection-per-op opens wait instead of failing immediately.
const BUSY_TIMEOUT: Duration = Duration::from_secs(30);

/// Opens SQLite databases with foreign keys enabled.
///
/// Matches C# `SqliteConnectionFactory`: callers open one connection per operation.
/// rusqlite's default connection handling (and SQLite's own pooling of page cache)
/// is sufficient; we do not hold a long-lived shared connection.
#[derive(Debug, Clone)]
pub struct SqliteConnectionFactory {
    path: PathBuf,
}

impl SqliteConnectionFactory {
    /// Create a factory for the given database file path.
    ///
    /// Prefer a real filesystem path. [`open`](Self::open) rejects empty paths,
    /// SQLite's private `:memory:` name, and `file:` URIs — those break the
    /// one-connection-per-operation contract (each open would see a different DB).
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Database file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Open a new connection with `PRAGMA foreign_keys = ON` and a busy timeout.
    pub fn open(&self) -> Result<Connection> {
        validate_db_path(&self.path)?;
        let conn = Connection::open(&self.path).map_err(StorageError::Sqlite)?;
        configure_connection(&conn)?;
        Ok(conn)
    }
}

/// Apply connection pragmas expected by Wormhole (FK enforcement + busy wait).
pub(crate) fn configure_connection(conn: &Connection) -> Result<()> {
    conn.busy_timeout(BUSY_TIMEOUT)
        .map_err(StorageError::Sqlite)?;
    conn.execute_batch("PRAGMA foreign_keys = ON;")
        .map_err(StorageError::Sqlite)?;
    Ok(())
}

/// Reject path forms that are incompatible with one-connection-per-op semantics.
fn validate_db_path(path: &Path) -> Result<()> {
    let raw = path.to_string_lossy();
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(StorageError::Path(path.to_path_buf()));
    }
    // SQLite treats exactly ":memory:" as a private in-memory DB (not shared across opens).
    if trimmed.eq_ignore_ascii_case(":memory:") {
        return Err(StorageError::Path(path.to_path_buf()));
    }
    // URI filenames require SQLITE_OPEN_URI and can select memory/shared modes.
    if trimmed.len() >= 5 && trimmed[..5].eq_ignore_ascii_case("file:") {
        return Err(StorageError::Path(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_memory_and_empty_and_uri_paths() {
        for p in [":memory:", ":MEMORY:", "", "   ", "file:foo.db", "FILE:abc"] {
            let err = SqliteConnectionFactory::new(p).open().unwrap_err();
            assert!(
                matches!(err, StorageError::Path(_)),
                "expected Path error for {p:?}, got {err:?}"
            );
        }
    }

    #[test]
    fn accepts_normal_filesystem_path_name() {
        // Validation only — open may still fail if parent dirs are missing.
        assert!(validate_db_path(Path::new("wormhole.db")).is_ok());
        assert!(validate_db_path(Path::new(r"C:\temp\wormhole.db")).is_ok());
    }
}
