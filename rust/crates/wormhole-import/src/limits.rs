//! Shared size / path bounds for import + backup inspect (parity with C# BackupService).

use std::path::{Component, Path};

use crate::error::ImportError;

/// Matches C# `BackupService.MaxBackupFileBytes` (64 MiB).
pub const MAX_IMPORT_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// Soft cap on planned / parsed nodes to bound memory from shallow-wide hostile XML.
pub const MAX_NODE_COUNT: usize = 100_000;

pub fn is_oversized(len: u64) -> bool {
    len > MAX_IMPORT_FILE_BYTES
}

pub fn ensure_file_size_acceptable(path: &Path) -> Result<(), ImportError> {
    let meta = std::fs::metadata(path)?;
    if is_oversized(meta.len()) {
        return Err(ImportError::InvalidData(format!(
            "file is {} bytes; refusing to read anything larger than {MAX_IMPORT_FILE_BYTES} bytes",
            meta.len()
        )));
    }
    Ok(())
}

/// Reject NUL and `..` path components on user-supplied paths (path traversal).
pub fn validate_user_path(path: &Path) -> Result<(), ImportError> {
    let lossy = path.to_string_lossy();
    if lossy.contains('\0') {
        return Err(ImportError::InvalidData(
            "import path must not contain NUL bytes".into(),
        ));
    }
    if path
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(ImportError::InvalidData(
            "import path must not contain '..' components".into(),
        ));
    }
    Ok(())
}

pub fn read_file_capped(path: &Path) -> Result<Vec<u8>, ImportError> {
    validate_user_path(path)?;
    ensure_file_size_acceptable(path)?;
    let bytes = std::fs::read(path)?;
    if is_oversized(bytes.len() as u64) {
        return Err(ImportError::InvalidData(format!(
            "file content exceeds {MAX_IMPORT_FILE_BYTES} bytes"
        )));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_threshold() {
        assert!(!is_oversized(MAX_IMPORT_FILE_BYTES));
        assert!(is_oversized(MAX_IMPORT_FILE_BYTES + 1));
    }

    #[test]
    fn path_rejects_parent_and_nul() {
        assert!(validate_user_path(Path::new("..\\x")).is_err());
        assert!(validate_user_path(Path::new("a\\..\\b")).is_err());
        assert!(validate_user_path(Path::new("foo\0bar")).is_err());
        assert!(validate_user_path(Path::new("C:\\Users\\me\\file.xml")).is_ok());
    }
}
