//! Remote directory entry — mirrors C# `SftpEntry`.

use std::time::SystemTime;

/// One listing / attribute result from the remote filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SftpEntry {
    pub name: String,
    pub full_path: String,
    pub is_directory: bool,
    pub is_symbolic_link: bool,
    pub size: u64,
    pub last_modified_utc: Option<SystemTime>,
    /// Unix nine-bit mode bits (rwxrwxrwx), or 0 when unknown.
    pub permission_bits: u32,
}

impl SftpEntry {
    pub fn file(name: impl Into<String>, full_path: impl Into<String>, size: u64) -> Self {
        Self {
            name: name.into(),
            full_path: full_path.into(),
            is_directory: false,
            is_symbolic_link: false,
            size,
            last_modified_utc: None,
            permission_bits: 0,
        }
    }

    pub fn directory(name: impl Into<String>, full_path: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            full_path: full_path.into(),
            is_directory: true,
            is_symbolic_link: false,
            size: 0,
            last_modified_utc: None,
            permission_bits: 0,
        }
    }
}
