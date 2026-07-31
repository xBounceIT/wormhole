//! Backend ops trait — mirrors C# `ISftpSession` method surface.
//!
//! Callers that share a session **must** go through [`crate::SerializedSftpSession`]
//! (or an equivalent single-flight gate). Raw backends are not concurrency-safe;
//! that matches SSH.NET `SftpClient` and keeps parity with
//! `FileTransferOrchestrator`'s `SemaphoreSlim(1,1)` invariant.

use async_trait::async_trait;

use crate::entry::SftpEntry;
use crate::SftpError;

/// Low-level SFTP operations (one implementation = one transport/session).
#[async_trait]
pub trait SftpOps: Send + Sync {
    fn working_directory(&self) -> &str;
    fn host_fingerprint(&self) -> Option<&str>;
    fn is_connected(&self) -> bool;

    async fn list_directory(&self, path: &str) -> Result<Vec<SftpEntry>, SftpError>;
    async fn get_attributes(&self, path: &str) -> Result<Option<SftpEntry>, SftpError>;
    async fn exists(&self, path: &str) -> Result<bool, SftpError>;

    async fn upload(&self, remote_path: &str, data: &[u8]) -> Result<(), SftpError>;
    async fn download(&self, remote_path: &str) -> Result<Vec<u8>, SftpError>;

    async fn create_directory(&self, remote_path: &str) -> Result<(), SftpError>;
    async fn create_empty_file(&self, remote_path: &str) -> Result<(), SftpError>;
    async fn delete_file(&self, remote_path: &str) -> Result<(), SftpError>;
    async fn delete_directory(&self, remote_path: &str, recursive: bool) -> Result<(), SftpError>;
    async fn rename(&self, old_path: &str, new_path: &str) -> Result<(), SftpError>;
}
