use async_trait::async_trait;
use crate::McpError;
/// Mirrors `IMcpServerHost` — owns the in-process loopback MCP listener lifecycle.
#[async_trait]
pub trait McpServerHost: Send + Sync {
    fn is_running(&self) -> bool;
    /// TCP port the server listens on (or would listen on when stopped).
    fn port(&self) -> u16;
    /// Loopback endpoint URL an MCP client connects to (`http://127.0.0.1:{port}`).
    fn endpoint_url(&self) -> String;
    async fn start(&self) -> Result<(), McpError>;
    async fn stop(&self) -> Result<(), McpError>;
    /// Read the existing bearer token, generating one if none exists.
    async fn get_or_create_token(&self) -> Result<String, McpError>;
    async fn peek_token(&self) -> Result<Option<String>, McpError>;
    async fn regenerate_token(&self) -> Result<String, McpError>;
}
