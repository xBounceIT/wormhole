use thiserror::Error;

#[derive(Debug, Error)]
pub enum McpError {
    #[error("MCP server is already running")]
    AlreadyRunning,
    #[error("MCP server is not running")]
    NotRunning,
    #[error("invalid MCP port: {0}")]
    InvalidPort(u16),
    #[error("MCP bind address must be loopback (got {0})")]
    NonLoopbackBind(std::net::SocketAddr),
    #[error("MCP bind address is invalid or not loopback (got {0})")]
    InvalidBindAddress(String),
    #[error("MCP bind failed: {0}")]
    Bind(std::io::Error),
    #[error("MCP token store error: {0}")]
    TokenStore(String),
    #[error("{0}")]
    Message(String),
}
