//! HTTP placeholder host — compiles without `rmcp`; no real bind.

use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex as AsyncMutex;

use crate::approval::SessionApprovalGate;
use crate::bind::{loopback_endpoint_url, validate_mcp_port};
use crate::token::{self, McpTokenStore, MemoryTokenStore};
use crate::{McpError, McpServerHost, DEFAULT_MCP_PORT};

/// In-memory stand-in for the loopback MCP server (no socket).
///
/// When the `rmcp` feature is enabled, prefer [`crate::RmcpLoopbackHost`] which
/// binds Streamable HTTP on `127.0.0.1`.
///
/// **Safety:** `endpoint_url` is always `http://127.0.0.1:{port}`. Tokens are
/// never written to tracing fields.
pub struct HttpPlaceholderMcpHost {
    running: AtomicBool,
    port: AtomicU16,
    token_store: Arc<dyn McpTokenStore>,
    token_gate: AsyncMutex<()>,
    approval: Arc<SessionApprovalGate>,
}

impl HttpPlaceholderMcpHost {
    pub fn new() -> Self {
        Self::with_port(DEFAULT_MCP_PORT).expect("default MCP port is valid")
    }

    pub fn with_port(port: u16) -> Result<Self, McpError> {
        Self::with_port_and_store(port, Arc::new(MemoryTokenStore::new()))
    }

    pub fn with_port_and_store(
        port: u16,
        token_store: Arc<dyn McpTokenStore>,
    ) -> Result<Self, McpError> {
        validate_mcp_port(port)?;
        Ok(Self {
            running: AtomicBool::new(false),
            port: AtomicU16::new(port),
            token_store,
            token_gate: AsyncMutex::new(()),
            approval: Arc::new(SessionApprovalGate::new()),
        })
    }

    pub fn approval(&self) -> Arc<SessionApprovalGate> {
        Arc::clone(&self.approval)
    }
}

impl Default for HttpPlaceholderMcpHost {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl McpServerHost for HttpPlaceholderMcpHost {
    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn port(&self) -> u16 {
        self.port.load(Ordering::SeqCst)
    }

    fn endpoint_url(&self) -> String {
        loopback_endpoint_url(self.port())
    }

    async fn start(&self) -> Result<(), McpError> {
        validate_mcp_port(self.port())?;
        if self
            .running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Ok(());
        }
        if let Err(e) = self.get_or_create_token().await {
            self.running.store(false, Ordering::SeqCst);
            return Err(e);
        }
        tracing::info!(
            endpoint = %self.endpoint_url(),
            "MCP HTTP placeholder 'started' (no socket bind; loopback-only URL)"
        );
        Ok(())
    }

    async fn stop(&self) -> Result<(), McpError> {
        if self
            .running
            .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Ok(());
        }
        tracing::info!("MCP HTTP placeholder stopped");
        Ok(())
    }

    async fn get_or_create_token(&self) -> Result<String, McpError> {
        // Intentionally no tracing of the token value.
        token::get_or_create_token(self.token_store.as_ref(), &self.token_gate).await
    }

    async fn peek_token(&self) -> Result<Option<String>, McpError> {
        self.token_store.peek().await
    }

    async fn regenerate_token(&self) -> Result<String, McpError> {
        // Intentionally no tracing of the token value.
        token::regenerate_token(self.token_store.as_ref(), &self.token_gate).await
    }
}
