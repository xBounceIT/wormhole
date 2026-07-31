//! Bearer token minting + storage (never logged).

use std::fmt;
use std::sync::Mutex;

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use tokio::sync::Mutex as AsyncMutex;

use crate::McpError;

/// Persist / load the MCP bearer token (CredMgr in production, memory in tests).
#[async_trait]
pub trait McpTokenStore: Send + Sync {
    async fn peek(&self) -> Result<Option<String>, McpError>;
    async fn store(&self, token: &str) -> Result<(), McpError>;
}

/// In-process token store (tests / hosts without CredMgr).
#[derive(Default)]
pub struct MemoryTokenStore {
    token: Mutex<Option<String>>,
}

impl MemoryTokenStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_token(token: impl Into<String>) -> Self {
        Self {
            token: Mutex::new(Some(token.into())),
        }
    }
}

impl fmt::Debug for MemoryTokenStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let present = self
            .token
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .is_some_and(|t| !t.is_empty());
        f.debug_struct("MemoryTokenStore")
            .field("token", &if present { "[REDACTED]" } else { "None" })
            .finish()
    }
}

#[async_trait]
impl McpTokenStore for MemoryTokenStore {
    async fn peek(&self) -> Result<Option<String>, McpError> {
        Ok(self.token.lock().unwrap_or_else(|p| p.into_inner()).clone())
    }

    async fn store(&self, token: &str) -> Result<(), McpError> {
        *self.token.lock().unwrap_or_else(|p| p.into_inner()) = Some(token.to_owned());
        Ok(())
    }
}

/// Windows Credential Manager store using the fixed C# MCP credential id.
#[cfg(feature = "secrets")]
#[derive(Debug, Default)]
pub struct CredMgrTokenStore;

#[cfg(feature = "secrets")]
impl CredMgrTokenStore {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(feature = "secrets")]
#[async_trait]
impl McpTokenStore for CredMgrTokenStore {
    async fn peek(&self) -> Result<Option<String>, McpError> {
        wormhole_secrets_win::read_password(&wormhole_secrets_win::MCP_TOKEN_CREDENTIAL_ID)
            .map_err(|e| McpError::TokenStore(e.to_string()))
    }

    async fn store(&self, token: &str) -> Result<(), McpError> {
        wormhole_secrets_win::store_password(&wormhole_secrets_win::MCP_TOKEN_CREDENTIAL_ID, token)
            .map_err(|e| McpError::TokenStore(e.to_string()))
    }
}

/// URL-safe unpadded bearer token (32 random bytes) — mirrors C# `GenerateToken`.
pub fn generate_bearer_token() -> Result<String, McpError> {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).map_err(|e| McpError::TokenStore(e.to_string()))?;
    Ok(URL_SAFE_NO_PAD.encode(buf))
}

/// Constant-time UTF-8 compare for bearer tokens (length mismatch → false).
pub fn tokens_equal(presented: &str, expected: &str) -> bool {
    let a = presented.as_bytes();
    let b = expected.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Parse `Authorization: Bearer <token>` (scheme matched case-insensitively — C# parity).
pub fn extract_bearer_token(authorization: Option<&str>) -> Option<&str> {
    let header = authorization?.trim();
    const PREFIX: &str = "bearer ";
    if header.len() < PREFIX.len() {
        return None;
    }
    if !header.as_bytes()[..PREFIX.len()].eq_ignore_ascii_case(PREFIX.as_bytes()) {
        return None;
    }
    let token = header[PREFIX.len()..].trim();
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

/// True when `Authorization` presents a bearer token matching `expected` (fail closed on empty).
pub fn is_authorized(authorization: Option<&str>, expected: &str) -> bool {
    if expected.is_empty() {
        return false;
    }
    match extract_bearer_token(authorization) {
        Some(presented) => tokens_equal(presented, expected),
        None => false,
    }
}

/// Read-or-mint under a gate (mirrors C# `_tokenGate` — concurrent callers share one token).
pub async fn get_or_create_token(
    store: &dyn McpTokenStore,
    gate: &AsyncMutex<()>,
) -> Result<String, McpError> {
    let _guard = gate.lock().await;
    if let Some(t) = store.peek().await? {
        if !t.is_empty() {
            return Ok(t);
        }
    }
    let minted = generate_bearer_token()?;
    store.store(&minted).await?;
    Ok(minted)
}

/// Replace the stored token under the same gate as create-if-missing.
pub async fn regenerate_token(
    store: &dyn McpTokenStore,
    gate: &AsyncMutex<()>,
) -> Result<String, McpError> {
    let _guard = gate.lock().await;
    let minted = generate_bearer_token()?;
    store.store(&minted).await?;
    Ok(minted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_scheme_is_case_insensitive() {
        assert_eq!(extract_bearer_token(Some("Bearer abc")), Some("abc"));
        assert_eq!(extract_bearer_token(Some("bearer abc")), Some("abc"));
        assert_eq!(extract_bearer_token(Some("BEARER abc")), Some("abc"));
        assert_eq!(extract_bearer_token(Some("Basic abc")), None);
        assert_eq!(extract_bearer_token(Some("Bearer ")), None);
        assert_eq!(extract_bearer_token(None), None);
    }

    #[test]
    fn authorization_fail_closed_on_empty_expected() {
        assert!(!is_authorized(Some("Bearer secret"), ""));
        assert!(is_authorized(Some("Bearer secret"), "secret"));
        assert!(!is_authorized(Some("Bearer wrong"), "secret"));
        assert!(!is_authorized(None, "secret"));
    }

    #[test]
    fn memory_token_store_debug_redacts() {
        let store = MemoryTokenStore::with_token("super-secret-token");
        let dbg = format!("{store:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("super-secret-token"));
    }

    #[tokio::test]
    async fn concurrent_get_or_create_shares_one_token() {
        let store = MemoryTokenStore::new();
        let gate = AsyncMutex::new(());
        let store_ref = &store;
        let gate_ref = &gate;

        let (a, b, c) = tokio::join!(
            get_or_create_token(store_ref, gate_ref),
            get_or_create_token(store_ref, gate_ref),
            get_or_create_token(store_ref, gate_ref),
        );
        let a = a.unwrap();
        let b = b.unwrap();
        let c = c.unwrap();
        assert_eq!(a, b);
        assert_eq!(b, c);
        assert_eq!(store.peek().await.unwrap().as_deref(), Some(a.as_str()));
    }

    #[tokio::test]
    async fn empty_stored_token_is_regenerated() {
        let store = MemoryTokenStore::with_token("");
        let gate = AsyncMutex::new(());
        let minted = get_or_create_token(&store, &gate).await.unwrap();
        assert!(!minted.is_empty());
        assert_eq!(
            store.peek().await.unwrap().as_deref(),
            Some(minted.as_str())
        );
    }
}
