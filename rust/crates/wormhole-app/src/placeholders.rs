//! Local trait stubs until `wormhole-storage` / `wormhole-secrets` exist.

use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

/// Placeholder for SQLite connection / profile persistence.
#[async_trait]
pub trait ConnectionStore: Send + Sync {
    async fn ping(&self) -> Result<(), String>;
}

/// Placeholder for Credential Manager + DPAPI secret IO.
#[async_trait]
pub trait SecretStore: Send + Sync {
    async fn read_tunnel_secret(&self, config_id: Uuid) -> Result<Option<Vec<u8>>, String>;
}

#[derive(Debug, Default)]
pub struct StubConnectionStore;

#[async_trait]
impl ConnectionStore for StubConnectionStore {
    async fn ping(&self) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct StubSecretStore;

#[async_trait]
impl SecretStore for StubSecretStore {
    async fn read_tunnel_secret(&self, _config_id: Uuid) -> Result<Option<Vec<u8>>, String> {
        Ok(None)
    }
}

pub fn stub_connection_store() -> Arc<dyn ConnectionStore> {
    Arc::new(StubConnectionStore)
}

pub fn stub_secret_store() -> Arc<dyn SecretStore> {
    Arc::new(StubSecretStore)
}
