use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;

use crate::{TunnelConfigSnapshot, TunnelError, TunnelKind, TunnelState};

/// Loopback SOCKS5 endpoint advertised by a live tunnel (typically a Go sidecar).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Socks5Endpoint {
    pub addr: SocketAddr,
}

impl Socks5Endpoint {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    pub fn loopback(port: u16) -> Self {
        Self {
            addr: SocketAddr::from(([127, 0, 0, 1], port)),
        }
    }
}

/// Mirrors `ITunnelProvider`.
#[async_trait]
pub trait TunnelProvider: Send + Sync {
    fn kind(&self) -> TunnelKind;

    async fn establish(
        &self,
        config: &TunnelConfigSnapshot,
        secret_blob: &[u8],
    ) -> Result<Arc<dyn TunnelInstance>, TunnelError>;
}

/// Mirrors `ITunnelInstance`.
#[async_trait]
pub trait TunnelInstance: Send + Sync {
    fn state(&self) -> TunnelState;

    fn socks5_endpoint(&self) -> Option<Socks5Endpoint>;

    /// Bind `127.0.0.1:0` → SOCKS5 → `host:port`. Returns the chosen local port.
    ///
    /// Idempotent per `(host, port)` for the instance lifetime (RDP/VNC loopback
    /// bridge). Requires a live [`Socks5Endpoint`].
    async fn bind_local_forwarder(&self, host: &str, port: u16) -> Result<u16, TunnelError>;

    async fn close(&self);
}
