//! Injectable protocol / tunnel / credential backends (live + fakes).

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use uuid::Uuid;
use wormhole_domain::SerialFlowControlMode;
use wormhole_serial::{SerialLineSettings, SerialOpenOptions, SerialSession};
use wormhole_ssh::SshConnectOptions;
use wormhole_tunnels::{TunnelConfigSnapshot, TunnelLease, TunnelManager};

use crate::error::{Result, SessionError};
use crate::fake_port::NamedFakeSerialPort;
use crate::state::SshConnected;

/// Resolve passwords / tunnel secret blobs without logging them.
#[async_trait]
pub trait CredentialResolver: Send + Sync {
    async fn resolve_password(&self, credential_id: Uuid) -> Result<Option<String>>;
    async fn resolve_tunnel_secret(&self, tunnel_config_id: Uuid) -> Result<Option<Vec<u8>>>;
}

/// Open a serial session from resolved line settings.
#[async_trait]
pub trait SerialConnector: Send + Sync {
    async fn open(
        &self,
        settings: &SerialLineSettings,
        options: SerialOpenOptions,
    ) -> Result<SerialSession>;
}

/// SSH password + shell connect.
#[async_trait]
pub trait SshConnector: Send + Sync {
    async fn connect_password_shell(&self, options: SshConnectOptions) -> Result<SshConnected>;
}

/// Establish a tunnel lease (typically [`TunnelManager`]).
#[async_trait]
pub trait TunnelBroker: Send + Sync {
    async fn establish(
        &self,
        config: TunnelConfigSnapshot,
        secret_blob: Vec<u8>,
    ) -> Result<TunnelLease>;
}

// --- Live adapters ---------------------------------------------------------

/// Opens a real COM port via [`SerialSession::open`].
#[derive(Debug, Default, Clone, Copy)]
pub struct LiveSerialConnector;

#[async_trait]
impl SerialConnector for LiveSerialConnector {
    async fn open(
        &self,
        settings: &SerialLineSettings,
        options: SerialOpenOptions,
    ) -> Result<SerialSession> {
        Ok(SerialSession::open(settings, options).await?)
    }
}

/// Live russh password connect (requires `ssh-client` feature).
#[derive(Debug, Default, Clone, Copy)]
pub struct LiveSshConnector;

#[async_trait]
impl SshConnector for LiveSshConnector {
    async fn connect_password_shell(&self, options: SshConnectOptions) -> Result<SshConnected> {
        #[cfg(feature = "ssh-client")]
        {
            let (session, shell) = wormhole_ssh::connect_password_shell(options).await?;
            Ok(SshConnected::Live { session, shell })
        }
        #[cfg(not(feature = "ssh-client"))]
        {
            let _ = options;
            Err(SessionError::Ssh(wormhole_ssh::SshError::ClientFeatureDisabled))
        }
    }
}

/// [`TunnelManager`] adapter.
pub struct ManagerTunnelBroker {
    manager: Arc<TunnelManager>,
}

impl ManagerTunnelBroker {
    pub fn new(manager: Arc<TunnelManager>) -> Self {
        Self { manager }
    }
}

#[async_trait]
impl TunnelBroker for ManagerTunnelBroker {
    async fn establish(
        &self,
        config: TunnelConfigSnapshot,
        secret_blob: Vec<u8>,
    ) -> Result<TunnelLease> {
        Ok(self.manager.establish(config, secret_blob).await?)
    }
}

// --- Fakes -----------------------------------------------------------------

/// Always returns `None` — host wires CredMgr/DPAPI later.
#[derive(Debug, Default, Clone, Copy)]
pub struct EmptyCredentialResolver;

#[async_trait]
impl CredentialResolver for EmptyCredentialResolver {
    async fn resolve_password(&self, _credential_id: Uuid) -> Result<Option<String>> {
        Ok(None)
    }

    async fn resolve_tunnel_secret(&self, _tunnel_config_id: Uuid) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
}

/// In-memory credential map for tests.
#[derive(Default)]
pub struct FakeCredentialResolver {
    passwords: Mutex<HashMap<Uuid, String>>,
    tunnel_secrets: Mutex<HashMap<Uuid, Vec<u8>>>,
}

impl FakeCredentialResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_password(self, id: Uuid, password: impl Into<String>) -> Self {
        self.passwords
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(id, password.into());
        self
    }

    pub fn with_tunnel_secret(self, id: Uuid, secret: impl Into<Vec<u8>>) -> Self {
        self.tunnel_secrets
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(id, secret.into());
        self
    }
}

impl fmt::Debug for FakeCredentialResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pw = self.passwords.lock().unwrap_or_else(|p| p.into_inner());
        let ts = self
            .tunnel_secrets
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        f.debug_struct("FakeCredentialResolver")
            .field("password_ids", &pw.keys().copied().collect::<Vec<_>>())
            .field("tunnel_secret_ids", &ts.keys().copied().collect::<Vec<_>>())
            .finish()
    }
}

#[async_trait]
impl CredentialResolver for FakeCredentialResolver {
    async fn resolve_password(&self, credential_id: Uuid) -> Result<Option<String>> {
        Ok(self
            .passwords
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&credential_id)
            .cloned())
    }

    async fn resolve_tunnel_secret(&self, tunnel_config_id: Uuid) -> Result<Option<Vec<u8>>> {
        Ok(self
            .tunnel_secrets
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&tunnel_config_id)
            .cloned())
    }
}

/// Opens [`SerialSession::from_port`] over an in-memory fake COM handle.
#[derive(Debug, Default)]
pub struct FakeSerialConnector {
    open_count: AtomicUsize,
}

impl FakeSerialConnector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn open_count(&self) -> usize {
        self.open_count.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl SerialConnector for FakeSerialConnector {
    async fn open(
        &self,
        settings: &SerialLineSettings,
        _options: SerialOpenOptions,
    ) -> Result<SerialSession> {
        self.open_count.fetch_add(1, Ordering::SeqCst);
        let port = NamedFakeSerialPort::new(settings.port_name.clone());
        let flow = settings.flow_control;
        // Keep DSR-friendly default for FakeSerialPort.
        let _ = matches!(flow, SerialFlowControlMode::None);
        Ok(SerialSession::from_port(Box::new(port), flow))
    }
}

/// Always returns [`SshConnected::Fake`] — no network.
#[derive(Debug)]
pub struct FakeSshConnector {
    connect_count: AtomicUsize,
    delay: Option<Duration>,
    fail_next: Mutex<Option<String>>,
}

impl Default for FakeSshConnector {
    fn default() -> Self {
        Self {
            connect_count: AtomicUsize::new(0),
            delay: None,
            fail_next: Mutex::new(None),
        }
    }
}

impl FakeSshConnector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_delay(delay: Duration) -> Self {
        Self {
            delay: Some(delay),
            ..Self::default()
        }
    }

    pub fn connect_count(&self) -> usize {
        self.connect_count.load(Ordering::SeqCst)
    }

    pub fn fail_next(&self, message: impl Into<String>) {
        *self
            .fail_next
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(message.into());
    }
}

#[async_trait]
impl SshConnector for FakeSshConnector {
    async fn connect_password_shell(&self, options: SshConnectOptions) -> Result<SshConnected> {
        self.connect_count.fetch_add(1, Ordering::SeqCst);
        if let Some(delay) = self.delay {
            tokio::time::sleep(delay).await;
        }
        if let Some(msg) = self
            .fail_next
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
        {
            return Err(SessionError::Ssh(wormhole_ssh::SshError::Other(msg)));
        }
        let via_socks = matches!(
            options.transport,
            wormhole_ssh::SshTransport::Socks5(_)
        );
        // Touch auth so unused-password lint stays quiet without logging it.
        let _ = options.auth.username().len();
        Ok(SshConnected::Fake {
            host: options.host,
            port: options.port,
            via_socks,
        })
    }
}

/// Thin wrapper that always succeeds via [`wormhole_tunnels::FakeTunnelProvider`].
pub struct FakeTunnelBroker {
    provider: Arc<wormhole_tunnels::FakeTunnelProvider>,
    manager: Arc<TunnelManager>,
}

impl FakeTunnelBroker {
    pub fn new(kind: wormhole_tunnels::TunnelKind) -> Self {
        let provider = Arc::new(wormhole_tunnels::FakeTunnelProvider::new(kind));
        let as_trait: Arc<dyn wormhole_tunnels::TunnelProvider> = provider.clone();
        let manager = TunnelManager::new(vec![as_trait]).expect("single fake provider");
        Self {
            provider,
            manager: Arc::new(manager),
        }
    }

    pub fn provider(&self) -> &wormhole_tunnels::FakeTunnelProvider {
        &self.provider
    }

    pub fn manager(&self) -> Arc<TunnelManager> {
        Arc::clone(&self.manager)
    }
}

#[async_trait]
impl TunnelBroker for FakeTunnelBroker {
    async fn establish(
        &self,
        config: TunnelConfigSnapshot,
        secret_blob: Vec<u8>,
    ) -> Result<TunnelLease> {
        Ok(self.manager.establish(config, secret_blob).await?)
    }
}
