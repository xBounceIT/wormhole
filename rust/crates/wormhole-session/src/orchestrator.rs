//! Session orchestrator: tunnel lease + protocol dispatch + cancel.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{debug, info};
use wormhole_domain::{ConnectionNode, ConnectionProfile, ProtocolType};
use wormhole_http::{
    build_direct_target, build_forwarder_target, build_socks_target, select_http_tunnel_route,
    HttpScheme, HttpTunnelRoute, HttpTunnelRouteSource, Socks5Proxy,
};
use wormhole_serial::{serial_settings_from_profile, SerialOpenOptions};
use wormhole_ssh::{PasswordAuth, SshAuthMethod, SshConnectOptions, SshTransport};
use wormhole_tunnels::{TunnelConfigSnapshot, TunnelLease};

use crate::connectors::{
    CredentialResolver, FakeCredentialResolver, SerialConnector, SshConnector, TunnelBroker,
};
use crate::error::{Result, SessionError};
use crate::id::SessionId;
use crate::profile::profile_from_node;
use crate::rdp_vnc::{StubRdpConnector, StubVncConnector};
use crate::state::{ConnectedSession, SessionState, SshConnected};

/// Optional tunnel establish inputs when `profile.tunnel_enabled`.
#[derive(Clone)]
pub struct TunnelConnectArgs {
    pub config: TunnelConfigSnapshot,
    /// When `None`, loaded via [`CredentialResolver::resolve_tunnel_secret`].
    pub secret_blob: Option<Vec<u8>>,
}

impl fmt::Debug for TunnelConnectArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelConnectArgs")
            .field("config_id", &self.config.id)
            .field("kind", &self.config.kind)
            .field(
                "secret_blob",
                &self
                    .secret_blob
                    .as_ref()
                    .map(|b| format!("<{} bytes>", b.len())),
            )
            .finish()
    }
}

/// Connect knobs for one session start.
pub struct ConnectOptions {
    pub cancel: CancellationToken,
    /// When set, [`SessionHandle::id`] uses this UUID instead of allocating a fresh one.
    ///
    /// Lets UI glue open a tab (and cancel by the same id) before `connect` returns.
    pub session_id: Option<SessionId>,
    /// Inline / pre-resolved password for SSH (never logged).
    pub password: Option<String>,
    /// Required when `profile.tunnel_enabled` (Serial ignores tunnels).
    pub tunnel: Option<TunnelConnectArgs>,
    pub ssh_connect_timeout: Duration,
    pub ssh_accept_any_host_key: bool,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self {
            cancel: CancellationToken::new(),
            session_id: None,
            password: None,
            tunnel: None,
            ssh_connect_timeout: Duration::from_secs(15),
            ssh_accept_any_host_key: true,
        }
    }
}

impl fmt::Debug for ConnectOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectOptions")
            .field("cancel_is_cancelled", &self.cancel.is_cancelled())
            .field("session_id", &self.session_id)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("tunnel", &self.tunnel)
            .field("ssh_connect_timeout", &self.ssh_connect_timeout)
            .field("ssh_accept_any_host_key", &self.ssh_accept_any_host_key)
            .finish()
    }
}

/// Live session after connect (may be Failed / Closed).
pub struct SessionHandle {
    id: SessionId,
    state: SessionState,
    profile: ConnectionProfile,
    connected: Option<ConnectedSession>,
    tunnel_lease: Option<TunnelLease>,
    last_error: Option<SessionError>,
}

impl SessionHandle {
    fn connecting(profile: ConnectionProfile) -> Self {
        Self::connecting_with_id(SessionId::new(), profile)
    }

    fn connecting_with_id(id: SessionId, profile: ConnectionProfile) -> Self {
        Self {
            id,
            state: SessionState::Connecting,
            profile,
            connected: None,
            tunnel_lease: None,
            last_error: None,
        }
    }

    /// Stable id for tab chrome / registry (allocated at connect start).
    pub fn id(&self) -> SessionId {
        self.id
    }

    pub fn state(&self) -> SessionState {
        self.state
    }

    pub fn profile(&self) -> &ConnectionProfile {
        &self.profile
    }

    pub fn connected(&self) -> Option<&ConnectedSession> {
        self.connected.as_ref()
    }

    pub fn tunnel_lease(&self) -> Option<&TunnelLease> {
        self.tunnel_lease.as_ref()
    }

    pub fn last_error(&self) -> Option<&SessionError> {
        self.last_error.as_ref()
    }

    /// `Ok(self)` when Connected; otherwise `Err` with the typed failure (Failed/Closed).
    pub fn into_result(mut self) -> Result<Self> {
        match self.state {
            SessionState::Connected => Ok(self),
            SessionState::Failed | SessionState::Closed | SessionState::Connecting => {
                Err(self
                    .last_error
                    .take()
                    .unwrap_or(SessionError::Other(format!(
                        "session ended in state {:?}",
                        self.state
                    ))))
            }
        }
    }

    /// Release protocol resources and drop the tunnel lease (ref-count).
    pub async fn close(mut self) {
        if let Some(connected) = self.connected.take() {
            match connected {
                ConnectedSession::Serial(session) => {
                    session.dispose().await;
                }
                ConnectedSession::Ssh(ssh) => match ssh {
                    #[cfg(feature = "ssh-client")]
                    SshConnected::Live { session, shell } => {
                        let _ = shell.close().await;
                        let _ = session.disconnect().await;
                    }
                    SshConnected::Fake { .. } => {}
                },
                ConnectedSession::Http(_) => {}
            }
        }
        if let Some(lease) = self.tunnel_lease.take() {
            lease.release();
        }
        self.state = SessionState::Closed;
    }
}

impl fmt::Debug for SessionHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionHandle")
            .field("id", &self.id)
            .field("state", &self.state)
            .field("node_id", &self.profile.node_id)
            .field("protocol", &self.profile.protocol)
            .field("has_tunnel", &self.tunnel_lease.is_some())
            .field(
                "last_error",
                &self.last_error.as_ref().map(|e| e.to_string()),
            )
            .finish()
    }
}

/// Dispatches resolved profiles to protocol crates with optional tunnel lease.
pub struct SessionOrchestrator {
    serial: Arc<dyn SerialConnector>,
    ssh: Arc<dyn SshConnector>,
    tunnels: Option<Arc<dyn TunnelBroker>>,
    credentials: Arc<dyn CredentialResolver>,
}

impl SessionOrchestrator {
    pub fn new(
        serial: Arc<dyn SerialConnector>,
        ssh: Arc<dyn SshConnector>,
        tunnels: Option<Arc<dyn TunnelBroker>>,
        credentials: Arc<dyn CredentialResolver>,
    ) -> Self {
        Self {
            serial,
            ssh,
            tunnels,
            credentials,
        }
    }

    /// Test-friendly orchestrator with fake serial/SSH and optional tunnel broker.
    pub fn for_tests(
        serial: Arc<dyn SerialConnector>,
        ssh: Arc<dyn SshConnector>,
        tunnels: Option<Arc<dyn TunnelBroker>>,
    ) -> Self {
        Self::new(
            serial,
            ssh,
            tunnels,
            Arc::new(FakeCredentialResolver::new()),
        )
    }

    /// Start a session from a resolved profile.
    ///
    /// Returns a handle in [`SessionState::Connected`] or [`SessionState::Failed`].
    /// Use [`SessionHandle::into_result`] when you prefer `Result`.
    pub async fn connect(
        &self,
        profile: ConnectionProfile,
        mut options: ConnectOptions,
    ) -> SessionHandle {
        let mut handle = match options.session_id.take() {
            Some(id) => SessionHandle::connecting_with_id(id, profile.clone()),
            None => SessionHandle::connecting(profile.clone()),
        };

        info!(
            session_id = %handle.id,
            node_id = %profile.node_id,
            protocol = %profile.protocol,
            tunnel_enabled = profile.tunnel_enabled,
            "session connect starting"
        );

        match self.connect_inner(&mut handle, &mut options).await {
            Ok(()) => {
                handle.state = SessionState::Connected;
                handle
            }
            Err(e) => {
                debug!(error = %e, cancelled = e.is_cancelled(), "session connect failed");
                if let Some(lease) = handle.tunnel_lease.take() {
                    lease.release();
                }
                handle.connected = None;
                handle.last_error = Some(e);
                handle.state = SessionState::Failed;
                handle
            }
        }
    }

    /// Convenience: map a populated [`ConnectionNode`] then connect.
    pub async fn connect_node(
        &self,
        node: &ConnectionNode,
        options: ConnectOptions,
    ) -> SessionHandle {
        match profile_from_node(node) {
            Ok(profile) => self.connect(profile, options).await,
            Err(e) => {
                let mut handle = SessionHandle::connecting(ConnectionProfile {
                    node_id: node.id,
                    name: node.name.clone(),
                    ..ConnectionProfile::default()
                });
                handle.last_error = Some(e);
                handle.state = SessionState::Failed;
                handle
            }
        }
    }

    async fn connect_inner(
        &self,
        handle: &mut SessionHandle,
        options: &mut ConnectOptions,
    ) -> Result<()> {
        check_cancel(&options.cancel)?;

        let profile = handle.profile.clone();

        // Prepare RDP/VNC stubs, then fail closed before any tunnel establish
        // (no OTP / lease churn; no OLE / VNC engine).
        match profile.protocol {
            ProtocolType::Rdp => {
                let request = StubRdpConnector::prepare(&profile)?;
                return Err(StubRdpConnector::connect(request));
            }
            ProtocolType::Vnc => {
                let request = StubVncConnector::prepare(&profile)?;
                return Err(StubVncConnector::connect(request));
            }
            ProtocolType::Serial
            | ProtocolType::Ssh
            | ProtocolType::Http
            | ProtocolType::Https => {}
        }

        // Serial is always local — never establish a VPN lease.
        let wants_tunnel = profile.tunnel_enabled && profile.protocol != ProtocolType::Serial;

        if wants_tunnel {
            let lease = self.establish_tunnel(&profile, options).await?;
            handle.tunnel_lease = Some(lease);
            check_cancel(&options.cancel)?;
        }

        let connected = match profile.protocol {
            ProtocolType::Serial => self.connect_serial(&profile, options).await?,
            ProtocolType::Ssh => {
                self.connect_ssh(&profile, options, handle.tunnel_lease.as_ref())
                    .await?
            }
            ProtocolType::Http => {
                self.connect_http(
                    &profile,
                    HttpScheme::Http,
                    handle.tunnel_lease.as_ref(),
                    &options.cancel,
                )
                .await?
            }
            ProtocolType::Https => {
                self.connect_http(
                    &profile,
                    HttpScheme::Https,
                    handle.tunnel_lease.as_ref(),
                    &options.cancel,
                )
                .await?
            }
            ProtocolType::Rdp | ProtocolType::Vnc => {
                unreachable!("unsupported protocols rejected before tunnel/dispatch");
            }
        };

        handle.connected = Some(connected);
        Ok(())
    }

    async fn establish_tunnel(
        &self,
        profile: &ConnectionProfile,
        options: &mut ConnectOptions,
    ) -> Result<TunnelLease> {
        let tunnel_args = options
            .tunnel
            .take()
            .ok_or(SessionError::TunnelArgsMissing)?;
        let config_id = profile
            .tunnel_config_id
            .ok_or(SessionError::TunnelConfigMissing)?;
        if tunnel_args.config.id != config_id {
            return Err(SessionError::Other(
                "tunnel connect args config id does not match profile.tunnel_config_id".into(),
            ));
        }

        let broker = self
            .tunnels
            .as_ref()
            .ok_or_else(|| SessionError::Other("tunnel broker is not configured".into()))?;

        let secret = match tunnel_args.secret_blob {
            Some(blob) => blob,
            None => self
                .credentials
                .resolve_tunnel_secret(config_id)
                .await?
                .ok_or(SessionError::TunnelSecretMissing)?,
        };

        check_cancel(&options.cancel)?;

        let establish = broker.establish(tunnel_args.config, secret);
        tokio::select! {
            biased;
            _ = options.cancel.cancelled() => Err(SessionError::Cancelled),
            result = establish => Ok(result?),
        }
    }

    async fn connect_serial(
        &self,
        profile: &ConnectionProfile,
        options: &ConnectOptions,
    ) -> Result<ConnectedSession> {
        let settings = serial_settings_from_profile(profile)?;
        check_cancel(&options.cancel)?;
        let open = self.serial.open(&settings, SerialOpenOptions::default());
        let session = tokio::select! {
            biased;
            _ = options.cancel.cancelled() => return Err(SessionError::Cancelled),
            result = open => result?,
        };
        Ok(ConnectedSession::Serial(session))
    }

    async fn connect_ssh(
        &self,
        profile: &ConnectionProfile,
        options: &mut ConnectOptions,
        lease: Option<&TunnelLease>,
    ) -> Result<ConnectedSession> {
        let port =
            u16::try_from(profile.port).map_err(|_| SessionError::InvalidPort(profile.port))?;
        if port == 0 {
            return Err(SessionError::InvalidPort(0));
        }

        let password = self.resolve_ssh_password(profile, options).await?;
        let username = profile.username.clone().unwrap_or_default();

        let transport = match lease {
            Some(lease) => {
                let socks = lease
                    .instance()
                    .socks5_endpoint()
                    .ok_or(SessionError::TunnelSocksRequired)?;
                SshTransport::Socks5(wormhole_ssh::Socks5Endpoint {
                    proxy_host: socks.addr.ip().to_string(),
                    proxy_port: socks.addr.port(),
                    username: None,
                    password: None,
                })
            }
            None => SshTransport::Direct,
        };

        let ssh_opts = SshConnectOptions {
            host: profile.host.clone(),
            port,
            auth: SshAuthMethod::Password(PasswordAuth { username, password }),
            transport,
            connect_timeout: options.ssh_connect_timeout,
            accept_any_host_key: options.ssh_accept_any_host_key,
            ..SshConnectOptions::default()
        };

        check_cancel(&options.cancel)?;
        let connect = self.ssh.connect_password_shell(ssh_opts);
        let connected = tokio::select! {
            biased;
            _ = options.cancel.cancelled() => return Err(SessionError::Cancelled),
            result = connect => result?,
        };
        Ok(ConnectedSession::Ssh(connected))
    }

    async fn resolve_ssh_password(
        &self,
        profile: &ConnectionProfile,
        options: &mut ConnectOptions,
    ) -> Result<String> {
        if let Some(pw) = options.password.take() {
            return Ok(pw);
        }
        if let Some(cred_id) = profile.credential_id {
            if let Some(pw) = self.credentials.resolve_password(cred_id).await? {
                return Ok(pw);
            }
        }
        Err(SessionError::PasswordRequired)
    }

    async fn connect_http(
        &self,
        profile: &ConnectionProfile,
        scheme: HttpScheme,
        lease: Option<&TunnelLease>,
        cancel: &CancellationToken,
    ) -> Result<ConnectedSession> {
        check_cancel(cancel)?;
        // Prefer Socks5Endpoint when present; else BindLocalForwarder.
        // Serial never reaches here (local COM; tunnel lease skipped above).
        let target = match lease {
            None => build_direct_target(
                scheme,
                &profile.host,
                profile.port,
                profile.http_ignore_cert_errors,
            )?,
            Some(lease) => {
                let view = LeaseHttpTunnelRoute(lease);
                match select_http_tunnel_route(Some(&view))? {
                    HttpTunnelRoute::Direct => {
                        // `select_http_tunnel_route(Some(_))` never returns Direct;
                        // keep the arm so the match stays exhaustive if that changes.
                        return Err(SessionError::Other(
                            "HTTP tunnel lease present but route selector returned Direct".into(),
                        ));
                    }
                    HttpTunnelRoute::Socks5(proxy) => build_socks_target(
                        scheme,
                        &profile.host,
                        profile.port,
                        profile.http_ignore_cert_errors,
                        proxy,
                        profile.tunnel_config_id,
                    )?,
                    HttpTunnelRoute::LocalForwarder => {
                        let remote_port = u16::try_from(profile.port)
                            .map_err(|_| SessionError::InvalidPort(profile.port))?;
                        if remote_port == 0 {
                            return Err(SessionError::InvalidPort(0));
                        }
                        check_cancel(cancel)?;
                        let bind = lease
                            .instance()
                            .bind_local_forwarder(&profile.host, remote_port);
                        let local = tokio::select! {
                            biased;
                            _ = cancel.cancelled() => return Err(SessionError::Cancelled),
                            result = bind => result?,
                        };
                        build_forwarder_target(
                            scheme,
                            &profile.host,
                            profile.port,
                            profile.http_ignore_cert_errors,
                            local,
                            profile.tunnel_config_id,
                        )?
                    }
                }
            }
        };
        Ok(ConnectedSession::Http(target))
    }
}

/// Adapts a live [`TunnelLease`] to [`HttpTunnelRouteSource`] (SOCKS addr only).
struct LeaseHttpTunnelRoute<'a>(&'a TunnelLease);

impl HttpTunnelRouteSource for LeaseHttpTunnelRoute<'_> {
    fn socks5_endpoint(&self) -> Option<Socks5Proxy> {
        self.0
            .instance()
            .socks5_endpoint()
            .map(|ep| Socks5Proxy::new(ep.addr))
    }
}

fn check_cancel(token: &CancellationToken) -> Result<()> {
    if token.is_cancelled() {
        Err(SessionError::Cancelled)
    } else {
        Ok(())
    }
}
