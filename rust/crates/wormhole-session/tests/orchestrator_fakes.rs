//! Unit tests — all use fakes; no live network / COM required.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use wormhole_domain::{ConnectionNode, ConnectionProfile, NodeKind, ProtocolType};
use wormhole_http::TunnelRouteHint;
use wormhole_tunnels::{
    TunnelConfigSnapshot, TunnelError, TunnelInstance, TunnelKind, TunnelManager, TunnelProvider,
    TunnelState,
};

use wormhole_session::{
    ConnectedSession, ConnectOptions, FakeCredentialResolver, FakeSerialConnector,
    FakeSshConnector, FakeTunnelBroker, SessionError, SessionOrchestrator, SessionState,
    SshConnected, TunnelConnectArgs,
};

fn ssh_profile() -> ConnectionProfile {
    ConnectionProfile {
        node_id: Uuid::new_v4(),
        name: "ssh-box".into(),
        protocol: ProtocolType::Ssh,
        host: "10.0.0.5".into(),
        port: 22,
        username: Some("alice".into()),
        use_inline_password: true,
        ..ConnectionProfile::default()
    }
}

fn serial_profile() -> ConnectionProfile {
    ConnectionProfile {
        node_id: Uuid::new_v4(),
        name: "com".into(),
        protocol: ProtocolType::Serial,
        host: "COM3".into(),
        port: 0,
        ..ConnectionProfile::default()
    }
}

fn http_profile(https: bool) -> ConnectionProfile {
    ConnectionProfile {
        node_id: Uuid::new_v4(),
        name: "fw".into(),
        protocol: if https {
            ProtocolType::Https
        } else {
            ProtocolType::Http
        },
        host: "fw.local".into(),
        port: if https { 443 } else { 80 },
        http_ignore_cert_errors: https,
        ..ConnectionProfile::default()
    }
}

fn orch_no_tunnel() -> SessionOrchestrator {
    SessionOrchestrator::for_tests(
        Arc::new(FakeSerialConnector::new()),
        Arc::new(FakeSshConnector::new()),
        None,
    )
}

/// Tunnel with no public SOCKS — `bind_local_forwarder` still returns a loopback port
/// (session HTTP SOCKS-optional path).
struct ForwarderOnlyInstance {
    local_port: u16,
}

#[async_trait]
impl TunnelInstance for ForwarderOnlyInstance {
    fn state(&self) -> TunnelState {
        TunnelState::Up
    }

    fn socks5_endpoint(&self) -> Option<wormhole_tunnels::Socks5Endpoint> {
        None
    }

    async fn bind_local_forwarder(&self, _host: &str, _port: u16) -> Result<u16, TunnelError> {
        Ok(self.local_port)
    }

    async fn close(&self) {}
}

struct ForwarderOnlyProvider {
    kind: TunnelKind,
    local_port: u16,
}

#[async_trait]
impl TunnelProvider for ForwarderOnlyProvider {
    fn kind(&self) -> TunnelKind {
        self.kind
    }

    async fn establish(
        &self,
        _config: &TunnelConfigSnapshot,
        _secret_blob: &[u8],
    ) -> Result<Arc<dyn TunnelInstance>, TunnelError> {
        Ok(Arc::new(ForwarderOnlyInstance {
            local_port: self.local_port,
        }))
    }
}

struct ForwarderOnlyBroker {
    manager: Arc<TunnelManager>,
}

impl ForwarderOnlyBroker {
    fn new(kind: TunnelKind, local_port: u16) -> Self {
        let provider: Arc<dyn TunnelProvider> = Arc::new(ForwarderOnlyProvider {
            kind,
            local_port,
        });
        let manager = TunnelManager::new(vec![provider]).expect("forwarder-only provider");
        Self {
            manager: Arc::new(manager),
        }
    }
}

#[async_trait]
impl wormhole_session::TunnelBroker for ForwarderOnlyBroker {
    async fn establish(
        &self,
        config: TunnelConfigSnapshot,
        secret_blob: Vec<u8>,
    ) -> wormhole_session::Result<wormhole_tunnels::TunnelLease> {
        Ok(self.manager.establish(config, secret_blob).await?)
    }
}

/// Tunnel advertising SOCKS on port 0 — HTTP selector must reject (`InvalidPort`).
struct ZeroPortSocksInstance;

#[async_trait]
impl TunnelInstance for ZeroPortSocksInstance {
    fn state(&self) -> TunnelState {
        TunnelState::Up
    }

    fn socks5_endpoint(&self) -> Option<wormhole_tunnels::Socks5Endpoint> {
        Some(wormhole_tunnels::Socks5Endpoint::loopback(0))
    }

    async fn bind_local_forwarder(&self, _host: &str, _port: u16) -> Result<u16, TunnelError> {
        // Defensive: select_http_tunnel_route must reject port 0 before bind.
        Err(TunnelError::Socks5(
            "zero-port SOCKS must not fall through to BindLocalForwarder".into(),
        ))
    }

    async fn close(&self) {}
}

struct ZeroPortSocksProvider {
    kind: TunnelKind,
}

#[async_trait]
impl TunnelProvider for ZeroPortSocksProvider {
    fn kind(&self) -> TunnelKind {
        self.kind
    }

    async fn establish(
        &self,
        _config: &TunnelConfigSnapshot,
        _secret_blob: &[u8],
    ) -> Result<Arc<dyn TunnelInstance>, TunnelError> {
        Ok(Arc::new(ZeroPortSocksInstance))
    }
}

struct ZeroPortSocksBroker {
    manager: Arc<TunnelManager>,
}

impl ZeroPortSocksBroker {
    fn new(kind: TunnelKind) -> Self {
        let provider: Arc<dyn TunnelProvider> = Arc::new(ZeroPortSocksProvider { kind });
        let manager = TunnelManager::new(vec![provider]).expect("zero-port socks provider");
        Self {
            manager: Arc::new(manager),
        }
    }
}

#[async_trait]
impl wormhole_session::TunnelBroker for ZeroPortSocksBroker {
    async fn establish(
        &self,
        config: TunnelConfigSnapshot,
        secret_blob: Vec<u8>,
    ) -> wormhole_session::Result<wormhole_tunnels::TunnelLease> {
        Ok(self.manager.establish(config, secret_blob).await?)
    }
}

#[tokio::test]
async fn ssh_password_connects_fake() {
    let orch = orch_no_tunnel();
    let handle = orch
        .connect(
            ssh_profile(),
            ConnectOptions {
                password: Some("s3cret".into()),
                ..ConnectOptions::default()
            },
        )
        .await;
    assert_eq!(handle.state(), SessionState::Connected);
    match handle.connected() {
        Some(ConnectedSession::Ssh(SshConnected::Fake {
            host,
            port,
            via_socks,
        })) => {
            assert_eq!(host, "10.0.0.5");
            assert_eq!(*port, 22);
            assert!(!*via_socks);
        }
        other => panic!("expected fake ssh, got {other:?}"),
    }
    handle.close().await;
}

#[tokio::test]
async fn connect_uses_preferred_session_id_when_set() {
    let orch = orch_no_tunnel();
    let preferred = wormhole_session::SessionId::new();
    let handle = orch
        .connect(
            http_profile(false),
            ConnectOptions {
                session_id: Some(preferred),
                ..ConnectOptions::default()
            },
        )
        .await;
    assert_eq!(handle.id(), preferred);
    assert_eq!(handle.state(), SessionState::Connected);
    handle.close().await;
}

#[tokio::test]
async fn session_handle_allocates_unique_stable_ids() {
    let orch = orch_no_tunnel();
    let secret = "s3cret-for-debug-assert";
    let h1 = orch
        .connect(
            ssh_profile(),
            ConnectOptions {
                password: Some(secret.into()),
                ..ConnectOptions::default()
            },
        )
        .await;
    let h2 = orch
        .connect(
            ssh_profile(),
            ConnectOptions {
                password: Some(secret.into()),
                ..ConnectOptions::default()
            },
        )
        .await;
    assert_eq!(h1.state(), SessionState::Connected);
    assert_eq!(h2.state(), SessionState::Connected);
    let id1 = h1.id();
    let id2 = h2.id();
    assert_ne!(id1, id2, "each connect allocates a fresh SessionId");
    assert_eq!(h1.id(), id1, "SessionHandle::id is stable for the handle");
    let dbg = format!("{h1:?}");
    assert!(
        dbg.contains(&id1.to_string()),
        "Debug should surface the allocated id"
    );
    assert!(
        !dbg.contains(secret),
        "SessionHandle Debug must not leak connect password"
    );
    h1.close().await;
    h2.close().await;
}

#[tokio::test]
async fn ssh_password_missing_fails_without_leaking_secret_shape() {
    let orch = orch_no_tunnel();
    let handle = orch.connect(ssh_profile(), ConnectOptions::default()).await;
    assert_eq!(handle.state(), SessionState::Failed);
    let err = handle.last_error().unwrap();
    assert!(matches!(err, SessionError::PasswordRequired));
    let display = err.to_string();
    assert!(!display.to_lowercase().contains("password:"));
    assert!(!display.contains("s3cret"));
}

#[tokio::test]
async fn ssh_credential_resolver_path() {
    let cred = Uuid::new_v4();
    let credentials = Arc::new(FakeCredentialResolver::new().with_password(cred, "from-store"));
    let orch = SessionOrchestrator::new(
        Arc::new(FakeSerialConnector::new()),
        Arc::new(FakeSshConnector::new()),
        None,
        credentials,
    );
    let mut profile = ssh_profile();
    profile.use_inline_password = false;
    profile.credential_id = Some(cred);
    let handle = orch.connect(profile, ConnectOptions::default()).await;
    assert_eq!(handle.state(), SessionState::Connected);
    handle.close().await;
}

#[tokio::test]
async fn serial_opens_via_fake_port() {
    let serial = Arc::new(FakeSerialConnector::new());
    let orch = SessionOrchestrator::for_tests(
        Arc::clone(&serial) as Arc<dyn wormhole_session::SerialConnector>,
        Arc::new(FakeSshConnector::new()),
        None,
    );
    let handle = orch
        .connect(serial_profile(), ConnectOptions::default())
        .await;
    assert_eq!(handle.state(), SessionState::Connected);
    assert_eq!(serial.open_count(), 1);
    assert!(matches!(
        handle.connected(),
        Some(ConnectedSession::Serial(_))
    ));
    handle.close().await;
}

#[tokio::test]
async fn serial_ignores_tunnel_enabled() {
    let tunnel_id = Uuid::new_v4();
    let broker = Arc::new(FakeTunnelBroker::new(TunnelKind::WireGuard));
    let orch = SessionOrchestrator::for_tests(
        Arc::new(FakeSerialConnector::new()),
        Arc::new(FakeSshConnector::new()),
        Some(broker.clone() as Arc<dyn wormhole_session::TunnelBroker>),
    );
    let mut profile = serial_profile();
    profile.tunnel_enabled = true;
    profile.tunnel_config_id = Some(tunnel_id);
    let handle = orch
        .connect(
            profile,
            ConnectOptions {
                tunnel: Some(TunnelConnectArgs {
                    config: TunnelConfigSnapshot::new(tunnel_id, TunnelKind::WireGuard, "wg"),
                    secret_blob: Some(b"unused".to_vec()),
                }),
                ..ConnectOptions::default()
            },
        )
        .await;
    assert_eq!(handle.state(), SessionState::Connected);
    assert!(handle.tunnel_lease().is_none());
    assert_eq!(broker.manager().establish_start_count(), 0);
    assert_eq!(broker.provider().establish_count(), 0);
    handle.close().await;
}

#[tokio::test]
async fn http_direct_target() {
    let orch = orch_no_tunnel();
    let handle = orch
        .connect(http_profile(false), ConnectOptions::default())
        .await;
    assert_eq!(handle.state(), SessionState::Connected);
    assert!(handle.tunnel_lease().is_none());
    match handle.connected() {
        Some(ConnectedSession::Http(t)) => {
            assert_eq!(t.navigate_uri, "http://fw.local:80/");
            assert_eq!(t.route, TunnelRouteHint::Direct);
            assert!(t.socks5_proxy.is_none());
            assert!(t.original_uri.is_none());
            assert!(!t.ignore_cert_errors());
            assert!(t.tunnel_config_id.is_none());
        }
        other => panic!("expected http target, got {other:?}"),
    }
}

#[tokio::test]
async fn https_via_tunnel_socks() {
    let tunnel_id = Uuid::new_v4();
    let broker = Arc::new(FakeTunnelBroker::new(TunnelKind::WireGuard));
    let orch = SessionOrchestrator::for_tests(
        Arc::new(FakeSerialConnector::new()),
        Arc::new(FakeSshConnector::new()),
        Some(broker as Arc<dyn wormhole_session::TunnelBroker>),
    );
    let mut profile = http_profile(true);
    profile.tunnel_enabled = true;
    profile.tunnel_config_id = Some(tunnel_id);
    let handle = orch
        .connect(
            profile,
            ConnectOptions {
                tunnel: Some(TunnelConnectArgs {
                    config: TunnelConfigSnapshot::new(tunnel_id, TunnelKind::WireGuard, "wg"),
                    secret_blob: Some(b"blob".to_vec()),
                }),
                ..ConnectOptions::default()
            },
        )
        .await;
    assert_eq!(handle.state(), SessionState::Connected);
    assert!(handle.tunnel_lease().is_some());
    match handle.connected() {
        Some(ConnectedSession::Http(t)) => {
            assert_eq!(t.navigate_uri, "https://fw.local:443/");
            assert_eq!(t.route, TunnelRouteHint::Socks5);
            assert!(t.socks5_proxy.is_some());
            assert!(t.original_uri.is_none());
            assert_eq!(t.tunnel_config_id, Some(tunnel_id));
            // Prefer-SOCKS must preserve HTTPS ∧ leaf ignore-cert (never strip to Default).
            assert!(t.ignore_cert_errors());
        }
        other => panic!("expected socks http, got {other:?}"),
    }
    handle.close().await;
}

#[tokio::test]
async fn https_via_tunnel_zero_port_socks_rejected() {
    let tunnel_id = Uuid::new_v4();
    let broker = Arc::new(ZeroPortSocksBroker::new(TunnelKind::WireGuard));
    let manager = Arc::clone(&broker.manager);
    let orch = SessionOrchestrator::for_tests(
        Arc::new(FakeSerialConnector::new()),
        Arc::new(FakeSshConnector::new()),
        Some(broker as Arc<dyn wormhole_session::TunnelBroker>),
    );
    let mut profile = http_profile(true);
    profile.tunnel_enabled = true;
    profile.tunnel_config_id = Some(tunnel_id);
    let handle = orch
        .connect(
            profile,
            ConnectOptions {
                tunnel: Some(TunnelConnectArgs {
                    config: TunnelConfigSnapshot::new(tunnel_id, TunnelKind::WireGuard, "wg"),
                    secret_blob: Some(b"blob".to_vec()),
                }),
                ..ConnectOptions::default()
            },
        )
        .await;
    assert_eq!(handle.state(), SessionState::Failed);
    assert!(matches!(
        handle.last_error(),
        Some(SessionError::Http(wormhole_http::HttpError::InvalidPort(0)))
    ));
    // Fail closed: no ConnectedSession::Http, lease released (no silent Direct/forwarder).
    assert!(handle.connected().is_none());
    assert!(handle.tunnel_lease().is_none());
    assert_eq!(manager.pool_ref_count(tunnel_id), 0);
}

#[tokio::test]
async fn https_via_tunnel_forwarder_when_no_socks() {
    let tunnel_id = Uuid::new_v4();
    let broker = Arc::new(ForwarderOnlyBroker::new(TunnelKind::WireGuard, 51_515));
    let orch = SessionOrchestrator::for_tests(
        Arc::new(FakeSerialConnector::new()),
        Arc::new(FakeSshConnector::new()),
        Some(broker as Arc<dyn wormhole_session::TunnelBroker>),
    );
    let mut profile = http_profile(true);
    profile.tunnel_enabled = true;
    profile.tunnel_config_id = Some(tunnel_id);
    let handle = orch
        .connect(
            profile,
            ConnectOptions {
                tunnel: Some(TunnelConnectArgs {
                    config: TunnelConfigSnapshot::new(tunnel_id, TunnelKind::WireGuard, "wg"),
                    secret_blob: Some(b"blob".to_vec()),
                }),
                ..ConnectOptions::default()
            },
        )
        .await;
    assert_eq!(handle.state(), SessionState::Connected);
    match handle.connected() {
        Some(ConnectedSession::Http(t)) => {
            assert_eq!(t.navigate_uri, "https://127.0.0.1:51515/");
            assert_eq!(t.original_uri.as_deref(), Some("https://fw.local:443/"));
            assert!(t.socks5_proxy.is_none());
            assert_eq!(t.route, TunnelRouteHint::LocalForwarder);
            assert_eq!(t.tunnel_config_id, Some(tunnel_id));
            assert!(t.ignore_cert_errors());
        }
        other => panic!("expected forwarder http, got {other:?}"),
    }
    handle.close().await;
}

#[tokio::test]
async fn ssh_via_tunnel_sets_socks_transport() {
    let tunnel_id = Uuid::new_v4();
    let broker = Arc::new(FakeTunnelBroker::new(TunnelKind::OpenVpn));
    let orch = SessionOrchestrator::for_tests(
        Arc::new(FakeSerialConnector::new()),
        Arc::new(FakeSshConnector::new()),
        Some(broker as Arc<dyn wormhole_session::TunnelBroker>),
    );
    let mut profile = ssh_profile();
    profile.tunnel_enabled = true;
    profile.tunnel_config_id = Some(tunnel_id);
    let handle = orch
        .connect(
            profile,
            ConnectOptions {
                password: Some("x".into()),
                tunnel: Some(TunnelConnectArgs {
                    config: TunnelConfigSnapshot::new(tunnel_id, TunnelKind::OpenVpn, "ovpn"),
                    secret_blob: Some(vec![1, 2, 3]),
                }),
                ..ConnectOptions::default()
            },
        )
        .await;
    assert_eq!(handle.state(), SessionState::Connected);
    match handle.connected() {
        Some(ConnectedSession::Ssh(SshConnected::Fake { via_socks, .. })) => {
            assert!(*via_socks);
        }
        other => panic!("expected socks ssh, got {other:?}"),
    }
    handle.close().await;
}

#[tokio::test]
async fn ssh_via_tunnel_without_socks_fails_and_releases_lease() {
    let tunnel_id = Uuid::new_v4();
    let broker = Arc::new(ForwarderOnlyBroker::new(TunnelKind::WireGuard, 40_000));
    let manager = Arc::clone(&broker.manager);
    let orch = SessionOrchestrator::for_tests(
        Arc::new(FakeSerialConnector::new()),
        Arc::new(FakeSshConnector::new()),
        Some(broker as Arc<dyn wormhole_session::TunnelBroker>),
    );
    let mut profile = ssh_profile();
    profile.tunnel_enabled = true;
    profile.tunnel_config_id = Some(tunnel_id);
    let handle = orch
        .connect(
            profile,
            ConnectOptions {
                password: Some("x".into()),
                tunnel: Some(TunnelConnectArgs {
                    config: TunnelConfigSnapshot::new(tunnel_id, TunnelKind::WireGuard, "wg"),
                    secret_blob: Some(b"blob".to_vec()),
                }),
                ..ConnectOptions::default()
            },
        )
        .await;
    assert_eq!(handle.state(), SessionState::Failed);
    assert!(matches!(
        handle.last_error(),
        Some(SessionError::TunnelSocksRequired)
    ));
    assert!(handle.tunnel_lease().is_none());
    assert_eq!(manager.pool_ref_count(tunnel_id), 0);
}

#[tokio::test]
async fn cancel_before_connect() {
    let orch = orch_no_tunnel();
    let cancel = CancellationToken::new();
    cancel.cancel();
    let handle = orch
        .connect(
            ssh_profile(),
            ConnectOptions {
                cancel,
                password: Some("x".into()),
                ..ConnectOptions::default()
            },
        )
        .await;
    assert_eq!(handle.state(), SessionState::Failed);
    assert!(handle.last_error().unwrap().is_cancelled());
    // Cancel ends Failed (not Connecting); close → Closed.
    handle.close().await;
}

#[tokio::test]
async fn cancel_during_slow_ssh() {
    let ssh = Arc::new(FakeSshConnector::with_delay(Duration::from_millis(500)));
    let orch = SessionOrchestrator::for_tests(
        Arc::new(FakeSerialConnector::new()),
        Arc::clone(&ssh) as Arc<dyn wormhole_session::SshConnector>,
        None,
    );
    let cancel = CancellationToken::new();
    let cancel2 = cancel.clone();
    let connect = orch.connect(
        ssh_profile(),
        ConnectOptions {
            cancel,
            password: Some("x".into()),
            ..ConnectOptions::default()
        },
    );
    let killer = async {
        tokio::time::sleep(Duration::from_millis(20)).await;
        cancel2.cancel();
    };
    let (handle, _) = tokio::join!(connect, killer);
    assert_eq!(handle.state(), SessionState::Failed);
    assert!(handle.last_error().unwrap().is_cancelled());
    assert_ne!(handle.state(), SessionState::Connecting);
    handle.close().await;
}

#[tokio::test]
async fn cancel_after_tunnel_releases_lease() {
    let tunnel_id = Uuid::new_v4();
    let broker = Arc::new(FakeTunnelBroker::new(TunnelKind::WireGuard));
    let manager = broker.manager();
    let ssh = Arc::new(FakeSshConnector::with_delay(Duration::from_millis(400)));
    let orch = SessionOrchestrator::for_tests(
        Arc::new(FakeSerialConnector::new()),
        Arc::clone(&ssh) as Arc<dyn wormhole_session::SshConnector>,
        Some(broker as Arc<dyn wormhole_session::TunnelBroker>),
    );
    let mut profile = ssh_profile();
    profile.tunnel_enabled = true;
    profile.tunnel_config_id = Some(tunnel_id);
    let cancel = CancellationToken::new();
    let cancel2 = cancel.clone();
    let connect = orch.connect(
        profile,
        ConnectOptions {
            cancel,
            password: Some("x".into()),
            tunnel: Some(TunnelConnectArgs {
                config: TunnelConfigSnapshot::new(tunnel_id, TunnelKind::WireGuard, "wg"),
                secret_blob: Some(b"blob".to_vec()),
            }),
            ..ConnectOptions::default()
        },
    );
    let killer = async {
        // Let tunnel establish, then cancel during slow SSH.
        tokio::time::sleep(Duration::from_millis(30)).await;
        cancel2.cancel();
    };
    let (handle, _) = tokio::join!(connect, killer);
    assert_eq!(handle.state(), SessionState::Failed);
    assert!(handle.last_error().unwrap().is_cancelled());
    assert!(handle.tunnel_lease().is_none());
    assert_eq!(manager.pool_ref_count(tunnel_id), 0);
    handle.close().await;
}

#[tokio::test]
async fn ssh_fail_after_tunnel_releases_lease() {
    let tunnel_id = Uuid::new_v4();
    let broker = Arc::new(FakeTunnelBroker::new(TunnelKind::WireGuard));
    let manager = broker.manager();
    let ssh = Arc::new(FakeSshConnector::new());
    ssh.fail_next("boom");
    let orch = SessionOrchestrator::for_tests(
        Arc::new(FakeSerialConnector::new()),
        Arc::clone(&ssh) as Arc<dyn wormhole_session::SshConnector>,
        Some(broker as Arc<dyn wormhole_session::TunnelBroker>),
    );
    let mut profile = ssh_profile();
    profile.tunnel_enabled = true;
    profile.tunnel_config_id = Some(tunnel_id);
    let handle = orch
        .connect(
            profile,
            ConnectOptions {
                password: Some("x".into()),
                tunnel: Some(TunnelConnectArgs {
                    config: TunnelConfigSnapshot::new(tunnel_id, TunnelKind::WireGuard, "wg"),
                    secret_blob: Some(b"blob".to_vec()),
                }),
                ..ConnectOptions::default()
            },
        )
        .await;
    assert_eq!(handle.state(), SessionState::Failed);
    assert!(handle.tunnel_lease().is_none());
    assert_eq!(manager.pool_ref_count(tunnel_id), 0);
}

#[tokio::test]
async fn unsupported_rdp() {
    let orch = orch_no_tunnel();
    let profile = ConnectionProfile {
        protocol: ProtocolType::Rdp,
        host: "dc.local".into(),
        port: 3389,
        ..ConnectionProfile::default()
    };
    let handle = orch.connect(profile, ConnectOptions::default()).await;
    assert_eq!(handle.state(), SessionState::Failed);
    match handle.last_error() {
        Some(SessionError::UnsupportedProtocol { protocol, reason }) => {
            assert_eq!(*protocol, ProtocolType::Rdp);
            let req = reason.as_rdp_request().expect("rdp prepared");
            assert_eq!(req.host, "dc.local");
            assert_eq!(req.port, 3389);
            assert!(!req.tunnel_enabled);
            let display = handle.last_error().unwrap().to_string();
            assert!(display.contains("RDP surface host not wired"));
            assert!(display.contains("dc.local:3389"));
        }
        other => panic!("expected UnsupportedProtocol Rdp, got {other:?}"),
    }
}

#[tokio::test]
async fn unsupported_vnc() {
    let orch = orch_no_tunnel();
    let profile = ConnectionProfile {
        protocol: ProtocolType::Vnc,
        host: "vnc.local".into(),
        port: 5900,
        ..ConnectionProfile::default()
    };
    let handle = orch.connect(profile, ConnectOptions::default()).await;
    assert_eq!(handle.state(), SessionState::Failed);
    match handle.last_error() {
        Some(SessionError::UnsupportedProtocol { protocol, reason }) => {
            assert_eq!(*protocol, ProtocolType::Vnc);
            let req = reason.as_vnc_request().expect("vnc prepared");
            assert_eq!(req.host, "vnc.local");
            assert_eq!(req.port, 5900);
            let display = handle.last_error().unwrap().to_string();
            assert!(display.contains("VNC engine not wired"));
        }
        other => panic!("expected UnsupportedProtocol Vnc, got {other:?}"),
    }
}

#[tokio::test]
async fn unsupported_rdp_skips_tunnel_even_when_enabled() {
    let tunnel_id = Uuid::new_v4();
    let broker = Arc::new(FakeTunnelBroker::new(TunnelKind::WireGuard));
    let orch = SessionOrchestrator::for_tests(
        Arc::new(FakeSerialConnector::new()),
        Arc::new(FakeSshConnector::new()),
        Some(broker.clone() as Arc<dyn wormhole_session::TunnelBroker>),
    );
    let profile = ConnectionProfile {
        protocol: ProtocolType::Rdp,
        host: "dc.local".into(),
        port: 3389,
        tunnel_enabled: true,
        tunnel_config_id: Some(tunnel_id),
        ..ConnectionProfile::default()
    };
    let handle = orch
        .connect(
            profile,
            ConnectOptions {
                tunnel: Some(TunnelConnectArgs {
                    config: TunnelConfigSnapshot::new(tunnel_id, TunnelKind::WireGuard, "wg"),
                    secret_blob: Some(b"blob".to_vec()),
                }),
                ..ConnectOptions::default()
            },
        )
        .await;
    assert_eq!(handle.state(), SessionState::Failed);
    match handle.last_error() {
        Some(SessionError::UnsupportedProtocol { protocol, reason }) => {
            assert_eq!(*protocol, ProtocolType::Rdp);
            let req = reason.as_rdp_request().expect("rdp prepared");
            assert!(req.tunnel_enabled);
            assert_eq!(req.tunnel_config_id, Some(tunnel_id));
        }
        other => panic!("expected UnsupportedProtocol Rdp, got {other:?}"),
    }
    assert_eq!(broker.provider().establish_count(), 0);
    assert_eq!(broker.manager().establish_start_count(), 0);
}

#[tokio::test]
async fn unsupported_rdp_invalid_port_before_unsupported() {
    let orch = orch_no_tunnel();
    let profile = ConnectionProfile {
        protocol: ProtocolType::Rdp,
        host: "dc.local".into(),
        port: 0,
        ..ConnectionProfile::default()
    };
    let handle = orch.connect(profile, ConnectOptions::default()).await;
    assert_eq!(handle.state(), SessionState::Failed);
    assert!(matches!(
        handle.last_error(),
        Some(SessionError::InvalidPort(0))
    ));
}

#[tokio::test]
async fn unsupported_vnc_invalid_port_before_unsupported() {
    let orch = orch_no_tunnel();
    let profile = ConnectionProfile {
        protocol: ProtocolType::Vnc,
        host: "vnc.local".into(),
        port: -5,
        ..ConnectionProfile::default()
    };
    let handle = orch.connect(profile, ConnectOptions::default()).await;
    assert_eq!(handle.state(), SessionState::Failed);
    assert!(matches!(
        handle.last_error(),
        Some(SessionError::InvalidPort(-5))
    ));
}

#[tokio::test]
async fn unsupported_rdp_invalid_port_skips_tunnel() {
    let tunnel_id = Uuid::new_v4();
    let broker = Arc::new(FakeTunnelBroker::new(TunnelKind::WireGuard));
    let orch = SessionOrchestrator::for_tests(
        Arc::new(FakeSerialConnector::new()),
        Arc::new(FakeSshConnector::new()),
        Some(broker.clone() as Arc<dyn wormhole_session::TunnelBroker>),
    );
    let profile = ConnectionProfile {
        protocol: ProtocolType::Rdp,
        host: "dc.local".into(),
        port: 70_000,
        tunnel_enabled: true,
        tunnel_config_id: Some(tunnel_id),
        ..ConnectionProfile::default()
    };
    let handle = orch
        .connect(
            profile,
            ConnectOptions {
                tunnel: Some(TunnelConnectArgs {
                    config: TunnelConfigSnapshot::new(tunnel_id, TunnelKind::WireGuard, "wg"),
                    secret_blob: Some(b"blob".to_vec()),
                }),
                password: Some("super-secret-password".into()),
                ..ConnectOptions::default()
            },
        )
        .await;
    assert_eq!(handle.state(), SessionState::Failed);
    assert!(matches!(
        handle.last_error(),
        Some(SessionError::InvalidPort(70_000))
    ));
    assert_eq!(broker.provider().establish_count(), 0);
    let err = handle.last_error().unwrap();
    assert!(!format!("{err:?}").contains("super-secret-password"));
    assert!(!err.to_string().contains("super-secret-password"));
}

#[tokio::test]
async fn unsupported_vnc_skips_tunnel_even_when_enabled() {
    let tunnel_id = Uuid::new_v4();
    let broker = Arc::new(FakeTunnelBroker::new(TunnelKind::WireGuard));
    let orch = SessionOrchestrator::for_tests(
        Arc::new(FakeSerialConnector::new()),
        Arc::new(FakeSshConnector::new()),
        Some(broker.clone() as Arc<dyn wormhole_session::TunnelBroker>),
    );
    let profile = ConnectionProfile {
        protocol: ProtocolType::Vnc,
        host: "vnc.local".into(),
        port: 5900,
        tunnel_enabled: true,
        tunnel_config_id: Some(tunnel_id),
        ..ConnectionProfile::default()
    };
    let handle = orch
        .connect(
            profile,
            ConnectOptions {
                tunnel: Some(TunnelConnectArgs {
                    config: TunnelConfigSnapshot::new(tunnel_id, TunnelKind::WireGuard, "wg"),
                    secret_blob: Some(b"blob".to_vec()),
                }),
                ..ConnectOptions::default()
            },
        )
        .await;
    assert_eq!(handle.state(), SessionState::Failed);
    match handle.last_error() {
        Some(SessionError::UnsupportedProtocol { reason, .. }) => {
            assert!(reason.as_vnc_request().unwrap().tunnel_enabled);
        }
        other => panic!("expected UnsupportedProtocol Vnc, got {other:?}"),
    }
    assert_eq!(broker.provider().establish_count(), 0);
    assert_eq!(broker.manager().establish_start_count(), 0);
}

#[tokio::test]
async fn unsupported_rdp_error_debug_omits_connect_options_password() {
    let orch = orch_no_tunnel();
    let secret = "super-secret-password";
    let profile = ConnectionProfile {
        protocol: ProtocolType::Rdp,
        host: "dc.local".into(),
        port: 3389,
        ..ConnectionProfile::default()
    };
    let handle = orch
        .connect(
            profile,
            ConnectOptions {
                password: Some(secret.into()),
                ..ConnectOptions::default()
            },
        )
        .await;
    assert_eq!(handle.state(), SessionState::Failed);
    let err = handle.last_error().expect("error");
    match err {
        SessionError::UnsupportedProtocol { reason, .. } => {
            let req = reason.as_rdp_request().expect("rdp");
            assert!(!format!("{req:?}").contains(secret));
        }
        other => panic!("expected UnsupportedProtocol, got {other:?}"),
    }
    assert!(!format!("{err:?}").contains(secret));
    assert!(!err.to_string().contains(secret));
    assert!(!format!("{handle:?}").contains(secret));
}

#[tokio::test]
async fn unsupported_vnc_empty_host_skips_tunnel() {
    let tunnel_id = Uuid::new_v4();
    let broker = Arc::new(FakeTunnelBroker::new(TunnelKind::WireGuard));
    let orch = SessionOrchestrator::for_tests(
        Arc::new(FakeSerialConnector::new()),
        Arc::new(FakeSshConnector::new()),
        Some(broker.clone() as Arc<dyn wormhole_session::TunnelBroker>),
    );
    let profile = ConnectionProfile {
        protocol: ProtocolType::Vnc,
        host: "  ".into(),
        port: 5900,
        tunnel_enabled: true,
        tunnel_config_id: Some(tunnel_id),
        ..ConnectionProfile::default()
    };
    let handle = orch
        .connect(
            profile,
            ConnectOptions {
                tunnel: Some(TunnelConnectArgs {
                    config: TunnelConfigSnapshot::new(tunnel_id, TunnelKind::WireGuard, "wg"),
                    secret_blob: Some(b"blob".to_vec()),
                }),
                ..ConnectOptions::default()
            },
        )
        .await;
    assert_eq!(handle.state(), SessionState::Failed);
    assert!(matches!(
        handle.last_error(),
        Some(SessionError::IncompleteNode)
    ));
    assert_eq!(broker.provider().establish_count(), 0);
}

#[tokio::test]
async fn connect_node_ssh() {
    let orch = orch_no_tunnel();
    let mut node = ConnectionNode::default();
    node.id = Uuid::new_v4();
    node.kind = NodeKind::Connection;
    node.name = "n".into();
    node.protocol = Some(ProtocolType::Ssh);
    node.host = Some("1.2.3.4".into());
    node.port = Some(22);
    node.username = Some("u".into());
    let handle = orch
        .connect_node(
            &node,
            ConnectOptions {
                password: Some("p".into()),
                ..ConnectOptions::default()
            },
        )
        .await;
    assert_eq!(handle.state(), SessionState::Connected);
    handle.close().await;
}

#[tokio::test]
async fn tunnel_args_required_when_enabled() {
    let broker = Arc::new(FakeTunnelBroker::new(TunnelKind::WireGuard));
    let orch = SessionOrchestrator::for_tests(
        Arc::new(FakeSerialConnector::new()),
        Arc::new(FakeSshConnector::new()),
        Some(broker as Arc<dyn wormhole_session::TunnelBroker>),
    );
    let mut profile = http_profile(true);
    profile.tunnel_enabled = true;
    profile.tunnel_config_id = Some(Uuid::new_v4());
    let handle = orch.connect(profile, ConnectOptions::default()).await;
    assert_eq!(handle.state(), SessionState::Failed);
    assert!(matches!(
        handle.last_error(),
        Some(SessionError::TunnelArgsMissing)
    ));
}

#[tokio::test]
async fn error_display_redacts_password_context() {
    let err = SessionError::PasswordRequired;
    assert_eq!(
        err.to_string(),
        "SSH password is required (inline password or credential_id)"
    );
    // Tunnel establish messages must not embed secret blobs (TunnelError path).
    let te = SessionError::Tunnel(wormhole_tunnels::TunnelError::Establish(
        "provider failed".into(),
    ));
    assert!(!te.to_string().contains("blob"));
}

#[tokio::test]
async fn connect_options_debug_redacts_password() {
    let opts = ConnectOptions {
        password: Some("super-secret-password".into()),
        tunnel: Some(TunnelConnectArgs {
            config: TunnelConfigSnapshot::new(Uuid::nil(), TunnelKind::WireGuard, "wg"),
            secret_blob: Some(b"tunnel-secret-bytes".to_vec()),
        }),
        ..ConnectOptions::default()
    };
    let rendered = format!("{opts:?}");
    assert!(rendered.contains("<redacted>"));
    assert!(!rendered.contains("super-secret-password"));
    assert!(!rendered.contains("tunnel-secret-bytes"));
    assert!(rendered.contains("bytes>"));
}

#[tokio::test]
async fn ssh_invalid_port_fails() {
    let orch = orch_no_tunnel();
    let mut profile = ssh_profile();
    profile.port = 0;
    let handle = orch
        .connect(
            profile,
            ConnectOptions {
                password: Some("x".into()),
                ..ConnectOptions::default()
            },
        )
        .await;
    assert_eq!(handle.state(), SessionState::Failed);
    assert!(matches!(
        handle.last_error(),
        Some(SessionError::InvalidPort(0))
    ));
}

#[tokio::test]
async fn into_result_ok_when_connected() {
    let orch = orch_no_tunnel();
    let handle = orch
        .connect(http_profile(false), ConnectOptions::default())
        .await
        .into_result()
        .expect("connected");
    assert_eq!(handle.state(), SessionState::Connected);
}

#[tokio::test]
async fn close_after_connected_reaches_closed() {
    let orch = orch_no_tunnel();
    let handle = orch
        .connect(http_profile(false), ConnectOptions::default())
        .await;
    assert_eq!(handle.state(), SessionState::Connected);
    // close consumes the handle; state transition is Connecting/Connected → Closed only via close.
    handle.close().await;
}

#[tokio::test]
async fn cancel_then_close_is_failed_then_closed() {
    let orch = orch_no_tunnel();
    let cancel = CancellationToken::new();
    cancel.cancel();
    let handle = orch
        .connect(
            ssh_profile(),
            ConnectOptions {
                cancel,
                password: Some("x".into()),
                ..ConnectOptions::default()
            },
        )
        .await;
    assert_eq!(handle.state(), SessionState::Failed);
    // Illegal Connecting→Closed skip is avoided: cancel lands Failed first.
    assert_ne!(handle.state(), SessionState::Connecting);
    handle.close().await;
}
