//! SSH SOCKS5 tunnel route select glue stub.
//!
//! Pure decision: resolved `tunnel_enabled` + optional SOCKS endpoint →
//! [`SshConnectTarget::{Direct,Socks5}`]. Fail-closed when the tunnel is on but
//! SOCKS is missing / port `0`. **Serial never routes** (always Direct).
//!
//! Mirrors C# `SshSessionService` / `SftpService` SOCKS-when-tunnel (no local
//! forwarder fallback — unlike HTTP). Unit tests use [`FakeTunnelSocks`] only
//! (no live SSH / no network). Live SOCKS CONNECT remains the transport hook
//! (`Socks5NotImplemented`).

use std::fmt;
use std::net::SocketAddr;

/// Session kind for SSH dial-target routing.
///
/// Serial is local COM and never uses VPN / SOCKS (domain inheritance also forces
/// `tunnel_enabled = false`; this enum is defense in depth at the select site).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SshRouteSessionKind {
    /// SSH terminal (and SFTP-over-SSH peer path).
    Ssh,
    /// Local serial line — never Direct→Socks5.
    Serial,
}

impl SshRouteSessionKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
            Self::Serial => "serial",
        }
    }

    /// Whether this session may consume a tunnel SOCKS endpoint.
    pub const fn allows_tunnel_routing(self) -> bool {
        matches!(self, Self::Ssh)
    }
}

/// Loopback (or other) SOCKS5 proxy when a tunnel lease is present.
///
/// Shape matches `wormhole_tunnels::Socks5Endpoint` / SFTP (`addr` only — v1
/// sidecars are no-auth). Kept local so this always-on glue does not depend on
/// the tunnels crate or the `client` dialer hook's credential-capable endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunnelSocksEndpoint {
    pub addr: SocketAddr,
}

impl TunnelSocksEndpoint {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    /// `127.0.0.1:port`. Port `0` is rejected (not a usable SOCKS listener).
    pub fn loopback(port: u16) -> Result<Self, SshTunnelRouteError> {
        if port == 0 {
            return Err(SshTunnelRouteError::InvalidSocksPort(0));
        }
        Ok(Self {
            addr: SocketAddr::from(([127, 0, 0, 1], port)),
        })
    }
}

/// How the SSH client should obtain its byte stream (route only).
///
/// Carries **proxy route only** — never a rewritten SSH destination. Callers
/// keep the original SSH host/port as the CONNECT target; do **not** dial
/// [`TunnelSocksEndpoint::addr`] as the SSH peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshConnectTarget {
    /// Tunnel off (or Serial) — dial `host:port` directly.
    Direct,
    /// Tunnel on — dial via SOCKS5; CONNECT target remains the real SSH host/port.
    Socks5(TunnelSocksEndpoint),
}

impl SshConnectTarget {
    pub fn is_direct(&self) -> bool {
        matches!(self, Self::Direct)
    }

    pub fn socks5(&self) -> Option<TunnelSocksEndpoint> {
        match self {
            Self::Direct => None,
            Self::Socks5(ep) => Some(*ep),
        }
    }
}

/// Minimal view of a tunnel instance for SSH routing (tests use [`FakeTunnelSocks`]).
///
/// Production adapts `wormhole_tunnels::TunnelInstance::socks5_endpoint` without
/// pulling that crate into unit tests here.
pub trait TunnelSocksSource {
    fn socks5_endpoint(&self) -> Option<TunnelSocksEndpoint>;
}

/// In-memory tunnel SOCKS stub — pure data, **no sockets / no network I/O**.
#[derive(Debug, Clone, Default)]
pub struct FakeTunnelSocks {
    pub socks5: Option<TunnelSocksEndpoint>,
}

impl FakeTunnelSocks {
    pub fn none() -> Self {
        Self { socks5: None }
    }

    pub fn with_socks5(endpoint: TunnelSocksEndpoint) -> Self {
        Self {
            socks5: Some(endpoint),
        }
    }

    /// In-memory `127.0.0.1:port` view — does **not** bind a listener.
    pub fn loopback(port: u16) -> Result<Self, SshTunnelRouteError> {
        Ok(Self::with_socks5(TunnelSocksEndpoint::loopback(port)?))
    }
}

impl TunnelSocksSource for FakeTunnelSocks {
    fn socks5_endpoint(&self) -> Option<TunnelSocksEndpoint> {
        self.socks5
    }
}

/// Route select failed (fail closed — never silent Direct when tunnel is on).
#[derive(Clone, PartialEq, Eq)]
pub enum SshTunnelRouteError {
    /// `tunnel_enabled` but lease missing SOCKS (or no lease view).
    TunnelSocksRequired,
    /// Present SOCKS endpoint with port `0`.
    InvalidSocksPort(u16),
}

impl SshTunnelRouteError {
    /// Stable, secrets-free message for UI / logs.
    pub fn public_message(&self) -> &'static str {
        match self {
            Self::TunnelSocksRequired => {
                "SSH over tunnel requires a SOCKS5 endpoint on the lease"
            }
            Self::InvalidSocksPort(_) => "invalid SOCKS5 port 0",
        }
    }
}

impl fmt::Debug for SshTunnelRouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TunnelSocksRequired => f.write_str("TunnelSocksRequired"),
            Self::InvalidSocksPort(p) => f.debug_tuple("InvalidSocksPort").field(p).finish(),
        }
    }
}

impl fmt::Display for SshTunnelRouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TunnelSocksRequired => f.write_str(self.public_message()),
            Self::InvalidSocksPort(port) => write!(f, "invalid SOCKS5 port {port}"),
        }
    }
}

impl std::error::Error for SshTunnelRouteError {}

/// Pick Direct vs SOCKS5 from resolved `tunnel_enabled` + optional lease SOCKS.
///
/// | Session | `tunnel_enabled` | SOCKS on source | Result |
/// |---|---|---|---|
/// | [`Serial`](SshRouteSessionKind::Serial) | * | * | [`Direct`](SshConnectTarget::Direct) |
/// | [`Ssh`](SshRouteSessionKind::Ssh) | `false` | * | [`Direct`](SshConnectTarget::Direct) |
/// | [`Ssh`](SshRouteSessionKind::Ssh) | `true` | `Some(ep)` port ≠ 0 | [`Socks5`](SshConnectTarget::Socks5) |
/// | [`Ssh`](SshRouteSessionKind::Ssh) | `true` | missing / `None` | [`TunnelSocksRequired`](SshTunnelRouteError::TunnelSocksRequired) |
/// | [`Ssh`](SshRouteSessionKind::Ssh) | `true` | port `0` | [`InvalidSocksPort`](SshTunnelRouteError::InvalidSocksPort) |
///
/// Unlike HTTP, SSH does **not** fall back to a local TCP forwarder. Port `0` and
/// missing SOCKS never become Direct when the tunnel is on.
///
/// `tunnel` may be `None` when `tunnel_enabled` is false (no lease). When
/// `tunnel_enabled` is true, `None` or a source without SOCKS fails closed.
pub fn select_ssh_connect_target(
    session: SshRouteSessionKind,
    tunnel_enabled: bool,
    tunnel: Option<&dyn TunnelSocksSource>,
) -> Result<SshConnectTarget, SshTunnelRouteError> {
    if !session.allows_tunnel_routing() {
        return Ok(SshConnectTarget::Direct);
    }
    if !tunnel_enabled {
        return Ok(SshConnectTarget::Direct);
    }
    match tunnel.and_then(|t| t.socks5_endpoint()) {
        Some(ep) => {
            let port = ep.addr.port();
            if port == 0 {
                return Err(SshTunnelRouteError::InvalidSocksPort(port));
            }
            Ok(SshConnectTarget::Socks5(ep))
        }
        None => Err(SshTunnelRouteError::TunnelSocksRequired),
    }
}

/// SSH-only convenience — same as [`select_ssh_connect_target`] with
/// [`SshRouteSessionKind::Ssh`].
pub fn select_ssh_tunnel_route(
    tunnel_enabled: bool,
    tunnel: Option<&dyn TunnelSocksSource>,
) -> Result<SshConnectTarget, SshTunnelRouteError> {
    select_ssh_connect_target(SshRouteSessionKind::Ssh, tunnel_enabled, tunnel)
}

#[cfg(feature = "client")]
impl SshConnectTarget {
    /// Map route select → dialer [`crate::SshTransport`] (SOCKS CONNECT still stubbed).
    pub fn to_transport(&self) -> crate::SshTransport {
        match self {
            Self::Direct => crate::SshTransport::Direct,
            Self::Socks5(ep) => crate::SshTransport::Socks5(crate::Socks5Endpoint {
                proxy_host: ep.addr.ip().to_string(),
                proxy_port: ep.addr.port(),
                username: None,
                password: None,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    #[test]
    fn tunnel_off_selects_direct() {
        let t = select_ssh_tunnel_route(false, None).unwrap();
        assert!(t.is_direct());
        assert!(t.socks5().is_none());
        assert_eq!(t, SshConnectTarget::Direct);

        // Socks present but tunnel off → still Direct (user/inheritance chose direct).
        let fake = FakeTunnelSocks::loopback(1080).unwrap();
        assert_eq!(
            select_ssh_tunnel_route(false, Some(&fake)).unwrap(),
            SshConnectTarget::Direct
        );
    }

    #[test]
    fn tunnel_on_with_socks_selects_socks5() {
        let fake = FakeTunnelSocks::loopback(1080).unwrap();
        let t = select_ssh_tunnel_route(true, Some(&fake)).unwrap();
        let ep = t.socks5().expect("socks");
        assert_eq!(ep.addr, SocketAddr::from((Ipv4Addr::LOCALHOST, 1080)));
        assert!(!t.is_direct());
    }

    #[test]
    fn socks5_keeps_ssh_connect_host_at_call_site() {
        let proxy = SocketAddr::from((Ipv4Addr::LOCALHOST, 1080));
        let fake = FakeTunnelSocks::with_socks5(TunnelSocksEndpoint::new(proxy));
        match select_ssh_tunnel_route(true, Some(&fake)).unwrap() {
            SshConnectTarget::Socks5(ep) => {
                assert_eq!(ep.addr, proxy);
                assert_ne!(ep.addr.port(), 22);
            }
            other => panic!("expected Socks5 (proxy-only route), got {other:?}"),
        }
    }

    #[test]
    fn tunnel_on_without_socks_fails_closed() {
        let fake = FakeTunnelSocks::none();
        let err = select_ssh_tunnel_route(true, Some(&fake)).unwrap_err();
        assert_eq!(err, SshTunnelRouteError::TunnelSocksRequired);
        assert_eq!(
            err.public_message(),
            "SSH over tunnel requires a SOCKS5 endpoint on the lease"
        );
        assert_eq!(format!("{err}"), err.public_message());
        assert_eq!(format!("{err:?}"), "TunnelSocksRequired");

        // No lease view at all.
        assert_eq!(
            select_ssh_tunnel_route(true, None).unwrap_err(),
            SshTunnelRouteError::TunnelSocksRequired
        );
        assert!(select_ssh_tunnel_route(true, Some(&FakeTunnelSocks::default())).is_err());
    }

    #[test]
    fn zero_port_socks_rejected() {
        assert_eq!(
            TunnelSocksEndpoint::loopback(0).unwrap_err(),
            SshTunnelRouteError::InvalidSocksPort(0)
        );
        assert!(FakeTunnelSocks::loopback(0).is_err());

        let fake = FakeTunnelSocks::with_socks5(TunnelSocksEndpoint::new(SocketAddr::from((
            Ipv4Addr::LOCALHOST,
            0,
        ))));
        let err = select_ssh_tunnel_route(true, Some(&fake)).unwrap_err();
        assert_eq!(err, SshTunnelRouteError::InvalidSocksPort(0));
        assert_eq!(err.public_message(), "invalid SOCKS5 port 0");
        assert_eq!(format!("{err}"), "invalid SOCKS5 port 0");
        assert_eq!(format!("{err:?}"), "InvalidSocksPort(0)");

        let v6 = FakeTunnelSocks::with_socks5(TunnelSocksEndpoint::new(SocketAddr::from((
            Ipv6Addr::LOCALHOST,
            0,
        ))));
        assert_eq!(
            select_ssh_tunnel_route(true, Some(&v6)).unwrap_err(),
            SshTunnelRouteError::InvalidSocksPort(0)
        );
    }

    #[test]
    fn serial_never_routes() {
        let fake = FakeTunnelSocks::loopback(1080).unwrap();
        // Even with tunnel_enabled + SOCKS, Serial stays Direct.
        let t = select_ssh_connect_target(SshRouteSessionKind::Serial, true, Some(&fake)).unwrap();
        assert_eq!(t, SshConnectTarget::Direct);
        assert!(!SshRouteSessionKind::Serial.allows_tunnel_routing());
        assert!(SshRouteSessionKind::Ssh.allows_tunnel_routing());
        assert_eq!(SshRouteSessionKind::Serial.as_str(), "serial");
        assert_eq!(SshRouteSessionKind::Ssh.as_str(), "ssh");

        // Serial + tunnel on + no socks must not fail closed (never consults SOCKS).
        assert_eq!(
            select_ssh_connect_target(SshRouteSessionKind::Serial, true, None).unwrap(),
            SshConnectTarget::Direct
        );
    }

    #[test]
    fn select_ssh_tunnel_route_matches_ssh_kind() {
        let fake = FakeTunnelSocks::loopback(9050).unwrap();
        assert_eq!(
            select_ssh_tunnel_route(true, Some(&fake)).unwrap(),
            select_ssh_connect_target(SshRouteSessionKind::Ssh, true, Some(&fake)).unwrap()
        );
        assert_eq!(
            select_ssh_tunnel_route(false, None).unwrap(),
            select_ssh_connect_target(SshRouteSessionKind::Ssh, false, None).unwrap()
        );
    }

    #[test]
    fn routing_errors_omit_secrets() {
        for err in [
            select_ssh_tunnel_route(true, None).unwrap_err(),
            select_ssh_tunnel_route(true, Some(&FakeTunnelSocks::none())).unwrap_err(),
            select_ssh_tunnel_route(
                true,
                Some(&FakeTunnelSocks::with_socks5(TunnelSocksEndpoint::new(
                    SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                ))),
            )
            .unwrap_err(),
        ] {
            let surfaces = [
                format!("{err}"),
                format!("{err:?}"),
                err.public_message().to_string(),
            ];
            for s in surfaces {
                let lower = s.to_ascii_lowercase();
                assert!(!lower.contains("password"), "{s}");
                assert!(!lower.contains("secret"), "{s}");
                assert!(!s.contains("hunter2"), "{s}");
            }
        }
    }

    #[test]
    fn fake_tunnel_socks_is_pure_data() {
        let _ = FakeTunnelSocks::none();
        let _ = FakeTunnelSocks::loopback(1080).unwrap();
        let _ = FakeTunnelSocks::with_socks5(TunnelSocksEndpoint::new(SocketAddr::from((
            Ipv4Addr::LOCALHOST,
            9050,
        ))));
        assert!(FakeTunnelSocks::default().socks5.is_none());
    }

    #[test]
    fn fake_endpoint_addr_is_preserved() {
        let addr = SocketAddr::from(([10, 0, 0, 2], 9050));
        let fake = FakeTunnelSocks::with_socks5(TunnelSocksEndpoint::new(addr));
        match select_ssh_tunnel_route(true, Some(&fake)).unwrap() {
            SshConnectTarget::Socks5(ep) => assert_eq!(ep.addr, addr),
            other => panic!("expected Socks5, got {other:?}"),
        }
    }

    #[test]
    fn ipv6_nonzero_socks_preserved() {
        let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, 1080));
        let fake = FakeTunnelSocks::with_socks5(TunnelSocksEndpoint::new(addr));
        match select_ssh_tunnel_route(true, Some(&fake)).unwrap() {
            SshConnectTarget::Socks5(ep) => assert_eq!(ep.addr, addr),
            other => panic!("expected Socks5, got {other:?}"),
        }
    }

    #[test]
    fn connect_target_is_direct_or_socks5_only() {
        // Exhaustive match: adding LocalForwarder (HTTP/RDP path) fails compile here.
        for target in [
            SshConnectTarget::Direct,
            SshConnectTarget::Socks5(TunnelSocksEndpoint::loopback(1080).unwrap()),
        ] {
            match target {
                SshConnectTarget::Direct => assert!(target.is_direct()),
                SshConnectTarget::Socks5(_) => assert!(target.socks5().is_some()),
            }
        }
    }

    #[cfg(feature = "client")]
    #[test]
    fn to_transport_maps_direct_and_socks() {
        assert_eq!(
            SshConnectTarget::Direct.to_transport(),
            crate::SshTransport::Direct
        );
        let ep = TunnelSocksEndpoint::loopback(1080).unwrap();
        match SshConnectTarget::Socks5(ep).to_transport() {
            crate::SshTransport::Socks5(dial) => {
                assert_eq!(dial.proxy_host, "127.0.0.1");
                assert_eq!(dial.proxy_port, 1080);
                assert!(dial.username.is_none());
                assert!(dial.password.is_none());
            }
            other => panic!("expected Socks5 transport, got {other:?}"),
        }

        // IPv6 loopback maps via IpAddr::to_string (no brackets) — dialer owns CONNECT.
        let v6 = TunnelSocksEndpoint::new(SocketAddr::from((Ipv6Addr::LOCALHOST, 9050)));
        match SshConnectTarget::Socks5(v6).to_transport() {
            crate::SshTransport::Socks5(dial) => {
                assert_eq!(dial.proxy_host, "::1");
                assert_eq!(dial.proxy_port, 9050);
                assert!(dial.username.is_none());
                assert!(dial.password.is_none());
            }
            other => panic!("expected Socks5 transport, got {other:?}"),
        }
    }
}
