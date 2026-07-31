//! SFTP dial target selection: Direct vs SOCKS5 from an optional tunnel lease.
//!
//! Mirrors C# `SftpService.ConnectAsync` tunnel routing — same fail-closed rule as
//! SSH: a tunnel without SOCKS5 must not silently dial the public network.
//!
//! Live SOCKS CONNECT + `russh` channel wiring remains deferred; this module only
//! picks the route (unit-tested with [`FakeTunnelSocks`], no network).

use std::net::SocketAddr;

use crate::error::SftpError;
use crate::Result;

/// Loopback (or other) SOCKS5 proxy for SFTP-over-SSH when a tunnel lease is present.
///
/// Shape matches `wormhole_tunnels::Socks5Endpoint` (`addr` only — v1 sidecars are
/// no-auth). Kept local so `wormhole-sftp` does not depend on the tunnels crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Socks5Endpoint {
    pub addr: SocketAddr,
}

impl Socks5Endpoint {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    /// `127.0.0.1:port`. Port `0` is rejected (not a usable SOCKS listener).
    pub fn loopback(port: u16) -> Result<Self> {
        if port == 0 {
            return Err(SftpError::InvalidSocksPort(0));
        }
        Ok(Self {
            addr: SocketAddr::from(([127, 0, 0, 1], port)),
        })
    }
}

/// How the SFTP client should obtain its SSH byte stream.
///
/// Maps to C# `ConnectionInfo` with/without `ProxyTypes.Socks5`. This enum
/// carries **route only** — never a rewritten SSH destination. Callers must
/// keep the original SSH host/port as the CONNECT target (C#
/// `ConnectionInfo(profile.Host, profile.Port, …)`); do **not** dial
/// [`Socks5Endpoint::addr`] as the SSH peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SftpTransport {
    /// No tunnel — dial `host:port` directly.
    Direct,
    /// Dial via tunnel SOCKS5; CONNECT target remains the real SSH host/port.
    Socks5(Socks5Endpoint),
}

impl SftpTransport {
    pub fn is_direct(&self) -> bool {
        matches!(self, Self::Direct)
    }

    pub fn socks5(&self) -> Option<Socks5Endpoint> {
        match self {
            Self::Direct => None,
            Self::Socks5(ep) => Some(*ep),
        }
    }
}

/// Minimal view of a tunnel instance for SFTP routing (tests use [`FakeTunnelSocks`]).
///
/// Production call sites will adapt `wormhole_tunnels::TunnelInstance` /
/// `TunnelLease` without pulling that crate into unit tests here.
pub trait TunnelSocksSource {
    fn socks5_endpoint(&self) -> Option<Socks5Endpoint>;
}

/// In-memory tunnel SOCKS stub — pure data, **no sockets / no network I/O**.
#[derive(Debug, Clone, Default)]
pub struct FakeTunnelSocks {
    pub socks5: Option<Socks5Endpoint>,
}

impl FakeTunnelSocks {
    pub fn none() -> Self {
        Self { socks5: None }
    }

    pub fn with_socks5(endpoint: Socks5Endpoint) -> Self {
        Self {
            socks5: Some(endpoint),
        }
    }

    /// In-memory `127.0.0.1:port` view — does **not** bind a listener.
    pub fn loopback(port: u16) -> Result<Self> {
        Ok(Self::with_socks5(Socks5Endpoint::loopback(port)?))
    }
}

impl TunnelSocksSource for FakeTunnelSocks {
    fn socks5_endpoint(&self) -> Option<Socks5Endpoint> {
        self.socks5
    }
}

/// Pick Direct vs SOCKS5 from an optional tunnel lease.
///
/// | `tunnel` | SOCKS on instance | Result |
/// |---|---|---|
/// | `None` | — | [`SftpTransport::Direct`] |
/// | `Some` | `Some(ep)` | [`SftpTransport::Socks5`] (SSH host unchanged at call site) |
/// | `Some` | `None` | [`SftpError::TunnelSocksRequired`] |
///
/// Unlike HTTP, SFTP does **not** fall back to a local TCP forwarder — parity with
/// C# `SftpService` / SSH terminal (`TunnelSocksRequired` if the lease has no SOCKS).
///
/// Port `0` on a present SOCKS endpoint → [`SftpError::InvalidSocksPort`] (fail closed;
/// never treat as Direct). Error Display / [`SftpError::public_message`] carry only
/// the port number — no hostnames, credentials, or tunnel secrets.
pub fn select_sftp_transport(tunnel: Option<&dyn TunnelSocksSource>) -> Result<SftpTransport> {
    match tunnel {
        None => Ok(SftpTransport::Direct),
        Some(t) => match t.socks5_endpoint() {
            Some(ep) => {
                let port = ep.addr.port();
                if port == 0 {
                    return Err(SftpError::InvalidSocksPort(port));
                }
                Ok(SftpTransport::Socks5(ep))
            }
            None => Err(SftpError::TunnelSocksRequired),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn no_tunnel_selects_direct() {
        let t = select_sftp_transport(None).unwrap();
        assert!(t.is_direct());
        assert!(t.socks5().is_none());
        assert_eq!(t, SftpTransport::Direct);
    }

    #[test]
    fn fake_socks_endpoint_selects_socks5() {
        let fake = FakeTunnelSocks::loopback(1080).unwrap();
        let t = select_sftp_transport(Some(&fake)).unwrap();
        let ep = t.socks5().expect("socks");
        assert_eq!(ep.addr, SocketAddr::from((Ipv4Addr::LOCALHOST, 1080)));
        assert!(!t.is_direct());
    }

    #[test]
    fn socks5_keeps_ssh_connect_host_at_call_site() {
        // C# ConnectionInfo(profile.Host, profile.Port, …, ProxyTypes.Socks5, …):
        // SSH CONNECT target stays the real host; SOCKS is proxy-only on the transport.
        // select_sftp_transport takes no host — SftpTransport::Socks5 must carry only
        // the proxy endpoint (no rewritten SSH destination field).
        let proxy = SocketAddr::from((Ipv4Addr::LOCALHOST, 1080));
        let fake = FakeTunnelSocks::with_socks5(Socks5Endpoint::new(proxy));
        match select_sftp_transport(Some(&fake)).unwrap() {
            SftpTransport::Socks5(ep) => {
                assert_eq!(ep.addr, proxy);
                // Proxy loopback is not a stand-in SSH peer (callers dial real host:22).
                assert_ne!(ep.addr.port(), 22);
            }
            other => panic!("expected Socks5 (proxy-only route), got {other:?}"),
        }
    }

    #[test]
    fn tunnel_without_socks_fails_closed() {
        let fake = FakeTunnelSocks::none();
        let err = select_sftp_transport(Some(&fake)).unwrap_err();
        assert!(matches!(err, SftpError::TunnelSocksRequired));
        assert_eq!(
            err.public_message(),
            "SFTP over tunnel requires a SOCKS5 endpoint on the lease"
        );
        assert_eq!(format!("{err}"), err.public_message());
        assert_eq!(format!("{err:?}"), "TunnelSocksRequired");
        // Never silent-Direct.
        assert!(select_sftp_transport(Some(&FakeTunnelSocks::default())).is_err());
    }

    #[test]
    fn zero_port_socks_rejected() {
        assert!(matches!(
            Socks5Endpoint::loopback(0),
            Err(SftpError::InvalidSocksPort(0))
        ));
        assert!(FakeTunnelSocks::loopback(0).is_err());

        let fake = FakeTunnelSocks::with_socks5(Socks5Endpoint::new(SocketAddr::from((
            Ipv4Addr::LOCALHOST,
            0,
        ))));
        let err = select_sftp_transport(Some(&fake)).unwrap_err();
        assert!(matches!(err, SftpError::InvalidSocksPort(0)));
        assert_eq!(err.public_message(), "invalid SOCKS5 port 0");
        assert_eq!(format!("{err}"), "invalid SOCKS5 port 0");
        assert_eq!(format!("{err:?}"), "InvalidSocksPort(0)");

        // IPv6 :0 also fail-closed (not Direct).
        let v6 = FakeTunnelSocks::with_socks5(Socks5Endpoint::new(SocketAddr::from((
            std::net::Ipv6Addr::LOCALHOST,
            0,
        ))));
        let err6 = select_sftp_transport(Some(&v6)).unwrap_err();
        assert!(matches!(err6, SftpError::InvalidSocksPort(0)));
    }

    #[test]
    fn routing_errors_omit_secrets() {
        for err in [
            select_sftp_transport(Some(&FakeTunnelSocks::none())).unwrap_err(),
            select_sftp_transport(Some(&FakeTunnelSocks::with_socks5(Socks5Endpoint::new(
                SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            ))))
            .unwrap_err(),
        ] {
            let surfaces = [
                format!("{err}"),
                format!("{err:?}"),
                err.public_message(),
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
        // Construction must not bind ports or perform I/O (in-memory stub only).
        let _ = FakeTunnelSocks::none();
        let _ = FakeTunnelSocks::loopback(1080).unwrap();
        let _ = FakeTunnelSocks::with_socks5(Socks5Endpoint::new(SocketAddr::from((
            Ipv4Addr::LOCALHOST,
            9050,
        ))));
        assert!(FakeTunnelSocks::default().socks5.is_none());
    }

    #[test]
    fn fake_endpoint_addr_is_preserved() {
        let addr = SocketAddr::from(([10, 0, 0, 2], 9050));
        let fake = FakeTunnelSocks::with_socks5(Socks5Endpoint::new(addr));
        match select_sftp_transport(Some(&fake)).unwrap() {
            SftpTransport::Socks5(ep) => assert_eq!(ep.addr, addr),
            other => panic!("expected Socks5, got {other:?}"),
        }
    }
}
