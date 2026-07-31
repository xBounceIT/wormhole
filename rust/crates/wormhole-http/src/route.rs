//! HTTP/HTTPS tunnel route selection: prefer SOCKS5, else local forwarder.
//!
//! Mirrors C# `HttpSessionViewModel.BuildTargetAsync` hybrid routing (no I/O):
//! navigate the real hostname when the tunnel exposes SOCKS5; otherwise the
//! caller binds a loopback forwarder and uses [`crate::build_forwarder_target`].
//!
//! **Serial never applies** — COM sessions are local and credential-less; they
//! never call this helper (see session orchestrator: Serial skips tunnel lease).
//! SSH/SFTP require SOCKS and fail closed; RDP/VNC always forwarder.

use crate::target::Socks5Proxy;
use crate::HttpError;

/// Pure preference from an optional tunnel lease view (no network / bind).
///
/// | `tunnel` | SOCKS on instance | Result |
/// |---|---|---|
/// | `None` | — | [`HttpTunnelRoute::Direct`] |
/// | `Some` | `Some(ep)` (port ≠ 0) | [`HttpTunnelRoute::Socks5`] |
/// | `Some` | `None` | [`HttpTunnelRoute::LocalForwarder`] |
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpTunnelRoute {
    /// No tunnel — [`crate::build_direct_target`].
    Direct,
    /// Prefer SOCKS: keep real host; WebView2 `--proxy-server=socks5://…`.
    Socks5(Socks5Proxy),
    /// No SOCKS — caller `BindLocalForwarder` then [`crate::build_forwarder_target`].
    LocalForwarder,
}

impl HttpTunnelRoute {
    pub fn is_direct(&self) -> bool {
        matches!(self, Self::Direct)
    }

    pub fn socks5(&self) -> Option<Socks5Proxy> {
        match self {
            Self::Socks5(ep) => Some(*ep),
            Self::Direct | Self::LocalForwarder => None,
        }
    }

    pub fn needs_local_forwarder(&self) -> bool {
        matches!(self, Self::LocalForwarder)
    }
}

/// Minimal tunnel view for HTTP routing (tests use [`FakeHttpTunnelRoute`]).
///
/// Production adapts `wormhole_tunnels::TunnelInstance::socks5_endpoint` without
/// pulling that crate into `wormhole-http` unit tests.
pub trait HttpTunnelRouteSource {
    fn socks5_endpoint(&self) -> Option<Socks5Proxy>;
}

/// In-memory tunnel route stub — no network.
#[derive(Debug, Clone, Default)]
pub struct FakeHttpTunnelRoute {
    pub socks5: Option<Socks5Proxy>,
}

impl FakeHttpTunnelRoute {
    pub fn none() -> Self {
        Self { socks5: None }
    }

    pub fn with_socks5(endpoint: Socks5Proxy) -> Self {
        Self {
            socks5: Some(endpoint),
        }
    }

    pub fn loopback(port: u16) -> Result<Self, HttpError> {
        Ok(Self::with_socks5(Socks5Proxy::loopback(port)?))
    }
}

impl HttpTunnelRouteSource for FakeHttpTunnelRoute {
    fn socks5_endpoint(&self) -> Option<Socks5Proxy> {
        self.socks5
    }
}

/// Prefer tunnel [`Socks5Proxy`] when present; otherwise local-forwarder fallback.
///
/// Unlike SFTP/SSH (`TunnelSocksRequired`), HTTP falls back to
/// [`HttpTunnelRoute::LocalForwarder`] when the lease has no SOCKS — parity with
/// C# hybrid WebView2 routing. Port `0` SOCKS is rejected (not a usable listener).
///
/// Scope: HTTP/HTTPS targets only. Serial never uses this selector.
pub fn select_http_tunnel_route(
    tunnel: Option<&dyn HttpTunnelRouteSource>,
) -> Result<HttpTunnelRoute, HttpError> {
    match tunnel {
        None => Ok(HttpTunnelRoute::Direct),
        Some(t) => match t.socks5_endpoint() {
            Some(ep) => {
                if ep.addr.port() == 0 {
                    return Err(HttpError::InvalidPort(0));
                }
                Ok(HttpTunnelRoute::Socks5(ep))
            }
            None => Ok(HttpTunnelRoute::LocalForwarder),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::{
        build_direct_target, build_forwarder_target, build_socks_target, resolve_cert_policy,
        HttpCertPolicy, HttpScheme, TunnelRouteHint,
    };
    use std::net::{Ipv4Addr, SocketAddr};
    use uuid::Uuid;

    #[test]
    fn no_tunnel_selects_direct() {
        let r = select_http_tunnel_route(None).unwrap();
        assert!(r.is_direct());
        assert!(r.socks5().is_none());
        assert!(!r.needs_local_forwarder());
        assert_eq!(r, HttpTunnelRoute::Direct);
    }

    #[test]
    fn prefer_socks5_when_endpoint_present() {
        let fake = FakeHttpTunnelRoute::loopback(1080).unwrap();
        let r = select_http_tunnel_route(Some(&fake)).unwrap();
        let ep = r.socks5().expect("socks preferred");
        assert_eq!(ep.addr, SocketAddr::from((Ipv4Addr::LOCALHOST, 1080)));
        assert!(!r.needs_local_forwarder());
        assert!(!r.is_direct());
    }

    #[test]
    fn else_local_forwarder_when_no_socks() {
        let fake = FakeHttpTunnelRoute::none();
        let r = select_http_tunnel_route(Some(&fake)).unwrap();
        assert_eq!(r, HttpTunnelRoute::LocalForwarder);
        assert!(r.needs_local_forwarder());
        assert!(r.socks5().is_none());
    }

    #[test]
    fn socks_presence_never_selects_forwarder() {
        // Selection only sees SOCKS; presence alone forces Socks5 (never forwarder).
        let fake = FakeHttpTunnelRoute::with_socks5(Socks5Proxy::new(SocketAddr::from((
            Ipv4Addr::LOCALHOST,
            58921,
        ))));
        let ep = fake.socks5.unwrap();
        assert_eq!(
            select_http_tunnel_route(Some(&fake)).unwrap(),
            HttpTunnelRoute::Socks5(ep)
        );
        assert!(!select_http_tunnel_route(Some(&FakeHttpTunnelRoute::with_socks5(ep)))
            .unwrap()
            .needs_local_forwarder());
    }

    #[test]
    fn zero_port_socks_rejected() {
        assert!(FakeHttpTunnelRoute::loopback(0).is_err());
        assert!(matches!(
            Socks5Proxy::loopback(0),
            Err(HttpError::InvalidPort(0))
        ));

        let fake = FakeHttpTunnelRoute::with_socks5(Socks5Proxy::new(SocketAddr::from((
            Ipv4Addr::LOCALHOST,
            0,
        ))));
        assert_eq!(
            select_http_tunnel_route(Some(&fake)),
            Err(HttpError::InvalidPort(0))
        );

        // IPv6 :0 also fail-closed (never Direct / never LocalForwarder).
        let v6 = FakeHttpTunnelRoute::with_socks5(Socks5Proxy::new(SocketAddr::from((
            std::net::Ipv6Addr::LOCALHOST,
            0,
        ))));
        assert_eq!(
            select_http_tunnel_route(Some(&v6)),
            Err(HttpError::InvalidPort(0))
        );
    }

    #[test]
    fn selection_then_builder_preserves_cert_policy() {
        let id = Uuid::new_v4();
        let cases = [
            (HttpScheme::Http, false, HttpCertPolicy::Default),
            (HttpScheme::Http, true, HttpCertPolicy::Default),
            (HttpScheme::Https, false, HttpCertPolicy::Default),
            (HttpScheme::Https, true, HttpCertPolicy::IgnoreErrors),
        ];
        for (scheme, leaf, expected) in cases {
            assert_eq!(resolve_cert_policy(scheme, leaf), expected);
            let port = i32::from(scheme.default_port());

            // Direct
            assert_eq!(select_http_tunnel_route(None).unwrap(), HttpTunnelRoute::Direct);
            let direct = build_direct_target(scheme, "fw.local", port, leaf).unwrap();
            assert_eq!(direct.cert_policy, expected);
            assert_eq!(direct.route, TunnelRouteHint::Direct);

            // Prefer SOCKS
            let socks_src = FakeHttpTunnelRoute::loopback(1080).unwrap();
            let HttpTunnelRoute::Socks5(proxy) =
                select_http_tunnel_route(Some(&socks_src)).unwrap()
            else {
                panic!("expected Socks5");
            };
            let socks_t =
                build_socks_target(scheme, "fw.local", port, leaf, proxy, Some(id)).unwrap();
            assert_eq!(socks_t.cert_policy, expected);
            assert_eq!(socks_t.route, TunnelRouteHint::Socks5);
            assert!(socks_t.original_uri.is_none());
            assert!(socks_t.navigate_uri.contains("fw.local"));

            // Else forwarder
            let fwd_src = FakeHttpTunnelRoute::none();
            assert!(select_http_tunnel_route(Some(&fwd_src))
                .unwrap()
                .needs_local_forwarder());
            let fwd =
                build_forwarder_target(scheme, "fw.local", port, leaf, 51515, Some(id)).unwrap();
            assert_eq!(fwd.cert_policy, expected);
            assert_eq!(fwd.route, TunnelRouteHint::LocalForwarder);
            assert!(fwd.socks5_proxy.is_none());
            assert!(fwd.navigate_uri.contains("127.0.0.1"));
        }
    }

    /// Serial is out of scope for this crate: no `HttpScheme::Serial`, and
    /// `select_http_tunnel_route` is never consulted for COM sessions.
    #[test]
    fn serial_never_applies_http_tunnel_routing() {
        fn scheme_label(scheme: HttpScheme) -> &'static str {
            // Exhaustive: adding a non-web scheme would fail to compile here.
            match scheme {
                HttpScheme::Http => "http",
                HttpScheme::Https => "https",
            }
        }
        assert_eq!(scheme_label(HttpScheme::Http), "http");
        assert_eq!(scheme_label(HttpScheme::Https), "https");
        // Selection API has no protocol/serial parameter — tunnel view only.
        assert_eq!(select_http_tunnel_route(None).unwrap(), HttpTunnelRoute::Direct);
        assert!(select_http_tunnel_route(Some(&FakeHttpTunnelRoute::none()))
            .unwrap()
            .needs_local_forwarder());
    }
}
