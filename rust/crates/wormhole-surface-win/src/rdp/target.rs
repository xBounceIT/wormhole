//! RDP dial target selection: Direct vs loopback `BindLocalForwarder`.
//!
//! Mirrors C# `RdpSessionViewModel.PrepareConnectProfileAsync` tunnel routing and
//! VNC's [`wormhole_vnc::select_vnc_connect_target`] — ActiveX **cannot** speak
//! SOCKS5, so a present tunnel always binds a `127.0.0.1` forwarder to the real
//! host/port and the OCX dials loopback.
//!
//! Live bind + Connect remain deferred; this module picks the route (unit-tested
//! with [`FakeTunnelForwarder`], no network) and fails closed on the mistaken
//! HTTP-style SOCKS preference. Tunnel policy combos (external / gateway /
//! strict) are checked by [`prepare_rdp_connect_target`] **before** any bind.

use std::cell::RefCell;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};

use super::configure::{validate_tunnel_rdp_policy, TunnelRdpConflict, TunnelRdpPolicy};

/// C# `IPAddress.Loopback.ToString()` — RDP always dials this after a forwarder bind.
const LOOPBACK_HOST: &str = "127.0.0.1";

/// How the RDP ActiveX control should obtain its TCP endpoint.
///
/// Unlike HTTP (SOCKS preferred) or SSH/SFTP (SOCKS required), RDP **never**
/// uses SOCKS — parity with C# `BindLocalForwarderAsync` for RDP/VNC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RdpConnectTarget {
    /// No tunnel — dial `host:port` directly (`Server` / `RDPPort`).
    Direct {
        /// Real RDP server hostname or IP.
        host: String,
        /// Real RDP TCP port.
        port: u16,
    },
    /// Tunnel present — dial loopback forwarder; keep original host/port for logging.
    LocalForwarder {
        /// Always `127.0.0.1` (C# `IPAddress.Loopback`).
        connect_host: String,
        /// Local listen port from `BindLocalForwarder`.
        local_port: u16,
        /// Logical remote host (unchanged for display / sentinel).
        original_host: String,
        /// Logical remote port (unchanged for display / sentinel).
        original_port: u16,
    },
}

impl RdpConnectTarget {
    /// True when dialing the real host (no tunnel forwarder).
    pub fn is_direct(&self) -> bool {
        matches!(self, Self::Direct { .. })
    }

    /// True when dialing the loopback forwarder.
    pub fn is_local_forwarder(&self) -> bool {
        matches!(self, Self::LocalForwarder { .. })
    }

    /// Host the OCX should dial (real host or `127.0.0.1`).
    pub fn connect_host(&self) -> &str {
        match self {
            Self::Direct { host, .. } => host,
            Self::LocalForwarder { connect_host, .. } => connect_host,
        }
    }

    /// Port the OCX should dial (remote or forwarder local port).
    pub fn connect_port(&self) -> u16 {
        match self {
            Self::Direct { port, .. } => *port,
            Self::LocalForwarder { local_port, .. } => *local_port,
        }
    }

    /// Logical remote host (unchanged when routed via forwarder).
    pub fn original_host(&self) -> &str {
        match self {
            Self::Direct { host, .. } => host,
            Self::LocalForwarder { original_host, .. } => original_host,
        }
    }

    /// Logical remote port (unchanged when routed via forwarder).
    pub fn original_port(&self) -> u16 {
        match self {
            Self::Direct { port, .. } => *port,
            Self::LocalForwarder { original_port, .. } => *original_port,
        }
    }
}

/// Errors from RDP dial-target selection / prepare (no COM).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RdpConnectTargetError {
    /// Tunnel + RDP combo rejected (external / gateway / strict).
    Policy(TunnelRdpConflict),
    /// HTTP/SSH SOCKS dial path is not valid for ActiveX RDP.
    SocksNotSupported,
    /// Empty / whitespace / NUL host rejected before dial or forwarder bind.
    InvalidHost,
    /// Remote RDP port must be non-zero.
    InvalidPort(u16),
    /// Loopback forwarder listen port must be non-zero.
    InvalidForwarderPort(u16),
    /// Tunnel `BindLocalForwarder` failed (no live socket in the stub path).
    ForwarderBindFailed(String),
}

impl RdpConnectTargetError {
    /// User-facing / diagnostic message (never includes secrets).
    pub fn message(&self) -> String {
        match self {
            Self::Policy(c) => c.message().to_string(),
            Self::SocksNotSupported => {
                "RDP cannot use a SOCKS5 dial path; the ActiveX control must connect via BindLocalForwarder to 127.0.0.1 (same as VNC). Prefer the local forwarder route, or disable the tunnel.".into()
            }
            Self::InvalidHost => "RDP host is required".into(),
            Self::InvalidPort(p) => format!("invalid RDP port {p}"),
            Self::InvalidForwarderPort(p) => format!("invalid local forwarder port {p}"),
            Self::ForwarderBindFailed(msg) => {
                format!("RDP local forwarder bind failed: {msg}")
            }
        }
    }
}

impl fmt::Display for RdpConnectTargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for RdpConnectTargetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Policy(c) => Some(c),
            _ => None,
        }
    }
}

impl From<TunnelRdpConflict> for RdpConnectTargetError {
    fn from(value: TunnelRdpConflict) -> Self {
        Self::Policy(value)
    }
}

/// Result alias for RDP dial-target helpers.
pub type RdpConnectTargetResult<T> = Result<T, RdpConnectTargetError>;

/// Minimal view of a tunnel instance for RDP routing (tests use [`FakeTunnelForwarder`]).
///
/// Production call sites will adapt `wormhole_tunnels::TunnelInstance::bind_local_forwarder`
/// without pulling that crate into unit tests here. SOCKS is intentionally absent —
/// RDP never consumes `Socks5Endpoint` for the OCX dial.
pub trait TunnelLocalForwarderSource {
    /// Bind `127.0.0.1:0` → tunnel dial of `host:port`; return the local listen port.
    fn bind_local_forwarder(&self, host: &str, port: u16) -> RdpConnectTargetResult<u16>;
}

/// Recorded [`TunnelLocalForwarderSource::bind_local_forwarder`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeForwarderBind {
    /// Host passed to bind (real target, never loopback rewrite).
    pub host: String,
    /// Port passed to bind (real target port).
    pub port: u16,
}

/// In-memory tunnel forwarder stub — no network, no SOCKS.
#[derive(Debug, Default)]
pub struct FakeTunnelForwarder {
    /// Port returned from a successful bind (`0` → [`RdpConnectTargetError::InvalidForwarderPort`]).
    pub local_port: u16,
    /// When set, every bind fails with this message (never opens a socket).
    pub fail_message: Option<&'static str>,
    binds: RefCell<Vec<FakeForwarderBind>>,
}

impl FakeTunnelForwarder {
    /// Successful bind stub returning `local_port`.
    pub fn with_local_port(local_port: u16) -> Self {
        Self {
            local_port,
            fail_message: None,
            binds: RefCell::new(Vec::new()),
        }
    }

    /// Every bind fails with `message` after recording the call.
    pub fn failing(message: &'static str) -> Self {
        Self {
            local_port: 0,
            fail_message: Some(message),
            binds: RefCell::new(Vec::new()),
        }
    }

    /// Recorded bind arguments (real host/port, never loopback).
    pub fn binds(&self) -> Vec<FakeForwarderBind> {
        self.binds.borrow().clone()
    }

    /// Number of bind attempts.
    pub fn bind_count(&self) -> usize {
        self.binds.borrow().len()
    }
}

impl TunnelLocalForwarderSource for FakeTunnelForwarder {
    fn bind_local_forwarder(&self, host: &str, port: u16) -> RdpConnectTargetResult<u16> {
        self.binds.borrow_mut().push(FakeForwarderBind {
            host: host.to_string(),
            port,
        });
        if let Some(msg) = self.fail_message {
            return Err(RdpConnectTargetError::ForwarderBindFailed(msg.into()));
        }
        if self.local_port == 0 {
            return Err(RdpConnectTargetError::InvalidForwarderPort(0));
        }
        Ok(self.local_port)
    }
}

fn normalize_host(host: &str) -> RdpConnectTargetResult<String> {
    let host = host.trim();
    if host.is_empty() {
        return Err(RdpConnectTargetError::InvalidHost);
    }
    if host.contains('\0') {
        return Err(RdpConnectTargetError::InvalidHost);
    }
    Ok(host.to_string())
}

fn validate_port(port: u16) -> RdpConnectTargetResult<u16> {
    if port == 0 {
        return Err(RdpConnectTargetError::InvalidPort(0));
    }
    Ok(port)
}

/// Fail closed for the mistaken HTTP-style SOCKS dial path (ActiveX cannot speak SOCKS5).
///
/// Call when a hybrid router would prefer SOCKS — RDP must use
/// [`select_rdp_connect_target`] / `BindLocalForwarder` instead.
pub fn reject_rdp_socks_only_path() -> RdpConnectTargetError {
    RdpConnectTargetError::SocksNotSupported
}

/// Pick Direct vs loopback forwarder from an optional tunnel instance.
///
/// | `tunnel` | Result |
/// |---|---|
/// | `None` | [`RdpConnectTarget::Direct`] |
/// | `Some` | Bind forwarder to `host:port`, dial `127.0.0.1:local` |
///
/// Unlike HTTP, RDP does **not** prefer SOCKS when available — always
/// `BindLocalForwarder` when a tunnel lease is present (VNC parity).
///
/// Does **not** run gateway / external / strict policy — use
/// [`prepare_rdp_connect_target`] when those guards must apply before dial.
pub fn select_rdp_connect_target(
    host: &str,
    port: u16,
    tunnel: Option<&dyn TunnelLocalForwarderSource>,
) -> RdpConnectTargetResult<RdpConnectTarget> {
    let host = normalize_host(host)?;
    let port = validate_port(port)?;
    match tunnel {
        None => Ok(RdpConnectTarget::Direct { host, port }),
        Some(t) => {
            let local_port = t.bind_local_forwarder(&host, port)?;
            if local_port == 0 {
                return Err(RdpConnectTargetError::InvalidForwarderPort(0));
            }
            Ok(RdpConnectTarget::LocalForwarder {
                connect_host: LOOPBACK_HOST.to_string(),
                local_port,
                original_host: host,
                original_port: port,
            })
        }
    }
}

/// Policy rejects → optional SOCKS reject → Direct / LocalForwarder (before dial).
///
/// Parity with C# `RdpSessionViewModel.ConnectAsync`: external / gateway / strict
/// guards run before `PrepareConnectProfileAsync` / `BindLocalForwarderAsync`.
/// When `http_socks_preferred` is true, fails with [`RdpConnectTargetError::SocksNotSupported`]
/// without binding (mistaken HTTP hybrid arm).
pub fn prepare_rdp_connect_target(
    host: &str,
    port: u16,
    policy: TunnelRdpPolicy,
    tunnel: Option<&dyn TunnelLocalForwarderSource>,
    http_socks_preferred: bool,
) -> RdpConnectTargetResult<RdpConnectTarget> {
    // C# order: external → gateway → strict before any forwarder bind / Connect.
    validate_tunnel_rdp_policy(policy)?;
    if http_socks_preferred {
        return Err(reject_rdp_socks_only_path());
    }
    select_rdp_connect_target(host, port, tunnel)
}

/// Convenience: `127.0.0.1:local_port` socket addr for a forwarder target.
pub fn forwarder_socket_addr(local_port: u16) -> RdpConnectTargetResult<SocketAddr> {
    if local_port == 0 {
        return Err(RdpConnectTargetError::InvalidForwarderPort(0));
    }
    Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, local_port)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use crate::rdp::configure::{
        TunnelRdpConflict, TunnelRdpPolicy, TUNNEL_EXTERNAL_CLIENT_UNSUPPORTED,
        TUNNEL_GATEWAY_UNSUPPORTED, TUNNEL_STRICT_SERVER_AUTH_UNSUPPORTED,
    };

    fn allow_policy() -> TunnelRdpPolicy {
        TunnelRdpPolicy {
            tunnel_enabled: true,
            use_external_client: false,
            gateway_usage_method: 0,
            server_authentication: 2, // Warn
        }
    }

    fn tunnel_off_policy() -> TunnelRdpPolicy {
        TunnelRdpPolicy {
            tunnel_enabled: false,
            use_external_client: false,
            gateway_usage_method: 0,
            server_authentication: 0,
        }
    }

    #[test]
    fn loopback_host_matches_ipv4_localhost() {
        assert_eq!(LOOPBACK_HOST, "127.0.0.1");
        assert_eq!(LOOPBACK_HOST, Ipv4Addr::LOCALHOST.to_string());
        assert_eq!(
            forwarder_socket_addr(3389).unwrap(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 3389))
        );
    }

    #[test]
    fn no_tunnel_selects_direct() {
        let t = select_rdp_connect_target("dc.local", 3389, None).unwrap();
        assert!(t.is_direct());
        assert!(!t.is_local_forwarder());
        assert_eq!(t.connect_host(), "dc.local");
        assert_eq!(t.connect_port(), 3389);
        assert_eq!(t.original_host(), "dc.local");
        assert_eq!(t.original_port(), 3389);
        assert_eq!(
            t,
            RdpConnectTarget::Direct {
                host: "dc.local".into(),
                port: 3389,
            }
        );
    }

    #[test]
    fn fake_forwarder_selects_loopback() {
        let fake = FakeTunnelForwarder::with_local_port(51_515);
        let t = select_rdp_connect_target("dc.local", 3389, Some(&fake)).unwrap();
        assert!(t.is_local_forwarder());
        assert_eq!(t.connect_host(), LOOPBACK_HOST);
        assert_eq!(t.connect_port(), 51_515);
        assert_eq!(t.original_host(), "dc.local");
        assert_eq!(t.original_port(), 3389);
        assert_eq!(
            forwarder_socket_addr(t.connect_port()).unwrap(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 51_515))
        );
        assert_eq!(fake.bind_count(), 1);
        assert_eq!(
            fake.binds(),
            vec![FakeForwarderBind {
                host: "dc.local".into(),
                port: 3389,
            }]
        );
    }

    #[test]
    fn tunnel_present_is_local_forwarder_never_socks_variant() {
        // Trait omits SOCKS (unlike HttpTunnelRouteSource); exhaustiveness pins no Socks arm.
        let fake = FakeTunnelForwarder::with_local_port(40_040);
        let t = select_rdp_connect_target("rdp.internal", 3389, Some(&fake)).unwrap();
        assert_eq!(t.connect_host(), LOOPBACK_HOST);
        assert_eq!(t.connect_port(), 40_040);
        assert_eq!(t.original_host(), "rdp.internal");
        assert_eq!(t.original_port(), 3389);
        assert_eq!(fake.bind_count(), 1);
        match &t {
            RdpConnectTarget::LocalForwarder { connect_host, .. } => {
                assert_eq!(connect_host, LOOPBACK_HOST);
            }
            RdpConnectTarget::Direct { .. } => panic!("tunnel present → LocalForwarder only"),
        }
    }

    #[test]
    fn fake_bind_receives_real_host_not_loopback() {
        // C#: BindLocalForwarderAsync(profile.Host, profile.Port) then rewrite connect host.
        let fake = FakeTunnelForwarder::with_local_port(40_000);
        let _ = select_rdp_connect_target("10.0.0.9", 3390, Some(&fake)).unwrap();
        let bind = &fake.binds()[0];
        assert_eq!(bind.host, "10.0.0.9");
        assert_eq!(bind.port, 3390);
        assert_ne!(bind.host, "127.0.0.1");
    }

    #[test]
    fn fake_forwarder_failure_propagates() {
        let fake = FakeTunnelForwarder::failing("tunnel closed");
        let err = select_rdp_connect_target("dc.local", 3389, Some(&fake)).unwrap_err();
        // Err (not Direct / LocalForwarder) — no silent fallback when tunnel bind fails.
        assert!(matches!(
            &err,
            RdpConnectTargetError::ForwarderBindFailed(m) if m == "tunnel closed"
        ));
        assert_eq!(fake.bind_count(), 1);
    }

    #[test]
    fn forwarder_bind_failed_display_is_non_secret() {
        let fake = FakeTunnelForwarder::failing("tunnel closed");
        let err = select_rdp_connect_target("dc.local", 3389, Some(&fake)).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("tunnel closed"));
        assert!(!msg.to_lowercase().contains("password"));
        assert!(!msg.contains("credential"));
    }

    #[test]
    fn zero_forwarder_port_rejected() {
        let fake = FakeTunnelForwarder::with_local_port(0);
        let err = select_rdp_connect_target("dc.local", 3389, Some(&fake)).unwrap_err();
        assert!(matches!(err, RdpConnectTargetError::InvalidForwarderPort(0)));
        assert!(matches!(
            forwarder_socket_addr(0),
            Err(RdpConnectTargetError::InvalidForwarderPort(0))
        ));
    }

    /// Hostile impl returns `Ok(0)` — select must fail closed (defense in depth).
    struct OkZeroPortForwarder {
        binds: RefCell<Vec<FakeForwarderBind>>,
    }

    impl TunnelLocalForwarderSource for OkZeroPortForwarder {
        fn bind_local_forwarder(&self, host: &str, port: u16) -> RdpConnectTargetResult<u16> {
            self.binds.borrow_mut().push(FakeForwarderBind {
                host: host.to_string(),
                port,
            });
            Ok(0)
        }
    }

    #[test]
    fn hostile_ok_zero_forwarder_port_fail_closed() {
        let hostile = OkZeroPortForwarder {
            binds: RefCell::new(Vec::new()),
        };
        let err = select_rdp_connect_target("dc.local", 3389, Some(&hostile)).unwrap_err();
        assert!(matches!(err, RdpConnectTargetError::InvalidForwarderPort(0)));
        assert_eq!(hostile.binds.borrow().len(), 1);
    }

    #[test]
    fn rejects_empty_host_and_zero_port_without_bind() {
        let fake = FakeTunnelForwarder::with_local_port(51_515);
        assert!(matches!(
            select_rdp_connect_target("", 3389, Some(&fake)),
            Err(RdpConnectTargetError::InvalidHost)
        ));
        assert!(matches!(
            select_rdp_connect_target("   ", 3389, Some(&fake)),
            Err(RdpConnectTargetError::InvalidHost)
        ));
        assert!(matches!(
            select_rdp_connect_target("dc.local", 0, Some(&fake)),
            Err(RdpConnectTargetError::InvalidPort(0))
        ));
        assert_eq!(fake.bind_count(), 0, "validation must precede bind");
    }

    #[test]
    fn direct_rejects_empty_host_and_zero_port_without_tunnel() {
        assert!(matches!(
            select_rdp_connect_target("", 3389, None),
            Err(RdpConnectTargetError::InvalidHost)
        ));
        assert!(matches!(
            select_rdp_connect_target("\t\n  ", 3389, None),
            Err(RdpConnectTargetError::InvalidHost)
        ));
        assert!(matches!(
            select_rdp_connect_target("dc.local", 0, None),
            Err(RdpConnectTargetError::InvalidPort(0))
        ));
    }

    #[test]
    fn trims_host_whitespace() {
        let t = select_rdp_connect_target("  dc.local  ", 3389, None).unwrap();
        assert_eq!(t.connect_host(), "dc.local");
    }

    #[test]
    fn tunnel_path_binds_trimmed_host() {
        let fake = FakeTunnelForwarder::with_local_port(33_333);
        let t = select_rdp_connect_target("  10.1.2.3  ", 3390, Some(&fake)).unwrap();
        assert_eq!(
            fake.binds(),
            vec![FakeForwarderBind {
                host: "10.1.2.3".into(),
                port: 3390,
            }]
        );
        assert_eq!(t.original_host(), "10.1.2.3");
        assert_eq!(t.connect_host(), LOOPBACK_HOST);
    }

    #[test]
    fn ipv6_and_bracketed_host_preserved_on_forwarder_path() {
        let fake = FakeTunnelForwarder::with_local_port(44_444);
        let t = select_rdp_connect_target("2001:db8::9", 3389, Some(&fake)).unwrap();
        assert_eq!(fake.binds()[0].host, "2001:db8::9");
        assert_eq!(t.original_host(), "2001:db8::9");
        assert_eq!(t.connect_host(), LOOPBACK_HOST);

        let fake2 = FakeTunnelForwarder::with_local_port(44_445);
        let t2 = select_rdp_connect_target("[2001:db8::9]", 3391, Some(&fake2)).unwrap();
        assert_eq!(fake2.binds()[0].host, "[2001:db8::9]");
        assert_eq!(t2.original_host(), "[2001:db8::9]");
        assert_eq!(t2.connect_port(), 44_445);
    }

    #[test]
    fn rejects_nul_in_host() {
        assert!(matches!(
            select_rdp_connect_target("dc\0.local", 3389, None),
            Err(RdpConnectTargetError::InvalidHost)
        ));
    }

    #[test]
    fn reject_socks_only_mistaken_path() {
        let err = reject_rdp_socks_only_path();
        assert_eq!(err, RdpConnectTargetError::SocksNotSupported);
        assert!(err.message().contains("SOCKS5"));
        assert!(err.message().contains("BindLocalForwarder"));
        assert!(!err.message().to_lowercase().contains("password"));
    }

    #[test]
    fn prepare_rejects_socks_preferred_without_bind() {
        let fake = FakeTunnelForwarder::with_local_port(51_515);
        let err = prepare_rdp_connect_target(
            "dc.local",
            3389,
            allow_policy(),
            Some(&fake),
            true, // mistaken HTTP SOCKS arm
        )
        .unwrap_err();
        assert_eq!(err, RdpConnectTargetError::SocksNotSupported);
        assert_eq!(fake.bind_count(), 0, "SOCKS reject must precede bind");
    }

    #[test]
    fn prepare_policy_external_before_bind() {
        let fake = FakeTunnelForwarder::with_local_port(51_515);
        let err = prepare_rdp_connect_target(
            "dc.local",
            3389,
            TunnelRdpPolicy {
                tunnel_enabled: true,
                use_external_client: true,
                gateway_usage_method: 0,
                server_authentication: 2,
            },
            Some(&fake),
            false,
        )
        .unwrap_err();
        assert_eq!(
            err,
            RdpConnectTargetError::Policy(TunnelRdpConflict::ExternalClient)
        );
        assert_eq!(err.message(), TUNNEL_EXTERNAL_CLIENT_UNSUPPORTED);
        assert_eq!(fake.bind_count(), 0, "policy must precede bind");
    }

    #[test]
    fn prepare_policy_gateway_before_bind() {
        // C# RdpGatewayUsageMethod: 1=Always, 2=Detect, 3=DefaultRdg + extremes — any nonzero.
        const NONZERO_GATEWAY: &[i32] = &[1, 2, 3, -1, i32::MAX, i32::MIN];
        for &method in NONZERO_GATEWAY {
            let fake = FakeTunnelForwarder::with_local_port(51_515);
            let err = prepare_rdp_connect_target(
                "dc.local",
                3389,
                TunnelRdpPolicy {
                    tunnel_enabled: true,
                    use_external_client: false,
                    gateway_usage_method: method,
                    server_authentication: 2,
                },
                Some(&fake),
                false,
            )
            .unwrap_err();
            assert_eq!(
                err,
                RdpConnectTargetError::Policy(TunnelRdpConflict::Gateway),
                "gateway method {method}"
            );
            assert_eq!(err.message(), TUNNEL_GATEWAY_UNSUPPORTED);
            assert_eq!(fake.bind_count(), 0, "policy must precede bind for method {method}");
        }
    }

    #[test]
    fn prepare_policy_strict_before_bind() {
        let fake = FakeTunnelForwarder::with_local_port(51_515);
        let err = prepare_rdp_connect_target(
            "dc.local",
            3389,
            TunnelRdpPolicy {
                tunnel_enabled: true,
                use_external_client: false,
                gateway_usage_method: 0,
                server_authentication: 1, // Require
            },
            Some(&fake),
            false,
        )
        .unwrap_err();
        assert_eq!(
            err,
            RdpConnectTargetError::Policy(TunnelRdpConflict::StrictServerAuth)
        );
        assert_eq!(err.message(), TUNNEL_STRICT_SERVER_AUTH_UNSUPPORTED);
        assert_eq!(fake.bind_count(), 0);
    }

    #[test]
    fn prepare_policy_before_socks_reject() {
        // When both policy and SOCKS apply, policy wins (C# guards first).
        let fake = FakeTunnelForwarder::with_local_port(51_515);
        let err = prepare_rdp_connect_target(
            "dc.local",
            3389,
            TunnelRdpPolicy {
                tunnel_enabled: true,
                use_external_client: false,
                gateway_usage_method: 2,
                server_authentication: 1,
            },
            Some(&fake),
            true,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            RdpConnectTargetError::Policy(TunnelRdpConflict::Gateway)
        ));
        assert_eq!(fake.bind_count(), 0);
    }

    #[test]
    fn prepare_external_before_socks_reject() {
        // External still wins over SOCKS reject (and over Gateway/Strict).
        let fake = FakeTunnelForwarder::with_local_port(51_515);
        let err = prepare_rdp_connect_target(
            "dc.local",
            3389,
            TunnelRdpPolicy {
                tunnel_enabled: true,
                use_external_client: true,
                gateway_usage_method: 3,
                server_authentication: 1,
            },
            Some(&fake),
            true,
        )
        .unwrap_err();
        assert_eq!(
            err,
            RdpConnectTargetError::Policy(TunnelRdpConflict::ExternalClient)
        );
        assert_eq!(fake.bind_count(), 0);
    }

    #[test]
    fn prepare_allows_forwarder_when_policy_ok() {
        let fake = FakeTunnelForwarder::with_local_port(44_444);
        let t = prepare_rdp_connect_target(
            "dc.local",
            3389,
            allow_policy(),
            Some(&fake),
            false,
        )
        .unwrap();
        assert!(t.is_local_forwarder());
        assert_eq!(t.connect_host(), LOOPBACK_HOST);
        assert_eq!(t.connect_port(), 44_444);
        assert_eq!(fake.bind_count(), 1);
        match &t {
            RdpConnectTarget::LocalForwarder { .. } => {}
            RdpConnectTarget::Direct { .. } => panic!("tunnel+policy ok → LocalForwarder only"),
        }
    }

    #[test]
    fn prepare_direct_when_tunnel_off() {
        let t = prepare_rdp_connect_target(
            "dc.local",
            3389,
            tunnel_off_policy(),
            None,
            false,
        )
        .unwrap();
        assert!(t.is_direct());
        assert_eq!(t.connect_host(), "dc.local");
        assert_eq!(t.connect_port(), 3389);
    }

    #[test]
    fn prepare_socks_reject_source_is_none() {
        let err = reject_rdp_socks_only_path();
        assert!(err.source().is_none());
        let policy_err = RdpConnectTargetError::from(TunnelRdpConflict::Gateway);
        assert!(policy_err.source().is_some());
    }

    #[test]
    fn debug_omits_credential_shaped_fields() {
        let t = select_rdp_connect_target("dc.local", 3389, None).unwrap();
        let dbg = format!("{t:?}");
        assert!(!dbg.to_lowercase().contains("password"));
        assert!(!dbg.contains("credential"));
        let fake = FakeTunnelForwarder::with_local_port(12_345);
        let fwd = select_rdp_connect_target("dc.local", 3389, Some(&fake)).unwrap();
        let dbg = format!("{fwd:?}");
        assert!(!dbg.to_lowercase().contains("password"));
        assert!(!dbg.contains("socks"));
    }
}
