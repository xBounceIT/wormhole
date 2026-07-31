//! VNC dial target selection: Direct vs loopback `BindLocalForwarder`.
//!
//! Mirrors C# `VncSessionService.ConnectAsync` tunnel routing — same rule as RDP:
//! VNC cannot speak SOCKS5, so a present tunnel always binds a `127.0.0.1` forwarder
//! to the real host/port and the RFB client dials loopback.
//!
//! Live bind + RFB connect remain deferred; this module only picks the route
//! (unit-tested with [`FakeTunnelForwarder`], no network).

use std::cell::RefCell;
use std::net::{Ipv4Addr, SocketAddr};

use crate::error::VncError;
use crate::Result;

/// C# `IPAddress.Loopback.ToString()` — VNC always dials this after a forwarder bind.
const LOOPBACK_HOST: &str = "127.0.0.1";

/// How the VNC / RFB client should obtain its TCP endpoint.
///
/// Unlike HTTP (SOCKS preferred) or SFTP (SOCKS required), VNC **never** uses
/// SOCKS — parity with C# `BindLocalForwarderAsync` for RDP/VNC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VncConnectTarget {
    /// No tunnel — dial `host:port` directly.
    Direct { host: String, port: u16 },
    /// Tunnel present — dial loopback forwarder; keep original host/port for logging.
    LocalForwarder {
        /// Always `127.0.0.1` (C# `IPAddress.Loopback`).
        connect_host: String,
        local_port: u16,
        original_host: String,
        original_port: u16,
    },
}

impl VncConnectTarget {
    pub fn is_direct(&self) -> bool {
        matches!(self, Self::Direct { .. })
    }

    pub fn is_local_forwarder(&self) -> bool {
        matches!(self, Self::LocalForwarder { .. })
    }

    /// Host the RFB client should dial (real host or `127.0.0.1`).
    pub fn connect_host(&self) -> &str {
        match self {
            Self::Direct { host, .. } => host,
            Self::LocalForwarder { connect_host, .. } => connect_host,
        }
    }

    /// Port the RFB client should dial (remote or forwarder local port).
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

/// Minimal view of a tunnel instance for VNC routing (tests use [`FakeTunnelForwarder`]).
///
/// Production call sites will adapt `wormhole_tunnels::TunnelInstance::bind_local_forwarder`
/// without pulling that crate into unit tests here. SOCKS is intentionally absent —
/// VNC never consumes `Socks5Endpoint`.
pub trait TunnelLocalForwarderSource {
    /// Bind `127.0.0.1:0` → tunnel dial of `host:port`; return the local listen port.
    fn bind_local_forwarder(&self, host: &str, port: u16) -> Result<u16>;
}

/// Recorded [`TunnelLocalForwarderSource::bind_local_forwarder`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeForwarderBind {
    pub host: String,
    pub port: u16,
}

/// In-memory tunnel forwarder stub — no network, no SOCKS.
#[derive(Debug, Default)]
pub struct FakeTunnelForwarder {
    /// Port returned from a successful bind (`0` → [`VncError::InvalidForwarderPort`]).
    pub local_port: u16,
    /// When set, every bind fails with this message (never opens a socket).
    pub fail_message: Option<&'static str>,
    binds: RefCell<Vec<FakeForwarderBind>>,
}

impl FakeTunnelForwarder {
    pub fn with_local_port(local_port: u16) -> Self {
        Self {
            local_port,
            fail_message: None,
            binds: RefCell::new(Vec::new()),
        }
    }

    pub fn failing(message: &'static str) -> Self {
        Self {
            local_port: 0,
            fail_message: Some(message),
            binds: RefCell::new(Vec::new()),
        }
    }

    pub fn binds(&self) -> Vec<FakeForwarderBind> {
        self.binds.borrow().clone()
    }

    pub fn bind_count(&self) -> usize {
        self.binds.borrow().len()
    }
}

impl TunnelLocalForwarderSource for FakeTunnelForwarder {
    fn bind_local_forwarder(&self, host: &str, port: u16) -> Result<u16> {
        self.binds.borrow_mut().push(FakeForwarderBind {
            host: host.to_string(),
            port,
        });
        if let Some(msg) = self.fail_message {
            return Err(VncError::ForwarderBindFailed(msg.into()));
        }
        if self.local_port == 0 {
            return Err(VncError::InvalidForwarderPort(0));
        }
        Ok(self.local_port)
    }
}

fn normalize_host(host: &str) -> Result<String> {
    let host = host.trim();
    if host.is_empty() {
        return Err(VncError::InvalidHost);
    }
    if host.contains('\0') {
        return Err(VncError::InvalidHost);
    }
    Ok(host.to_string())
}

fn validate_port(port: u16) -> Result<u16> {
    if port == 0 {
        return Err(VncError::InvalidPort(0));
    }
    Ok(port)
}

/// Pick Direct vs loopback forwarder from an optional tunnel instance.
///
/// | `tunnel` | Result |
/// |---|---|
/// | `None` | [`VncConnectTarget::Direct`] |
/// | `Some` | Bind forwarder to `host:port`, dial `127.0.0.1:local` |
///
/// Unlike HTTP, VNC does **not** prefer SOCKS when available — always
/// `BindLocalForwarder` when a tunnel lease is present (RDP parity).
pub fn select_vnc_connect_target(
    host: &str,
    port: u16,
    tunnel: Option<&dyn TunnelLocalForwarderSource>,
) -> Result<VncConnectTarget> {
    let host = normalize_host(host)?;
    let port = validate_port(port)?;
    match tunnel {
        None => Ok(VncConnectTarget::Direct { host, port }),
        Some(t) => {
            let local_port = t.bind_local_forwarder(&host, port)?;
            if local_port == 0 {
                return Err(VncError::InvalidForwarderPort(0));
            }
            Ok(VncConnectTarget::LocalForwarder {
                connect_host: LOOPBACK_HOST.to_string(),
                local_port,
                original_host: host,
                original_port: port,
            })
        }
    }
}

/// Convenience: `127.0.0.1:local_port` socket addr for a forwarder target.
pub fn forwarder_socket_addr(local_port: u16) -> Result<SocketAddr> {
    if local_port == 0 {
        return Err(VncError::InvalidForwarderPort(0));
    }
    Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, local_port)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_host_matches_ipv4_localhost() {
        assert_eq!(LOOPBACK_HOST, "127.0.0.1");
        assert_eq!(LOOPBACK_HOST, Ipv4Addr::LOCALHOST.to_string());
        assert_eq!(
            forwarder_socket_addr(5900).unwrap(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 5900))
        );
    }

    #[test]
    fn no_tunnel_selects_direct() {
        let t = select_vnc_connect_target("vnc.local", 5900, None).unwrap();
        assert!(t.is_direct());
        assert!(!t.is_local_forwarder());
        assert_eq!(t.connect_host(), "vnc.local");
        assert_eq!(t.connect_port(), 5900);
        assert_eq!(t.original_host(), "vnc.local");
        assert_eq!(t.original_port(), 5900);
        assert_eq!(
            t,
            VncConnectTarget::Direct {
                host: "vnc.local".into(),
                port: 5900,
            }
        );
    }

    #[test]
    fn fake_forwarder_selects_loopback() {
        let fake = FakeTunnelForwarder::with_local_port(51_515);
        let t = select_vnc_connect_target("vnc.local", 5900, Some(&fake)).unwrap();
        assert!(t.is_local_forwarder());
        assert_eq!(t.connect_host(), LOOPBACK_HOST);
        assert_eq!(t.connect_port(), 51_515);
        assert_eq!(t.original_host(), "vnc.local");
        assert_eq!(t.original_port(), 5900);
        assert_eq!(
            forwarder_socket_addr(t.connect_port()).unwrap(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 51_515))
        );
        assert_eq!(fake.bind_count(), 1);
        assert_eq!(
            fake.binds(),
            vec![FakeForwarderBind {
                host: "vnc.local".into(),
                port: 5900,
            }]
        );
    }

    #[test]
    fn fake_bind_receives_real_host_not_loopback() {
        // C#: BindLocalForwarderAsync(profile.Host, profile.Port) then rewrite connect host.
        let fake = FakeTunnelForwarder::with_local_port(40_000);
        let _ = select_vnc_connect_target("10.0.0.9", 5901, Some(&fake)).unwrap();
        let bind = &fake.binds()[0];
        assert_eq!(bind.host, "10.0.0.9");
        assert_eq!(bind.port, 5901);
        assert_ne!(bind.host, "127.0.0.1");
    }

    #[test]
    fn fake_forwarder_failure_propagates() {
        let fake = FakeTunnelForwarder::failing("tunnel closed");
        let err = select_vnc_connect_target("vnc.local", 5900, Some(&fake)).unwrap_err();
        // Err (not Direct / LocalForwarder) — no silent fallback when tunnel bind fails.
        assert!(matches!(
            &err,
            VncError::ForwarderBindFailed(m) if m == "tunnel closed"
        ));
        assert_eq!(fake.bind_count(), 1);
    }

    #[test]
    fn zero_forwarder_port_rejected() {
        let fake = FakeTunnelForwarder::with_local_port(0);
        let err = select_vnc_connect_target("vnc.local", 5900, Some(&fake)).unwrap_err();
        assert!(matches!(err, VncError::InvalidForwarderPort(0)));
        assert!(matches!(
            forwarder_socket_addr(0),
            Err(VncError::InvalidForwarderPort(0))
        ));
    }

    #[test]
    fn rejects_empty_host_and_zero_port_without_bind() {
        let fake = FakeTunnelForwarder::with_local_port(51_515);
        assert!(matches!(
            select_vnc_connect_target("", 5900, Some(&fake)),
            Err(VncError::InvalidHost)
        ));
        assert!(matches!(
            select_vnc_connect_target("   ", 5900, Some(&fake)),
            Err(VncError::InvalidHost)
        ));
        assert!(matches!(
            select_vnc_connect_target("vnc.local", 0, Some(&fake)),
            Err(VncError::InvalidPort(0))
        ));
        assert_eq!(fake.bind_count(), 0, "validation must precede bind");
    }

    #[test]
    fn trims_host_whitespace() {
        let t = select_vnc_connect_target("  vnc.local  ", 5900, None).unwrap();
        assert_eq!(t.connect_host(), "vnc.local");
    }

    #[test]
    fn rejects_nul_in_host() {
        assert!(matches!(
            select_vnc_connect_target("vnc\0.local", 5900, None),
            Err(VncError::InvalidHost)
        ));
    }

    #[test]
    fn debug_omits_credential_shaped_fields() {
        // Targets are host/port only — no password / credential id on the type.
        let t = select_vnc_connect_target("vnc.local", 5900, None).unwrap();
        let dbg = format!("{t:?}");
        assert!(!dbg.to_lowercase().contains("password"));
        assert!(!dbg.contains("credential"));
        let fake = FakeTunnelForwarder::with_local_port(12_345);
        let fwd = select_vnc_connect_target("vnc.local", 5900, Some(&fake)).unwrap();
        let dbg = format!("{fwd:?}");
        assert!(!dbg.to_lowercase().contains("password"));
        assert!(!dbg.contains("socks"));
    }

    #[test]
    fn tunnel_present_is_local_forwarder_never_socks_variant() {
        // Trait omits SOCKS (unlike HttpTunnelRouteSource); exhaustiveness pins no Socks arm.
        let fake = FakeTunnelForwarder::with_local_port(40_040);
        let t = select_vnc_connect_target("vnc.internal", 5900, Some(&fake)).unwrap();
        assert_eq!(t.connect_host(), LOOPBACK_HOST);
        assert_eq!(t.connect_port(), 40_040);
        assert_eq!(t.original_host(), "vnc.internal");
        assert_eq!(t.original_port(), 5900);
        assert_eq!(fake.bind_count(), 1);
        match &t {
            VncConnectTarget::LocalForwarder { connect_host, .. } => {
                assert_eq!(connect_host, LOOPBACK_HOST);
            }
            VncConnectTarget::Direct { .. } => panic!("tunnel present → LocalForwarder only"),
        }
    }

    #[test]
    fn direct_rejects_empty_host_and_zero_port_without_tunnel() {
        assert!(matches!(
            select_vnc_connect_target("", 5900, None),
            Err(VncError::InvalidHost)
        ));
        assert!(matches!(
            select_vnc_connect_target("\t\n  ", 5900, None),
            Err(VncError::InvalidHost)
        ));
        assert!(matches!(
            select_vnc_connect_target("vnc.local", 0, None),
            Err(VncError::InvalidPort(0))
        ));
    }

    /// Hostile impl returns `Ok(0)` — select must fail closed (defense in depth).
    struct OkZeroPortForwarder {
        binds: RefCell<Vec<FakeForwarderBind>>,
    }

    impl TunnelLocalForwarderSource for OkZeroPortForwarder {
        fn bind_local_forwarder(&self, host: &str, port: u16) -> Result<u16> {
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
        let err = select_vnc_connect_target("vnc.local", 5900, Some(&hostile)).unwrap_err();
        assert!(matches!(err, VncError::InvalidForwarderPort(0)));
        assert_eq!(hostile.binds.borrow().len(), 1);
    }

    #[test]
    fn tunnel_path_binds_trimmed_host() {
        let fake = FakeTunnelForwarder::with_local_port(33_333);
        let t = select_vnc_connect_target("  10.1.2.3  ", 5902, Some(&fake)).unwrap();
        assert_eq!(
            fake.binds(),
            vec![FakeForwarderBind {
                host: "10.1.2.3".into(),
                port: 5902,
            }]
        );
        assert_eq!(t.original_host(), "10.1.2.3");
        assert_eq!(t.connect_host(), LOOPBACK_HOST);
    }

    #[test]
    fn ipv6_and_bracketed_host_preserved_on_forwarder_path() {
        let fake = FakeTunnelForwarder::with_local_port(44_444);
        let t = select_vnc_connect_target("2001:db8::9", 5900, Some(&fake)).unwrap();
        assert_eq!(fake.binds()[0].host, "2001:db8::9");
        assert_eq!(t.original_host(), "2001:db8::9");
        assert_eq!(t.connect_host(), LOOPBACK_HOST);

        let fake2 = FakeTunnelForwarder::with_local_port(44_445);
        let t2 = select_vnc_connect_target("[2001:db8::9]", 5901, Some(&fake2)).unwrap();
        assert_eq!(fake2.binds()[0].host, "[2001:db8::9]");
        assert_eq!(t2.original_host(), "[2001:db8::9]");
        assert_eq!(t2.connect_port(), 44_445);
    }

    #[test]
    fn forwarder_bind_failed_display_is_non_secret() {
        let fake = FakeTunnelForwarder::failing("tunnel closed");
        let err = select_vnc_connect_target("vnc.local", 5900, Some(&fake)).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("tunnel closed"));
        assert!(!msg.to_lowercase().contains("password"));
        assert!(!msg.contains("credential"));
    }
}
