//! RDP / VNC connect stubs — prepare typed requests without OLE / VNC engines.
//!
//! The orchestrator builds these from a resolved [`ConnectionProfile`], then fails
//! closed with [`SessionError::UnsupportedProtocol`] so UI can branch on the
//! prepared request. No COM, no framebuffer, no tunnel establish.

use std::fmt;

use uuid::Uuid;
use wormhole_domain::{ConnectionProfile, ProtocolType};

use crate::error::{Result, SessionError};

/// High-level session protocol kind used for UI / dispatcher branching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionKind {
    Serial,
    Ssh,
    Http,
    Https,
    /// Stub: prepare [`RdpConnectRequest`] only (OLE host not wired).
    Rdp,
    /// Stub: prepare [`VncConnectRequest`] only (VNC engine not wired).
    Vnc,
}

impl SessionKind {
    pub fn from_protocol(protocol: ProtocolType) -> Self {
        match protocol {
            ProtocolType::Serial => Self::Serial,
            ProtocolType::Ssh => Self::Ssh,
            ProtocolType::Http => Self::Http,
            ProtocolType::Https => Self::Https,
            ProtocolType::Rdp => Self::Rdp,
            ProtocolType::Vnc => Self::Vnc,
        }
    }

    /// True for RDP/VNC stubs that prepare a connect request but never connect.
    pub fn is_surface_stub(self) -> bool {
        matches!(self, Self::Rdp | Self::Vnc)
    }
}

impl fmt::Display for SessionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Serial => "Serial",
            Self::Ssh => "Ssh",
            Self::Http => "Http",
            Self::Https => "Https",
            Self::Rdp => "Rdp",
            Self::Vnc => "Vnc",
        })
    }
}

/// Prepared RDP connect inputs (host/port/tunnel) — no ActiveX / COM.
///
/// Intentionally omits passwords / credential ids so [`Debug`] / [`Display`] of
/// [`UnsupportedProtocolReason`] cannot leak secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdpConnectRequest {
    pub host: String,
    pub port: u16,
    pub tunnel_enabled: bool,
    pub tunnel_config_id: Option<Uuid>,
    /// From profile; UI may reject external client + tunnel combos later.
    pub use_external_client: bool,
    pub domain: Option<String>,
}

impl RdpConnectRequest {
    /// Build from a resolved profile. Validates port; does not touch OLE.
    pub fn try_from_profile(profile: &ConnectionProfile) -> Result<Self> {
        if profile.protocol != ProtocolType::Rdp {
            return Err(SessionError::Other(format!(
                "RdpConnectRequest requires ProtocolType::Rdp, got {}",
                profile.protocol
            )));
        }
        let port = validate_port(profile.port)?;
        let host = normalize_host(&profile.host)?;
        Ok(Self {
            host,
            port,
            tunnel_enabled: profile.tunnel_enabled,
            tunnel_config_id: profile.tunnel_config_id,
            use_external_client: profile.rdp_use_external_client,
            domain: profile.rdp_domain.clone(),
        })
    }
}

/// Prepared VNC connect inputs (host/port/tunnel) — no RFB / framebuffer engine.
///
/// Intentionally omits the VNC password so [`Debug`] / [`Display`] stay secret-free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VncConnectRequest {
    pub host: String,
    pub port: u16,
    pub tunnel_enabled: bool,
    pub tunnel_config_id: Option<Uuid>,
}

impl VncConnectRequest {
    /// Build from a resolved profile. Validates port; does not open a VNC session.
    pub fn try_from_profile(profile: &ConnectionProfile) -> Result<Self> {
        if profile.protocol != ProtocolType::Vnc {
            return Err(SessionError::Other(format!(
                "VncConnectRequest requires ProtocolType::Vnc, got {}",
                profile.protocol
            )));
        }
        let port = validate_port(profile.port)?;
        let host = normalize_host(&profile.host)?;
        Ok(Self {
            host,
            port,
            tunnel_enabled: profile.tunnel_enabled,
            tunnel_config_id: profile.tunnel_config_id,
        })
    }
}

/// Structured reason for [`SessionError::UnsupportedProtocol`] (RDP/VNC stubs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnsupportedProtocolReason {
    /// RDP ActiveX / OLE surface host is not wired into the orchestrator.
    RdpSurfaceNotWired { request: RdpConnectRequest },
    /// VNC framebuffer engine is not wired into the orchestrator.
    VncEngineNotWired { request: VncConnectRequest },
}

impl UnsupportedProtocolReason {
    pub fn session_kind(&self) -> SessionKind {
        match self {
            Self::RdpSurfaceNotWired { .. } => SessionKind::Rdp,
            Self::VncEngineNotWired { .. } => SessionKind::Vnc,
        }
    }

    pub fn as_rdp_request(&self) -> Option<&RdpConnectRequest> {
        match self {
            Self::RdpSurfaceNotWired { request } => Some(request),
            Self::VncEngineNotWired { .. } => None,
        }
    }

    pub fn as_vnc_request(&self) -> Option<&VncConnectRequest> {
        match self {
            Self::VncEngineNotWired { request } => Some(request),
            Self::RdpSurfaceNotWired { .. } => None,
        }
    }
}

impl fmt::Display for UnsupportedProtocolReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RdpSurfaceNotWired { request } => write!(
                f,
                "RDP surface host not wired (prepared {}:{} tunnel_enabled={})",
                request.host, request.port, request.tunnel_enabled
            ),
            Self::VncEngineNotWired { request } => write!(
                f,
                "VNC engine not wired (prepared {}:{} tunnel_enabled={})",
                request.host, request.port, request.tunnel_enabled
            ),
        }
    }
}

/// Thin stub connector: prepares [`RdpConnectRequest`], never calls OLE.
#[derive(Debug, Default, Clone, Copy)]
pub struct StubRdpConnector;

impl StubRdpConnector {
    pub fn prepare(profile: &ConnectionProfile) -> Result<RdpConnectRequest> {
        RdpConnectRequest::try_from_profile(profile)
    }

    /// Always fails closed with structured [`SessionError::UnsupportedProtocol`].
    pub fn connect(request: RdpConnectRequest) -> SessionError {
        SessionError::UnsupportedProtocol {
            protocol: ProtocolType::Rdp,
            reason: UnsupportedProtocolReason::RdpSurfaceNotWired { request },
        }
    }
}

/// Thin stub connector: prepares [`VncConnectRequest`], never opens RFB.
#[derive(Debug, Default, Clone, Copy)]
pub struct StubVncConnector;

impl StubVncConnector {
    pub fn prepare(profile: &ConnectionProfile) -> Result<VncConnectRequest> {
        VncConnectRequest::try_from_profile(profile)
    }

    /// Always fails closed with structured [`SessionError::UnsupportedProtocol`].
    pub fn connect(request: VncConnectRequest) -> SessionError {
        SessionError::UnsupportedProtocol {
            protocol: ProtocolType::Vnc,
            reason: UnsupportedProtocolReason::VncEngineNotWired { request },
        }
    }
}

fn validate_port(port: i32) -> Result<u16> {
    let port = u16::try_from(port).map_err(|_| SessionError::InvalidPort(port))?;
    if port == 0 {
        return Err(SessionError::InvalidPort(0));
    }
    Ok(port)
}

fn normalize_host(host: &str) -> Result<String> {
    let host = host.trim();
    if host.is_empty() {
        return Err(SessionError::IncompleteNode);
    }
    Ok(host.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn rdp_profile() -> ConnectionProfile {
        ConnectionProfile {
            protocol: ProtocolType::Rdp,
            host: "dc.local".into(),
            port: 3389,
            tunnel_enabled: true,
            tunnel_config_id: Some(Uuid::nil()),
            rdp_use_external_client: false,
            rdp_domain: Some("CORP".into()),
            ..ConnectionProfile::default()
        }
    }

    fn vnc_profile() -> ConnectionProfile {
        ConnectionProfile {
            protocol: ProtocolType::Vnc,
            host: "vnc.local".into(),
            port: 5900,
            tunnel_enabled: false,
            tunnel_config_id: None,
            ..ConnectionProfile::default()
        }
    }

    #[test]
    fn rdp_request_from_profile() {
        let req = RdpConnectRequest::try_from_profile(&rdp_profile()).unwrap();
        assert_eq!(req.host, "dc.local");
        assert_eq!(req.port, 3389);
        assert!(req.tunnel_enabled);
        assert_eq!(req.tunnel_config_id, Some(Uuid::nil()));
        assert_eq!(req.domain.as_deref(), Some("CORP"));
        assert!(!req.use_external_client);
    }

    #[test]
    fn vnc_request_from_profile() {
        let req = VncConnectRequest::try_from_profile(&vnc_profile()).unwrap();
        assert_eq!(req.host, "vnc.local");
        assert_eq!(req.port, 5900);
        assert!(!req.tunnel_enabled);
        assert!(req.tunnel_config_id.is_none());
    }

    #[test]
    fn stub_rdp_connect_fails_with_prepared_request() {
        let req = StubRdpConnector::prepare(&rdp_profile()).unwrap();
        let err = StubRdpConnector::connect(req);
        match err {
            SessionError::UnsupportedProtocol { protocol, reason } => {
                assert_eq!(protocol, ProtocolType::Rdp);
                assert_eq!(reason.session_kind(), SessionKind::Rdp);
                let prepared = reason.as_rdp_request().unwrap();
                assert_eq!(prepared.host, "dc.local");
                assert_eq!(prepared.port, 3389);
                assert!(prepared.tunnel_enabled);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn stub_vnc_connect_fails_with_prepared_request() {
        let req = StubVncConnector::prepare(&vnc_profile()).unwrap();
        let err = StubVncConnector::connect(req);
        match err {
            SessionError::UnsupportedProtocol { protocol, reason } => {
                assert_eq!(protocol, ProtocolType::Vnc);
                let prepared = reason.as_vnc_request().unwrap();
                assert_eq!(prepared.host, "vnc.local");
                assert_eq!(prepared.port, 5900);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn rejects_zero_port() {
        let mut p = rdp_profile();
        p.port = 0;
        assert!(matches!(
            RdpConnectRequest::try_from_profile(&p),
            Err(SessionError::InvalidPort(0))
        ));
        let mut v = vnc_profile();
        v.port = 0;
        assert!(matches!(
            VncConnectRequest::try_from_profile(&v),
            Err(SessionError::InvalidPort(0))
        ));
    }

    #[test]
    fn rejects_negative_and_overflow_ports() {
        let mut p = rdp_profile();
        p.port = -1;
        assert!(matches!(
            RdpConnectRequest::try_from_profile(&p),
            Err(SessionError::InvalidPort(-1))
        ));
        p.port = 70_000;
        assert!(matches!(
            RdpConnectRequest::try_from_profile(&p),
            Err(SessionError::InvalidPort(70_000))
        ));
        let mut v = vnc_profile();
        v.port = i32::MIN;
        assert!(matches!(
            VncConnectRequest::try_from_profile(&v),
            Err(SessionError::InvalidPort(i32::MIN))
        ));
    }

    #[test]
    fn rejects_empty_or_whitespace_host() {
        let mut p = rdp_profile();
        p.host = String::new();
        assert!(matches!(
            RdpConnectRequest::try_from_profile(&p),
            Err(SessionError::IncompleteNode)
        ));
        p.host = "   ".into();
        assert!(matches!(
            RdpConnectRequest::try_from_profile(&p),
            Err(SessionError::IncompleteNode)
        ));
        let mut v = vnc_profile();
        v.host = "\t".into();
        assert!(matches!(
            VncConnectRequest::try_from_profile(&v),
            Err(SessionError::IncompleteNode)
        ));
    }

    #[test]
    fn rejects_wrong_protocol() {
        let mut p = rdp_profile();
        p.protocol = ProtocolType::Vnc;
        assert!(matches!(
            RdpConnectRequest::try_from_profile(&p),
            Err(SessionError::Other(_))
        ));
        let mut v = vnc_profile();
        v.protocol = ProtocolType::Rdp;
        assert!(matches!(
            VncConnectRequest::try_from_profile(&v),
            Err(SessionError::Other(_))
        ));
    }

    #[test]
    fn request_debug_omits_credential_and_password_material() {
        let secret = "super-secret-password-value";
        let mut p = rdp_profile();
        p.use_inline_password = true;
        p.credential_id = Some(Uuid::new_v4());
        p.username = Some(format!("user-with-{secret}"));
        let req = RdpConnectRequest::try_from_profile(&p).unwrap();
        let dbg = format!("{req:?}");
        assert!(!dbg.contains(secret));
        assert!(!dbg.contains("credential"));
        assert!(!dbg.to_lowercase().contains("password"));
        let err = StubRdpConnector::connect(req);
        let err_dbg = format!("{err:?}");
        let err_display = err.to_string();
        assert!(!err_dbg.contains(secret));
        assert!(!err_display.contains(secret));

        let mut v = vnc_profile();
        v.use_inline_password = true;
        v.credential_id = Some(Uuid::new_v4());
        v.username = Some(format!("vnc-{secret}"));
        let vreq = VncConnectRequest::try_from_profile(&v).unwrap();
        let vdbg = format!("{vreq:?}");
        assert!(!vdbg.contains(secret));
        assert!(!vdbg.to_lowercase().contains("password"));
        let verr = StubVncConnector::connect(vreq);
        assert!(!format!("{verr:?}").contains(secret));
        assert!(!verr.to_string().contains(secret));
    }

    #[test]
    fn session_kind_surface_stubs() {
        assert!(SessionKind::Rdp.is_surface_stub());
        assert!(SessionKind::Vnc.is_surface_stub());
        assert!(!SessionKind::Ssh.is_surface_stub());
        assert_eq!(
            SessionKind::from_protocol(ProtocolType::Https),
            SessionKind::Https
        );
    }
}
