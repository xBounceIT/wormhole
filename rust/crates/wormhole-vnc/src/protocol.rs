//! RFB protocol constants and negotiated types (RFC 6143 subset).

/// RFB protocol version string Wormhole speaks (3.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RfbVersion {
    /// `RFB 003.008\n`
    V3_8,
}

impl RfbVersion {
    pub const fn wire(self) -> &'static [u8] {
        b"RFB 003.008\n"
    }

    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.starts_with(b"RFB 003.008") {
            Some(Self::V3_8)
        } else {
            None
        }
    }
}

/// Security type **None** (RFC 6143 §7.1.2).
pub const SECURITY_TYPE_NONE: u8 = 1;
/// Security type **VNC Authentication** (classic DES challenge).
pub const SECURITY_TYPE_VNC_AUTH: u8 = 2;

/// Security types Wormhole v1 accepts (matches C# no-auth + classic password).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RfbSecurityType {
    None = SECURITY_TYPE_NONE,
    VncAuth = SECURITY_TYPE_VNC_AUTH,
}

impl RfbSecurityType {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Prefer no-auth when offered; otherwise classic VNC auth. Reject others.
    pub fn select(offered: &[u8]) -> Result<Self, crate::VncError> {
        if offered.contains(&SECURITY_TYPE_NONE) {
            return Ok(Self::None);
        }
        if offered.contains(&SECURITY_TYPE_VNC_AUTH) {
            return Ok(Self::VncAuth);
        }
        let first = offered.first().copied().unwrap_or(0);
        Err(crate::VncError::UnsupportedSecurityType(first))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_prefers_none() {
        assert_eq!(
            RfbSecurityType::select(&[2, 1]).unwrap(),
            RfbSecurityType::None
        );
    }

    #[test]
    fn select_vnc_auth_when_only_option() {
        assert_eq!(
            RfbSecurityType::select(&[2]).unwrap(),
            RfbSecurityType::VncAuth
        );
    }

    #[test]
    fn select_rejects_unknown() {
        assert!(matches!(
            RfbSecurityType::select(&[16 /* Tight */]),
            Err(crate::VncError::UnsupportedSecurityType(16))
        ));
    }

    #[test]
    fn select_rejects_empty_offer() {
        assert!(matches!(
            RfbSecurityType::select(&[]),
            Err(crate::VncError::UnsupportedSecurityType(0))
        ));
    }

    #[test]
    fn version_wire_bytes() {
        assert_eq!(RfbVersion::V3_8.wire(), b"RFB 003.008\n");
        assert_eq!(RfbVersion::parse(b"RFB 003.008\n"), Some(RfbVersion::V3_8));
        assert_eq!(RfbVersion::parse(b"RFB 003.003\n"), None);
    }
}
