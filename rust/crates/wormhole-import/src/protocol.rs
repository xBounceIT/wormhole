//! Protocol string mapping — SSH / RDP / VNC only (parity with C# `TryMapProtocol`).

use crate::error::ImportError;

#[cfg(feature = "domain")]
pub use wormhole_domain::ProtocolType as MappedProtocol;

#[cfg(not(feature = "domain"))]
/// Local protocol tag when `wormhole-domain` is disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolType {
    Ssh,
    Rdp,
    Vnc,
}

#[cfg(not(feature = "domain"))]
pub type MappedProtocol = ProtocolType;

/// Map an mRemoteNG `Protocol` attribute. HTTP / HTTPS / Serial / others → `None`
/// (skipped on Connection leaves; folders may keep a null protocol).
pub fn map_protocol(raw: &str) -> Option<MappedProtocol> {
    let normalized = raw.trim();
    if normalized.eq_ignore_ascii_case("SSH")
        || normalized.eq_ignore_ascii_case("SSH1")
        || normalized.eq_ignore_ascii_case("SSH2")
    {
        return Some(MappedProtocol::Ssh);
    }
    if normalized.eq_ignore_ascii_case("RDP") {
        return Some(MappedProtocol::Rdp);
    }
    if normalized.eq_ignore_ascii_case("VNC") {
        return Some(MappedProtocol::Vnc);
    }
    None
}

/// Same mapping as [`map_protocol`], but returns [`ImportError::UnsupportedProtocol`]
/// instead of `None` for HTTP / HTTPS / Serial and other unmapped values.
pub fn try_map_protocol(raw: &str) -> Result<MappedProtocol, ImportError> {
    map_protocol(raw).ok_or_else(|| ImportError::UnsupportedProtocol(raw.trim().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_ssh_rdp_vnc() {
        assert_eq!(map_protocol("SSH2"), Some(MappedProtocol::Ssh));
        assert_eq!(map_protocol(" ssh "), Some(MappedProtocol::Ssh));
        assert_eq!(map_protocol("RDP"), Some(MappedProtocol::Rdp));
        assert_eq!(map_protocol("VNC"), Some(MappedProtocol::Vnc));
        assert!(try_map_protocol("SSH2").is_ok());
        assert!(try_map_protocol("RDP").is_ok());
        assert!(try_map_protocol("VNC").is_ok());
    }

    #[test]
    fn rejects_http_https_serial_telnet_as_unsupported() {
        for raw in [
            "HTTP", "HTTPS", "http", "Serial", "serial", "Telnet", "TELNET", "RAW", "ICA", "",
            "  HTTPS  ",
        ] {
            assert!(
                map_protocol(raw).is_none(),
                "map_protocol({raw:?}) should be None — never remap to SSH/RDP/VNC"
            );
            let err = try_map_protocol(raw).expect_err("expected UnsupportedProtocol");
            match err {
                ImportError::UnsupportedProtocol(ref label) => {
                    assert_eq!(label, raw.trim());
                    let msg = err.to_string();
                    assert!(
                        msg.contains("unsupported mRemoteNG protocol"),
                        "{msg}"
                    );
                    assert!(msg.contains("SSH, RDP, and VNC"), "{msg}");
                    assert!(
                        msg.contains("Telnet") || msg.contains("not mapped"),
                        "{msg}"
                    );
                }
                other => panic!("expected UnsupportedProtocol, got {other:?}"),
            }
        }
        // Explicit: HTTP must not become SSH (domain ProtocolType also has Http).
        assert_ne!(map_protocol("HTTP"), Some(MappedProtocol::Ssh));
        assert_ne!(map_protocol("HTTPS"), Some(MappedProtocol::Ssh));
        assert_ne!(map_protocol("Serial"), Some(MappedProtocol::Ssh));
    }
}
