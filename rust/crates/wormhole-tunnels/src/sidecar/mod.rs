//! Existing Go / C++ sidecar binaries under `tools/` — spawn these; do not rewrite.

mod locate;
mod process;
mod protocol;

use crate::TunnelKind;

pub use locate::{
    candidate_paths, locate_among, locate_sidecar, locate_sidecar_for_kind, sidecar_dir_from_env,
    validate_sidecar_dir, SIDECAR_DIR_ENV,
};
pub use process::{SidecarProcess, SidecarTunnelInstance, DEFAULT_READY_TIMEOUT};
pub use protocol::{parse_ready_or_socks_line, MAX_HANDSHAKE_LINE_BYTES};

/// Known Wormhole tunnel sidecar binaries staged next to the app (MSBuild / cargo later).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SidecarBinary {
    /// `tools/wormhole-wgproxy` — WireGuard userspace + loopback SOCKS5.
    WgProxy,
    /// `tools/wormhole-ovpnproxy` — OpenVPN data plane (also WatchGuard / Stormshield / Azure VPN).
    OvpnProxy,
    /// `tools/wormhole-fortiproxy` — Fortinet SSL-VPN.
    FortiProxy,
    /// `tools/wormhole-ciscoproxy` — Cisco Secure Client / AnyConnect protocol.
    CiscoProxy,
}

impl SidecarBinary {
    pub fn for_kind(kind: TunnelKind) -> Option<Self> {
        match kind {
            TunnelKind::WireGuard => Some(Self::WgProxy),
            TunnelKind::OpenVpn
            | TunnelKind::Watchguard
            | TunnelKind::Stormshield
            | TunnelKind::AzureVpn => Some(Self::OvpnProxy),
            TunnelKind::Fortinet => Some(Self::FortiProxy),
            TunnelKind::CiscoSecureClient => Some(Self::CiscoProxy),
        }
    }

    pub fn directory_name(self) -> &'static str {
        match self {
            Self::WgProxy => "wormhole-wgproxy",
            Self::OvpnProxy => "wormhole-ovpnproxy",
            Self::FortiProxy => "wormhole-fortiproxy",
            Self::CiscoProxy => "wormhole-ciscoproxy",
        }
    }

    pub fn exe_name(self) -> &'static str {
        match self {
            Self::WgProxy => "wormhole-wgproxy.exe",
            Self::OvpnProxy => "wormhole-ovpnproxy.exe",
            Self::FortiProxy => "wormhole-fortiproxy.exe",
            Self::CiscoProxy => "wormhole-ciscoproxy.exe",
        }
    }
}

/// Relative repo path to the sidecar project directory (`tools/<name>`).
pub fn sidecar_relative_path(kind: TunnelKind) -> Option<&'static str> {
    match kind {
        TunnelKind::WireGuard => Some("tools/wormhole-wgproxy"),
        TunnelKind::OpenVpn
        | TunnelKind::Watchguard
        | TunnelKind::Stormshield
        | TunnelKind::AzureVpn => Some("tools/wormhole-ovpnproxy"),
        TunnelKind::Fortinet => Some("tools/wormhole-fortiproxy"),
        TunnelKind::CiscoSecureClient => Some("tools/wormhole-ciscoproxy"),
    }
}

pub fn sidecar_binary_name(kind: TunnelKind) -> Option<&'static str> {
    SidecarBinary::for_kind(kind).map(|b| b.exe_name())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kinds::all_kinds;

    #[test]
    fn every_kind_maps_to_a_sidecar() {
        for kind in all_kinds() {
            assert!(sidecar_relative_path(*kind).is_some(), "{kind:?}");
            assert!(sidecar_binary_name(*kind).is_some(), "{kind:?}");
            assert!(SidecarBinary::for_kind(*kind).is_some(), "{kind:?}");
        }
    }
}
