//! Tunnel kind — prefer `wormhole-domain` when the feature is enabled.

#[cfg(feature = "domain")]
pub use wormhole_domain::TunnelKind;

#[cfg(not(feature = "domain"))]
/// Local stub when `wormhole-domain` is not a workspace member yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum TunnelKind {
    WireGuard = 0,
    OpenVpn = 1,
    Fortinet = 2,
    Watchguard = 3,
    Stormshield = 4,
    AzureVpn = 5,
    CiscoSecureClient = 6,
}

/// Every supported tunnel kind (stable order matching the C# enum).
pub fn all_kinds() -> &'static [TunnelKind] {
    &[
        TunnelKind::WireGuard,
        TunnelKind::OpenVpn,
        TunnelKind::Fortinet,
        TunnelKind::Watchguard,
        TunnelKind::Stormshield,
        TunnelKind::AzureVpn,
        TunnelKind::CiscoSecureClient,
    ]
}
