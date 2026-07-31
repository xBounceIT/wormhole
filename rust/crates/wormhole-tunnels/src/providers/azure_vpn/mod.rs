//! Azure VPN establish-path glue (config id → metadata + Entra stub → OpenVPN sidecar).
//!
//! Separate from WireGuard / OpenVPN / Cisco / Fortinet glue. Reuses shared
//! [`TunnelConfigLookup`] / [`TunnelSecretLookup`] (and Fakes) from the WireGuard
//! establish module — production wires `TunnelConfigRepository` +
//! `TunnelPayloadStore`; tests use those Fakes with [`crate::FakeTunnelProvider`]
//! and [`crate::FakeEntraTokenProvider`].
//!
//! Two entry points:
//! - [`establish_azure`] — already-resolved OpenVPN sidecar JSON from the secret store
//! - [`establish_azure_from_entra`] — profile + [`EntraTokenProvider`] stub →
//!   [`AzureVpnAuthGlue`] stdin JSON (`username`=`AzureAD`, password=access token)
//!
//! **No** live Azure VPN Gateway / WAN, **no** interactive Entra WebView2 popup.
//! The data plane remains shared `wormhole-ovpnproxy` ([`crate::AzureVpnProvider`]).
//! Secrets / tokens never appear in [`Debug`] / logs / [`TunnelError`] text.

mod establish;

pub use establish::{
    establish_azure, establish_azure_from_entra, AzureVpnEstablishOptions,
    FAKE_AZURE_VPN_SIDECAR_JSON,
};
