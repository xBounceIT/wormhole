//! OpenVPN provider + establish-path glue (config id → metadata + secret → establish).
//!
//! Production spawn uses [`OpenVpnProvider`] + `wormhole-ovpnproxy`. Unit tests drive
//! [`crate::FakeTunnelProvider`] through [`establish_openvpn`] with the shared
//! WireGuard-module lookup Fakes ([`crate::providers::wireguard::FakeTunnelConfigLookup`] /
//! [`crate::providers::wireguard::FakeTunnelSecretLookup`], or
//! `wormhole_secrets_win::FakeTunnelPayloadStore` via
//! [`crate::providers::wireguard::PayloadStoreSecretLookup`]) — **no** live OpenVPN
//! process / network. Distinct entry point from [`super::wireguard::establish_wireguard`].

mod establish;
mod provider;

pub use establish::{establish_openvpn, FAKE_OPENVPN_SIDECAR_JSON};
pub use provider::OpenVpnProvider;
