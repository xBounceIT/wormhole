//! WireGuard tunnel provider (`wormhole-wgproxy` sidecar) + establish glue.

mod establish;
mod provider;

pub use establish::{
    establish_wireguard, FakeTunnelConfigLookup, FakeTunnelSecretLookup, TunnelConfigLookup,
    TunnelConfigRecord, TunnelSecretLookup, FAKE_WIREGUARD_SIDECAR_JSON,
};
#[cfg(feature = "secrets")]
pub use establish::PayloadStoreSecretLookup;
pub use provider::WireGuardProvider;
