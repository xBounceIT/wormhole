//! Stormshield SNS auth stubs + establish-path glue + shared OpenVPN data plane.
//!
//! **Data plane:** [`crate::StormshieldProvider`] (in `ovpn_backed`) spawns the shared
//! `tools/wormhole-ovpnproxy` sidecar — there is no Stormshield-specific binary.
//!
//! **Auth glue:** lives in [`crate::providers::auth_glue::stormshield_sns`]
//! (`StormshieldSnsAuth` / Fake — `password + otp` concat, never WatchGuard
//! `challenge_response`).
//!
//! **Establish glue:** [`establish`] loads TunnelConfigs metadata (+ optional secret
//! store or SNS auth stubs) and calls [`TunnelProvider::establish`] — tests use
//! [`crate::FakeTunnelProvider`]. Portal HTTPS / config-hash cache / SSO remain TODO.

pub mod establish;

pub use establish::{
    establish_stormshield, establish_stormshield_sns, FAKE_STORMSHIELD_PROFILE_OVPN,
    FAKE_STORMSHIELD_SIDECAR_JSON,
};
