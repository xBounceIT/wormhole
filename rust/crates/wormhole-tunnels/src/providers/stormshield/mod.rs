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
//! [`crate::FakeTunnelProvider`]. Portal HTTPS / config-hash cache / SSO live in
//! [`portal`]; SSO itself remains unported.
//!
//! **Portal glue:** [`portal`] adds the Automatic-mode loop (C# `StormshieldTunnelProvider`):
//! physical-path preflight, cached profile + config-hash fast path, TLS trust consent,
//! single-spend OTP guard, and portal download — all injectable / Fake-first.

pub mod establish;
pub mod portal;

pub use establish::{
    establish_stormshield, establish_stormshield_sns, FAKE_STORMSHIELD_PROFILE_OVPN,
    FAKE_STORMSHIELD_SIDECAR_JSON,
};
pub use portal::{
    encode_stormshield_cache_record, establish_stormshield_portal, extract_ovpn_remote_hosts,
    looks_like_openvpn_profile, prompt_guarded_stormshield_otp, require_nonempty_profile,
    require_physical_path, stormshield_cache_record_is_current, validate_stormshield_portal_settings,
    AutomaticOutcome, FakeStormshieldPortalFetcher, MemoryStormshieldPortalFetcher,
    MemoryStormshieldProfileCache, ResolveError, SharedStormshieldPortalFetcher,
    StormshieldOtpReuseGuard, StormshieldPortalFetchCall, StormshieldPortalFetcher,
    StormshieldPortalRequest, StormshieldPortalSettings, StormshieldProfileCache,
    StormshieldTlsFailure, STORMSHIELD_CACHE_MAX_AGE, STORMSHIELD_CONFIG_DOWNLOAD_PATH,
    STORMSHIELD_CONFIG_HASH_PATH, STORMSHIELD_DEFAULT_APP_TOKEN, STORMSHIELD_OTP_REUSE_WINDOW,
};
#[cfg(feature = "secrets")]
pub use portal::DpapiStormshieldProfileCache;
