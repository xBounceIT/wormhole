//! WatchGuard Firebox auth stubs + establish-path glue + shared OpenVPN data plane.
//!
//! **Data plane:** [`crate::WatchguardProvider`] (in `ovpn_backed`) spawns the shared
//! `tools/wormhole-ovpnproxy` sidecar — there is no WatchGuard-specific binary.
//!
//! **Auth glue:** [`firebox_auth`] builds [`crate::ResolvedOvpnMaterials`] /
//! [`crate::OpenVpnSidecarConfig`] from username/password + optional OTP (via
//! [`crate::request_otp`]). CRV1 keeps the account password and puts OTP in
//! `challenge_response`; portal applies the OTP→password quirk and omits challenge.
//!
//! **Establish glue:** [`establish`] loads TunnelConfigs metadata (+ optional secret
//! store or Firebox auth stubs) and calls [`TunnelProvider::establish`] — tests use
//! [`crate::FakeTunnelProvider`]. Portal HTTP / SAML WebView2 / live Firebox remain TODO.

pub mod establish;
pub mod firebox_auth;
pub mod portal;

pub use establish::{
    establish_watchguard, establish_watchguard_crv1, establish_watchguard_portal,
    FAKE_WATCHGUARD_PROFILE_OVPN, FAKE_WATCHGUARD_SIDECAR_JSON,
};
pub use firebox_auth::{
    firebox_materials_crv1, firebox_materials_portal, firebox_second_factor_prompt_request,
    normalize_firebox_second_factor, portal_openvpn_password, request_firebox_second_factor,
    resolve_firebox_crv1_sidecar_json, resolve_firebox_portal_sidecar_json, FakeFireboxCredentials,
    FireboxCredentials, FireboxPassword, FireboxSecondFactor, FireboxUsername,
    FIREBOX_DEFAULT_DOMAIN, FIREBOX_PUSH_SELECTOR,
};
pub use portal::{
    encode_watchguard_cache_record, establish_watchguard_automatic,
    map_watchguard_resolve_error, prompt_guarded_watchguard_otp,
    validate_watchguard_portal_settings, watchguard_cache_record_is_current,
    FakeWatchguardPortalFetcher, MemoryWatchguardPortalFetcher, MemoryWatchguardProfileCache,
    SharedWatchguardPortalFetcher, WatchguardOtpReuseGuard, WatchguardOutcome,
    WatchguardPortalFetchCall, WatchguardPortalFetcher, WatchguardPortalRequest,
    WatchguardPortalSettings, WatchguardProfileCache, WatchguardResolveError,
    WatchguardTlsFailure, WATCHGUARD_CACHE_MAX_AGE, WATCHGUARD_OTP_REUSE_WINDOW,
};
#[cfg(feature = "secrets")]
pub use portal::DpapiWatchguardProfileCache;
