//! Auth glue: portal / cache materials → [`OpenVpnSidecarConfig`] stdin JSON.
//!
//! WatchGuard / Stormshield / Azure VPN store **editor** settings under DPAPI and
//! resolve an OpenVPN profile + credentials (OTP / SAML / Entra) in managed code
//! before spawning `wormhole-ovpnproxy`. This module ports the **construction**
//! half:
//!
//! - [`OpenVpnSidecarConfig`] wire type (snake_case, matches Go + C#)
//! - Cache record decode (WatchGuard / Stormshield / Azure) + optional DPAPI read
//!   via `wormhole-secrets-win` entropy/path helpers
//! - Azure Entra refresh-token cache glue ([`AzureVpnRefreshTokenCache`] + Fake /
//!   DPAPI store; persist / load / clear; **no** WebView2 popup)
//! - [`OvpnAuthGlue`] trait + builders that emit JSON accepted by
//!   [`crate::providers::secret_shape`] / establish
//! - [`OtpPrompt`] / [`SecondFactorPrompt`] stub + [`request_otp`] hook (UI later;
//!   portal loops not wired yet)
//! - [`TlsTrustPrompt`] stub + [`request_tls_trust`] hook (Stormshield portal TLS
//!   consent not wired yet)
//! - [`EntraTokenProvider`] stub + [`request_entra_access_token`] (access token → OpenVPN
//!   password with username `AzureAD`; refresh via [`AzureVpnRefreshTokenCache`]; WebView2 not wired)
//! - [`StormshieldSnsAuth`] stub + username/password + optional OTP typing
//!   (`password + otp` concat; shared OpenVPN sidecar data plane)
//!
//! Interactive SAML / Entra WebView2 remain TODO. OTP / Entra / SNS credential **APIs**
//! are ready; callers still supply already-resolved [`ResolvedOvpnMaterials`] for establish.

mod builders;
mod cache;
mod entra_refresh_cache;
mod entra_token;
mod otp_prompt;
mod tls_trust_prompt;
mod sidecar_config;
mod stormshield_sns;

pub use builders::{
    azure_materials_from_access_token, build_sidecar_json, stormshield_materials,
    watchguard_materials, AzureVpnAuthGlue, OvpnAuthGlue, ResolvedOvpnMaterials,
    StormshieldAuthGlue, WatchguardAuthGlue, AZURE_AAD_USERNAME,
};
pub use cache::{
    azure_token_cache_record, decode_azure_token_cache_json, decode_stormshield_cache_json,
    decode_watchguard_cache_json, encode_azure_token_cache_json, try_read_azure_token_cache,
    try_read_stormshield_cache, try_read_watchguard_cache, AzureVpnTokenCacheRecord,
    StormshieldOvpnCacheRecord, WatchguardOvpnCacheRecord, AZURE_TOKEN_CACHE_MAX_AGE,
    AZURE_TOKEN_CACHE_SCHEMA, STORM_SHIELD_CACHE_SCHEMA, WATCHGUARD_CACHE_SCHEMA,
};
pub use entra_refresh_cache::{
    clear_entra_refresh_token_cache, compute_azure_vpn_identity_hash, persist_entra_refresh_token,
    AzureVpnCacheIdentity, AzureVpnRefreshTokenCache, FakeAzureVpnRefreshTokenCache,
    MemoryAzureVpnRefreshTokenCache, SharedAzureVpnRefreshTokenCache,
};
#[cfg(feature = "secrets")]
pub use entra_refresh_cache::DpapiAzureVpnRefreshTokenCache;
pub use entra_token::{
    azure_materials_from_entra, azure_vpn_refresh_token_cache_path, request_entra_access_token,
    AccessToken, EntraTokenError, EntraTokenProvider, EntraTokenRequest, EntraTokenResponse,
    EntraTokenResult, FakeEntraTokenProvider, MemoryEntraTokenProvider, NullEntraTokenProvider,
    RefreshToken, SharedEntraTokenProvider, ENTRA_OPENVPN_USERNAME,
};
pub use otp_prompt::{
    request_otp, request_second_factor, ChannelOtpPrompt, FakeOtpPrompt, MemoryOtpPrompt,
    NullOtpPrompt, OtpCode, OtpPrompt, OtpPromptError, OtpPromptRequest, OtpPromptResponse,
    PendingOtpPrompt, SecondFactorPrompt, SharedOtpPrompt,
};
pub use tls_trust_prompt::{
    request_tls_trust, ChannelTlsTrustPrompt, FakeTlsTrustPrompt, MemoryTlsTrustPrompt,
    NullTlsTrustPrompt, PendingTlsTrustPrompt, SharedTlsTrustPrompt, TlsTrustChoice,
    TlsTrustPrompt, TlsTrustPromptError, TlsTrustPromptRequest, TlsTrustPromptResponse,
    ACCEPT_BUTTON_LABEL,
};
pub use sidecar_config::{OpenVpnSidecarConfig, OpenVpnTransportRemote};
pub use stormshield_sns::{
    append_otp_to_password, compose_sns_auth_password, request_stormshield_otp,
    resolve_sns_data_plane_auth, stormshield_materials_from_sns, stormshield_sns_to_sidecar_json,
    FakeStormshieldSnsAuth, MemoryStormshieldSnsAuth, NullStormshieldSnsAuth, SharedStormshieldSnsAuth,
    StormshieldOtpSpend, StormshieldPassword, StormshieldSnsAuth, StormshieldSnsAuthRequest,
    StormshieldSnsAuthResult, StormshieldSnsCredentials, StormshieldUsername,
    STORMSHIELD_OTP_SUBTITLE, STORMSHIELD_OTP_TITLE_PREFIX,
};

/// Debug placeholder for non-empty secret-bearing strings (never print the value).
pub(crate) fn redact_nonempty(s: &str) -> &str {
    if s.is_empty() {
        ""
    } else {
        "[REDACTED]"
    }
}
