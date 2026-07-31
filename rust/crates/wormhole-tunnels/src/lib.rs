//! VPN tunnel manager for the Rust migration.
//!
//! Mirrors `Services/Tunneling/TunnelManager.cs`: one ref-counted live tunnel
//! per `TunnelConfigId`, concurrent `establish` calls coalesce into a single
//! provider establishment (one OTP), and leases dispose the real instance when
//! the last holder releases. `UpdatedAt` bumps and dead `Failed`/`Closed`
//! instances fail-closed to a fresh establish. Unit tests use
//! [`FakeTunnelProvider`] — no live VPN.
//!
//! **Sidecars:** do not rewrite the Go proxies under `tools/`. WireGuard / OpenVPN /
//! Fortinet / Cisco and the ovpn-backed kinds (WatchGuard / Stormshield / Azure VPN)
//! spawn their binaries via [`sidecar::SidecarProcess`] (identical READY/SOCKS
//! control plane).

mod config;
mod error;
mod forwarder;
mod kinds;
mod lease;
mod manager;
mod physical_network_path;
mod providers;
pub mod sidecar;
mod socks5;
mod state;
mod traits;

pub use config::TunnelConfigSnapshot;
pub use error::TunnelError;
pub use forwarder::{
    bind_local_forwarder_for, ForwarderRegistry, LocalForwarder,
};
pub use kinds::{all_kinds, TunnelKind};
pub use lease::TunnelLease;
pub use manager::TunnelManager;
pub use physical_network_path::{
    build_physical_network_path, classify_split_route, is_vpn_like_adapter,
    physical_adapter_score, FakePhysicalNetworkPath, PhysicalAdapterKind, PhysicalAdapterRecord,
    PhysicalNetworkAdapter, PhysicalNetworkPath, PhysicalNetworkPathProbe, PhysicalNetworkRoute,
    MAX_PHYSICAL_ADAPTERS,
};
pub use socks5::Socks5Client;
pub use providers::{
    answer_aggregate_auth_form, authenticate_fortinet_saml, build_fortinet_sidecar_config,
    default_stub_providers, establish_azure, establish_azure_from_entra, establish_cisco,
    establish_cisco_from_auth, establish_fortinet, establish_openvpn, establish_stormshield,
    establish_stormshield_sns, establish_watchguard, establish_watchguard_crv1,
    establish_watchguard_portal, establish_wireguard, firebox_materials_crv1,
    firebox_materials_portal, firebox_second_factor_prompt_request,
    is_second_factor_field_name, normalize_firebox_second_factor, parse_fortinet_settings,
    portal_openvpn_password, prepare_cisco_sidecar_config, reject_cisco_unsupported_auth,
    reject_unsupported_cisco_auth, request_firebox_second_factor, resolve_firebox_crv1_sidecar_json,
    resolve_firebox_portal_sidecar_json, resolve_fortinet_sidecar_json, AggregateAuthAnswer,
    AggregateAuthFieldType, AggregateAuthFormKind, AggregateAuthInput, AzureVpnEstablishOptions,
    AzureVpnProvider, CiscoAuthError, CiscoAuthOptions, CiscoSecondFactor,
    CiscoSecureClientProvider, CiscoSecureClientSidecarConfig, CiscoUnsupportedAuth,
    ChannelSamlAuthCallback, FakeFireboxCredentials, FakeFortinetConfigLookup,
    FakeFortinetSecretLookup, FakeSamlAuthCallback, FakeTunnelConfigLookup, FakeTunnelProvider,
    FakeTunnelSecretLookup, FireboxCredentials, FireboxPassword, FireboxSecondFactor,
    FireboxUsername, FortinetConfigLookup, FortinetConfigRecord, FortinetProvider,
    FortinetSecretLookup, FortinetSettings, FortinetSidecarConfig, OpenVpnProvider,
    PendingSamlPrompt, SamlAuthCallback, SamlAuthError, SamlAuthFlow, SamlAuthId, SamlAuthRequest,
    SamlAuthResult, SamlPromptResponse, SharedSamlAuthCallback, StormshieldProvider,
    StubSamlAuthCallback, StubTunnelInstance, SvpnCookie, TunnelConfigLookup, TunnelConfigRecord,
    TunnelSecretLookup, WatchguardProvider, WireGuardProvider, DEFAULT_CISCO_PORT,
    DEFAULT_SAML_REDIRECT_PORT, FAKE_AZURE_VPN_SIDECAR_JSON, FAKE_CISCO_SIDECAR_JSON,
    FAKE_FORTINET_SETTINGS_JSON, FAKE_FORTINET_SIDECAR_JSON, FAKE_OPENVPN_SIDECAR_JSON,
    FAKE_STORMSHIELD_PROFILE_OVPN, FAKE_STORMSHIELD_SIDECAR_JSON, FAKE_WATCHGUARD_PROFILE_OVPN,
    FAKE_WATCHGUARD_SIDECAR_JSON, FAKE_WIREGUARD_SIDECAR_JSON, FIREBOX_DEFAULT_DOMAIN,
    FIREBOX_PUSH_SELECTOR,
};
#[cfg(feature = "secrets")]
pub use providers::{FortinetPayloadStoreSecretLookup, PayloadStoreSecretLookup};
pub use providers::auth_glue::{
    append_otp_to_password, azure_materials_from_access_token, azure_materials_from_entra,
    azure_token_cache_record, azure_vpn_refresh_token_cache_path, build_sidecar_json,
    clear_entra_refresh_token_cache, compose_sns_auth_password, compute_azure_vpn_identity_hash,
    decode_azure_token_cache_json, decode_stormshield_cache_json, decode_watchguard_cache_json,
    encode_azure_token_cache_json, persist_entra_refresh_token, request_entra_access_token,
    request_otp, request_second_factor, request_stormshield_otp, request_tls_trust,
    resolve_sns_data_plane_auth,
    stormshield_materials, stormshield_materials_from_sns, stormshield_sns_to_sidecar_json,
    try_read_azure_token_cache, try_read_stormshield_cache, try_read_watchguard_cache,
    watchguard_materials, AccessToken, AzureVpnAuthGlue, AzureVpnCacheIdentity,
    AzureVpnRefreshTokenCache, AzureVpnTokenCacheRecord, ChannelOtpPrompt, ChannelTlsTrustPrompt,
    EntraTokenError,
    EntraTokenProvider, EntraTokenRequest, EntraTokenResponse, EntraTokenResult,
    FakeAzureVpnRefreshTokenCache, FakeEntraTokenProvider, FakeOtpPrompt, FakeStormshieldSnsAuth,
    FakeTlsTrustPrompt, MemoryAzureVpnRefreshTokenCache, MemoryEntraTokenProvider, MemoryOtpPrompt,
    MemoryStormshieldSnsAuth, MemoryTlsTrustPrompt, NullEntraTokenProvider, NullOtpPrompt,
    NullStormshieldSnsAuth, NullTlsTrustPrompt,
    OpenVpnSidecarConfig, OpenVpnTransportRemote, OtpCode, OtpPrompt, OtpPromptError,
    OtpPromptRequest, OtpPromptResponse, OvpnAuthGlue, PendingOtpPrompt, PendingTlsTrustPrompt,
    RefreshToken,
    ResolvedOvpnMaterials, SecondFactorPrompt, SharedAzureVpnRefreshTokenCache,
    SharedEntraTokenProvider, SharedOtpPrompt, SharedTlsTrustPrompt, SharedStormshieldSnsAuth,
    StormshieldAuthGlue, StormshieldOtpSpend, StormshieldOvpnCacheRecord, StormshieldPassword, StormshieldSnsAuth,
    StormshieldSnsAuthRequest, StormshieldSnsAuthResult, StormshieldSnsCredentials,
    StormshieldUsername, WatchguardAuthGlue, WatchguardOvpnCacheRecord, AZURE_AAD_USERNAME,
    AZURE_TOKEN_CACHE_MAX_AGE, AZURE_TOKEN_CACHE_SCHEMA, ENTRA_OPENVPN_USERNAME,
    STORM_SHIELD_CACHE_SCHEMA, STORMSHIELD_OTP_SUBTITLE, STORMSHIELD_OTP_TITLE_PREFIX,
    WATCHGUARD_CACHE_SCHEMA, ACCEPT_BUTTON_LABEL, TlsTrustChoice, TlsTrustPrompt,
    TlsTrustPromptError, TlsTrustPromptRequest, TlsTrustPromptResponse,
};
#[cfg(feature = "secrets")]
pub use providers::auth_glue::DpapiAzureVpnRefreshTokenCache;
pub use sidecar::{
    candidate_paths, locate_sidecar, parse_ready_or_socks_line, sidecar_binary_name,
    sidecar_relative_path, validate_sidecar_dir, SidecarBinary, SidecarProcess,
    SidecarTunnelInstance, MAX_HANDSHAKE_LINE_BYTES, SIDECAR_DIR_ENV,
};
pub use state::TunnelState;
pub use traits::{Socks5Endpoint, TunnelInstance, TunnelProvider};
