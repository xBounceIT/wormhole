//! Fortinet provider + SAML SSO auth stub + establish-path glue.
//!
//! Sidecar establish (`wormhole-fortiproxy`) is unchanged. SAML path types /
//! Fake / Channel callback live in [`saml`] — no WebView2 or OS-browser loopback
//! yet (channel is Fake UI transport only). Config-id → metadata + DPAPI/auth →
//! provider lives in [`establish`] (FakeTunnel / Fake or Channel SAML; **no**
//! live FortiGate).

mod establish;
mod provider;
pub mod saml;

pub use establish::{
    build_fortinet_sidecar_config, establish_fortinet, parse_fortinet_settings,
    resolve_fortinet_sidecar_json, FakeFortinetConfigLookup, FakeFortinetSecretLookup,
    FortinetConfigLookup, FortinetConfigRecord, FortinetSecretLookup, FortinetSettings,
    FortinetSidecarConfig, FAKE_FORTINET_SETTINGS_JSON, FAKE_FORTINET_SIDECAR_JSON,
};
#[cfg(feature = "secrets")]
pub use establish::FortinetPayloadStoreSecretLookup;
pub use provider::FortinetProvider;
pub use saml::{
    authenticate, ChannelSamlAuthCallback, FakeSamlAuthCallback, PendingSamlPrompt,
    SamlAuthCallback, SamlAuthError, SamlAuthFlow, SamlAuthId, SamlAuthRequest, SamlAuthResult,
    SamlPromptResponse, SharedSamlAuthCallback, StubSamlAuthCallback, SvpnCookie,
    DEFAULT_SAML_REDIRECT_PORT,
};
