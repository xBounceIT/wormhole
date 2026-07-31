//! Providers for every `TunnelKind`. Real implementations spawn sidecars from `tools/`.
//!
//! WireGuard / OpenVPN / Fortinet / Cisco and the ovpn-backed kinds (WatchGuard /
//! Stormshield / Azure VPN) drive Go sidecars via [`SidecarProcess`].
//! Use [`FakeTunnelProvider`] in unit tests when a successful establish is required without a binary.
//! WireGuard / OpenVPN / Cisco expose establish glue ([`establish_wireguard`] /
//! [`establish_openvpn`] / [`establish_cisco`] / [`establish_cisco_from_auth`]:
//! config id → metadata + secret or Cisco auth stub → provider) with shared
//! [`FakeTunnelConfigLookup`] / [`FakeTunnelSecretLookup`].
//! Fortinet has a **separate** establish module ([`establish_fortinet`]: metadata +
//! `FortinetSettings` DPAPI + SAML stub → sidecar JSON → Fake/`FortinetProvider`).
//! Azure VPN has a **separate** establish module ([`establish_azure`] /
//! [`establish_azure_from_entra`]: metadata + secret or Entra stub → OpenVPN
//! sidecar JSON → Fake/`AzureVpnProvider`; **no** live Entra popup).
//!
//! [`auth_glue`] turns resolved portal/cache materials into `OpenVpnSidecarConfig`
//! JSON accepted by the ovpn-backed establish shape gate. OTP prompts go through
//! [`auth_glue::OtpPrompt`] / [`auth_glue::request_otp`]; Azure Entra access tokens
//! through [`auth_glue::EntraTokenProvider`] / [`auth_glue::request_entra_access_token`];
//! Stormshield SNS username/password (+ optional OTP concat) through
//! [`auth_glue::StormshieldSnsAuth`]; establish-path glue lives in [`stormshield`]
//! (shared `wormhole-ovpnproxy`; portal / cache / SSO UI not wired).
//! Cisco aggregate-auth group / second-factor typing lives in
//! [`cisco::aggregate_auth`] (no STF; SAML SSO / CSD / client cert unsupported); establish glue
//! ([`establish_cisco`] / [`establish_cisco_from_auth`]) is separate from WireGuard /
//! OpenVPN / Fortinet / Azure.
//! WatchGuard Firebox auth + establish-path glue live in [`watchguard`] /
//! [`watchguard::establish`] (shared `wormhole-ovpnproxy`; FakeFireboxCredentials /
//! Fake OTP → FakeTunnelProvider; **no** live Firebox) — separate from WireGuard /
//! OpenVPN / Cisco / Fortinet / Azure / Stormshield.

pub mod auth_glue;
mod azure_vpn;
mod cisco;
mod fortinet;
mod openvpn;
mod ovpn_backed;
pub(crate) mod secret_shape;
mod spawn;
pub mod stormshield;
pub mod watchguard;
pub(crate) mod wireguard;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::{
    bind_local_forwarder_for, ForwarderRegistry, Socks5Endpoint, TunnelConfigSnapshot, TunnelError,
    TunnelInstance, TunnelKind, TunnelProvider, TunnelState,
};

pub use cisco::{
    answer_aggregate_auth_form, establish_cisco, establish_cisco_from_auth,
    is_second_factor_field_name, prepare_cisco_sidecar_config, reject_cisco_unsupported_auth,
    reject_unsupported_cisco_auth, AggregateAuthAnswer, AggregateAuthFieldType,
    AggregateAuthFormKind, AggregateAuthInput, CiscoAuthError, CiscoAuthOptions,
    CiscoSecondFactor, CiscoSecureClientProvider, CiscoSecureClientSidecarConfig,
    CiscoUnsupportedAuth, DEFAULT_CISCO_PORT, FAKE_CISCO_SIDECAR_JSON,
};
pub use fortinet::{
    authenticate as authenticate_fortinet_saml, build_fortinet_sidecar_config, establish_fortinet,
    parse_fortinet_settings, resolve_fortinet_sidecar_json, ChannelSamlAuthCallback,
    FakeFortinetConfigLookup, FakeFortinetSecretLookup, FakeSamlAuthCallback, FortinetConfigLookup,
    FortinetConfigRecord, FortinetProvider, FortinetSecretLookup, FortinetSettings,
    FortinetSidecarConfig, PendingSamlPrompt, SamlAuthCallback, SamlAuthError, SamlAuthFlow,
    SamlAuthId, SamlAuthRequest, SamlAuthResult, SamlPromptResponse, SharedSamlAuthCallback,
    StubSamlAuthCallback, SvpnCookie, DEFAULT_SAML_REDIRECT_PORT, FAKE_FORTINET_SETTINGS_JSON,
    FAKE_FORTINET_SIDECAR_JSON,
};
#[cfg(feature = "secrets")]
pub use fortinet::FortinetPayloadStoreSecretLookup;
pub use azure_vpn::{
    establish_azure, establish_azure_from_entra, AzureVpnEstablishOptions,
    FAKE_AZURE_VPN_SIDECAR_JSON,
};
pub use openvpn::{establish_openvpn, OpenVpnProvider, FAKE_OPENVPN_SIDECAR_JSON};
pub use ovpn_backed::{AzureVpnProvider, StormshieldProvider, WatchguardProvider};
pub use stormshield::{
    establish_stormshield, establish_stormshield_sns, FAKE_STORMSHIELD_PROFILE_OVPN,
    FAKE_STORMSHIELD_SIDECAR_JSON,
};
pub use watchguard::{
    establish_watchguard, establish_watchguard_crv1, establish_watchguard_portal,
    firebox_materials_crv1, firebox_materials_portal, firebox_second_factor_prompt_request,
    normalize_firebox_second_factor, portal_openvpn_password, request_firebox_second_factor,
    resolve_firebox_crv1_sidecar_json, resolve_firebox_portal_sidecar_json, FakeFireboxCredentials,
    FireboxCredentials, FireboxPassword, FireboxSecondFactor, FireboxUsername,
    FAKE_WATCHGUARD_PROFILE_OVPN, FAKE_WATCHGUARD_SIDECAR_JSON, FIREBOX_DEFAULT_DOMAIN,
    FIREBOX_PUSH_SELECTOR,
};
pub use wireguard::{
    establish_wireguard, FakeTunnelConfigLookup, FakeTunnelSecretLookup, TunnelConfigLookup,
    TunnelConfigRecord, TunnelSecretLookup, WireGuardProvider, FAKE_WIREGUARD_SIDECAR_JSON,
};
#[cfg(feature = "secrets")]
pub use wireguard::PayloadStoreSecretLookup;

/// In-memory tunnel used by [`FakeTunnelProvider`] and unit tests.
pub struct StubTunnelInstance {
    state: Mutex<TunnelState>,
    socks: Option<Socks5Endpoint>,
    forwarders: ForwarderRegistry,
    pub close_count: AtomicUsize,
}

impl StubTunnelInstance {
    pub fn up_with_socks(port: u16) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(TunnelState::Up),
            socks: Some(Socks5Endpoint::loopback(port)),
            forwarders: ForwarderRegistry::new(),
            close_count: AtomicUsize::new(0),
        })
    }

    pub fn failed() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(TunnelState::Failed),
            socks: None,
            forwarders: ForwarderRegistry::new(),
            close_count: AtomicUsize::new(0),
        })
    }

    pub fn close_count(&self) -> usize {
        self.close_count.load(Ordering::SeqCst)
    }

    pub fn mark_failed(&self) {
        *self
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = TunnelState::Failed;
    }

    pub fn mark_closed(&self) {
        *self
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = TunnelState::Closed;
    }
}

#[async_trait]
impl TunnelInstance for StubTunnelInstance {
    fn state(&self) -> TunnelState {
        *self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn socks5_endpoint(&self) -> Option<Socks5Endpoint> {
        self.socks
    }

    async fn bind_local_forwarder(&self, host: &str, port: u16) -> Result<u16, TunnelError> {
        bind_local_forwarder_for(self.state(), self.socks, &self.forwarders, host, port).await
    }

    async fn close(&self) {
        self.close_count.fetch_add(1, Ordering::SeqCst);
        *self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = TunnelState::Closed;
        self.forwarders.close_all().await;
    }
}

/// Controllable test double that actually establishes an in-memory [`StubTunnelInstance`].
///
/// Production [`default_stub_providers`] spawn real sidecars (or return BinaryNotFound).
/// `establish_count` stands in for "OTP prompts / VPN logins" — concurrent manager
/// coalesce must keep it at 1 for the same config id.
pub struct FakeTunnelProvider {
    kind: TunnelKind,
    establish_count: AtomicUsize,
    delay: Option<std::time::Duration>,
    next_socks_port: AtomicUsize,
    /// When set, the next `establish` returns this error string (then clears).
    fail_next: Mutex<Option<String>>,
    /// When set, establish returns this instance instead of minting a new Up one.
    force_instance: Mutex<Option<Arc<StubTunnelInstance>>>,
}

impl std::fmt::Debug for FakeTunnelProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never dump fail_next / forced instance internals — tests may put markers there.
        f.debug_struct("FakeTunnelProvider")
            .field("kind", &self.kind)
            .field("establish_count", &self.establish_count.load(Ordering::SeqCst))
            .field("delay", &self.delay)
            .field(
                "has_fail_next",
                &self
                    .fail_next
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .is_some(),
            )
            .field(
                "has_force_instance",
                &self
                    .force_instance
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .is_some(),
            )
            .finish()
    }
}

impl FakeTunnelProvider {
    pub fn new(kind: TunnelKind) -> Self {
        Self {
            kind,
            establish_count: AtomicUsize::new(0),
            delay: None,
            next_socks_port: AtomicUsize::new(18_000),
            fail_next: Mutex::new(None),
            force_instance: Mutex::new(None),
        }
    }

    pub fn with_delay(kind: TunnelKind, delay: std::time::Duration) -> Self {
        Self {
            delay: Some(delay),
            ..Self::new(kind)
        }
    }

    pub fn establish_count(&self) -> usize {
        self.establish_count.load(Ordering::SeqCst)
    }

    pub fn fail_next(&self, message: impl Into<String>) {
        *self
            .fail_next
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(message.into());
    }

    pub fn force_next_instance(&self, instance: Arc<StubTunnelInstance>) {
        *self
            .force_instance
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(instance);
    }
}

#[async_trait]
impl TunnelProvider for FakeTunnelProvider {
    fn kind(&self) -> TunnelKind {
        self.kind
    }

    async fn establish(
        &self,
        _config: &TunnelConfigSnapshot,
        _secret_blob: &[u8],
    ) -> Result<Arc<dyn TunnelInstance>, TunnelError> {
        self.establish_count.fetch_add(1, Ordering::SeqCst);
        if let Some(delay) = self.delay {
            tokio::time::sleep(delay).await;
        }
        if let Some(msg) = self
            .fail_next
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
        {
            return Err(TunnelError::Establish(msg));
        }
        if let Some(forced) = self
            .force_instance
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
        {
            return Ok(forced);
        }
        let port = self.next_socks_port.fetch_add(1, Ordering::SeqCst) as u16;
        Ok(StubTunnelInstance::up_with_socks(port))
    }
}

/// One provider per kind (production defaults).
///
/// All kinds locate + spawn their Go sidecar when `secret_blob` is non-empty.
/// Missing binary → [`TunnelError::BinaryNotFound`]. WatchGuard / Stormshield /
/// Azure VPN expect OpenVPN sidecar JSON (use [`crate::providers::auth_glue`] to
/// build it from resolved portal/cache materials).
pub fn default_stub_providers() -> Vec<Arc<dyn TunnelProvider>> {
    use crate::kinds::all_kinds;
    let providers: Vec<Arc<dyn TunnelProvider>> = vec![
        Arc::new(WireGuardProvider::new()),
        Arc::new(OpenVpnProvider::new()),
        Arc::new(FortinetProvider::new()),
        Arc::new(WatchguardProvider::new()),
        Arc::new(StormshieldProvider::new()),
        Arc::new(AzureVpnProvider::new()),
        Arc::new(CiscoSecureClientProvider::new()),
    ];
    debug_assert_eq!(providers.len(), all_kinds().len());
    providers
}
