//! Thin Fortinet establish-path glue: config id → metadata + DPAPI/auth stubs → provider.
//!
//! Mirrors C# `FortinetTunnelProvider.EstablishAsync` load order:
//! 1. SQLite `TunnelConfigs` metadata (`TunnelConfigRepository`)
//! 2. DPAPI / fake tunnel secret (`TunnelPayloadStore`) as `FortinetSettings` JSON
//! 3. Optional SAML via [`super::saml`] (`StubSamlAuthCallback` /
//!    [`FakeSamlAuthCallback`] / [`super::saml::ChannelSamlAuthCallback`])
//! 4. Build `FortinetSidecarConfig` stdin JSON → [`TunnelProvider::establish`]
//!
//! Unit tests drive [`crate::FakeTunnelProvider`] — **no** live FortiGate / network /
//! WebView2 / OS-browser. Separate from WireGuard / OpenVPN establish glue modules.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::saml::{
    authenticate, SamlAuthCallback, SamlAuthError, SamlAuthFlow, SamlAuthRequest, SamlAuthResult,
    DEFAULT_SAML_REDIRECT_PORT,
};
use crate::providers::auth_glue::redact_nonempty;
use crate::providers::secret_shape::require_fortinet_establish_secret;
use crate::{
    TunnelConfigSnapshot, TunnelError, TunnelInstance, TunnelKind, TunnelProvider,
};

/// Minimal Fortinet **editor** settings JSON (PascalCase) used by Fake establish tests.
///
/// Matches C# `FortinetSettings` DPAPI blob shape (not sidecar stdin).
pub const FAKE_FORTINET_SETTINGS_JSON: &[u8] = br#"{"Host":"vpn.example.com","Port":443,"Username":"alice","Password":"x"}"#;

/// Minimal Fortinet **sidecar** stdin JSON (snake_case) — shape already used by
/// `tests/sidecar_control_plane.rs` / [`crate::FortinetProvider`].
pub const FAKE_FORTINET_SIDECAR_JSON: &[u8] =
    br#"{"host":"vpn.example.com","port":443,"username":"alice","password":"x"}"#;

/// Metadata-only tunnel config row (SQLite `TunnelConfigs` shape).
///
/// Secrets never live here — only id / name / kind / `updated_at`.
#[derive(Debug, Clone)]
pub struct FortinetConfigRecord {
    pub id: Uuid,
    pub name: String,
    pub kind: TunnelKind,
    /// Mirrors C# / SQLite `UpdatedAt` for pool invalidation.
    pub updated_at: SystemTime,
}

impl FortinetConfigRecord {
    pub fn new(id: Uuid, kind: TunnelKind, name: impl Into<String>) -> Self {
        Self {
            id,
            kind,
            name: name.into(),
            updated_at: SystemTime::UNIX_EPOCH,
        }
    }

    pub fn with_updated_at(mut self, updated_at: SystemTime) -> Self {
        self.updated_at = updated_at;
        self
    }

    pub fn to_snapshot(&self) -> TunnelConfigSnapshot {
        TunnelConfigSnapshot {
            id: self.id,
            kind: self.kind,
            name: self.name.clone(),
            updated_at: self.updated_at,
        }
    }
}

/// Load TunnelConfigs metadata by id (production: `TunnelConfigRepository::get_by_id`).
pub trait FortinetConfigLookup: Send + Sync {
    fn get(&self, id: Uuid) -> Result<Option<FortinetConfigRecord>, TunnelError>;
}

/// Load the tunnel secret blob by config id (production: `TunnelPayloadStore::read`).
///
/// Implementations must **never** log or put plaintext into [`TunnelError`] / [`Debug`].
pub trait FortinetSecretLookup: Send + Sync {
    fn read(&self, tunnel_config_id: &Uuid) -> Result<Option<Vec<u8>>, TunnelError>;
}

/// Adapt any [`wormhole_secrets_win::TunnelPayloadStore`] as a [`FortinetSecretLookup`].
#[cfg(feature = "secrets")]
pub struct FortinetPayloadStoreSecretLookup<S> {
    store: S,
}

#[cfg(feature = "secrets")]
impl<S> FortinetPayloadStoreSecretLookup<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub fn into_inner(self) -> S {
        self.store
    }

    pub fn store(&self) -> &S {
        &self.store
    }
}

#[cfg(feature = "secrets")]
impl<S> fmt::Debug for FortinetPayloadStoreSecretLookup<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FortinetPayloadStoreSecretLookup")
            .field("store", &self.store)
            .finish()
    }
}

#[cfg(feature = "secrets")]
impl<S> FortinetSecretLookup for FortinetPayloadStoreSecretLookup<S>
where
    S: wormhole_secrets_win::TunnelPayloadStore + Send + Sync,
{
    fn read(&self, tunnel_config_id: &Uuid) -> Result<Option<Vec<u8>>, TunnelError> {
        self.store.read(tunnel_config_id).map_err(|e| {
            TunnelError::Establish(format!("tunnel secret store read failed: {e}"))
        })
    }
}

/// In-memory TunnelConfigs stand-in for unit tests (no SQLite).
#[derive(Default)]
pub struct FakeFortinetConfigLookup {
    entries: Mutex<HashMap<Uuid, FortinetConfigRecord>>,
    get_calls: AtomicUsize,
}

impl FakeFortinetConfigLookup {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(self, record: FortinetConfigRecord) -> Self {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(record.id, record);
        self
    }

    pub fn insert(&self, record: FortinetConfigRecord) {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(record.id, record);
    }

    pub fn get_calls(&self) -> usize {
        self.get_calls.load(Ordering::SeqCst)
    }
}

impl fmt::Debug for FakeFortinetConfigLookup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        let ids: Vec<Uuid> = entries.keys().copied().collect();
        f.debug_struct("FakeFortinetConfigLookup")
            .field("config_ids", &ids)
            .field("get_calls", &self.get_calls.load(Ordering::SeqCst))
            .finish()
    }
}

impl FortinetConfigLookup for FakeFortinetConfigLookup {
    fn get(&self, id: Uuid) -> Result<Option<FortinetConfigRecord>, TunnelError> {
        self.get_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&id)
            .cloned())
    }
}

/// In-memory tunnel-secret stand-in for unit tests (no DPAPI).
pub struct FakeFortinetSecretLookup {
    entries: Mutex<HashMap<Uuid, Vec<u8>>>,
    read_calls: AtomicUsize,
}

impl Default for FakeFortinetSecretLookup {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeFortinetSecretLookup {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            read_calls: AtomicUsize::new(0),
        }
    }

    pub fn with_secret(self, id: Uuid, secret: impl Into<Vec<u8>>) -> Self {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(id, secret.into());
        self
    }

    pub fn insert(&self, id: Uuid, secret: impl Into<Vec<u8>>) {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(id, secret.into());
    }

    pub fn read_calls(&self) -> usize {
        self.read_calls.load(Ordering::SeqCst)
    }
}

impl fmt::Debug for FakeFortinetSecretLookup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        let lengths: Vec<(Uuid, usize)> = entries.iter().map(|(k, v)| (*k, v.len())).collect();
        f.debug_struct("FakeFortinetSecretLookup")
            .field("entry_byte_lengths", &lengths)
            .field("read_calls", &self.read_calls.load(Ordering::SeqCst))
            .finish()
    }
}

impl FortinetSecretLookup for FakeFortinetSecretLookup {
    fn read(&self, tunnel_config_id: &Uuid) -> Result<Option<Vec<u8>>, TunnelError> {
        self.read_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(tunnel_config_id)
            .cloned())
    }
}

/// Editor settings deserialized from the DPAPI tunnel blob (C# `FortinetSettings`).
///
/// [`Debug`] redacts password / TOTP — never log these fields.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct FortinetSettings {
    #[serde(default)]
    pub host: String,
    #[serde(default = "default_fortinet_port")]
    pub port: i32,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub realm: Option<String>,
    #[serde(default)]
    pub totp_secret: Option<String>,
    #[serde(default)]
    pub use_single_sign_on: bool,
    #[serde(default = "default_use_external_browser")]
    pub use_external_browser: bool,
    #[serde(default = "default_saml_redirect_port")]
    pub saml_redirect_port: u16,
    #[serde(default)]
    pub trust_server_certificate: bool,
    #[serde(default)]
    pub server_cert_sha256_pin: Option<String>,
}

fn default_fortinet_port() -> i32 {
    443
}

fn default_use_external_browser() -> bool {
    true
}

fn default_saml_redirect_port() -> u16 {
    DEFAULT_SAML_REDIRECT_PORT
}

impl fmt::Debug for FortinetSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FortinetSettings")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &redact_nonempty(&self.password))
            .field("realm", &self.realm)
            .field(
                "totp_secret",
                &self
                    .totp_secret
                    .as_deref()
                    .map(redact_nonempty)
                    .unwrap_or(""),
            )
            .field("use_single_sign_on", &self.use_single_sign_on)
            .field("use_external_browser", &self.use_external_browser)
            .field("saml_redirect_port", &self.saml_redirect_port)
            .field("trust_server_certificate", &self.trust_server_certificate)
            .field(
                "server_cert_sha256_pin",
                &self
                    .server_cert_sha256_pin
                    .as_deref()
                    .map(redact_nonempty)
                    .unwrap_or(""),
            )
            .finish()
    }
}

/// Sidecar stdin JSON (snake_case) for `wormhole-fortiproxy`.
///
/// [`Debug`] redacts password / TOTP / SAML material.
#[derive(Clone, Serialize)]
pub struct FortinetSidecarConfig {
    pub host: String,
    pub port: i32,
    pub username: String,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saml_auth_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub svpn_cookie: Option<String>,
    pub trust_server_certificate: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_cert_sha256_pin: Option<String>,
}

impl fmt::Debug for FortinetSidecarConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FortinetSidecarConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &redact_nonempty(&self.password))
            .field("realm", &self.realm)
            .field(
                "totp_secret",
                &self
                    .totp_secret
                    .as_deref()
                    .map(redact_nonempty)
                    .unwrap_or(""),
            )
            .field(
                "saml_auth_id",
                &self
                    .saml_auth_id
                    .as_deref()
                    .map(redact_nonempty)
                    .unwrap_or(""),
            )
            .field(
                "svpn_cookie",
                &self
                    .svpn_cookie
                    .as_deref()
                    .map(redact_nonempty)
                    .unwrap_or(""),
            )
            .field("trust_server_certificate", &self.trust_server_certificate)
            .field(
                "server_cert_sha256_pin",
                &self
                    .server_cert_sha256_pin
                    .as_deref()
                    .map(redact_nonempty)
                    .unwrap_or(""),
            )
            .finish()
    }
}

impl FortinetSidecarConfig {
    /// Serialize to UTF-8 JSON bytes (never log the result).
    pub fn to_stdin_json(&self) -> Result<Vec<u8>, TunnelError> {
        serde_json::to_vec(self).map_err(|_| {
            TunnelError::Establish("failed to serialize Fortinet sidecar config".into())
        })
    }
}

/// Parse Fortinet editor settings from a DPAPI blob. Never echoes the blob on error.
pub fn parse_fortinet_settings(secret_blob: &[u8]) -> Result<FortinetSettings, TunnelError> {
    if secret_blob.is_empty() {
        return Err(TunnelError::Establish(
            "Fortinet tunnel has an empty secret payload".into(),
        ));
    }
    serde_json::from_slice(secret_blob).map_err(|_| {
        TunnelError::Establish(
            "tunnel secret is not valid FortinetSettings JSON (empty/invalid Fortinet payload)"
                .into(),
        )
    })
}

/// Build sidecar stdin JSON from settings + optional SAML result (C# parity).
///
/// When SSO is on, mirrors C# `SanitizedForAuthenticationMode` + sidecar field
/// rules: clear username/password/TOTP and omit realm (SAML material only).
pub fn build_fortinet_sidecar_config(
    settings: &FortinetSettings,
    saml: Option<&SamlAuthResult>,
) -> FortinetSidecarConfig {
    let (saml_auth_id, svpn_cookie) = match saml {
        Some(SamlAuthResult::AuthId(id)) => (Some(id.as_str().to_owned()), None),
        Some(SamlAuthResult::SvpnCookie(c)) => (None, Some(c.as_str().to_owned())),
        None => (None, None),
    };
    let (username, password, realm, totp_secret) = if settings.use_single_sign_on {
        (String::new(), String::new(), None, None)
    } else {
        (
            settings.username.clone(),
            settings.password.clone(),
            settings.realm.clone(),
            settings.totp_secret.clone(),
        )
    };
    FortinetSidecarConfig {
        host: settings.host.clone(),
        port: settings.port,
        username,
        password,
        realm,
        totp_secret,
        saml_auth_id,
        svpn_cookie,
        trust_server_certificate: settings.trust_server_certificate,
        server_cert_sha256_pin: settings.server_cert_sha256_pin.clone(),
    }
}

fn saml_flow_from_settings(settings: &FortinetSettings) -> Result<SamlAuthFlow, TunnelError> {
    if settings.use_external_browser {
        if settings.saml_redirect_port == 0 {
            return Err(TunnelError::Establish(
                "Fortinet SAML callback port must be between 1 and 65535".into(),
            ));
        }
        Ok(SamlAuthFlow::external_browser(settings.saml_redirect_port))
    } else {
        Ok(SamlAuthFlow::embedded())
    }
}

fn map_saml_error(err: SamlAuthError) -> TunnelError {
    match err {
        SamlAuthError::Cancelled | SamlAuthError::ChannelClosed => TunnelError::Cancelled,
        SamlAuthError::NotImplemented => TunnelError::NotImplemented {
            kind: TunnelKind::Fortinet,
            sidecar: "wormhole-fortiproxy (SAML UI not wired)",
        },
        SamlAuthError::InvalidCallbackPort => TunnelError::Establish(
            "Fortinet SAML callback port must be between 1 and 65535".into(),
        ),
        SamlAuthError::InvalidResult => TunnelError::Establish(
            "Fortinet SAML authentication returned an invalid result".into(),
        ),
        // Failed payload must already be secret-free from callers; do not re-echo
        // through a second channel beyond the message itself.
        SamlAuthError::Failed(msg) => TunnelError::Establish(format!(
            "Fortinet SAML authentication failed: {msg}"
        )),
    }
}

/// Resolve FortinetSettings → sidecar JSON, running the SAML stub when SSO is on.
///
/// Fail-closed preflight mirrors C# `FortinetTunnelProvider` (empty Host, missing
/// username/password when SSO off, external+realm, embedded+pin). SAML UI remains
/// stubbed ([`StubSamlAuthCallback`] / [`FakeSamlAuthCallback`] /
/// [`super::saml::ChannelSamlAuthCallback`] Fake transport — no live WebView2 / OS browser).
pub async fn resolve_fortinet_sidecar_json(
    settings: &FortinetSettings,
    config_name: &str,
    saml: &dyn SamlAuthCallback,
) -> Result<Vec<u8>, TunnelError> {
    if settings.host.trim().is_empty() {
        return Err(TunnelError::Establish(format!(
            "tunnel config '{config_name}' has an unreadable Fortinet payload (empty Host). \
             Open the tunnel editor to re-enter settings."
        )));
    }

    let saml_result = if settings.use_single_sign_on {
        if settings.use_external_browser {
            if let Some(realm) = settings.realm.as_deref() {
                if !realm.trim().is_empty() {
                    return Err(TunnelError::Establish(
                        "External-browser Fortinet SSO does not support realms.".into(),
                    ));
                }
            }
        } else if let Some(pin) = settings.server_cert_sha256_pin.as_deref() {
            if !pin.trim().is_empty() {
                return Err(TunnelError::Establish(
                    "Embedded-browser Fortinet SSO cannot enforce a server certificate pin; \
                     use the external browser or clear the pin."
                        .into(),
                ));
            }
        }

        let flow = saml_flow_from_settings(settings)?;
        let request = SamlAuthRequest::new(config_name, flow);
        Some(
            authenticate(saml, request)
                .await
                .map_err(map_saml_error)?,
        )
    } else if settings.username.trim().is_empty() || settings.password.trim().is_empty() {
        return Err(TunnelError::Establish(format!(
            "tunnel config '{config_name}' requires a username and password when SSO is disabled."
        )));
    } else {
        None
    };

    let sidecar = build_fortinet_sidecar_config(settings, saml_result.as_ref());
    let json = sidecar.to_stdin_json()?;
    require_fortinet_establish_secret(&json, config_name)?;
    Ok(json)
}

/// Load TunnelConfig metadata + Fortinet secret for `config_id`, run auth stubs,
/// then call Fortinet [`TunnelProvider::establish`].
///
/// Fail-closed:
/// - missing config → [`TunnelError::ConfigNotFound`]
/// - kind ≠ Fortinet → [`TunnelError::WrongKind`]
/// - missing secret → [`TunnelError::SecretMissing`]
/// - bad settings / SAML stub failures → [`TunnelError::Establish`] /
///   [`TunnelError::NotImplemented`] / [`TunnelError::Cancelled`] (never echoes secrets)
///
/// `provider.kind()` must be [`TunnelKind::Fortinet`]. Pass [`FakeSamlAuthCallback`]
/// or [`super::saml::ChannelSamlAuthCallback`] (UI Fake transport) in tests; production may wire
/// [`StubSamlAuthCallback`] until WebView2 / OS-browser land, or the channel + host
/// Fake reply surface.
pub async fn establish_fortinet(
    config_id: Uuid,
    configs: &dyn FortinetConfigLookup,
    secrets: &dyn FortinetSecretLookup,
    provider: &dyn TunnelProvider,
    saml: &dyn SamlAuthCallback,
) -> Result<Arc<dyn TunnelInstance>, TunnelError> {
    if provider.kind() != TunnelKind::Fortinet {
        return Err(TunnelError::WrongKind {
            expected: TunnelKind::Fortinet,
            actual: provider.kind(),
        });
    }

    let record = configs
        .get(config_id)?
        .ok_or(TunnelError::ConfigNotFound { id: config_id })?;

    if record.kind != TunnelKind::Fortinet {
        return Err(TunnelError::WrongKind {
            expected: TunnelKind::Fortinet,
            actual: record.kind,
        });
    }

    let secret = secrets
        .read(&config_id)?
        .ok_or(TunnelError::SecretMissing { id: config_id })?;

    let settings = parse_fortinet_settings(&secret)?;
    let sidecar_json = resolve_fortinet_sidecar_json(&settings, &record.name, saml).await?;

    let snapshot = record.to_snapshot();
    tracing::info!(
        tunnel_config_id = %config_id,
        tunnel_name = %snapshot.name,
        use_sso = settings.use_single_sign_on,
        secret_len = secret.len(),
        "establishing Fortinet tunnel from stored config"
    );
    // Never log `secret` / settings password / SAML tokens / stdin JSON.
    provider.establish(&snapshot, &sidecar_json).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::fortinet::saml::{
        ChannelSamlAuthCallback, FakeSamlAuthCallback, SamlPromptResponse, StubSamlAuthCallback,
    };
    use crate::FakeTunnelProvider;
    use std::sync::Arc;

    fn forti_id() -> Uuid {
        Uuid::parse_str("ffffffff-1111-2222-3333-444444444444").unwrap()
    }

    fn settings_with_secret_marker() -> Vec<u8> {
        br#"{"Host":"vpn.example.com","Port":443,"Username":"alice","Password":"SUPER_SECRET_FORTI_PASSWORD"}"#
            .to_vec()
    }

    fn sso_external_settings() -> Vec<u8> {
        br#"{"Host":"vpn.example.com","Port":443,"UseSingleSignOn":true,"UseExternalBrowser":true,"SamlRedirectPort":8020}"#
            .to_vec()
    }

    fn sso_embedded_settings() -> Vec<u8> {
        br#"{"Host":"vpn.example.com","Port":443,"UseSingleSignOn":true,"UseExternalBrowser":false}"#
            .to_vec()
    }

    #[tokio::test]
    async fn establish_loads_metadata_and_secret_via_fake_provider() {
        let id = forti_id();
        let configs = FakeFortinetConfigLookup::new().with_config(
            FortinetConfigRecord::new(id, TunnelKind::Fortinet, "lab-forti"),
        );
        let secrets =
            FakeFortinetSecretLookup::new().with_secret(id, FAKE_FORTINET_SETTINGS_JSON);
        let provider = FakeTunnelProvider::new(TunnelKind::Fortinet);

        let instance =
            establish_fortinet(id, &configs, &secrets, &provider, &StubSamlAuthCallback)
                .await
                .expect("establish");
        assert_eq!(provider.establish_count(), 1);
        assert_eq!(configs.get_calls(), 1);
        assert_eq!(secrets.read_calls(), 1);
        assert_eq!(instance.state(), crate::TunnelState::Up);
        assert!(instance.socks5_endpoint().is_some());
    }

    #[tokio::test]
    async fn missing_config_fails_closed() {
        let id = forti_id();
        let configs = FakeFortinetConfigLookup::new();
        let secrets =
            FakeFortinetSecretLookup::new().with_secret(id, FAKE_FORTINET_SETTINGS_JSON);
        let provider = FakeTunnelProvider::new(TunnelKind::Fortinet);

        let err = establish_fortinet(id, &configs, &secrets, &provider, &StubSamlAuthCallback)
            .await.err().expect("missing config");
        assert!(matches!(err, TunnelError::ConfigNotFound { id: got } if got == id));
        assert_eq!(provider.establish_count(), 0);
        assert_eq!(secrets.read_calls(), 0);
    }

    #[tokio::test]
    async fn missing_secret_fails_closed() {
        let id = forti_id();
        let configs = FakeFortinetConfigLookup::new().with_config(
            FortinetConfigRecord::new(id, TunnelKind::Fortinet, "lab-forti"),
        );
        let secrets = FakeFortinetSecretLookup::new();
        let provider = FakeTunnelProvider::new(TunnelKind::Fortinet);

        let err = establish_fortinet(id, &configs, &secrets, &provider, &StubSamlAuthCallback)
            .await.err().expect("missing secret");
        assert!(matches!(err, TunnelError::SecretMissing { id: got } if got == id));
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn empty_secret_fails_before_provider() {
        let id = forti_id();
        let configs = FakeFortinetConfigLookup::new().with_config(
            FortinetConfigRecord::new(id, TunnelKind::Fortinet, "lab-forti"),
        );
        let secrets = FakeFortinetSecretLookup::new().with_secret(id, Vec::<u8>::new());
        let provider = FakeTunnelProvider::new(TunnelKind::Fortinet);

        let err = establish_fortinet(id, &configs, &secrets, &provider, &StubSamlAuthCallback)
            .await.err().expect("empty secret");
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
        assert!(format!("{err}").contains("empty"), "{err}");
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn wrong_config_kind_fails_closed() {
        let id = forti_id();
        let configs = FakeFortinetConfigLookup::new().with_config(
            FortinetConfigRecord::new(id, TunnelKind::WireGuard, "not-forti"),
        );
        let secrets =
            FakeFortinetSecretLookup::new().with_secret(id, FAKE_FORTINET_SETTINGS_JSON);
        let provider = FakeTunnelProvider::new(TunnelKind::Fortinet);

        let err = establish_fortinet(id, &configs, &secrets, &provider, &StubSamlAuthCallback)
            .await.err().expect("wrong kind");
        assert!(matches!(
            err,
            TunnelError::WrongKind {
                expected: TunnelKind::Fortinet,
                actual: TunnelKind::WireGuard
            }
        ));
        assert_eq!(provider.establish_count(), 0);
        assert_eq!(secrets.read_calls(), 0);
    }

    #[tokio::test]
    async fn wrong_provider_kind_fails_closed() {
        let id = forti_id();
        let configs = FakeFortinetConfigLookup::new().with_config(
            FortinetConfigRecord::new(id, TunnelKind::Fortinet, "lab-forti"),
        );
        let secrets =
            FakeFortinetSecretLookup::new().with_secret(id, FAKE_FORTINET_SETTINGS_JSON);
        let provider = FakeTunnelProvider::new(TunnelKind::WireGuard);

        let err = establish_fortinet(id, &configs, &secrets, &provider, &StubSamlAuthCallback)
            .await.err().expect("wrong provider");
        assert!(matches!(
            err,
            TunnelError::WrongKind {
                expected: TunnelKind::Fortinet,
                actual: TunnelKind::WireGuard
            }
        ));
        assert_eq!(provider.establish_count(), 0);
        assert_eq!(configs.get_calls(), 0);
    }

    #[tokio::test]
    async fn empty_host_rejects_without_echoing_password() {
        let id = forti_id();
        let configs = FakeFortinetConfigLookup::new().with_config(
            FortinetConfigRecord::new(id, TunnelKind::Fortinet, "lab-forti"),
        );
        let secrets = FakeFortinetSecretLookup::new().with_secret(
            id,
            br#"{"Host":"","Username":"alice","Password":"SUPER_SECRET_FORTI_PASSWORD"}"#,
        );
        let provider = FakeTunnelProvider::new(TunnelKind::Fortinet);

        let err = establish_fortinet(id, &configs, &secrets, &provider, &StubSamlAuthCallback)
            .await.err().expect("empty host");
        let rendered = format!("{err} / {err:?}");
        assert!(rendered.contains("Host") || rendered.contains("empty"), "{rendered}");
        assert!(
            !rendered.contains("SUPER_SECRET_FORTI_PASSWORD"),
            "must not echo secret: {rendered}"
        );
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn password_path_rejects_missing_credentials_without_echo() {
        let id = forti_id();
        let configs = FakeFortinetConfigLookup::new().with_config(
            FortinetConfigRecord::new(id, TunnelKind::Fortinet, "lab-forti"),
        );
        let secrets = FakeFortinetSecretLookup::new().with_secret(
            id,
            br#"{"Host":"vpn.example.com","Username":"alice","Password":""}"#,
        );
        let provider = FakeTunnelProvider::new(TunnelKind::Fortinet);

        let err = establish_fortinet(id, &configs, &secrets, &provider, &StubSamlAuthCallback)
            .await.err().expect("missing password");
        assert!(format!("{err}").contains("username and password"), "{err}");
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn sso_with_fake_saml_auth_id_establishes() {
        let id = forti_id();
        let configs = FakeFortinetConfigLookup::new().with_config(
            FortinetConfigRecord::new(id, TunnelKind::Fortinet, "sso-forti"),
        );
        let secrets = FakeFortinetSecretLookup::new().with_secret(id, sso_external_settings());
        let provider = FakeTunnelProvider::new(TunnelKind::Fortinet);
        let fake_saml = FakeSamlAuthCallback::new();
        fake_saml.push_auth_id("ephemeral-auth-id-SECRET");

        let instance = establish_fortinet(id, &configs, &secrets, &provider, &fake_saml)
            .await
            .expect("sso establish");
        assert_eq!(provider.establish_count(), 1);
        assert_eq!(fake_saml.complete_count(), 1);
        assert_eq!(instance.state(), crate::TunnelState::Up);
        assert_eq!(
            fake_saml.requests()[0].flow,
            SamlAuthFlow::ExternalBrowser {
                callback_port: 8020
            }
        );
    }

    #[tokio::test]
    async fn sso_with_fake_saml_cookie_establishes() {
        let id = forti_id();
        let configs = FakeFortinetConfigLookup::new().with_config(
            FortinetConfigRecord::new(id, TunnelKind::Fortinet, "embedded-forti"),
        );
        let secrets = FakeFortinetSecretLookup::new().with_secret(id, sso_embedded_settings());
        let provider = FakeTunnelProvider::new(TunnelKind::Fortinet);
        let fake_saml = FakeSamlAuthCallback::new();
        fake_saml.push_svpn_cookie("SVPNCOOKIE-SECRET-VALUE");

        let instance = establish_fortinet(id, &configs, &secrets, &provider, &fake_saml)
            .await
            .expect("embedded sso");
        assert_eq!(provider.establish_count(), 1);
        assert_eq!(fake_saml.complete_count(), 1);
        assert!(fake_saml.requests()[0].flow.is_embedded());
        assert_eq!(instance.state(), crate::TunnelState::Up);
    }

    #[tokio::test]
    async fn stub_saml_returns_not_implemented_without_provider_call() {
        let id = forti_id();
        let configs = FakeFortinetConfigLookup::new().with_config(
            FortinetConfigRecord::new(id, TunnelKind::Fortinet, "sso-forti"),
        );
        let secrets = FakeFortinetSecretLookup::new().with_secret(id, sso_external_settings());
        let provider = FakeTunnelProvider::new(TunnelKind::Fortinet);

        let err = establish_fortinet(id, &configs, &secrets, &provider, &StubSamlAuthCallback)
            .await.err().expect("saml stub");
        assert!(
            matches!(
                err,
                TunnelError::NotImplemented {
                    kind: TunnelKind::Fortinet,
                    ..
                }
            ),
            "{err:?}"
        );
        assert_eq!(provider.establish_count(), 0);
        let rendered = format!("{err}");
        assert!(rendered.contains("not implemented") || rendered.contains("SAML"), "{rendered}");
    }

    #[tokio::test]
    async fn embedded_sso_with_cert_pin_fails_before_saml() {
        let id = forti_id();
        let configs = FakeFortinetConfigLookup::new().with_config(
            FortinetConfigRecord::new(id, TunnelKind::Fortinet, "pin-forti"),
        );
        let pin = "A".repeat(64);
        let blob = format!(
            r#"{{"Host":"vpn.example.com","UseSingleSignOn":true,"UseExternalBrowser":false,"ServerCertSha256Pin":"{pin}"}}"#
        );
        let secrets = FakeFortinetSecretLookup::new().with_secret(id, blob.into_bytes());
        let provider = FakeTunnelProvider::new(TunnelKind::Fortinet);
        let fake_saml = FakeSamlAuthCallback::new();
        fake_saml.push_svpn_cookie("should-not-be-consumed");

        let err = establish_fortinet(id, &configs, &secrets, &provider, &fake_saml)
            .await.err().expect("pin + embedded");
        assert!(format!("{err}").contains("certificate pin"), "{err}");
        assert_eq!(fake_saml.complete_count(), 0);
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn external_sso_with_realm_fails_before_saml() {
        let id = forti_id();
        let configs = FakeFortinetConfigLookup::new().with_config(
            FortinetConfigRecord::new(id, TunnelKind::Fortinet, "realm-forti"),
        );
        let secrets = FakeFortinetSecretLookup::new().with_secret(
            id,
            br#"{"Host":"vpn.example.com","UseSingleSignOn":true,"UseExternalBrowser":true,"Realm":"corp"}"#,
        );
        let provider = FakeTunnelProvider::new(TunnelKind::Fortinet);
        let fake_saml = FakeSamlAuthCallback::new();
        fake_saml.push_auth_id("should-not-be-consumed");

        let err = establish_fortinet(id, &configs, &secrets, &provider, &fake_saml)
            .await.err().expect("realm + external");
        assert!(format!("{err}").contains("realm"), "{err}");
        assert_eq!(fake_saml.complete_count(), 0);
        assert_eq!(provider.establish_count(), 0);
    }

    #[test]
    fn settings_and_sidecar_debug_redact_secrets() {
        let settings = parse_fortinet_settings(
            br#"{"Host":"vpn.example.com","Username":"alice","Password":"SUPER_SECRET_FORTI_PASSWORD","TotpSecret":"TOTP_SECRET_MARKER"}"#,
        )
        .unwrap();
        let dbg = format!("{settings:?}");
        assert!(dbg.contains("[REDACTED]"), "{dbg}");
        assert!(!dbg.contains("SUPER_SECRET_FORTI_PASSWORD"), "{dbg}");
        assert!(!dbg.contains("TOTP_SECRET_MARKER"), "{dbg}");

        let sidecar = build_fortinet_sidecar_config(&settings, None);
        let sdbg = format!("{sidecar:?}");
        assert!(sdbg.contains("[REDACTED]"), "{sdbg}");
        assert!(!sdbg.contains("SUPER_SECRET_FORTI_PASSWORD"), "{sdbg}");
        assert!(!sdbg.contains("TOTP_SECRET_MARKER"), "{sdbg}");
    }

    #[test]
    fn saml_sidecar_debug_redacts_auth_id_and_cookie() {
        let settings = parse_fortinet_settings(FAKE_FORTINET_SETTINGS_JSON).unwrap();
        let auth = build_fortinet_sidecar_config(
            &settings,
            Some(&SamlAuthResult::from_auth_id("AUTH_ID_SECRET_MARKER")),
        );
        let cookie = build_fortinet_sidecar_config(
            &settings,
            Some(&SamlAuthResult::from_svpn_cookie("SVPNCOOKIE_SECRET_MARKER")),
        );
        let a = format!("{auth:?}");
        let c = format!("{cookie:?}");
        assert!(a.contains("[REDACTED]"), "{a}");
        assert!(!a.contains("AUTH_ID_SECRET_MARKER"), "{a}");
        assert!(c.contains("[REDACTED]"), "{c}");
        assert!(!c.contains("SVPNCOOKIE_SECRET_MARKER"), "{c}");
    }

    #[tokio::test]
    async fn sso_resolve_clears_password_totp_and_carries_auth_id() {
        // External + non-empty Realm is rejected earlier; password/TOTP leftovers must
        // still be wiped from sidecar JSON when SSO succeeds.
        let settings = parse_fortinet_settings(
            br#"{"Host":"vpn.example.com","Username":"alice","Password":"SUPER_SECRET_FORTI_PASSWORD","TotpSecret":"TOTP_SECRET_MARKER","UseSingleSignOn":true,"UseExternalBrowser":true,"SamlRedirectPort":8020}"#,
        )
        .unwrap();
        let fake = FakeSamlAuthCallback::new();
        fake.push_auth_id("AUTH_ID_SECRET_MARKER");

        let json = resolve_fortinet_sidecar_json(&settings, "sso-lab", &fake)
            .await
            .expect("sso resolve");
        require_fortinet_establish_secret(&json, "sso-lab").unwrap();
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(v["host"], "vpn.example.com");
        assert_eq!(v["username"], "");
        assert_eq!(v["password"], "");
        assert!(v.get("totp_secret").is_none() || v["totp_secret"].is_null());
        assert_eq!(v["saml_auth_id"], "AUTH_ID_SECRET_MARKER");
        assert!(v.get("svpn_cookie").is_none() || v["svpn_cookie"].is_null());

        let sidecar = build_fortinet_sidecar_config(
            &settings,
            Some(&SamlAuthResult::from_auth_id("AUTH_ID_SECRET_MARKER")),
        );
        let dbg = format!("{sidecar:?}");
        assert!(!dbg.contains("SUPER_SECRET_FORTI_PASSWORD"), "{dbg}");
        assert!(!dbg.contains("TOTP_SECRET_MARKER"), "{dbg}");
        assert!(!dbg.contains("AUTH_ID_SECRET_MARKER"), "{dbg}");
    }

    #[test]
    fn sso_build_clears_realm_even_when_settings_still_carry_one() {
        // Embedded SSO allows a stored Realm through preflight; sidecar must still omit it.
        let settings = parse_fortinet_settings(
            br#"{"Host":"vpn.example.com","Realm":"corp","UseSingleSignOn":true,"UseExternalBrowser":false}"#,
        )
        .unwrap();
        let sidecar = build_fortinet_sidecar_config(
            &settings,
            Some(&SamlAuthResult::from_svpn_cookie("c")),
        );
        let json = sidecar.to_stdin_json().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert!(v.get("realm").is_none() || v["realm"].is_null());
        assert_eq!(v["password"], "");
        assert_eq!(v["username"], "");
    }

    #[tokio::test]
    async fn sso_embedded_resolve_carries_cookie_without_debug_echo() {
        let settings = parse_fortinet_settings(&sso_embedded_settings()).unwrap();
        let fake = FakeSamlAuthCallback::new();
        fake.push_svpn_cookie("SVPNCOOKIE_SECRET_MARKER");

        let json = resolve_fortinet_sidecar_json(&settings, "embedded-lab", &fake)
            .await
            .expect("embedded resolve");
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(v["svpn_cookie"], "SVPNCOOKIE_SECRET_MARKER");
        assert!(v.get("saml_auth_id").is_none() || v["saml_auth_id"].is_null());
        assert_eq!(v["password"], "");

        let sidecar = build_fortinet_sidecar_config(
            &settings,
            Some(&SamlAuthResult::from_svpn_cookie("SVPNCOOKIE_SECRET_MARKER")),
        );
        assert!(!format!("{sidecar:?}").contains("SVPNCOOKIE_SECRET_MARKER"));
    }

    #[tokio::test]
    async fn saml_cancelled_maps_without_provider_call() {
        let id = forti_id();
        let configs = FakeFortinetConfigLookup::new().with_config(
            FortinetConfigRecord::new(id, TunnelKind::Fortinet, "sso-forti"),
        );
        let secrets = FakeFortinetSecretLookup::new().with_secret(id, sso_external_settings());
        let provider = FakeTunnelProvider::new(TunnelKind::Fortinet);
        // Empty Fake queue → Cancelled.
        let fake_saml = FakeSamlAuthCallback::new();

        let err = establish_fortinet(id, &configs, &secrets, &provider, &fake_saml)
            .await
            .err()
            .expect("cancelled");
        assert!(matches!(err, TunnelError::Cancelled), "{err:?}");
        assert_eq!(provider.establish_count(), 0);
        assert_eq!(fake_saml.complete_count(), 1);
    }

    #[tokio::test]
    async fn channel_saml_auth_id_establishes_via_oneshot() {
        let id = forti_id();
        let configs = Arc::new(FakeFortinetConfigLookup::new().with_config(
            FortinetConfigRecord::new(id, TunnelKind::Fortinet, "sso-channel"),
        ));
        let secrets = Arc::new(
            FakeFortinetSecretLookup::new().with_secret(id, sso_external_settings()),
        );
        let provider = Arc::new(FakeTunnelProvider::new(TunnelKind::Fortinet));
        let channel = Arc::new(ChannelSamlAuthCallback::new());
        let mut rx = channel.open_channel();

        let task = tokio::spawn({
            let configs = Arc::clone(&configs);
            let secrets = Arc::clone(&secrets);
            let provider = Arc::clone(&provider);
            let channel = Arc::clone(&channel);
            async move {
                establish_fortinet(
                    id,
                    configs.as_ref(),
                    secrets.as_ref(),
                    provider.as_ref(),
                    channel.as_ref(),
                )
                .await
            }
        });

        let pending = rx.recv().await.expect("pending SAML");
        assert_eq!(pending.request.config_name, "sso-channel");
        pending
            .respond
            .send(SamlPromptResponse::from_auth_id("CHANNEL_AUTH_ID_SECRET"))
            .unwrap();

        let instance = task.await.unwrap().expect("establish");
        assert_eq!(instance.state(), crate::TunnelState::Up);
        assert_eq!(provider.establish_count(), 1);
        assert_eq!(channel.complete_count(), 1);
        assert!(!format!("{channel:?}").contains("CHANNEL_AUTH_ID_SECRET"));
    }

    #[tokio::test]
    async fn channel_saml_cancel_fail_closed_before_provider() {
        let id = forti_id();
        let configs = Arc::new(FakeFortinetConfigLookup::new().with_config(
            FortinetConfigRecord::new(id, TunnelKind::Fortinet, "sso-cancel"),
        ));
        let secrets = Arc::new(
            FakeFortinetSecretLookup::new().with_secret(id, sso_external_settings()),
        );
        let provider = Arc::new(FakeTunnelProvider::new(TunnelKind::Fortinet));
        let channel = Arc::new(ChannelSamlAuthCallback::new());
        let mut rx = channel.open_channel();

        let task = tokio::spawn({
            let configs = Arc::clone(&configs);
            let secrets = Arc::clone(&secrets);
            let provider = Arc::clone(&provider);
            let channel = Arc::clone(&channel);
            async move {
                establish_fortinet(
                    id,
                    configs.as_ref(),
                    secrets.as_ref(),
                    provider.as_ref(),
                    channel.as_ref(),
                )
                .await
            }
        });

        let pending = rx.recv().await.expect("pending");
        pending
            .respond
            .send(SamlPromptResponse::Cancelled)
            .unwrap();
        let err = match task.await.expect("join") {
            Ok(_) => panic!("expected cancel"),
            Err(e) => e,
        };
        assert!(matches!(err, TunnelError::Cancelled), "{err:?}");
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn channel_auto_cancel_before_open_fail_closed() {
        let id = forti_id();
        let configs = FakeFortinetConfigLookup::new().with_config(
            FortinetConfigRecord::new(id, TunnelKind::Fortinet, "sso-auto"),
        );
        let secrets = FakeFortinetSecretLookup::new().with_secret(id, sso_external_settings());
        let provider = FakeTunnelProvider::new(TunnelKind::Fortinet);
        let channel = ChannelSamlAuthCallback::new(); // no open_channel

        let err = match establish_fortinet(id, &configs, &secrets, &provider, &channel).await {
            Ok(_) => panic!("expected cancel"),
            Err(e) => e,
        };
        assert!(matches!(err, TunnelError::Cancelled), "{err:?}");
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn saml_mismatched_credential_fails_without_echoing_cookie() {
        let id = forti_id();
        let configs = FakeFortinetConfigLookup::new().with_config(
            FortinetConfigRecord::new(id, TunnelKind::Fortinet, "sso-forti"),
        );
        let secrets = FakeFortinetSecretLookup::new().with_secret(id, sso_external_settings());
        let provider = FakeTunnelProvider::new(TunnelKind::Fortinet);
        let fake_saml = FakeSamlAuthCallback::new();
        // External flow expects auth_id; cookie → InvalidResult.
        fake_saml.push_svpn_cookie("SVPNCOOKIE_SECRET_MARKER");

        let err = establish_fortinet(id, &configs, &secrets, &provider, &fake_saml)
            .await
            .err()
            .expect("invalid result");
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
        let rendered = format!("{err} / {err:?}");
        assert!(
            rendered.contains("invalid") || rendered.contains("SAML"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("SVPNCOOKIE_SECRET_MARKER"),
            "must not echo cookie: {rendered}"
        );
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn whitespace_host_rejects_without_echoing_password() {
        let id = forti_id();
        let configs = FakeFortinetConfigLookup::new().with_config(
            FortinetConfigRecord::new(id, TunnelKind::Fortinet, "lab-forti"),
        );
        let secrets = FakeFortinetSecretLookup::new().with_secret(
            id,
            br#"{"Host":"   ","Username":"alice","Password":"SUPER_SECRET_FORTI_PASSWORD"}"#,
        );
        let provider = FakeTunnelProvider::new(TunnelKind::Fortinet);

        let err = establish_fortinet(id, &configs, &secrets, &provider, &StubSamlAuthCallback)
            .await
            .err()
            .expect("whitespace host");
        let rendered = format!("{err} / {err:?}");
        assert!(rendered.contains("Host") || rendered.contains("empty"), "{rendered}");
        assert!(
            !rendered.contains("SUPER_SECRET_FORTI_PASSWORD"),
            "must not echo secret: {rendered}"
        );
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn snake_case_sidecar_blob_as_settings_fails_closed() {
        let id = forti_id();
        let configs = FakeFortinetConfigLookup::new().with_config(
            FortinetConfigRecord::new(id, TunnelKind::Fortinet, "lab-forti"),
        );
        // Sidecar JSON uses `host` — FortinetSettings expects PascalCase `Host` → empty Host.
        let secrets =
            FakeFortinetSecretLookup::new().with_secret(id, FAKE_FORTINET_SIDECAR_JSON);
        let provider = FakeTunnelProvider::new(TunnelKind::Fortinet);

        let err = establish_fortinet(id, &configs, &secrets, &provider, &StubSamlAuthCallback)
            .await
            .err()
            .expect("wrong shape");
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
        assert!(format!("{err}").contains("Host") || format!("{err}").contains("empty"), "{err}");
        assert_eq!(provider.establish_count(), 0);
    }

    #[test]
    fn invalid_settings_json_does_not_echo_secret() {
        let err = parse_fortinet_settings(
            br#"{"Host":"vpn.example.com","Password":"SUPER_SECRET_FORTI_PASSWORD""#,
        )
        .expect_err("malformed JSON");
        let rendered = format!("{err} / {err:?}");
        assert!(rendered.contains("FortinetSettings") || rendered.contains("JSON"), "{rendered}");
        assert!(
            !rendered.contains("SUPER_SECRET_FORTI_PASSWORD"),
            "must not echo secret: {rendered}"
        );
    }

    #[tokio::test]
    async fn external_sso_port_zero_fails_before_saml() {
        let id = forti_id();
        let configs = FakeFortinetConfigLookup::new().with_config(
            FortinetConfigRecord::new(id, TunnelKind::Fortinet, "port-forti"),
        );
        let secrets = FakeFortinetSecretLookup::new().with_secret(
            id,
            br#"{"Host":"vpn.example.com","UseSingleSignOn":true,"UseExternalBrowser":true,"SamlRedirectPort":0}"#,
        );
        let provider = FakeTunnelProvider::new(TunnelKind::Fortinet);
        let fake_saml = FakeSamlAuthCallback::new();
        fake_saml.push_auth_id("should-not-be-consumed");

        let err = establish_fortinet(id, &configs, &secrets, &provider, &fake_saml)
            .await
            .err()
            .expect("port 0");
        assert!(format!("{err}").contains("port") || format!("{err}").contains("1 and 65535"), "{err}");
        assert_eq!(fake_saml.complete_count(), 0);
        assert_eq!(provider.establish_count(), 0);
    }

    #[test]
    fn fake_secret_lookup_debug_redacts_payload() {
        let id = forti_id();
        let secrets =
            FakeFortinetSecretLookup::new().with_secret(id, settings_with_secret_marker());
        let dbg = format!("{secrets:?}");
        assert!(!dbg.contains("SUPER_SECRET"));
        assert!(!dbg.contains("Password"));
        assert!(dbg.contains("entry_byte_lengths"));
    }

    #[test]
    fn build_sidecar_matches_fake_shape() {
        let settings = parse_fortinet_settings(FAKE_FORTINET_SETTINGS_JSON).unwrap();
        let json = build_fortinet_sidecar_config(&settings, None)
            .to_stdin_json()
            .unwrap();
        require_fortinet_establish_secret(&json, "lab").unwrap();
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(v["host"], "vpn.example.com");
        assert_eq!(v["username"], "alice");
        assert!(v.get("Host").is_none());
    }

    #[cfg(feature = "secrets")]
    #[tokio::test]
    async fn payload_store_adapter_establish_with_fake_store() {
        use wormhole_secrets_win::{FakeTunnelPayloadStore, TunnelPayloadStore};

        let id = forti_id();
        let configs = FakeFortinetConfigLookup::new().with_config(
            FortinetConfigRecord::new(id, TunnelKind::Fortinet, "lab-forti"),
        );
        let store = FakeTunnelPayloadStore::new();
        store
            .store(&id, FAKE_FORTINET_SETTINGS_JSON)
            .expect("store");
        let secrets = FortinetPayloadStoreSecretLookup::new(store);
        let provider = FakeTunnelProvider::new(TunnelKind::Fortinet);

        let instance =
            establish_fortinet(id, &configs, &secrets, &provider, &StubSamlAuthCallback)
                .await
                .expect("establish via payload store");
        assert_eq!(provider.establish_count(), 1);
        assert_eq!(instance.state(), crate::TunnelState::Up);

        // FakeTunnelPayloadStore Debug is length-only — never password / settings JSON.
        let dbg = format!("{secrets:?}");
        assert!(!dbg.contains("SUPER_SECRET"));
        assert!(!dbg.contains("Password"));
        assert!(!dbg.contains(r#""password""#));
        assert!(!dbg.contains("alice"));
    }
}
