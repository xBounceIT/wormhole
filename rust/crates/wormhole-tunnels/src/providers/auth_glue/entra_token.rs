//! Azure VPN Entra ID access-token stub (UI-independent).
//!
//! Mirrors C# `IAzureVpnAuthService` / `AzureVpnTokenResult` / `AzureVpnTokenCache` path:
//! the gateway authenticates OpenVPN `auth-user-pass` with username
//! [`AZURE_AAD_USERNAME`](super::AZURE_AAD_USERNAME) (`AzureAD`) and the Entra **access
//! token** as the password. A DPAPI-cached **refresh** token (see
//! [`super::entra_refresh_cache`]) lets the next connect skip the interactive Microsoft
//! popup.
//!
//! **Wiring today:** interactive WebView2 / WinRT OAuth popup is **not** implemented.
//! [`EntraTokenProvider`] + [`MemoryEntraTokenProvider`] / [`FakeEntraTokenProvider`] are
//! the test / headless surface; Azure `establish` still takes already-resolved
//! [`ResolvedOvpnMaterials`](super::ResolvedOvpnMaterials) / stdin JSON. Call
//! [`request_entra_access_token`] then [`azure_materials_from_entra`] when the provider
//! path is ported. Persist refresh via
//! [`persist_entra_refresh_token`](super::persist_entra_refresh_token) /
//! [`AzureVpnRefreshTokenCache`](super::AzureVpnRefreshTokenCache).
//!
//! Never log access or refresh tokens. [`AccessToken`] / [`RefreshToken`] /
//! [`EntraTokenResult`] / [`MemoryEntraTokenProvider`] [`Debug`] (and token [`Display`])
//! redact values.

use std::collections::VecDeque;
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use uuid::Uuid;

use super::builders::{azure_materials_from_access_token, ResolvedOvpnMaterials, AZURE_AAD_USERNAME};
use super::redact_nonempty;
use crate::TunnelError;

/// Entra access token — sent as the OpenVPN `auth-user-pass` **password**.
///
/// Username is always [`AZURE_AAD_USERNAME`] (`AzureAD`). Prefer
/// [`AccessToken::into_inner`] / [`as_str`](AccessToken::as_str) only at the auth-glue /
/// sidecar stdin boundary (never pass into tracing fields).
#[derive(Clone, PartialEq, Eq)]
pub struct AccessToken(String);

impl AccessToken {
    /// Wrap a raw access token (caller may still need to trim via [`request_entra_access_token`]).
    pub fn new(token: impl Into<String>) -> Self {
        Self(token.into())
    }

    /// Borrow the plaintext (do not log).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume into the plaintext string (do not log).
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AccessToken")
            .field(&redact_nonempty(&self.0))
            .finish()
    }
}

impl fmt::Display for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(redact_nonempty(&self.0))
    }
}

/// Entra refresh token — DPAPI-cached for silent redeem (never the OpenVPN password).
#[derive(Clone, PartialEq, Eq)]
pub struct RefreshToken(String);

impl RefreshToken {
    pub fn new(token: impl Into<String>) -> Self {
        Self(token.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Debug for RefreshToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RefreshToken")
            .field(&redact_nonempty(&self.0))
            .finish()
    }
}

impl fmt::Display for RefreshToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(redact_nonempty(&self.0))
    }
}

/// Outcome of Entra token acquisition (parity with C# `AzureVpnTokenResult`).
///
/// - [`access_token`](EntraTokenResult::access_token) → OpenVPN password
/// - [`refresh_token`](EntraTokenResult::refresh_token) → optional
///   [`super::persist_entra_refresh_token`] cache write
#[derive(Clone, PartialEq, Eq)]
pub struct EntraTokenResult {
    pub access_token: AccessToken,
    pub refresh_token: Option<RefreshToken>,
}

impl EntraTokenResult {
    pub fn new(
        access_token: impl Into<String>,
        refresh_token: Option<impl Into<String>>,
    ) -> Self {
        Self {
            access_token: AccessToken::new(access_token),
            refresh_token: refresh_token.map(|t| RefreshToken::new(t)),
        }
    }

    pub fn access_only(access_token: impl Into<String>) -> Self {
        Self {
            access_token: AccessToken::new(access_token),
            refresh_token: None,
        }
    }
}

impl fmt::Debug for EntraTokenResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntraTokenResult")
            .field("access_token", &self.access_token)
            .field("refresh_token", &self.refresh_token)
            .finish()
    }
}

/// Non-secret Entra request metadata (mirrors settings fields used for identity / UI title).
///
/// Does **not** carry refresh tokens or client secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntraTokenRequest {
    pub tunnel_config_id: Uuid,
    pub config_name: String,
    pub tenant_id: String,
    pub audience: String,
    pub client_id: String,
}

impl EntraTokenRequest {
    pub fn new(
        tunnel_config_id: Uuid,
        config_name: impl Into<String>,
        tenant_id: impl Into<String>,
        audience: impl Into<String>,
        client_id: impl Into<String>,
    ) -> Self {
        Self {
            tunnel_config_id,
            config_name: config_name.into(),
            tenant_id: tenant_id.into(),
            audience: audience.into(),
            client_id: client_id.into(),
        }
    }
}

/// Errors from the Entra token transport (not user dismiss alone — see
/// [`EntraTokenResponse::Cancelled`]).
#[derive(Debug, thiserror::Error)]
pub enum EntraTokenError {
    /// Caller cancellation / shutdown.
    #[error("Entra token acquisition cancelled")]
    Cancelled,
    /// Future channel / UI host mode: no listener.
    #[error("Entra token provider channel closed")]
    ChannelClosed,
}

/// Outcome of a single acquisition attempt (scripted / UI).
#[derive(Clone, PartialEq, Eq)]
pub enum EntraTokenResponse {
    /// Tokens acquired (access may still be empty/whitespace; [`request_entra_access_token`] rejects that).
    Acquired(EntraTokenResult),
    /// User dismissed the Microsoft sign-in popup (parity with C# `UserInteractionCancelledException`).
    Cancelled,
}

impl fmt::Debug for EntraTokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Acquired(result) => f.debug_tuple("Acquired").field(result).finish(),
            Self::Cancelled => f.write_str("Cancelled"),
        }
    }
}

/// UI-independent Entra access-token source — mirrors C# auth + silent-refresh surface.
///
/// Implementations must **never** write access or refresh tokens to logs or tracing.
/// Interactive WebView2 is **not** wired; use [`MemoryEntraTokenProvider`] in tests.
#[async_trait]
pub trait EntraTokenProvider: Send + Sync {
    async fn acquire(
        &self,
        request: EntraTokenRequest,
    ) -> Result<EntraTokenResponse, EntraTokenError>;
}

/// Provider hook: acquire a trimmed non-empty access token for OpenVPN password use.
///
/// Maps:
/// - user dismiss → [`TunnelError::Cancelled`]
/// - empty/whitespace access token after trim → [`TunnelError::Establish`]
/// - transport cancel / closed → [`TunnelError::Cancelled`]
///
/// Returns **only** the access token (OpenVPN password). Any refresh token on
/// [`EntraTokenResult`] is discarded here — call
/// [`super::persist_entra_refresh_token`] after [`EntraTokenProvider::acquire`]
/// when the refresh should be cached. Never logs tokens. OpenVPN username remains
/// [`AZURE_AAD_USERNAME`] via [`azure_materials_from_entra`] /
/// [`AzureVpnAuthGlue`](super::AzureVpnAuthGlue).
pub async fn request_entra_access_token(
    provider: &dyn EntraTokenProvider,
    request: EntraTokenRequest,
) -> Result<AccessToken, TunnelError> {
    // Metadata only — never attach token fields.
    tracing::debug!(
        tunnel_config_id = %request.tunnel_config_id,
        config_name = %request.config_name,
        tenant_id = %request.tenant_id,
        "requesting Entra access token (interactive WebView2 not wired)"
    );

    let response = provider.acquire(request).await.map_err(|e| match e {
        EntraTokenError::Cancelled | EntraTokenError::ChannelClosed => TunnelError::Cancelled,
    })?;

    match response {
        EntraTokenResponse::Cancelled => Err(TunnelError::Cancelled),
        EntraTokenResponse::Acquired(result) => {
            // Refresh is intentionally dropped here — persist via AzureVpnRefreshTokenCache.
            let EntraTokenResult {
                access_token,
                refresh_token: _,
            } = result;
            let raw = access_token.into_inner();
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(TunnelError::Establish(
                    "Entra token provider returned an empty access token".into(),
                ));
            }
            Ok(AccessToken::new(trimmed))
        }
    }
}

/// Build OpenVPN materials: username [`AZURE_AAD_USERNAME`], password = access token.
pub fn azure_materials_from_entra(
    profile_ovpn: impl Into<String>,
    access_token: &AccessToken,
) -> ResolvedOvpnMaterials {
    azure_materials_from_access_token(profile_ovpn, access_token.as_str())
}

/// `%LOCALAPPDATA%\Wormhole\azurevpn-cache\<id:N>.tokencache` path helper.
///
/// Parity with C# `AzureVpnTokenCache` / `AppPaths.GetAzureVpnCacheDirectory`.
/// Persist / load / clear live in [`super::entra_refresh_cache`] (DPAPI + Fake);
/// this returns the on-disk path only. When feature `secrets` is on, delegates to
/// `wormhole_secrets_win::azure_vpn_token_cache_path`.
pub fn azure_vpn_refresh_token_cache_path(tunnel_config_id: &Uuid) -> PathBuf {
    #[cfg(feature = "secrets")]
    {
        wormhole_secrets_win::azure_vpn_token_cache_path(tunnel_config_id)
    }
    #[cfg(not(feature = "secrets"))]
    {
        local_app_data()
            .join("Wormhole")
            .join("azurevpn-cache")
            .join(format!("{}.tokencache", tunnel_config_id.simple()))
    }
}

#[cfg(not(feature = "secrets"))]
fn local_app_data() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("USERPROFILE").map(|p| PathBuf::from(p).join("AppData").join("Local"))
        })
        .unwrap_or_else(|| PathBuf::from(r"C:\Users\Default\AppData\Local"))
}

/// Always returns user-cancel. Fail-closed default until a UI or test harness is attached.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullEntraTokenProvider;

#[async_trait]
impl EntraTokenProvider for NullEntraTokenProvider {
    async fn acquire(
        &self,
        _request: EntraTokenRequest,
    ) -> Result<EntraTokenResponse, EntraTokenError> {
        Ok(EntraTokenResponse::Cancelled)
    }
}

/// Scripted / in-memory Entra token provider for unit tests.
///
/// Each [`acquire`](EntraTokenProvider::acquire) dequeues the next queued response.
/// Queue empty → user-cancel (`Cancelled`).
///
/// [`Debug`] redacts queued tokens (never dump script plaintext).
#[derive(Default)]
pub struct MemoryEntraTokenProvider {
    script: Mutex<VecDeque<Option<EntraTokenResult>>>,
    requests: Mutex<Vec<EntraTokenRequest>>,
    acquire_count: AtomicUsize,
}

impl fmt::Debug for MemoryEntraTokenProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let script = self.script.lock().unwrap_or_else(|p| p.into_inner());
        let redacted_script: Vec<Option<&str>> = script
            .iter()
            .map(|slot| match slot {
                Some(_) => Some("[REDACTED]"),
                None => None,
            })
            .collect();
        let requests = self.requests.lock().unwrap_or_else(|p| p.into_inner());
        f.debug_struct("MemoryEntraTokenProvider")
            .field("script", &redacted_script)
            .field("requests", &*requests)
            .field("acquire_count", &self.acquire_count.load(Ordering::SeqCst))
            .finish()
    }
}

impl MemoryEntraTokenProvider {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue acquired results and optional cancels (`None` = user dismiss).
    pub fn from_results(results: impl IntoIterator<Item = Option<EntraTokenResult>>) -> Self {
        let provider = Self::new();
        for result in results {
            provider.push(result);
        }
        provider
    }

    /// Convenience: all entries are acquired access tokens (no refresh, no cancels).
    pub fn from_access_tokens(tokens: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::from_results(
            tokens
                .into_iter()
                .map(|t| Some(EntraTokenResult::access_only(t))),
        )
    }

    pub fn push(&self, result: Option<EntraTokenResult>) {
        self.script
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push_back(result);
    }

    pub fn acquire_count(&self) -> usize {
        self.acquire_count.load(Ordering::SeqCst)
    }

    pub fn requests(&self) -> Vec<EntraTokenRequest> {
        self.requests
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

#[async_trait]
impl EntraTokenProvider for MemoryEntraTokenProvider {
    async fn acquire(
        &self,
        request: EntraTokenRequest,
    ) -> Result<EntraTokenResponse, EntraTokenError> {
        self.acquire_count.fetch_add(1, Ordering::SeqCst);
        self.requests
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(request);
        let next = self
            .script
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .pop_front();
        match next {
            Some(Some(result)) => Ok(EntraTokenResponse::Acquired(result)),
            Some(None) | None => Ok(EntraTokenResponse::Cancelled),
        }
    }
}

/// Alias used in tests — same type as [`MemoryEntraTokenProvider`].
pub type FakeEntraTokenProvider = MemoryEntraTokenProvider;

/// Shared handle type for DI / future provider fields.
pub type SharedEntraTokenProvider = Arc<dyn EntraTokenProvider>;

/// Documented OpenVPN username for Azure Entra P2S (`AzureAD`).
pub const ENTRA_OPENVPN_USERNAME: &str = AZURE_AAD_USERNAME;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::auth_glue::AzureVpnAuthGlue;
    use crate::providers::auth_glue::OvpnAuthGlue;
    use crate::providers::secret_shape::require_openvpn_sidecar_secret;

    fn sample_request() -> EntraTokenRequest {
        EntraTokenRequest::new(
            Uuid::parse_str("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee").unwrap(),
            "lab-vpn",
            "tenant-guid",
            "audience-guid",
            "client-guid",
        )
    }

    #[test]
    fn access_and_refresh_debug_and_display_redact() {
        let access = AccessToken::new("eyJhbGciOi.ACCESS_LEAK");
        let refresh = RefreshToken::new("0.REFRESH_LEAK");
        let dbg_a = format!("{access:?}");
        let dbg_r = format!("{refresh:?}");
        assert!(dbg_a.contains("[REDACTED]"), "{dbg_a}");
        assert!(!dbg_a.contains("ACCESS_LEAK"), "{dbg_a}");
        assert_eq!(format!("{access}"), "[REDACTED]");
        assert!(dbg_r.contains("[REDACTED]"), "{dbg_r}");
        assert!(!dbg_r.contains("REFRESH_LEAK"), "{dbg_r}");
        assert_eq!(format!("{refresh}"), "[REDACTED]");
        assert_eq!(format!("{:?}", AccessToken::new("")), "AccessToken(\"\")");
    }

    #[test]
    fn token_result_and_response_debug_redact() {
        let result = EntraTokenResult::new("access.SECRET", Some("refresh.SECRET"));
        let dbg = format!("{result:?}");
        assert!(dbg.contains("[REDACTED]"), "{dbg}");
        assert!(!dbg.contains("access.SECRET"), "{dbg}");
        assert!(!dbg.contains("refresh.SECRET"), "{dbg}");

        let resp = EntraTokenResponse::Acquired(result);
        let resp_dbg = format!("{resp:?}");
        assert!(!resp_dbg.contains("access.SECRET"), "{resp_dbg}");
        assert!(!resp_dbg.contains("refresh.SECRET"), "{resp_dbg}");
    }

    #[test]
    fn memory_provider_debug_redacts_queued_tokens() {
        let provider = MemoryEntraTokenProvider::from_results([
            Some(EntraTokenResult::new("tok-AAA", Some("rt-BBB"))),
            None,
        ]);
        let dbg = format!("{provider:?}");
        assert!(!dbg.contains("tok-AAA"), "{dbg}");
        assert!(!dbg.contains("rt-BBB"), "{dbg}");
        assert!(dbg.contains("[REDACTED]"), "{dbg}");
        assert!(dbg.contains("None"), "{dbg}");
    }

    #[test]
    fn refresh_token_cache_path_is_tokencache_under_azurevpn_cache() {
        let id = Uuid::parse_str("f00dcafe-aaaa-4000-8000-0000cafebabe").unwrap();
        let path = azure_vpn_refresh_token_cache_path(&id);
        let parent = path.parent().expect("tokencache parent");
        assert_eq!(
            parent.file_name().and_then(|n| n.to_str()),
            Some("azurevpn-cache"),
            "cache file must live directly under azurevpn-cache, got {path:?}"
        );
        let expected_name = format!("{}.tokencache", id.simple());
        assert_eq!(
            path.file_name().and_then(|n| n.to_str()),
            Some(expected_name.as_str()),
            "{path:?}"
        );
        // Path stub only — no interactive WebView2 profile path.
        let s = path.to_string_lossy();
        assert!(!s.contains("azurevpn-webview2"), "{s}");
    }

    #[cfg(feature = "secrets")]
    #[test]
    fn refresh_token_cache_path_matches_secrets_win() {
        let id = Uuid::parse_str("f00dcafe-bbbb-4000-8000-0000cafebabe").unwrap();
        assert_eq!(
            azure_vpn_refresh_token_cache_path(&id),
            wormhole_secrets_win::azure_vpn_token_cache_path(&id)
        );
    }

    #[test]
    fn entra_openvpn_username_is_azure_ad() {
        assert_eq!(ENTRA_OPENVPN_USERNAME, "AzureAD");
        assert_eq!(AZURE_AAD_USERNAME, "AzureAD");
    }

    #[test]
    fn materials_from_entra_use_azure_ad_username_and_access_password() {
        let token = AccessToken::new("access.for.openvpn");
        let materials = azure_materials_from_entra("client\nremote gw 443\n", &token);
        assert_eq!(materials.username.as_deref(), Some(AZURE_AAD_USERNAME));
        assert_eq!(materials.password.as_deref(), Some("access.for.openvpn"));
        let json = AzureVpnAuthGlue.to_sidecar_json(&materials).unwrap();
        require_openvpn_sidecar_secret(&json).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(v["username"], "AzureAD");
        assert_eq!(v["password"], "access.for.openvpn");
        let materials_dbg = format!("{materials:?}");
        assert!(!materials_dbg.contains("access.for.openvpn"), "{materials_dbg}");
    }

    #[tokio::test]
    async fn memory_provider_acquire_then_cancel() {
        let provider = MemoryEntraTokenProvider::from_results([
            Some(EntraTokenResult::new("access-1", Some("refresh-1"))),
            None,
        ]);
        let r1 = provider.acquire(sample_request()).await.unwrap();
        match r1 {
            EntraTokenResponse::Acquired(result) => {
                assert_eq!(result.access_token.as_str(), "access-1");
                assert_eq!(
                    result.refresh_token.as_ref().map(|t| t.as_str()),
                    Some("refresh-1")
                );
            }
            EntraTokenResponse::Cancelled => panic!("expected acquired"),
        }
        let r2 = provider.acquire(sample_request()).await.unwrap();
        assert_eq!(r2, EntraTokenResponse::Cancelled);
        let r3 = provider.acquire(sample_request()).await.unwrap();
        assert_eq!(r3, EntraTokenResponse::Cancelled);
        assert_eq!(provider.acquire_count(), 3);
        assert_eq!(provider.requests().len(), 3);
    }

    #[tokio::test]
    async fn request_entra_returns_trimmed_access_token() {
        let provider = FakeEntraTokenProvider::from_access_tokens(["  eyJ.trimmed  "]);
        let token = request_entra_access_token(&provider, sample_request())
            .await
            .unwrap();
        assert_eq!(token.as_str(), "eyJ.trimmed");
        assert_eq!(provider.acquire_count(), 1);
        assert_eq!(provider.requests()[0].config_name, "lab-vpn");
        assert!(!format!("{token:?}").contains("eyJ.trimmed"));
    }

    #[tokio::test]
    async fn request_entra_user_cancel() {
        let provider = MemoryEntraTokenProvider::from_results([None]);
        let err = request_entra_access_token(&provider, sample_request())
            .await
            .unwrap_err();
        assert!(matches!(err, TunnelError::Cancelled));
    }

    #[tokio::test]
    async fn request_entra_empty_after_trim_fails_without_echo() {
        let provider = MemoryEntraTokenProvider::from_access_tokens(["   "]);
        let err = request_entra_access_token(&provider, sample_request())
            .await
            .unwrap_err();
        let rendered = format!("{err}");
        assert!(rendered.contains("empty"), "{rendered}");
        assert!(!rendered.contains("   "));
    }

    #[tokio::test]
    async fn request_entra_empty_string_fails() {
        let provider = MemoryEntraTokenProvider::from_access_tokens([""]);
        let err = request_entra_access_token(&provider, sample_request())
            .await
            .unwrap_err();
        match err {
            TunnelError::Establish(msg) => assert!(msg.contains("empty"), "{msg}"),
            other => panic!("expected Establish, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn null_provider_always_cancels() {
        let direct = NullEntraTokenProvider
            .acquire(sample_request())
            .await
            .unwrap();
        assert_eq!(direct, EntraTokenResponse::Cancelled);
        let err = request_entra_access_token(&NullEntraTokenProvider, sample_request())
            .await
            .unwrap_err();
        assert!(matches!(err, TunnelError::Cancelled));
    }

    #[tokio::test]
    async fn end_to_end_stub_to_sidecar_json_documents_azure_ad_password() {
        let provider = FakeEntraTokenProvider::from_results([Some(EntraTokenResult::new(
            "access.TOKEN_VALUE",
            Some("refresh.TOKEN_VALUE"),
        ))]);
        let access = request_entra_access_token(&provider, sample_request())
            .await
            .unwrap();
        let materials = azure_materials_from_entra("client\n", &access);
        let cfg = AzureVpnAuthGlue.to_sidecar_config(&materials).unwrap();
        assert_eq!(cfg.username.as_deref(), Some("AzureAD"));
        assert_eq!(cfg.password.as_deref(), Some("access.TOKEN_VALUE"));
        // Refresh token is for the DPAPI cache path — never the OpenVPN password.
        assert_ne!(cfg.password.as_deref(), Some("refresh.TOKEN_VALUE"));
        let path = azure_vpn_refresh_token_cache_path(&sample_request().tunnel_config_id);
        assert!(path.to_string_lossy().ends_with(".tokencache"));
    }

    #[tokio::test]
    async fn stub_never_writes_tokencache_bytes_to_disk() {
        let request = sample_request();
        let path = azure_vpn_refresh_token_cache_path(&request.tunnel_config_id);
        let before_exists = path.is_file();
        let before_meta = std::fs::metadata(&path)
            .ok()
            .and_then(|m| m.modified().ok().map(|t| (m.len(), t)));

        let provider = FakeEntraTokenProvider::from_results([Some(EntraTokenResult::new(
            "access.NO_DISK_WRITE",
            Some("refresh.NO_DISK_WRITE"),
        ))]);
        let access = request_entra_access_token(&provider, request.clone())
            .await
            .unwrap();
        let _materials = azure_materials_from_entra("client\n", &access);
        // Pure path helper — must not create or mutate the cache file.
        let _ = azure_vpn_refresh_token_cache_path(&request.tunnel_config_id);

        if !before_exists {
            assert!(
                !path.is_file(),
                "Entra stub must not create tokencache at {}",
                path.display()
            );
        } else {
            let after_meta = std::fs::metadata(&path)
                .ok()
                .and_then(|m| m.modified().ok().map(|t| (m.len(), t)));
            assert_eq!(
                before_meta, after_meta,
                "Entra stub must not rewrite existing tokencache"
            );
            if let Ok(bytes) = std::fs::read(&path) {
                let text = String::from_utf8_lossy(&bytes);
                assert!(
                    !text.contains("NO_DISK_WRITE"),
                    "stub must not write token probe bytes into existing cache"
                );
            }
        }
    }

    #[tokio::test]
    async fn fake_provider_is_deterministic_queue() {
        let provider = FakeEntraTokenProvider::from_access_tokens(["first", "second"]);
        let a = request_entra_access_token(&provider, sample_request())
            .await
            .unwrap();
        let b = request_entra_access_token(&provider, sample_request())
            .await
            .unwrap();
        assert_eq!(a.as_str(), "first");
        assert_eq!(b.as_str(), "second");
        let exhausted = request_entra_access_token(&provider, sample_request())
            .await
            .unwrap_err();
        assert!(matches!(exhausted, TunnelError::Cancelled));
        assert_eq!(provider.acquire_count(), 3);
    }
}
