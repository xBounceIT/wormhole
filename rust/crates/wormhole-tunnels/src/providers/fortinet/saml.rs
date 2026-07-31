//! Fortinet SAML SSO auth stub — path types + callbacks + channel UI transport.
//!
//! Mirrors C# `IFortinetSamlAuthService` / `FortinetSamlAuthResult` **shapes**:
//! - [`SamlAuthFlow::ExternalBrowser`] — intended OS-browser + loopback callback
//!   (default port [`DEFAULT_SAML_REDIRECT_PORT`] = 8020) → ephemeral `auth_id`
//! - [`SamlAuthFlow::Embedded`] — intended embedded cookie path → ephemeral `SVPNCOOKIE`
//!
//! **Not implemented here:** WebView2 dialog, OS browser launch, or loopback listener.
//! Production [`StubSamlAuthCallback`] validates the request and returns
//! [`SamlAuthError::NotImplemented`]. Tests use [`FakeSamlAuthCallback`].
//! UI glue uses [`ChannelSamlAuthCallback`] (oneshot pending → Fake / host reply).
//! Not wired into [`super::FortinetProvider::establish`] (sidecar path unchanged;
//! establish-path glue calls [`authenticate`] via the callback trait).
//!
//! Credentials are ephemeral and sent only on sidecar stdin later. **Never** log
//! `SVPNCOOKIE` / `auth_id` (see [`Debug`] on [`SamlAuthId`], [`SvpnCookie`],
//! [`SamlAuthResult`], [`FakeSamlAuthCallback`], [`SamlPromptResponse`]).

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::sync::{mpsc, oneshot};

use crate::providers::auth_glue::redact_nonempty;

/// FortiGate `saml-redirect-port` / Wormhole loopback callback default
/// (`FortinetSettings.DefaultSamlRedirectPort`).
pub const DEFAULT_SAML_REDIRECT_PORT: u16 = 8020;

/// SAML UI path selection (parity with `UseExternalBrowser` + `SamlRedirectPort`).
///
/// Carries path + callback-port configuration only. Does **not** launch a browser
/// or open WebView2 — see [`StubSamlAuthCallback`] / [`authenticate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SamlAuthFlow {
    /// External-browser path: loopback callback port → ephemeral `auth_id` (UI later).
    ExternalBrowser {
        /// Loopback HTTP callback port (FortiGate `saml-redirect-port`). Default 8020.
        callback_port: u16,
    },
    /// Embedded path: ephemeral `SVPNCOOKIE` (UI later).
    Embedded,
}

impl SamlAuthFlow {
    /// External browser with the default callback port (8020).
    pub fn external_browser_default() -> Self {
        Self::ExternalBrowser {
            callback_port: DEFAULT_SAML_REDIRECT_PORT,
        }
    }

    /// External browser with an explicit callback port.
    pub fn external_browser(callback_port: u16) -> Self {
        Self::ExternalBrowser { callback_port }
    }

    /// Embedded cookie path (UI later).
    pub fn embedded() -> Self {
        Self::Embedded
    }

    pub fn is_external_browser(&self) -> bool {
        matches!(self, Self::ExternalBrowser { .. })
    }

    pub fn is_embedded(&self) -> bool {
        matches!(self, Self::Embedded)
    }

    /// Callback port for external browser; `None` for embedded.
    pub fn callback_port(&self) -> Option<u16> {
        match self {
            Self::ExternalBrowser { callback_port } => Some(*callback_port),
            Self::Embedded => None,
        }
    }

    /// Reject port `0` for external browser (parity: must be 1..=65535).
    pub fn validate(&self) -> Result<(), SamlAuthError> {
        match self {
            Self::ExternalBrowser { callback_port: 0 } => Err(SamlAuthError::InvalidCallbackPort),
            Self::ExternalBrowser { .. } | Self::Embedded => Ok(()),
        }
    }
}

/// Ephemeral external-browser `auth_id` (never log).
#[derive(Clone, PartialEq, Eq)]
pub struct SamlAuthId(String);

impl SamlAuthId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Borrow plaintext (do not log / tracing).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume into plaintext (sidecar stdin only).
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Debug for SamlAuthId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SamlAuthId")
            .field(&redact_nonempty(&self.0))
            .finish()
    }
}

impl fmt::Display for SamlAuthId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(redact_nonempty(&self.0))
    }
}

/// Ephemeral embedded-browser `SVPNCOOKIE` (never log).
#[derive(Clone, PartialEq, Eq)]
pub struct SvpnCookie(String);

impl SvpnCookie {
    pub fn new(cookie: impl Into<String>) -> Self {
        Self(cookie.into())
    }

    /// Borrow plaintext (do not log / tracing).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume into plaintext (sidecar stdin only).
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Debug for SvpnCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SvpnCookie")
            .field(&redact_nonempty(&self.0))
            .finish()
    }
}

impl fmt::Display for SvpnCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(redact_nonempty(&self.0))
    }
}

/// Exactly one of `auth_id` (external) or `SVPNCOOKIE` (embedded).
///
/// Parity with C# `FortinetSamlAuthResult` (`HasExactlyOneCredential`).
#[derive(Clone, PartialEq, Eq)]
pub enum SamlAuthResult {
    AuthId(SamlAuthId),
    SvpnCookie(SvpnCookie),
}

impl SamlAuthResult {
    pub fn from_auth_id(id: impl Into<String>) -> Self {
        Self::AuthId(SamlAuthId::new(id))
    }

    pub fn from_svpn_cookie(cookie: impl Into<String>) -> Self {
        Self::SvpnCookie(SvpnCookie::new(cookie))
    }

    pub fn is_auth_id(&self) -> bool {
        matches!(self, Self::AuthId(_))
    }

    pub fn is_svpn_cookie(&self) -> bool {
        matches!(self, Self::SvpnCookie(_))
    }

    /// `true` when the single credential is non-empty after trim.
    ///
    /// Enum shape already enforces exactly one variant; [`authenticate`] rejects
    /// empty / whitespace tokens via this check.
    pub fn has_exactly_one_credential(&self) -> bool {
        match self {
            Self::AuthId(id) => !id.as_str().trim().is_empty(),
            Self::SvpnCookie(c) => !c.as_str().trim().is_empty(),
        }
    }

    /// Ensure the credential kind matches the selected flow.
    pub fn matches_flow(&self, flow: SamlAuthFlow) -> bool {
        match (flow, self) {
            (SamlAuthFlow::ExternalBrowser { .. }, Self::AuthId(_)) => true,
            (SamlAuthFlow::Embedded, Self::SvpnCookie(_)) => true,
            _ => false,
        }
    }
}

impl fmt::Debug for SamlAuthResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthId(id) => f.debug_tuple("AuthId").field(id).finish(),
            Self::SvpnCookie(c) => f.debug_tuple("SvpnCookie").field(c).finish(),
        }
    }
}

/// Non-secret request metadata for a SAML auth attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlAuthRequest {
    pub config_name: String,
    pub flow: SamlAuthFlow,
}

impl SamlAuthRequest {
    pub fn new(config_name: impl Into<String>, flow: SamlAuthFlow) -> Self {
        Self {
            config_name: config_name.into(),
            flow,
        }
    }
}

/// Errors from the SAML auth stub / channel UI transport.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum SamlAuthError {
    /// User dismiss / cancellation token / channel auto-cancel.
    #[error("Fortinet SAML authentication cancelled")]
    Cancelled,
    /// Stub: no WebView2 / external browser UI wired yet.
    #[error(
        "Fortinet SAML authentication is not implemented yet (no WebView2 / external browser UI)"
    )]
    NotImplemented,
    /// External-browser callback port was 0.
    #[error("Fortinet SAML callback port must be between 1 and 65535")]
    InvalidCallbackPort,
    /// Callback returned the wrong credential kind or empty token.
    #[error("Fortinet SAML authentication returned an invalid result")]
    InvalidResult,
    /// Channel receiver / oneshot abandoned (maps to cancel at establish).
    #[error("Fortinet SAML authentication channel closed")]
    ChannelClosed,
    /// Generic establish-style failure (message must not contain secrets).
    #[error("Fortinet SAML authentication failed: {0}")]
    Failed(String),
}

/// UI / Fake reply on a pending [`ChannelSamlAuthCallback`] prompt.
///
/// [`Debug`] redacts submitted `auth_id` / `SVPNCOOKIE`.
#[derive(Clone, PartialEq, Eq)]
pub enum SamlPromptResponse {
    /// Ephemeral credential for the requested flow (validated by [`authenticate`]).
    Submitted(SamlAuthResult),
    /// User dismiss / Fake cancel.
    Cancelled,
}

impl SamlPromptResponse {
    pub fn from_auth_id(id: impl Into<String>) -> Self {
        Self::Submitted(SamlAuthResult::from_auth_id(id))
    }

    pub fn from_svpn_cookie(cookie: impl Into<String>) -> Self {
        Self::Submitted(SamlAuthResult::from_svpn_cookie(cookie))
    }
}

impl fmt::Debug for SamlPromptResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Submitted(result) => f.debug_tuple("Submitted").field(result).finish(),
            Self::Cancelled => f.write_str("Cancelled"),
        }
    }
}

/// Callback that yields ephemeral SAML material for a chosen [`SamlAuthFlow`].
///
/// Implementations must **never** write `auth_id` / `SVPNCOOKIE` to logs or tracing.
#[async_trait]
pub trait SamlAuthCallback: Send + Sync {
    async fn complete(&self, request: SamlAuthRequest) -> Result<SamlAuthResult, SamlAuthError>;
}

/// Run SAML auth via a callback: validate flow, invoke callback, enforce
/// credential/flow match and non-empty tokens. Never logs secrets.
///
/// Not wired into [`super::FortinetProvider::establish`] yet — callers supply
/// already-resolved sidecar JSON today.
pub async fn authenticate(
    callback: &dyn SamlAuthCallback,
    request: SamlAuthRequest,
) -> Result<SamlAuthResult, SamlAuthError> {
    request.flow.validate()?;

    // Safe fields only — never attach auth_id / cookie.
    tracing::debug!(
        config_name = %request.config_name,
        flow = ?request.flow,
        "requesting Fortinet SAML authentication"
    );

    let flow = request.flow;
    let result = callback.complete(request).await?;

    if !result.has_exactly_one_credential() || !result.matches_flow(flow) {
        return Err(SamlAuthError::InvalidResult);
    }

    Ok(result)
}

/// Production stub: validates the request then returns [`SamlAuthError::NotImplemented`].
///
/// Does not open a browser or bind a loopback listener.
#[derive(Debug, Default, Clone, Copy)]
pub struct StubSamlAuthCallback;

#[async_trait]
impl SamlAuthCallback for StubSamlAuthCallback {
    async fn complete(&self, request: SamlAuthRequest) -> Result<SamlAuthResult, SamlAuthError> {
        request.flow.validate()?;
        Err(SamlAuthError::NotImplemented)
    }
}

/// Scripted callback for unit tests — yields ephemeral tokens without UI.
///
/// Each [`complete`](SamlAuthCallback::complete) dequeues the next scripted
/// outcome. Empty queue → [`SamlAuthError::Cancelled`].
///
/// [`Debug`] redacts queued token values.
#[derive(Default)]
pub struct FakeSamlAuthCallback {
    script: Mutex<VecDeque<Result<SamlAuthResult, SamlAuthError>>>,
    requests: Mutex<Vec<SamlAuthRequest>>,
    complete_count: AtomicUsize,
}

impl fmt::Debug for FakeSamlAuthCallback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let script = self.script.lock().unwrap_or_else(|p| p.into_inner());
        let redacted: Vec<String> = script
            .iter()
            .map(|slot| match slot {
                Ok(SamlAuthResult::AuthId(_)) => "Ok(AuthId([REDACTED]))".into(),
                Ok(SamlAuthResult::SvpnCookie(_)) => "Ok(SvpnCookie([REDACTED]))".into(),
                // Never echo Failed payloads — callers must keep them secret-free,
                // but Debug of the fake must not become a second leak channel.
                Err(SamlAuthError::Failed(_)) => "Err(Failed([REDACTED]))".into(),
                Err(e) => format!("Err({e:?})"),
            })
            .collect();
        let requests = self.requests.lock().unwrap_or_else(|p| p.into_inner());
        f.debug_struct("FakeSamlAuthCallback")
            .field("script", &redacted)
            .field("requests", &*requests)
            .field(
                "complete_count",
                &self.complete_count.load(Ordering::SeqCst),
            )
            .finish()
    }
}

impl FakeSamlAuthCallback {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue successful / error outcomes in order.
    pub fn from_results(
        results: impl IntoIterator<Item = Result<SamlAuthResult, SamlAuthError>>,
    ) -> Self {
        let fake = Self::new();
        for result in results {
            fake.push(result);
        }
        fake
    }

    /// Queue an ephemeral `auth_id` (external-browser path).
    pub fn push_auth_id(&self, id: impl Into<String>) {
        self.push(Ok(SamlAuthResult::from_auth_id(id)));
    }

    /// Queue an ephemeral `SVPNCOOKIE` (embedded path).
    pub fn push_svpn_cookie(&self, cookie: impl Into<String>) {
        self.push(Ok(SamlAuthResult::from_svpn_cookie(cookie)));
    }

    pub fn push(&self, result: Result<SamlAuthResult, SamlAuthError>) {
        self.script
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push_back(result);
    }

    pub fn complete_count(&self) -> usize {
        self.complete_count.load(Ordering::SeqCst)
    }

    pub fn requests(&self) -> Vec<SamlAuthRequest> {
        self.requests
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

#[async_trait]
impl SamlAuthCallback for FakeSamlAuthCallback {
    async fn complete(&self, request: SamlAuthRequest) -> Result<SamlAuthResult, SamlAuthError> {
        self.complete_count.fetch_add(1, Ordering::SeqCst);
        self.requests
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(request);
        self.script
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .pop_front()
            .unwrap_or(Err(SamlAuthError::Cancelled))
    }
}

/// Shared handle for DI / future Fortinet provider fields.
pub type SharedSamlAuthCallback = Arc<dyn SamlAuthCallback>;

#[derive(Debug)]
enum ChannelMode {
    /// Fail closed: behave like an empty Fake queue ([`SamlAuthError::Cancelled`]).
    AutoCancel,
    /// Forward to a UI / test consumer.
    Channel(mpsc::UnboundedSender<PendingSamlPrompt>),
}

/// Pending SAML prompt waiting for a UI (or Fake) decision.
///
/// Request metadata only — never carries `auth_id` / `SVPNCOOKIE`.
pub struct PendingSamlPrompt {
    pub request: SamlAuthRequest,
    pub respond: oneshot::Sender<SamlPromptResponse>,
}

impl fmt::Debug for PendingSamlPrompt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingSamlPrompt")
            .field("request", &self.request)
            .field("respond", &"<oneshot>")
            .finish()
    }
}

/// Channel-backed SAML callback for UI glue (independent of WebView2 / GPUI).
///
/// Default mode is auto-cancel (fail closed). Tests / host call
/// [`open_channel`](ChannelSamlAuthCallback::open_channel) and answer via the oneshot.
/// Does **not** launch a browser or bind a loopback listener.
#[derive(Debug)]
pub struct ChannelSamlAuthCallback {
    mode: Mutex<ChannelMode>,
    complete_count: AtomicUsize,
}

impl Default for ChannelSamlAuthCallback {
    fn default() -> Self {
        Self::new()
    }
}

impl ChannelSamlAuthCallback {
    pub fn new() -> Self {
        Self {
            mode: Mutex::new(ChannelMode::AutoCancel),
            complete_count: AtomicUsize::new(0),
        }
    }

    pub fn set_auto_cancel(&self) {
        *self.mode.lock().unwrap_or_else(|p| p.into_inner()) = ChannelMode::AutoCancel;
    }

    pub fn open_channel(&self) -> mpsc::UnboundedReceiver<PendingSamlPrompt> {
        let (tx, rx) = mpsc::unbounded_channel();
        *self.mode.lock().unwrap_or_else(|p| p.into_inner()) = ChannelMode::Channel(tx);
        rx
    }

    pub fn complete_count(&self) -> usize {
        self.complete_count.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl SamlAuthCallback for ChannelSamlAuthCallback {
    async fn complete(&self, request: SamlAuthRequest) -> Result<SamlAuthResult, SamlAuthError> {
        self.complete_count.fetch_add(1, Ordering::SeqCst);
        request.flow.validate()?;
        let respond_rx = {
            let mode = self.mode.lock().unwrap_or_else(|p| p.into_inner());
            match &*mode {
                ChannelMode::AutoCancel => return Err(SamlAuthError::Cancelled),
                ChannelMode::Channel(tx) => {
                    let (respond_tx, respond_rx) = oneshot::channel();
                    let pending = PendingSamlPrompt {
                        request,
                        respond: respond_tx,
                    };
                    if tx.send(pending).is_err() {
                        return Err(SamlAuthError::ChannelClosed);
                    }
                    respond_rx
                }
            }
        };
        match respond_rx.await {
            Ok(SamlPromptResponse::Submitted(result)) => Ok(result),
            Ok(SamlPromptResponse::Cancelled) => Err(SamlAuthError::Cancelled),
            Err(_) => Err(SamlAuthError::ChannelClosed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_callback_port_is_8020() {
        assert_eq!(DEFAULT_SAML_REDIRECT_PORT, 8020);
        let flow = SamlAuthFlow::external_browser_default();
        assert_eq!(flow.callback_port(), Some(8020));
        assert!(flow.is_external_browser());
        assert!(!flow.is_embedded());

        let custom = SamlAuthFlow::external_browser(18443);
        assert_eq!(custom.callback_port(), Some(18443));

        let embedded = SamlAuthFlow::embedded();
        assert!(embedded.is_embedded());
        assert_eq!(embedded.callback_port(), None);
    }

    #[test]
    fn external_browser_rejects_port_zero() {
        let err = SamlAuthFlow::external_browser(0).validate().unwrap_err();
        assert_eq!(err, SamlAuthError::InvalidCallbackPort);
        assert!(SamlAuthFlow::external_browser(1).validate().is_ok());
        assert!(SamlAuthFlow::external_browser(65535).validate().is_ok());
        assert!(SamlAuthFlow::embedded().validate().is_ok());
    }

    #[test]
    fn auth_id_and_cookie_debug_redact() {
        let id = SamlAuthId::new("ephemeral-auth-id-secret");
        let cookie = SvpnCookie::new("SVPNCOOKIE-value-secret");
        let id_dbg = format!("{id:?}");
        let cookie_dbg = format!("{cookie:?}");
        let id_disp = format!("{id}");
        let cookie_disp = format!("{cookie}");

        assert!(id_dbg.contains("[REDACTED]"), "{id_dbg}");
        assert!(!id_dbg.contains("ephemeral-auth-id-secret"), "{id_dbg}");
        assert!(!id_dbg.contains("auth-id-secret"), "{id_dbg}");
        assert_eq!(id_disp, "[REDACTED]");

        assert!(cookie_dbg.contains("[REDACTED]"), "{cookie_dbg}");
        assert!(!cookie_dbg.contains("SVPNCOOKIE-value-secret"), "{cookie_dbg}");
        assert!(!cookie_dbg.contains("SVPNCOOKIE-value"), "{cookie_dbg}");
        assert_eq!(cookie_disp, "[REDACTED]");

        assert_eq!(id.as_str(), "ephemeral-auth-id-secret");
        assert_eq!(cookie.as_str(), "SVPNCOOKIE-value-secret");
        assert_eq!(format!("{:?}", SamlAuthId::new("")), "SamlAuthId(\"\")");
        assert_eq!(format!("{:?}", SvpnCookie::new("")), "SvpnCookie(\"\")");
    }

    #[test]
    fn result_debug_redacts_tokens() {
        let auth = SamlAuthResult::from_auth_id("auth-id-xyz");
        let cookie = SamlAuthResult::from_svpn_cookie("cookie-abc");
        let a = format!("{auth:?}");
        let c = format!("{cookie:?}");
        assert!(a.contains("[REDACTED]"), "{a}");
        assert!(!a.contains("auth-id-xyz"), "{a}");
        assert!(c.contains("[REDACTED]"), "{c}");
        assert!(!c.contains("cookie-abc"), "{c}");
        assert!(auth.has_exactly_one_credential());
        assert!(cookie.has_exactly_one_credential());
        assert!(!SamlAuthResult::from_auth_id("  ").has_exactly_one_credential());
    }

    #[test]
    fn result_matches_flow() {
        let auth = SamlAuthResult::from_auth_id("id1");
        let cookie = SamlAuthResult::from_svpn_cookie("c1");
        assert!(auth.matches_flow(SamlAuthFlow::external_browser_default()));
        assert!(!auth.matches_flow(SamlAuthFlow::embedded()));
        assert!(cookie.matches_flow(SamlAuthFlow::embedded()));
        assert!(!cookie.matches_flow(SamlAuthFlow::external_browser(8020)));
    }

    #[test]
    fn fake_debug_redacts_scripted_tokens() {
        let fake = FakeSamlAuthCallback::new();
        fake.push_auth_id("secret-auth-id-999");
        fake.push_svpn_cookie("secret-svpn-cookie-888");
        fake.push(Err(SamlAuthError::Cancelled));
        let dbg = format!("{fake:?}");
        assert!(!dbg.contains("secret-auth-id-999"), "{dbg}");
        assert!(!dbg.contains("secret-svpn-cookie-888"), "{dbg}");
        assert!(dbg.contains("[REDACTED]"), "{dbg}");
        assert!(dbg.contains("Cancelled"), "{dbg}");
    }

    #[tokio::test]
    async fn fake_yields_ephemeral_auth_id_for_external() {
        let fake = FakeSamlAuthCallback::new();
        fake.push_auth_id("ephemeral-id-1");
        let result = authenticate(
            &fake,
            SamlAuthRequest::new("lab-vpn", SamlAuthFlow::external_browser_default()),
        )
        .await
        .unwrap();
        let dbg = format!("{result:?}");
        assert!(!dbg.contains("ephemeral-id-1"), "{dbg}");
        match result {
            SamlAuthResult::AuthId(id) => assert_eq!(id.as_str(), "ephemeral-id-1"),
            SamlAuthResult::SvpnCookie(_) => panic!("expected AuthId"),
        }
        assert_eq!(fake.complete_count(), 1);
        assert_eq!(fake.requests()[0].config_name, "lab-vpn");
        assert_eq!(
            fake.requests()[0].flow,
            SamlAuthFlow::ExternalBrowser {
                callback_port: 8020
            }
        );
    }

    #[tokio::test]
    async fn fake_yields_ephemeral_cookie_for_embedded() {
        let fake = FakeSamlAuthCallback::from_results([Ok(SamlAuthResult::from_svpn_cookie(
            "SVPNCOOKIE-ephemeral",
        ))]);
        let result = authenticate(
            &fake,
            SamlAuthRequest::new("embedded-cfg", SamlAuthFlow::embedded()),
        )
        .await
        .unwrap();
        let dbg = format!("{result:?}");
        assert!(!dbg.contains("SVPNCOOKIE-ephemeral"), "{dbg}");
        match result {
            SamlAuthResult::SvpnCookie(c) => assert_eq!(c.as_str(), "SVPNCOOKIE-ephemeral"),
            SamlAuthResult::AuthId(_) => panic!("expected SvpnCookie"),
        }
    }

    #[tokio::test]
    async fn authenticate_rejects_mismatched_credential_kind() {
        let fake = FakeSamlAuthCallback::new();
        // External flow but cookie credential → InvalidResult
        fake.push_svpn_cookie("wrong-kind-cookie");
        let err = authenticate(
            &fake,
            SamlAuthRequest::new("x", SamlAuthFlow::external_browser(8020)),
        )
        .await
        .unwrap_err();
        assert_eq!(err, SamlAuthError::InvalidResult);
        // Message must not echo the cookie.
        assert!(!format!("{err}").contains("wrong-kind-cookie"));

        // Embedded flow but auth_id credential → InvalidResult (fail-closed both ways)
        let fake2 = FakeSamlAuthCallback::new();
        fake2.push_auth_id("wrong-kind-auth-id");
        let err2 = authenticate(
            &fake2,
            SamlAuthRequest::new("y", SamlAuthFlow::embedded()),
        )
        .await
        .unwrap_err();
        assert_eq!(err2, SamlAuthError::InvalidResult);
        assert!(!format!("{err2}").contains("wrong-kind-auth-id"));
    }

    #[tokio::test]
    async fn authenticate_rejects_empty_token() {
        let fake = FakeSamlAuthCallback::new();
        fake.push_auth_id("   ");
        let err = authenticate(
            &fake,
            SamlAuthRequest::new("x", SamlAuthFlow::external_browser_default()),
        )
        .await
        .unwrap_err();
        assert_eq!(err, SamlAuthError::InvalidResult);

        let fake_cookie = FakeSamlAuthCallback::new();
        fake_cookie.push_svpn_cookie("   ");
        let err_cookie = authenticate(
            &fake_cookie,
            SamlAuthRequest::new("y", SamlAuthFlow::embedded()),
        )
        .await
        .unwrap_err();
        assert_eq!(err_cookie, SamlAuthError::InvalidResult);

        let fake_empty = FakeSamlAuthCallback::new();
        fake_empty.push_svpn_cookie("");
        let err_empty = authenticate(
            &fake_empty,
            SamlAuthRequest::new("z", SamlAuthFlow::embedded()),
        )
        .await
        .unwrap_err();
        assert_eq!(err_empty, SamlAuthError::InvalidResult);
    }

    #[test]
    fn fake_debug_redacts_failed_payload() {
        let fake = FakeSamlAuthCallback::new();
        fake.push(Err(SamlAuthError::Failed(
            "leaked-svpn-cookie-should-not-appear".into(),
        )));
        let dbg = format!("{fake:?}");
        assert!(!dbg.contains("leaked-svpn-cookie-should-not-appear"), "{dbg}");
        assert!(dbg.contains("Failed([REDACTED])"), "{dbg}");
    }

    #[tokio::test]
    async fn authenticate_rejects_port_zero_before_callback() {
        let fake = FakeSamlAuthCallback::new();
        fake.push_auth_id("should-not-be-consumed");
        let err = authenticate(
            &fake,
            SamlAuthRequest::new("x", SamlAuthFlow::external_browser(0)),
        )
        .await
        .unwrap_err();
        assert_eq!(err, SamlAuthError::InvalidCallbackPort);
        assert_eq!(fake.complete_count(), 0);
    }

    #[tokio::test]
    async fn stub_returns_not_implemented() {
        let err = authenticate(
            &StubSamlAuthCallback,
            SamlAuthRequest::new("prod", SamlAuthFlow::embedded()),
        )
        .await
        .unwrap_err();
        assert_eq!(err, SamlAuthError::NotImplemented);
        assert!(format!("{err}").contains("not implemented"));
        assert!(format!("{err}").contains("WebView2") || format!("{err}").contains("browser"));
    }

    #[tokio::test]
    async fn stub_validates_port_zero() {
        let err = StubSamlAuthCallback
            .complete(SamlAuthRequest::new("x", SamlAuthFlow::external_browser(0)))
            .await
            .unwrap_err();
        assert_eq!(err, SamlAuthError::InvalidCallbackPort);
    }

    #[tokio::test]
    async fn fake_exhausted_queue_cancels() {
        let fake = FakeSamlAuthCallback::new();
        let err = authenticate(
            &fake,
            SamlAuthRequest::new("x", SamlAuthFlow::embedded()),
        )
        .await
        .unwrap_err();
        assert_eq!(err, SamlAuthError::Cancelled);
        assert_eq!(fake.complete_count(), 1);
    }

    #[tokio::test]
    async fn custom_callback_port_is_preserved_on_request() {
        let fake = FakeSamlAuthCallback::new();
        fake.push_auth_id("id-on-custom-port");
        let flow = SamlAuthFlow::external_browser(18443);
        authenticate(&fake, SamlAuthRequest::new("cfg", flow))
            .await
            .unwrap();
        assert_eq!(fake.requests()[0].flow.callback_port(), Some(18443));
    }

    #[test]
    fn prompt_response_debug_redacts_submitted() {
        let auth = SamlPromptResponse::from_auth_id("AUTH_ID_SECRET");
        let cookie = SamlPromptResponse::from_svpn_cookie("SVPNCOOKIE_SECRET");
        let a = format!("{auth:?}");
        let c = format!("{cookie:?}");
        assert!(a.contains("[REDACTED]"), "{a}");
        assert!(!a.contains("AUTH_ID_SECRET"), "{a}");
        assert!(c.contains("[REDACTED]"), "{c}");
        assert!(!c.contains("SVPNCOOKIE_SECRET"), "{c}");
        assert_eq!(format!("{:?}", SamlPromptResponse::Cancelled), "Cancelled");
    }

    #[tokio::test]
    async fn channel_submit_auth_id_via_oneshot() {
        let channel = Arc::new(ChannelSamlAuthCallback::new());
        let mut rx = channel.open_channel();

        let task = tokio::spawn({
            let channel = Arc::clone(&channel);
            async move {
                authenticate(
                    channel.as_ref(),
                    SamlAuthRequest::new("lab", SamlAuthFlow::external_browser_default()),
                )
                .await
            }
        });

        let pending = rx.recv().await.expect("pending");
        assert_eq!(pending.request.config_name, "lab");
        assert_eq!(
            pending.request.flow,
            SamlAuthFlow::ExternalBrowser {
                callback_port: 8020
            }
        );
        pending
            .respond
            .send(SamlPromptResponse::from_auth_id("ephemeral-channel-id"))
            .unwrap();
        let result = task.await.unwrap().unwrap();
        let dbg = format!("{result:?}");
        match result {
            SamlAuthResult::AuthId(id) => assert_eq!(id.as_str(), "ephemeral-channel-id"),
            SamlAuthResult::SvpnCookie(_) => panic!("expected AuthId"),
        }
        assert!(!dbg.contains("ephemeral-channel-id"));
        assert_eq!(channel.complete_count(), 1);
    }

    #[tokio::test]
    async fn channel_submit_svpn_cookie_via_oneshot() {
        let channel = Arc::new(ChannelSamlAuthCallback::new());
        let mut rx = channel.open_channel();

        let task = tokio::spawn({
            let channel = Arc::clone(&channel);
            async move {
                authenticate(
                    channel.as_ref(),
                    SamlAuthRequest::new("emb", SamlAuthFlow::embedded()),
                )
                .await
            }
        });

        let pending = rx.recv().await.expect("pending");
        pending
            .respond
            .send(SamlPromptResponse::from_svpn_cookie("SVPNCOOKIE-channel"))
            .unwrap();
        let result = task.await.unwrap().unwrap();
        let dbg = format!("{result:?}");
        match result {
            SamlAuthResult::SvpnCookie(c) => assert_eq!(c.as_str(), "SVPNCOOKIE-channel"),
            SamlAuthResult::AuthId(_) => panic!("expected SvpnCookie"),
        }
        assert!(!dbg.contains("SVPNCOOKIE-channel"));
    }

    #[tokio::test]
    async fn channel_cancel_fail_closed() {
        let channel = Arc::new(ChannelSamlAuthCallback::new());
        let mut rx = channel.open_channel();

        let task = tokio::spawn({
            let channel = Arc::clone(&channel);
            async move {
                authenticate(
                    channel.as_ref(),
                    SamlAuthRequest::new("x", SamlAuthFlow::embedded()),
                )
                .await
            }
        });

        let pending = rx.recv().await.expect("pending");
        pending
            .respond
            .send(SamlPromptResponse::Cancelled)
            .unwrap();
        assert_eq!(task.await.unwrap().unwrap_err(), SamlAuthError::Cancelled);
    }

    #[tokio::test]
    async fn channel_auto_cancel_before_open() {
        let channel = ChannelSamlAuthCallback::new();
        let err = authenticate(
            &channel,
            SamlAuthRequest::new("x", SamlAuthFlow::external_browser_default()),
        )
        .await
        .unwrap_err();
        assert_eq!(err, SamlAuthError::Cancelled);
        assert_eq!(channel.complete_count(), 1);
    }

    #[tokio::test]
    async fn channel_closed_when_receiver_dropped() {
        let channel = ChannelSamlAuthCallback::new();
        let rx = channel.open_channel();
        drop(rx);
        let err = channel
            .complete(SamlAuthRequest::new("x", SamlAuthFlow::embedded()))
            .await
            .unwrap_err();
        assert_eq!(err, SamlAuthError::ChannelClosed);
    }

    #[tokio::test]
    async fn channel_pending_drop_maps_to_channel_closed() {
        let channel = Arc::new(ChannelSamlAuthCallback::new());
        let mut rx = channel.open_channel();
        let task = tokio::spawn({
            let channel = Arc::clone(&channel);
            async move {
                authenticate(
                    channel.as_ref(),
                    SamlAuthRequest::new("x", SamlAuthFlow::embedded()),
                )
                .await
            }
        });
        let pending = rx.recv().await.expect("pending");
        drop(pending);
        assert_eq!(task.await.unwrap().unwrap_err(), SamlAuthError::ChannelClosed);
    }

    #[tokio::test]
    async fn channel_rejects_mismatched_kind_without_echo() {
        let channel = Arc::new(ChannelSamlAuthCallback::new());
        let mut rx = channel.open_channel();
        let task = tokio::spawn({
            let channel = Arc::clone(&channel);
            async move {
                authenticate(
                    channel.as_ref(),
                    SamlAuthRequest::new("x", SamlAuthFlow::external_browser(8020)),
                )
                .await
            }
        });
        let pending = rx.recv().await.expect("pending");
        pending
            .respond
            .send(SamlPromptResponse::from_svpn_cookie("wrong-kind-cookie-SECRET"))
            .unwrap();
        let err = task.await.unwrap().unwrap_err();
        assert_eq!(err, SamlAuthError::InvalidResult);
        assert!(!format!("{err}").contains("wrong-kind-cookie-SECRET"));
    }

    #[tokio::test]
    async fn channel_set_auto_cancel_fail_closed_again() {
        let channel = ChannelSamlAuthCallback::new();
        let rx = channel.open_channel();
        drop(rx);
        channel.set_auto_cancel();
        let err = authenticate(
            &channel,
            SamlAuthRequest::new("x", SamlAuthFlow::embedded()),
        )
        .await
        .unwrap_err();
        assert_eq!(err, SamlAuthError::Cancelled);
    }
}
