//! Stormshield SNS (SN SSL VPN / "rpv") auth glue stub — OpenVPN-backed.
//!
//! Mirrors C# `StormshieldTunnelProvider` / `StormshieldSettings` credential typing:
//! username + password, with an optional single-use OTP **concatenated** onto the
//! password (`password + otp`) for both the HTTPS portal form and the OpenVPN
//! `auth-user-pass` data plane. Unlike WatchGuard (CRV1 `challenge_response`), SNS
//! never puts the OTP in a separate sidecar field.
//!
//! **Data plane:** shared `wormhole-ovpnproxy` via [`StormshieldAuthGlue`] /
//! [`stormshield_materials`] — same sidecar as OpenVPN / WatchGuard / Azure VPN.
//! No Stormshield-specific binary.
//!
//! **Wiring today:** portal download, config-hash cache, OTP reuse guard, and SSO
//! are **not** implemented. Helpers compose already-known credentials (+ optional
//! OTP from [`OtpPrompt`]) into [`ResolvedOvpnMaterials`]. Establish-path glue
//! ([`crate::establish_stormshield`] / [`crate::establish_stormshield_sns`]) calls
//! these stubs then [`StormshieldProvider`] / Fake — still **no** live SNS network.
//! `StormshieldProvider::establish` itself still expects already-built OpenVPN stdin JSON.
//!
//! Never log passwords or OTP codes. [`StormshieldPassword`] / [`StormshieldSnsCredentials`]
//! / [`StormshieldSnsAuthResult`] / [`FakeStormshieldSnsAuth`] [`Debug`] redact secrets.

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use super::builders::{stormshield_materials, ResolvedOvpnMaterials, StormshieldAuthGlue};
use super::otp_prompt::{request_otp, OtpCode, OtpPrompt};
use super::redact_nonempty;
use super::sidecar_config::OpenVpnTransportRemote;
use super::OvpnAuthGlue;
use crate::TunnelError;

/// OTP prompt title prefix (parity with C# `PromptOtpAsync`: `"Stormshield OTP — {name}"`).
pub const STORMSHIELD_OTP_TITLE_PREFIX: &str = "Stormshield OTP — ";

/// OTP prompt subtitle (parity with C# `PromptOtpAsync`).
pub const STORMSHIELD_OTP_SUBTITLE: &str =
    "Enter the one-time code for your VPN connection.";

/// Stormshield portal / OpenVPN username (not a secret — shown in Debug).
#[derive(Clone, PartialEq, Eq)]
pub struct StormshieldUsername(String);

impl StormshieldUsername {
    pub fn new(username: impl Into<String>) -> Self {
        Self(username.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }

    /// Trimmed non-empty username, or `None` when blank (Import / cert-only profiles).
    pub fn trimmed_nonempty(&self) -> Option<String> {
        let t = self.0.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    }
}

impl fmt::Debug for StormshieldUsername {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("StormshieldUsername")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for StormshieldUsername {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Stormshield password (never the OTP alone — OTP is appended via helpers).
///
/// [`Debug`] / [`Display`] never print the plaintext.
#[derive(Clone, PartialEq, Eq)]
pub struct StormshieldPassword(String);

impl StormshieldPassword {
    pub fn new(password: impl Into<String>) -> Self {
        Self(password.into())
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

impl fmt::Debug for StormshieldPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("StormshieldPassword")
            .field(&redact_nonempty(&self.0))
            .finish()
    }
}

impl fmt::Display for StormshieldPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(redact_nonempty(&self.0))
    }
}

/// Editor-facing credentials (username / password / OTP flag). OTP codes are never stored here.
#[derive(Clone, PartialEq, Eq)]
pub struct StormshieldSnsCredentials {
    pub username: StormshieldUsername,
    pub password: StormshieldPassword,
    /// When true, connect-time OTP is prompted and concatenated onto the password.
    pub use_otp: bool,
}

impl StormshieldSnsCredentials {
    pub fn new(
        username: impl Into<String>,
        password: impl Into<String>,
        use_otp: bool,
    ) -> Self {
        Self {
            username: StormshieldUsername::new(username),
            password: StormshieldPassword::new(password),
            use_otp,
        }
    }

    pub fn without_otp(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self::new(username, password, false)
    }

    pub fn with_otp(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self::new(username, password, true)
    }
}

impl fmt::Debug for StormshieldSnsCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StormshieldSnsCredentials")
            .field("username", &self.username)
            .field("password", &self.password)
            .field("use_otp", &self.use_otp)
            .finish()
    }
}

/// Where a prompted OTP is spent (parity with C# `ResolveAutomaticCoreAsync`).
///
/// SNS spends a single-use code in **exactly one** place — never both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StormshieldOtpSpend {
    /// No OTP — data-plane / portal password is the saved password alone.
    None,
    /// Cache hit: route OTP to OpenVPN `auth-user-pass` (`password + otp`).
    DataPlane,
    /// Cache miss: route OTP to HTTPS portal download (`pass = password + otp`).
    PortalDownload,
}

/// Resolved SNS auth materials ready for OpenVPN sidecar construction (or portal POST).
///
/// [`auth_password`](StormshieldSnsAuthResult::auth_password) is already composed
/// (`password` or `password + otp`). Never log it.
#[derive(Clone, PartialEq, Eq)]
pub struct StormshieldSnsAuthResult {
    pub username: StormshieldUsername,
    pub auth_password: StormshieldPassword,
    pub otp_spend: StormshieldOtpSpend,
}

impl StormshieldSnsAuthResult {
    pub fn new(
        username: StormshieldUsername,
        auth_password: StormshieldPassword,
        otp_spend: StormshieldOtpSpend,
    ) -> Self {
        Self {
            username,
            auth_password,
            otp_spend,
        }
    }
}

impl fmt::Debug for StormshieldSnsAuthResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StormshieldSnsAuthResult")
            .field("username", &self.username)
            .field("auth_password", &self.auth_password)
            .field("otp_spend", &self.otp_spend)
            .finish()
    }
}

/// Append a single-use OTP onto the saved password (C# `password + otp` / portal `pass`).
///
/// Never logs inputs or the result.
pub fn append_otp_to_password(password: &str, otp: &OtpCode) -> String {
    let mut out = String::with_capacity(password.len() + otp.as_str().len());
    out.push_str(password);
    out.push_str(otp.as_str());
    out
}

/// Compose SNS auth password: optional OTP concatenation.
///
/// - `otp == None` → `password` unchanged (Import mode / `UseOtp == false`)
/// - `otp == Some` → `password + otp` (Automatic cache-hit data plane or portal download)
pub fn compose_sns_auth_password(password: &str, otp: Option<&OtpCode>) -> String {
    match otp {
        Some(code) => append_otp_to_password(password, code),
        None => password.to_string(),
    }
}

/// Build OpenVPN materials for [`StormshieldAuthGlue`] from SNS credentials + composed password.
///
/// `auth_password` must already include any OTP suffix. Optional transport pinning matches
/// C# `BuildSidecarConfig` (`TransportAdapterIds` / `TransportRemotes`).
pub fn stormshield_materials_from_sns(
    profile_ovpn: impl Into<String>,
    username: &StormshieldUsername,
    auth_password: &StormshieldPassword,
    transport_adapter_ids: Option<Vec<String>>,
    transport_remotes: Option<Vec<OpenVpnTransportRemote>>,
) -> ResolvedOvpnMaterials {
    stormshield_materials(
        profile_ovpn,
        username.trimmed_nonempty(),
        {
            let p = auth_password.as_str();
            if p.is_empty() {
                None
            } else {
                Some(p.to_string())
            }
        },
        transport_adapter_ids,
        transport_remotes,
    )
}

/// Prompt for a Stormshield OTP with C#-parity title/subtitle.
///
/// Never logs the code. Call from portal / cache-hit data-plane paths when those land.
pub async fn request_stormshield_otp(
    prompt: &dyn OtpPrompt,
    config_name: impl AsRef<str>,
) -> Result<OtpCode, TunnelError> {
    let title = format!("{STORMSHIELD_OTP_TITLE_PREFIX}{}", config_name.as_ref());
    request_otp(prompt, title, STORMSHIELD_OTP_SUBTITLE).await
}

/// Resolve data-plane auth password from editor credentials + optional OTP prompt.
///
/// - `use_otp == false` → saved password, no prompt ([`StormshieldOtpSpend::None`])
/// - `use_otp == true` → prompt then `password + otp` ([`StormshieldOtpSpend::DataPlane`])
///
/// Portal-download spend ([`StormshieldOtpSpend::PortalDownload`]) is the same composition;
/// callers choose spend semantics after cache hit/miss — this helper covers the data-plane path.
/// Does **not** run portal HTTPS or mutate establish.
pub async fn resolve_sns_data_plane_auth(
    credentials: &StormshieldSnsCredentials,
    prompt: &dyn OtpPrompt,
    config_name: impl AsRef<str>,
) -> Result<StormshieldSnsAuthResult, TunnelError> {
    tracing::debug!(
        config_name = %config_name.as_ref(),
        use_otp = credentials.use_otp,
        "resolving Stormshield SNS data-plane auth (portal/cache not wired)"
    );

    let otp = if credentials.use_otp {
        Some(request_stormshield_otp(prompt, config_name).await?)
    } else {
        None
    };
    let otp_spend = if otp.is_some() {
        StormshieldOtpSpend::DataPlane
    } else {
        StormshieldOtpSpend::None
    };
    let composed = compose_sns_auth_password(credentials.password.as_str(), otp.as_ref());
    Ok(StormshieldSnsAuthResult::new(
        credentials.username.clone(),
        StormshieldPassword::new(composed),
        otp_spend,
    ))
}

/// Serialize [`StormshieldAuthGlue`] stdin JSON from SNS materials (shape-gate safe).
pub fn stormshield_sns_to_sidecar_json(
    materials: &ResolvedOvpnMaterials,
) -> Result<Vec<u8>, TunnelError> {
    StormshieldAuthGlue.to_sidecar_json(materials)
}

/// Non-secret request metadata for scripted [`StormshieldSnsAuth`] fakes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StormshieldSnsAuthRequest {
    pub config_name: String,
    pub credentials: StormshieldSnsCredentials,
    pub otp_spend: StormshieldOtpSpend,
}

impl StormshieldSnsAuthRequest {
    pub fn new(
        config_name: impl Into<String>,
        credentials: StormshieldSnsCredentials,
        otp_spend: StormshieldOtpSpend,
    ) -> Self {
        Self {
            config_name: config_name.into(),
            credentials,
            otp_spend,
        }
    }
}

/// UI-independent SNS auth resolver — test / headless surface until portal loops land.
///
/// Implementations must **never** write passwords or OTP codes to logs.
#[async_trait]
pub trait StormshieldSnsAuth: Send + Sync {
    async fn resolve(
        &self,
        request: StormshieldSnsAuthRequest,
    ) -> Result<StormshieldSnsAuthResult, TunnelError>;
}

/// Always cancels when OTP is required; otherwise returns password-only credentials.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullStormshieldSnsAuth;

#[async_trait]
impl StormshieldSnsAuth for NullStormshieldSnsAuth {
    async fn resolve(
        &self,
        request: StormshieldSnsAuthRequest,
    ) -> Result<StormshieldSnsAuthResult, TunnelError> {
        match request.otp_spend {
            StormshieldOtpSpend::None => Ok(StormshieldSnsAuthResult::new(
                request.credentials.username,
                request.credentials.password,
                StormshieldOtpSpend::None,
            )),
            StormshieldOtpSpend::DataPlane | StormshieldOtpSpend::PortalDownload => {
                Err(TunnelError::Cancelled)
            }
        }
    }
}

/// Scripted SNS auth for unit tests (parity with other auth_glue Fakes).
///
/// Each [`resolve`](StormshieldSnsAuth::resolve) dequeues the next optional OTP code
/// when spend ≠ [`StormshieldOtpSpend::None`]. Queue empty / `None` → cancel when OTP required.
///
/// [`Debug`] redacts queued OTP codes and never dumps passwords.
#[derive(Default)]
pub struct MemoryStormshieldSnsAuth {
    /// Queued OTP codes for DataPlane / PortalDownload spends (`None` = user dismiss).
    otp_script: Mutex<VecDeque<Option<String>>>,
    requests: Mutex<Vec<StormshieldSnsAuthRequest>>,
    resolve_count: AtomicUsize,
}

impl fmt::Debug for MemoryStormshieldSnsAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let script = self.otp_script.lock().unwrap_or_else(|p| p.into_inner());
        let redacted: Vec<Option<&str>> = script
            .iter()
            .map(|slot| match slot {
                Some(code) => Some(redact_nonempty(code)),
                None => None,
            })
            .collect();
        let requests = self.requests.lock().unwrap_or_else(|p| p.into_inner());
        f.debug_struct("MemoryStormshieldSnsAuth")
            .field("otp_script", &redacted)
            .field("requests", &*requests)
            .field("resolve_count", &self.resolve_count.load(Ordering::SeqCst))
            .finish()
    }
}

impl MemoryStormshieldSnsAuth {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue OTP codes / cancels for OTP spends.
    pub fn from_otp_codes(codes: impl IntoIterator<Item = Option<impl Into<String>>>) -> Self {
        let auth = Self::new();
        for code in codes {
            auth.push_otp(code.map(Into::into));
        }
        auth
    }

    /// Convenience: all queued entries are submitted OTP codes.
    pub fn from_submitted_otps(codes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::from_otp_codes(codes.into_iter().map(|c| Some(c)))
    }

    pub fn push_otp(&self, code: Option<String>) {
        self.otp_script
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push_back(code);
    }

    pub fn resolve_count(&self) -> usize {
        self.resolve_count.load(Ordering::SeqCst)
    }

    pub fn requests(&self) -> Vec<StormshieldSnsAuthRequest> {
        self.requests
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

#[async_trait]
impl StormshieldSnsAuth for MemoryStormshieldSnsAuth {
    async fn resolve(
        &self,
        request: StormshieldSnsAuthRequest,
    ) -> Result<StormshieldSnsAuthResult, TunnelError> {
        self.resolve_count.fetch_add(1, Ordering::SeqCst);
        self.requests
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(request.clone());

        let otp = match request.otp_spend {
            StormshieldOtpSpend::None => None,
            StormshieldOtpSpend::DataPlane | StormshieldOtpSpend::PortalDownload => {
                let next = self
                    .otp_script
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .pop_front();
                match next {
                    Some(Some(code)) => {
                        let trimmed = code.trim();
                        if trimmed.is_empty() {
                            return Err(TunnelError::Establish(
                                "Stormshield OTP prompt returned an empty code".into(),
                            ));
                        }
                        Some(OtpCode::new(trimmed))
                    }
                    Some(None) | None => return Err(TunnelError::Cancelled),
                }
            }
        };

        let composed =
            compose_sns_auth_password(request.credentials.password.as_str(), otp.as_ref());
        Ok(StormshieldSnsAuthResult::new(
            request.credentials.username,
            StormshieldPassword::new(composed),
            request.otp_spend,
        ))
    }
}

/// Alias used in tests — same type as [`MemoryStormshieldSnsAuth`].
pub type FakeStormshieldSnsAuth = MemoryStormshieldSnsAuth;

/// Shared handle type for DI / future provider fields.
pub type SharedStormshieldSnsAuth = Arc<dyn StormshieldSnsAuth>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::auth_glue::otp_prompt::FakeOtpPrompt;
    use crate::providers::secret_shape::require_openvpn_sidecar_secret;

    #[test]
    fn append_otp_concatenates_without_separator() {
        let otp = OtpCode::new("123456");
        assert_eq!(append_otp_to_password("s3cret", &otp), "s3cret123456");
        assert_eq!(
            compose_sns_auth_password("s3cret", Some(&otp)),
            "s3cret123456"
        );
        assert_eq!(compose_sns_auth_password("s3cret", None), "s3cret");
    }

    #[test]
    fn sns_otp_goes_into_password_never_challenge_response() {
        // C# parity: `password + otp` (portal `pass` / OpenVPN auth-user-pass).
        // WatchGuard CRV1 puts OTP in `challenge_response` — that shape is wrong for SNS.
        let otp = OtpCode::new("654321");
        let composed = compose_sns_auth_password("secret", Some(&otp));
        assert_eq!(composed, "secret654321");
        // Wrong compositions rejected:
        assert_ne!(composed, "654321", "OTP alone is not SNS auth password");
        assert_ne!(
            composed, "secret",
            "password without OTP suffix is wrong when OTP is present"
        );

        let materials = stormshield_materials_from_sns(
            "client\n",
            &StormshieldUsername::new("u"),
            &StormshieldPassword::new(composed),
            None,
            None,
        );
        assert_eq!(materials.password.as_deref(), Some("secret654321"));
        assert!(
            materials.challenge_response.is_none(),
            "SNS must not populate challenge_response (WatchGuard CRV1 shape)"
        );
        let json = stormshield_sns_to_sidecar_json(&materials).unwrap();
        require_openvpn_sidecar_secret(&json).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(v["password"], "secret654321");
        assert!(
            v.get("challenge_response").is_none() || v["challenge_response"].is_null(),
            "sidecar JSON must not carry challenge_response for SNS: {v}"
        );
    }

    #[test]
    fn password_debug_and_display_redact_secrets() {
        let pw = StormshieldPassword::new("PASS_SECRET");
        let dbg_pw = format!("{pw:?}");
        assert!(dbg_pw.contains("[REDACTED]"), "{dbg_pw}");
        assert!(!dbg_pw.contains("PASS_SECRET"), "{dbg_pw}");
        assert_eq!(format!("{pw}"), "[REDACTED]");
        assert_eq!(format!("{:?}", StormshieldPassword::new("")), "StormshieldPassword(\"\")");

        let creds = StormshieldSnsCredentials::with_otp("alice", "PASS_SECRET");
        let dbg_creds = format!("{creds:?}");
        assert!(dbg_creds.contains("[REDACTED]"), "{dbg_creds}");
        assert!(!dbg_creds.contains("PASS_SECRET"), "{dbg_creds}");
        assert!(dbg_creds.contains("alice"), "{dbg_creds}");

        let otp = OtpCode::new("OTP_SECRET");
        let composed = compose_sns_auth_password("PASS_SECRET", Some(&otp));
        let result = StormshieldSnsAuthResult::new(
            StormshieldUsername::new("alice"),
            StormshieldPassword::new(composed),
            StormshieldOtpSpend::DataPlane,
        );
        let dbg = format!("{result:?}");
        assert!(dbg.contains("[REDACTED]"), "{dbg}");
        assert!(!dbg.contains("PASS_SECRET"), "{dbg}");
        assert!(!dbg.contains("OTP_SECRET"), "{dbg}");
        assert!(!dbg.contains("PASS_SECRETOTP_SECRET"), "{dbg}");

        let req = StormshieldSnsAuthRequest::new(
            "lab",
            StormshieldSnsCredentials::with_otp("alice", "PASS_SECRET"),
            StormshieldOtpSpend::DataPlane,
        );
        let dbg_req = format!("{req:?}");
        assert!(!dbg_req.contains("PASS_SECRET"), "{dbg_req}");
        assert!(dbg_req.contains("[REDACTED]"), "{dbg_req}");
    }

    #[test]
    fn fake_debug_redacts_otp_script() {
        let fake = FakeStormshieldSnsAuth::from_submitted_otps(["OTP_SECRET"]);
        let dbg = format!("{fake:?}");
        assert!(dbg.contains("[REDACTED]"), "{dbg}");
        assert!(!dbg.contains("OTP_SECRET"), "{dbg}");
    }

    #[tokio::test]
    async fn fake_data_plane_otp_composes_password_and_sidecar_json() {
        let fake = FakeStormshieldSnsAuth::from_submitted_otps(["654321"]);
        let creds = StormshieldSnsCredentials::with_otp("bob", "pw");
        let result = fake
            .resolve(StormshieldSnsAuthRequest::new(
                "lab",
                creds,
                StormshieldOtpSpend::DataPlane,
            ))
            .await
            .unwrap();
        assert_eq!(result.auth_password.as_str(), "pw654321");
        assert_eq!(result.otp_spend, StormshieldOtpSpend::DataPlane);

        let materials = stormshield_materials_from_sns(
            "dev tun\nremote fw.example 1194 udp\n",
            &result.username,
            &result.auth_password,
            Some(vec!["{adapter}".into()]),
            Some(vec![OpenVpnTransportRemote {
                host: "fw.example".into(),
                port: "1194".into(),
                protocol: "udp".into(),
            }]),
        );
        let json = stormshield_sns_to_sidecar_json(&materials).unwrap();
        require_openvpn_sidecar_secret(&json).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(v["username"], "bob");
        assert_eq!(v["password"], "pw654321");
        assert!(v.get("challenge_response").is_none());
        assert_eq!(v["transport_remotes"][0]["host"], "fw.example");
    }

    #[tokio::test]
    async fn fake_portal_download_spend_same_composition() {
        let fake = FakeStormshieldSnsAuth::from_submitted_otps(["111222"]);
        let result = fake
            .resolve(StormshieldSnsAuthRequest::new(
                "lab",
                StormshieldSnsCredentials::with_otp("u", "base"),
                StormshieldOtpSpend::PortalDownload,
            ))
            .await
            .unwrap();
        assert_eq!(result.auth_password.as_str(), "base111222");
        assert_eq!(result.otp_spend, StormshieldOtpSpend::PortalDownload);
    }

    #[tokio::test]
    async fn fake_no_otp_uses_password_alone() {
        let fake = FakeStormshieldSnsAuth::new();
        let result = fake
            .resolve(StormshieldSnsAuthRequest::new(
                "lab",
                StormshieldSnsCredentials::without_otp("u", "only"),
                StormshieldOtpSpend::None,
            ))
            .await
            .unwrap();
        assert_eq!(result.auth_password.as_str(), "only");
        assert_eq!(fake.resolve_count(), 1);
        assert_eq!(fake.requests().len(), 1);
    }

    #[tokio::test]
    async fn fake_cancel_when_otp_required_and_exhausted() {
        let fake = FakeStormshieldSnsAuth::new();
        let err = fake
            .resolve(StormshieldSnsAuthRequest::new(
                "lab",
                StormshieldSnsCredentials::with_otp("u", "pw"),
                StormshieldOtpSpend::DataPlane,
            ))
            .await
            .unwrap_err();
        assert!(matches!(err, TunnelError::Cancelled), "{err:?}");
    }

    #[tokio::test]
    async fn resolve_sns_data_plane_auth_uses_otp_prompt_titles() {
        let prompt = FakeOtpPrompt::from_submitted(["999888"]);
        let creds = StormshieldSnsCredentials::with_otp("carol", "secret");
        let result = resolve_sns_data_plane_auth(&creds, &prompt, "edge-fw")
            .await
            .unwrap();
        assert_eq!(result.auth_password.as_str(), "secret999888");
        assert_eq!(result.otp_spend, StormshieldOtpSpend::DataPlane);
        let reqs = prompt.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].title, "Stormshield OTP — edge-fw");
        assert_eq!(reqs[0].subtitle, STORMSHIELD_OTP_SUBTITLE);
    }

    #[tokio::test]
    async fn resolve_without_otp_skips_prompt() {
        let prompt = FakeOtpPrompt::from_submitted(["SHOULD_NOT_USE"]);
        let creds = StormshieldSnsCredentials::without_otp("carol", "secret");
        let result = resolve_sns_data_plane_auth(&creds, &prompt, "edge-fw")
            .await
            .unwrap();
        assert_eq!(result.auth_password.as_str(), "secret");
        assert_eq!(result.otp_spend, StormshieldOtpSpend::None);
        assert_eq!(prompt.prompt_count(), 0);
    }

    #[tokio::test]
    async fn null_auth_cancels_when_otp_required() {
        for spend in [
            StormshieldOtpSpend::DataPlane,
            StormshieldOtpSpend::PortalDownload,
        ] {
            let err = NullStormshieldSnsAuth
                .resolve(StormshieldSnsAuthRequest::new(
                    "lab",
                    StormshieldSnsCredentials::with_otp("u", "pw"),
                    spend,
                ))
                .await
                .unwrap_err();
            assert!(
                matches!(err, TunnelError::Cancelled),
                "Null must fail-closed for {spend:?}, got {err:?}"
            );
        }

        // No OTP spend → password-only (fail-closed does not apply).
        let ok = NullStormshieldSnsAuth
            .resolve(StormshieldSnsAuthRequest::new(
                "lab",
                StormshieldSnsCredentials::without_otp("u", "pw"),
                StormshieldOtpSpend::None,
            ))
            .await
            .unwrap();
        assert_eq!(ok.auth_password.as_str(), "pw");
        assert_eq!(ok.otp_spend, StormshieldOtpSpend::None);
    }

    #[tokio::test]
    async fn fake_is_deterministic_otp_queue() {
        let fake = FakeStormshieldSnsAuth::from_submitted_otps(["111111", "222222"]);
        let creds = StormshieldSnsCredentials::with_otp("u", "pw");
        let a = fake
            .resolve(StormshieldSnsAuthRequest::new(
                "lab",
                creds.clone(),
                StormshieldOtpSpend::DataPlane,
            ))
            .await
            .unwrap();
        let b = fake
            .resolve(StormshieldSnsAuthRequest::new(
                "lab",
                creds.clone(),
                StormshieldOtpSpend::PortalDownload,
            ))
            .await
            .unwrap();
        assert_eq!(a.auth_password.as_str(), "pw111111");
        assert_eq!(b.auth_password.as_str(), "pw222222");
        let exhausted = fake
            .resolve(StormshieldSnsAuthRequest::new(
                "lab",
                creds,
                StormshieldOtpSpend::DataPlane,
            ))
            .await
            .unwrap_err();
        assert!(matches!(exhausted, TunnelError::Cancelled));
        assert_eq!(fake.resolve_count(), 3);
    }

    #[tokio::test]
    async fn fake_rejects_empty_otp_code() {
        let fake = FakeStormshieldSnsAuth::from_otp_codes([Some("   ")]);
        let err = fake
            .resolve(StormshieldSnsAuthRequest::new(
                "lab",
                StormshieldSnsCredentials::with_otp("u", "pw"),
                StormshieldOtpSpend::DataPlane,
            ))
            .await
            .unwrap_err();
        match err {
            TunnelError::Establish(msg) => assert!(msg.contains("empty"), "{msg}"),
            other => panic!("expected Establish, got {other:?}"),
        }
    }

    #[test]
    fn empty_username_omitted_from_materials() {
        let materials = stormshield_materials_from_sns(
            "client\n",
            &StormshieldUsername::new("  "),
            &StormshieldPassword::new("pw"),
            None,
            None,
        );
        assert!(materials.username.is_none());
        assert_eq!(materials.password.as_deref(), Some("pw"));
        assert!(materials.challenge_response.is_none());
    }
}
