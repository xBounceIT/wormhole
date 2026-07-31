//! WatchGuard Firebox username/password + optional OTP typing helpers.
//!
//! Mirrors the C# credential / second-factor half of `WatchguardTunnelProvider`
//! (stored-profile CRV1 path + portal sslvpn_logon password quirk) **without**
//! HTTP pre-auth or WebView2 SAML.
//!
//! **Data plane:** always the shared OpenVPN sidecar (`wormhole-ovpnproxy`) via
//! [`WatchguardAuthGlue`](crate::providers::auth_glue::WatchguardAuthGlue).
//! Establish-path glue ([`crate::establish_watchguard_crv1`] /
//! [`crate::establish_watchguard_portal`]) resolves stdin JSON through these
//! helpers then calls [`WatchguardProvider`](crate::WatchguardProvider) /
//! [`FakeTunnelProvider`](crate::FakeTunnelProvider). Live Firebox HTTP / SAML
//! remain unwired — profile text is caller-supplied.
//!
//! **CRV1 vs portal (do not cross the password field):**
//! - Stored-profile / cache ([`firebox_materials_crv1`] / [`resolve_firebox_crv1_sidecar_json`]):
//!   account password → OpenVPN `password`; OTP/`"p"` → `challenge_response`.
//! - Portal download ([`firebox_materials_portal`] / [`resolve_firebox_portal_sidecar_json`]):
//!   OTP → OpenVPN `password` quirk ([`portal_openvpn_password`]); push/no-2FA keep
//!   account password; **never** set `challenge_response`.
//!
//! Never log passwords or OTP codes. [`FireboxPassword`] / [`FireboxSecondFactor`]
//! / [`FakeFireboxCredentials`] [`Debug`] (and password [`Display`]) redact values.

use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::providers::auth_glue::{
    request_second_factor, watchguard_materials, OtpCode, OtpPrompt, OtpPromptRequest, OvpnAuthGlue,
    ResolvedOvpnMaterials, WatchguardAuthGlue,
};
use crate::providers::auth_glue::redact_nonempty;
use crate::TunnelError;

/// AuthPoint / Firebox push selector typed into the OTP prompt (`"p"`).
pub const FIREBOX_PUSH_SELECTOR: &str = "p";

/// Built-in Firebox domain default (`WatchguardSettings.DefaultDomain` = `Firebox-DB`).
/// Empty / this value both mean “let the Firebox choose” on the wire.
pub const FIREBOX_DEFAULT_DOMAIN: &str = "Firebox-DB";

/// Firebox / SSL-VPN username (not redacted — matches [`ResolvedOvpnMaterials`] Debug).
#[derive(Clone, PartialEq, Eq)]
pub struct FireboxUsername(String);

impl FireboxUsername {
    pub fn new(username: impl Into<String>) -> Self {
        Self(username.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Debug for FireboxUsername {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("FireboxUsername").field(&self.0).finish()
    }
}

impl fmt::Display for FireboxUsername {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Firebox account password (never log).
#[derive(Clone, PartialEq, Eq)]
pub struct FireboxPassword(String);

impl FireboxPassword {
    pub fn new(password: impl Into<String>) -> Self {
        Self(password.into())
    }

    /// Borrow plaintext (do not log / tracing).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume into plaintext (sidecar / materials boundary only).
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Debug for FireboxPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("FireboxPassword")
            .field(&redact_nonempty(&self.0))
            .finish()
    }
}

impl fmt::Display for FireboxPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(redact_nonempty(&self.0))
    }
}

/// Username + password for Firebox username/password auth.
#[derive(Clone, PartialEq, Eq)]
pub struct FireboxCredentials {
    pub username: FireboxUsername,
    pub password: FireboxPassword,
}

impl FireboxCredentials {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: FireboxUsername::new(username),
            password: FireboxPassword::new(password),
        }
    }

    /// Reject whitespace-only username/password (parity with C# `IsNullOrWhiteSpace` pre-flight).
    ///
    /// Username is trimmed for the wire. Password keeps its stored form after the
    /// whitespace-only check — C# does not strip surrounding spaces from `settings.Password`.
    pub fn validated(self) -> Result<Self, TunnelError> {
        let user = self.username.into_inner();
        let pass = self.password.into_inner();
        let user_t = user.trim();
        if user_t.is_empty() {
            return Err(TunnelError::Establish(
                "WatchGuard Firebox credentials require a non-empty username".into(),
            ));
        }
        if pass.trim().is_empty() {
            return Err(TunnelError::Establish(
                "WatchGuard Firebox credentials require a non-empty password".into(),
            ));
        }
        Ok(Self::new(user_t, pass))
    }
}

impl fmt::Debug for FireboxCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FireboxCredentials")
            .field("username", &self.username)
            .field("password", &self.password)
            .finish()
    }
}

/// Optional second factor for OpenVPN CRV1 / AuthPoint (parity with C# prompt).
#[derive(Clone, PartialEq, Eq)]
pub enum FireboxSecondFactor {
    /// One-time passcode → OpenVPN `challenge_response` (CRV1) or portal OpenVPN password.
    OneTimeCode(OtpCode),
    /// Push selector `"p"` (normalized).
    Push,
}

impl FireboxSecondFactor {
    /// Value carried as OpenVPN `challenge_response` on the stored-profile path.
    pub fn challenge_response_value(&self) -> &str {
        match self {
            Self::OneTimeCode(code) => code.as_str(),
            Self::Push => FIREBOX_PUSH_SELECTOR,
        }
    }

    pub fn is_push(&self) -> bool {
        matches!(self, Self::Push)
    }
}

impl fmt::Debug for FireboxSecondFactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OneTimeCode(code) => f.debug_tuple("OneTimeCode").field(code).finish(),
            Self::Push => f.write_str("Push"),
        }
    }
}

/// Map a trimmed OTP prompt result to [`FireboxSecondFactor`] (`"p"` → Push).
pub fn normalize_firebox_second_factor(code: OtpCode) -> FireboxSecondFactor {
    if code.as_str().eq_ignore_ascii_case(FIREBOX_PUSH_SELECTOR) {
        FireboxSecondFactor::Push
    } else {
        FireboxSecondFactor::OneTimeCode(code)
    }
}

/// OTP prompt metadata for WatchGuard 2FA (parity with C# `PromptForSecondFactorAsync`).
pub fn firebox_second_factor_prompt_request(
    config_name: impl AsRef<str>,
    challenge_text: Option<&str>,
) -> OtpPromptRequest {
    let title = format!("Watchguard 2FA — {}", config_name.as_ref());
    let subtitle = match challenge_text.map(str::trim).filter(|s| !s.is_empty()) {
        Some(text) => format!(
            "{text}\n\nEnter an AuthPoint OTP code, or type 'p' to send a push notification."
        ),
        None => {
            "Enter your one-time passcode, or type 'p' to approve with a push notification."
                .to_string()
        }
    };
    OtpPromptRequest::new(title, subtitle)
}

/// Request a Firebox / AuthPoint second factor via [`request_second_factor`] /
/// [`request_otp`] (same trim / cancel / empty contracts).
///
/// Used by [`crate::establish_watchguard_crv1`] / [`crate::establish_watchguard_portal`]
/// (and `resolve_firebox_*`); live Firebox HTTP challenge text remains optional.
pub async fn request_firebox_second_factor(
    prompt: &dyn OtpPrompt,
    config_name: impl AsRef<str>,
    challenge_text: Option<&str>,
) -> Result<FireboxSecondFactor, TunnelError> {
    let request = firebox_second_factor_prompt_request(config_name, challenge_text);
    let code = request_second_factor(prompt, request).await?;
    Ok(normalize_firebox_second_factor(code))
}

/// Portal sslvpn_logon quirk: OTP becomes the OpenVPN password; push keeps the account password.
///
/// Parity with C# `RunPreAuthLoopAsync` return value after a successful challenge.
pub fn portal_openvpn_password(
    account_password: &FireboxPassword,
    second_factor: Option<&FireboxSecondFactor>,
) -> FireboxPassword {
    match second_factor {
        Some(FireboxSecondFactor::OneTimeCode(code)) => FireboxPassword::new(code.as_str()),
        Some(FireboxSecondFactor::Push) | None => FireboxPassword::new(account_password.as_str()),
    }
}

/// Stored-profile / cache path: username + password + optional CRV1 `challenge_response`.
///
/// OTP answers the OpenVPN dynamic challenge; account password stays on `auth-user-pass`.
pub fn firebox_materials_crv1(
    profile_ovpn: impl Into<String>,
    credentials: &FireboxCredentials,
    second_factor: Option<&FireboxSecondFactor>,
) -> ResolvedOvpnMaterials {
    let challenge = second_factor.map(|f| f.challenge_response_value().to_string());
    watchguard_materials(
        profile_ovpn,
        credentials.username.as_str(),
        credentials.password.as_str(),
        challenge,
    )
}

/// Portal download path: 2FA already satisfied at sslvpn_logon — no `challenge_response`.
///
/// `openvpn_password` is either the account password (no 2FA / push) or the OTP
/// (Firebox one-shot quirk) from [`portal_openvpn_password`].
pub fn firebox_materials_portal(
    profile_ovpn: impl Into<String>,
    username: &FireboxUsername,
    openvpn_password: &FireboxPassword,
) -> ResolvedOvpnMaterials {
    watchguard_materials(
        profile_ovpn,
        username.as_str(),
        openvpn_password.as_str(),
        None,
    )
}

async fn optional_firebox_second_factor(
    otp_prompt: Option<&dyn OtpPrompt>,
    config_name: impl AsRef<str>,
) -> Result<Option<FireboxSecondFactor>, TunnelError> {
    match otp_prompt {
        Some(prompt) => Ok(Some(
            request_firebox_second_factor(prompt, config_name, None).await?,
        )),
        None => Ok(None),
    }
}

/// Build OpenVPN sidecar stdin JSON for the CRV1 / stored-profile path.
///
/// When `otp_prompt` is `Some`, prompts once and sets `challenge_response`
/// (account password stays on `auth-user-pass`). When `None`, emits username/password
/// only (no 2FA). [`NullOtpPrompt`] / user cancel → [`TunnelError::Cancelled`].
pub async fn resolve_firebox_crv1_sidecar_json(
    profile_ovpn: impl Into<String>,
    credentials: &FireboxCredentials,
    otp_prompt: Option<&dyn OtpPrompt>,
    config_name: impl AsRef<str>,
) -> Result<Vec<u8>, TunnelError> {
    let credentials = credentials.clone().validated()?;
    let second = optional_firebox_second_factor(otp_prompt, config_name).await?;
    let materials = firebox_materials_crv1(profile_ovpn, &credentials, second.as_ref());
    WatchguardAuthGlue.to_sidecar_json(&materials)
}

/// Build OpenVPN sidecar stdin JSON for the portal path (no CRV1 challenge).
///
/// Optional OTP is applied via [`portal_openvpn_password`] (OTP → OpenVPN password quirk;
/// push keeps the account password). Never sets `challenge_response`.
/// [`NullOtpPrompt`] / user cancel → [`TunnelError::Cancelled`].
pub async fn resolve_firebox_portal_sidecar_json(
    profile_ovpn: impl Into<String>,
    credentials: &FireboxCredentials,
    otp_prompt: Option<&dyn OtpPrompt>,
    config_name: impl AsRef<str>,
) -> Result<Vec<u8>, TunnelError> {
    let credentials = credentials.clone().validated()?;
    let second = optional_firebox_second_factor(otp_prompt, config_name).await?;
    let openvpn_password = portal_openvpn_password(&credentials.password, second.as_ref());
    let materials =
        firebox_materials_portal(profile_ovpn, &credentials.username, &openvpn_password);
    WatchguardAuthGlue.to_sidecar_json(&materials)
}

/// Scripted Firebox credentials for unit tests (`Fake` naming parity with SAML / Entra stubs).
///
/// [`Debug`] redacts the password. Pair with [`crate::FakeOtpPrompt`] for OTP flows.
#[derive(Clone)]
pub struct FakeFireboxCredentials {
    inner: Arc<Mutex<FireboxCredentials>>,
    resolve_count: Arc<AtomicUsize>,
}

impl FakeFireboxCredentials {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(FireboxCredentials::new(username, password))),
            resolve_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn credentials(&self) -> FireboxCredentials {
        self.resolve_count.fetch_add(1, Ordering::SeqCst);
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    pub fn resolve_count(&self) -> usize {
        self.resolve_count.load(Ordering::SeqCst)
    }

    pub fn set_password(&self, password: impl Into<String>) {
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        guard.password = FireboxPassword::new(password);
    }
}

impl fmt::Debug for FakeFireboxCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let creds = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        f.debug_struct("FakeFireboxCredentials")
            .field("username", &creds.username)
            .field("password", &creds.password)
            .field("resolve_count", &self.resolve_count.load(Ordering::SeqCst))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::auth_glue::{FakeOtpPrompt, NullOtpPrompt};
    use crate::providers::secret_shape::require_openvpn_sidecar_secret;

    #[test]
    fn firebox_default_domain_matches_csharp() {
        assert_eq!(FIREBOX_DEFAULT_DOMAIN, "Firebox-DB");
    }

    #[test]
    fn password_debug_and_display_redact() {
        let pw = FireboxPassword::new("WG_PASS_SECRET");
        let dbg = format!("{pw:?}");
        assert!(dbg.contains("[REDACTED]"), "{dbg}");
        assert!(!dbg.contains("WG_PASS_SECRET"), "{dbg}");
        assert_eq!(format!("{pw}"), "[REDACTED]");
        assert_eq!(format!("{:?}", FireboxPassword::new("")), "FireboxPassword(\"\")");
    }

    #[test]
    fn credentials_and_fake_debug_redact_password() {
        let creds = FireboxCredentials::new("alice", "PASS_LEAK");
        let dbg = format!("{creds:?}");
        assert!(dbg.contains("alice"), "{dbg}");
        assert!(!dbg.contains("PASS_LEAK"), "{dbg}");
        assert!(dbg.contains("[REDACTED]"), "{dbg}");

        let fake = FakeFireboxCredentials::new("bob", "FAKE_PASS_LEAK");
        let fake_dbg = format!("{fake:?}");
        assert!(!fake_dbg.contains("FAKE_PASS_LEAK"), "{fake_dbg}");
        assert!(fake_dbg.contains("[REDACTED]"), "{fake_dbg}");
    }

    #[test]
    fn second_factor_debug_redacts_otp() {
        let factor = FireboxSecondFactor::OneTimeCode(OtpCode::new("OTP_LEAK_999"));
        let dbg = format!("{factor:?}");
        assert!(dbg.contains("[REDACTED]"), "{dbg}");
        assert!(!dbg.contains("OTP_LEAK_999"), "{dbg}");
        assert_eq!(format!("{:?}", FireboxSecondFactor::Push), "Push");
    }

    #[test]
    fn normalize_push_selector_case_insensitive() {
        assert!(normalize_firebox_second_factor(OtpCode::new("p")).is_push());
        assert!(normalize_firebox_second_factor(OtpCode::new("P")).is_push());
        match normalize_firebox_second_factor(OtpCode::new("123456")) {
            FireboxSecondFactor::OneTimeCode(code) => assert_eq!(code.as_str(), "123456"),
            FireboxSecondFactor::Push => panic!("expected OTP"),
        }
    }

    #[test]
    fn validated_rejects_empty_without_echo() {
        let err = FireboxCredentials::new("  ", "pw")
            .validated()
            .unwrap_err();
        assert!(format!("{err}").contains("username"), "{err}");
        let err = FireboxCredentials::new("user", "   ")
            .validated()
            .unwrap_err();
        let rendered = format!("{err}");
        assert!(rendered.contains("password"), "{rendered}");
        assert!(!rendered.contains("   "));
    }

    #[test]
    fn validated_trims_username_preserves_password_spaces() {
        let creds = FireboxCredentials::new("  alice  ", "  pass with spaces  ")
            .validated()
            .unwrap();
        assert_eq!(creds.username.as_str(), "alice");
        assert_eq!(creds.password.as_str(), "  pass with spaces  ");
    }

    #[test]
    fn portal_password_quirk_otp_vs_push() {
        let account = FireboxPassword::new("account-pw");
        let otp = FireboxSecondFactor::OneTimeCode(OtpCode::new("654321"));
        assert_eq!(
            portal_openvpn_password(&account, Some(&otp)).as_str(),
            "654321"
        );
        assert_eq!(
            portal_openvpn_password(&account, Some(&FireboxSecondFactor::Push)).as_str(),
            "account-pw"
        );
        assert_eq!(portal_openvpn_password(&account, None).as_str(), "account-pw");
    }

    #[test]
    fn crv1_materials_carry_challenge_and_pass_shape_gate() {
        let creds = FireboxCredentials::new("alice", "secret");
        let factor = FireboxSecondFactor::OneTimeCode(OtpCode::new("112233"));
        let materials = firebox_materials_crv1("client\nremote fw 443\n", &creds, Some(&factor));
        assert_eq!(materials.username.as_deref(), Some("alice"));
        assert_eq!(materials.password.as_deref(), Some("secret"));
        assert_eq!(materials.challenge_response.as_deref(), Some("112233"));
        let json = WatchguardAuthGlue.to_sidecar_json(&materials).unwrap();
        require_openvpn_sidecar_secret(&json).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(v["challenge_response"], "112233");
        assert_eq!(v["password"], "secret");
        let materials_dbg = format!("{materials:?}");
        assert!(!materials_dbg.contains("secret"), "{materials_dbg}");
        assert!(!materials_dbg.contains("112233"), "{materials_dbg}");
    }

    #[test]
    fn portal_materials_omit_challenge_and_use_otp_password() {
        let user = FireboxUsername::new("alice");
        let openvpn_pw = FireboxPassword::new("otp-as-password");
        let materials = firebox_materials_portal("client\n", &user, &openvpn_pw);
        assert_eq!(materials.password.as_deref(), Some("otp-as-password"));
        assert!(materials.challenge_response.is_none());
        let json = WatchguardAuthGlue.to_sidecar_json(&materials).unwrap();
        require_openvpn_sidecar_secret(&json).unwrap();
    }

    #[test]
    fn prompt_request_includes_config_name_and_push_hint() {
        let req = firebox_second_factor_prompt_request("lab-fw", None);
        assert!(req.title.contains("lab-fw"));
        assert!(req.subtitle.contains("'p'"));
        let with_chal = firebox_second_factor_prompt_request("lab-fw", Some("enter code"));
        assert!(with_chal.subtitle.contains("enter code"));
        assert!(with_chal.subtitle.contains("AuthPoint"));
    }

    #[tokio::test]
    async fn fake_credentials_plus_fake_otp_crv1_to_sidecar_json() {
        let fake = FakeFireboxCredentials::new("alice", "account-secret");
        let otp = FakeOtpPrompt::from_submitted(["  998877  "]);
        let json = resolve_firebox_crv1_sidecar_json(
            "client\nremote firebox 443 tcp\n",
            &fake.credentials(),
            Some(&otp),
            "lab",
        )
        .await
        .unwrap();
        require_openvpn_sidecar_secret(&json).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(v["username"], "alice");
        assert_eq!(v["password"], "account-secret");
        assert_eq!(v["challenge_response"], "998877");
        assert_eq!(fake.resolve_count(), 1);
        assert_eq!(otp.prompt_count(), 1);
        assert!(otp.requests()[0].title.contains("Watchguard 2FA"));
    }

    #[tokio::test]
    async fn fake_portal_path_otp_becomes_openvpn_password() {
        let fake = FakeFireboxCredentials::new("alice", "account-secret");
        let otp = FakeOtpPrompt::from_submitted(["portal-otp"]);
        let json = resolve_firebox_portal_sidecar_json(
            "client\n",
            &fake.credentials(),
            Some(&otp),
            "lab",
        )
        .await
        .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(v["password"], "portal-otp");
        assert!(v.get("challenge_response").is_none() || v["challenge_response"].is_null());
    }

    #[tokio::test]
    async fn fake_portal_push_keeps_account_password() {
        let fake = FakeFireboxCredentials::new("alice", "account-secret");
        let otp = FakeOtpPrompt::from_submitted(["p"]);
        let json = resolve_firebox_portal_sidecar_json(
            "client\n",
            &fake.credentials(),
            Some(&otp),
            "lab",
        )
        .await
        .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(v["password"], "account-secret");
        assert_eq!(v["challenge_response"], serde_json::Value::Null);
    }

    #[tokio::test]
    async fn crv1_without_otp_prompt_omits_challenge() {
        let creds = FireboxCredentials::new("alice", "pw");
        let json = resolve_firebox_crv1_sidecar_json("client\n", &creds, None, "lab")
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(v["password"], "pw");
        assert!(v.get("challenge_response").is_none() || v["challenge_response"].is_null());
    }

    #[tokio::test]
    async fn request_second_factor_cancel_maps() {
        let err = request_firebox_second_factor(&NullOtpPrompt, "lab", None)
            .await
            .unwrap_err();
        assert!(matches!(err, TunnelError::Cancelled));
    }

    #[tokio::test]
    async fn resolve_crv1_and_portal_null_otp_fail_closed() {
        let creds = FireboxCredentials::new("alice", "account-secret");
        let err = resolve_firebox_crv1_sidecar_json("client\n", &creds, Some(&NullOtpPrompt), "lab")
            .await
            .unwrap_err();
        assert!(matches!(err, TunnelError::Cancelled));
        let err =
            resolve_firebox_portal_sidecar_json("client\n", &creds, Some(&NullOtpPrompt), "lab")
                .await
                .unwrap_err();
        assert!(matches!(err, TunnelError::Cancelled));
        let rendered = format!("{err}");
        assert!(!rendered.contains("account-secret"), "{rendered}");
    }

    #[tokio::test]
    async fn resolve_crv1_empty_otp_fails_without_echo() {
        let creds = FireboxCredentials::new("alice", "account-secret");
        let otp = FakeOtpPrompt::from_submitted(["   "]);
        let err = resolve_firebox_crv1_sidecar_json("client\n", &creds, Some(&otp), "lab")
            .await
            .unwrap_err();
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
        let rendered = format!("{err}");
        assert!(rendered.contains("empty"), "{rendered}");
        assert!(!rendered.contains("account-secret"), "{rendered}");
        assert!(!rendered.contains("   "), "{rendered}");
    }

    #[tokio::test]
    async fn crv1_vs_portal_otp_field_placement_diverges() {
        // Same OTP must not silently land in the wrong OpenVPN field across paths.
        let otp_code = "FIELD_FORK_OTP";
        let account = "FIELD_FORK_PASS";
        let creds = FireboxCredentials::new("alice", account);

        let crv1 = FakeOtpPrompt::from_submitted([otp_code]);
        let crv1_json =
            resolve_firebox_crv1_sidecar_json("client\n", &creds, Some(&crv1), "lab")
                .await
                .unwrap();
        let crv1_v: serde_json::Value = serde_json::from_slice(&crv1_json).unwrap();
        assert_eq!(crv1_v["password"], account);
        assert_eq!(crv1_v["challenge_response"], otp_code);

        let portal = FakeOtpPrompt::from_submitted([otp_code]);
        let portal_json =
            resolve_firebox_portal_sidecar_json("client\n", &creds, Some(&portal), "lab")
                .await
                .unwrap();
        let portal_v: serde_json::Value = serde_json::from_slice(&portal_json).unwrap();
        assert_eq!(portal_v["password"], otp_code);
        assert!(
            portal_v.get("challenge_response").is_none() || portal_v["challenge_response"].is_null()
        );
    }

    #[tokio::test]
    async fn crv1_push_sets_challenge_response_p() {
        let fake = FakeFireboxCredentials::new("alice", "pw");
        let otp = FakeOtpPrompt::from_submitted(["P"]);
        let json =
            resolve_firebox_crv1_sidecar_json("client\n", &fake.credentials(), Some(&otp), "lab")
                .await
                .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(v["challenge_response"], FIREBOX_PUSH_SELECTOR);
        assert_eq!(v["password"], "pw");
    }
}
