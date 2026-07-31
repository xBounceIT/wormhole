//! Cisco AnyConnect aggregate-auth typing stub (no STF / CSTP / HTTPS).
//!
//! Mirrors Go `tools/wormhole-ciscoproxy` form-answering contracts and C#
//! `CiscoSecureClientSidecarConfig` optional `group` / `secondary_password`.
//! This module builds / validates stdin JSON and answers form fields in
//! memory — it does **not** speak aggregate-auth XML over the network or
//! STF-framed CSTP.
//!
//! **Unsupported (v1):** SAML SSO, client-certificate auth, CSD / HostScan
//! posture. See [`CiscoUnsupportedAuth`] / [`reject_unsupported_cisco_auth`].
//!
//! Never log passwords / OTP / TOTP secrets. [`Debug`] redacts secret fields
//! (`password` / `secondary_password` / `totp_secret` / form answers). Do **not**
//! `tracing` the stdin JSON from [`CiscoSecureClientSidecarConfig::to_stdin_json`] —
//! that blob necessarily carries wire secrets for the sidecar.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::providers::auth_glue::{
    redact_nonempty, request_second_factor, OtpPrompt, OtpPromptRequest,
};
use crate::providers::secret_shape::require_cisco_sidecar_secret;
use crate::TunnelError;

/// Default AnyConnect SSL VPN port (C# / Go default).
pub const DEFAULT_CISCO_PORT: u16 = 443;

/// Auth modes that v1 explicitly does **not** implement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CiscoUnsupportedAuth {
    /// SAML single sign-on (embedded or external browser).
    SamlSso,
    /// Client-certificate authentication.
    ClientCertificate,
    /// Endpoint posture assessment (CSD / HostScan).
    CsdHostScan,
}

impl CiscoUnsupportedAuth {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SamlSso => "SAML SSO",
            Self::ClientCertificate => "client-certificate authentication",
            Self::CsdHostScan => "CSD / HostScan posture assessment",
        }
    }
}

/// Fail closed with a clear, secret-free error for unsupported auth modes.
pub fn reject_unsupported_cisco_auth(mode: CiscoUnsupportedAuth) -> TunnelError {
    TunnelError::Establish(format!(
        "Cisco Secure Client does not support {} in v1 \
         (username/password + optional group + TOTP/secondary password only)",
        mode.as_str()
    ))
}

/// How the second factor is supplied for aggregate-auth challenge forms.
///
/// Variants are mutually exclusive on [`CiscoAuthOptions`]. On the wire config,
/// Go `secondFactor` prefers a non-empty `totp_secret` over `secondary_password`
/// when both are present — [`prepare_cisco_sidecar_config`] never sets both.
/// [`Prompt`](CiscoSecondFactor::Prompt) resolves via [`OtpPrompt`] into
/// `secondary_password` on the wire config (Fake / Null / Channel).
#[derive(Clone, PartialEq, Eq, Default)]
pub enum CiscoSecondFactor {
    /// Primary auth only — no challenge answer configured.
    #[default]
    None,
    /// Static secondary password / challenge response (already known).
    SecondaryPassword(String),
    /// Base32 TOTP shared secret — sidecar generates codes (not prompted here).
    TotpSecret(String),
    /// Interactive / scripted prompt → fills `secondary_password` before spawn.
    Prompt,
}

impl fmt::Debug for CiscoSecondFactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("None"),
            Self::SecondaryPassword(s) => f
                .debug_tuple("SecondaryPassword")
                .field(&redact_nonempty(s))
                .finish(),
            Self::TotpSecret(s) => f
                .debug_tuple("TotpSecret")
                .field(&redact_nonempty(s))
                .finish(),
            Self::Prompt => f.write_str("Prompt"),
        }
    }
}

/// Pre-spawn auth options (editor / resolver output).
///
/// Optional [`group`](CiscoAuthOptions::group) maps to AnyConnect
/// `<group-select>` / `group` stdin field. Second factor via
/// [`second_factor`](CiscoAuthOptions::second_factor).
#[derive(Clone, PartialEq, Eq)]
pub struct CiscoAuthOptions {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    /// Tunnel group / connection profile (AnyConnect "Group" dropdown).
    pub group: Option<String>,
    pub second_factor: CiscoSecondFactor,
    pub trust_server_certificate: bool,
    pub server_cert_sha256_pin: Option<String>,
}

impl fmt::Debug for CiscoAuthOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CiscoAuthOptions")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &redact_nonempty(&self.password))
            .field("group", &self.group)
            .field("second_factor", &self.second_factor)
            .field("trust_server_certificate", &self.trust_server_certificate)
            .field("server_cert_sha256_pin", &self.server_cert_sha256_pin)
            .finish()
    }
}

impl CiscoAuthOptions {
    pub fn new(
        host: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            host: host.into(),
            port: DEFAULT_CISCO_PORT,
            username: username.into(),
            password: password.into(),
            group: None,
            second_factor: CiscoSecondFactor::None,
            trust_server_certificate: false,
            server_cert_sha256_pin: None,
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub fn with_group(mut self, group: impl Into<String>) -> Self {
        let trimmed = group.into();
        let trimmed = trimmed.trim();
        self.group = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        };
        self
    }

    pub fn with_second_factor(mut self, second_factor: CiscoSecondFactor) -> Self {
        self.second_factor = second_factor;
        self
    }

    pub fn with_trust_server_certificate(mut self, trust: bool) -> Self {
        self.trust_server_certificate = trust;
        self
    }

    pub fn with_server_cert_sha256_pin(mut self, pin: impl Into<String>) -> Self {
        let trimmed = pin.into();
        let trimmed = trimmed.trim();
        self.server_cert_sha256_pin = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        };
        self
    }
}

/// Wire format passed to `wormhole-ciscoproxy.exe` via stdin (one JSON object).
///
/// Field names are lower_snake_case (Go + C# `CiscoSecureClientSidecarConfig`).
/// [`Debug`] redacts `password` / `secondary_password` / `totp_secret`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiscoSecureClientSidecarConfig {
    pub host: String,
    #[serde(default = "default_cisco_port_i32")]
    pub port: i32,
    pub username: String,
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secondary_password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp_secret: Option<String>,
    #[serde(default)]
    pub trust_server_certificate: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_cert_sha256_pin: Option<String>,
}

fn default_cisco_port_i32() -> i32 {
    DEFAULT_CISCO_PORT as i32
}

impl fmt::Debug for CiscoSecureClientSidecarConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CiscoSecureClientSidecarConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &redact_nonempty(&self.password))
            .field("group", &self.group)
            .field(
                "secondary_password",
                &self.secondary_password.as_ref().map(|s| redact_nonempty(s)),
            )
            .field(
                "totp_secret",
                &self.totp_secret.as_ref().map(|s| redact_nonempty(s)),
            )
            .field("trust_server_certificate", &self.trust_server_certificate)
            .field("server_cert_sha256_pin", &self.server_cert_sha256_pin)
            .finish()
    }
}

impl CiscoSecureClientSidecarConfig {
    /// Serialize to UTF-8 JSON bytes and validate the establish shape gate.
    pub fn to_stdin_json(&self) -> Result<Vec<u8>, TunnelError> {
        let bytes = serde_json::to_vec(self).map_err(|_| {
            TunnelError::Establish("failed to serialize CiscoSecureClientSidecarConfig JSON".into())
        })?;
        require_cisco_sidecar_secret(&bytes)?;
        Ok(bytes)
    }
}

/// Aggregate-auth form phase (init response = primary; later = challenge).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggregateAuthFormKind {
    /// First form: username + account password (unless a field is 2FA-named).
    Primary,
    /// Challenge / second-factor form after primary.
    Challenge,
}

/// Gateway form input type attribute (subset used by Go `answerForm`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggregateAuthFieldType {
    Text,
    Password,
    Hidden,
    Other,
}

impl AggregateAuthFieldType {
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "password" | "passwd" => Self::Password,
            "text" | "email" | "" => Self::Text,
            "hidden" => Self::Hidden,
            _ => Self::Other,
        }
    }
}

/// One aggregate-auth `<input>` (typing only — no XML parse here).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregateAuthInput {
    pub name: String,
    pub field_type: AggregateAuthFieldType,
}

impl AggregateAuthInput {
    pub fn new(name: impl Into<String>, field_type: AggregateAuthFieldType) -> Self {
        Self {
            name: name.into(),
            field_type,
        }
    }
}

/// Filled form field (name → value). [`Debug`] redacts values.
#[derive(Clone, PartialEq, Eq)]
pub struct AggregateAuthAnswer {
    pub name: String,
    pub value: String,
}

impl fmt::Debug for AggregateAuthAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AggregateAuthAnswer")
            .field("name", &self.name)
            .field("value", &redact_nonempty(&self.value))
            .finish()
    }
}

/// Errors from aggregate-auth form typing / prepare (never embed secrets).
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum CiscoAuthError {
    #[error("Cisco aggregate-auth form has no mappable credential inputs")]
    NoMappableInputs,
    #[error(
        "Cisco Secure Client second factor is missing or empty \
         (configure a non-empty TOTP secret or secondary password)"
    )]
    SecondFactorMissing,
    #[error("Cisco Secure Client host is required")]
    EmptyHost,
    #[error("Cisco Secure Client username is required")]
    EmptyUsername,
    #[error("Cisco Secure Client password is required")]
    EmptyPassword,
    #[error("Cisco Secure Client second-factor prompt requires an OtpPrompt")]
    PromptRequired,
}

impl From<CiscoAuthError> for TunnelError {
    fn from(value: CiscoAuthError) -> Self {
        TunnelError::Establish(value.to_string())
    }
}

/// Field names that always receive the second factor (even on the primary form).
///
/// Parity with Go `isSecondFactorName`.
pub fn is_second_factor_field_name(name: &str) -> bool {
    matches!(
        name.trim().to_ascii_lowercase().as_str(),
        "secondary_password"
            | "secondary-password"
            | "secondarypassword"
            | "answer"
            | "challenge"
            | "otp"
            | "passcode"
    )
}

fn empty_to_none(s: Option<String>) -> Option<String> {
    s.map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Trim and require a non-empty second-factor secret (fail closed).
fn require_nonempty_second_factor(raw: String) -> Result<String, CiscoAuthError> {
    empty_to_none(Some(raw)).ok_or(CiscoAuthError::SecondFactorMissing)
}

fn trim_required(value: &str, err: CiscoAuthError) -> Result<String, CiscoAuthError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Err(err)
    } else {
        Ok(trimmed.to_string())
    }
}

/// Resolve [`CiscoAuthOptions`] into sidecar stdin JSON materials.
///
/// - [`CiscoSecondFactor::Prompt`] calls [`request_second_factor`] (Fake / Null /
///   Channel). Null → [`TunnelError::Cancelled`].
/// - [`CiscoSecondFactor::TotpSecret`] is passed through for the sidecar (codes
///   generated there). [`CiscoSecondFactor::SecondaryPassword`] fills
///   `secondary_password` only — variants are mutually exclusive here.
/// - Does **not** spawn the sidecar or speak STF.
///
/// Prefer [`super::establish_cisco_from_auth`] when starting from a config id +
/// auth options. [`super::CiscoSecureClientProvider::establish`] still expects
/// already-resolved stdin JSON (no prepare inside the provider).
pub async fn prepare_cisco_sidecar_config(
    options: CiscoAuthOptions,
    prompt: Option<&dyn OtpPrompt>,
) -> Result<CiscoSecureClientSidecarConfig, TunnelError> {
    let host = trim_required(&options.host, CiscoAuthError::EmptyHost)?;
    let username = trim_required(&options.username, CiscoAuthError::EmptyUsername)?;
    let password = trim_required(&options.password, CiscoAuthError::EmptyPassword)?;
    let group = empty_to_none(options.group);
    let pin = empty_to_none(options.server_cert_sha256_pin);

    tracing::debug!(
        host = %host,
        port = options.port,
        group = ?group.as_deref(),
        second_factor = ?options.second_factor,
        "preparing Cisco Secure Client sidecar config (aggregate-auth stub)"
    );

    let (secondary_password, totp_secret) = match options.second_factor {
        CiscoSecondFactor::None => (None, None),
        // Explicit SecondaryPassword / TotpSecret with empty/whitespace must fail closed
        // (do not silently downgrade to "no second factor"). Use `None` to omit 2FA.
        CiscoSecondFactor::SecondaryPassword(pw) => {
            (Some(require_nonempty_second_factor(pw)?), None)
        }
        CiscoSecondFactor::TotpSecret(secret) => {
            (None, Some(require_nonempty_second_factor(secret)?))
        }
        CiscoSecondFactor::Prompt => {
            let prompt = prompt.ok_or(CiscoAuthError::PromptRequired)?;
            let code = request_second_factor(
                prompt,
                OtpPromptRequest::new(
                    format!("Cisco 2FA — {host}"),
                    "Enter secondary password / TOTP.",
                ),
            )
            .await?;
            (Some(code.into_inner()), None)
        }
    };

    let cfg = CiscoSecureClientSidecarConfig {
        host,
        port: i32::from(options.port),
        username,
        password,
        group,
        secondary_password,
        totp_secret,
        trust_server_certificate: options.trust_server_certificate,
        server_cert_sha256_pin: pin,
    };
    // Shape-validate early (same gate as establish).
    cfg.to_stdin_json()?;
    Ok(cfg)
}

/// Pure aggregate-auth form answering (parity with Go `answerForm`).
///
/// `second_factor_answer` is the **already-resolved** challenge value (static
/// secondary password or a generated OTP code). Live TOTP generation from
/// `totp_secret` remains sidecar-side — pass the code here when testing the
/// mapping. Does not speak STF or touch the network.
pub fn answer_aggregate_auth_form(
    username: &str,
    password: &str,
    second_factor_answer: Option<&str>,
    inputs: &[AggregateAuthInput],
    kind: AggregateAuthFormKind,
) -> Result<Vec<AggregateAuthAnswer>, CiscoAuthError> {
    let is_primary = matches!(kind, AggregateAuthFormKind::Primary);
    let second = second_factor_answer
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let answer = |name: &str, is_password: bool| -> Result<String, CiscoAuthError> {
        if !is_primary || is_second_factor_field_name(name) {
            return second
                .map(str::to_string)
                .ok_or(CiscoAuthError::SecondFactorMissing);
        }
        if is_password {
            Ok(password.to_string())
        } else {
            Ok(username.to_string())
        }
    };

    let mut out = Vec::new();
    for input in inputs {
        if input.name.trim().is_empty() {
            continue;
        }
        match input.field_type {
            AggregateAuthFieldType::Password => {
                out.push(AggregateAuthAnswer {
                    name: input.name.clone(),
                    value: answer(&input.name, true)?,
                });
            }
            AggregateAuthFieldType::Text => {
                out.push(AggregateAuthAnswer {
                    name: input.name.clone(),
                    value: answer(&input.name, false)?,
                });
            }
            AggregateAuthFieldType::Hidden | AggregateAuthFieldType::Other => {
                // Hidden / unknown: omit (opaque blob carries session state).
            }
        }
    }

    if out.is_empty() {
        // Name-based fallback (Go describeInputs path).
        for input in inputs {
            let lname = input.name.trim().to_ascii_lowercase();
            if matches!(
                lname.as_str(),
                "username" | "password" | "answer" | "secondary_password"
            ) {
                out.push(AggregateAuthAnswer {
                    name: input.name.clone(),
                    value: answer(&input.name, lname != "username")?,
                });
                break;
            }
        }
    }

    if out.is_empty() {
        return Err(CiscoAuthError::NoMappableInputs);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::auth_glue::{FakeOtpPrompt, MemoryOtpPrompt, NullOtpPrompt};

    #[test]
    fn unsupported_modes_fail_closed_without_secrets() {
        for mode in [
            CiscoUnsupportedAuth::SamlSso,
            CiscoUnsupportedAuth::ClientCertificate,
            CiscoUnsupportedAuth::CsdHostScan,
        ] {
            let err = reject_unsupported_cisco_auth(mode);
            let rendered = format!("{err}");
            assert!(rendered.contains("does not support"), "{rendered}");
            assert!(rendered.contains(mode.as_str()), "{rendered}");
            // Message may mention "password" as a supported mode name — never echo secrets.
            assert!(!rendered.contains("SECRET"), "{rendered}");
            assert!(!rendered.contains("s3cret"), "{rendered}");
        }
    }

    #[test]
    fn second_factor_debug_redacts() {
        let pw = CiscoSecondFactor::SecondaryPassword("sec-pass-SECRET".into());
        let totp = CiscoSecondFactor::TotpSecret("JBSWY3DPEHPK3PXP".into());
        let pw_dbg = format!("{pw:?}");
        let totp_dbg = format!("{totp:?}");
        assert!(pw_dbg.contains("[REDACTED]"), "{pw_dbg}");
        assert!(!pw_dbg.contains("sec-pass-SECRET"), "{pw_dbg}");
        assert!(totp_dbg.contains("[REDACTED]"), "{totp_dbg}");
        assert!(!totp_dbg.contains("JBSWY3DPEHPK3PXP"), "{totp_dbg}");
        assert_eq!(format!("{:?}", CiscoSecondFactor::None), "None");
        assert_eq!(format!("{:?}", CiscoSecondFactor::Prompt), "Prompt");
    }

    #[test]
    fn auth_options_and_sidecar_debug_redact_secrets() {
        let opts = CiscoAuthOptions::new("vpn.example", "alice", "p@ss-SECRET")
            .with_group("Contractors")
            .with_second_factor(CiscoSecondFactor::SecondaryPassword("2fa-SECRET".into()));
        let opts_dbg = format!("{opts:?}");
        assert!(opts_dbg.contains("[REDACTED]"), "{opts_dbg}");
        assert!(!opts_dbg.contains("p@ss-SECRET"), "{opts_dbg}");
        assert!(!opts_dbg.contains("2fa-SECRET"), "{opts_dbg}");
        assert!(opts_dbg.contains("Contractors"), "{opts_dbg}");
        assert!(opts_dbg.contains("alice"), "{opts_dbg}");

        let cfg = CiscoSecureClientSidecarConfig {
            host: "vpn.example".into(),
            port: 443,
            username: "alice".into(),
            password: "p@ss-SECRET".into(),
            group: Some("Contractors".into()),
            secondary_password: Some("2fa-SECRET".into()),
            totp_secret: Some("TOTP_SECRET_MARKER".into()),
            trust_server_certificate: false,
            server_cert_sha256_pin: None,
        };
        let cfg_dbg = format!("{cfg:?}");
        assert!(!cfg_dbg.contains("p@ss-SECRET"), "{cfg_dbg}");
        assert!(!cfg_dbg.contains("2fa-SECRET"), "{cfg_dbg}");
        assert!(!cfg_dbg.contains("TOTP_SECRET_MARKER"), "{cfg_dbg}");
        assert!(cfg_dbg.contains("Contractors"), "{cfg_dbg}");
    }

    #[test]
    fn sidecar_json_includes_optional_group_and_secondary() {
        let cfg = CiscoSecureClientSidecarConfig {
            host: "vpn.example".into(),
            port: 8443,
            username: "alice".into(),
            password: "secret".into(),
            group: Some("Contractors".into()),
            secondary_password: Some("otp-1".into()),
            totp_secret: None,
            trust_server_certificate: true,
            server_cert_sha256_pin: None,
        };
        let bytes = cfg.to_stdin_json().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["host"], "vpn.example");
        assert_eq!(v["port"], 8443);
        assert_eq!(v["group"], "Contractors");
        assert_eq!(v["secondary_password"], "otp-1");
        assert!(v.get("totp_secret").is_none());
        assert_eq!(v["trust_server_certificate"], true);
    }

    #[test]
    fn sidecar_json_omits_empty_optionals() {
        let cfg = CiscoSecureClientSidecarConfig {
            host: "vpn.example".into(),
            port: 443,
            username: "u".into(),
            password: "p".into(),
            group: None,
            secondary_password: None,
            totp_secret: None,
            trust_server_certificate: false,
            server_cert_sha256_pin: None,
        };
        let bytes = cfg.to_stdin_json().unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains("group"));
        assert!(!text.contains("secondary_password"));
        assert!(!text.contains("totp_secret"));
    }

    #[tokio::test]
    async fn prepare_with_group_and_static_second_factor() {
        let opts = CiscoAuthOptions::new("vpn.example", "alice", "s3cret")
            .with_group("  Contractors  ")
            .with_second_factor(CiscoSecondFactor::SecondaryPassword("  2fa  ".into()));
        let cfg = prepare_cisco_sidecar_config(opts, None).await.unwrap();
        assert_eq!(cfg.group.as_deref(), Some("Contractors"));
        assert_eq!(cfg.secondary_password.as_deref(), Some("2fa"));
        assert!(cfg.totp_secret.is_none());
        assert!(!format!("{cfg:?}").contains("s3cret"));
    }

    #[tokio::test]
    async fn prepare_totp_secret_sets_totp_not_secondary() {
        let opts = CiscoAuthOptions::new("vpn.example", "alice", "s3cret")
            .with_second_factor(CiscoSecondFactor::TotpSecret("JBSWY3DPEHPK3PXP".into()));
        let cfg = prepare_cisco_sidecar_config(opts, None).await.unwrap();
        assert_eq!(cfg.totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert!(cfg.secondary_password.is_none());
    }

    #[tokio::test]
    async fn prepare_prompt_uses_fake_otp() {
        let prompt = FakeOtpPrompt::from_submitted(["  424242  "]);
        let opts = CiscoAuthOptions::new("vpn.example", "alice", "s3cret")
            .with_second_factor(CiscoSecondFactor::Prompt);
        let cfg = prepare_cisco_sidecar_config(opts, Some(&prompt))
            .await
            .unwrap();
        assert_eq!(cfg.secondary_password.as_deref(), Some("424242"));
        assert_eq!(prompt.prompt_count(), 1);
        let req = &prompt.requests()[0];
        assert!(req.title.contains("Cisco"));
        assert!(req.subtitle.contains("secondary") || req.subtitle.contains("TOTP"));
        assert!(!format!("{cfg:?}").contains("424242"));
    }

    #[tokio::test]
    async fn prepare_null_otp_cancels() {
        let opts = CiscoAuthOptions::new("vpn.example", "alice", "s3cret")
            .with_second_factor(CiscoSecondFactor::Prompt);
        let err = prepare_cisco_sidecar_config(opts, Some(&NullOtpPrompt))
            .await
            .unwrap_err();
        assert!(matches!(err, TunnelError::Cancelled));
    }

    #[tokio::test]
    async fn prepare_prompt_without_prompt_handle_fails() {
        let opts = CiscoAuthOptions::new("vpn.example", "alice", "s3cret")
            .with_second_factor(CiscoSecondFactor::Prompt);
        let err = prepare_cisco_sidecar_config(opts, None).await.unwrap_err();
        let rendered = format!("{err}");
        assert!(rendered.contains("OtpPrompt"), "{rendered}");
    }

    #[tokio::test]
    async fn prepare_rejects_empty_host() {
        let opts = CiscoAuthOptions::new("  ", "alice", "s3cret");
        let err = prepare_cisco_sidecar_config(opts, None).await.unwrap_err();
        assert!(format!("{err}").contains("host"));
    }

    #[tokio::test]
    async fn prepare_rejects_empty_username_and_password() {
        let user_err = prepare_cisco_sidecar_config(
            CiscoAuthOptions::new("vpn.example", "  ", "s3cret"),
            None,
        )
        .await
        .unwrap_err();
        let user_rendered = format!("{user_err}");
        assert!(user_rendered.contains("username"), "{user_rendered}");
        assert!(!user_rendered.contains("s3cret"), "{user_rendered}");

        let pass_err = prepare_cisco_sidecar_config(
            CiscoAuthOptions::new("vpn.example", "alice", "   "),
            None,
        )
        .await
        .unwrap_err();
        let pass_rendered = format!("{pass_err}");
        assert!(pass_rendered.contains("password"), "{pass_rendered}");
    }

    #[tokio::test]
    async fn prepare_empty_second_factor_secrets_fail_closed() {
        for factor in [
            CiscoSecondFactor::SecondaryPassword("  ".into()),
            CiscoSecondFactor::SecondaryPassword(String::new()),
            CiscoSecondFactor::TotpSecret("   ".into()),
            CiscoSecondFactor::TotpSecret(String::new()),
        ] {
            let opts = CiscoAuthOptions::new("vpn.example", "alice", "s3cret")
                .with_second_factor(factor);
            let err = prepare_cisco_sidecar_config(opts, None).await.unwrap_err();
            let rendered = format!("{err}");
            assert!(
                rendered.contains("second factor")
                    || rendered.contains("TOTP")
                    || rendered.contains("secondary"),
                "{rendered}"
            );
            assert!(!rendered.contains("s3cret"), "{rendered}");
        }
    }

    #[tokio::test]
    async fn prepare_prompt_whitespace_otp_fails_without_echo() {
        let prompt = FakeOtpPrompt::from_submitted(["   "]);
        let opts = CiscoAuthOptions::new("vpn.example", "alice", "s3cret-MARK")
            .with_second_factor(CiscoSecondFactor::Prompt);
        let err = prepare_cisco_sidecar_config(opts, Some(&prompt))
            .await
            .unwrap_err();
        let rendered = format!("{err}");
        assert!(
            matches!(err, TunnelError::Establish(_)),
            "empty OTP must not cancel quietly: {err:?}"
        );
        assert!(!rendered.contains("s3cret-MARK"), "{rendered}");
    }

    #[tokio::test]
    async fn prepare_debug_redacts_while_stdin_json_keeps_wire_secrets() {
        let opts = CiscoAuthOptions::new("vpn.example", "alice", "wire-pass-SECRET")
            .with_second_factor(CiscoSecondFactor::SecondaryPassword("wire-2fa-SECRET".into()));
        let cfg = prepare_cisco_sidecar_config(opts, None).await.unwrap();
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("wire-pass-SECRET"), "{dbg}");
        assert!(!dbg.contains("wire-2fa-SECRET"), "{dbg}");
        assert!(dbg.contains("[REDACTED]"), "{dbg}");

        let json = String::from_utf8(cfg.to_stdin_json().unwrap()).unwrap();
        // Sidecar stdin must carry secrets; Debug / tracing must never print this JSON.
        assert!(json.contains("wire-pass-SECRET"), "{json}");
        assert!(json.contains("wire-2fa-SECRET"), "{json}");
        assert!(!dbg.contains(&json), "Debug must not embed stdin JSON");
    }

    #[test]
    fn answer_primary_form_username_password() {
        let inputs = [
            AggregateAuthInput::new("username", AggregateAuthFieldType::Text),
            AggregateAuthInput::new("password", AggregateAuthFieldType::Password),
        ];
        let answers = answer_aggregate_auth_form(
            "alice",
            "s3cret",
            None,
            &inputs,
            AggregateAuthFormKind::Primary,
        )
        .unwrap();
        assert_eq!(answers.len(), 2);
        assert_eq!(answers[0].name, "username");
        assert_eq!(answers[0].value, "alice");
        assert_eq!(answers[1].name, "password");
        assert_eq!(answers[1].value, "s3cret");
        assert!(!format!("{answers:?}").contains("s3cret"));
    }

    #[test]
    fn answer_challenge_form_uses_second_factor() {
        let inputs = [AggregateAuthInput::new(
            "password",
            AggregateAuthFieldType::Password,
        )];
        let answers = answer_aggregate_auth_form(
            "alice",
            "s3cret",
            Some("totp-1"),
            &inputs,
            AggregateAuthFormKind::Challenge,
        )
        .unwrap();
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].value, "totp-1");
        assert_ne!(answers[0].value, "s3cret");
    }

    #[test]
    fn answer_combined_primary_secondary_password_field() {
        let inputs = [
            AggregateAuthInput::new("username", AggregateAuthFieldType::Text),
            AggregateAuthInput::new("password", AggregateAuthFieldType::Password),
            AggregateAuthInput::new("secondary_password", AggregateAuthFieldType::Password),
        ];
        let answers = answer_aggregate_auth_form(
            "alice",
            "s3cret",
            Some("654321"),
            &inputs,
            AggregateAuthFormKind::Primary,
        )
        .unwrap();
        assert_eq!(answers[0].value, "alice");
        assert_eq!(answers[1].value, "s3cret");
        assert_eq!(answers[2].name, "secondary_password");
        assert_eq!(answers[2].value, "654321");
    }

    #[test]
    fn answer_challenge_without_second_factor_fails() {
        let inputs = [AggregateAuthInput::new(
            "answer",
            AggregateAuthFieldType::Text,
        )];
        let err = answer_aggregate_auth_form(
            "alice",
            "s3cret",
            None,
            &inputs,
            AggregateAuthFormKind::Challenge,
        )
        .unwrap_err();
        assert_eq!(err, CiscoAuthError::SecondFactorMissing);
        assert!(!format!("{err}").contains("s3cret"));
    }

    #[test]
    fn second_factor_field_name_detection() {
        assert!(is_second_factor_field_name("secondary_password"));
        assert!(is_second_factor_field_name("OTP"));
        assert!(is_second_factor_field_name("answer"));
        assert!(!is_second_factor_field_name("password"));
        assert!(!is_second_factor_field_name("username"));
    }

    #[test]
    fn answer_no_inputs_fails_closed() {
        let err = answer_aggregate_auth_form(
            "alice",
            "s3cret",
            None,
            &[AggregateAuthInput::new("x", AggregateAuthFieldType::Hidden)],
            AggregateAuthFormKind::Primary,
        )
        .unwrap_err();
        assert_eq!(err, CiscoAuthError::NoMappableInputs);
    }

    #[tokio::test]
    async fn prepare_memory_cancel_maps_cancelled() {
        let prompt = MemoryOtpPrompt::from_codes([None::<&str>]);
        let opts = CiscoAuthOptions::new("vpn.example", "alice", "s3cret")
            .with_second_factor(CiscoSecondFactor::Prompt);
        let err = prepare_cisco_sidecar_config(opts, Some(&prompt))
            .await
            .unwrap_err();
        assert!(matches!(err, TunnelError::Cancelled));
    }
}
