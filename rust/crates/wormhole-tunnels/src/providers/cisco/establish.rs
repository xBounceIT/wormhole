//! Thin Cisco Secure Client establish-path glue: config id → metadata + secret/auth stub → provider.
//!
//! Separate from WireGuard / Fortinet / OpenVPN glue. Reuses shared
//! [`TunnelConfigLookup`] / [`TunnelSecretLookup`] (and Fakes) from the WireGuard
//! establish module — production wires `TunnelConfigRepository` +
//! `TunnelPayloadStore`; tests use those Fakes with [`crate::FakeTunnelProvider`].
//!
//! Two entry points:
//! - [`establish_cisco`] — already-resolved sidecar JSON from the secret store
//! - [`establish_cisco_from_auth`] — [`CiscoAuthOptions`] via
//!   [`prepare_cisco_sidecar_config`] (aggregate-auth stub / Fake·Null OTP)
//!
//! **No** live ASA network, **no** local Cisco Secure Client. **SAML SSO**,
//! client certificates, and **CSD / HostScan** stay fail-closed via
//! [`reject_cisco_unsupported_auth`] (alias of [`reject_unsupported_cisco_auth`]).
//! Secrets never appear in [`Debug`] / logs / [`TunnelError`] text.

use std::sync::Arc;

use uuid::Uuid;

use crate::providers::auth_glue::OtpPrompt;
use crate::providers::secret_shape::require_cisco_establish_secret;
use crate::providers::wireguard::{TunnelConfigLookup, TunnelSecretLookup};
use crate::{
    TunnelError, TunnelInstance, TunnelKind, TunnelProvider,
};

use super::aggregate_auth::{
    prepare_cisco_sidecar_config, reject_unsupported_cisco_auth, CiscoAuthOptions,
    CiscoUnsupportedAuth,
};

/// Minimal Cisco sidecar stdin JSON used by crate tests / Fake establish.
///
/// Same snake_case shape as Go `wormhole-ciscoproxy` / `CiscoSecureClientSidecarConfig`
/// (`host` required by the establish shape gate).
pub const FAKE_CISCO_SIDECAR_JSON: &[u8] =
    br#"{"host":"vpn.example","username":"u","password":"p"}"#;

/// Fail closed before any establish when a caller requests an unsupported Cisco auth mode.
///
/// Thin alias so establish-path callers do not reach into aggregate-auth for the
/// SAML / CSD / client-cert reject surface.
#[inline]
pub fn reject_cisco_unsupported_auth(mode: CiscoUnsupportedAuth) -> TunnelError {
    reject_unsupported_cisco_auth(mode)
}

fn load_cisco_snapshot(
    config_id: Uuid,
    configs: &dyn TunnelConfigLookup,
    provider: &dyn TunnelProvider,
) -> Result<crate::TunnelConfigSnapshot, TunnelError> {
    if provider.kind() != TunnelKind::CiscoSecureClient {
        return Err(TunnelError::WrongKind {
            expected: TunnelKind::CiscoSecureClient,
            actual: provider.kind(),
        });
    }

    let record = configs
        .get(config_id)?
        .ok_or(TunnelError::ConfigNotFound { id: config_id })?;

    if record.kind != TunnelKind::CiscoSecureClient {
        return Err(TunnelError::WrongKind {
            expected: TunnelKind::CiscoSecureClient,
            actual: record.kind,
        });
    }

    Ok(record.to_snapshot())
}

/// Load TunnelConfig metadata + secret for `config_id`, then call Cisco
/// [`TunnelProvider::establish`].
///
/// Fail-closed:
/// - missing config → [`TunnelError::ConfigNotFound`]
/// - kind ≠ CiscoSecureClient → [`TunnelError::WrongKind`]
/// - missing / empty / wrong-shape secret → [`TunnelError::SecretMissing`] /
///   [`TunnelError::Establish`] (never echoes the blob)
///
/// `provider.kind()` must be [`TunnelKind::CiscoSecureClient`].
pub async fn establish_cisco(
    config_id: Uuid,
    configs: &dyn TunnelConfigLookup,
    secrets: &dyn TunnelSecretLookup,
    provider: &dyn TunnelProvider,
) -> Result<Arc<dyn TunnelInstance>, TunnelError> {
    let snapshot = load_cisco_snapshot(config_id, configs, provider)?;

    let secret = secrets
        .read(&config_id)?
        .ok_or(TunnelError::SecretMissing { id: config_id })?;

    require_cisco_establish_secret(&secret, &snapshot.name)?;

    tracing::info!(
        tunnel_config_id = %config_id,
        tunnel_name = %snapshot.name,
        secret_len = secret.len(),
        "establishing Cisco Secure Client tunnel from stored config"
    );
    // Never log `secret` / stdin JSON.
    provider.establish(&snapshot, &secret).await
}

/// Load TunnelConfig metadata, resolve [`CiscoAuthOptions`] through the
/// aggregate-auth stub, then call Cisco [`TunnelProvider::establish`].
///
/// Uses [`prepare_cisco_sidecar_config`] (Fake / Null / Channel OTP for
/// [`CiscoSecondFactor::Prompt`](super::CiscoSecondFactor::Prompt)). Does **not**
/// speak aggregate-auth HTTPS / STF / CSTP. Call
/// [`reject_cisco_unsupported_auth`] for SAML SSO / CSD / client cert — those
/// modes are never accepted here.
///
/// Fail-closed on missing config / wrong kind / prepare errors (empty host,
/// cancel, …). Secrets never appear in tracing fields.
pub async fn establish_cisco_from_auth(
    config_id: Uuid,
    configs: &dyn TunnelConfigLookup,
    options: CiscoAuthOptions,
    prompt: Option<&dyn OtpPrompt>,
    provider: &dyn TunnelProvider,
) -> Result<Arc<dyn TunnelInstance>, TunnelError> {
    let snapshot = load_cisco_snapshot(config_id, configs, provider)?;

    let cfg = prepare_cisco_sidecar_config(options, prompt).await?;
    let secret = cfg.to_stdin_json()?;

    tracing::info!(
        tunnel_config_id = %config_id,
        tunnel_name = %snapshot.name,
        host = %cfg.host,
        port = cfg.port,
        secret_len = secret.len(),
        "establishing Cisco Secure Client tunnel from auth stub"
    );
    // Never log password / secondary / totp / stdin JSON.
    provider.establish(&snapshot, &secret).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::auth_glue::{FakeOtpPrompt, NullOtpPrompt};
    use crate::providers::wireguard::{
        FakeTunnelConfigLookup, FakeTunnelSecretLookup, TunnelConfigRecord,
    };
    use crate::{CiscoSecondFactor, FakeTunnelProvider};

    fn cisco_id() -> Uuid {
        Uuid::parse_str("cccccccc-dddd-eeee-ffff-000011112222").unwrap()
    }

    fn secret_marker() -> &'static [u8] {
        br#"{"host":"vpn.example","username":"alice","password":"CISCO_SECRET_MARKER_DO_NOT_LEAK"}"#
    }

    fn auth_options() -> CiscoAuthOptions {
        CiscoAuthOptions::new("vpn.example", "alice", "s3cret-MARK")
    }

    fn assert_no_secret_echo(err: &TunnelError) {
        let rendered = format!("{err} / {err:?}");
        assert!(
            !rendered.contains("CISCO_SECRET_MARKER_DO_NOT_LEAK"),
            "must not echo secret: {rendered}"
        );
        assert!(
            !rendered.contains("s3cret-MARK"),
            "must not echo password: {rendered}"
        );
        assert!(
            !rendered.contains("2fa-SECRET"),
            "must not echo second factor: {rendered}"
        );
    }

    fn cisco_config(id: Uuid) -> FakeTunnelConfigLookup {
        FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::CiscoSecureClient,
            "lab-cisco",
        ))
    }

    #[tokio::test]
    async fn establish_loads_metadata_and_secret_via_fake_provider() {
        let id = cisco_id();
        let configs = cisco_config(id);
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, FAKE_CISCO_SIDECAR_JSON);
        let provider = FakeTunnelProvider::new(TunnelKind::CiscoSecureClient);

        let instance = establish_cisco(id, &configs, &secrets, &provider)
            .await
            .expect("establish");
        assert_eq!(provider.establish_count(), 1);
        assert_eq!(configs.get_calls(), 1);
        assert_eq!(secrets.read_calls(), 1);
        assert_eq!(instance.state(), crate::TunnelState::Up);
        assert!(instance.socks5_endpoint().is_some());
    }

    #[tokio::test]
    async fn establish_from_auth_via_aggregate_stub_and_fake_provider() {
        let id = cisco_id();
        let configs = cisco_config(id);
        let provider = FakeTunnelProvider::new(TunnelKind::CiscoSecureClient);
        let opts = auth_options().with_second_factor(CiscoSecondFactor::SecondaryPassword(
            "2fa-SECRET".into(),
        ));

        let instance = establish_cisco_from_auth(id, &configs, opts, None, &provider)
            .await
            .expect("establish from auth");
        assert_eq!(provider.establish_count(), 1);
        assert_eq!(configs.get_calls(), 1);
        assert_eq!(instance.state(), crate::TunnelState::Up);
    }

    #[tokio::test]
    async fn establish_from_auth_prompt_uses_fake_otp() {
        let id = cisco_id();
        let configs = cisco_config(id);
        let provider = FakeTunnelProvider::new(TunnelKind::CiscoSecureClient);
        let prompt = FakeOtpPrompt::from_submitted(["otp-from-fake"]);
        let opts = auth_options().with_second_factor(CiscoSecondFactor::Prompt);

        let instance =
            establish_cisco_from_auth(id, &configs, opts, Some(&prompt), &provider)
                .await
                .expect("prompt path");
        assert_eq!(provider.establish_count(), 1);
        assert_eq!(instance.state(), crate::TunnelState::Up);
    }

    #[tokio::test]
    async fn missing_config_fails_closed() {
        let id = cisco_id();
        let configs = FakeTunnelConfigLookup::new();
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, FAKE_CISCO_SIDECAR_JSON);
        let provider = FakeTunnelProvider::new(TunnelKind::CiscoSecureClient);

        let err = establish_cisco(id, &configs, &secrets, &provider)
            .await
            .err()
            .expect("missing config");
        assert!(matches!(err, TunnelError::ConfigNotFound { id: got } if got == id));
        assert_eq!(provider.establish_count(), 0);
        assert_eq!(secrets.read_calls(), 0);
    }

    #[tokio::test]
    async fn missing_config_fails_closed_on_auth_path() {
        let id = cisco_id();
        let configs = FakeTunnelConfigLookup::new();
        let provider = FakeTunnelProvider::new(TunnelKind::CiscoSecureClient);

        let err = establish_cisco_from_auth(id, &configs, auth_options(), None, &provider)
            .await
            .err()
            .expect("missing config");
        assert!(matches!(err, TunnelError::ConfigNotFound { id: got } if got == id));
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn missing_secret_fails_closed() {
        let id = cisco_id();
        let configs = cisco_config(id);
        let secrets = FakeTunnelSecretLookup::new();
        let provider = FakeTunnelProvider::new(TunnelKind::CiscoSecureClient);

        let err = establish_cisco(id, &configs, &secrets, &provider)
            .await
            .err()
            .expect("missing secret");
        assert!(matches!(err, TunnelError::SecretMissing { id: got } if got == id));
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn empty_secret_fails_before_provider() {
        let id = cisco_id();
        let configs = cisco_config(id);
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, Vec::<u8>::new());
        let provider = FakeTunnelProvider::new(TunnelKind::CiscoSecureClient);

        let err = establish_cisco(id, &configs, &secrets, &provider)
            .await
            .err()
            .expect("empty secret");
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
        assert!(format!("{err}").contains("empty"), "{err}");
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn wrong_config_kind_fails_closed() {
        let id = cisco_id();
        let configs = FakeTunnelConfigLookup::new()
            .with_config(TunnelConfigRecord::new(id, TunnelKind::WireGuard, "not-cisco"));
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, FAKE_CISCO_SIDECAR_JSON);
        let provider = FakeTunnelProvider::new(TunnelKind::CiscoSecureClient);

        let err = establish_cisco(id, &configs, &secrets, &provider)
            .await
            .err()
            .expect("wrong kind");
        assert!(matches!(
            err,
            TunnelError::WrongKind {
                expected: TunnelKind::CiscoSecureClient,
                actual: TunnelKind::WireGuard
            }
        ));
        assert_eq!(provider.establish_count(), 0);
        assert_eq!(secrets.read_calls(), 0);
    }

    #[tokio::test]
    async fn wrong_config_kind_fails_closed_on_auth_path() {
        let id = cisco_id();
        let configs = FakeTunnelConfigLookup::new()
            .with_config(TunnelConfigRecord::new(id, TunnelKind::OpenVpn, "not-cisco"));
        let provider = FakeTunnelProvider::new(TunnelKind::CiscoSecureClient);

        let err = establish_cisco_from_auth(id, &configs, auth_options(), None, &provider)
            .await
            .err()
            .expect("wrong kind");
        assert!(matches!(
            err,
            TunnelError::WrongKind {
                expected: TunnelKind::CiscoSecureClient,
                actual: TunnelKind::OpenVpn
            }
        ));
        assert_eq!(provider.establish_count(), 0);
        assert_no_secret_echo(&err);
    }

    #[tokio::test]
    async fn wrong_provider_kind_fails_closed() {
        let id = cisco_id();
        let configs = cisco_config(id);
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, FAKE_CISCO_SIDECAR_JSON);
        let provider = FakeTunnelProvider::new(TunnelKind::WireGuard);

        let err = establish_cisco(id, &configs, &secrets, &provider)
            .await
            .err()
            .expect("wrong provider");
        assert!(matches!(
            err,
            TunnelError::WrongKind {
                expected: TunnelKind::CiscoSecureClient,
                actual: TunnelKind::WireGuard
            }
        ));
        assert_eq!(provider.establish_count(), 0);
        assert_eq!(configs.get_calls(), 0);
    }

    #[tokio::test]
    async fn wrong_provider_kind_fails_closed_on_auth_path() {
        let id = cisco_id();
        let configs = cisco_config(id);
        let provider = FakeTunnelProvider::new(TunnelKind::Fortinet);

        let err = establish_cisco_from_auth(id, &configs, auth_options(), None, &provider)
            .await
            .err()
            .expect("wrong provider");
        assert!(matches!(
            err,
            TunnelError::WrongKind {
                expected: TunnelKind::CiscoSecureClient,
                actual: TunnelKind::Fortinet
            }
        ));
        assert_eq!(provider.establish_count(), 0);
        assert_eq!(configs.get_calls(), 0);
        assert_no_secret_echo(&err);
    }

    #[tokio::test]
    async fn bad_secret_shape_rejects_without_echoing_blob() {
        let id = cisco_id();
        let configs = cisco_config(id);
        // PascalCase editor blob — shape gate must reject; marker must not appear.
        let secrets = FakeTunnelSecretLookup::new().with_secret(
            id,
            br#"{"Host":"vpn.example","Password":"CISCO_SECRET_MARKER_DO_NOT_LEAK"}"#,
        );
        let provider = FakeTunnelProvider::new(TunnelKind::CiscoSecureClient);

        let err = establish_cisco(id, &configs, &secrets, &provider)
            .await
            .err()
            .expect("bad shape");
        let rendered = format!("{err} / {err:?}");
        assert!(
            rendered.contains("host") || rendered.contains("Cisco"),
            "{rendered}"
        );
        assert_no_secret_echo(&err);
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn whitespace_host_secret_rejects_without_echo() {
        let id = cisco_id();
        let configs = cisco_config(id);
        let secrets = FakeTunnelSecretLookup::new().with_secret(
            id,
            br#"{"host":"   ","username":"u","password":"CISCO_SECRET_MARKER_DO_NOT_LEAK"}"#,
        );
        let provider = FakeTunnelProvider::new(TunnelKind::CiscoSecureClient);

        let err = establish_cisco(id, &configs, &secrets, &provider)
            .await
            .err()
            .expect("whitespace host");
        let rendered = format!("{err} / {err:?}");
        assert!(rendered.contains("host"), "{rendered}");
        assert_no_secret_echo(&err);
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn auth_path_empty_credentials_fail_without_echo() {
        let id = cisco_id();
        let configs = cisco_config(id);
        let provider = FakeTunnelProvider::new(TunnelKind::CiscoSecureClient);

        for (label, opts) in [
            (
                "empty host",
                CiscoAuthOptions::new("  ", "alice", "s3cret-MARK"),
            ),
            (
                "empty username",
                CiscoAuthOptions::new("vpn.example", "  ", "s3cret-MARK"),
            ),
            (
                "empty password",
                CiscoAuthOptions::new("vpn.example", "alice", "  "),
            ),
        ] {
            let err = establish_cisco_from_auth(id, &configs, opts, None, &provider)
                .await
                .err()
                .unwrap_or_else(|| panic!("{label}: expected fail"));
            assert!(matches!(err, TunnelError::Establish(_)), "{label}: {err:?}");
            assert_eq!(provider.establish_count(), 0, "{label}");
            assert_no_secret_echo(&err);
        }
    }

    #[tokio::test]
    async fn auth_path_prompt_without_otp_fails_before_establish() {
        let id = cisco_id();
        let configs = cisco_config(id);
        let provider = FakeTunnelProvider::new(TunnelKind::CiscoSecureClient);
        let opts = auth_options().with_second_factor(CiscoSecondFactor::Prompt);

        let err = establish_cisco_from_auth(id, &configs, opts, None, &provider)
            .await
            .err()
            .expect("prompt required");
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
        assert!(format!("{err}").contains("OtpPrompt"), "{err}");
        assert_eq!(provider.establish_count(), 0);
        assert_no_secret_echo(&err);
    }

    #[tokio::test]
    async fn auth_path_null_otp_cancels_without_establish() {
        let id = cisco_id();
        let configs = cisco_config(id);
        let provider = FakeTunnelProvider::new(TunnelKind::CiscoSecureClient);
        let opts = auth_options().with_second_factor(CiscoSecondFactor::Prompt);

        let err =
            establish_cisco_from_auth(id, &configs, opts, Some(&NullOtpPrompt), &provider)
                .await
                .err()
                .expect("null otp");
        assert!(matches!(err, TunnelError::Cancelled), "{err:?}");
        assert_eq!(provider.establish_count(), 0);
        assert_no_secret_echo(&err);
    }

    #[test]
    fn unsupported_saml_csd_client_cert_fail_closed() {
        for mode in [
            CiscoUnsupportedAuth::SamlSso,
            CiscoUnsupportedAuth::ClientCertificate,
            CiscoUnsupportedAuth::CsdHostScan,
        ] {
            let err = reject_cisco_unsupported_auth(mode);
            assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
            let rendered = format!("{err}");
            assert!(rendered.contains("does not support"), "{rendered}");
            assert!(rendered.contains(mode.as_str()), "{rendered}");
            assert_no_secret_echo(&err);
        }
    }

    #[test]
    fn fake_secret_lookup_debug_redacts_payload() {
        let id = cisco_id();
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, secret_marker());
        let dbg = format!("{secrets:?}");
        assert!(!dbg.contains("CISCO_SECRET"));
        assert!(!dbg.contains("password"));
        assert!(dbg.contains("entry_byte_lengths"));
    }

    #[cfg(feature = "secrets")]
    #[tokio::test]
    async fn payload_store_adapter_establish_with_fake_store() {
        use crate::providers::wireguard::PayloadStoreSecretLookup;
        use wormhole_secrets_win::{FakeTunnelPayloadStore, TunnelPayloadStore};

        let id = cisco_id();
        let configs = cisco_config(id);
        let store = FakeTunnelPayloadStore::new();
        store
            .store(&id, FAKE_CISCO_SIDECAR_JSON)
            .expect("store");
        let secrets = PayloadStoreSecretLookup::new(store);
        let provider = FakeTunnelProvider::new(TunnelKind::CiscoSecureClient);

        let instance = establish_cisco(id, &configs, &secrets, &provider)
            .await
            .expect("establish via payload store");
        assert_eq!(provider.establish_count(), 1);
        assert_eq!(instance.state(), crate::TunnelState::Up);

        let dbg = format!("{secrets:?}");
        assert!(!dbg.contains("vpn.example"));
        assert!(!dbg.contains("password"));
    }
}
