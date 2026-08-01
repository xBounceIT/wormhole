//! Thin Stormshield establish-path glue: config id → metadata + secret/auth stub → provider.
//!
//! Mirrors the C# load order (SQLite `TunnelConfigs` row, then SNS auth / secret
//! materials) before [`TunnelProvider::establish`]. Production wires
//! [`wormhole_storage::TunnelConfigRepository`] + DPAPI / SNS auth; tests use
//! shared [`TunnelConfigLookup`] / [`TunnelSecretLookup`] Fakes plus
//! [`FakeStormshieldSnsAuth`] → OpenVPN sidecar JSON, then
//! [`crate::FakeTunnelProvider`] with [`TunnelKind::Stormshield`].
//!
//! **Data plane:** shared `wormhole-ovpnproxy` (no Stormshield-specific binary).
//! **No** live SNS portal / network — profile text is caller-supplied;
//! portal download / config-hash cache / SSO remain TODO.

use std::sync::Arc;

use uuid::Uuid;

use crate::providers::auth_glue::{
    stormshield_materials_from_sns, stormshield_sns_to_sidecar_json, StormshieldOtpSpend,
    StormshieldSnsAuth, StormshieldSnsAuthRequest, StormshieldSnsCredentials,
};
use crate::providers::secret_shape::require_openvpn_establish_secret;
use crate::providers::wireguard::{TunnelConfigLookup, TunnelSecretLookup};
use crate::{TunnelError, TunnelInstance, TunnelKind, TunnelProvider};

/// Minimal `.ovpn` profile fragment for unit tests (no live SNS portal download).
pub const FAKE_STORMSHIELD_PROFILE_OVPN: &str = "client\nremote 127.0.0.1 443 tcp\n";

/// Minimal OpenVPN sidecar stdin JSON accepted by the Stormshield shape gate / Fake establish.
///
/// Same snake_case `profile_ovpn` field the shared `wormhole-ovpnproxy` config and
/// ovpn-backed providers already exercise.
pub const FAKE_STORMSHIELD_SIDECAR_JSON: &[u8] = br#"{"profile_ovpn":"client\nremote 127.0.0.1 443 tcp\n","username":"sns-user","password":"x"}"#;

pub(crate) fn require_stormshield_provider(provider: &dyn TunnelProvider) -> Result<(), TunnelError> {
    if provider.kind() != TunnelKind::Stormshield {
        return Err(TunnelError::WrongKind {
            expected: TunnelKind::Stormshield,
            actual: provider.kind(),
        });
    }
    Ok(())
}

pub(crate) fn load_stormshield_record(
    config_id: Uuid,
    configs: &dyn TunnelConfigLookup,
) -> Result<crate::TunnelConfigRecord, TunnelError> {
    let record = configs
        .get(config_id)?
        .ok_or(TunnelError::ConfigNotFound { id: config_id })?;

    if record.kind != TunnelKind::Stormshield {
        return Err(TunnelError::WrongKind {
            expected: TunnelKind::Stormshield,
            actual: record.kind,
        });
    }

    Ok(record)
}

pub(crate) async fn establish_with_secret(
    record: &crate::TunnelConfigRecord,
    secret: &[u8],
    provider: &dyn TunnelProvider,
) -> Result<Arc<dyn TunnelInstance>, TunnelError> {
    require_openvpn_establish_secret(secret, "Stormshield", &record.name)?;

    let snapshot = record.to_snapshot();
    tracing::info!(
        tunnel_config_id = %record.id,
        tunnel_name = %snapshot.name,
        secret_len = secret.len(),
        "establishing Stormshield tunnel from stored config"
    );
    // Never log `secret` / stdin JSON / passwords / OTP.
    provider.establish(&snapshot, secret).await
}

/// Load TunnelConfig metadata + already-resolved OpenVPN sidecar secret, then
/// call Stormshield [`TunnelProvider::establish`].
///
/// Fail-closed:
/// - missing config → [`TunnelError::ConfigNotFound`]
/// - kind ≠ Stormshield → [`TunnelError::WrongKind`]
/// - missing / empty / wrong-shape secret → [`TunnelError::SecretMissing`] /
///   [`TunnelError::Establish`] (never echoes the blob)
///
/// `provider.kind()` must be [`TunnelKind::Stormshield`]. Prefer
/// [`establish_stormshield_sns`] when materials still need SNS auth stubs.
pub async fn establish_stormshield(
    config_id: Uuid,
    configs: &dyn TunnelConfigLookup,
    secrets: &dyn TunnelSecretLookup,
    provider: &dyn TunnelProvider,
) -> Result<Arc<dyn TunnelInstance>, TunnelError> {
    require_stormshield_provider(provider)?;
    let record = load_stormshield_record(config_id, configs)?;

    let secret = secrets
        .read(&config_id)?
        .ok_or(TunnelError::SecretMissing { id: config_id })?;

    establish_with_secret(&record, &secret, provider).await
}

/// Load metadata, resolve OpenVPN sidecar JSON via Stormshield **SNS** auth stub, then establish.
///
/// Uses [`StormshieldSnsAuth`] + [`stormshield_materials_from_sns`] /
/// [`stormshield_sns_to_sidecar_json`] (`password + otp` concat — never
/// WatchGuard CRV1 `challenge_response`). Profile text is caller-supplied —
/// no SNS portal download. [`NullStormshieldSnsAuth`] / cancel when OTP spend
/// is required → [`TunnelError::Cancelled`].
///
/// Fail-closed on empty/whitespace `profile_ovpn` **before** SNS auth so a
/// single-use OTP is never spent when the shape gate would reject the profile.
pub async fn establish_stormshield_sns(
    config_id: Uuid,
    configs: &dyn TunnelConfigLookup,
    profile_ovpn: impl Into<String>,
    credentials: StormshieldSnsCredentials,
    otp_spend: StormshieldOtpSpend,
    auth: &dyn StormshieldSnsAuth,
    provider: &dyn TunnelProvider,
) -> Result<Arc<dyn TunnelInstance>, TunnelError> {
    require_stormshield_provider(provider)?;
    let record = load_stormshield_record(config_id, configs)?;

    let profile_ovpn = profile_ovpn.into();
    if profile_ovpn.trim().is_empty() {
        return Err(TunnelError::Establish(
            "Stormshield establish requires a non-empty OpenVPN profile before SNS auth"
                .into(),
        ));
    }

    let auth_result = auth
        .resolve(StormshieldSnsAuthRequest::new(
            record.name.clone(),
            credentials,
            otp_spend,
        ))
        .await?;

    let materials = stormshield_materials_from_sns(
        profile_ovpn,
        &auth_result.username,
        &auth_result.auth_password,
        None,
        None,
    );
    let secret = stormshield_sns_to_sidecar_json(&materials)?;

    establish_with_secret(&record, &secret, provider).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use async_trait::async_trait;

    use crate::providers::auth_glue::{
        FakeStormshieldSnsAuth, NullStormshieldSnsAuth, StormshieldOtpSpend,
        StormshieldSnsCredentials,
    };
    use crate::providers::wireguard::{
        FakeTunnelConfigLookup, FakeTunnelSecretLookup, TunnelConfigRecord,
    };
    use crate::{
        FakeTunnelProvider, StubTunnelInstance, TunnelConfigSnapshot, TunnelState,
    };

    fn sns_id() -> Uuid {
        Uuid::parse_str("cccccccc-dddd-eeee-ffff-000000000001").unwrap()
    }

    fn secret_marker() -> &'static [u8] {
        br#"{"profile_ovpn":"client\n","username":"alice","password":"SUPER_SECRET_SNS_PASS_DO_NOT_LEAK"}"#
    }

    /// Records last stdin JSON — [`FakeTunnelProvider`] ignores the blob.
    /// [`Debug`] is length-only (never dumps passwords / OTP).
    struct RecordingStormshieldProvider {
        establish_count: AtomicUsize,
        last_secret: Mutex<Option<Vec<u8>>>,
    }

    impl RecordingStormshieldProvider {
        fn new() -> Self {
            Self {
                establish_count: AtomicUsize::new(0),
                last_secret: Mutex::new(None),
            }
        }

        fn establish_count(&self) -> usize {
            self.establish_count.load(Ordering::SeqCst)
        }

        fn last_secret(&self) -> Option<Vec<u8>> {
            self.last_secret
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone()
        }
    }

    impl std::fmt::Debug for RecordingStormshieldProvider {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let len = self
                .last_secret
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .as_ref()
                .map(|b| b.len());
            f.debug_struct("RecordingStormshieldProvider")
                .field("establish_count", &self.establish_count())
                .field("last_secret_len", &len)
                .finish()
        }
    }

    #[async_trait]
    impl TunnelProvider for RecordingStormshieldProvider {
        fn kind(&self) -> TunnelKind {
            TunnelKind::Stormshield
        }

        async fn establish(
            &self,
            _config: &TunnelConfigSnapshot,
            secret_blob: &[u8],
        ) -> Result<Arc<dyn TunnelInstance>, TunnelError> {
            self.establish_count.fetch_add(1, Ordering::SeqCst);
            *self
                .last_secret
                .lock()
                .unwrap_or_else(|p| p.into_inner()) = Some(secret_blob.to_vec());
            Ok(StubTunnelInstance::up_with_socks(18_701))
        }
    }

    #[tokio::test]
    async fn establish_loads_metadata_and_secret_via_fake_provider() {
        let id = sns_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::Stormshield,
            "lab-sns",
        ));
        let secrets =
            FakeTunnelSecretLookup::new().with_secret(id, FAKE_STORMSHIELD_SIDECAR_JSON);
        let provider = FakeTunnelProvider::new(TunnelKind::Stormshield);

        let instance = establish_stormshield(id, &configs, &secrets, &provider)
            .await
            .expect("establish");
        assert_eq!(provider.establish_count(), 1);
        assert_eq!(configs.get_calls(), 1);
        assert_eq!(secrets.read_calls(), 1);
        assert_eq!(instance.state(), crate::TunnelState::Up);
        assert!(instance.socks5_endpoint().is_some());
    }

    #[tokio::test]
    async fn establish_sns_via_fake_auth_and_otp() {
        let id = sns_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::Stormshield,
            "edge-fw",
        ));
        let auth = FakeStormshieldSnsAuth::from_submitted_otps(["654321"]);
        let provider = FakeTunnelProvider::new(TunnelKind::Stormshield);

        let instance = establish_stormshield_sns(
            id,
            &configs,
            FAKE_STORMSHIELD_PROFILE_OVPN,
            StormshieldSnsCredentials::with_otp("alice", "base-pw"),
            StormshieldOtpSpend::DataPlane,
            &auth,
            &provider,
        )
        .await
        .expect("sns establish");
        assert_eq!(provider.establish_count(), 1);
        assert_eq!(auth.resolve_count(), 1);
        assert_eq!(instance.state(), crate::TunnelState::Up);
        let reqs = auth.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].config_name, "edge-fw");
        assert_eq!(reqs[0].otp_spend, StormshieldOtpSpend::DataPlane);
    }

    #[tokio::test]
    async fn establish_sns_without_otp_succeeds() {
        let id = sns_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::Stormshield,
            "lab-sns",
        ));
        let auth = FakeStormshieldSnsAuth::new();
        let provider = FakeTunnelProvider::new(TunnelKind::Stormshield);

        let instance = establish_stormshield_sns(
            id,
            &configs,
            FAKE_STORMSHIELD_PROFILE_OVPN,
            StormshieldSnsCredentials::without_otp("bob", "only-pw"),
            StormshieldOtpSpend::None,
            &auth,
            &provider,
        )
        .await
        .expect("no-otp establish");
        assert_eq!(provider.establish_count(), 1);
        assert_eq!(auth.resolve_count(), 1);
        assert_eq!(instance.state(), crate::TunnelState::Up);
    }

    #[tokio::test]
    async fn establish_sns_password_otp_concat_never_echoes_secret() {
        let id = sns_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::Stormshield,
            "lab-sns",
        ));
        let auth = FakeStormshieldSnsAuth::from_submitted_otps(["OTP_LEAK"]);
        let provider = RecordingStormshieldProvider::new();

        let instance = establish_stormshield_sns(
            id,
            &configs,
            FAKE_STORMSHIELD_PROFILE_OVPN,
            StormshieldSnsCredentials::with_otp("alice", "PASS_LEAK_MARKER"),
            StormshieldOtpSpend::DataPlane,
            &auth,
            &provider,
        )
        .await
        .expect("sns establish");
        assert_eq!(provider.establish_count(), 1);
        assert_eq!(instance.state(), TunnelState::Up);

        let json = provider.last_secret().expect("captured stdin");
        let parsed: serde_json::Value = serde_json::from_slice(&json).expect("json");
        assert_eq!(
            parsed["password"].as_str(),
            Some("PASS_LEAK_MARKEROTP_LEAK"),
            "SNS must concat password+otp (never CRV1 challenge_response)"
        );
        assert!(
            parsed.get("challenge_response").is_none()
                || parsed["challenge_response"].is_null()
        );

        let dbg = format!("{auth:?} / {provider:?}");
        assert!(!dbg.contains("PASS_LEAK_MARKER"), "{dbg}");
        assert!(!dbg.contains("OTP_LEAK"), "{dbg}");
    }

    #[tokio::test]
    async fn missing_config_fails_closed() {
        let id = sns_id();
        let configs = FakeTunnelConfigLookup::new();
        let secrets =
            FakeTunnelSecretLookup::new().with_secret(id, FAKE_STORMSHIELD_SIDECAR_JSON);
        let provider = FakeTunnelProvider::new(TunnelKind::Stormshield);

        let err = match establish_stormshield(id, &configs, &secrets, &provider).await {
            Ok(_) => panic!("missing config"),
            Err(e) => e,
        };
        assert!(matches!(err, TunnelError::ConfigNotFound { id: got } if got == id));
        assert_eq!(provider.establish_count(), 0);
        assert_eq!(secrets.read_calls(), 0);

        let auth = FakeStormshieldSnsAuth::new();
        let err = match establish_stormshield_sns(
            id,
            &configs,
            FAKE_STORMSHIELD_PROFILE_OVPN,
            StormshieldSnsCredentials::without_otp("u", "pw"),
            StormshieldOtpSpend::None,
            &auth,
            &provider,
        )
        .await
        {
            Ok(_) => panic!("missing config on auth path"),
            Err(e) => e,
        };
        assert!(matches!(err, TunnelError::ConfigNotFound { id: got } if got == id));
        assert_eq!(provider.establish_count(), 0);
        assert_eq!(auth.resolve_count(), 0);
    }

    #[tokio::test]
    async fn missing_secret_fails_closed() {
        let id = sns_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::Stormshield,
            "lab-sns",
        ));
        let secrets = FakeTunnelSecretLookup::new();
        let provider = FakeTunnelProvider::new(TunnelKind::Stormshield);

        let err = match establish_stormshield(id, &configs, &secrets, &provider).await {
            Ok(_) => panic!("missing secret"),
            Err(e) => e,
        };
        assert!(matches!(err, TunnelError::SecretMissing { id: got } if got == id));
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn empty_secret_fails_before_provider() {
        let id = sns_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::Stormshield,
            "lab-sns",
        ));
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, Vec::<u8>::new());
        let provider = FakeTunnelProvider::new(TunnelKind::Stormshield);

        let err = match establish_stormshield(id, &configs, &secrets, &provider).await {
            Ok(_) => panic!("empty secret"),
            Err(e) => e,
        };
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
        assert!(format!("{err}").contains("empty"), "{err}");
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn wrong_config_kind_fails_closed() {
        let id = sns_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::Watchguard,
            "not-sns",
        ));
        let secrets =
            FakeTunnelSecretLookup::new().with_secret(id, FAKE_STORMSHIELD_SIDECAR_JSON);
        let provider = FakeTunnelProvider::new(TunnelKind::Stormshield);

        let err = match establish_stormshield(id, &configs, &secrets, &provider).await {
            Ok(_) => panic!("wrong kind"),
            Err(e) => e,
        };
        assert!(matches!(
            err,
            TunnelError::WrongKind {
                expected: TunnelKind::Stormshield,
                actual: TunnelKind::Watchguard
            }
        ));
        assert_eq!(provider.establish_count(), 0);
        assert_eq!(secrets.read_calls(), 0);

        let auth = FakeStormshieldSnsAuth::from_submitted_otps(["should-not-spend"]);
        let err = match establish_stormshield_sns(
            id,
            &configs,
            FAKE_STORMSHIELD_PROFILE_OVPN,
            StormshieldSnsCredentials::with_otp("alice", "pw"),
            StormshieldOtpSpend::DataPlane,
            &auth,
            &provider,
        )
        .await
        {
            Ok(_) => panic!("wrong kind on sns path"),
            Err(e) => e,
        };
        assert!(matches!(
            err,
            TunnelError::WrongKind {
                expected: TunnelKind::Stormshield,
                actual: TunnelKind::Watchguard
            }
        ));
        assert_eq!(provider.establish_count(), 0);
        assert_eq!(auth.resolve_count(), 0);
    }

    #[tokio::test]
    async fn wrong_provider_kind_fails_closed() {
        let id = sns_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::Stormshield,
            "lab-sns",
        ));
        let secrets =
            FakeTunnelSecretLookup::new().with_secret(id, FAKE_STORMSHIELD_SIDECAR_JSON);
        let provider = FakeTunnelProvider::new(TunnelKind::OpenVpn);

        let err = match establish_stormshield(id, &configs, &secrets, &provider).await {
            Ok(_) => panic!("wrong provider"),
            Err(e) => e,
        };
        assert!(matches!(
            err,
            TunnelError::WrongKind {
                expected: TunnelKind::Stormshield,
                actual: TunnelKind::OpenVpn
            }
        ));
        assert_eq!(provider.establish_count(), 0);
        assert_eq!(configs.get_calls(), 0);

        let auth = FakeStormshieldSnsAuth::new();
        let err = match establish_stormshield_sns(
            id,
            &configs,
            FAKE_STORMSHIELD_PROFILE_OVPN,
            StormshieldSnsCredentials::without_otp("u", "pw"),
            StormshieldOtpSpend::None,
            &auth,
            &provider,
        )
        .await
        {
            Ok(_) => panic!("wrong provider on sns path"),
            Err(e) => e,
        };
        assert!(matches!(
            err,
            TunnelError::WrongKind {
                expected: TunnelKind::Stormshield,
                actual: TunnelKind::OpenVpn
            }
        ));
        assert_eq!(auth.resolve_count(), 0);
        assert_eq!(configs.get_calls(), 0);
    }

    #[tokio::test]
    async fn editor_settings_blob_rejects_without_echoing() {
        let id = sns_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::Stormshield,
            "lab-sns",
        ));
        let secrets = FakeTunnelSecretLookup::new().with_secret(
            id,
            br#"{"Server":"sns.example","Username":"alice","Password":"SUPER_SECRET_SNS_PASS_DO_NOT_LEAK"}"#,
        );
        let provider = FakeTunnelProvider::new(TunnelKind::Stormshield);

        let err = match establish_stormshield(id, &configs, &secrets, &provider).await {
            Ok(_) => panic!("editor blob"),
            Err(e) => e,
        };
        let rendered = format!("{err} / {err:?}");
        assert!(
            rendered.contains("profile_ovpn") || rendered.contains("OpenVpn"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("SUPER_SECRET_SNS_PASS_DO_NOT_LEAK"),
            "must not echo secret: {rendered}"
        );
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn null_sns_auth_on_otp_spend_fails_closed_without_echo() {
        let id = sns_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::Stormshield,
            "lab-sns",
        ));
        let provider = FakeTunnelProvider::new(TunnelKind::Stormshield);

        for spend in [
            StormshieldOtpSpend::DataPlane,
            StormshieldOtpSpend::PortalDownload,
        ] {
            let err = match establish_stormshield_sns(
                id,
                &configs,
                FAKE_STORMSHIELD_PROFILE_OVPN,
                StormshieldSnsCredentials::with_otp("alice", "account-secret"),
                spend,
                &NullStormshieldSnsAuth,
                &provider,
            )
            .await
            {
                Ok(_) => panic!("cancelled for {spend:?}"),
                Err(e) => e,
            };
            assert!(matches!(err, TunnelError::Cancelled), "{spend:?} → {err:?}");
            let rendered = format!("{err}");
            assert!(!rendered.contains("account-secret"), "{rendered}");
        }
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn empty_profile_fails_before_sns_auth() {
        let id = sns_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::Stormshield,
            "lab-sns",
        ));
        let auth = FakeStormshieldSnsAuth::from_submitted_otps(["must-not-spend"]);
        let provider = FakeTunnelProvider::new(TunnelKind::Stormshield);

        let err = match establish_stormshield_sns(
            id,
            &configs,
            "   ",
            StormshieldSnsCredentials::with_otp("alice", "account-secret"),
            StormshieldOtpSpend::DataPlane,
            &auth,
            &provider,
        )
        .await
        {
            Ok(_) => panic!("empty profile"),
            Err(e) => e,
        };
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
        assert!(format!("{err}").contains("profile"), "{err}");
        assert_eq!(provider.establish_count(), 0);
        assert_eq!(auth.resolve_count(), 0);
        let rendered = format!("{err} / {err:?}");
        assert!(!rendered.contains("account-secret"), "{rendered}");
        assert!(!rendered.contains("must-not-spend"), "{rendered}");
    }

    #[tokio::test]
    async fn auth_then_secret_store_compose_via_fake() {
        // Auth stub builds sidecar JSON; secret-store path consumes it (no live network).
        let id = sns_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::Stormshield,
            "lab-sns",
        ));
        let auth = FakeStormshieldSnsAuth::from_submitted_otps(["112233"]);
        let auth_result = auth
            .resolve(StormshieldSnsAuthRequest::new(
                "lab-sns",
                StormshieldSnsCredentials::with_otp("alice", "account-secret"),
                StormshieldOtpSpend::DataPlane,
            ))
            .await
            .expect("resolve");
        let materials = stormshield_materials_from_sns(
            FAKE_STORMSHIELD_PROFILE_OVPN,
            &auth_result.username,
            &auth_result.auth_password,
            None,
            None,
        );
        let json = stormshield_sns_to_sidecar_json(&materials).expect("sidecar json");
        // password+otp composition — never challenge_response.
        let parsed: serde_json::Value = serde_json::from_slice(&json).expect("json");
        assert_eq!(parsed["password"].as_str(), Some("account-secret112233"));
        assert!(parsed.get("challenge_response").is_none()
            || parsed["challenge_response"].is_null());

        let secrets = FakeTunnelSecretLookup::new().with_secret(id, json);
        let provider = FakeTunnelProvider::new(TunnelKind::Stormshield);

        let instance = establish_stormshield(id, &configs, &secrets, &provider)
            .await
            .expect("establish from auth-built secret");
        assert_eq!(provider.establish_count(), 1);
        assert_eq!(instance.state(), crate::TunnelState::Up);
        let dbg = format!("{secrets:?}");
        assert!(!dbg.contains("account-secret"), "{dbg}");
        assert!(!dbg.contains("112233"), "{dbg}");
    }

    #[test]
    fn fake_secret_lookup_debug_redacts_payload() {
        let id = sns_id();
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, secret_marker());
        let dbg = format!("{secrets:?}");
        assert!(!dbg.contains("SUPER_SECRET"));
        assert!(!dbg.contains("profile_ovpn"));
        assert!(dbg.contains("entry_byte_lengths"));
    }

    #[cfg(feature = "secrets")]
    #[tokio::test]
    async fn payload_store_adapter_establish_with_fake_store() {
        use crate::PayloadStoreSecretLookup;
        use wormhole_secrets_win::{FakeTunnelPayloadStore, TunnelPayloadStore};

        let id = sns_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::Stormshield,
            "lab-sns",
        ));
        let store = FakeTunnelPayloadStore::new();
        store
            .store(&id, FAKE_STORMSHIELD_SIDECAR_JSON)
            .expect("store");
        let secrets = PayloadStoreSecretLookup::new(store);
        let provider = FakeTunnelProvider::new(TunnelKind::Stormshield);

        let instance = establish_stormshield(id, &configs, &secrets, &provider)
            .await
            .expect("establish via payload store");
        assert_eq!(provider.establish_count(), 1);
        assert_eq!(instance.state(), crate::TunnelState::Up);

        let dbg = format!("{secrets:?}");
        assert!(!dbg.contains("profile_ovpn"));
        assert!(!dbg.contains("sns-user"));
    }
}
