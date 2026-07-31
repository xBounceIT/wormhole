//! Thin WatchGuard establish-path glue: config id → metadata + secret/auth stub → provider.
//!
//! Mirrors the C# load order (SQLite `TunnelConfigs` row, then auth / secret materials)
//! before [`TunnelProvider::establish`]. Production wires
//! [`wormhole_storage::TunnelConfigRepository`] + DPAPI / Firebox auth; tests use
//! shared [`TunnelConfigLookup`] / [`TunnelSecretLookup`] Fakes plus
//! [`FakeFireboxCredentials`] / [`FakeOtpPrompt`] → OpenVPN sidecar JSON, then
//! [`crate::FakeTunnelProvider`] with [`TunnelKind::Watchguard`].
//!
//! **Data plane:** shared `wormhole-ovpnproxy` (no WatchGuard-specific binary).
//! **No** live Firebox HTTP / SAML / network — profile text is caller-supplied;
//! portal download remains TODO.

use std::sync::Arc;

use uuid::Uuid;

use crate::providers::auth_glue::OtpPrompt;
use crate::providers::secret_shape::require_openvpn_establish_secret;
use crate::providers::wireguard::{TunnelConfigLookup, TunnelSecretLookup};
use crate::{
    FireboxCredentials, TunnelError, TunnelInstance, TunnelKind, TunnelProvider,
};

use super::firebox_auth::{
    resolve_firebox_crv1_sidecar_json, resolve_firebox_portal_sidecar_json,
};

/// Minimal `.ovpn` profile fragment for unit tests (no live Firebox download).
pub const FAKE_WATCHGUARD_PROFILE_OVPN: &str = "client\nremote 127.0.0.1 443 tcp\n";

/// Minimal OpenVPN sidecar stdin JSON accepted by the WatchGuard shape gate / Fake establish.
///
/// Same snake_case `profile_ovpn` field the shared `wormhole-ovpnproxy` config and
/// ovpn-backed providers already exercise.
pub const FAKE_WATCHGUARD_SIDECAR_JSON: &[u8] = br#"{"profile_ovpn":"client\nremote 127.0.0.1 443 tcp\n","username":"wg-user","password":"x"}"#;

fn require_watchguard_provider(provider: &dyn TunnelProvider) -> Result<(), TunnelError> {
    if provider.kind() != TunnelKind::Watchguard {
        return Err(TunnelError::WrongKind {
            expected: TunnelKind::Watchguard,
            actual: provider.kind(),
        });
    }
    Ok(())
}

fn load_watchguard_record(
    config_id: Uuid,
    configs: &dyn TunnelConfigLookup,
) -> Result<crate::TunnelConfigRecord, TunnelError> {
    let record = configs
        .get(config_id)?
        .ok_or(TunnelError::ConfigNotFound { id: config_id })?;

    if record.kind != TunnelKind::Watchguard {
        return Err(TunnelError::WrongKind {
            expected: TunnelKind::Watchguard,
            actual: record.kind,
        });
    }

    Ok(record)
}

async fn establish_with_secret(
    record: &crate::TunnelConfigRecord,
    secret: &[u8],
    provider: &dyn TunnelProvider,
) -> Result<Arc<dyn TunnelInstance>, TunnelError> {
    require_openvpn_establish_secret(secret, "WatchGuard", &record.name)?;

    let snapshot = record.to_snapshot();
    tracing::info!(
        tunnel_config_id = %record.id,
        tunnel_name = %snapshot.name,
        secret_len = secret.len(),
        "establishing WatchGuard tunnel from stored config"
    );
    // Never log `secret` / stdin JSON / passwords / OTP.
    provider.establish(&snapshot, secret).await
}

/// Load TunnelConfig metadata + already-resolved OpenVPN sidecar secret, then
/// call WatchGuard [`TunnelProvider::establish`].
///
/// Fail-closed:
/// - missing config → [`TunnelError::ConfigNotFound`]
/// - kind ≠ WatchGuard → [`TunnelError::WrongKind`]
/// - missing / empty / wrong-shape secret → [`TunnelError::SecretMissing`] /
///   [`TunnelError::Establish`] (never echoes the blob)
///
/// `provider.kind()` must be [`TunnelKind::Watchguard`]. Prefer
/// [`establish_watchguard_crv1`] / [`establish_watchguard_portal`] when materials
/// still need Firebox auth stubs.
pub async fn establish_watchguard(
    config_id: Uuid,
    configs: &dyn TunnelConfigLookup,
    secrets: &dyn TunnelSecretLookup,
    provider: &dyn TunnelProvider,
) -> Result<Arc<dyn TunnelInstance>, TunnelError> {
    require_watchguard_provider(provider)?;
    let record = load_watchguard_record(config_id, configs)?;

    let secret = secrets
        .read(&config_id)?
        .ok_or(TunnelError::SecretMissing { id: config_id })?;

    establish_with_secret(&record, &secret, provider).await
}

/// Load metadata, resolve OpenVPN sidecar JSON via Firebox **CRV1** auth stub, then establish.
///
/// Uses [`resolve_firebox_crv1_sidecar_json`] (account password + optional
/// `challenge_response`). Profile text is caller-supplied — no Firebox download.
/// [`NullOtpPrompt`] / cancel → [`TunnelError::Cancelled`]. Empty username /
/// whitespace-only password → [`TunnelError::Establish`] (never echoes).
pub async fn establish_watchguard_crv1(
    config_id: Uuid,
    configs: &dyn TunnelConfigLookup,
    profile_ovpn: impl Into<String>,
    credentials: &FireboxCredentials,
    otp_prompt: Option<&dyn OtpPrompt>,
    provider: &dyn TunnelProvider,
) -> Result<Arc<dyn TunnelInstance>, TunnelError> {
    require_watchguard_provider(provider)?;
    let record = load_watchguard_record(config_id, configs)?;

    let secret = resolve_firebox_crv1_sidecar_json(
        profile_ovpn,
        credentials,
        otp_prompt,
        &record.name,
    )
    .await?;

    establish_with_secret(&record, &secret, provider).await
}

/// Load metadata, resolve OpenVPN sidecar JSON via Firebox **portal** auth stub, then establish.
///
/// Uses [`resolve_firebox_portal_sidecar_json`] (OTP → OpenVPN password quirk; no
/// `challenge_response`). Profile text is caller-supplied — no Firebox download.
/// [`NullOtpPrompt`] / cancel → [`TunnelError::Cancelled`]. Empty username /
/// whitespace-only password → [`TunnelError::Establish`] (never echoes).
pub async fn establish_watchguard_portal(
    config_id: Uuid,
    configs: &dyn TunnelConfigLookup,
    profile_ovpn: impl Into<String>,
    credentials: &FireboxCredentials,
    otp_prompt: Option<&dyn OtpPrompt>,
    provider: &dyn TunnelProvider,
) -> Result<Arc<dyn TunnelInstance>, TunnelError> {
    require_watchguard_provider(provider)?;
    let record = load_watchguard_record(config_id, configs)?;

    let secret = resolve_firebox_portal_sidecar_json(
        profile_ovpn,
        credentials,
        otp_prompt,
        &record.name,
    )
    .await?;

    establish_with_secret(&record, &secret, provider).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use async_trait::async_trait;

    use crate::providers::auth_glue::{FakeOtpPrompt, NullOtpPrompt};
    use crate::providers::wireguard::{
        FakeTunnelConfigLookup, FakeTunnelSecretLookup, TunnelConfigRecord,
    };
    use crate::{
        FakeFireboxCredentials, FakeTunnelProvider, StubTunnelInstance, TunnelConfigSnapshot,
        TunnelState, FIREBOX_PUSH_SELECTOR,
    };

    const SECRET_MARKER: &str = "SUPER_SECRET_WG_PASS_DO_NOT_LEAK";
    const ACCOUNT_SECRET: &str = "account-secret";

    fn wg_id() -> Uuid {
        Uuid::parse_str("bbbbbbbb-cccc-dddd-eeee-ffffffffffff").unwrap()
    }

    fn secret_marker() -> &'static [u8] {
        br#"{"profile_ovpn":"client\n","username":"alice","password":"SUPER_SECRET_WG_PASS_DO_NOT_LEAK"}"#
    }

    fn expect_tunnel_err(
        result: Result<Arc<dyn TunnelInstance>, TunnelError>,
        context: &str,
    ) -> TunnelError {
        match result {
            Ok(_) => panic!("expected error: {context}"),
            Err(e) => e,
        }
    }

    fn assert_no_secret_echo(err: &TunnelError, markers: &[&str]) {
        let rendered = format!("{err} / {err:?}");
        for marker in markers {
            assert!(
                !rendered.contains(marker),
                "must not echo secret marker {marker:?}: {rendered}"
            );
        }
    }

    /// Records the last stdin JSON passed to `establish` (`FakeTunnelProvider` ignores it).
    ///
    /// [`Debug`] is length-only so CRV1/portal password/OTP markers never leak.
    struct RecordingWatchguardProvider {
        establish_count: AtomicUsize,
        last_secret: Mutex<Option<Vec<u8>>>,
    }

    impl RecordingWatchguardProvider {
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

    impl fmt::Debug for RecordingWatchguardProvider {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let len = self
                .last_secret
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .as_ref()
                .map(|b| b.len());
            f.debug_struct("RecordingWatchguardProvider")
                .field("establish_count", &self.establish_count())
                .field("last_secret_len", &len)
                .finish()
        }
    }

    #[async_trait]
    impl TunnelProvider for RecordingWatchguardProvider {
        fn kind(&self) -> TunnelKind {
            TunnelKind::Watchguard
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
            Ok(StubTunnelInstance::up_with_socks(18_766))
        }
    }

    #[tokio::test]
    async fn establish_loads_metadata_and_secret_via_fake_provider() {
        let id = wg_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::Watchguard,
            "lab-wg",
        ));
        let secrets =
            FakeTunnelSecretLookup::new().with_secret(id, FAKE_WATCHGUARD_SIDECAR_JSON);
        let provider = FakeTunnelProvider::new(TunnelKind::Watchguard);

        let instance = establish_watchguard(id, &configs, &secrets, &provider)
            .await
            .expect("establish");
        assert_eq!(provider.establish_count(), 1);
        assert_eq!(configs.get_calls(), 1);
        assert_eq!(secrets.read_calls(), 1);
        assert_eq!(instance.state(), TunnelState::Up);
        assert!(instance.socks5_endpoint().is_some());
    }

    #[tokio::test]
    async fn establish_crv1_via_fake_firebox_credentials_and_otp() {
        let id = wg_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::Watchguard,
            "lab-fw",
        ));
        let fake = FakeFireboxCredentials::new("alice", ACCOUNT_SECRET);
        let otp = FakeOtpPrompt::from_submitted(["  998877  "]);
        let provider = RecordingWatchguardProvider::new();

        let instance = establish_watchguard_crv1(
            id,
            &configs,
            FAKE_WATCHGUARD_PROFILE_OVPN,
            &fake.credentials(),
            Some(&otp),
            &provider,
        )
        .await
        .expect("crv1 establish");
        assert_eq!(provider.establish_count(), 1);
        assert_eq!(fake.resolve_count(), 1);
        assert_eq!(otp.prompt_count(), 1);
        assert_eq!(instance.state(), TunnelState::Up);
        assert!(otp.requests()[0].title.contains("Watchguard 2FA"));

        // CRV1: account password stays on auth-user-pass; OTP → challenge_response.
        let secret = provider.last_secret().expect("captured stdin");
        let v: serde_json::Value = serde_json::from_slice(&secret).expect("json");
        assert_eq!(v["username"], "alice");
        assert_eq!(v["password"], ACCOUNT_SECRET);
        assert_eq!(v["challenge_response"], "998877");
        let dbg = format!("{provider:?}");
        assert!(!dbg.contains(ACCOUNT_SECRET), "{dbg}");
        assert!(!dbg.contains("998877"), "{dbg}");
        assert!(dbg.contains("last_secret_len"), "{dbg}");
    }

    #[tokio::test]
    async fn establish_portal_otp_becomes_openvpn_password_path() {
        let id = wg_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::Watchguard,
            "lab-fw",
        ));
        let fake = FakeFireboxCredentials::new("alice", ACCOUNT_SECRET);
        let otp = FakeOtpPrompt::from_submitted(["portal-otp"]);
        let provider = RecordingWatchguardProvider::new();

        let instance = establish_watchguard_portal(
            id,
            &configs,
            FAKE_WATCHGUARD_PROFILE_OVPN,
            &fake.credentials(),
            Some(&otp),
            &provider,
        )
        .await
        .expect("portal establish");
        assert_eq!(provider.establish_count(), 1);
        assert_eq!(instance.state(), TunnelState::Up);

        // Portal quirk: OTP becomes OpenVPN password; never set challenge_response.
        let secret = provider.last_secret().expect("captured stdin");
        let v: serde_json::Value = serde_json::from_slice(&secret).expect("json");
        assert_eq!(v["password"], "portal-otp");
        assert!(v.get("challenge_response").is_none() || v["challenge_response"].is_null());
        let dbg = format!("{provider:?}");
        assert!(!dbg.contains(ACCOUNT_SECRET), "{dbg}");
        assert!(!dbg.contains("portal-otp"), "{dbg}");
    }

    #[tokio::test]
    async fn establish_crv1_push_succeeds_without_echoing_secret() {
        let id = wg_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::Watchguard,
            "lab-fw",
        ));
        let fake = FakeFireboxCredentials::new("alice", "PASS_LEAK_MARKER");
        let otp = FakeOtpPrompt::from_submitted([FIREBOX_PUSH_SELECTOR]);
        let provider = RecordingWatchguardProvider::new();

        let instance = establish_watchguard_crv1(
            id,
            &configs,
            FAKE_WATCHGUARD_PROFILE_OVPN,
            &fake.credentials(),
            Some(&otp),
            &provider,
        )
        .await
        .expect("push establish");
        assert_eq!(provider.establish_count(), 1);
        assert_eq!(instance.state(), TunnelState::Up);

        let secret = provider.last_secret().expect("captured stdin");
        let v: serde_json::Value = serde_json::from_slice(&secret).expect("json");
        assert_eq!(v["password"], "PASS_LEAK_MARKER");
        assert_eq!(v["challenge_response"], FIREBOX_PUSH_SELECTOR);

        let dbg = format!("{fake:?} / {otp:?} / {provider:?}");
        assert!(!dbg.contains("PASS_LEAK_MARKER"), "{dbg}");
    }

    #[tokio::test]
    async fn missing_config_fails_closed() {
        let id = wg_id();
        let configs = FakeTunnelConfigLookup::new();
        let secrets =
            FakeTunnelSecretLookup::new().with_secret(id, FAKE_WATCHGUARD_SIDECAR_JSON);
        let provider = FakeTunnelProvider::new(TunnelKind::Watchguard);

        let err = expect_tunnel_err(
            establish_watchguard(id, &configs, &secrets, &provider).await,
            "missing config",
        );
        assert!(matches!(err, TunnelError::ConfigNotFound { id: got } if got == id));
        assert_eq!(provider.establish_count(), 0);
        assert_eq!(secrets.read_calls(), 0);

        let fake = FakeFireboxCredentials::new("alice", "pw");
        let err = expect_tunnel_err(
            establish_watchguard_crv1(
                id,
                &configs,
                FAKE_WATCHGUARD_PROFILE_OVPN,
                &fake.credentials(),
                None,
                &provider,
            )
            .await,
            "missing config on crv1",
        );
        assert!(matches!(err, TunnelError::ConfigNotFound { id: got } if got == id));
        assert_eq!(provider.establish_count(), 0);

        let err = expect_tunnel_err(
            establish_watchguard_portal(
                id,
                &configs,
                FAKE_WATCHGUARD_PROFILE_OVPN,
                &fake.credentials(),
                None,
                &provider,
            )
            .await,
            "missing config on portal",
        );
        assert!(matches!(err, TunnelError::ConfigNotFound { id: got } if got == id));
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn missing_secret_fails_closed() {
        let id = wg_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::Watchguard,
            "lab-wg",
        ));
        let secrets = FakeTunnelSecretLookup::new();
        let provider = FakeTunnelProvider::new(TunnelKind::Watchguard);

        let err = expect_tunnel_err(
            establish_watchguard(id, &configs, &secrets, &provider).await,
            "missing secret",
        );
        assert!(matches!(err, TunnelError::SecretMissing { id: got } if got == id));
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn empty_secret_fails_before_provider() {
        let id = wg_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::Watchguard,
            "lab-wg",
        ));
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, Vec::<u8>::new());
        let provider = FakeTunnelProvider::new(TunnelKind::Watchguard);

        let err = expect_tunnel_err(
            establish_watchguard(id, &configs, &secrets, &provider).await,
            "empty secret",
        );
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
        assert!(format!("{err}").contains("empty"), "{err}");
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn whitespace_profile_and_invalid_json_reject_without_echo() {
        let id = wg_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::Watchguard,
            "lab-wg",
        ));
        let provider = FakeTunnelProvider::new(TunnelKind::Watchguard);

        let secrets = FakeTunnelSecretLookup::new().with_secret(
            id,
            br#"{"profile_ovpn":"  \t\n  ","password":"SUPER_SECRET_WG_PASS_DO_NOT_LEAK"}"#,
        );
        let err = expect_tunnel_err(
            establish_watchguard(id, &configs, &secrets, &provider).await,
            "whitespace profile_ovpn",
        );
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
        assert_no_secret_echo(&err, &[SECRET_MARKER]);
        assert_eq!(provider.establish_count(), 0);

        let secrets = FakeTunnelSecretLookup::new().with_secret(
            id,
            br#"not-json SUPER_SECRET_WG_PASS_DO_NOT_LEAK {"profile_ovpn":"x"}"#,
        );
        let err = expect_tunnel_err(
            establish_watchguard(id, &configs, &secrets, &provider).await,
            "invalid json",
        );
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
        assert!(format!("{err}").contains("JSON"), "{err}");
        assert_no_secret_echo(&err, &[SECRET_MARKER]);
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn wrong_config_kind_fails_closed() {
        let id = wg_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::OpenVpn,
            "not-wg",
        ));
        let secrets =
            FakeTunnelSecretLookup::new().with_secret(id, FAKE_WATCHGUARD_SIDECAR_JSON);
        let provider = FakeTunnelProvider::new(TunnelKind::Watchguard);

        let err = expect_tunnel_err(
            establish_watchguard(id, &configs, &secrets, &provider).await,
            "wrong kind",
        );
        assert!(matches!(
            err,
            TunnelError::WrongKind {
                expected: TunnelKind::Watchguard,
                actual: TunnelKind::OpenVpn
            }
        ));
        assert_eq!(provider.establish_count(), 0);
        assert_eq!(secrets.read_calls(), 0);
    }

    #[tokio::test]
    async fn wrong_provider_kind_fails_closed() {
        let id = wg_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::Watchguard,
            "lab-wg",
        ));
        let secrets =
            FakeTunnelSecretLookup::new().with_secret(id, FAKE_WATCHGUARD_SIDECAR_JSON);
        let provider = FakeTunnelProvider::new(TunnelKind::OpenVpn);

        let err = expect_tunnel_err(
            establish_watchguard(id, &configs, &secrets, &provider).await,
            "wrong provider",
        );
        assert!(matches!(
            err,
            TunnelError::WrongKind {
                expected: TunnelKind::Watchguard,
                actual: TunnelKind::OpenVpn
            }
        ));
        assert_eq!(provider.establish_count(), 0);
        assert_eq!(configs.get_calls(), 0);
    }

    #[tokio::test]
    async fn editor_settings_blob_rejects_without_echoing() {
        let id = wg_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::Watchguard,
            "lab-wg",
        ));
        let secrets = FakeTunnelSecretLookup::new().with_secret(
            id,
            br#"{"Server":"fw.example","Username":"alice","Password":"SUPER_SECRET_WG_PASS_DO_NOT_LEAK"}"#,
        );
        let provider = FakeTunnelProvider::new(TunnelKind::Watchguard);

        let err = expect_tunnel_err(
            establish_watchguard(id, &configs, &secrets, &provider).await,
            "editor blob",
        );
        let rendered = format!("{err} / {err:?}");
        assert!(
            rendered.contains("profile_ovpn") || rendered.contains("OpenVpn"),
            "{rendered}"
        );
        assert_no_secret_echo(&err, &[SECRET_MARKER]);
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn null_otp_on_crv1_and_portal_fails_closed_without_echo() {
        let id = wg_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::Watchguard,
            "lab-fw",
        ));
        let creds = FireboxCredentials::new("alice", ACCOUNT_SECRET);
        let provider = FakeTunnelProvider::new(TunnelKind::Watchguard);

        let err = expect_tunnel_err(
            establish_watchguard_crv1(
                id,
                &configs,
                FAKE_WATCHGUARD_PROFILE_OVPN,
                &creds,
                Some(&NullOtpPrompt),
                &provider,
            )
            .await,
            "crv1 cancelled",
        );
        assert!(matches!(err, TunnelError::Cancelled));
        assert_eq!(provider.establish_count(), 0);
        assert_no_secret_echo(&err, &[ACCOUNT_SECRET]);

        let err = expect_tunnel_err(
            establish_watchguard_portal(
                id,
                &configs,
                FAKE_WATCHGUARD_PROFILE_OVPN,
                &creds,
                Some(&NullOtpPrompt),
                &provider,
            )
            .await,
            "portal cancelled",
        );
        assert!(matches!(err, TunnelError::Cancelled));
        assert_eq!(provider.establish_count(), 0);
        assert_no_secret_echo(&err, &[ACCOUNT_SECRET]);
    }

    #[tokio::test]
    async fn auth_path_empty_credentials_fail_without_echo() {
        let id = wg_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::Watchguard,
            "lab-fw",
        ));
        let provider = FakeTunnelProvider::new(TunnelKind::Watchguard);

        for (label, creds) in [
            (
                "empty username",
                FireboxCredentials::new("  ", "s3cret-MARK"),
            ),
            (
                "empty password",
                FireboxCredentials::new("alice", "   "),
            ),
        ] {
            let err = expect_tunnel_err(
                establish_watchguard_crv1(
                    id,
                    &configs,
                    FAKE_WATCHGUARD_PROFILE_OVPN,
                    &creds,
                    None,
                    &provider,
                )
                .await,
                label,
            );
            assert!(matches!(err, TunnelError::Establish(_)), "{label}: {err:?}");
            assert_eq!(provider.establish_count(), 0, "{label}");
            assert_no_secret_echo(&err, &["s3cret-MARK"]);

            let err = expect_tunnel_err(
                establish_watchguard_portal(
                    id,
                    &configs,
                    FAKE_WATCHGUARD_PROFILE_OVPN,
                    &creds,
                    None,
                    &provider,
                )
                .await,
                &format!("portal {label}"),
            );
            assert!(matches!(err, TunnelError::Establish(_)), "{label}: {err:?}");
            assert_eq!(provider.establish_count(), 0, "{label}");
            assert_no_secret_echo(&err, &["s3cret-MARK"]);
        }
    }

    #[tokio::test]
    async fn auth_then_secret_store_compose_via_fake() {
        // Auth stub builds sidecar JSON; secret-store path consumes it (no live network).
        let id = wg_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::Watchguard,
            "lab-fw",
        ));
        let fake = FakeFireboxCredentials::new("alice", ACCOUNT_SECRET);
        let otp = FakeOtpPrompt::from_submitted(["112233"]);
        let json = resolve_firebox_crv1_sidecar_json(
            FAKE_WATCHGUARD_PROFILE_OVPN,
            &fake.credentials(),
            Some(&otp),
            "lab-fw",
        )
        .await
        .expect("resolve");
        let parsed: serde_json::Value = serde_json::from_slice(&json).expect("json");
        assert_eq!(parsed["password"], ACCOUNT_SECRET);
        assert_eq!(parsed["challenge_response"], "112233");

        let secrets = FakeTunnelSecretLookup::new().with_secret(id, json);
        let provider = FakeTunnelProvider::new(TunnelKind::Watchguard);

        let instance = establish_watchguard(id, &configs, &secrets, &provider)
            .await
            .expect("establish from auth-built secret");
        assert_eq!(provider.establish_count(), 1);
        assert_eq!(instance.state(), TunnelState::Up);
        let dbg = format!("{secrets:?}");
        assert!(!dbg.contains(ACCOUNT_SECRET), "{dbg}");
        assert!(!dbg.contains("112233"), "{dbg}");
    }

    #[test]
    fn fake_secret_lookup_debug_redacts_payload() {
        let id = wg_id();
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

        let id = wg_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::Watchguard,
            "lab-wg",
        ));
        let store = FakeTunnelPayloadStore::new();
        store
            .store(&id, FAKE_WATCHGUARD_SIDECAR_JSON)
            .expect("store");
        let secrets = PayloadStoreSecretLookup::new(store);
        let provider = FakeTunnelProvider::new(TunnelKind::Watchguard);

        let instance = establish_watchguard(id, &configs, &secrets, &provider)
            .await
            .expect("establish via payload store");
        assert_eq!(provider.establish_count(), 1);
        assert_eq!(instance.state(), TunnelState::Up);

        let dbg = format!("{secrets:?}");
        assert!(!dbg.contains("profile_ovpn"));
        assert!(!dbg.contains("wg-user"));
    }
}
