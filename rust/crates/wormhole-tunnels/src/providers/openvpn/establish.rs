//! Thin OpenVPN establish-path glue: config id → metadata + DPAPI/fake secret → provider.
//!
//! Mirrors the C# load order (SQLite `TunnelConfigs` row, then
//! `%LOCALAPPDATA%\Wormhole\tunnels\<id:N>.dpapi`) before
//! [`TunnelProvider::establish`]. Uses the same lookup traits / Fake stores as
//! the WireGuard glue ([`crate::providers::wireguard`]) — **separate** API
//! ([`establish_openvpn`]) so OpenVPN and WireGuard callers do not share an
//! entry point. Production wires `TunnelConfigRepository` +
//! [`wormhole_secrets_win::TunnelPayloadStore`]; tests use
//! [`FakeTunnelConfigLookup`] / [`FakeTunnelSecretLookup`] (or
//! [`PayloadStoreSecretLookup`]`<`[`wormhole_secrets_win::FakeTunnelPayloadStore`]`>`)
//! with [`crate::FakeTunnelProvider`]. **No** live network / OpenVPN process.

use std::sync::Arc;

use uuid::Uuid;

use crate::providers::secret_shape::require_openvpn_establish_secret;
use crate::providers::wireguard::{
    TunnelConfigLookup, TunnelSecretLookup,
};
use crate::{
    TunnelError, TunnelInstance, TunnelKind, TunnelProvider,
};

/// Minimal OpenVPN sidecar stdin JSON used by crate tests / Fake establish.
///
/// Same snake_case `profile_ovpn` field the Go `wormhole-ovpnproxy` config and
/// provider unit tests already exercise.
pub const FAKE_OPENVPN_SIDECAR_JSON: &[u8] =
    br#"{"profile_ovpn":"client\n","mock":true}"#;

/// Load TunnelConfig metadata + secret for `config_id`, then call OpenVPN
/// [`TunnelProvider::establish`].
///
/// Fail-closed:
/// - missing config → [`TunnelError::ConfigNotFound`]
/// - kind ≠ OpenVpn → [`TunnelError::WrongKind`]
/// - missing / empty / wrong-shape secret → [`TunnelError::SecretMissing`] /
///   [`TunnelError::Establish`] (never echoes the blob)
///
/// `provider.kind()` must be [`TunnelKind::OpenVpn`].
pub async fn establish_openvpn(
    config_id: Uuid,
    configs: &dyn TunnelConfigLookup,
    secrets: &dyn TunnelSecretLookup,
    provider: &dyn TunnelProvider,
) -> Result<Arc<dyn TunnelInstance>, TunnelError> {
    if provider.kind() != TunnelKind::OpenVpn {
        return Err(TunnelError::WrongKind {
            expected: TunnelKind::OpenVpn,
            actual: provider.kind(),
        });
    }

    let record = configs
        .get(config_id)?
        .ok_or(TunnelError::ConfigNotFound { id: config_id })?;

    if record.kind != TunnelKind::OpenVpn {
        return Err(TunnelError::WrongKind {
            expected: TunnelKind::OpenVpn,
            actual: record.kind,
        });
    }

    let secret = secrets
        .read(&config_id)?
        .ok_or(TunnelError::SecretMissing { id: config_id })?;

    require_openvpn_establish_secret(&secret, "OpenVPN", &record.name)?;

    let snapshot = record.to_snapshot();
    tracing::info!(
        tunnel_config_id = %config_id,
        tunnel_name = %snapshot.name,
        secret_len = secret.len(),
        "establishing OpenVPN tunnel from stored config"
    );
    // Never log `secret` / stdin JSON.
    provider.establish(&snapshot, &secret).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::{Duration, SystemTime};

    use async_trait::async_trait;

    use crate::providers::wireguard::{
        FakeTunnelConfigLookup, FakeTunnelSecretLookup, TunnelConfigRecord,
    };
    use crate::{FakeTunnelProvider, StubTunnelInstance, TunnelConfigSnapshot, TunnelState};

    const SECRET_MARKER: &str = "SUPER_SECRET_OVPN_PASS_DO_NOT_LEAK";

    fn ovpn_id() -> Uuid {
        Uuid::parse_str("bbbbbbbb-cccc-dddd-eeee-ffffffffffff").unwrap()
    }

    fn secret_marker() -> Vec<u8> {
        format!(r#"{{"profile_ovpn":"client\n","password":"{SECRET_MARKER}"}}"#).into_bytes()
    }

    fn secret_with_profile(profile_ovpn: &str) -> Vec<u8> {
        format!(
            r#"{{"profile_ovpn":"{profile_ovpn}","mock":true,"password":"{SECRET_MARKER}"}}"#
        )
        .into_bytes()
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

    fn assert_no_secret_echo(err: &TunnelError) {
        let rendered = format!("{err} / {err:?}");
        assert!(
            !rendered.contains(SECRET_MARKER),
            "must not echo secret: {rendered}"
        );
    }

    /// Pins that establish forwards the exact snapshot + secret bytes (Fake ignores them).
    struct CapturingOvpnProvider {
        last: Mutex<Option<(TunnelConfigSnapshot, Vec<u8>)>>,
        establish_count: AtomicUsize,
    }

    impl CapturingOvpnProvider {
        fn new() -> Self {
            Self {
                last: Mutex::new(None),
                establish_count: AtomicUsize::new(0),
            }
        }

        fn establish_count(&self) -> usize {
            self.establish_count.load(Ordering::SeqCst)
        }

        fn take_last(&self) -> Option<(TunnelConfigSnapshot, Vec<u8>)> {
            self.last.lock().unwrap_or_else(|p| p.into_inner()).take()
        }
    }

    impl fmt::Debug for CapturingOvpnProvider {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("CapturingOvpnProvider")
                .field("establish_count", &self.establish_count())
                .field(
                    "has_last",
                    &self
                        .last
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .is_some(),
                )
                .finish()
        }
    }

    #[async_trait]
    impl TunnelProvider for CapturingOvpnProvider {
        fn kind(&self) -> TunnelKind {
            TunnelKind::OpenVpn
        }

        async fn establish(
            &self,
            config: &TunnelConfigSnapshot,
            secret_blob: &[u8],
        ) -> Result<Arc<dyn TunnelInstance>, TunnelError> {
            self.establish_count.fetch_add(1, Ordering::SeqCst);
            *self.last.lock().unwrap_or_else(|p| p.into_inner()) =
                Some((config.clone(), secret_blob.to_vec()));
            Ok(StubTunnelInstance::up_with_socks(19_001))
        }
    }

    #[tokio::test]
    async fn establish_loads_metadata_and_secret_via_fake_provider() {
        let id = ovpn_id();
        let configs = FakeTunnelConfigLookup::new()
            .with_config(TunnelConfigRecord::new(id, TunnelKind::OpenVpn, "lab-ovpn"));
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, FAKE_OPENVPN_SIDECAR_JSON);
        let provider = FakeTunnelProvider::new(TunnelKind::OpenVpn);

        let instance = establish_openvpn(id, &configs, &secrets, &provider)
            .await
            .expect("establish");
        assert_eq!(provider.establish_count(), 1);
        assert_eq!(configs.get_calls(), 1);
        assert_eq!(secrets.read_calls(), 1);
        assert_eq!(instance.state(), TunnelState::Up);
        assert!(instance.socks5_endpoint().is_some());
    }

    #[tokio::test]
    async fn establish_forwards_snapshot_and_secret_bytes() {
        let id = ovpn_id();
        let updated_at = SystemTime::UNIX_EPOCH + Duration::from_secs(42);
        let configs = FakeTunnelConfigLookup::new().with_config(
            TunnelConfigRecord::new(id, TunnelKind::OpenVpn, "lab-ovpn").with_updated_at(updated_at),
        );
        let marker = secret_marker();
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, marker.clone());
        let provider = CapturingOvpnProvider::new();

        let _instance = establish_openvpn(id, &configs, &secrets, &provider)
            .await
            .expect("establish");
        assert_eq!(provider.establish_count(), 1);
        let (snapshot, secret) = provider.take_last().expect("captured establish args");
        assert_eq!(snapshot.id, id);
        assert_eq!(snapshot.kind, TunnelKind::OpenVpn);
        assert_eq!(snapshot.name, "lab-ovpn");
        assert_eq!(snapshot.updated_at, updated_at);
        assert_eq!(secret, marker);
        let dbg = format!("{provider:?}");
        assert!(!dbg.contains(SECRET_MARKER), "{dbg}");
    }

    #[tokio::test]
    async fn missing_config_fails_closed() {
        let id = ovpn_id();
        let configs = FakeTunnelConfigLookup::new();
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, FAKE_OPENVPN_SIDECAR_JSON);
        let provider = FakeTunnelProvider::new(TunnelKind::OpenVpn);

        let err = expect_tunnel_err(
            establish_openvpn(id, &configs, &secrets, &provider).await,
            "missing config",
        );
        assert!(matches!(err, TunnelError::ConfigNotFound { id: got } if got == id));
        assert_eq!(provider.establish_count(), 0);
        assert_eq!(secrets.read_calls(), 0);
    }

    #[tokio::test]
    async fn missing_secret_fails_closed() {
        let id = ovpn_id();
        let configs = FakeTunnelConfigLookup::new()
            .with_config(TunnelConfigRecord::new(id, TunnelKind::OpenVpn, "lab-ovpn"));
        let secrets = FakeTunnelSecretLookup::new();
        let provider = FakeTunnelProvider::new(TunnelKind::OpenVpn);

        let err = expect_tunnel_err(
            establish_openvpn(id, &configs, &secrets, &provider).await,
            "missing secret",
        );
        assert!(matches!(err, TunnelError::SecretMissing { id: got } if got == id));
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn empty_secret_fails_before_provider() {
        let id = ovpn_id();
        let configs = FakeTunnelConfigLookup::new()
            .with_config(TunnelConfigRecord::new(id, TunnelKind::OpenVpn, "lab-ovpn"));
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, Vec::<u8>::new());
        let provider = FakeTunnelProvider::new(TunnelKind::OpenVpn);

        let err = expect_tunnel_err(
            establish_openvpn(id, &configs, &secrets, &provider).await,
            "empty secret",
        );
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
        assert!(format!("{err}").contains("empty"), "{err}");
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn empty_profile_ovpn_with_mock_fails_before_provider() {
        // ovpnproxy mock mode can READY with empty profile — establish must still fail closed.
        let id = ovpn_id();
        let configs = FakeTunnelConfigLookup::new()
            .with_config(TunnelConfigRecord::new(id, TunnelKind::OpenVpn, "lab-ovpn"));
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, secret_with_profile(""));
        let provider = FakeTunnelProvider::new(TunnelKind::OpenVpn);

        let err = expect_tunnel_err(
            establish_openvpn(id, &configs, &secrets, &provider).await,
            "empty profile_ovpn",
        );
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
        let rendered = format!("{err}");
        assert!(
            rendered.contains("profile_ovpn") || rendered.contains("OpenVpn"),
            "{rendered}"
        );
        assert_no_secret_echo(&err);
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn whitespace_profile_ovpn_fails_before_provider() {
        let id = ovpn_id();
        let configs = FakeTunnelConfigLookup::new()
            .with_config(TunnelConfigRecord::new(id, TunnelKind::OpenVpn, "lab-ovpn"));
        let secrets =
            FakeTunnelSecretLookup::new().with_secret(id, secret_with_profile("  \\t\\n  "));
        let provider = FakeTunnelProvider::new(TunnelKind::OpenVpn);

        let err = expect_tunnel_err(
            establish_openvpn(id, &configs, &secrets, &provider).await,
            "whitespace profile_ovpn",
        );
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
        assert_no_secret_echo(&err);
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn invalid_json_secret_rejects_without_echoing_blob() {
        let id = ovpn_id();
        let configs = FakeTunnelConfigLookup::new()
            .with_config(TunnelConfigRecord::new(id, TunnelKind::OpenVpn, "lab-ovpn"));
        let secrets = FakeTunnelSecretLookup::new().with_secret(
            id,
            format!("not-json {SECRET_MARKER} {{\"profile_ovpn\":\"x\"}}").into_bytes(),
        );
        let provider = FakeTunnelProvider::new(TunnelKind::OpenVpn);

        let err = expect_tunnel_err(
            establish_openvpn(id, &configs, &secrets, &provider).await,
            "invalid json",
        );
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
        assert!(format!("{err}").contains("JSON"), "{err}");
        assert_no_secret_echo(&err);
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn non_object_json_secret_rejects_without_echoing_blob() {
        let id = ovpn_id();
        let configs = FakeTunnelConfigLookup::new()
            .with_config(TunnelConfigRecord::new(id, TunnelKind::OpenVpn, "lab-ovpn"));
        let secrets = FakeTunnelSecretLookup::new().with_secret(
            id,
            format!(r#"["{SECRET_MARKER}","profile_ovpn"]"#).into_bytes(),
        );
        let provider = FakeTunnelProvider::new(TunnelKind::OpenVpn);

        let err = expect_tunnel_err(
            establish_openvpn(id, &configs, &secrets, &provider).await,
            "non-object json",
        );
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
        assert!(format!("{err}").contains("object"), "{err}");
        assert_no_secret_echo(&err);
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn wrong_config_kind_fails_closed() {
        let id = ovpn_id();
        let configs = FakeTunnelConfigLookup::new()
            .with_config(TunnelConfigRecord::new(id, TunnelKind::WireGuard, "not-ovpn"));
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, FAKE_OPENVPN_SIDECAR_JSON);
        let provider = FakeTunnelProvider::new(TunnelKind::OpenVpn);

        let err = expect_tunnel_err(
            establish_openvpn(id, &configs, &secrets, &provider).await,
            "wrong kind",
        );
        assert!(matches!(
            err,
            TunnelError::WrongKind {
                expected: TunnelKind::OpenVpn,
                actual: TunnelKind::WireGuard
            }
        ));
        assert_eq!(provider.establish_count(), 0);
        assert_eq!(secrets.read_calls(), 0);
    }

    #[tokio::test]
    async fn wrong_provider_kind_fails_closed() {
        let id = ovpn_id();
        let configs = FakeTunnelConfigLookup::new()
            .with_config(TunnelConfigRecord::new(id, TunnelKind::OpenVpn, "lab-ovpn"));
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, FAKE_OPENVPN_SIDECAR_JSON);
        let provider = FakeTunnelProvider::new(TunnelKind::WireGuard);

        let err = expect_tunnel_err(
            establish_openvpn(id, &configs, &secrets, &provider).await,
            "wrong provider",
        );
        assert!(matches!(
            err,
            TunnelError::WrongKind {
                expected: TunnelKind::OpenVpn,
                actual: TunnelKind::WireGuard
            }
        ));
        assert_eq!(provider.establish_count(), 0);
        assert_eq!(configs.get_calls(), 0);
    }

    #[tokio::test]
    async fn bad_secret_shape_rejects_without_echoing_blob() {
        let id = ovpn_id();
        let configs = FakeTunnelConfigLookup::new()
            .with_config(TunnelConfigRecord::new(id, TunnelKind::OpenVpn, "lab-ovpn"));
        // PascalCase editor blob — shape gate must reject; marker must not appear in errors.
        let secrets = FakeTunnelSecretLookup::new().with_secret(
            id,
            format!(
                r#"{{"Server":"vpn.example","Password":"{SECRET_MARKER}","ProfileOvpn":"client"}}"#
            )
            .into_bytes(),
        );
        let provider = FakeTunnelProvider::new(TunnelKind::OpenVpn);

        let err = expect_tunnel_err(
            establish_openvpn(id, &configs, &secrets, &provider).await,
            "bad shape",
        );
        let rendered = format!("{err} / {err:?}");
        assert!(
            rendered.contains("profile_ovpn") || rendered.contains("OpenVpn"),
            "{rendered}"
        );
        assert_no_secret_echo(&err);
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn provider_error_propagates_without_wrapping_secret() {
        let id = ovpn_id();
        let configs = FakeTunnelConfigLookup::new()
            .with_config(TunnelConfigRecord::new(id, TunnelKind::OpenVpn, "lab-ovpn"));
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, secret_marker());
        let provider = FakeTunnelProvider::new(TunnelKind::OpenVpn);
        provider.fail_next("sidecar spawn failed (unit)");

        let err = expect_tunnel_err(
            establish_openvpn(id, &configs, &secrets, &provider).await,
            "provider fail_next",
        );
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
        assert!(format!("{err}").contains("sidecar spawn failed"), "{err}");
        assert_no_secret_echo(&err);
        assert_eq!(provider.establish_count(), 1);
        let provider_dbg = format!("{provider:?}");
        assert!(!provider_dbg.contains(SECRET_MARKER), "{provider_dbg}");
    }

    #[test]
    fn fake_secret_lookup_debug_redacts_payload() {
        let id = ovpn_id();
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, secret_marker());
        let dbg = format!("{secrets:?}");
        assert!(!dbg.contains("SUPER_SECRET"));
        assert!(!dbg.contains("profile_ovpn"));
        assert!(dbg.contains("entry_byte_lengths"));
    }

    #[cfg(feature = "secrets")]
    #[tokio::test]
    async fn payload_store_adapter_establish_with_fake_store() {
        use crate::providers::wireguard::PayloadStoreSecretLookup;
        use wormhole_secrets_win::{FakeTunnelPayloadStore, TunnelPayloadStore};

        let id = ovpn_id();
        let configs = FakeTunnelConfigLookup::new()
            .with_config(TunnelConfigRecord::new(id, TunnelKind::OpenVpn, "lab-ovpn"));
        let store = FakeTunnelPayloadStore::new();
        store
            .store(&id, FAKE_OPENVPN_SIDECAR_JSON)
            .expect("store");
        let secrets = PayloadStoreSecretLookup::new(store);
        let provider = FakeTunnelProvider::new(TunnelKind::OpenVpn);

        let instance = establish_openvpn(id, &configs, &secrets, &provider)
            .await
            .expect("establish via payload store");
        assert_eq!(provider.establish_count(), 1);
        assert_eq!(instance.state(), crate::TunnelState::Up);

        let dbg = format!("{secrets:?}");
        assert!(!dbg.contains("profile_ovpn"));
        assert!(!dbg.contains("client"));
    }
}
