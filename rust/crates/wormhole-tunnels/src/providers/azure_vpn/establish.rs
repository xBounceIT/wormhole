//! Thin Azure VPN establish-path glue: config id → metadata + Entra/auth stub → provider.
//!
//! Mirrors the C# load order (SQLite `TunnelConfigs` row, then Entra access token
//! + synthesized OpenVPN profile) before [`TunnelProvider::establish`]. Uses the
//! same lookup traits / Fake stores as the WireGuard glue
//! ([`crate::providers::wireguard`]) — **separate** API so Azure callers do not
//! share an entry point with OpenVPN / Cisco. Unit tests drive
//! [`crate::FakeTunnelProvider`] + [`FakeEntraTokenProvider`] — **no** live
//! network / Entra popup / ovpnproxy process.

use std::fmt;
use std::sync::Arc;

use uuid::Uuid;

use crate::providers::auth_glue::{
    azure_materials_from_entra, request_entra_access_token, AzureVpnAuthGlue, EntraTokenProvider,
    EntraTokenRequest, OvpnAuthGlue,
};
use crate::providers::secret_shape::require_openvpn_establish_secret;
use crate::providers::wireguard::{TunnelConfigLookup, TunnelSecretLookup};
use crate::{TunnelError, TunnelInstance, TunnelKind, TunnelProvider};

/// Minimal Azure VPN OpenVPN-sidecar stdin JSON used by crate tests / Fake establish.
///
/// Same snake_case `profile_ovpn` shape as `wormhole-ovpnproxy`, with the Azure
/// credential contract (`username`=`AzureAD`).
pub const FAKE_AZURE_VPN_SIDECAR_JSON: &[u8] =
    br#"{"profile_ovpn":"client\n","username":"AzureAD","password":"mock-access-token","mock":true}"#;

/// Non-secret Entra identity + OpenVPN profile inputs for [`establish_azure_from_entra`].
///
/// Does **not** carry access / refresh tokens. [`Debug`] redacts `profile_ovpn`.
#[derive(Clone, PartialEq, Eq)]
pub struct AzureVpnEstablishOptions {
    pub profile_ovpn: String,
    pub tenant_id: String,
    pub audience: String,
    pub client_id: String,
}

impl AzureVpnEstablishOptions {
    pub fn new(
        profile_ovpn: impl Into<String>,
        tenant_id: impl Into<String>,
        audience: impl Into<String>,
        client_id: impl Into<String>,
    ) -> Self {
        Self {
            profile_ovpn: profile_ovpn.into(),
            tenant_id: tenant_id.into(),
            audience: audience.into(),
            client_id: client_id.into(),
        }
    }

    fn to_entra_request(&self, config_id: Uuid, config_name: &str) -> EntraTokenRequest {
        EntraTokenRequest::new(
            config_id,
            config_name,
            self.tenant_id.clone(),
            self.audience.clone(),
            self.client_id.clone(),
        )
    }
}

impl fmt::Debug for AzureVpnEstablishOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AzureVpnEstablishOptions")
            .field(
                "profile_ovpn",
                &if self.profile_ovpn.trim().is_empty() {
                    ""
                } else {
                    "[REDACTED]"
                },
            )
            .field("tenant_id", &self.tenant_id)
            .field("audience", &self.audience)
            .field("client_id", &self.client_id)
            .finish()
    }
}

fn require_azure_provider(provider: &dyn TunnelProvider) -> Result<(), TunnelError> {
    if provider.kind() != TunnelKind::AzureVpn {
        return Err(TunnelError::WrongKind {
            expected: TunnelKind::AzureVpn,
            actual: provider.kind(),
        });
    }
    Ok(())
}

fn load_azure_record(
    config_id: Uuid,
    configs: &dyn TunnelConfigLookup,
) -> Result<crate::TunnelConfigRecord, TunnelError> {
    let record = configs
        .get(config_id)?
        .ok_or(TunnelError::ConfigNotFound { id: config_id })?;

    if record.kind != TunnelKind::AzureVpn {
        return Err(TunnelError::WrongKind {
            expected: TunnelKind::AzureVpn,
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
    require_openvpn_establish_secret(secret, "Azure VPN", &record.name)?;

    let snapshot = record.to_snapshot();
    tracing::info!(
        tunnel_config_id = %record.id,
        tunnel_name = %snapshot.name,
        secret_len = secret.len(),
        "establishing Azure VPN tunnel"
    );
    // Never log `secret` / stdin JSON / access tokens / refresh tokens.
    provider.establish(&snapshot, secret).await
}

/// Load TunnelConfig metadata + secret for `config_id`, then call Azure VPN
/// [`TunnelProvider::establish`].
///
/// Fail-closed:
/// - missing config → [`TunnelError::ConfigNotFound`]
/// - kind ≠ AzureVpn → [`TunnelError::WrongKind`]
/// - missing / empty / wrong-shape secret → [`TunnelError::SecretMissing`] /
///   [`TunnelError::Establish`] (never echoes the blob)
///
/// `provider.kind()` must be [`TunnelKind::AzureVpn`]. Expects already-resolved
/// OpenVPN sidecar JSON (not editor settings). Prefer
/// [`establish_azure_from_entra`] when starting from a profile + Entra stub.
pub async fn establish_azure(
    config_id: Uuid,
    configs: &dyn TunnelConfigLookup,
    secrets: &dyn TunnelSecretLookup,
    provider: &dyn TunnelProvider,
) -> Result<Arc<dyn TunnelInstance>, TunnelError> {
    require_azure_provider(provider)?;
    let record = load_azure_record(config_id, configs)?;

    let secret = secrets
        .read(&config_id)?
        .ok_or(TunnelError::SecretMissing { id: config_id })?;

    establish_with_secret(&record, &secret, provider).await
}

/// Load TunnelConfig metadata, acquire an Entra access token via the stub, build
/// OpenVPN sidecar JSON (`AzureAD` + access token), then call Azure VPN
/// [`TunnelProvider::establish`].
///
/// Uses [`request_entra_access_token`] + [`azure_materials_from_entra`] +
/// [`AzureVpnAuthGlue`]. Does **not** show a Microsoft sign-in popup and does
/// **not** write the refresh-token tokencache.
///
/// Fail-closed on missing config / wrong kind / empty profile / cancelled or
/// empty Entra token. Secrets never appear in tracing fields.
pub async fn establish_azure_from_entra(
    config_id: Uuid,
    configs: &dyn TunnelConfigLookup,
    options: AzureVpnEstablishOptions,
    entra: &dyn EntraTokenProvider,
    provider: &dyn TunnelProvider,
) -> Result<Arc<dyn TunnelInstance>, TunnelError> {
    require_azure_provider(provider)?;
    let record = load_azure_record(config_id, configs)?;

    if options.profile_ovpn.trim().is_empty() {
        return Err(TunnelError::Establish(
            "Azure VPN establish requires a non-empty OpenVPN profile before Entra token acquisition"
                .into(),
        ));
    }

    let request = options.to_entra_request(config_id, &record.name);
    let access = request_entra_access_token(entra, request).await?;
    let materials = azure_materials_from_entra(options.profile_ovpn, &access);
    let secret = AzureVpnAuthGlue.to_sidecar_json(&materials)?;

    establish_with_secret(&record, &secret, provider).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use async_trait::async_trait;

    use std::time::{Duration, SystemTime};

    use crate::providers::auth_glue::{
        azure_vpn_refresh_token_cache_path, FakeEntraTokenProvider, NullEntraTokenProvider,
        AZURE_AAD_USERNAME,
    };
    use crate::providers::wireguard::{
        FakeTunnelConfigLookup, FakeTunnelSecretLookup, TunnelConfigRecord,
    };
    use crate::{FakeTunnelProvider, StubTunnelInstance, TunnelConfigSnapshot, TunnelState};

    const SECRET_MARKER: &str = "AZURE_ACCESS_TOKEN_DO_NOT_LEAK";

    fn azure_id() -> Uuid {
        Uuid::parse_str("cccccccc-dddd-eeee-ffff-000000000000").unwrap()
    }

    fn sample_options() -> AzureVpnEstablishOptions {
        AzureVpnEstablishOptions::new(
            "client\nremote azure-gw.example 443\n",
            "tenant-guid",
            "api://AzureVPN/",
            "client-app-id",
        )
    }

    fn secret_marker() -> Vec<u8> {
        format!(
            r#"{{"profile_ovpn":"client\n","username":"AzureAD","password":"{SECRET_MARKER}"}}"#
        )
        .into_bytes()
    }

    fn secret_with_profile(profile_ovpn: &str) -> Vec<u8> {
        format!(
            r#"{{"profile_ovpn":"{profile_ovpn}","username":"AzureAD","password":"{SECRET_MARKER}","mock":true}}"#
        )
        .into_bytes()
    }

    fn assert_no_secret_echo(err: &TunnelError) {
        let rendered = format!("{err} / {err:?}");
        assert!(
            !rendered.contains(SECRET_MARKER),
            "must not echo secret: {rendered}"
        );
    }

    /// Pins that establish forwards snapshot + exact stdin bytes (`FakeTunnelProvider` ignores them).
    ///
    /// `Debug` is length/presence only (never dumps tokens / profile).
    struct RecordingAzureProvider {
        establish_count: AtomicUsize,
        last: Mutex<Option<(TunnelConfigSnapshot, Vec<u8>)>>,
    }

    impl RecordingAzureProvider {
        fn new() -> Self {
            Self {
                establish_count: AtomicUsize::new(0),
                last: Mutex::new(None),
            }
        }

        fn establish_count(&self) -> usize {
            self.establish_count.load(Ordering::SeqCst)
        }

        fn take_last(&self) -> Option<(TunnelConfigSnapshot, Vec<u8>)> {
            self.last.lock().unwrap_or_else(|p| p.into_inner()).take()
        }
    }

    impl fmt::Debug for RecordingAzureProvider {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let len = self
                .last
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .as_ref()
                .map(|(_, b)| b.len());
            f.debug_struct("RecordingAzureProvider")
                .field("establish_count", &self.establish_count())
                .field("last_secret_len", &len)
                .finish()
        }
    }

    #[async_trait]
    impl TunnelProvider for RecordingAzureProvider {
        fn kind(&self) -> TunnelKind {
            TunnelKind::AzureVpn
        }

        async fn establish(
            &self,
            config: &TunnelConfigSnapshot,
            secret_blob: &[u8],
        ) -> Result<Arc<dyn TunnelInstance>, TunnelError> {
            self.establish_count.fetch_add(1, Ordering::SeqCst);
            *self.last.lock().unwrap_or_else(|p| p.into_inner()) =
                Some((config.clone(), secret_blob.to_vec()));
            Ok(StubTunnelInstance::up_with_socks(18_765))
        }
    }

    #[tokio::test]
    async fn establish_loads_metadata_and_secret_via_fake_provider() {
        let id = azure_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::AzureVpn,
            "lab-azure",
        ));
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, FAKE_AZURE_VPN_SIDECAR_JSON);
        let provider = FakeTunnelProvider::new(TunnelKind::AzureVpn);

        let instance = establish_azure(id, &configs, &secrets, &provider)
            .await
            .expect("establish");
        assert_eq!(provider.establish_count(), 1);
        assert_eq!(configs.get_calls(), 1);
        assert_eq!(secrets.read_calls(), 1);
        assert_eq!(instance.state(), TunnelState::Up);
        assert!(instance.socks5_endpoint().is_some());
    }

    #[tokio::test]
    async fn establish_from_entra_via_fake_token_and_fake_provider() {
        let id = azure_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::AzureVpn,
            "lab-azure",
        ));
        let provider = FakeTunnelProvider::new(TunnelKind::AzureVpn);
        let entra = FakeEntraTokenProvider::from_access_tokens(["access-TOKEN-marker"]);

        let instance =
            establish_azure_from_entra(id, &configs, sample_options(), &entra, &provider)
                .await
                .expect("establish from entra");
        assert_eq!(provider.establish_count(), 1);
        assert_eq!(configs.get_calls(), 1);
        assert_eq!(instance.state(), TunnelState::Up);

        let requests = entra.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].tunnel_config_id, id);
        assert_eq!(requests[0].config_name, "lab-azure");
        assert_eq!(requests[0].tenant_id, "tenant-guid");
    }

    #[tokio::test]
    async fn establish_forwards_snapshot_and_secret_bytes() {
        let id = azure_id();
        let updated_at = SystemTime::UNIX_EPOCH + Duration::from_secs(42);
        let configs = FakeTunnelConfigLookup::new().with_config(
            TunnelConfigRecord::new(id, TunnelKind::AzureVpn, "lab-azure")
                .with_updated_at(updated_at),
        );
        let marker = secret_marker();
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, marker.clone());
        let provider = RecordingAzureProvider::new();

        let instance = establish_azure(id, &configs, &secrets, &provider)
            .await
            .expect("establish");
        assert_eq!(provider.establish_count(), 1);
        assert_eq!(instance.state(), TunnelState::Up);

        let (snapshot, secret) = provider.take_last().expect("captured");
        assert_eq!(snapshot.id, id);
        assert_eq!(snapshot.name, "lab-azure");
        assert_eq!(snapshot.kind, TunnelKind::AzureVpn);
        assert_eq!(snapshot.updated_at, updated_at);
        assert_eq!(secret, marker);

        let dbg = format!("{provider:?}");
        assert!(!dbg.contains(SECRET_MARKER), "{dbg}");
    }

    #[tokio::test]
    async fn establish_from_entra_passes_azure_ad_access_token_stdin() {
        let id = azure_id();
        let updated_at = SystemTime::UNIX_EPOCH + Duration::from_secs(99);
        let configs = FakeTunnelConfigLookup::new().with_config(
            TunnelConfigRecord::new(id, TunnelKind::AzureVpn, "lab-azure")
                .with_updated_at(updated_at),
        );
        let provider = RecordingAzureProvider::new();
        let entra = FakeEntraTokenProvider::from_access_tokens(["ACCESS_TOKEN_LEAK_MARKER"]);

        let instance =
            establish_azure_from_entra(id, &configs, sample_options(), &entra, &provider)
                .await
                .expect("establish from entra");
        assert_eq!(provider.establish_count(), 1);
        assert_eq!(instance.state(), TunnelState::Up);

        let (snapshot, secret) = provider.take_last().expect("captured stdin");
        assert_eq!(snapshot.id, id);
        assert_eq!(snapshot.name, "lab-azure");
        assert_eq!(snapshot.kind, TunnelKind::AzureVpn);
        assert_eq!(snapshot.updated_at, updated_at);

        let v: serde_json::Value = serde_json::from_slice(&secret).expect("json");
        assert_eq!(v["username"], AZURE_AAD_USERNAME);
        assert_eq!(v["password"], "ACCESS_TOKEN_LEAK_MARKER");
        assert!(
            v["profile_ovpn"]
                .as_str()
                .unwrap_or("")
                .contains("azure-gw.example"),
            "{v}"
        );

        let dbg = format!("{provider:?}");
        assert!(!dbg.contains("ACCESS_TOKEN_LEAK_MARKER"), "{dbg}");
        assert!(!dbg.contains("azure-gw.example"), "{dbg}");
        assert!(dbg.contains("last_secret_len"), "{dbg}");
    }

    #[tokio::test]
    async fn establish_from_entra_never_writes_tokencache() {
        let id = azure_id();
        let path = azure_vpn_refresh_token_cache_path(&id);
        let _ = std::fs::remove_file(&path);
        let existed = path.exists();

        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::AzureVpn,
            "lab-azure",
        ));
        let provider = FakeTunnelProvider::new(TunnelKind::AzureVpn);
        let entra = FakeEntraTokenProvider::from_results([Some(
            crate::providers::auth_glue::EntraTokenResult::new(
                "access-no-disk",
                Some("refresh-MUST-NOT-HIT-DISK"),
            ),
        )]);

        establish_azure_from_entra(id, &configs, sample_options(), &entra, &provider)
            .await
            .expect("establish");

        if existed {
            // Pre-existing file must not gain refresh bytes from this stub path.
            let after = std::fs::read(&path).unwrap_or_default();
            let text = String::from_utf8_lossy(&after);
            assert!(
                !text.contains("refresh-MUST-NOT-HIT-DISK"),
                "must not rewrite tokencache with refresh"
            );
        } else {
            assert!(
                !path.exists(),
                "establish_azure_from_entra must not create tokencache at {}",
                path.display()
            );
        }
    }

    #[tokio::test]
    async fn missing_config_fails_closed() {
        let id = azure_id();
        let configs = FakeTunnelConfigLookup::new();
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, FAKE_AZURE_VPN_SIDECAR_JSON);
        let provider = FakeTunnelProvider::new(TunnelKind::AzureVpn);

        let err = establish_azure(id, &configs, &secrets, &provider)
            .await
            .err()
            .expect("missing config");
        assert!(matches!(err, TunnelError::ConfigNotFound { id: got } if got == id));
        assert_eq!(provider.establish_count(), 0);
        assert_eq!(secrets.read_calls(), 0);
    }

    #[tokio::test]
    async fn missing_config_fails_closed_on_entra_path() {
        let id = azure_id();
        let configs = FakeTunnelConfigLookup::new();
        let provider = FakeTunnelProvider::new(TunnelKind::AzureVpn);
        let entra = FakeEntraTokenProvider::from_access_tokens(["tok"]);

        let err = establish_azure_from_entra(id, &configs, sample_options(), &entra, &provider)
            .await
            .err()
            .expect("missing config");
        assert!(matches!(err, TunnelError::ConfigNotFound { id: got } if got == id));
        assert_eq!(provider.establish_count(), 0);
        assert!(entra.requests().is_empty());
    }

    #[tokio::test]
    async fn missing_secret_fails_closed() {
        let id = azure_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::AzureVpn,
            "lab-azure",
        ));
        let secrets = FakeTunnelSecretLookup::new();
        let provider = FakeTunnelProvider::new(TunnelKind::AzureVpn);

        let err = establish_azure(id, &configs, &secrets, &provider)
            .await
            .err()
            .expect("missing secret");
        assert!(matches!(err, TunnelError::SecretMissing { id: got } if got == id));
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn empty_secret_fails_before_provider() {
        let id = azure_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::AzureVpn,
            "lab-azure",
        ));
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, Vec::<u8>::new());
        let provider = FakeTunnelProvider::new(TunnelKind::AzureVpn);

        let err = establish_azure(id, &configs, &secrets, &provider)
            .await
            .err()
            .expect("empty secret");
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
        assert!(format!("{err}").contains("empty"), "{err}");
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn empty_profile_ovpn_with_mock_fails_before_provider() {
        let id = azure_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::AzureVpn,
            "lab-azure",
        ));
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, secret_with_profile(""));
        let provider = FakeTunnelProvider::new(TunnelKind::AzureVpn);

        let err = establish_azure(id, &configs, &secrets, &provider)
            .await
            .err()
            .expect("empty profile");
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
        assert_eq!(provider.establish_count(), 0);
        assert_no_secret_echo(&err);
    }

    #[tokio::test]
    async fn whitespace_profile_ovpn_fails_before_provider() {
        let id = azure_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::AzureVpn,
            "lab-azure",
        ));
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, secret_with_profile("   "));
        let provider = FakeTunnelProvider::new(TunnelKind::AzureVpn);

        let err = establish_azure(id, &configs, &secrets, &provider)
            .await
            .err()
            .expect("whitespace profile");
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
        assert_eq!(provider.establish_count(), 0);
        assert_no_secret_echo(&err);
    }

    #[tokio::test]
    async fn invalid_json_secret_rejects_without_echoing_blob() {
        let id = azure_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::AzureVpn,
            "lab-azure",
        ));
        let blob = format!(r#"{{not-json "{SECRET_MARKER}"}}"#,).into_bytes();
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, blob);
        let provider = FakeTunnelProvider::new(TunnelKind::AzureVpn);

        let err = establish_azure(id, &configs, &secrets, &provider)
            .await
            .err()
            .expect("invalid json");
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
        assert_eq!(provider.establish_count(), 0);
        assert_no_secret_echo(&err);
    }

    #[tokio::test]
    async fn provider_error_propagates_without_wrapping_secret() {
        let id = azure_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::AzureVpn,
            "lab-azure",
        ));
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, secret_marker());
        let provider = FakeTunnelProvider::new(TunnelKind::AzureVpn);
        provider.fail_next("sidecar spawn failed (unit)");

        let err = establish_azure(id, &configs, &secrets, &provider)
            .await
            .err()
            .expect("provider fail_next");
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
        assert!(format!("{err}").contains("sidecar spawn failed"), "{err}");
        assert_no_secret_echo(&err);
    }

    #[tokio::test]
    async fn null_entra_cancels_without_establish() {
        let id = azure_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::AzureVpn,
            "lab-azure",
        ));
        let provider = FakeTunnelProvider::new(TunnelKind::AzureVpn);

        let err = establish_azure_from_entra(
            id,
            &configs,
            sample_options(),
            &NullEntraTokenProvider,
            &provider,
        )
        .await
        .err()
        .expect("null entra");
        assert!(matches!(err, TunnelError::Cancelled), "{err:?}");
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn empty_entra_token_fails_without_echo() {
        let id = azure_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::AzureVpn,
            "lab-azure",
        ));
        let provider = FakeTunnelProvider::new(TunnelKind::AzureVpn);
        let entra = FakeEntraTokenProvider::from_access_tokens(["   "]);

        let err = establish_azure_from_entra(id, &configs, sample_options(), &entra, &provider)
            .await
            .err()
            .expect("empty token");
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
        assert_eq!(provider.establish_count(), 0);
        let rendered = format!("{err} / {err:?}");
        assert!(!rendered.contains("access-TOKEN"), "{rendered}");
    }

    #[tokio::test]
    async fn empty_profile_fails_before_entra() {
        let id = azure_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::AzureVpn,
            "lab-azure",
        ));
        let provider = FakeTunnelProvider::new(TunnelKind::AzureVpn);
        let entra = FakeEntraTokenProvider::from_access_tokens(["tok"]);
        let opts = AzureVpnEstablishOptions::new("  ", "t", "a", "c");

        let err = establish_azure_from_entra(id, &configs, opts, &entra, &provider)
            .await
            .err()
            .expect("empty profile");
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
        assert!(format!("{err}").contains("profile"), "{err}");
        assert_eq!(provider.establish_count(), 0);
        assert!(entra.requests().is_empty());
    }

    #[tokio::test]
    async fn wrong_config_kind_fails_closed() {
        let id = azure_id();
        let configs = FakeTunnelConfigLookup::new()
            .with_config(TunnelConfigRecord::new(id, TunnelKind::OpenVpn, "not-azure"));
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, FAKE_AZURE_VPN_SIDECAR_JSON);
        let provider = FakeTunnelProvider::new(TunnelKind::AzureVpn);

        let err = establish_azure(id, &configs, &secrets, &provider)
            .await
            .err()
            .expect("wrong kind");
        assert!(matches!(
            err,
            TunnelError::WrongKind {
                expected: TunnelKind::AzureVpn,
                actual: TunnelKind::OpenVpn
            }
        ));
        assert_eq!(provider.establish_count(), 0);
        assert_eq!(secrets.read_calls(), 0);
    }

    #[tokio::test]
    async fn wrong_config_kind_fails_closed_on_entra_path() {
        let id = azure_id();
        let configs = FakeTunnelConfigLookup::new()
            .with_config(TunnelConfigRecord::new(id, TunnelKind::OpenVpn, "not-azure"));
        let provider = FakeTunnelProvider::new(TunnelKind::AzureVpn);
        let entra = FakeEntraTokenProvider::from_access_tokens(["tok"]);

        let err = establish_azure_from_entra(id, &configs, sample_options(), &entra, &provider)
            .await
            .err()
            .expect("wrong kind");
        assert!(matches!(
            err,
            TunnelError::WrongKind {
                expected: TunnelKind::AzureVpn,
                actual: TunnelKind::OpenVpn
            }
        ));
        assert_eq!(provider.establish_count(), 0);
        assert!(entra.requests().is_empty());
    }

    #[tokio::test]
    async fn wrong_provider_kind_fails_closed() {
        let id = azure_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::AzureVpn,
            "lab-azure",
        ));
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, FAKE_AZURE_VPN_SIDECAR_JSON);
        let provider = FakeTunnelProvider::new(TunnelKind::OpenVpn);

        let err = establish_azure(id, &configs, &secrets, &provider)
            .await
            .err()
            .expect("wrong provider");
        assert!(matches!(
            err,
            TunnelError::WrongKind {
                expected: TunnelKind::AzureVpn,
                actual: TunnelKind::OpenVpn
            }
        ));
        assert_eq!(provider.establish_count(), 0);
        assert_eq!(configs.get_calls(), 0);
    }

    #[tokio::test]
    async fn wrong_provider_kind_fails_closed_on_entra_path() {
        let id = azure_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::AzureVpn,
            "lab-azure",
        ));
        let provider = FakeTunnelProvider::new(TunnelKind::OpenVpn);
        let entra = FakeEntraTokenProvider::from_access_tokens(["tok"]);

        let err = establish_azure_from_entra(id, &configs, sample_options(), &entra, &provider)
            .await
            .err()
            .expect("wrong provider");
        assert!(matches!(
            err,
            TunnelError::WrongKind {
                expected: TunnelKind::AzureVpn,
                actual: TunnelKind::OpenVpn
            }
        ));
        assert_eq!(provider.establish_count(), 0);
        assert_eq!(configs.get_calls(), 0);
        assert!(entra.requests().is_empty());
    }

    #[tokio::test]
    async fn bad_secret_shape_rejects_without_echoing_blob() {
        let id = azure_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::AzureVpn,
            "lab-azure",
        ));
        let secrets = FakeTunnelSecretLookup::new().with_secret(
            id,
            format!(
                r#"{{"TenantId":"t","Audience":"a","Password":"{SECRET_MARKER}"}}"#
            )
            .into_bytes(),
        );
        let provider = FakeTunnelProvider::new(TunnelKind::AzureVpn);

        let err = establish_azure(id, &configs, &secrets, &provider)
            .await
            .err()
            .expect("bad shape");
        let rendered = format!("{err} / {err:?}");
        assert!(
            rendered.contains("profile_ovpn") || rendered.contains("OpenVpn"),
            "{rendered}"
        );
        assert_no_secret_echo(&err);
        assert_eq!(provider.establish_count(), 0);
    }

    #[test]
    fn options_debug_redacts_profile() {
        let opts = sample_options();
        let dbg = format!("{opts:?}");
        assert!(dbg.contains("[REDACTED]"), "{dbg}");
        assert!(!dbg.contains("azure-gw.example"), "{dbg}");
        assert!(!dbg.contains("remote"), "{dbg}");
        assert!(dbg.contains("tenant-guid"), "{dbg}");

        let empty = AzureVpnEstablishOptions::new("", "t", "a", "c");
        let empty_dbg = format!("{empty:?}");
        assert!(empty_dbg.contains("profile_ovpn: \"\""), "{empty_dbg}");
        assert!(!empty_dbg.contains("[REDACTED]"), "{empty_dbg}");
    }

    #[test]
    fn fake_secret_lookup_debug_redacts_payload() {
        let id = azure_id();
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, secret_marker());
        let dbg = format!("{secrets:?}");
        assert!(!dbg.contains(SECRET_MARKER));
        assert!(!dbg.contains("password"));
        assert!(dbg.contains("entry_byte_lengths"));
    }

    #[cfg(feature = "secrets")]
    #[tokio::test]
    async fn payload_store_adapter_establish_with_fake_store() {
        use crate::providers::wireguard::PayloadStoreSecretLookup;
        use wormhole_secrets_win::{FakeTunnelPayloadStore, TunnelPayloadStore};

        let id = azure_id();
        let configs = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            id,
            TunnelKind::AzureVpn,
            "lab-azure",
        ));
        let store = FakeTunnelPayloadStore::new();
        store
            .store(&id, FAKE_AZURE_VPN_SIDECAR_JSON)
            .expect("store");
        let secrets = PayloadStoreSecretLookup::new(store);
        let provider = FakeTunnelProvider::new(TunnelKind::AzureVpn);

        let instance = establish_azure(id, &configs, &secrets, &provider)
            .await
            .expect("establish via payload store");
        assert_eq!(provider.establish_count(), 1);
        assert_eq!(instance.state(), TunnelState::Up);

        let dbg = format!("{secrets:?}");
        assert!(!dbg.contains("AzureAD"));
        assert!(!dbg.contains("mock-access-token"));
    }
}
