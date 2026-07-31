//! Thin WireGuard establish-path glue: config id → metadata + DPAPI/fake secret → provider.
//!
//! Mirrors the C# load order (SQLite `TunnelConfigs` row, then
//! `%LOCALAPPDATA%\Wormhole\tunnels\<id:N>.dpapi`) before
//! [`TunnelProvider::establish`]. Production wires
//! [`wormhole_storage::TunnelConfigRepository`] +
//! [`wormhole_secrets_win::TunnelPayloadStore`]; tests use the Fake lookups below
//! with [`crate::FakeTunnelProvider`] and the sidecar JSON shape already used in
//! this crate (`interface_private_key`). **No** live network / WireGuard iface.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use uuid::Uuid;

use crate::providers::secret_shape::require_wireguard_establish_secret;
use crate::{
    TunnelConfigSnapshot, TunnelError, TunnelInstance, TunnelKind, TunnelProvider,
};

/// Minimal WireGuard sidecar stdin JSON used by crate tests / Fake establish.
///
/// Same snake_case field the Go `wormhole-wgproxy` config and
/// `tests/sidecar_control_plane.rs` already exercise.
pub const FAKE_WIREGUARD_SIDECAR_JSON: &[u8] =
    br#"{"interface_private_key":"x","endpoint":"127.0.0.1:51820"}"#;

/// Metadata-only tunnel config row (SQLite `TunnelConfigs` shape).
///
/// Secrets never live here — only id / name / kind / `updated_at`.
#[derive(Debug, Clone)]
pub struct TunnelConfigRecord {
    pub id: Uuid,
    pub name: String,
    pub kind: TunnelKind,
    /// Mirrors C# / SQLite `UpdatedAt` for pool invalidation.
    pub updated_at: SystemTime,
}

impl TunnelConfigRecord {
    pub fn new(id: Uuid, kind: TunnelKind, name: impl Into<String>) -> Self {
        Self {
            id,
            kind,
            name: name.into(),
            updated_at: SystemTime::UNIX_EPOCH,
        }
    }

    pub fn with_updated_at(mut self, updated_at: SystemTime) -> Self {
        self.updated_at = updated_at;
        self
    }

    pub fn to_snapshot(&self) -> TunnelConfigSnapshot {
        TunnelConfigSnapshot {
            id: self.id,
            kind: self.kind,
            name: self.name.clone(),
            updated_at: self.updated_at,
        }
    }
}

/// Load TunnelConfigs metadata by id (production: `TunnelConfigRepository::get_by_id`).
pub trait TunnelConfigLookup: Send + Sync {
    fn get(&self, id: Uuid) -> Result<Option<TunnelConfigRecord>, TunnelError>;
}

/// Load the tunnel secret blob by config id (production: `TunnelPayloadStore::read`).
///
/// Implementations must **never** log or put plaintext into [`TunnelError`] / [`Debug`].
pub trait TunnelSecretLookup: Send + Sync {
    fn read(&self, tunnel_config_id: &Uuid) -> Result<Option<Vec<u8>>, TunnelError>;
}

/// Adapt any [`wormhole_secrets_win::TunnelPayloadStore`] as a [`TunnelSecretLookup`].
///
/// Enabled with the `secrets` feature (default). Maps store I/O failures to
/// [`TunnelError::Establish`] without embedding payload bytes.
#[cfg(feature = "secrets")]
pub struct PayloadStoreSecretLookup<S> {
    store: S,
}

#[cfg(feature = "secrets")]
impl<S> PayloadStoreSecretLookup<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub fn into_inner(self) -> S {
        self.store
    }

    pub fn store(&self) -> &S {
        &self.store
    }
}

#[cfg(feature = "secrets")]
impl<S> fmt::Debug for PayloadStoreSecretLookup<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Delegate — FakeTunnelPayloadStore / DpapiTunnelPayloadStore already redact.
        f.debug_struct("PayloadStoreSecretLookup")
            .field("store", &self.store)
            .finish()
    }
}

#[cfg(feature = "secrets")]
impl<S> TunnelSecretLookup for PayloadStoreSecretLookup<S>
where
    S: wormhole_secrets_win::TunnelPayloadStore + Send + Sync,
{
    fn read(&self, tunnel_config_id: &Uuid) -> Result<Option<Vec<u8>>, TunnelError> {
        self.store.read(tunnel_config_id).map_err(|e| {
            // SecretsError Display is already free of secret material.
            TunnelError::Establish(format!("tunnel secret store read failed: {e}"))
        })
    }
}

/// In-memory TunnelConfigs stand-in for unit tests (no SQLite).
#[derive(Default)]
pub struct FakeTunnelConfigLookup {
    entries: Mutex<HashMap<Uuid, TunnelConfigRecord>>,
    get_calls: AtomicUsize,
}

impl FakeTunnelConfigLookup {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(self, record: TunnelConfigRecord) -> Self {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(record.id, record);
        self
    }

    pub fn insert(&self, record: TunnelConfigRecord) {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(record.id, record);
    }

    pub fn get_calls(&self) -> usize {
        self.get_calls.load(Ordering::SeqCst)
    }
}

impl fmt::Debug for FakeTunnelConfigLookup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        let ids: Vec<Uuid> = entries.keys().copied().collect();
        f.debug_struct("FakeTunnelConfigLookup")
            .field("config_ids", &ids)
            .field("get_calls", &self.get_calls.load(Ordering::SeqCst))
            .finish()
    }
}

impl TunnelConfigLookup for FakeTunnelConfigLookup {
    fn get(&self, id: Uuid) -> Result<Option<TunnelConfigRecord>, TunnelError> {
        self.get_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&id)
            .cloned())
    }
}

/// In-memory tunnel-secret stand-in for unit tests (no DPAPI).
///
/// Prefer [`PayloadStoreSecretLookup`]`<`[`wormhole_secrets_win::FakeTunnelPayloadStore`]`>`
/// when the `secrets` feature is on and you want the real store trait surface.
pub struct FakeTunnelSecretLookup {
    entries: Mutex<HashMap<Uuid, Vec<u8>>>,
    read_calls: AtomicUsize,
}

impl Default for FakeTunnelSecretLookup {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeTunnelSecretLookup {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            read_calls: AtomicUsize::new(0),
        }
    }

    pub fn with_secret(self, id: Uuid, secret: impl Into<Vec<u8>>) -> Self {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(id, secret.into());
        self
    }

    pub fn insert(&self, id: Uuid, secret: impl Into<Vec<u8>>) {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(id, secret.into());
    }

    pub fn read_calls(&self) -> usize {
        self.read_calls.load(Ordering::SeqCst)
    }
}

impl fmt::Debug for FakeTunnelSecretLookup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        let lengths: Vec<(Uuid, usize)> = entries.iter().map(|(k, v)| (*k, v.len())).collect();
        f.debug_struct("FakeTunnelSecretLookup")
            .field("entry_byte_lengths", &lengths)
            .field("read_calls", &self.read_calls.load(Ordering::SeqCst))
            .finish()
    }
}

impl TunnelSecretLookup for FakeTunnelSecretLookup {
    fn read(&self, tunnel_config_id: &Uuid) -> Result<Option<Vec<u8>>, TunnelError> {
        self.read_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(tunnel_config_id)
            .cloned())
    }
}

/// Load TunnelConfig metadata + secret for `config_id`, then call WireGuard
/// [`TunnelProvider::establish`].
///
/// Fail-closed:
/// - missing config → [`TunnelError::ConfigNotFound`]
/// - kind ≠ WireGuard → [`TunnelError::WrongKind`]
/// - missing / empty / wrong-shape secret → [`TunnelError::SecretMissing`] /
///   [`TunnelError::Establish`] (never echoes the blob)
///
/// `provider.kind()` must be [`TunnelKind::WireGuard`].
pub async fn establish_wireguard(
    config_id: Uuid,
    configs: &dyn TunnelConfigLookup,
    secrets: &dyn TunnelSecretLookup,
    provider: &dyn TunnelProvider,
) -> Result<Arc<dyn TunnelInstance>, TunnelError> {
    if provider.kind() != TunnelKind::WireGuard {
        return Err(TunnelError::WrongKind {
            expected: TunnelKind::WireGuard,
            actual: provider.kind(),
        });
    }

    let record = configs
        .get(config_id)?
        .ok_or(TunnelError::ConfigNotFound { id: config_id })?;

    if record.kind != TunnelKind::WireGuard {
        return Err(TunnelError::WrongKind {
            expected: TunnelKind::WireGuard,
            actual: record.kind,
        });
    }

    let secret = secrets
        .read(&config_id)?
        .ok_or(TunnelError::SecretMissing { id: config_id })?;

    require_wireguard_establish_secret(&secret, &record.name)?;

    let snapshot = record.to_snapshot();
    tracing::info!(
        tunnel_config_id = %config_id,
        tunnel_name = %snapshot.name,
        secret_len = secret.len(),
        "establishing WireGuard tunnel from stored config"
    );
    // Never log `secret` / stdin JSON.
    provider.establish(&snapshot, &secret).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use crate::FakeTunnelProvider;

    fn wg_id() -> Uuid {
        Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap()
    }

    fn secret_marker() -> &'static [u8] {
        br#"{"interface_private_key":"SUPER_SECRET_WG_KEY_DO_NOT_LEAK","endpoint":"10.0.0.1"}"#
    }

    const SECRET_MARKER: &str = "SUPER_SECRET_WG_KEY_DO_NOT_LEAK";

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
        assert!(
            !rendered.contains("10.0.0.1"),
            "must not echo endpoint from blob: {rendered}"
        );
    }

    /// Pins that establish forwards the exact snapshot + secret bytes (Fake ignores them).
    struct CapturingWgProvider {
        last: Mutex<Option<(TunnelConfigSnapshot, Vec<u8>)>>,
        establish_count: AtomicUsize,
    }

    impl CapturingWgProvider {
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

    impl fmt::Debug for CapturingWgProvider {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("CapturingWgProvider")
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
    impl TunnelProvider for CapturingWgProvider {
        fn kind(&self) -> TunnelKind {
            TunnelKind::WireGuard
        }

        async fn establish(
            &self,
            config: &TunnelConfigSnapshot,
            secret_blob: &[u8],
        ) -> Result<Arc<dyn TunnelInstance>, TunnelError> {
            self.establish_count.fetch_add(1, Ordering::SeqCst);
            *self.last.lock().unwrap_or_else(|p| p.into_inner()) =
                Some((config.clone(), secret_blob.to_vec()));
            Ok(crate::StubTunnelInstance::up_with_socks(18_001))
        }
    }

    #[tokio::test]
    async fn establish_loads_metadata_and_secret_via_fake_provider() {
        let id = wg_id();
        let configs = FakeTunnelConfigLookup::new()
            .with_config(TunnelConfigRecord::new(id, TunnelKind::WireGuard, "lab-wg"));
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, FAKE_WIREGUARD_SIDECAR_JSON);
        let provider = FakeTunnelProvider::new(TunnelKind::WireGuard);

        let instance = establish_wireguard(id, &configs, &secrets, &provider)
            .await
            .expect("establish");
        assert_eq!(provider.establish_count(), 1);
        assert_eq!(configs.get_calls(), 1);
        assert_eq!(secrets.read_calls(), 1);
        assert_eq!(instance.state(), crate::TunnelState::Up);
        assert!(instance.socks5_endpoint().is_some());
    }

    #[tokio::test]
    async fn establish_forwards_snapshot_and_secret_bytes() {
        let id = wg_id();
        let updated_at = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(42);
        let configs = FakeTunnelConfigLookup::new().with_config(
            TunnelConfigRecord::new(id, TunnelKind::WireGuard, "lab-wg").with_updated_at(updated_at),
        );
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, secret_marker());
        let provider = CapturingWgProvider::new();

        let _instance = establish_wireguard(id, &configs, &secrets, &provider)
            .await
            .expect("establish");
        assert_eq!(provider.establish_count(), 1);
        // Debug while the capture still holds the secret — must stay length/flag only.
        let dbg = format!("{provider:?}");
        assert!(!dbg.contains(SECRET_MARKER), "{dbg}");
        assert!(dbg.contains("has_last"), "{dbg}");
        let (snapshot, secret) = provider.take_last().expect("captured establish args");
        assert_eq!(snapshot.id, id);
        assert_eq!(snapshot.kind, TunnelKind::WireGuard);
        assert_eq!(snapshot.name, "lab-wg");
        assert_eq!(snapshot.updated_at, updated_at);
        assert_eq!(secret, secret_marker());
    }

    #[tokio::test]
    async fn missing_config_fails_closed() {
        let id = wg_id();
        let configs = FakeTunnelConfigLookup::new();
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, FAKE_WIREGUARD_SIDECAR_JSON);
        let provider = FakeTunnelProvider::new(TunnelKind::WireGuard);

        let err = expect_tunnel_err(
            establish_wireguard(id, &configs, &secrets, &provider).await,
            "missing config",
        );
        assert!(matches!(err, TunnelError::ConfigNotFound { id: got } if got == id));
        assert_eq!(provider.establish_count(), 0);
        assert_eq!(secrets.read_calls(), 0);
    }

    #[tokio::test]
    async fn missing_secret_fails_closed() {
        let id = wg_id();
        let configs = FakeTunnelConfigLookup::new()
            .with_config(TunnelConfigRecord::new(id, TunnelKind::WireGuard, "lab-wg"));
        let secrets = FakeTunnelSecretLookup::new();
        let provider = FakeTunnelProvider::new(TunnelKind::WireGuard);

        let err = expect_tunnel_err(
            establish_wireguard(id, &configs, &secrets, &provider).await,
            "missing secret",
        );
        assert!(matches!(err, TunnelError::SecretMissing { id: got } if got == id));
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn empty_secret_fails_before_provider() {
        let id = wg_id();
        let configs = FakeTunnelConfigLookup::new()
            .with_config(TunnelConfigRecord::new(id, TunnelKind::WireGuard, "lab-wg"));
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, Vec::<u8>::new());
        let provider = FakeTunnelProvider::new(TunnelKind::WireGuard);

        let err = expect_tunnel_err(
            establish_wireguard(id, &configs, &secrets, &provider).await,
            "empty secret",
        );
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
        assert!(format!("{err}").contains("empty"), "{err}");
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn wrong_config_kind_fails_closed() {
        let id = wg_id();
        let configs = FakeTunnelConfigLookup::new()
            .with_config(TunnelConfigRecord::new(id, TunnelKind::OpenVpn, "not-wg"));
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, FAKE_WIREGUARD_SIDECAR_JSON);
        let provider = FakeTunnelProvider::new(TunnelKind::WireGuard);

        let err = expect_tunnel_err(
            establish_wireguard(id, &configs, &secrets, &provider).await,
            "wrong kind",
        );
        assert!(matches!(
            err,
            TunnelError::WrongKind {
                expected: TunnelKind::WireGuard,
                actual: TunnelKind::OpenVpn
            }
        ));
        assert_eq!(provider.establish_count(), 0);
        assert_eq!(secrets.read_calls(), 0);
    }

    #[tokio::test]
    async fn wrong_provider_kind_fails_closed() {
        let id = wg_id();
        let configs = FakeTunnelConfigLookup::new()
            .with_config(TunnelConfigRecord::new(id, TunnelKind::WireGuard, "lab-wg"));
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, FAKE_WIREGUARD_SIDECAR_JSON);
        let provider = FakeTunnelProvider::new(TunnelKind::OpenVpn);

        let err = expect_tunnel_err(
            establish_wireguard(id, &configs, &secrets, &provider).await,
            "wrong provider",
        );
        assert!(matches!(
            err,
            TunnelError::WrongKind {
                expected: TunnelKind::WireGuard,
                actual: TunnelKind::OpenVpn
            }
        ));
        assert_eq!(provider.establish_count(), 0);
        assert_eq!(configs.get_calls(), 0);
    }

    #[tokio::test]
    async fn bad_secret_shape_rejects_without_echoing_blob() {
        let id = wg_id();
        let configs = FakeTunnelConfigLookup::new()
            .with_config(TunnelConfigRecord::new(id, TunnelKind::WireGuard, "lab-wg"));
        let secrets = FakeTunnelSecretLookup::new().with_secret(
            id,
            br#"{"PrivateKey":"SUPER_SECRET_WG_KEY_DO_NOT_LEAK","Endpoint":"10.0.0.1"}"#,
        );
        let provider = FakeTunnelProvider::new(TunnelKind::WireGuard);

        let err = expect_tunnel_err(
            establish_wireguard(id, &configs, &secrets, &provider).await,
            "bad shape",
        );
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
        let rendered = format!("{err}");
        assert!(
            rendered.contains("interface_private_key"),
            "expected shape-gate wording: {rendered}"
        );
        assert_no_secret_echo(&err);
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn whitespace_only_key_rejects_without_echoing_blob() {
        let id = wg_id();
        let configs = FakeTunnelConfigLookup::new()
            .with_config(TunnelConfigRecord::new(id, TunnelKind::WireGuard, "lab-wg"));
        // Marker lives in a sibling field so a serde-echo regression would fail the assert.
        let secrets = FakeTunnelSecretLookup::new().with_secret(
            id,
            br#"{"interface_private_key":"  \t  ","endpoint":"10.0.0.1","note":"SUPER_SECRET_WG_KEY_DO_NOT_LEAK"}"#,
        );
        let provider = FakeTunnelProvider::new(TunnelKind::WireGuard);

        let err = expect_tunnel_err(
            establish_wireguard(id, &configs, &secrets, &provider).await,
            "whitespace key",
        );
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
        assert!(format!("{err}").contains("interface_private_key"), "{err}");
        assert_no_secret_echo(&err);
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn invalid_json_secret_rejects_without_echoing_blob() {
        let id = wg_id();
        let configs = FakeTunnelConfigLookup::new()
            .with_config(TunnelConfigRecord::new(id, TunnelKind::WireGuard, "lab-wg"));
        // Marker must never appear even if a future change stringifies serde errors.
        let secrets = FakeTunnelSecretLookup::new()
            .with_secret(id, SECRET_MARKER.as_bytes());
        let provider = FakeTunnelProvider::new(TunnelKind::WireGuard);

        let err = expect_tunnel_err(
            establish_wireguard(id, &configs, &secrets, &provider).await,
            "invalid json",
        );
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
        let rendered = format!("{err}");
        assert!(
            rendered.contains("JSON"),
            "expected invalid-JSON wording: {rendered}"
        );
        assert_no_secret_echo(&err);
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn non_object_json_secret_rejects_without_echoing_blob() {
        let id = wg_id();
        let configs = FakeTunnelConfigLookup::new()
            .with_config(TunnelConfigRecord::new(id, TunnelKind::WireGuard, "lab-wg"));
        let secrets = FakeTunnelSecretLookup::new()
            .with_secret(id, br#""SUPER_SECRET_WG_KEY_DO_NOT_LEAK""#);
        let provider = FakeTunnelProvider::new(TunnelKind::WireGuard);

        let err = expect_tunnel_err(
            establish_wireguard(id, &configs, &secrets, &provider).await,
            "non-object json",
        );
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
        assert!(format!("{err}").contains("object"), "{err}");
        assert_no_secret_echo(&err);
        assert_eq!(provider.establish_count(), 0);
    }

    #[tokio::test]
    async fn openvpn_shaped_secret_rejects_for_wireguard() {
        let id = wg_id();
        let configs = FakeTunnelConfigLookup::new()
            .with_config(TunnelConfigRecord::new(id, TunnelKind::WireGuard, "lab-wg"));
        let secrets = FakeTunnelSecretLookup::new().with_secret(
            id,
            br#"{"profile_ovpn":"client\n","password":"SUPER_SECRET_WG_KEY_DO_NOT_LEAK"}"#,
        );
        let provider = FakeTunnelProvider::new(TunnelKind::WireGuard);

        let err = expect_tunnel_err(
            establish_wireguard(id, &configs, &secrets, &provider).await,
            "openvpn shape",
        );
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
        assert!(format!("{err}").contains("interface_private_key"), "{err}");
        assert_no_secret_echo(&err);
        assert_eq!(provider.establish_count(), 0);
    }

    #[test]
    fn fake_secret_lookup_debug_redacts_payload() {
        let id = wg_id();
        let secrets = FakeTunnelSecretLookup::new().with_secret(id, secret_marker());
        let dbg = format!("{secrets:?}");
        assert!(!dbg.contains(SECRET_MARKER));
        assert!(!dbg.contains("interface_private_key"));
        assert!(!dbg.contains("10.0.0.1"));
        assert!(dbg.contains("entry_byte_lengths"));
    }

    #[test]
    fn fake_config_lookup_debug_is_ids_only() {
        let id = wg_id();
        let configs = FakeTunnelConfigLookup::new()
            .with_config(TunnelConfigRecord::new(id, TunnelKind::WireGuard, "lab-wg"));
        let dbg = format!("{configs:?}");
        assert!(dbg.contains("config_ids"));
        assert!(!dbg.contains("lab-wg"), "Debug must not dump names: {dbg}");
    }

    #[cfg(feature = "secrets")]
    #[tokio::test]
    async fn payload_store_adapter_establish_with_fake_store() {
        use wormhole_secrets_win::{FakeTunnelPayloadStore, TunnelPayloadStore};

        let id = wg_id();
        let configs = FakeTunnelConfigLookup::new()
            .with_config(TunnelConfigRecord::new(id, TunnelKind::WireGuard, "lab-wg"));
        let store = FakeTunnelPayloadStore::new();
        store
            .store(&id, FAKE_WIREGUARD_SIDECAR_JSON)
            .expect("store");
        let secrets = PayloadStoreSecretLookup::new(store);
        let provider = FakeTunnelProvider::new(TunnelKind::WireGuard);

        let instance = establish_wireguard(id, &configs, &secrets, &provider)
            .await
            .expect("establish via payload store");
        assert_eq!(provider.establish_count(), 1);
        assert_eq!(instance.state(), crate::TunnelState::Up);

        let dbg = format!("{secrets:?}");
        assert!(!dbg.contains("interface_private_key"));
        assert!(!dbg.contains("127.0.0.1"));
    }

    #[cfg(feature = "secrets")]
    #[tokio::test]
    async fn payload_store_adapter_maps_store_err_without_echoing_marker() {
        use wormhole_secrets_win::{SecretsError, TunnelPayloadStore};

        struct FailingTunnelStore;

        impl TunnelPayloadStore for FailingTunnelStore {
            fn store(&self, _: &Uuid, _: &[u8]) -> wormhole_secrets_win::Result<()> {
                unreachable!("store unused")
            }

            fn read(&self, _: &Uuid) -> wormhole_secrets_win::Result<Option<Vec<u8>>> {
                // Io Display embeds the message — adapter must not invent a secret-bearing path.
                Err(SecretsError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "simulated-io-without-payload",
                )))
            }

            fn delete(&self, _: &Uuid) -> wormhole_secrets_win::Result<()> {
                unreachable!("delete unused")
            }
        }

        let id = wg_id();
        let configs = FakeTunnelConfigLookup::new()
            .with_config(TunnelConfigRecord::new(id, TunnelKind::WireGuard, "lab-wg"));
        let secrets = PayloadStoreSecretLookup::new(FailingTunnelStore);
        let provider = FakeTunnelProvider::new(TunnelKind::WireGuard);

        let err = expect_tunnel_err(
            establish_wireguard(id, &configs, &secrets, &provider).await,
            "store io",
        );
        assert!(matches!(err, TunnelError::Establish(_)), "{err:?}");
        let rendered = format!("{err}");
        assert!(rendered.contains("secret store read failed"), "{rendered}");
        assert!(!rendered.contains(SECRET_MARKER), "{rendered}");
        assert_eq!(provider.establish_count(), 0);
    }
}
