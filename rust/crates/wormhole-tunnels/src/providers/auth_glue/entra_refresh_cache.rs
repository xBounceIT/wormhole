//! Azure VPN Entra refresh-token DPAPI cache glue (persist / load / clear).
//!
//! Thin layer over [`RefreshToken`] / [`EntraTokenRequest`] and (when feature
//! `secrets` is on) `wormhole_secrets_win::AzureVpnTokenCacheStore`. Mirrors C#
//! `IAzureVpnTokenCache`: identity-bound refresh tokens under
//! `azurevpn-cache\<id:N>.tokencache`, clear on logout / tunnel delete.
//!
//! **Not wired:** interactive WebView2 / silent OAuth redeem / Azure `establish`.
//! Never log refresh tokens — [`Debug`] redacts.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::cache::{
    azure_token_cache_record, decode_azure_token_cache_json, encode_azure_token_cache_json,
    AZURE_TOKEN_CACHE_MAX_AGE,
};
use super::entra_token::{EntraTokenRequest, EntraTokenResult, RefreshToken};
use crate::TunnelError;

/// Non-secret identity fields that bind a cached refresh token (tenant / audience / client).
///
/// Changing any field invalidates the silent path (parity with C#
/// `AzureVpnTokenCache.ComputeIdentity`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AzureVpnCacheIdentity {
    /// Entra tenant id (or empty).
    pub tenant_id: String,
    /// Resource audience (or empty).
    pub audience: String,
    /// App client id (or empty).
    pub client_id: String,
}

impl AzureVpnCacheIdentity {
    /// Build from Entra request metadata (no secrets).
    pub fn from_request(request: &EntraTokenRequest) -> Self {
        Self {
            tenant_id: request.tenant_id.clone(),
            audience: request.audience.clone(),
            client_id: request.client_id.clone(),
        }
    }

    /// Construct from the three identity-defining settings fields.
    pub fn new(
        tenant_id: impl Into<String>,
        audience: impl Into<String>,
        client_id: impl Into<String>,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            audience: audience.into(),
            client_id: client_id.into(),
        }
    }
}

/// SHA-256 hex (uppercase) of `tenant\\naudience\\nclient` — C# `Convert.ToHexString`.
pub fn compute_azure_vpn_identity_hash(identity: &AzureVpnCacheIdentity) -> String {
    let material = format!(
        "{}\n{}\n{}",
        identity.tenant_id, identity.audience, identity.client_id
    );
    let digest = Sha256::digest(material.as_bytes());
    digest.iter().map(|b| format!("{b:02X}")).collect()
}

/// DI surface for Entra refresh-token persistence (C# `IAzureVpnTokenCache`).
///
/// Implementations must **never** write refresh tokens to logs or tracing.
pub trait AzureVpnRefreshTokenCache: Send + Sync {
    /// Load a refresh token, or `Ok(None)` on any cache miss (missing / identity /
    /// expired / undecryptable / malformed). Path confinement escapes → `Err`.
    fn try_load(
        &self,
        tunnel_config_id: &Uuid,
        identity: &AzureVpnCacheIdentity,
    ) -> Result<Option<RefreshToken>, TunnelError>;

    /// Persist a refresh token bound to `identity` (atomic DPAPI when using secrets store).
    fn persist(
        &self,
        tunnel_config_id: &Uuid,
        identity: &AzureVpnCacheIdentity,
        refresh_token: &RefreshToken,
    ) -> Result<(), TunnelError>;

    /// Clear the cache entry (logout / tunnel delete). Missing → `Ok(())`.
    ///
    /// Never reads or unprotects the blob.
    fn clear(&self, tunnel_config_id: &Uuid) -> Result<(), TunnelError>;
}

/// Shared trait object for DI.
pub type SharedAzureVpnRefreshTokenCache = Arc<dyn AzureVpnRefreshTokenCache>;

/// Persist refresh from an [`EntraTokenResult`] when present (no-op if `None` / blank).
pub fn persist_entra_refresh_token(
    cache: &dyn AzureVpnRefreshTokenCache,
    tunnel_config_id: &Uuid,
    identity: &AzureVpnCacheIdentity,
    result: &EntraTokenResult,
) -> Result<(), TunnelError> {
    match &result.refresh_token {
        Some(rt) if !rt.as_str().trim().is_empty() => {
            cache.persist(tunnel_config_id, identity, rt)
        }
        _ => Ok(()),
    }
}

/// Clear cached refresh token (logout / editor delete). Metadata-only tracing.
pub fn clear_entra_refresh_token_cache(
    cache: &dyn AzureVpnRefreshTokenCache,
    tunnel_config_id: &Uuid,
) -> Result<(), TunnelError> {
    tracing::debug!(
        tunnel_config_id = %tunnel_config_id,
        "clearing Azure VPN Entra refresh-token cache"
    );
    cache.clear(tunnel_config_id)
}

/// In-memory refresh-token cache for tests (parity with C# `FakeAzureVpnTokenCache`).
///
/// Ignores identity / max-age (concrete cache owns those). [`Debug`] never echoes tokens.
#[derive(Default)]
pub struct FakeAzureVpnRefreshTokenCache {
    entries: Mutex<HashMap<Uuid, String>>,
    last_written: Mutex<Option<String>>,
    load_calls: AtomicUsize,
    persist_calls: AtomicUsize,
    clear_calls: AtomicUsize,
    fail_persist: Mutex<bool>,
}

impl fmt::Debug for FakeAzureVpnRefreshTokenCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self.entries.lock().map(|g| g.len()).unwrap_or(0);
        f.debug_struct("FakeAzureVpnRefreshTokenCache")
            .field("entry_count", &count)
            .field("load_calls", &self.load_calls.load(Ordering::Relaxed))
            .field("persist_calls", &self.persist_calls.load(Ordering::Relaxed))
            .field("clear_calls", &self.clear_calls.load(Ordering::Relaxed))
            .finish()
    }
}

impl FakeAzureVpnRefreshTokenCache {
    /// Empty in-memory cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed a refresh token without going through [`persist`](AzureVpnRefreshTokenCache::persist).
    pub fn seed(&self, tunnel_config_id: Uuid, refresh_token: impl Into<String>) {
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        guard.insert(tunnel_config_id, refresh_token.into());
    }

    /// Force the next [`persist`](AzureVpnRefreshTokenCache::persist) to fail.
    pub fn set_fail_persist(&self, fail: bool) {
        *self.fail_persist.lock().unwrap_or_else(|e| e.into_inner()) = fail;
    }

    /// How many times [`try_load`](AzureVpnRefreshTokenCache::try_load) was invoked.
    pub fn load_calls(&self) -> usize {
        self.load_calls.load(Ordering::Relaxed)
    }

    /// How many times [`persist`](AzureVpnRefreshTokenCache::persist) was invoked.
    pub fn persist_calls(&self) -> usize {
        self.persist_calls.load(Ordering::Relaxed)
    }

    /// How many times [`clear`](AzureVpnRefreshTokenCache::clear) was invoked.
    pub fn clear_calls(&self) -> usize {
        self.clear_calls.load(Ordering::Relaxed)
    }

    /// Last refresh token passed to persist (for assertions — do not log).
    pub fn last_written(&self) -> Option<String> {
        self.last_written
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

impl AzureVpnRefreshTokenCache for FakeAzureVpnRefreshTokenCache {
    fn try_load(
        &self,
        tunnel_config_id: &Uuid,
        _identity: &AzureVpnCacheIdentity,
    ) -> Result<Option<RefreshToken>, TunnelError> {
        self.load_calls.fetch_add(1, Ordering::Relaxed);
        let guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        Ok(guard
            .get(tunnel_config_id)
            .map(|s| RefreshToken::new(s.clone())))
    }

    fn persist(
        &self,
        tunnel_config_id: &Uuid,
        _identity: &AzureVpnCacheIdentity,
        refresh_token: &RefreshToken,
    ) -> Result<(), TunnelError> {
        self.persist_calls.fetch_add(1, Ordering::Relaxed);
        if *self.fail_persist.lock().unwrap_or_else(|e| e.into_inner()) {
            return Err(TunnelError::Establish(
                "simulated Azure VPN token cache write failure".into(),
            ));
        }
        let plain = refresh_token.as_str().to_string();
        *self
            .last_written
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(plain.clone());
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        guard.insert(*tunnel_config_id, plain);
        Ok(())
    }

    fn clear(&self, tunnel_config_id: &Uuid) -> Result<(), TunnelError> {
        self.clear_calls.fetch_add(1, Ordering::Relaxed);
        let mut guard = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        guard.remove(tunnel_config_id);
        Ok(())
    }
}

/// Alias used in tests — same type as [`FakeAzureVpnRefreshTokenCache`].
pub type MemoryAzureVpnRefreshTokenCache = FakeAzureVpnRefreshTokenCache;

/// DPAPI-backed refresh-token cache using a confined secrets-win blob store.
///
/// Reads are fail-open (miss) for decrypt / schema / identity / max-age failures.
/// Path confinement escapes fail closed. Writes use atomic DPAPI + tunnel-id entropy.
#[cfg(feature = "secrets")]
pub struct DpapiAzureVpnRefreshTokenCache<S> {
    store: S,
    max_age: Duration,
}

#[cfg(feature = "secrets")]
impl<S: fmt::Debug> fmt::Debug for DpapiAzureVpnRefreshTokenCache<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DpapiAzureVpnRefreshTokenCache")
            .field("store", &self.store)
            .field("max_age_secs", &self.max_age.as_secs())
            .finish()
    }
}

#[cfg(feature = "secrets")]
impl<S> DpapiAzureVpnRefreshTokenCache<S> {
    /// Wrap a secrets-win blob store with the default 90-day max age.
    pub fn new(store: S) -> Self {
        Self {
            store,
            max_age: AZURE_TOKEN_CACHE_MAX_AGE,
        }
    }

    /// Injectable max age (unit tests).
    pub fn with_max_age(store: S, max_age: Duration) -> Self {
        Self { store, max_age }
    }

    /// Borrow the underlying blob store.
    pub fn store(&self) -> &S {
        &self.store
    }
}

#[cfg(feature = "secrets")]
impl<S: wormhole_secrets_win::AzureVpnTokenCacheStore + Send + Sync> AzureVpnRefreshTokenCache
    for DpapiAzureVpnRefreshTokenCache<S>
{
    fn try_load(
        &self,
        tunnel_config_id: &Uuid,
        identity: &AzureVpnCacheIdentity,
    ) -> Result<Option<RefreshToken>, TunnelError> {
        let plain = match self.store.read(tunnel_config_id) {
            Ok(v) => v,
            Err(wormhole_secrets_win::SecretsError::PathNotConfined { .. }) => {
                return Err(TunnelError::Establish(
                    "Azure VPN token cache path is not confined".into(),
                ));
            }
            // C# TryReadAsync: decrypt / I/O → miss (never throw for cache-state).
            Err(_) => return Ok(None),
        };
        let Some(plain) = plain else {
            return Ok(None);
        };

        let record = match decode_azure_token_cache_json(&plain) {
            Ok(r) => r,
            Err(_) => return Ok(None),
        };

        let expected = compute_azure_vpn_identity_hash(identity);
        if record.identity_hash != expected {
            return Ok(None);
        }

        if cache_entry_expired(&record.cached_at_utc, self.max_age) {
            return Ok(None);
        }

        Ok(Some(RefreshToken::new(record.refresh_token)))
    }

    fn persist(
        &self,
        tunnel_config_id: &Uuid,
        identity: &AzureVpnCacheIdentity,
        refresh_token: &RefreshToken,
    ) -> Result<(), TunnelError> {
        let trimmed = refresh_token.as_str().trim();
        if trimmed.is_empty() {
            return Err(TunnelError::Establish(
                "Azure VPN refresh token is empty".into(),
            ));
        }
        let record =
            azure_token_cache_record(compute_azure_vpn_identity_hash(identity), trimmed);
        let json = encode_azure_token_cache_json(&record)?;
        map_store_write(self.store.store(tunnel_config_id, &json))
    }

    fn clear(&self, tunnel_config_id: &Uuid) -> Result<(), TunnelError> {
        map_store_write(self.store.clear(tunnel_config_id))
    }
}

#[cfg(feature = "secrets")]
fn map_store_write(result: wormhole_secrets_win::Result<()>) -> Result<(), TunnelError> {
    match result {
        Ok(()) => Ok(()),
        Err(wormhole_secrets_win::SecretsError::PathNotConfined { .. }) => Err(
            TunnelError::Establish("Azure VPN token cache path is not confined".into()),
        ),
        Err(wormhole_secrets_win::SecretsError::UnsupportedPlatform) => Err(
            TunnelError::Establish("Azure VPN token cache DPAPI requires Windows".into()),
        ),
        Err(_) => Err(TunnelError::Establish(
            "Azure VPN token cache write failed".into(),
        )),
    }
}

fn cache_entry_expired(cached_at_utc: &str, max_age: Duration) -> bool {
    let Ok(cached) = chrono::DateTime::parse_from_rfc3339(cached_at_utc) else {
        // Unparseable stamp → treat as miss (expired).
        return true;
    };
    let cached_utc = cached.with_timezone(&chrono::Utc);
    let age = chrono::Utc::now().signed_duration_since(cached_utc);
    match age.to_std() {
        Ok(d) => d > max_age,
        // Negative age (clock skew / future stamp) → not expired.
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::auth_glue::cache::{AzureVpnTokenCacheRecord, AZURE_TOKEN_CACHE_SCHEMA};
    use crate::providers::auth_glue::entra_token::EntraTokenResult;

    fn sample_identity() -> AzureVpnCacheIdentity {
        AzureVpnCacheIdentity::new(
            "11111111-1111-1111-1111-111111111111",
            "https://vpn.azure.com/",
            "22222222-2222-2222-2222-222222222222",
        )
    }

    #[test]
    fn identity_hash_is_uppercase_sha256_of_newline_fields() {
        let id = sample_identity();
        let hash = compute_azure_vpn_identity_hash(&id);
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(hash, hash.to_ascii_uppercase());

        let material = format!("{}\n{}\n{}", id.tenant_id, id.audience, id.client_id);
        let expected: String = Sha256::digest(material.as_bytes())
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect();
        assert_eq!(hash, expected);

        let other = AzureVpnCacheIdentity::new(&id.tenant_id, &id.audience, "other-client");
        assert_ne!(hash, compute_azure_vpn_identity_hash(&other));
    }

    #[test]
    fn identity_from_entra_request() {
        let req = EntraTokenRequest::new(
            Uuid::nil(),
            "lab",
            "tenant-a",
            "aud-b",
            "client-c",
        );
        let id = AzureVpnCacheIdentity::from_request(&req);
        assert_eq!(id.tenant_id, "tenant-a");
        assert_eq!(id.audience, "aud-b");
        assert_eq!(id.client_id, "client-c");
    }

    #[test]
    fn fake_persist_load_clear_and_debug_redacts() {
        let cache = FakeAzureVpnRefreshTokenCache::new();
        let tid = Uuid::parse_str("f00dcafe-aaaa-4000-8000-0000cafebabe").unwrap();
        let identity = sample_identity();

        assert!(cache.try_load(&tid, &identity).unwrap().is_none());
        cache
            .persist(&tid, &identity, &RefreshToken::new("rt.SECRET_LEAK"))
            .unwrap();
        assert_eq!(cache.last_written().as_deref(), Some("rt.SECRET_LEAK"));
        let loaded = cache.try_load(&tid, &identity).unwrap().unwrap();
        assert_eq!(loaded.as_str(), "rt.SECRET_LEAK");

        let dbg = format!("{cache:?}");
        assert!(!dbg.contains("SECRET_LEAK"), "{dbg}");
        assert!(!format!("{loaded:?}").contains("SECRET_LEAK"));

        clear_entra_refresh_token_cache(&cache, &tid).unwrap();
        assert!(cache.try_load(&tid, &identity).unwrap().is_none());
        assert_eq!(cache.clear_calls(), 1);
    }

    #[test]
    fn persist_entra_refresh_skips_missing_and_writes_present() {
        let cache = FakeAzureVpnRefreshTokenCache::new();
        let tid = Uuid::nil();
        let identity = sample_identity();

        let access_only = EntraTokenResult::access_only("access");
        persist_entra_refresh_token(&cache, &tid, &identity, &access_only).unwrap();
        assert_eq!(cache.persist_calls(), 0);

        let with_rt = EntraTokenResult::new("access", Some("rt.new"));
        persist_entra_refresh_token(&cache, &tid, &identity, &with_rt).unwrap();
        assert_eq!(cache.persist_calls(), 1);
        assert_eq!(cache.last_written().as_deref(), Some("rt.new"));
    }

    #[test]
    fn fake_fail_persist_does_not_echo_token() {
        let cache = FakeAzureVpnRefreshTokenCache::new();
        cache.set_fail_persist(true);
        let err = cache
            .persist(
                &Uuid::nil(),
                &sample_identity(),
                &RefreshToken::new("rt.SHOULD_NOT_LEAK"),
            )
            .unwrap_err();
        let rendered = format!("{err}");
        assert!(!rendered.contains("SHOULD_NOT_LEAK"), "{rendered}");
    }

    #[test]
    fn expired_stamp_helper_treats_ancient_as_expired() {
        assert!(cache_entry_expired("2000-01-01T00:00:00Z", Duration::from_secs(1)));
        assert!(!cache_entry_expired(
            &chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            AZURE_TOKEN_CACHE_MAX_AGE,
        ));
        assert!(cache_entry_expired("not-a-date", Duration::from_secs(1)));
    }

    #[cfg(all(windows, feature = "secrets"))]
    #[test]
    fn dpapi_cache_roundtrip_identity_mismatch_and_clear() {
        use wormhole_secrets_win::{
            azure_vpn_token_cache_path_under, DpapiAzureVpnTokenCacheStore,
        };

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("azurevpn-cache");
        let blob = DpapiAzureVpnTokenCacheStore::under(&root);
        let cache = DpapiAzureVpnRefreshTokenCache::new(blob);
        let tid = Uuid::parse_str("f00dcafe-bbbb-4000-8000-0000cafebabe").unwrap();
        let identity = sample_identity();

        cache
            .persist(&tid, &identity, &RefreshToken::new("rt.roundtrip"))
            .unwrap();
        let path = azure_vpn_token_cache_path_under(&root, &tid).unwrap();
        assert!(path.exists());

        let loaded = cache.try_load(&tid, &identity).unwrap().unwrap();
        assert_eq!(loaded.as_str(), "rt.roundtrip");

        let other = AzureVpnCacheIdentity::new("other-tenant", &identity.audience, &identity.client_id);
        assert!(cache.try_load(&tid, &other).unwrap().is_none());

        clear_entra_refresh_token_cache(&cache, &tid).unwrap();
        assert!(cache.try_load(&tid, &identity).unwrap().is_none());
        assert!(!path.exists());
    }

    #[cfg(feature = "secrets")]
    #[test]
    fn dpapi_cache_hostile_root_fail_closed_before_io() {
        use wormhole_secrets_win::DpapiAzureVpnTokenCacheStore;

        let dir = tempfile::tempdir().unwrap();
        let hostile = dir.path().join("azurevpn-cache").join("..").join("outside");
        let cache = DpapiAzureVpnRefreshTokenCache::new(DpapiAzureVpnTokenCacheStore::under(
            &hostile,
        ));
        let tid = Uuid::nil();
        let identity = sample_identity();

        let err = cache
            .persist(&tid, &identity, &RefreshToken::new("rt.never"))
            .unwrap_err();
        assert!(
            format!("{err}").contains("not confined"),
            "{err}"
        );
        assert!(!format!("{err}").contains("rt.never"));
        assert!(!dir.path().join("outside").exists());

        let err = cache.try_load(&tid, &identity).unwrap_err();
        assert!(format!("{err}").contains("not confined"));
    }

    /// Cross-platform glue: Fake blob store + identity / max-age / clear miss semantics
    /// (Windows DPAPI round-trip covered separately).
    #[cfg(feature = "secrets")]
    #[test]
    fn fake_store_try_load_rejects_identity_mismatch_expiry_and_clear() {
        use wormhole_secrets_win::{AzureVpnTokenCacheStore, FakeAzureVpnTokenCacheStore};

        let blob = FakeAzureVpnTokenCacheStore::new();
        let cache = DpapiAzureVpnRefreshTokenCache::with_max_age(blob, Duration::from_secs(60));
        let tid = Uuid::parse_str("f00dcafe-cccc-4000-8000-0000cafebabe").unwrap();
        let identity = sample_identity();

        cache
            .persist(&tid, &identity, &RefreshToken::new("rt.FAKE_STORE_LEAK"))
            .unwrap();
        assert_eq!(
            cache.try_load(&tid, &identity).unwrap().unwrap().as_str(),
            "rt.FAKE_STORE_LEAK"
        );

        let other =
            AzureVpnCacheIdentity::new("other-tenant", &identity.audience, &identity.client_id);
        assert!(
            cache.try_load(&tid, &other).unwrap().is_none(),
            "identity mismatch must be a miss"
        );

        // Overwrite with an ancient stamp → expired miss (still no Debug echo).
        let ancient = AzureVpnTokenCacheRecord {
            schema_version: AZURE_TOKEN_CACHE_SCHEMA,
            identity_hash: compute_azure_vpn_identity_hash(&identity),
            refresh_token: "rt.EXPIRED_LEAK".into(),
            cached_at_utc: "2000-01-01T00:00:00Z".into(),
        };
        let json = encode_azure_token_cache_json(&ancient).unwrap();
        cache.store().store(&tid, &json).unwrap();
        assert!(cache.try_load(&tid, &identity).unwrap().is_none());
        assert!(!format!("{:?}", cache).contains("EXPIRED_LEAK"));
        assert!(!format!("{:?}", cache).contains("FAKE_STORE_LEAK"));

        clear_entra_refresh_token_cache(&cache, &tid).unwrap();
        assert!(cache.try_load(&tid, &identity).unwrap().is_none());
        assert_eq!(cache.store().clear_calls(), 1);
        // clear must not read/unprotect (Fake read_calls stay at try_load count only).
        let reads_after_clear = cache.store().read_calls();
        clear_entra_refresh_token_cache(&cache, &tid).unwrap();
        assert_eq!(cache.store().clear_calls(), 2);
        assert_eq!(
            cache.store().read_calls(),
            reads_after_clear,
            "second clear must not read the blob"
        );
    }

    #[cfg(feature = "secrets")]
    #[test]
    fn fake_store_malformed_and_empty_refresh_are_miss_without_echo() {
        use wormhole_secrets_win::{AzureVpnTokenCacheStore, FakeAzureVpnTokenCacheStore};

        let cache = DpapiAzureVpnRefreshTokenCache::new(FakeAzureVpnTokenCacheStore::new());
        let tid = Uuid::nil();
        let identity = sample_identity();

        cache
            .store()
            .store(&tid, br#"{"not":"a-tokencache"}"#)
            .unwrap();
        assert!(cache.try_load(&tid, &identity).unwrap().is_none());

        let whitespace = br#"{"schemaVersion":1,"identityHash":"AB","refreshToken":"  ","cachedAtUtc":"2026-07-31T12:00:00Z"}"#;
        cache.store().store(&tid, whitespace).unwrap();
        assert!(cache.try_load(&tid, &identity).unwrap().is_none());

        let err = cache
            .persist(&tid, &identity, &RefreshToken::new("   "))
            .unwrap_err();
        assert!(!format!("{err}").contains("rt."));
        assert!(format!("{err}").contains("empty"), "{err}");
    }
}
