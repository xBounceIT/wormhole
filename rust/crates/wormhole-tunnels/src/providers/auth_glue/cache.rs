//! DPAPI cache record shapes for WatchGuard / Stormshield / Azure VPN.
//!
//! Paths + entropy match `wormhole-secrets-win` / C# caches. Interactive refresh
//! and portal download are out of scope — decode + optional unprotect only.

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::TunnelError;

/// WatchGuard profile cache schema (`WatchguardProfileCache.CacheRecord`).
pub const WATCHGUARD_CACHE_SCHEMA: i32 = 1;
/// Stormshield Automatic-mode profile cache (`StormshieldCacheRecord.CurrentSchemaVersion`).
pub const STORM_SHIELD_CACHE_SCHEMA: i32 = 3;
/// Azure VPN Entra refresh-token cache (`AzureVpnTokenCache.CacheRecord`).
pub const AZURE_TOKEN_CACHE_SCHEMA: i32 = 1;

/// Local max age for a cached Entra refresh token (C# `AzureVpnTokenCache` — 90 days).
///
/// Entra enforces the real lifetime server-side; this is only a disk bound.
pub const AZURE_TOKEN_CACHE_MAX_AGE: Duration = Duration::from_secs(90 * 24 * 60 * 60);
/// WatchGuard `*.ovpncache` plaintext JSON (inside DPAPI).
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WatchguardOvpnCacheRecord {
    pub schema_version: i32,
    pub site_identity_hash: String,
    pub profile_ovpn: String,
    /// ISO-8601 / RFC3339 timestamp from System.Text.Json `DateTimeOffset`.
    pub cached_at_utc: String,
}

impl fmt::Debug for WatchguardOvpnCacheRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WatchguardOvpnCacheRecord")
            .field("schema_version", &self.schema_version)
            .field("site_identity_hash", &self.site_identity_hash)
            .field("profile_ovpn", &super::redact_nonempty(&self.profile_ovpn))
            .field("cached_at_utc", &self.cached_at_utc)
            .finish()
    }
}

/// Stormshield `*.ovpncache` plaintext JSON (PascalCase — no JsonPropertyName in C#).
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct StormshieldOvpnCacheRecord {
    #[serde(alias = "schemaVersion")]
    pub schema_version: i32,
    #[serde(alias = "siteIdentityHash")]
    pub site_identity_hash: String,
    #[serde(alias = "configHash")]
    pub config_hash: String,
    #[serde(alias = "profileOvpn")]
    pub profile_ovpn: String,
    #[serde(alias = "cachedAtUtc")]
    pub cached_at_utc: String,
}

impl fmt::Debug for StormshieldOvpnCacheRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StormshieldOvpnCacheRecord")
            .field("schema_version", &self.schema_version)
            .field("site_identity_hash", &self.site_identity_hash)
            .field("config_hash", &self.config_hash)
            .field("profile_ovpn", &super::redact_nonempty(&self.profile_ovpn))
            .field("cached_at_utc", &self.cached_at_utc)
            .finish()
    }
}

/// Azure VPN `*.tokencache` plaintext JSON (inside DPAPI).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AzureVpnTokenCacheRecord {
    pub schema_version: i32,
    pub identity_hash: String,
    pub refresh_token: String,
    pub cached_at_utc: String,
}

impl fmt::Debug for AzureVpnTokenCacheRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AzureVpnTokenCacheRecord")
            .field("schema_version", &self.schema_version)
            .field("identity_hash", &self.identity_hash)
            .field(
                "refresh_token",
                &super::redact_nonempty(&self.refresh_token),
            )
            .field("cached_at_utc", &self.cached_at_utc)
            .finish()
    }
}

fn cache_json_err() -> TunnelError {
    TunnelError::Establish("tunnel cache JSON is malformed or unsupported schema".into())
}

/// Decode WatchGuard cache JSON; rejects wrong schema / empty profile.
pub fn decode_watchguard_cache_json(json: &[u8]) -> Result<WatchguardOvpnCacheRecord, TunnelError> {
    let record: WatchguardOvpnCacheRecord =
        serde_json::from_slice(json).map_err(|_| cache_json_err())?;
    if record.schema_version != WATCHGUARD_CACHE_SCHEMA
        || record.profile_ovpn.trim().is_empty()
        || record.site_identity_hash.trim().is_empty()
    {
        return Err(cache_json_err());
    }
    Ok(record)
}

/// Decode Stormshield cache JSON; rejects wrong schema / empty profile.
pub fn decode_stormshield_cache_json(
    json: &[u8],
) -> Result<StormshieldOvpnCacheRecord, TunnelError> {
    let record: StormshieldOvpnCacheRecord =
        serde_json::from_slice(json).map_err(|_| cache_json_err())?;
    if record.schema_version != STORM_SHIELD_CACHE_SCHEMA
        || record.profile_ovpn.trim().is_empty()
        || record.site_identity_hash.trim().is_empty()
    {
        return Err(cache_json_err());
    }
    Ok(record)
}

/// Decode Azure token cache JSON; rejects wrong schema / empty refresh token.
pub fn decode_azure_token_cache_json(
    json: &[u8],
) -> Result<AzureVpnTokenCacheRecord, TunnelError> {
    let record: AzureVpnTokenCacheRecord =
        serde_json::from_slice(json).map_err(|_| cache_json_err())?;
    if record.schema_version != AZURE_TOKEN_CACHE_SCHEMA
        || record.refresh_token.trim().is_empty()
        || record.identity_hash.trim().is_empty()
    {
        return Err(cache_json_err());
    }
    Ok(record)
}

/// Encode Azure token cache JSON (camelCase; never log the bytes).
pub fn encode_azure_token_cache_json(
    record: &AzureVpnTokenCacheRecord,
) -> Result<Vec<u8>, TunnelError> {
    if record.schema_version != AZURE_TOKEN_CACHE_SCHEMA
        || record.refresh_token.trim().is_empty()
        || record.identity_hash.trim().is_empty()
    {
        return Err(cache_json_err());
    }
    serde_json::to_vec(record).map_err(|_| cache_json_err())
}

/// Build a schema-1 record with a UTC RFC3339 `cached_at_utc` stamp.
pub fn azure_token_cache_record(
    identity_hash: impl Into<String>,
    refresh_token: impl Into<String>,
) -> AzureVpnTokenCacheRecord {
    AzureVpnTokenCacheRecord {
        schema_version: AZURE_TOKEN_CACHE_SCHEMA,
        identity_hash: identity_hash.into(),
        refresh_token: refresh_token.into(),
        cached_at_utc: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    }
}

/// Read + DPAPI-unprotect a WatchGuard ovpn cache (tunnel-id entropy).
///
/// Missing file → `Ok(None)`. Decrypt / schema failures → `Err` (never echo secrets).
#[cfg(feature = "secrets")]
pub fn try_read_watchguard_cache(
    tunnel_config_id: &Uuid,
) -> Result<Option<WatchguardOvpnCacheRecord>, TunnelError> {
    match read_protected_plain(tunnel_config_id, CacheKind::Watchguard)? {
        None => Ok(None),
        Some(plain) => decode_watchguard_cache_json(&plain).map(Some),
    }
}

/// Read + DPAPI-unprotect a Stormshield ovpn cache (tunnel-id entropy).
#[cfg(feature = "secrets")]
pub fn try_read_stormshield_cache(
    tunnel_config_id: &Uuid,
) -> Result<Option<StormshieldOvpnCacheRecord>, TunnelError> {
    match read_protected_plain(tunnel_config_id, CacheKind::Stormshield)? {
        None => Ok(None),
        Some(plain) => decode_stormshield_cache_json(&plain).map(Some),
    }
}

/// Read + DPAPI-unprotect an Azure VPN token cache (tunnel-id entropy).
///
/// Missing file → `Ok(None)`. Decrypt / schema failures → `Err` (never echo secrets).
/// Path confinement runs via `wormhole_secrets_win::read_azure_vpn_token_cache`
/// (fail-closed on root escape). Prefer
/// [`super::entra_refresh_cache::AzureVpnRefreshTokenCache`] for identity /
/// max-age miss semantics (C# `TryReadAsync`).
#[cfg(feature = "secrets")]
pub fn try_read_azure_token_cache(
    tunnel_config_id: &Uuid,
) -> Result<Option<AzureVpnTokenCacheRecord>, TunnelError> {
    match wormhole_secrets_win::read_azure_vpn_token_cache(tunnel_config_id) {
        Ok(None) => Ok(None),
        Ok(Some(plain)) => decode_azure_token_cache_json(&plain).map(Some),
        Err(wormhole_secrets_win::SecretsError::PathNotConfined { .. }) => Err(
            TunnelError::Establish("Azure VPN token cache path is not confined".into()),
        ),
        Err(wormhole_secrets_win::SecretsError::DpapiUnprotect)
        | Err(wormhole_secrets_win::SecretsError::Io(_)) => Err(TunnelError::Establish(
            "tunnel cache DPAPI unprotect failed".into(),
        )),
        Err(wormhole_secrets_win::SecretsError::UnsupportedPlatform) => Err(
            TunnelError::Establish("tunnel cache DPAPI requires Windows".into()),
        ),
        Err(_) => Err(TunnelError::Establish("tunnel cache read failed".into())),
    }
}

/// Stubs when the `secrets` feature is off.
#[cfg(not(feature = "secrets"))]
pub fn try_read_watchguard_cache(
    _tunnel_config_id: &Uuid,
) -> Result<Option<WatchguardOvpnCacheRecord>, TunnelError> {
    Err(TunnelError::Establish(
        "WatchGuard cache DPAPI read requires wormhole-tunnels feature `secrets`".into(),
    ))
}

#[cfg(not(feature = "secrets"))]
pub fn try_read_stormshield_cache(
    _tunnel_config_id: &Uuid,
) -> Result<Option<StormshieldOvpnCacheRecord>, TunnelError> {
    Err(TunnelError::Establish(
        "Stormshield cache DPAPI read requires wormhole-tunnels feature `secrets`".into(),
    ))
}

#[cfg(not(feature = "secrets"))]
pub fn try_read_azure_token_cache(
    _tunnel_config_id: &Uuid,
) -> Result<Option<AzureVpnTokenCacheRecord>, TunnelError> {
    Err(TunnelError::Establish(
        "Azure VPN token cache DPAPI read requires wormhole-tunnels feature `secrets`".into(),
    ))
}

#[cfg(feature = "secrets")]
enum CacheKind {
    Watchguard,
    Stormshield,
}

#[cfg(feature = "secrets")]
fn read_protected_plain(
    tunnel_config_id: &Uuid,
    kind: CacheKind,
) -> Result<Option<Vec<u8>>, TunnelError> {
    use wormhole_secrets_win::{
        read_protected_file, stormshield_ovpn_cache_path, tunnel_id_entropy,
        watchguard_ovpn_cache_path, SecretsError,
    };

    let path = match kind {
        CacheKind::Watchguard => watchguard_ovpn_cache_path(tunnel_config_id),
        CacheKind::Stormshield => stormshield_ovpn_cache_path(tunnel_config_id),
    };
    let entropy = tunnel_id_entropy(tunnel_config_id);
    match read_protected_file(&path, Some(&entropy)) {
        Ok(v) => Ok(v),
        Err(SecretsError::DpapiUnprotect) | Err(SecretsError::Io(_)) => Err(
            TunnelError::Establish("tunnel cache DPAPI unprotect failed".into()),
        ),
        Err(SecretsError::UnsupportedPlatform) => Err(TunnelError::Establish(
            "tunnel cache DPAPI requires Windows".into(),
        )),
        Err(_) => Err(TunnelError::Establish("tunnel cache read failed".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watchguard_decode_accepts_camel_case() {
        let json = br#"{
            "schemaVersion":1,
            "siteIdentityHash":"ABC",
            "profileOvpn":"client\nremote vpn.example 443",
            "cachedAtUtc":"2026-07-31T12:00:00+00:00"
        }"#;
        let r = decode_watchguard_cache_json(json).unwrap();
        assert_eq!(r.schema_version, 1);
        assert!(r.profile_ovpn.contains("remote"));
    }

    #[test]
    fn watchguard_rejects_empty_profile() {
        let json = br#"{"schemaVersion":1,"siteIdentityHash":"ABC","profileOvpn":"  ","cachedAtUtc":"2026-07-31T12:00:00Z"}"#;
        assert!(decode_watchguard_cache_json(json).is_err());
    }

    #[test]
    fn watchguard_rejects_wrong_schema_and_empty_hash() {
        let wrong = br#"{"schemaVersion":2,"siteIdentityHash":"ABC","profileOvpn":"client","cachedAtUtc":"2026-07-31T12:00:00Z"}"#;
        assert!(decode_watchguard_cache_json(wrong).is_err());
        let empty_hash = br#"{"schemaVersion":1,"siteIdentityHash":"  ","profileOvpn":"client","cachedAtUtc":"2026-07-31T12:00:00Z"}"#;
        assert!(decode_watchguard_cache_json(empty_hash).is_err());
        let empty = br"{}";
        assert!(decode_watchguard_cache_json(empty).is_err());
    }

    #[test]
    fn stormshield_decode_accepts_pascal_case() {
        let json = br#"{
            "SchemaVersion":3,
            "SiteIdentityHash":"DEF",
            "ConfigHash":"hash1",
            "ProfileOvpn":"dev tun\nremote fw.example 1194",
            "CachedAtUtc":"2026-07-31T12:00:00+00:00"
        }"#;
        let r = decode_stormshield_cache_json(json).unwrap();
        assert_eq!(r.schema_version, 3);
        assert_eq!(r.config_hash, "hash1");
    }

    #[test]
    fn stormshield_rejects_old_schema() {
        let json = br#"{
            "SchemaVersion":2,
            "SiteIdentityHash":"DEF",
            "ConfigHash":"h",
            "ProfileOvpn":"client",
            "CachedAtUtc":"2026-07-31T12:00:00Z"
        }"#;
        assert!(decode_stormshield_cache_json(json).is_err());
    }

    #[test]
    fn azure_decode_accepts_camel_case() {
        let json = br#"{
            "schemaVersion":1,
            "identityHash":"ID",
            "refreshToken":"rt.secret",
            "cachedAtUtc":"2026-07-31T12:00:00+00:00"
        }"#;
        let r = decode_azure_token_cache_json(json).unwrap();
        assert_eq!(r.refresh_token, "rt.secret");
    }

    #[test]
    fn azure_encode_roundtrip_preserves_fields_without_debug_leak() {
        let record = AzureVpnTokenCacheRecord {
            schema_version: 1,
            identity_hash: "AB".into(),
            refresh_token: "rt.ENCODE_LEAK".into(),
            cached_at_utc: "2026-07-31T12:00:00Z".into(),
        };
        let bytes = encode_azure_token_cache_json(&record).unwrap();
        let back = decode_azure_token_cache_json(&bytes).unwrap();
        assert_eq!(back.refresh_token, "rt.ENCODE_LEAK");
        assert!(!format!("{record:?}").contains("ENCODE_LEAK"));
    }

    #[test]
    fn azure_rejects_empty_refresh_and_wrong_schema_without_echo() {
        let empty_rt = br#"{"schemaVersion":1,"identityHash":"ID","refreshToken":"  ","cachedAtUtc":"2026-07-31T12:00:00Z"}"#;
        let err = decode_azure_token_cache_json(empty_rt).unwrap_err();
        let rendered = format!("{err}");
        assert!(!rendered.contains("rt.secret"), "{rendered}");
        assert!(rendered.contains("cache") || rendered.contains("schema"), "{rendered}");

        let wrong = br#"{"schemaVersion":99,"identityHash":"ID","refreshToken":"RT_LEAK_MARKER_999","cachedAtUtc":"2026-07-31T12:00:00Z"}"#;
        let err = decode_azure_token_cache_json(wrong).unwrap_err();
        let wrong_rendered = format!("{err}");
        assert!(
            !wrong_rendered.contains("RT_LEAK_MARKER_999"),
            "{wrong_rendered}"
        );

        let empty_hash = br#"{"schemaVersion":1,"identityHash":"","refreshToken":"RT_LEAK_MARKER_999","cachedAtUtc":"2026-07-31T12:00:00Z"}"#;
        let err = decode_azure_token_cache_json(empty_hash).unwrap_err();
        assert!(!format!("{err}").contains("RT_LEAK_MARKER_999"));
    }

    #[test]
    fn azure_cache_debug_redacts_refresh_token() {
        let json = br#"{
            "schemaVersion":1,
            "identityHash":"ID",
            "refreshToken":"rt.secret.LEAK",
            "cachedAtUtc":"2026-07-31T12:00:00+00:00"
        }"#;
        let r = decode_azure_token_cache_json(json).unwrap();
        let dbg = format!("{r:?}");
        assert!(dbg.contains("[REDACTED]"), "{dbg}");
        assert!(!dbg.contains("rt.secret.LEAK"), "{dbg}");
    }

    #[test]
    fn watchguard_cache_debug_redacts_profile() {
        let json = br#"{"schemaVersion":1,"siteIdentityHash":"ABC","profileOvpn":"client\nPROFILE_SECRET\n","cachedAtUtc":"2026-07-31T12:00:00Z"}"#;
        let r = decode_watchguard_cache_json(json).unwrap();
        let dbg = format!("{r:?}");
        assert!(dbg.contains("[REDACTED]"), "{dbg}");
        assert!(!dbg.contains("PROFILE_SECRET"), "{dbg}");
    }

    #[cfg(all(windows, feature = "secrets"))]
    #[test]
    fn watchguard_dpapi_roundtrip_via_secrets_entropy() {
        use wormhole_secrets_win::{
            protect, tunnel_id_entropy, unprotect, watchguard_ovpn_cache_path,
        };

        let id = Uuid::parse_str("f00dcafe-aaaa-4000-8000-0000cafebabe").unwrap();
        let json = br#"{"schemaVersion":1,"siteIdentityHash":"ABC","profileOvpn":"client\n","cachedAtUtc":"2026-07-31T12:00:00Z"}"#;
        let entropy = tunnel_id_entropy(&id);
        let blob = protect(json, Some(&entropy)).expect("protect");
        let plain = unprotect(&blob, Some(&entropy)).expect("unprotect");
        assert_eq!(plain, json);
        let decoded = decode_watchguard_cache_json(&plain).unwrap();
        assert!(decoded.profile_ovpn.starts_with("client"));
        assert!(watchguard_ovpn_cache_path(&id)
            .to_string_lossy()
            .contains("watchguard-cache"));
    }

    #[cfg(all(windows, feature = "secrets"))]
    #[test]
    fn dpapi_wrong_entropy_fails_without_echoing_plaintext() {
        use wormhole_secrets_win::{protect, tunnel_id_entropy, unprotect, SecretsError};

        let id = Uuid::parse_str("f00dcafe-bbbb-4000-8000-0000cafebabe").unwrap();
        let json = br#"{"schemaVersion":1,"siteIdentityHash":"ABC","profileOvpn":"PROFILE_PLAINTEXT_LEAK","cachedAtUtc":"2026-07-31T12:00:00Z"}"#;
        let entropy = tunnel_id_entropy(&id);
        let blob = protect(json, Some(&entropy)).expect("protect");
        let wrong = tunnel_id_entropy(&Uuid::nil());
        let err = unprotect(&blob, Some(&wrong)).expect_err("wrong entropy must fail");
        assert!(matches!(err, SecretsError::DpapiUnprotect));
        let rendered = format!("{err}");
        assert!(!rendered.contains("PROFILE_PLAINTEXT_LEAK"), "{rendered}");
        // Auth-glue establish mapping uses a fixed string (no blob echo).
        let mapped = TunnelError::Establish("tunnel cache DPAPI unprotect failed".into());
        assert!(!format!("{mapped}").contains("PROFILE_PLAINTEXT_LEAK"));
    }

    #[test]
    fn azure_error_does_not_echo_refresh_token() {
        let err = decode_azure_token_cache_json(br#"{"schemaVersion":1}"#).unwrap_err();
        let rendered = format!("{err}");
        assert!(!rendered.contains("rt.secret"));
        assert!(rendered.contains("cache") || rendered.contains("schema"));
    }
}
