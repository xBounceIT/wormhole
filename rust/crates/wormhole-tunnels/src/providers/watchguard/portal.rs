//! WatchGuard **Automatic** portal glue: Firebox auth wired into the establish
//! decision (Lab / Fake-first).
//!
//! Mirrors the C# `WatchguardTunnelProvider` / `IWatchguardProfileCache` /
//! `WatchguardConfigClient` / `IOtpPromptService` / `ITlsTrustPromptService` /
//! `WindowsPhysicalNetworkPathService` flow for **username/password auth mode**
//! (`ResolveProfileAndCredentialsAsync` → `ResolveViaStoredProfileAsync` /
//! `ResolveUsernamePasswordAsync`):
//!
//! 1. Editor settings payload → [`WatchguardPortalSettings`]
//! 2. Physical-path preflight toward the portal host ([`PhysicalNetworkPathProbe`])
//! 3. Profile + credential resolution ([`resolve_watchguard_with_consent`]):
//!    - **cached profile** (`*.ovpncache` DPAPI) → the user's single 2FA factor goes
//!      **straight to the OpenVPN CRV1 layer** (`challenge_response`), with **no**
//!      portal HTTPS step — matching the native client's "download once, reuse" model
//!    - **cache miss** → TLS trust consent (when certificate validation failed) →
//!      portal download with the pre-auth password (OTP one-shot quirk via
//!      [`portal_openvpn_password`]: OTP becomes the OpenVPN `password`, push / no-2FA
//!      keep the account password) → cache persist → connect **proceeds** (WatchGuard
//!      C# does **not** abort after a fresh download — the OTP is the data-plane
//!      credential; no `challenge_response` is carried because 2FA was satisfied at
//!      the web `sslvpn_logon`)
//! 4. Transport preflight against the profile's `remote` hosts (shared
//!    [`extract_ovpn_remote_hosts`]) + OpenVPN sidecar JSON
//!    (`WatchguardAuthGlue` passthrough, transport-adapter pinning)
//! 5. [`TunnelProvider::establish`] with the shape-gated secret
//!    ([`establish_with_secret`])
//!
//! **No live HTTPS / SAML / OpenVPN.** The portal fetcher and profile cache are
//! injectable seams; [`FakeWatchguardPortalFetcher`] /
//! [`MemoryWatchguardProfileCache`] script them deterministically. DPAPI persistence is
//! real behind the `secrets` feature ([`DpapiWatchguardProfileCache`]) and shares
//! entropy/paths with the `try_read_watchguard_cache` glue. WatchGuard has **no
//! config-hash endpoint** (unlike Stormshield), so every cache hit is an optimistic
//! reuse bounded by the site-identity hash + [`WATCHGUARD_CACHE_MAX_AGE`]; an
//! establish failure on a cached profile drops the cache so the next connect
//! re-downloads. SAML (browser flow) and the AuthPoint push web long-poll stay
//! unported.
//!
//! Fail-closed matrix (every row is covered by a test):
//!
//! | Condition | Result |
//! |---|---|
//! | Settings payload empty `Server` | `Establish` — "…has an unreadable Watchguard payload (empty Server)…" |
//! | Missing / whitespace-only username or password | `Establish` — "…is missing a username or password…" |
//! | Portal destination unclassifiable (`Unknown` / probe error) | `Establish` — "cannot classify its portal destination…" |
//! | No active physical adapter | `Establish` — "cannot find an active physical network adapter…" |
//! | Cached / downloaded profile with no usable `remote` endpoint | `Establish` — "…contains no usable remote endpoint." (before any sidecar work); the cache entry is dropped best-effort so the next connect re-downloads instead of failing the same preflight |
//! | Transport destination unclassifiable (`Unknown` / probe error) | `Establish` — "cannot classify its transport destination…" |
//! | Empty/whitespace downloaded profile | `Establish` **before** any OTP record / cache write |
//! | Cache read / DPAPI / decode failure | defensive cache miss (never propagated) |
//! | Cache schema ≠ 1 / empty profile / empty or mismatched identity / stale / future stamp / body not an OpenVPN profile | treated as miss |
//! | TLS validation failed + trust off | `TlsPreflight` **before** any OTP spend |
//! | Trust prompt rejected / cancelled | `TunnelError::Cancelled` (fail-closed) |
//! | Pinned CA (no `TrustServerCertificate`) | fails closed, **no** trust prompt |
//! | OTP prompt cancelled / empty | `TunnelError::Cancelled` |
//! | OTP code reused inside the 90 s window | `Establish` — "That one-time code was just used…" (strict `<`; data-plane codes are never recorded) |
//! | Cached profile establish failure | cache entry dropped (optimistic hit; next connect re-downloads) |
//! | Config / provider kind mismatch | `WrongKind` / `ConfigNotFound` (via [`load_watchguard_record`]) |
//!
//! **Secrets discipline:** never log settings passwords, OTP codes, or cached profile
//! text; `Debug` redacts every secret-bearing field (see [`redact_nonempty`]).
//!
//! **Deviations from C# (with justification):**
//! - 2FA prompting is gated by [`WatchguardPortalSettings::use_otp`]. C# always prompts
//!   for a second factor on the stored-profile path; without live HTTP the Rust glue
//!   cannot detect a gateway challenge, so it mirrors Stormshield's `UseOtp` flag.
//! - `watchguard_cache_record_is_current` requires the body to look like an OpenVPN
//!   profile ([`looks_like_openvpn_profile`]); C# checks schema/identity/age only. Stricter
//!   (a garbage body that happens to carry the identity hash is never reused).
//! - Any cached-profile establish failure drops the cache; C# preserves it for
//!   2FA/transport failures. The Rust provider cannot classify sidecar errors yet, and
//!   dropping forces a safe re-download (documented optimistic-cache behavior).
//! - The shared [`extract_ovpn_remote_hosts`] parser (Stormshield `portal.rs`) is reused
//!   verbatim: the WatchGuard profile is a synthesized self-contained OpenVPN profile
//!   (`client.wgssl` → `WatchguardWgsslImporter` + `WatchguardProfileBuilder`), so the
//!   `remote` directive grammar is identical; only the download source differs.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, SecondsFormat, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[cfg(feature = "secrets")]
use crate::providers::auth_glue::try_read_watchguard_cache;
use crate::providers::auth_glue::{
    redact_nonempty, request_tls_trust, OtpCode, OtpPrompt, OvpnAuthGlue, ResolvedOvpnMaterials,
    TlsTrustPrompt, WatchguardAuthGlue, WatchguardOvpnCacheRecord, ACCEPT_BUTTON_LABEL,
    WATCHGUARD_CACHE_SCHEMA,
};
use crate::providers::watchguard::establish::{
    establish_with_secret, load_watchguard_record, require_watchguard_provider,
};
use crate::providers::watchguard::firebox_auth::{
    portal_openvpn_password, request_firebox_second_factor, FireboxCredentials,
    FireboxSecondFactor,
};
use crate::providers::wireguard::TunnelConfigLookup;
use crate::{
    extract_ovpn_remote_hosts, looks_like_openvpn_profile, require_physical_path,
    PhysicalNetworkPathProbe, TunnelError, TunnelInstance, TunnelProvider,
};

/// Cached profile max age — C# `WatchguardProfileCache` (30 days).
pub const WATCHGUARD_CACHE_MAX_AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// OTP reuse window — Stormshield C# `StormshieldOtpReuseGuard.DefaultReuseWindow`
/// parity (WatchGuard has no dedicated guard in C#; the single-spend discipline is
/// shared with Stormshield's Automatic mode).
pub const WATCHGUARD_OTP_REUSE_WINDOW: Duration = Duration::from_secs(90);

/// WatchGuard username/password portal settings (C# `WatchguardSettings` shape, minus
/// SAML / domain / imported-material fields).
#[derive(Clone, PartialEq, Eq)]
pub struct WatchguardPortalSettings {
    /// Portal host (C# `Server`); never empty.
    pub server: String,
    /// Portal HTTPS port (C# `Port`, default 443).
    pub port: u16,
    pub username: String,
    pub password: String,
    /// When true, the user is prompted for a single-use AuthPoint second factor: on a
    /// cache hit it answers the OpenVPN CRV1 challenge; on a cache miss it is spent at
    /// the web `sslvpn_logon` and becomes the OpenVPN password (Firebox one-shot quirk).
    pub use_otp: bool,
    /// Persisted "trust this server certificate" override (C# `TrustServerCertificate`).
    pub trust_server_certificate: bool,
    /// Pinned CA PEM — trust prompts are never offered when set.
    pub ca_pem: Option<String>,
    /// Maximum cached-profile age before it counts as a miss (C# `TimeSpan.FromDays(30)`).
    pub max_cache_age: Duration,
}

impl WatchguardPortalSettings {
    pub fn new(
        server: impl Into<String>,
        port: u16,
        username: impl Into<String>,
        password: impl Into<String>,
        use_otp: bool,
    ) -> Self {
        Self {
            server: server.into(),
            port,
            username: username.into(),
            password: password.into(),
            use_otp,
            trust_server_certificate: false,
            ca_pem: None,
            max_cache_age: WATCHGUARD_CACHE_MAX_AGE,
        }
    }

    pub fn with_trust_server_certificate(mut self, value: bool) -> Self {
        self.trust_server_certificate = value;
        self
    }

    pub fn with_pinned_ca(mut self, ca_pem: impl Into<String>) -> Self {
        self.ca_pem = Some(ca_pem.into());
        self
    }

    pub fn with_max_cache_age(mut self, age: Duration) -> Self {
        self.max_cache_age = age;
        self
    }

    /// Stable site identity for the profile cache (C# `WatchguardProfileCache.ComputeSiteIdentity`).
    ///
    /// **Deliberately excludes the password** — rotating credentials must not
    /// invalidate the cached profile. TLS-trust settings are included because they
    /// change the security posture of the cached profile. Raw fields (no trimming),
    /// matching C# `string.Join('\n', …)` + `Convert.ToHexString(SHA256)`.
    pub fn site_identity_hash(&self) -> String {
        let joined = format!(
            "{}\n{}\n{}\n{}\n{}",
            self.server,
            self.port,
            self.username,
            if self.trust_server_certificate { "1" } else { "0" },
            self.ca_pem.as_deref().unwrap_or(""),
        );
        sha256_hex_upper(joined.as_bytes())
    }
}

impl Default for WatchguardPortalSettings {
    fn default() -> Self {
        Self {
            server: String::new(),
            port: 443,
            username: String::new(),
            password: String::new(),
            use_otp: false,
            trust_server_certificate: false,
            ca_pem: None,
            max_cache_age: WATCHGUARD_CACHE_MAX_AGE,
        }
    }
}

impl fmt::Debug for WatchguardPortalSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WatchguardPortalSettings")
            .field("server", &self.server)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &redact_nonempty(&self.password))
            .field("use_otp", &self.use_otp)
            .field("trust_server_certificate", &self.trust_server_certificate)
            .field("ca_pem_len", &self.ca_pem.as_ref().map(|s| s.len()))
            .field("max_cache_age_secs", &self.max_cache_age.as_secs())
            .finish()
    }
}

/// Non-secret portal request metadata (host + port only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchguardPortalRequest {
    pub server: String,
    pub port: u16,
}

impl WatchguardPortalRequest {
    pub fn new(server: impl Into<String>, port: u16) -> Self {
        Self {
            server: server.into(),
            port,
        }
    }
}

/// Last TLS validation failure observed by a [`WatchguardPortalFetcher`].
///
/// `Debug` prints a short thumbprint prefix only (never the full value).
#[derive(Clone, PartialEq, Eq)]
pub struct WatchguardTlsFailure {
    pub subject: String,
    pub issuer: String,
    pub thumbprint: String,
}

impl WatchguardTlsFailure {
    pub fn new(
        subject: impl Into<String>,
        issuer: impl Into<String>,
        thumbprint: impl Into<String>,
    ) -> Self {
        Self {
            subject: subject.into(),
            issuer: issuer.into(),
            thumbprint: thumbprint.into(),
        }
    }
}

impl fmt::Debug for WatchguardTlsFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WatchguardTlsFailure")
            .field("subject", &self.subject)
            .field("issuer", &self.issuer)
            .field("thumbprint_prefix", &thumbprint_prefix(&self.thumbprint))
            .finish()
    }
}

/// One recorded portal download attempt (credentials never logged).
#[derive(Clone, PartialEq, Eq)]
pub struct WatchguardPortalFetchCall {
    pub request: WatchguardPortalRequest,
    pub username: String,
    pub password: String,
}

impl WatchguardPortalFetchCall {
    pub fn new(
        request: WatchguardPortalRequest,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            request,
            username: username.into(),
            password: password.into(),
        }
    }
}

impl fmt::Debug for WatchguardPortalFetchCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WatchguardPortalFetchCall")
            .field("request", &self.request)
            .field("username", &self.username)
            .field("password", &redact_nonempty(&self.password))
            .finish()
    }
}

/// Portal HTTP surface (C# `WatchguardConfigClient.DownloadConfigAsync` +
/// `WatchguardWgsslImporter` + `WatchguardProfileBuilder`), injectable for tests.
///
/// `download_profile` returns the **synthesized self-contained `.ovpn`** (C#
/// `DownloadAndBuildProfileAsync`); `password` is already the pre-auth result (OTP
/// one-shot / account password). Implementations must never log credentials.
#[async_trait]
pub trait WatchguardPortalFetcher: Send + Sync {
    /// `GET /?action=sslvpn_download&filename=client.wgssl` + import + profile synthesis.
    async fn download_profile(
        &self,
        request: &WatchguardPortalRequest,
        username: &str,
        password: &str,
    ) -> Result<String, TunnelError>;

    /// Last TLS certificate-validation failure, if any.
    fn last_tls_failure(&self) -> Option<WatchguardTlsFailure>;
}

pub type SharedWatchguardPortalFetcher = Arc<dyn WatchguardPortalFetcher>;

enum MemoryPortalProfileScript {
    Ok(String),
    Error(String),
}

/// Scripted in-memory portal — the only [`WatchguardPortalFetcher`] today.
///
/// Profile scripts are consumed FIFO; an exhausted script fails closed.
pub struct MemoryWatchguardPortalFetcher {
    profile_scripts: Mutex<VecDeque<MemoryPortalProfileScript>>,
    calls: Mutex<Vec<WatchguardPortalFetchCall>>,
    download_calls: AtomicUsize,
    tls_failure: Mutex<Option<WatchguardTlsFailure>>,
}

impl MemoryWatchguardPortalFetcher {
    pub fn new() -> Self {
        Self {
            profile_scripts: Mutex::new(VecDeque::new()),
            calls: Mutex::new(Vec::new()),
            download_calls: AtomicUsize::new(0),
            tls_failure: Mutex::new(None),
        }
    }

    pub fn push_profile(&self, profile: impl Into<String>) {
        self.profile_scripts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push_back(MemoryPortalProfileScript::Ok(profile.into()));
    }

    pub fn push_profile_error(&self, message: impl Into<String>) {
        self.profile_scripts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push_back(MemoryPortalProfileScript::Error(message.into()));
    }

    pub fn with_profile(self, profile: impl Into<String>) -> Self {
        self.push_profile(profile);
        self
    }

    pub fn with_profile_error(self, message: impl Into<String>) -> Self {
        self.push_profile_error(message);
        self
    }

    pub fn set_tls_failure(&self, failure: WatchguardTlsFailure) {
        *self
            .tls_failure
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(failure);
    }

    pub fn with_tls_failure(self, failure: WatchguardTlsFailure) -> Self {
        self.set_tls_failure(failure);
        self
    }

    pub fn clear_tls_failure(&self) {
        *self.tls_failure.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }

    pub fn download_calls(&self) -> usize {
        self.download_calls.load(Ordering::SeqCst)
    }

    /// Download attempts with credentials (test assertions only).
    pub fn download_requests(&self) -> Vec<WatchguardPortalFetchCall> {
        self.calls.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

impl Default for MemoryWatchguardPortalFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for MemoryWatchguardPortalFetcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryWatchguardPortalFetcher")
            .field(
                "queued_profiles",
                &self
                    .profile_scripts
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .len(),
            )
            .field("download_calls", &self.download_calls.load(Ordering::SeqCst))
            .field(
                "has_tls_failure",
                &self
                    .tls_failure
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .is_some(),
            )
            .finish()
    }
}

#[async_trait]
impl WatchguardPortalFetcher for MemoryWatchguardPortalFetcher {
    async fn download_profile(
        &self,
        request: &WatchguardPortalRequest,
        username: &str,
        password: &str,
    ) -> Result<String, TunnelError> {
        self.download_calls.fetch_add(1, Ordering::SeqCst);
        self.calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(WatchguardPortalFetchCall::new(
                request.clone(),
                username,
                password,
            ));
        let script = self
            .profile_scripts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .pop_front();
        match script {
            Some(MemoryPortalProfileScript::Ok(profile)) => Ok(profile),
            Some(MemoryPortalProfileScript::Error(message)) => Err(TunnelError::Establish(message)),
            None => Err(TunnelError::Establish(
                "WatchGuard portal profile script exhausted (fake)".into(),
            )),
        }
    }

    fn last_tls_failure(&self) -> Option<WatchguardTlsFailure> {
        self.tls_failure
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

/// Alias used in tests — same type as [`MemoryWatchguardPortalFetcher`].
pub type FakeWatchguardPortalFetcher = MemoryWatchguardPortalFetcher;

/// Profile cache seam (C# `IWatchguardProfileCache` / `WatchguardProfileCache`).
///
/// `read` returns `Ok(None)` for a missing file; any DPAPI / decode failure is an
/// `Err` that callers treat as a **defensive miss** (never propagated).
pub trait WatchguardProfileCache: Send + Sync {
    fn read(
        &self,
        tunnel_config_id: &Uuid,
    ) -> Result<Option<WatchguardOvpnCacheRecord>, TunnelError>;
    fn write(
        &self,
        tunnel_config_id: &Uuid,
        record: &WatchguardOvpnCacheRecord,
    ) -> Result<(), TunnelError>;
    fn delete(&self, tunnel_config_id: &Uuid) -> Result<(), TunnelError>;
}

/// In-memory profile cache for tests.
#[derive(Default)]
pub struct MemoryWatchguardProfileCache {
    entries: Mutex<HashMap<Uuid, WatchguardOvpnCacheRecord>>,
    read_failure: Mutex<Option<String>>,
    read_calls: AtomicUsize,
    write_calls: AtomicUsize,
    delete_calls: AtomicUsize,
}

impl MemoryWatchguardProfileCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn seed(&self, tunnel_config_id: Uuid, record: WatchguardOvpnCacheRecord) {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(tunnel_config_id, record);
    }

    /// Simulate a DPAPI / decode failure on the next reads.
    pub fn set_read_failure(&self, message: impl Into<String>) {
        *self
            .read_failure
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(message.into());
    }

    pub fn clear_read_failure(&self) {
        *self.read_failure.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }

    pub fn entry(&self, tunnel_config_id: &Uuid) -> Option<WatchguardOvpnCacheRecord> {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(tunnel_config_id)
            .cloned()
    }

    pub fn read_calls(&self) -> usize {
        self.read_calls.load(Ordering::SeqCst)
    }

    pub fn write_calls(&self) -> usize {
        self.write_calls.load(Ordering::SeqCst)
    }

    pub fn delete_calls(&self) -> usize {
        self.delete_calls.load(Ordering::SeqCst)
    }
}

impl fmt::Debug for MemoryWatchguardProfileCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryWatchguardProfileCache")
            .field(
                "entry_count",
                &self.entries.lock().unwrap_or_else(|p| p.into_inner()).len(),
            )
            .field("read_calls", &self.read_calls.load(Ordering::SeqCst))
            .field("write_calls", &self.write_calls.load(Ordering::SeqCst))
            .field("delete_calls", &self.delete_calls.load(Ordering::SeqCst))
            .finish()
    }
}

impl WatchguardProfileCache for MemoryWatchguardProfileCache {
    fn read(
        &self,
        tunnel_config_id: &Uuid,
    ) -> Result<Option<WatchguardOvpnCacheRecord>, TunnelError> {
        self.read_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(message) = self
            .read_failure
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
        {
            return Err(TunnelError::Establish(message));
        }
        Ok(self.entry(tunnel_config_id))
    }

    fn write(
        &self,
        tunnel_config_id: &Uuid,
        record: &WatchguardOvpnCacheRecord,
    ) -> Result<(), TunnelError> {
        self.write_calls.fetch_add(1, Ordering::SeqCst);
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(*tunnel_config_id, record.clone());
        Ok(())
    }

    fn delete(&self, tunnel_config_id: &Uuid) -> Result<(), TunnelError> {
        self.delete_calls.fetch_add(1, Ordering::SeqCst);
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(tunnel_config_id);
        Ok(())
    }
}

/// Real DPAPI-backed profile cache (C# `WatchguardProfileCache` parity).
///
/// File layout / entropy match `wormhole-secrets-win`
/// (`watchguard_ovpn_cache_path` + `tunnel_id_entropy`) and the
/// `try_read_watchguard_cache` glue. Writes are atomic (temp + rename).
#[cfg(feature = "secrets")]
#[derive(Debug, Default, Clone, Copy)]
pub struct DpapiWatchguardProfileCache;

#[cfg(feature = "secrets")]
impl DpapiWatchguardProfileCache {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(feature = "secrets")]
impl WatchguardProfileCache for DpapiWatchguardProfileCache {
    fn read(
        &self,
        tunnel_config_id: &Uuid,
    ) -> Result<Option<WatchguardOvpnCacheRecord>, TunnelError> {
        try_read_watchguard_cache(tunnel_config_id)
    }

    fn write(
        &self,
        tunnel_config_id: &Uuid,
        record: &WatchguardOvpnCacheRecord,
    ) -> Result<(), TunnelError> {
        let path = wormhole_secrets_win::watchguard_ovpn_cache_path(tunnel_config_id);
        let entropy = wormhole_secrets_win::tunnel_id_entropy(tunnel_config_id);
        let plaintext = encode_watchguard_cache_record(record)?;
        wormhole_secrets_win::write_protected_file_atomic(&path, &plaintext, Some(&entropy))
            .map_err(map_secrets_error)
    }

    fn delete(&self, tunnel_config_id: &Uuid) -> Result<(), TunnelError> {
        let path = wormhole_secrets_win::watchguard_ovpn_cache_path(tunnel_config_id);
        wormhole_secrets_win::delete_protected_file_if_exists(&path).map_err(map_secrets_error)
    }
}

#[cfg(feature = "secrets")]
fn map_secrets_error(error: wormhole_secrets_win::SecretsError) -> TunnelError {
    use wormhole_secrets_win::SecretsError;
    match error {
        SecretsError::UnsupportedPlatform => TunnelError::Establish(
            "WatchGuard profile cache requires Windows".into(),
        ),
        SecretsError::DpapiUnprotect | SecretsError::Io(_) => TunnelError::Establish(
            "WatchGuard profile cache DPAPI failed".into(),
        ),
        SecretsError::PathNotConfined { .. } => TunnelError::Establish(
            "WatchGuard profile cache path is not confined".into(),
        ),
        SecretsError::PasswordTooLarge { .. } => TunnelError::Establish(
            "WatchGuard profile cache payload too large".into(),
        ),
        _ => TunnelError::Establish("WatchGuard profile cache operation failed".into()),
    }
}

/// Encode a schema-1 cache record as camelCase JSON (C# `System.Text.Json` shape).
pub fn encode_watchguard_cache_record(
    record: &WatchguardOvpnCacheRecord,
) -> Result<Vec<u8>, TunnelError> {
    if record.schema_version != WATCHGUARD_CACHE_SCHEMA
        || record.profile_ovpn.trim().is_empty()
        || record.site_identity_hash.trim().is_empty()
    {
        return Err(TunnelError::Establish(
            "tunnel cache JSON is malformed or unsupported schema".into(),
        ));
    }
    let value = serde_json::json!({
        "schemaVersion": record.schema_version,
        "siteIdentityHash": record.site_identity_hash.as_str(),
        "profileOvpn": record.profile_ovpn.as_str(),
        "cachedAtUtc": record.cached_at_utc.as_str(),
    });
    serde_json::to_vec(&value)
        .map_err(|_| TunnelError::Establish("tunnel cache JSON encoding failed".into()))
}

/// Whether a cached record may be reused for the given site identity / max age.
///
/// Fail-closed: wrong schema, empty profile, empty/mismatched identity, a body that
/// does not look like an OpenVPN profile, unparseable or future timestamps all count
/// as a miss. WatchGuard has no config-hash endpoint, so freshness is bounded purely
/// by identity + age (C# `WatchguardProfileCache.TryReadProfileAsync` parity, plus the
/// [`looks_like_openvpn_profile`] marker — stricter than C#, see the module header).
pub fn watchguard_cache_record_is_current(
    record: &WatchguardOvpnCacheRecord,
    site_identity_hash: &str,
    max_age: Duration,
) -> bool {
    if record.schema_version != WATCHGUARD_CACHE_SCHEMA {
        return false;
    }
    if record.profile_ovpn.trim().is_empty() {
        return false;
    }
    let identity = record.site_identity_hash.trim();
    if identity.is_empty() || identity != site_identity_hash {
        return false;
    }
    if !looks_like_openvpn_profile(&record.profile_ovpn) {
        return false;
    }
    let Ok(timestamp) = DateTime::parse_from_rfc3339(&record.cached_at_utc) else {
        return false;
    };
    match Utc::now()
        .signed_duration_since(timestamp.with_timezone(&Utc))
        .to_std()
    {
        Ok(age) => age <= max_age,
        Err(_) => false, // future stamp → miss
    }
}

/// Single-spend OTP guard (Stormshield C# `StormshieldOtpReuseGuard` parity).
///
/// Records a code **spent on the portal** (confirmed download) per tunnel and rejects
/// reuse inside [`WATCHGUARD_OTP_REUSE_WINDOW`]. Hash comparison is constant-time;
/// timestamps come from an injectable clock so tests can advance time.
pub struct WatchguardOtpReuseGuard {
    window: Duration,
    clock: Box<dyn Fn() -> DateTime<Utc> + Send + Sync>,
    #[allow(clippy::type_complexity)] // (sha256, spent-at) per tunnel, mirroring Stormshield.
    spent: Mutex<HashMap<Uuid, (Vec<u8>, DateTime<Utc>)>>,
}

impl WatchguardOtpReuseGuard {
    pub fn new() -> Self {
        Self {
            window: WATCHGUARD_OTP_REUSE_WINDOW,
            clock: Box::new(Utc::now),
            spent: Mutex::new(HashMap::new()),
        }
    }

    pub fn with_window(mut self, window: Duration) -> Self {
        self.window = window;
        self
    }

    pub fn with_clock<F>(mut self, clock: F) -> Self
    where
        F: Fn() -> DateTime<Utc> + Send + Sync + 'static,
    {
        self.clock = Box::new(clock);
        self
    }

    /// Remember a **confirmed portal spend** so the same code cannot be reused.
    ///
    /// Whitespace-only codes are ignored (they never leave the OTP prompt).
    pub fn record(&self, tunnel_id: Uuid, code: &OtpCode) {
        let trimmed = code.as_str().trim();
        if trimmed.is_empty() {
            return;
        }
        self.spent
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(tunnel_id, (sha256_bytes(trimmed.as_bytes()), (self.clock)()));
    }

    /// Reject a code that was already spent inside the reuse window (strict `<`).
    ///
    /// C# parity: the Stormshield guard rejects when `now - spent_at < window`; a
    /// **negative** elapsed (the clock jumped backward) is `< window` in C#, so the
    /// spent code stays rejected — fail closed, never re-submittable after a clock
    /// rollback.
    pub fn check(&self, tunnel_id: Uuid, code: &OtpCode) -> Result<(), TunnelError> {
        let trimmed = code.as_str().trim();
        if trimmed.is_empty() {
            return Ok(());
        }
        let candidate = sha256_bytes(trimmed.as_bytes());
        let spent = self.spent.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((previous, spent_at)) = spent.get(&tunnel_id) {
            let now = (self.clock)();
            let within_window = match now.signed_duration_since(*spent_at).to_std() {
                Ok(age) => age < self.window,
                // `now` before `spent_at` (clock rollback): C# `now - spent_at` is
                // negative, which is `< window` → the code is treated as spent.
                Err(_) => true,
            };
            if hashes_equal(previous, &candidate) && within_window {
                return Err(TunnelError::Establish(
                    "That one-time code was just used. Wait until your authenticator shows a NEW code, then reconnect.".into(),
                ));
            }
        }
        Ok(())
    }

    /// Forget every tunnel (config edits / test isolation).
    pub fn clear(&self) {
        self.spent.lock().unwrap_or_else(|p| p.into_inner()).clear();
    }
}

impl Default for WatchguardOtpReuseGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for WatchguardOtpReuseGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WatchguardOtpReuseGuard")
            .field("window_secs", &self.window.as_secs())
            .field(
                "tracked_tunnels",
                &self.spent.lock().unwrap_or_else(|p| p.into_inner()).len(),
            )
            .finish()
    }
}

/// Prompt for a WatchGuard second factor, rejecting codes spent inside the reuse window.
///
/// Push (`"p"`) is never checked against the guard — it carries no one-shot credential.
pub async fn prompt_guarded_watchguard_otp(
    prompt: &dyn OtpPrompt,
    guard: &WatchguardOtpReuseGuard,
    tunnel_id: Uuid,
    config_name: impl AsRef<str>,
) -> Result<FireboxSecondFactor, TunnelError> {
    let factor = request_firebox_second_factor(prompt, config_name, None).await?;
    if let FireboxSecondFactor::OneTimeCode(code) = &factor {
        guard.check(tunnel_id, code)?;
    }
    Ok(factor)
}

/// Fail-closed settings validation (C# `WatchguardTunnelProvider` parity).
pub fn validate_watchguard_portal_settings(
    settings: &WatchguardPortalSettings,
    config_name: &str,
) -> Result<(), TunnelError> {
    if settings.server.trim().is_empty() {
        return Err(TunnelError::Establish(format!(
            "Tunnel config '{config_name}' has an unreadable Watchguard payload (empty Server). Open the tunnel editor to re-enter settings."
        )));
    }
    if settings.username.trim().is_empty() || settings.password.trim().is_empty() {
        return Err(TunnelError::Establish(format!(
            "Tunnel config '{config_name}' is missing a username or password for Watchguard username/password authentication."
        )));
    }
    Ok(())
}

/// Reject empty/whitespace portal profiles **before** any OTP record or cache write.
fn require_nonempty_watchguard_profile(
    profile_ovpn: &str,
    config_name: &str,
) -> Result<(), TunnelError> {
    if profile_ovpn.trim().is_empty() {
        return Err(TunnelError::Establish(format!(
            "WatchGuard portal returned an empty OpenVPN profile for '{config_name}'"
        )));
    }
    Ok(())
}

/// Resolved WatchGuard materials ready for the data plane.
#[derive(Clone, PartialEq, Eq)]
pub struct WatchguardOutcome {
    pub profile_ovpn: String,
    pub username: String,
    /// OpenVPN `auth-user-pass` password — the account password on a cache hit (OTP
    /// rides in `challenge_response`), or the pre-auth result (OTP one-shot / account
    /// password) after a fresh portal download.
    pub openvpn_password: String,
    /// CRV1 `challenge_response` — only on the cached-profile path (2FA satisfied at
    /// the portal has none).
    pub challenge_response: Option<String>,
    /// True when the profile came from the per-tunnel cache (an optimistic reuse).
    pub from_cache: bool,
}

impl fmt::Debug for WatchguardOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WatchguardOutcome")
            .field("profile_len", &self.profile_ovpn.len())
            .field("username", &self.username)
            .field("openvpn_password", &redact_nonempty(&self.openvpn_password))
            .field(
                "challenge_response",
                &self.challenge_response.as_ref().map(|_| "[REDACTED]"),
            )
            .field("from_cache", &self.from_cache)
            .finish()
    }
}

/// Resolution control flow (not user-facing errors).
#[derive(Debug)]
pub enum WatchguardResolveError {
    /// TLS validation failed and consent has not been granted.
    TlsPreflight,
    Other(TunnelError),
}

impl From<TunnelError> for WatchguardResolveError {
    fn from(error: TunnelError) -> Self {
        Self::Other(error)
    }
}

/// Convert a resolution control-flow outcome into the user-facing error.
pub fn map_watchguard_resolve_error(
    config_name: &str,
    settings: &WatchguardPortalSettings,
    error: WatchguardResolveError,
) -> TunnelError {
    match error {
        WatchguardResolveError::TlsPreflight => TunnelError::Establish(format!(
            "The TLS certificate presented by '{}:{}' could not be verified. To trust this server anyway, enable \"Trust server certificate\" for '{config_name}' or approve the one-time prompt on the next attempt.",
            settings.server, settings.port
        )),
        WatchguardResolveError::Other(error) => error,
    }
}

/// Trust-prompt body for an unverified portal certificate (C# message parity).
fn watchguard_tls_trust_prompt_message(
    settings: &WatchguardPortalSettings,
    failure: &WatchguardTlsFailure,
) -> String {
    let mut message = format!(
        "The VPN server at '{}:{}' presented a certificate that could not be verified.\n\nSubject: {}\nIssuer: {}\nThumbprint: {}",
        settings.server, settings.port, failure.subject, failure.issuer, failure.thumbprint
    );
    message.push_str("\n\nMany VPN appliances ship with a factory certificate. Trust this server only if you recognize it.");
    if settings.use_otp {
        message.push_str(" Your one-time code will be sent to this server on the next attempt, so only proceed if the identity is expected.");
    }
    message.push_str(&format!("\n\n[{}]", ACCEPT_BUTTON_LABEL));
    message
}

/// Automatic-mode resolution with the trust override flag applied.
#[allow(clippy::too_many_arguments)] // mirrors the Stormshield portal core signature.
async fn resolve_watchguard_core(
    config_id: Uuid,
    config_name: &str,
    settings: &WatchguardPortalSettings,
    fetcher: &dyn WatchguardPortalFetcher,
    cache: &dyn WatchguardProfileCache,
    otp_prompt: &dyn OtpPrompt,
    guard: &WatchguardOtpReuseGuard,
    trust_enabled: bool,
) -> Result<WatchguardOutcome, WatchguardResolveError> {
    let request = WatchguardPortalRequest::new(settings.server.trim(), settings.port);
    let site_identity_hash = settings.site_identity_hash();
    let credentials = FireboxCredentials::new(settings.username.clone(), settings.password.clone())
        .validated()?;

    // Cached profile fast path (defensive miss on any read failure).
    let cached = match cache.read(&config_id) {
        Ok(cached) => cached,
        Err(error) => {
            tracing::debug!(
                tunnel_config_id = %config_id,
                error = %error,
                "WatchGuard profile cache read failed; treating as a miss"
            );
            None
        }
    };
    if let Some(record) = cached.as_ref().filter(|record| {
        watchguard_cache_record_is_current(record, &site_identity_hash, settings.max_cache_age)
    }) {
        // Cached profile: skip the web sslvpn_logon entirely; the user's single 2FA
        // factor answers the OpenVPN CRV1 challenge (no portal HTTPS, no double prompt).
        let second_factor = if settings.use_otp {
            Some(prompt_guarded_watchguard_otp(otp_prompt, guard, config_id, config_name).await?)
        } else {
            None
        };
        let challenge_response = second_factor
            .as_ref()
            .map(|factor| factor.challenge_response_value().to_string());
        return Ok(WatchguardOutcome {
            profile_ovpn: record.profile_ovpn.clone(),
            username: credentials.username.into_inner(),
            openvpn_password: credentials.password.into_inner(),
            challenge_response,
            from_cache: true,
        });
    }

    // Cache miss: surface a TLS failure *before* any OTP spend.
    if !trust_enabled && fetcher.last_tls_failure().is_some() {
        return Err(WatchguardResolveError::TlsPreflight);
    }

    let second_factor = if settings.use_otp {
        Some(prompt_guarded_watchguard_otp(otp_prompt, guard, config_id, config_name).await?)
    } else {
        None
    };

    // 2FA is satisfied at the web sslvpn_logon: OTP becomes the OpenVPN password
    // (Firebox one-shot quirk); push / no-2FA keep the account password. No CRV1
    // challenge response is carried.
    let openvpn_password = portal_openvpn_password(&credentials.password, second_factor.as_ref());
    let profile = fetcher
        .download_profile(&request, credentials.username.as_str(), openvpn_password.as_str())
        .await?;
    require_nonempty_watchguard_profile(&profile, config_name)?;

    // Only a confirmed download records the spent code.
    if let Some(FireboxSecondFactor::OneTimeCode(code)) = &second_factor {
        guard.record(config_id, code);
    }

    let record = WatchguardOvpnCacheRecord {
        schema_version: WATCHGUARD_CACHE_SCHEMA,
        site_identity_hash,
        profile_ovpn: profile.clone(),
        cached_at_utc: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    };
    if let Err(error) = cache.write(&config_id, &record) {
        tracing::warn!(
            tunnel_config_id = %config_id,
            error = %error,
            "WatchGuard profile cache write failed (best-effort)"
        );
    }

    Ok(WatchguardOutcome {
        profile_ovpn: profile,
        username: credentials.username.into_inner(),
        openvpn_password: openvpn_password.into_inner(),
        challenge_response: None,
        from_cache: false,
    })
}

/// Automatic-mode resolution with one TLS trust-consent retry (C# parity).
#[allow(clippy::too_many_arguments)] // mirrors the Stormshield portal consent signature.
async fn resolve_watchguard_with_consent(
    config_id: Uuid,
    config_name: &str,
    settings: &WatchguardPortalSettings,
    fetcher: &dyn WatchguardPortalFetcher,
    cache: &dyn WatchguardProfileCache,
    otp_prompt: &dyn OtpPrompt,
    guard: &WatchguardOtpReuseGuard,
    trust_prompt: &dyn TlsTrustPrompt,
) -> Result<WatchguardOutcome, WatchguardResolveError> {
    let mut trust_enabled = settings.trust_server_certificate;
    loop {
        match resolve_watchguard_core(
            config_id,
            config_name,
            settings,
            fetcher,
            cache,
            otp_prompt,
            guard,
            trust_enabled,
        )
        .await
        {
            Err(WatchguardResolveError::TlsPreflight) => {
                // Fail-closed guard: a pinned CA must never trigger a prompt.
                if settings.ca_pem.is_some() {
                    return Err(WatchguardResolveError::TlsPreflight);
                }
                let Some(failure) = fetcher.last_tls_failure() else {
                    return Err(WatchguardResolveError::TlsPreflight);
                };
                let title = format!("Unverified VPN server certificate — {config_name}");
                let message = watchguard_tls_trust_prompt_message(settings, &failure);
                match request_tls_trust(
                    trust_prompt,
                    title,
                    message,
                    Some(failure.thumbprint.clone()),
                )
                .await
                {
                    Ok(true) => {
                        trust_enabled = true;
                        continue;
                    }
                    Ok(false) => return Err(WatchguardResolveError::Other(TunnelError::Cancelled)),
                    Err(error) => return Err(WatchguardResolveError::Other(error)),
                }
            }
            outcome => return outcome,
        }
    }
}

/// Establish a WatchGuard username/password tunnel end to end (C# `EstablishAsync` /
/// `ResolveProfileAndCredentialsAsync`).
///
/// Order: provider/config kind gate → settings validation → portal physical-path
/// preflight → profile resolution (cached CRV1 or portal download + OTP + trust
/// consent) → transport physical-path preflight → OpenVPN sidecar JSON → establish.
///
/// On a cached-profile establish failure the cache entry is dropped (optimistic reuse
/// — next connect re-downloads). SAML mode is out of scope (unported).
#[allow(clippy::too_many_arguments)]
pub async fn establish_watchguard_automatic(
    config_id: Uuid,
    configs: &dyn TunnelConfigLookup,
    settings: WatchguardPortalSettings,
    fetcher: &dyn WatchguardPortalFetcher,
    cache: &dyn WatchguardProfileCache,
    probe: &dyn PhysicalNetworkPathProbe,
    otp_prompt: &dyn OtpPrompt,
    otp_guard: &WatchguardOtpReuseGuard,
    trust_prompt: &dyn TlsTrustPrompt,
    provider: &dyn TunnelProvider,
) -> Result<Arc<dyn TunnelInstance>, TunnelError> {
    require_watchguard_provider(provider)?;
    let record = load_watchguard_record(config_id, configs)?;
    let config_name = record.name.clone();

    validate_watchguard_portal_settings(&settings, &config_name)?;

    let _portal_path = require_physical_path(
        &config_name,
        probe,
        &[settings.server.trim()],
        "portal",
    )?;

    let outcome = resolve_watchguard_with_consent(
        config_id,
        &config_name,
        &settings,
        fetcher,
        cache,
        otp_prompt,
        otp_guard,
        trust_prompt,
    )
    .await
    .map_err(|error| map_watchguard_resolve_error(&config_name, &settings, error))?;

    // Transport preflight targets the profile's `remote` hosts (the portal server and
    // the OpenVPN endpoint are usually the same appliance, but not always).
    let remote_hosts = extract_ovpn_remote_hosts(&outcome.profile_ovpn);
    if remote_hosts.is_empty() {
        // The profile is unusable: never leave it cached for the next connect (it
        // would fail the same preflight for up to WATCHGUARD_CACHE_MAX_AGE). Drop
        // it best-effort so the next connect re-downloads. Covers both a fresh
        // download that produced the garbage and a cached record that failed the
        // remote extraction.
        if let Err(delete_error) = cache.delete(&config_id) {
            tracing::warn!(
                tunnel_config_id = %config_id,
                error = %delete_error,
                "failed to drop WatchGuard profile cache entry with no usable remote endpoint"
            );
        }
        return Err(TunnelError::Establish(format!(
            "WatchGuard '{config_name}' OpenVPN profile contains no usable remote endpoint."
        )));
    }
    let remote_host_refs: Vec<&str> = remote_hosts.iter().map(String::as_str).collect();
    let transport = require_physical_path(&config_name, probe, &remote_host_refs, "transport")?;
    let transport_adapter_ids = transport.adapter_ids();
    let from_cache = outcome.from_cache;

    let materials = ResolvedOvpnMaterials {
        profile_ovpn: outcome.profile_ovpn,
        username: Some(outcome.username),
        password: Some(outcome.openvpn_password),
        challenge_response: outcome.challenge_response,
        transport_adapter_ids: Some(transport_adapter_ids),
        ..Default::default()
    };
    let secret = WatchguardAuthGlue.to_sidecar_json(&materials)?;

    match establish_with_secret(&record, &secret, provider).await {
        Ok(instance) => Ok(instance),
        Err(error) => {
            if from_cache {
                // Unconfirmed cached profile — drop it so the next connect re-downloads
                // instead of looping on a profile the firewall may have rotated.
                if let Err(delete_error) = cache.delete(&config_id) {
                    tracing::warn!(
                        tunnel_config_id = %config_id,
                        error = %delete_error,
                        "failed to drop optimistic WatchGuard profile cache entry"
                    );
                }
            }
            Err(error)
        }
    }
}

fn sha256_hex_upper(input: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(input) {
        let _ = write!(hex, "{byte:02X}");
    }
    hex
}

fn sha256_bytes(input: &[u8]) -> Vec<u8> {
    Sha256::digest(input).to_vec()
}

/// Constant-time hash comparison (the values are hashes, but never compare
/// security-sensitive material in a way that leaks timing).
fn hashes_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Short prefix for logs / Debug (never the full thumbprint).
fn thumbprint_prefix(thumbprint: &str) -> String {
    let trimmed = thumbprint.trim();
    if trimmed.len() <= 8 {
        trimmed.to_string()
    } else {
        trimmed.chars().take(8).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::providers::auth_glue::{decode_watchguard_cache_json, FakeOtpPrompt, FakeTlsTrustPrompt};
    use crate::providers::wireguard::{FakeTunnelConfigLookup, TunnelConfigRecord};
    use crate::{
        FakePhysicalNetworkPath, PhysicalAdapterRecord, PhysicalNetworkRoute, StubTunnelInstance,
        TunnelConfigSnapshot, TunnelKind, TunnelState,
    };

    const TEST_SERVER: &str = "fw.example";
    const TEST_USERNAME: &str = "wg-user";
    const TEST_PASSWORD: &str = "s3cret";
    const TEST_OTP: &str = "654321";
    const TEST_PROFILE: &str = "client\nremote 127.0.0.1 443 tcp\n";
    const TEST_THUMBPRINT: &str =
        "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD";
    const TEST_CONFIG_ID: &str = "bbbbbbbb-cccc-dddd-eeee-000000000001";
    const TEST_CONFIG_ID_2: &str = "bbbbbbbb-cccc-dddd-eeee-000000000002";

    fn config_id() -> Uuid {
        Uuid::parse_str(TEST_CONFIG_ID).unwrap()
    }

    fn config_id_2() -> Uuid {
        Uuid::parse_str(TEST_CONFIG_ID_2).unwrap()
    }

    fn settings() -> WatchguardPortalSettings {
        WatchguardPortalSettings::new(TEST_SERVER, 443, TEST_USERNAME, TEST_PASSWORD, true)
    }

    fn settings_no_otp() -> WatchguardPortalSettings {
        WatchguardPortalSettings::new(TEST_SERVER, 443, TEST_USERNAME, TEST_PASSWORD, false)
    }

    fn ethernet_probe() -> FakePhysicalNetworkPath {
        FakePhysicalNetworkPath::new(vec![PhysicalAdapterRecord::ethernet(
            "eth0", "Ethernet", 1, 1,
        )])
        .with_host_route(TEST_SERVER, PhysicalNetworkRoute::Physical)
        .with_host_route("vpn.example", PhysicalNetworkRoute::Physical)
    }

    fn configs() -> FakeTunnelConfigLookup {
        FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            config_id(),
            TunnelKind::Watchguard,
            "lab-watchguard",
        ))
    }

    fn fresh_stamp() -> String {
        Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
    }

    fn current_cache_record(site_identity_hash: &str) -> WatchguardOvpnCacheRecord {
        WatchguardOvpnCacheRecord {
            schema_version: WATCHGUARD_CACHE_SCHEMA,
            site_identity_hash: site_identity_hash.to_string(),
            profile_ovpn: "client\nremote vpn.example 1194 tcp\ndev tun\n".to_string(),
            cached_at_utc: fresh_stamp(),
        }
    }

    fn trust_accepting() -> FakeTlsTrustPrompt {
        FakeTlsTrustPrompt::from_accepts([true])
    }

    fn trust_rejecting() -> FakeTlsTrustPrompt {
        FakeTlsTrustPrompt::from_accepts([false])
    }

    /// Controllable WatchGuard `TunnelProvider` that records the last secret blob.
    struct RecordingWatchguardProvider {
        establish_count: AtomicUsize,
        fail_next: Mutex<bool>,
        last_secret: Mutex<Option<Vec<u8>>>,
    }

    impl RecordingWatchguardProvider {
        fn new() -> Self {
            Self {
                establish_count: AtomicUsize::new(0),
                fail_next: Mutex::new(false),
                last_secret: Mutex::new(None),
            }
        }

        fn establish_count(&self) -> usize {
            self.establish_count.load(Ordering::SeqCst)
        }

        fn last_secret(&self) -> Option<Vec<u8>> {
            self.last_secret.lock().unwrap_or_else(|p| p.into_inner()).clone()
        }

        fn fail_next(&self) {
            *self.fail_next.lock().unwrap_or_else(|p| p.into_inner()) = true;
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
            if *self.fail_next.lock().unwrap_or_else(|p| p.into_inner()) {
                return Err(TunnelError::Establish("injected provider failure".into()));
            }
            *self.last_secret.lock().unwrap_or_else(|p| p.into_inner()) = Some(secret_blob.to_vec());
            Ok(StubTunnelInstance::up_with_socks(18_761))
        }
    }

    /// Parse a field from the recorded sidecar JSON.
    fn sidecar_field(secret: &[u8], field: &str) -> String {
        let value: serde_json::Value = serde_json::from_slice(secret).expect("sidecar JSON");
        match value[field].as_str() {
            Some(text) => text.to_string(),
            None => String::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn establish_automatic(
        fetcher: &dyn WatchguardPortalFetcher,
        cache: &dyn WatchguardProfileCache,
        probe: &dyn PhysicalNetworkPathProbe,
        prompt: &dyn OtpPrompt,
        guard: &WatchguardOtpReuseGuard,
        trust: &dyn TlsTrustPrompt,
        provider: &RecordingWatchguardProvider,
        settings: WatchguardPortalSettings,
    ) -> Result<Arc<dyn TunnelInstance>, TunnelError> {
        establish_watchguard_automatic(
            config_id(),
            &configs(),
            settings,
            fetcher,
            cache,
            probe,
            prompt,
            guard,
            trust,
            provider,
        )
        .await
    }

    #[tokio::test]
    async fn cached_profile_routes_otp_to_crv1_data_plane() {
        let settings = settings();
        let cache = MemoryWatchguardProfileCache::new();
        cache.seed(config_id(), current_cache_record(&settings.site_identity_hash()));
        let fetcher = FakeWatchguardPortalFetcher::new();
        let guard = WatchguardOtpReuseGuard::new();
        let prompt = FakeOtpPrompt::from_submitted([TEST_OTP]);
        let trust = trust_rejecting();
        let provider = RecordingWatchguardProvider::new();

        let instance = establish_automatic(
            &fetcher, &cache, &ethernet_probe(), &prompt, &guard, &trust, &provider, settings,
        )
        .await
        .unwrap();

        assert_eq!(instance.state(), TunnelState::Up);
        assert_eq!(provider.establish_count(), 1);
        let secret = provider.last_secret().expect("captured stdin");
        assert_eq!(sidecar_field(&secret, "password"), TEST_PASSWORD);
        assert_eq!(sidecar_field(&secret, "challenge_response"), TEST_OTP);
        assert_eq!(fetcher.download_calls(), 0, "cache hit must not hit the portal");
        assert_eq!(prompt.prompt_count(), 1);
        assert_eq!(trust.prompt_count(), 0);
        assert_eq!(cache.write_calls(), 0, "cache hit must not rewrite the profile");
        assert!(
            guard.check(config_id(), &OtpCode::new(TEST_OTP)).is_ok(),
            "data-plane codes must never be recorded as spent"
        );
    }

    #[tokio::test]
    async fn cached_profile_without_otp_skips_prompt_and_uses_account_password() {
        let settings = settings_no_otp();
        let cache = MemoryWatchguardProfileCache::new();
        cache.seed(config_id(), current_cache_record(&settings.site_identity_hash()));
        let fetcher = FakeWatchguardPortalFetcher::new();
        let prompt = FakeOtpPrompt::from_submitted(["SHOULD_NOT_PROMPT"]);
        let provider = RecordingWatchguardProvider::new();

        let instance = establish_automatic(
            &fetcher,
            &cache,
            &ethernet_probe(),
            &prompt,
            &WatchguardOtpReuseGuard::new(),
            &trust_rejecting(),
            &provider,
            settings,
        )
        .await
        .unwrap();

        assert_eq!(instance.state(), TunnelState::Up);
        let secret = provider.last_secret().expect("captured stdin");
        assert_eq!(sidecar_field(&secret, "password"), TEST_PASSWORD);
        assert_eq!(sidecar_field(&secret, "challenge_response"), "");
        assert_eq!(prompt.prompt_count(), 0, "no-OTP path must never prompt");
        assert_eq!(fetcher.download_calls(), 0);
    }

    #[tokio::test]
    async fn cached_profile_push_sets_challenge_p() {
        let settings = settings();
        let cache = MemoryWatchguardProfileCache::new();
        cache.seed(config_id(), current_cache_record(&settings.site_identity_hash()));
        let fetcher = FakeWatchguardPortalFetcher::new();
        let prompt = FakeOtpPrompt::from_submitted(["p"]);
        let provider = RecordingWatchguardProvider::new();

        let instance = establish_automatic(
            &fetcher,
            &cache,
            &ethernet_probe(),
            &prompt,
            &WatchguardOtpReuseGuard::new(),
            &trust_rejecting(),
            &provider,
            settings,
        )
        .await
        .unwrap();

        assert_eq!(instance.state(), TunnelState::Up);
        let secret = provider.last_secret().expect("captured stdin");
        assert_eq!(sidecar_field(&secret, "password"), TEST_PASSWORD);
        assert_eq!(sidecar_field(&secret, "challenge_response"), "p");
        assert_eq!(fetcher.download_calls(), 0);
    }

    #[tokio::test]
    async fn cache_miss_downloads_with_otp_as_password_and_records_spend() {
        let fetcher = FakeWatchguardPortalFetcher::new();
        fetcher.push_profile(TEST_PROFILE);
        let cache = MemoryWatchguardProfileCache::new();
        let guard = WatchguardOtpReuseGuard::new();
        let prompt = FakeOtpPrompt::from_submitted([TEST_OTP]);
        let provider = RecordingWatchguardProvider::new();

        let instance = establish_automatic(
            &fetcher,
            &cache,
            &ethernet_probe(),
            &prompt,
            &guard,
            &trust_rejecting(),
            &provider,
            settings(),
        )
        .await
        .unwrap();

        assert_eq!(instance.state(), TunnelState::Up);
        let secret = provider.last_secret().expect("captured stdin");
        assert_eq!(sidecar_field(&secret, "password"), TEST_OTP, "OTP one-shot becomes the OpenVPN password");
        assert_eq!(sidecar_field(&secret, "challenge_response"), "");
        assert_eq!(fetcher.download_calls(), 1);
        assert_eq!(prompt.prompt_count(), 1);
        assert_eq!(cache.write_calls(), 1, "fresh profile must be persisted");
        let stored = cache.entry(&config_id()).expect("profile must be cached");
        assert_eq!(stored.profile_ovpn, TEST_PROFILE);
        assert_eq!(
            fetcher.download_requests()[0].password,
            TEST_OTP,
            "portal download receives the pre-auth OTP"
        );
        assert!(
            guard.check(config_id(), &OtpCode::new(TEST_OTP)).is_err(),
            "a portal-spent code must be recorded"
        );
    }

    #[tokio::test]
    async fn cache_miss_push_keeps_account_password_and_does_not_record() {
        let fetcher = FakeWatchguardPortalFetcher::new();
        fetcher.push_profile(TEST_PROFILE);
        let cache = MemoryWatchguardProfileCache::new();
        let guard = WatchguardOtpReuseGuard::new();
        let prompt = FakeOtpPrompt::from_submitted(["p"]);
        let provider = RecordingWatchguardProvider::new();

        let instance = establish_automatic(
            &fetcher,
            &cache,
            &ethernet_probe(),
            &prompt,
            &guard,
            &trust_rejecting(),
            &provider,
            settings(),
        )
        .await
        .unwrap();

        assert_eq!(instance.state(), TunnelState::Up);
        let secret = provider.last_secret().expect("captured stdin");
        assert_eq!(sidecar_field(&secret, "password"), TEST_PASSWORD);
        assert_eq!(sidecar_field(&secret, "challenge_response"), "");
        assert_eq!(fetcher.download_requests()[0].password, TEST_PASSWORD);
        assert_eq!(cache.write_calls(), 1);
        assert!(cache.entry(&config_id()).is_some());
    }

    #[tokio::test]
    async fn cache_miss_without_otp_downloads_with_account_password() {
        let fetcher = FakeWatchguardPortalFetcher::new();
        fetcher.push_profile(TEST_PROFILE);
        let prompt = FakeOtpPrompt::from_submitted(["SHOULD_NOT_PROMPT"]);
        let provider = RecordingWatchguardProvider::new();

        let instance = establish_automatic(
            &fetcher,
            &MemoryWatchguardProfileCache::new(),
            &ethernet_probe(),
            &prompt,
            &WatchguardOtpReuseGuard::new(),
            &trust_accepting(),
            &provider,
            settings_no_otp(),
        )
        .await
        .unwrap();

        assert_eq!(instance.state(), TunnelState::Up);
        let secret = provider.last_secret().expect("captured stdin");
        assert_eq!(sidecar_field(&secret, "password"), TEST_PASSWORD);
        assert_eq!(fetcher.download_requests()[0].password, TEST_PASSWORD);
        assert_eq!(prompt.prompt_count(), 0);
    }

    #[tokio::test]
    async fn cache_read_failure_treated_as_miss() {
        let cache = MemoryWatchguardProfileCache::new();
        cache.set_read_failure("simulated DPAPI failure");
        let fetcher = FakeWatchguardPortalFetcher::new();
        fetcher.push_profile(TEST_PROFILE);
        let prompt = FakeOtpPrompt::from_submitted([TEST_OTP]);

        let instance = establish_automatic(
            &fetcher,
            &cache,
            &ethernet_probe(),
            &prompt,
            &WatchguardOtpReuseGuard::new(),
            &trust_rejecting(),
            &RecordingWatchguardProvider::new(),
            settings(),
        )
        .await
        .unwrap();

        assert_eq!(instance.state(), TunnelState::Up);
        assert_eq!(
            fetcher.download_calls(),
            1,
            "read failures must degrade to a download, not propagate"
        );
    }

    #[tokio::test]
    async fn corrupt_cache_never_reused() {
        let settings = settings();
        let base = current_cache_record(&settings.site_identity_hash());

        let cases = [
            ("wrong schema", WatchguardOvpnCacheRecord { schema_version: 2, ..base.clone() }),
            ("empty profile", WatchguardOvpnCacheRecord { profile_ovpn: "   ".into(), ..base.clone() }),
            ("identity mismatch", WatchguardOvpnCacheRecord { site_identity_hash: "OTHER".into(), ..base.clone() }),
            ("stale", WatchguardOvpnCacheRecord { cached_at_utc: (Utc::now() - chrono::Duration::days(31)).to_rfc3339_opts(SecondsFormat::Secs, true), ..base.clone() }),
            ("future", WatchguardOvpnCacheRecord { cached_at_utc: (Utc::now() + chrono::Duration::hours(1)).to_rfc3339_opts(SecondsFormat::Secs, true), ..base.clone() }),
            ("unparseable", WatchguardOvpnCacheRecord { cached_at_utc: "not-a-date".into(), ..base.clone() }),
            ("html body", WatchguardOvpnCacheRecord { profile_ovpn: "<html><body>remote login failed</body></html>".into(), ..base.clone() }),
        ];

        for (label, record) in cases {
            let cache = MemoryWatchguardProfileCache::new();
            cache.seed(config_id(), record);
            let fetcher = FakeWatchguardPortalFetcher::new();
            fetcher.push_profile(TEST_PROFILE);
            let prompt = FakeOtpPrompt::from_submitted([TEST_OTP]);

            let instance = establish_automatic(
                &fetcher,
                &cache,
                &ethernet_probe(),
                &prompt,
                &WatchguardOtpReuseGuard::new(),
                &trust_rejecting(),
                &RecordingWatchguardProvider::new(),
                settings.clone(),
            )
            .await
            .expect("corrupt cache must degrade to a fresh download");
            assert_eq!(instance.state(), TunnelState::Up, "{label}");
            assert_eq!(fetcher.download_calls(), 1, "{label}: corrupt cache must re-download");
        }
    }

    #[tokio::test]
    async fn otp_reuse_guard_rejects_within_window_strict_boundary() {
        let clock = Arc::new(Mutex::new(Utc::now()));
        let guard_clock = {
            let clock = clock.clone();
            move || *clock.lock().unwrap_or_else(|p| p.into_inner())
        };
        let guard = WatchguardOtpReuseGuard::new().with_clock(guard_clock);
        let id = config_id();

        guard.record(id, &OtpCode::new("  123456  "));

        let err = guard.check(id, &OtpCode::new("123456")).unwrap_err();
        assert!(err.to_string().contains("NEW code"), "unexpected: {err}");

        assert!(guard.check(id, &OtpCode::new("111111")).is_ok());

        *clock.lock().unwrap_or_else(|p| p.into_inner()) =
            Utc::now() + chrono::Duration::seconds(89);
        assert!(
            guard.check(id, &OtpCode::new("123456")).is_err(),
            "reuse inside the window must be rejected"
        );

        // C# parity: the window is strict (`<`), so a code at exactly 90 s is fresh.
        *clock.lock().unwrap_or_else(|p| p.into_inner()) =
            Utc::now() + chrono::Duration::seconds(90);
        assert!(
            guard.check(id, &OtpCode::new("123456")).is_ok(),
            "exactly-at-window reuse is not inside the window"
        );

        *clock.lock().unwrap_or_else(|p| p.into_inner()) =
            Utc::now() + chrono::Duration::seconds(91);
        assert!(guard.check(id, &OtpCode::new("123456")).is_ok(), "reuse outside the window is fine");
    }

    #[test]
    fn otp_reuse_guard_rejects_on_backward_clock_skew() {
        // C# `now - spent_at < window` treats a NEGATIVE elapsed (the clock jumped
        // backward) as inside the window — a spent code must stay rejected so it can
        // never be re-submitted after a clock rollback (fail closed).
        let clock = Arc::new(Mutex::new(Utc::now()));
        let guard_clock = {
            let clock = clock.clone();
            move || *clock.lock().unwrap_or_else(|p| p.into_inner())
        };
        let guard = WatchguardOtpReuseGuard::new().with_clock(guard_clock);
        let id = config_id();

        guard.record(id, &OtpCode::new("135790"));

        *clock.lock().unwrap_or_else(|p| p.into_inner()) =
            Utc::now() - chrono::Duration::seconds(300);
        assert!(
            guard.check(id, &OtpCode::new("135790")).is_err(),
            "a code spent before a backward clock jump must stay rejected"
        );
        assert!(guard.check(id, &OtpCode::new("864209")).is_ok(), "other codes stay accepted");
    }

    #[test]
    fn otp_reuse_guard_ignores_blank_and_scopes_by_tunnel() {
        let guard = WatchguardOtpReuseGuard::new();

        guard.record(config_id(), &OtpCode::new("   "));
        assert!(guard.check(config_id(), &OtpCode::new("anything")).is_ok());

        guard.record(config_id(), &OtpCode::new("999999"));
        assert!(guard.check(config_id_2(), &OtpCode::new("999999")).is_ok(), "per-tunnel scope");
        assert!(guard.check(config_id(), &OtpCode::new("999999")).is_err());
    }

    #[tokio::test]
    async fn otp_prompt_cancel_fails_closed() {
        let fetcher = FakeWatchguardPortalFetcher::new();
        fetcher.push_profile(TEST_PROFILE);
        let prompt = FakeOtpPrompt::from_codes([None::<&str>]);

        let error = establish_automatic(
            &fetcher,
            &MemoryWatchguardProfileCache::new(),
            &ethernet_probe(),
            &prompt,
            &WatchguardOtpReuseGuard::new(),
            &trust_rejecting(),
            &RecordingWatchguardProvider::new(),
            settings(),
        )
        .await
        .err()
        .expect("expected establishment failure");

        assert!(matches!(error, TunnelError::Cancelled));
        assert_eq!(fetcher.download_calls(), 0);
    }

    #[tokio::test]
    async fn tls_preflight_fails_fast_before_otp_prompt() {
        let fetcher = FakeWatchguardPortalFetcher::new();
        fetcher.push_profile(TEST_PROFILE);
        fetcher.set_tls_failure(WatchguardTlsFailure::new(
            "CN=fw.example",
            "CN=Lab Root CA",
            TEST_THUMBPRINT,
        ));
        let prompt = FakeOtpPrompt::from_submitted([TEST_OTP]);
        let trust = trust_rejecting();

        let error = establish_automatic(
            &fetcher,
            &MemoryWatchguardProfileCache::new(),
            &ethernet_probe(),
            &prompt,
            &WatchguardOtpReuseGuard::new(),
            &trust,
            &RecordingWatchguardProvider::new(),
            settings(),
        )
        .await
        .err()
        .expect("expected establishment failure");

        assert!(matches!(error, TunnelError::Cancelled), "unexpected: {error:?}");
        assert_eq!(prompt.prompt_count(), 0, "OTP must not be prompted before TLS consent");
        assert_eq!(fetcher.download_calls(), 0);
        assert_eq!(trust.prompt_count(), 1, "trust consent is the first user interaction");
    }

    #[tokio::test]
    async fn trust_accept_retries_downloads_and_establishes() {
        let fetcher = FakeWatchguardPortalFetcher::new();
        fetcher.push_profile(TEST_PROFILE);
        fetcher.set_tls_failure(WatchguardTlsFailure::new(
            "CN=fw.example",
            "CN=Lab Root CA",
            TEST_THUMBPRINT,
        ));
        let prompt = FakeOtpPrompt::from_submitted([TEST_OTP]);
        let trust = trust_accepting();
        let provider = RecordingWatchguardProvider::new();

        let instance = establish_automatic(
            &fetcher,
            &MemoryWatchguardProfileCache::new(),
            &ethernet_probe(),
            &prompt,
            &WatchguardOtpReuseGuard::new(),
            &trust,
            &provider,
            settings(),
        )
        .await
        .unwrap();

        assert_eq!(instance.state(), TunnelState::Up);
        assert_eq!(fetcher.download_calls(), 1);
        assert_eq!(prompt.prompt_count(), 1);
        assert_eq!(trust.prompt_count(), 1);
        let requests = trust.requests();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].title.contains("lab-watchguard"));
        assert!(requests[0].message.contains("factory certificate"));
        assert!(requests[0].message.contains("one-time code"));
        assert_eq!(requests[0].fingerprint.as_deref(), Some(TEST_THUMBPRINT));
        assert_eq!(
            fetcher.download_requests()[0].password,
            TEST_OTP,
            "portal download receives the pre-auth OTP"
        );
    }

    #[tokio::test]
    async fn trust_reject_fails_closed() {
        let fetcher = FakeWatchguardPortalFetcher::new();
        fetcher.push_profile(TEST_PROFILE);
        fetcher.set_tls_failure(WatchguardTlsFailure::new(
            "CN=fw.example",
            "CN=Lab Root CA",
            TEST_THUMBPRINT,
        ));
        let prompt = FakeOtpPrompt::from_submitted([TEST_OTP]);
        let trust = trust_rejecting();

        let error = establish_automatic(
            &fetcher,
            &MemoryWatchguardProfileCache::new(),
            &ethernet_probe(),
            &prompt,
            &WatchguardOtpReuseGuard::new(),
            &trust,
            &RecordingWatchguardProvider::new(),
            settings(),
        )
        .await
        .err()
        .expect("expected establishment failure");

        assert!(matches!(error, TunnelError::Cancelled));
        assert_eq!(fetcher.download_calls(), 0);
        assert_eq!(prompt.prompt_count(), 0);
        assert_eq!(trust.prompt_count(), 1);
    }

    #[tokio::test]
    async fn pinned_ca_never_offers_trust_prompt() {
        let settings = settings().with_pinned_ca("-----BEGIN CERTIFICATE-----");
        let fetcher = FakeWatchguardPortalFetcher::new();
        fetcher.push_profile(TEST_PROFILE);
        fetcher.set_tls_failure(WatchguardTlsFailure::new(
            "CN=fw.example",
            "CN=Lab Root CA",
            TEST_THUMBPRINT,
        ));
        let prompt = FakeOtpPrompt::from_submitted([TEST_OTP]);
        let trust = trust_accepting();

        let error = establish_automatic(
            &fetcher,
            &MemoryWatchguardProfileCache::new(),
            &ethernet_probe(),
            &prompt,
            &WatchguardOtpReuseGuard::new(),
            &trust,
            &RecordingWatchguardProvider::new(),
            settings,
        )
        .await
        .err()
        .expect("expected establishment failure");

        assert!(error.to_string().contains("could not be verified"));
        assert_eq!(trust.prompt_count(), 0, "pinned CA must never prompt");
        assert_eq!(prompt.prompt_count(), 0);
        assert_eq!(fetcher.download_calls(), 0);
    }

    #[tokio::test]
    async fn trust_already_enabled_skips_prompt_and_establishes() {
        let settings = settings().with_trust_server_certificate(true);
        let fetcher = FakeWatchguardPortalFetcher::new();
        fetcher.push_profile(TEST_PROFILE);
        fetcher.set_tls_failure(WatchguardTlsFailure::new(
            "CN=fw.example",
            "CN=Lab Root CA",
            TEST_THUMBPRINT,
        ));
        let trust = trust_rejecting();
        let provider = RecordingWatchguardProvider::new();

        let instance = establish_automatic(
            &fetcher,
            &MemoryWatchguardProfileCache::new(),
            &ethernet_probe(),
            &FakeOtpPrompt::from_submitted([TEST_OTP]),
            &WatchguardOtpReuseGuard::new(),
            &trust,
            &provider,
            settings,
        )
        .await
        .unwrap();

        assert_eq!(instance.state(), TunnelState::Up);
        assert_eq!(trust.prompt_count(), 0, "pre-enabled trust must not prompt");
        assert_eq!(provider.establish_count(), 1);
    }

    #[tokio::test]
    async fn settings_preflight_fails_closed() {
        let empty_server =
            WatchguardPortalSettings::new("", 443, TEST_USERNAME, TEST_PASSWORD, true);
        let error = establish_automatic(
            &FakeWatchguardPortalFetcher::new(),
            &MemoryWatchguardProfileCache::new(),
            &ethernet_probe(),
            &FakeOtpPrompt::from_submitted([TEST_OTP]),
            &WatchguardOtpReuseGuard::new(),
            &trust_rejecting(),
            &RecordingWatchguardProvider::new(),
            empty_server,
        )
        .await
        .err()
        .expect("expected establishment failure");
        assert!(error.to_string().contains("empty Server"), "unexpected: {error}");

        let missing_credentials =
            WatchguardPortalSettings::new(TEST_SERVER, 443, "", "", true);
        let error = establish_automatic(
            &FakeWatchguardPortalFetcher::new(),
            &MemoryWatchguardProfileCache::new(),
            &ethernet_probe(),
            &FakeOtpPrompt::from_submitted([TEST_OTP]),
            &WatchguardOtpReuseGuard::new(),
            &trust_rejecting(),
            &RecordingWatchguardProvider::new(),
            missing_credentials,
        )
        .await
        .err()
        .expect("expected establishment failure");
        assert!(
            error.to_string().contains("missing a username or password"),
            "unexpected: {error}"
        );
    }

    #[tokio::test]
    async fn config_missing_or_wrong_kind_fails_closed() {
        let fetcher = FakeWatchguardPortalFetcher::new();
        let cache = MemoryWatchguardProfileCache::new();
        let probe = ethernet_probe();
        let prompt = FakeOtpPrompt::from_submitted([TEST_OTP]);
        let guard = WatchguardOtpReuseGuard::new();
        let trust = trust_rejecting();
        let provider = RecordingWatchguardProvider::new();

        let error = establish_watchguard_automatic(
            config_id(),
            &FakeTunnelConfigLookup::new(),
            settings(),
            &fetcher,
            &cache,
            &probe,
            &prompt,
            &guard,
            &trust,
            &provider,
        )
        .await
        .err()
        .expect("expected establishment failure");
        assert!(matches!(error, TunnelError::ConfigNotFound { .. }));

        let wrong_kind = FakeTunnelConfigLookup::new().with_config(TunnelConfigRecord::new(
            config_id(),
            TunnelKind::WireGuard,
            "not-watchguard",
        ));
        let error = establish_watchguard_automatic(
            config_id(),
            &wrong_kind,
            settings(),
            &fetcher,
            &cache,
            &probe,
            &prompt,
            &guard,
            &trust,
            &provider,
        )
        .await
        .err()
        .expect("expected establishment failure");
        assert!(matches!(error, TunnelError::WrongKind { .. }));
    }

    #[tokio::test]
    async fn physical_path_fail_closed() {
        let probe =
            FakePhysicalNetworkPath::new(vec![]).with_default_route(PhysicalNetworkRoute::Physical);
        let error = establish_automatic(
            &FakeWatchguardPortalFetcher::new(),
            &MemoryWatchguardProfileCache::new(),
            &probe,
            &FakeOtpPrompt::from_submitted([TEST_OTP]),
            &WatchguardOtpReuseGuard::new(),
            &trust_rejecting(),
            &RecordingWatchguardProvider::new(),
            settings(),
        )
        .await
        .err()
        .expect("expected establishment failure");
        assert!(
            error.to_string().contains("physical network adapter"),
            "unexpected: {error}"
        );

        let probe = FakePhysicalNetworkPath::new(vec![PhysicalAdapterRecord::ethernet(
            "eth0", "Ethernet", 1, 1,
        )]);
        let error = establish_automatic(
            &FakeWatchguardPortalFetcher::new(),
            &MemoryWatchguardProfileCache::new(),
            &probe,
            &FakeOtpPrompt::from_submitted([TEST_OTP]),
            &WatchguardOtpReuseGuard::new(),
            &trust_rejecting(),
            &RecordingWatchguardProvider::new(),
            settings(),
        )
        .await
        .err()
        .expect("expected establishment failure");
        assert!(error.to_string().contains("cannot classify"), "unexpected: {error}");
    }

    #[tokio::test]
    async fn empty_downloaded_profile_fails_before_record_or_cache() {
        let fetcher = FakeWatchguardPortalFetcher::new();
        fetcher.push_profile("   ");
        let guard = WatchguardOtpReuseGuard::new();
        let cache = MemoryWatchguardProfileCache::new();

        let error = establish_automatic(
            &fetcher,
            &cache,
            &ethernet_probe(),
            &FakeOtpPrompt::from_submitted([TEST_OTP]),
            &guard,
            &trust_rejecting(),
            &RecordingWatchguardProvider::new(),
            settings(),
        )
        .await
        .err()
        .expect("expected establishment failure");

        assert!(error.to_string().contains("empty OpenVPN profile"), "unexpected: {error}");
        assert_eq!(cache.write_calls(), 0, "empty profile must not be cached");
        assert!(
            guard.check(config_id(), &OtpCode::new(TEST_OTP)).is_ok(),
            "code must not be recorded when the profile is unusable"
        );
    }

    #[tokio::test]
    async fn cached_profile_without_usable_remote_fails_closed() {
        let settings = settings();
        let mut record = current_cache_record(&settings.site_identity_hash());
        record.profile_ovpn = "client\ndev tun\nremote \n".to_string();
        let cache = MemoryWatchguardProfileCache::new();
        cache.seed(config_id(), record);
        let fetcher = FakeWatchguardPortalFetcher::new();
        let provider = RecordingWatchguardProvider::new();

        let error = establish_automatic(
            &fetcher,
            &cache,
            &ethernet_probe(),
            &FakeOtpPrompt::from_submitted([TEST_OTP]),
            &WatchguardOtpReuseGuard::new(),
            &trust_rejecting(),
            &provider,
            settings,
        )
        .await
        .err()
        .expect("expected establishment failure");

        let message = error.to_string();
        assert!(message.contains("no usable remote endpoint"), "unexpected: {message}");
        assert_eq!(provider.establish_count(), 0, "no sidecar work without an endpoint");
        assert_eq!(fetcher.download_calls(), 0, "cache hit must not download");
        assert_eq!(
            cache.delete_calls(),
            1,
            "a cached profile with no usable remote must be dropped so the next connect re-downloads"
        );
        assert!(cache.entry(&config_id()).is_none());
    }

    #[tokio::test]
    async fn fresh_profile_without_remote_fails_closed_before_sidecar() {
        let fetcher = FakeWatchguardPortalFetcher::new();
        fetcher.push_profile("client\ndev tun\n");
        let provider = RecordingWatchguardProvider::new();
        let cache = MemoryWatchguardProfileCache::new();

        let error = establish_automatic(
            &fetcher,
            &cache,
            &ethernet_probe(),
            &FakeOtpPrompt::from_submitted(["SHOULD_NOT_PROMPT"]),
            &WatchguardOtpReuseGuard::new(),
            &trust_accepting(),
            &provider,
            settings_no_otp(),
        )
        .await
        .err()
        .expect("expected establishment failure");

        let message = error.to_string();
        assert!(message.contains("no usable remote endpoint"), "unexpected: {message}");
        assert_eq!(provider.establish_count(), 0);
        assert_eq!(
            cache.delete_calls(),
            1,
            "a fresh download with no usable remote must not stay cached for the next connect"
        );
        assert!(cache.entry(&config_id()).is_none());
    }

    #[tokio::test]
    async fn transport_unknown_profile_remote_fails_closed() {
        let settings = settings();
        let mut record = current_cache_record(&settings.site_identity_hash());
        record.profile_ovpn =
            "client\nremote unknown-endpoint.example 1194 tcp\ndev tun\n".to_string();
        let cache = MemoryWatchguardProfileCache::new();
        cache.seed(config_id(), record);
        let fetcher = FakeWatchguardPortalFetcher::new();
        let provider = RecordingWatchguardProvider::new();

        let error = establish_automatic(
            &fetcher,
            &cache,
            &ethernet_probe(),
            &FakeOtpPrompt::from_submitted([TEST_OTP]),
            &WatchguardOtpReuseGuard::new(),
            &trust_rejecting(),
            &provider,
            settings,
        )
        .await
        .err()
        .expect("expected establishment failure");

        let message = error.to_string();
        assert!(
            message.contains("transport destination 'unknown-endpoint.example'"),
            "unexpected: {message}"
        );
        assert!(message.contains("cannot classify"), "unexpected: {message}");
        assert_eq!(provider.establish_count(), 0);
        assert_eq!(fetcher.download_calls(), 0, "cache hit must not download");
    }

    #[tokio::test]
    async fn optimistic_cache_drop_on_establish_failure() {
        let settings = settings();
        let cache = MemoryWatchguardProfileCache::new();
        cache.seed(config_id(), current_cache_record(&settings.site_identity_hash()));
        let fetcher = FakeWatchguardPortalFetcher::new();
        let provider = RecordingWatchguardProvider::new();
        provider.fail_next();

        let error = establish_automatic(
            &fetcher,
            &cache,
            &ethernet_probe(),
            &FakeOtpPrompt::from_submitted([TEST_OTP]),
            &WatchguardOtpReuseGuard::new(),
            &trust_rejecting(),
            &provider,
            settings,
        )
        .await
        .err()
        .expect("expected establishment failure");

        assert!(error.to_string().contains("injected provider failure"));
        assert_eq!(cache.delete_calls(), 1, "unconfirmed cached profile must be dropped");
        assert!(cache.entry(&config_id()).is_none());
        assert_eq!(fetcher.download_calls(), 0);
    }

    #[test]
    fn site_identity_hash_matches_csharp_shape() {
        let base = settings();
        let mut different_password = settings();
        different_password.password = "totally-different".to_string();
        assert_eq!(
            base.site_identity_hash(),
            different_password.site_identity_hash(),
            "password must never affect the site identity"
        );

        let trusted = settings().with_trust_server_certificate(true);
        assert_ne!(base.site_identity_hash(), trusted.site_identity_hash());

        let pinned = settings().with_pinned_ca("CA");
        assert_ne!(base.site_identity_hash(), pinned.site_identity_hash());

        let mut different_user = settings();
        different_user.username = "other-user".to_string();
        assert_ne!(base.site_identity_hash(), different_user.site_identity_hash());

        let mut different_server = settings();
        different_server.server = "other.example".to_string();
        assert_ne!(base.site_identity_hash(), different_server.site_identity_hash());

        let mut different_port = settings();
        different_port.port = 8443;
        assert_ne!(base.site_identity_hash(), different_port.site_identity_hash());

        let expected = sha256_hex_upper(b"fw.example\n443\nwg-user\n0\n");
        assert_eq!(base.site_identity_hash(), expected);
    }

    #[test]
    fn encode_watchguard_cache_record_roundtrips_camel_case() {
        let record = current_cache_record("IDENT");
        let json = encode_watchguard_cache_record(&record).unwrap();
        let decoded = decode_watchguard_cache_json(&json).unwrap();
        assert_eq!(decoded, record);

        let text = String::from_utf8(json).unwrap();
        assert!(text.contains("\"schemaVersion\""), "camelCase expected: {text}");
        assert!(!text.contains("\"SchemaVersion\""), "camelCase expected: {text}");
    }

    #[test]
    fn encode_watchguard_cache_record_rejects_bad_shape() {
        let mut record = current_cache_record("IDENT");
        record.schema_version = 99;
        assert!(encode_watchguard_cache_record(&record).is_err());

        record.schema_version = WATCHGUARD_CACHE_SCHEMA;
        record.profile_ovpn = " ".to_string();
        assert!(encode_watchguard_cache_record(&record).is_err());
    }

    #[test]
    fn cache_record_is_current_fail_closed_table() {
        let settings = settings();
        let good = current_cache_record(&settings.site_identity_hash());

        let mut wrong_schema = good.clone();
        wrong_schema.schema_version = 2;
        assert!(!watchguard_cache_record_is_current(
            &wrong_schema,
            &settings.site_identity_hash(),
            WATCHGUARD_CACHE_MAX_AGE
        ));

        let mut empty_profile = good.clone();
        empty_profile.profile_ovpn = "  ".to_string();
        assert!(!watchguard_cache_record_is_current(
            &empty_profile,
            &settings.site_identity_hash(),
            WATCHGUARD_CACHE_MAX_AGE
        ));

        let mut empty_identity = good.clone();
        empty_identity.site_identity_hash = "  ".to_string();
        assert!(!watchguard_cache_record_is_current(
            &empty_identity,
            &settings.site_identity_hash(),
            WATCHGUARD_CACHE_MAX_AGE
        ));

        let mut mismatched = good.clone();
        mismatched.site_identity_hash = "OTHER".to_string();
        assert!(!watchguard_cache_record_is_current(
            &mismatched,
            &settings.site_identity_hash(),
            WATCHGUARD_CACHE_MAX_AGE
        ));

        let mut stale = good.clone();
        stale.cached_at_utc = (Utc::now() - chrono::Duration::days(31))
            .to_rfc3339_opts(SecondsFormat::Secs, true);
        assert!(!watchguard_cache_record_is_current(
            &stale,
            &settings.site_identity_hash(),
            WATCHGUARD_CACHE_MAX_AGE
        ));

        let mut future = good.clone();
        future.cached_at_utc = (Utc::now() + chrono::Duration::hours(1))
            .to_rfc3339_opts(SecondsFormat::Secs, true);
        assert!(!watchguard_cache_record_is_current(
            &future,
            &settings.site_identity_hash(),
            WATCHGUARD_CACHE_MAX_AGE
        ));

        let mut unparseable = good.clone();
        unparseable.cached_at_utc = "not-a-date".to_string();
        assert!(!watchguard_cache_record_is_current(
            &unparseable,
            &settings.site_identity_hash(),
            WATCHGUARD_CACHE_MAX_AGE
        ));

        let mut not_ovpn = good.clone();
        not_ovpn.profile_ovpn = "<html><body>remote login failed</body></html>".to_string();
        assert!(!watchguard_cache_record_is_current(
            &not_ovpn,
            &settings.site_identity_hash(),
            WATCHGUARD_CACHE_MAX_AGE
        ));

        assert!(!watchguard_cache_record_is_current(
            &good,
            &settings.site_identity_hash(),
            Duration::ZERO
        ));
    }

    #[test]
    fn extract_remotes_shared_parser_handles_watchguard_profile() {
        // WatchGuard synthesizes a self-contained .ovpn from client.wgssl; the shared
        // `remote`-directive parser (Stormshield portal glue) must understand it.
        let profile = "client\nremote fw.example 443 tcp\nverify-x509-name /O=WatchGuard_Technologies\n<ca>\n-----BEGIN CERTIFICATE-----\nremote inside-ca.example\n-----END CERTIFICATE-----\n</ca>\n";
        assert!(looks_like_openvpn_profile(profile));
        assert_eq!(extract_ovpn_remote_hosts(profile), vec!["fw.example"]);
    }

    #[test]
    fn debug_never_prints_secrets() {
        let settings = settings();
        let debug = format!("{settings:?}");
        assert!(!debug.contains(TEST_PASSWORD));
        assert!(!debug.contains(TEST_OTP));

        let call = WatchguardPortalFetchCall::new(
            WatchguardPortalRequest::new(TEST_SERVER, 443),
            TEST_USERNAME,
            TEST_PASSWORD,
        );
        let debug = format!("{call:?}");
        assert!(!debug.contains(TEST_PASSWORD));
        assert!(debug.contains("[REDACTED]"));

        let failure = WatchguardTlsFailure::new("CN=fw.example", "CN=Lab Root CA", TEST_THUMBPRINT);
        let debug = format!("{failure:?}");
        assert!(!debug.contains(TEST_THUMBPRINT));
        assert!(debug.contains("thumbprint_prefix"));

        let outcome = WatchguardOutcome {
            profile_ovpn: TEST_PROFILE.to_string(),
            username: TEST_USERNAME.to_string(),
            openvpn_password: "s3cret654321".to_string(),
            challenge_response: Some(TEST_OTP.to_string()),
            from_cache: false,
        };
        let debug = format!("{outcome:?}");
        assert!(!debug.contains("s3cret654321"));
        assert!(!debug.contains(TEST_OTP));
        assert!(!debug.contains(TEST_PROFILE));

        let cache = MemoryWatchguardProfileCache::new();
        cache.seed(config_id(), current_cache_record("IDENT"));
        let debug = format!("{cache:?}");
        assert!(!debug.contains("IDENT"));
        assert!(!debug.contains("vpn.example"));

        let guard = WatchguardOtpReuseGuard::new();
        guard.record(config_id(), &OtpCode::new("SECRET_CODE_42"));
        let debug = format!("{guard:?}");
        assert!(!debug.contains("SECRET_CODE_42"));
        assert!(debug.contains("tracked_tunnels"));

        let fetcher = FakeWatchguardPortalFetcher::new();
        fetcher.set_tls_failure(failure);
        let debug = format!("{fetcher:?}");
        assert!(!debug.contains(TEST_THUMBPRINT));
    }

    #[tokio::test]
    async fn watchguard_resolve_error_never_echoes_credentials() {
        // An injected download failure must not leak the account password / OTP.
        let fetcher = FakeWatchguardPortalFetcher::new();
        fetcher.push_profile_error("download exploded");
        let cache = MemoryWatchguardProfileCache::new();
        let prompt = FakeOtpPrompt::from_submitted([TEST_OTP]);

        let error = establish_automatic(
            &fetcher,
            &cache,
            &ethernet_probe(),
            &prompt,
            &WatchguardOtpReuseGuard::new(),
            &trust_rejecting(),
            &RecordingWatchguardProvider::new(),
            settings(),
        )
        .await
        .err()
        .expect("expected establishment failure");

        let rendered = format!("{error}");
        assert!(rendered.contains("download exploded"), "unexpected: {rendered}");
        // The resolution code only forwards the fetcher error — it never appends the
        // account password or OTP to the message.
        assert!(!rendered.contains(TEST_PASSWORD), "unexpected: {rendered}");
        assert!(!rendered.contains(TEST_OTP), "unexpected: {rendered}");
    }
}
